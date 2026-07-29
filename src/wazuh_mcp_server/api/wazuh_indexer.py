"""
Wazuh Indexer client for querying OpenSearch indices (Wazuh 4.8.0+).

Handles:
- Alert queries (wazuh-alerts-4.x-*)
- Vulnerability queries (wazuh-states-vulnerabilities-*)
- Aggregations, full-text search, compliance checks, etc.
"""

import logging
from typing import Dict, Any, Optional, List
from datetime import datetime, timezone, timedelta
import httpx

logger = logging.getLogger(__name__)

# Index patterns
ALERT_INDEX = "wazuh-alerts-4.x-*"
VULNERABILITY_INDEX = "wazuh-states-vulnerabilities-*"

# Time range to timedelta mapping
TIME_RANGE_MAP = {
    "1h": timedelta(hours=1),
    "6h": timedelta(hours=6),
    "24h": timedelta(hours=24),
    "1d": timedelta(days=1),
    "7d": timedelta(days=7),
    "30d": timedelta(days=30),
}

# Compliance framework to rule group mapping
COMPLIANCE_GROUPS = {
    "PCI-DSS": "pci_dss",
    "HIPAA": "hipaa",
    "GDPR": "gdpr",
    "NIST": "nist_800_53",
    "SOX": "pci_dss",  # SOX uses similar controls
}


def _time_range_filter(time_range: str) -> Dict[str, Any]:
    """Build an OpenSearch range filter for timestamp."""
    delta = TIME_RANGE_MAP.get(time_range, timedelta(hours=24))
    now = datetime.now(timezone.utc)
    gte = (now - delta).isoformat()
    return {"range": {"timestamp": {"gte": gte, "lte": now.isoformat()}}}


class WazuhIndexerClient:
    """Client for querying the Wazuh Indexer (OpenSearch)."""

    def __init__(
        self,
        host: str,
        port: int = 9200,
        username: Optional[str] = None,
        password: Optional[str] = None,
        verify_ssl: bool = True,
        timeout: int = 30
    ):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self.client: Optional[httpx.AsyncClient] = None
        self._initialized = False

    @property
    def base_url(self) -> str:
        return f"https://{self.host}:{self.port}"

    async def initialize(self):
        auth = None
        if self.username and self.password:
            auth = (self.username, self.password)
        self.client = httpx.AsyncClient(
            verify=self.verify_ssl, timeout=self.timeout, auth=auth
        )
        self._initialized = True
        logger.info(f"WazuhIndexerClient initialized for {self.host}:{self.port}")

    async def close(self):
        if self.client:
            await self.client.aclose()
            self._initialized = False

    async def _ensure_initialized(self):
        if not self._initialized:
            await self.initialize()

    async def _search(
        self, index: str, body: Dict[str, Any], size: int = 100
    ) -> Dict[str, Any]:
        """Execute search query against OpenSearch."""
        await self._ensure_initialized()
        url = f"{self.base_url}/{index}/_search"
        if "size" not in body:
            body["size"] = size
        try:
            response = await self.client.post(
                url, json=body, headers={"Content-Type": "application/json"}
            )
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as e:
            logger.error(f"Indexer search failed: {e.response.status_code} - {e.response.text}")
            raise ValueError(f"Indexer query failed: {e.response.status_code}")
        except httpx.ConnectError:
            raise ConnectionError(f"Cannot connect to Wazuh Indexer at {self.host}:{self.port}")
        except httpx.TimeoutException:
            raise ConnectionError(f"Timeout connecting to Wazuh Indexer at {self.host}:{self.port}")

    # ------------------------------------------------------------------ #
    #  Alert methods (Phase 2)                                            #
    # ------------------------------------------------------------------ #

    async def get_alerts(
        self,
        agent_id: Optional[str] = None,
        level: Optional[str] = None,
        rule_id: Optional[str] = None,
        timestamp_start: Optional[str] = None,
        timestamp_end: Optional[str] = None,
        limit: int = 100,
    ) -> Dict[str, Any]:
        """Query wazuh-alerts-4.x-* with optional filters."""
        must: List[Dict] = []
        if agent_id:
            must.append({"match": {"agent.id": agent_id}})
        if rule_id:
            must.append({"match": {"rule.id": rule_id}})
        if level:
            # Support "10+" syntax
            if level.endswith("+"):
                must.append({"range": {"rule.level": {"gte": int(level[:-1])}}})
            else:
                must.append({"match": {"rule.level": int(level)}})
        # Time range
        ts_range: Dict[str, Any] = {}
        if timestamp_start:
            ts_range["gte"] = timestamp_start
        if timestamp_end:
            ts_range["lte"] = timestamp_end
        if ts_range:
            must.append({"range": {"timestamp": ts_range}})

        query = {"bool": {"must": must}} if must else {"match_all": {}}
        body = {"query": query, "sort": [{"timestamp": {"order": "desc"}}]}
        result = await self._search(ALERT_INDEX, body, size=limit)
        hits = result.get("hits", {})
        alerts = [h.get("_source", {}) for h in hits.get("hits", [])]
        return {
            "data": {
                "affected_items": alerts,
                "total_affected_items": hits.get("total", {}).get("value", len(alerts)),
            }
        }

    async def get_alert_summary(
        self, time_range: str = "24h", group_by: str = "rule.level"
    ) -> Dict[str, Any]:
        """Aggregation query grouped by a field."""
        body = {
            "size": 0,
            "query": _time_range_filter(time_range),
            "aggs": {
                "grouped": {
                    "terms": {"field": group_by, "size": 50, "order": {"_count": "desc"}}
                },
                "total": {"value_count": {"field": "_id"}},
            },
        }
        result = await self._search(ALERT_INDEX, body)
        aggs = result.get("aggregations", {})
        buckets = aggs.get("grouped", {}).get("buckets", [])
        return {
            "data": {
                "total_alerts": aggs.get("total", {}).get("value", 0),
                "groups": [{"key": b["key"], "count": b["doc_count"]} for b in buckets],
                "time_range": time_range,
                "group_by": group_by,
            }
        }

    async def analyze_alert_patterns(
        self, time_range: str = "24h", min_frequency: int = 5
    ) -> Dict[str, Any]:
        """Frequency / trend analysis aggregation."""
        body = {
            "size": 0,
            "query": _time_range_filter(time_range),
            "aggs": {
                "by_rule": {
                    "terms": {"field": "rule.id", "size": 100, "min_doc_count": min_frequency, "order": {"_count": "desc"}},
                    "aggs": {
                        "rule_desc": {"terms": {"field": "rule.description.keyword", "size": 1}},
                        "rule_level": {"avg": {"field": "rule.level"}},
                        "over_time": {
                            "date_histogram": {"field": "timestamp", "fixed_interval": "1h", "min_doc_count": 0}
                        },
                    },
                },
                "by_agent": {
                    "terms": {"field": "agent.name.keyword", "size": 20, "order": {"_count": "desc"}}
                },
            },
        }
        result = await self._search(ALERT_INDEX, body)
        aggs = result.get("aggregations", {})
        rule_buckets = aggs.get("by_rule", {}).get("buckets", [])
        patterns = []
        for rb in rule_buckets:
            desc_buckets = rb.get("rule_desc", {}).get("buckets", [])
            patterns.append({
                "rule_id": rb["key"],
                "count": rb["doc_count"],
                "description": desc_buckets[0]["key"] if desc_buckets else "N/A",
                "avg_level": round(rb.get("rule_level", {}).get("value", 0), 1),
            })
        agent_buckets = aggs.get("by_agent", {}).get("buckets", [])
        return {
            "data": {
                "patterns": patterns,
                "top_agents": [{"agent": b["key"], "count": b["doc_count"]} for b in agent_buckets],
                "time_range": time_range,
                "min_frequency": min_frequency,
            }
        }

    async def search_security_events(
        self, query: str, time_range: str = "24h", limit: int = 100
    ) -> Dict[str, Any]:
        """Full-text search across alert index."""
        body = {
            "query": {
                "bool": {
                    "must": [{"query_string": {"query": query, "default_operator": "AND"}}],
                    "filter": [_time_range_filter(time_range)],
                }
            },
            "sort": [{"timestamp": {"order": "desc"}}],
        }
        result = await self._search(ALERT_INDEX, body, size=limit)
        hits = result.get("hits", {})
        events = [h.get("_source", {}) for h in hits.get("hits", [])]
        return {
            "data": {
                "affected_items": events,
                "total_affected_items": hits.get("total", {}).get("value", len(events)),
                "query": query,
                "time_range": time_range,
            }
        }

    async def analyze_security_threat(
        self, indicator: str, indicator_type: str = "ip"
    ) -> Dict[str, Any]:
        """Search alerts matching an IP/domain/hash indicator."""
        field_map = {
            "ip": ["data.srcip", "data.dstip", "agent.ip"],
            "domain": ["data.url", "data.hostname"],
            "hash": ["syscheck.md5_after", "syscheck.sha256_after", "syscheck.sha1_after"],
            "url": ["data.url"],
        }
        fields = field_map.get(indicator_type, ["_all"])
        should = [{"match": {f: indicator}} for f in fields]
        body = {
            "query": {"bool": {"should": should, "minimum_should_match": 1}},
            "sort": [{"timestamp": {"order": "desc"}}],
            "aggs": {
                "by_rule": {"terms": {"field": "rule.description.keyword", "size": 10}},
                "by_level": {"terms": {"field": "rule.level", "size": 20}},
                "by_agent": {"terms": {"field": "agent.name.keyword", "size": 10}},
            },
        }
        result = await self._search(ALERT_INDEX, body, size=50)
        hits = result.get("hits", {})
        aggs = result.get("aggregations", {})
        total = hits.get("total", {}).get("value", 0)
        events = [h.get("_source", {}) for h in hits.get("hits", [])]
        return {
            "data": {
                "indicator": indicator,
                "indicator_type": indicator_type,
                "total_matches": total,
                "risk_level": "critical" if total > 50 else "high" if total > 20 else "medium" if total > 5 else "low" if total > 0 else "none",
                "matched_rules": [{"rule": b["key"], "count": b["doc_count"]} for b in aggs.get("by_rule", {}).get("buckets", [])],
                "severity_distribution": {str(b["key"]): b["doc_count"] for b in aggs.get("by_level", {}).get("buckets", [])},
                "affected_agents": [{"agent": b["key"], "count": b["doc_count"]} for b in aggs.get("by_agent", {}).get("buckets", [])],
                "recent_events": events[:10],
            }
        }

    async def check_ioc_reputation(
        self, indicator: str, indicator_type: str = "ip"
    ) -> Dict[str, Any]:
        """Search for an IoC across alerts and return frequency + context."""
        # Reuse threat analysis but present differently
        threat = await self.analyze_security_threat(indicator, indicator_type)
        data = threat["data"]
        total = data["total_matches"]
        return {
            "data": {
                "indicator": indicator,
                "indicator_type": indicator_type,
                "seen_in_alerts": total > 0,
                "total_occurrences": total,
                "risk_level": data["risk_level"],
                "first_seen": data["recent_events"][-1].get("timestamp") if data["recent_events"] else None,
                "last_seen": data["recent_events"][0].get("timestamp") if data["recent_events"] else None,
                "associated_rules": data["matched_rules"],
                "affected_agents": data["affected_agents"],
            }
        }

    async def perform_risk_assessment(
        self, agent_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """Aggregate risk metrics per agent or entire environment."""
        must: List[Dict] = [_time_range_filter("7d")]
        if agent_id:
            must.append({"match": {"agent.id": agent_id}})
        body = {
            "size": 0,
            "query": {"bool": {"must": must}},
            "aggs": {
                "total_alerts": {"value_count": {"field": "_id"}},
                "high_severity": {
                    "filter": {"range": {"rule.level": {"gte": 10}}}
                },
                "critical_severity": {
                    "filter": {"range": {"rule.level": {"gte": 13}}}
                },
                "by_level": {"terms": {"field": "rule.level", "size": 20, "order": {"_key": "desc"}}},
                "by_agent": {
                    "terms": {"field": "agent.name.keyword", "size": 20, "order": {"_count": "desc"}},
                    "aggs": {"max_level": {"max": {"field": "rule.level"}}},
                },
                "by_mitre": {
                    "terms": {"field": "rule.mitre.technique.keyword", "size": 20}
                },
            },
        }
        result = await self._search(ALERT_INDEX, body)
        aggs = result.get("aggregations", {})
        total = aggs.get("total_alerts", {}).get("value", 0)
        high = aggs.get("high_severity", {}).get("doc_count", 0)
        critical = aggs.get("critical_severity", {}).get("doc_count", 0)
        # Risk score 0-100
        risk_score = min(100, int((critical * 10 + high * 3 + total * 0.1)))
        return {
            "data": {
                "risk_score": risk_score,
                "risk_level": "critical" if risk_score >= 75 else "high" if risk_score >= 50 else "medium" if risk_score >= 25 else "low",
                "total_alerts_7d": total,
                "high_severity_alerts": high,
                "critical_severity_alerts": critical,
                "severity_distribution": {str(b["key"]): b["doc_count"] for b in aggs.get("by_level", {}).get("buckets", [])},
                "top_agents": [
                    {"agent": b["key"], "alerts": b["doc_count"], "max_level": b.get("max_level", {}).get("value", 0)}
                    for b in aggs.get("by_agent", {}).get("buckets", [])
                ],
                "mitre_techniques": [{"technique": b["key"], "count": b["doc_count"]} for b in aggs.get("by_mitre", {}).get("buckets", [])],
                "agent_id": agent_id,
            }
        }

    async def get_top_security_threats(
        self, limit: int = 10, time_range: str = "24h"
    ) -> Dict[str, Any]:
        """Top-N aggregation by rule/severity."""
        body = {
            "size": 0,
            "query": _time_range_filter(time_range),
            "aggs": {
                "top_rules": {
                    "terms": {"field": "rule.id", "size": limit, "order": {"_count": "desc"}},
                    "aggs": {
                        "description": {"terms": {"field": "rule.description.keyword", "size": 1}},
                        "level": {"max": {"field": "rule.level"}},
                        "agents_affected": {"cardinality": {"field": "agent.id"}},
                    },
                }
            },
        }
        result = await self._search(ALERT_INDEX, body)
        buckets = result.get("aggregations", {}).get("top_rules", {}).get("buckets", [])
        threats = []
        for b in buckets:
            desc_b = b.get("description", {}).get("buckets", [])
            threats.append({
                "rule_id": b["key"],
                "count": b["doc_count"],
                "description": desc_b[0]["key"] if desc_b else "N/A",
                "max_level": b.get("level", {}).get("value", 0),
                "agents_affected": b.get("agents_affected", {}).get("value", 0),
            })
        return {"data": {"threats": threats, "time_range": time_range}}

    async def generate_security_report(
        self, report_type: str = "daily", include_recommendations: bool = True
    ) -> Dict[str, Any]:
        """Comprehensive aggregation for security reporting."""
        tr_map = {"daily": "24h", "weekly": "7d", "monthly": "30d", "incident": "24h"}
        time_range = tr_map.get(report_type, "24h")
        body = {
            "size": 0,
            "query": _time_range_filter(time_range),
            "aggs": {
                "total": {"value_count": {"field": "_id"}},
                "by_level": {"terms": {"field": "rule.level", "size": 20, "order": {"_key": "desc"}}},
                "by_agent": {"terms": {"field": "agent.name.keyword", "size": 20, "order": {"_count": "desc"}}},
                "by_rule_group": {"terms": {"field": "rule.groups.keyword", "size": 20, "order": {"_count": "desc"}}},
                "by_mitre": {"terms": {"field": "rule.mitre.technique.keyword", "size": 10}},
                "high_severity": {"filter": {"range": {"rule.level": {"gte": 10}}}},
                "over_time": {"date_histogram": {"field": "timestamp", "fixed_interval": "1h", "min_doc_count": 0}},
            },
        }
        result = await self._search(ALERT_INDEX, body)
        aggs = result.get("aggregations", {})
        total = aggs.get("total", {}).get("value", 0)
        high = aggs.get("high_severity", {}).get("doc_count", 0)
        report: Dict[str, Any] = {
            "report_type": report_type,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "time_range": time_range,
            "summary": {
                "total_alerts": total,
                "high_severity_alerts": high,
                "severity_distribution": {str(b["key"]): b["doc_count"] for b in aggs.get("by_level", {}).get("buckets", [])},
            },
            "top_agents": [{"agent": b["key"], "alerts": b["doc_count"]} for b in aggs.get("by_agent", {}).get("buckets", [])],
            "top_rule_groups": [{"group": b["key"], "count": b["doc_count"]} for b in aggs.get("by_rule_group", {}).get("buckets", [])],
            "mitre_techniques": [{"technique": b["key"], "count": b["doc_count"]} for b in aggs.get("by_mitre", {}).get("buckets", [])],
            "timeline": [{"timestamp": b["key_as_string"], "count": b["doc_count"]} for b in aggs.get("over_time", {}).get("buckets", [])],
        }
        if include_recommendations:
            recs = []
            if high > 0:
                recs.append(f"Investigate {high} high-severity alerts (level >= 10)")
            level_buckets = aggs.get("by_level", {}).get("buckets", [])
            for lb in level_buckets:
                if int(lb["key"]) >= 12 and lb["doc_count"] > 10:
                    recs.append(f"Rule level {lb['key']} fired {lb['doc_count']} times — review for tuning or escalation")
            if not recs:
                recs.append("No critical issues detected in this period")
            report["recommendations"] = recs
        return {"data": report}

    async def run_compliance_check(
        self, framework: str = "PCI-DSS", agent_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """Query compliance-tagged rules (PCI-DSS, HIPAA, etc.)."""
        group_tag = COMPLIANCE_GROUPS.get(framework, framework.lower().replace("-", "_"))
        must: List[Dict] = [
            _time_range_filter("7d"),
            {"match": {"rule.groups": group_tag}},
        ]
        if agent_id:
            must.append({"match": {"agent.id": agent_id}})
        body = {
            "size": 0,
            "query": {"bool": {"must": must}},
            "aggs": {
                "total": {"value_count": {"field": "_id"}},
                "by_rule": {
                    "terms": {"field": "rule.id", "size": 50, "order": {"_count": "desc"}},
                    "aggs": {
                        "description": {"terms": {"field": "rule.description.keyword", "size": 1}},
                        "level": {"max": {"field": "rule.level"}},
                    },
                },
                "by_level": {"terms": {"field": "rule.level", "size": 20}},
                "by_agent": {"terms": {"field": "agent.name.keyword", "size": 20}},
            },
        }
        result = await self._search(ALERT_INDEX, body)
        aggs = result.get("aggregations", {})
        total = aggs.get("total", {}).get("value", 0)
        rule_buckets = aggs.get("by_rule", {}).get("buckets", [])
        findings = []
        for rb in rule_buckets:
            desc_b = rb.get("description", {}).get("buckets", [])
            findings.append({
                "rule_id": rb["key"],
                "count": rb["doc_count"],
                "description": desc_b[0]["key"] if desc_b else "N/A",
                "max_level": rb.get("level", {}).get("value", 0),
            })
        compliant = total == 0
        return {
            "data": {
                "framework": framework,
                "compliant": compliant,
                "status": "PASS" if compliant else "FAIL",
                "total_findings": total,
                "findings": findings,
                "severity_distribution": {str(b["key"]): b["doc_count"] for b in aggs.get("by_level", {}).get("buckets", [])},
                "affected_agents": [{"agent": b["key"], "count": b["doc_count"]} for b in aggs.get("by_agent", {}).get("buckets", [])],
                "agent_id": agent_id,
            }
        }

    # ------------------------------------------------------------------ #
    #  Vulnerability methods (existing, preserved)                        #
    # ------------------------------------------------------------------ #

    async def get_vulnerabilities(
        self,
        agent_id: Optional[str] = None,
        severity: Optional[str] = None,
        cve_id: Optional[str] = None,
        limit: int = 100,
    ) -> Dict[str, Any]:
        must_clauses = []
        if agent_id:
            must_clauses.append({"match": {"agent.id": agent_id}})
        if severity:
            must_clauses.append({"match": {"vulnerability.severity": severity.capitalize()}})
        if cve_id:
            must_clauses.append({"match": {"vulnerability.id": cve_id}})
        query = {"bool": {"must": must_clauses}} if must_clauses else {"match_all": {}}
        result = await self._search(VULNERABILITY_INDEX, {"query": query}, size=limit)
        hits = result.get("hits", {})
        vulns = []
        for hit in hits.get("hits", []):
            s = hit.get("_source", {})
            vulns.append({
                "id": s.get("vulnerability", {}).get("id"),
                "severity": s.get("vulnerability", {}).get("severity"),
                "description": s.get("vulnerability", {}).get("description"),
                "reference": s.get("vulnerability", {}).get("reference"),
                "status": s.get("vulnerability", {}).get("status"),
                "detected_at": s.get("vulnerability", {}).get("detected_at"),
                "published_at": s.get("vulnerability", {}).get("published_at"),
                "agent": {"id": s.get("agent", {}).get("id"), "name": s.get("agent", {}).get("name")},
                "package": {
                    "name": s.get("package", {}).get("name"),
                    "version": s.get("package", {}).get("version"),
                    "architecture": s.get("package", {}).get("architecture"),
                },
            })
        return {
            "data": {
                "affected_items": vulns,
                "total_affected_items": hits.get("total", {}).get("value", len(vulns)),
                "total_failed_items": 0,
                "failed_items": [],
            }
        }

    async def get_critical_vulnerabilities(self, limit: int = 50) -> Dict[str, Any]:
        return await self.get_vulnerabilities(severity="Critical", limit=limit)

    async def get_vulnerability_summary(self) -> Dict[str, Any]:
        await self._ensure_initialized()
        url = f"{self.base_url}/{VULNERABILITY_INDEX}/_search"
        body = {
            "size": 0,
            "aggs": {
                "by_severity": {"terms": {"field": "vulnerability.severity", "size": 10}},
                "by_agent": {"cardinality": {"field": "agent.id"}},
                "total_vulnerabilities": {"value_count": {"field": "vulnerability.id"}},
            },
        }
        try:
            response = await self.client.post(url, json=body, headers={"Content-Type": "application/json"})
            response.raise_for_status()
            result = response.json()
        except httpx.HTTPStatusError as e:
            raise ValueError(f"Vulnerability summary query failed: {e.response.status_code}")
        except httpx.ConnectError:
            raise ConnectionError(f"Cannot connect to Wazuh Indexer at {self.host}:{self.port}")

        aggs = result.get("aggregations", {})
        severity_counts = {b["key"]: b["doc_count"] for b in aggs.get("by_severity", {}).get("buckets", [])}
        return {
            "data": {
                "total_vulnerabilities": aggs.get("total_vulnerabilities", {}).get("value", 0),
                "affected_agents": aggs.get("by_agent", {}).get("value", 0),
                "by_severity": severity_counts,
                "critical": severity_counts.get("Critical", 0),
                "high": severity_counts.get("High", 0),
                "medium": severity_counts.get("Medium", 0),
                "low": severity_counts.get("Low", 0),
            }
        }

    async def health_check(self) -> Dict[str, Any]:
        await self._ensure_initialized()
        try:
            response = await self.client.get(f"{self.base_url}/_cluster/health")
            response.raise_for_status()
            h = response.json()
            return {
                "status": h.get("status"),
                "cluster_name": h.get("cluster_name"),
                "number_of_nodes": h.get("number_of_nodes"),
                "active_shards": h.get("active_shards"),
            }
        except Exception as e:
            return {"status": "unavailable", "error": str(e)}


class IndexerNotConfiguredError(Exception):
    """Raised when Wazuh Indexer is not configured but required."""

    def __init__(self, message: str = None):
        default_message = (
            "Wazuh Indexer not configured. "
            "Set WAZUH_INDEXER_HOST to enable alert, vulnerability, and security analysis tools.\n"
            "Required environment variables:\n"
            "  WAZUH_INDEXER_HOST, WAZUH_INDEXER_USER, WAZUH_INDEXER_PASS"
        )
        super().__init__(message or default_message)
