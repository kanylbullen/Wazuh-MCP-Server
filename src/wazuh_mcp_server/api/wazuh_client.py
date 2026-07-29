"""Wazuh API client optimized for Wazuh 4.8.0 to 4.14.1 compatibility with latest features."""

import asyncio
import json
import time
from typing import Dict, Any, Optional
import httpx
import logging

from wazuh_mcp_server.config import WazuhConfig
from wazuh_mcp_server.resilience import (
    CircuitBreaker,
    CircuitBreakerConfig,
    RetryConfig
)
from wazuh_mcp_server.api.wazuh_indexer import (
    WazuhIndexerClient,
    IndexerNotConfiguredError
)

logger = logging.getLogger(__name__)


class WazuhClient:
    """Simplified Wazuh API client with rate limiting, circuit breaker, and retry logic."""

    def __init__(self, config: WazuhConfig):
        self.config = config
        self.token: Optional[str] = None
        self.client: Optional[httpx.AsyncClient] = None
        # Rate limiting
        self._rate_limiter = asyncio.Semaphore(config.max_connections)
        self._request_times = []
        self._max_requests_per_minute = getattr(config, 'max_requests_per_minute', 100)
        self._rate_limit_enabled = True

        # Circuit breaker for API resilience
        circuit_config = CircuitBreakerConfig(
            failure_threshold=5,
            recovery_timeout=60,
            expected_exception=Exception
        )
        self._circuit_breaker = CircuitBreaker(circuit_config)

        # Initialize Wazuh Indexer client if configured (required for Wazuh 4.8.0+)
        self._indexer_client: Optional[WazuhIndexerClient] = None
        if config.wazuh_indexer_host:
            self._indexer_client = WazuhIndexerClient(
                host=config.wazuh_indexer_host,
                port=config.wazuh_indexer_port,
                username=config.wazuh_indexer_user,
                password=config.wazuh_indexer_pass,
                verify_ssl=config.verify_ssl,
                timeout=config.request_timeout_seconds
            )
            logger.info(f"WazuhIndexerClient configured for {config.wazuh_indexer_host}:{config.wazuh_indexer_port}")
        else:
            logger.warning(
                "Wazuh Indexer not configured. Alert, vulnerability, and security analysis tools will not work. "
                "Set WAZUH_INDEXER_HOST to enable."
            )

        logger.info("WazuhClient initialized with circuit breaker and retry logic")

    def _require_indexer(self) -> WazuhIndexerClient:
        """Return the indexer client or raise IndexerNotConfiguredError."""
        if not self._indexer_client:
            raise IndexerNotConfiguredError()
        return self._indexer_client

    async def initialize(self):
        """Initialize the HTTP client and authenticate."""
        self.client = httpx.AsyncClient(
            verify=self.config.verify_ssl,
            timeout=self.config.request_timeout_seconds
        )
        await self._authenticate()

        # Initialize indexer client if configured
        if self._indexer_client:
            try:
                await self._indexer_client.initialize()
                logger.info("Wazuh Indexer client initialized successfully")
            except Exception as e:
                logger.warning(f"Wazuh Indexer initialization failed: {e}")
    
    async def _authenticate(self):
        """Authenticate with Wazuh API."""
        auth_url = f"{self.config.base_url}/security/user/authenticate"
        
        try:
            response = await self.client.post(
                auth_url,
                auth=(self.config.wazuh_user, self.config.wazuh_pass)
            )
            response.raise_for_status()
            
            data = response.json()
            if "data" not in data or "token" not in data["data"]:
                raise ValueError("Invalid authentication response from Wazuh API")
            
            self.token = data["data"]["token"]
            print(f"✅ Authenticated with Wazuh server at {self.config.wazuh_host}")
            
        except httpx.ConnectError:
            raise ConnectionError(f"Cannot connect to Wazuh server at {self.config.wazuh_host}:{self.config.wazuh_port}")
        except httpx.TimeoutException:
            raise ConnectionError(f"Connection timeout to Wazuh server at {self.config.wazuh_host}")
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 401:
                raise ValueError("Invalid Wazuh credentials. Check WAZUH_USER and WAZUH_PASS")
            elif e.response.status_code == 403:
                raise ValueError("Wazuh user does not have sufficient permissions")
            else:
                raise ValueError(f"Wazuh API error: {e.response.status_code} - {e.response.text}")

    # ------------------------------------------------------------------ #
    #  Alert methods — delegated to Indexer                               #
    # ------------------------------------------------------------------ #

    async def get_alerts(self, **params) -> Dict[str, Any]:
        """Get alerts from Wazuh Indexer."""
        return await self._require_indexer().get_alerts(**params)

    async def get_alert_summary(self, time_range: str, group_by: str) -> Dict[str, Any]:
        """Get alert summary from Wazuh Indexer."""
        return await self._require_indexer().get_alert_summary(time_range, group_by)

    async def analyze_alert_patterns(self, time_range: str, min_frequency: int) -> Dict[str, Any]:
        """Analyze alert patterns from Wazuh Indexer."""
        return await self._require_indexer().analyze_alert_patterns(time_range, min_frequency)

    async def search_security_events(self, query: str, time_range: str, limit: int) -> Dict[str, Any]:
        """Search security events from Wazuh Indexer."""
        return await self._require_indexer().search_security_events(query, time_range, limit)

    # ------------------------------------------------------------------ #
    #  Security analysis methods — delegated to Indexer                   #
    # ------------------------------------------------------------------ #

    async def analyze_security_threat(self, indicator: str, indicator_type: str) -> Dict[str, Any]:
        """Analyze security threat via Indexer."""
        return await self._require_indexer().analyze_security_threat(indicator, indicator_type)

    async def check_ioc_reputation(self, indicator: str, indicator_type: str) -> Dict[str, Any]:
        """Check IoC reputation via Indexer."""
        return await self._require_indexer().check_ioc_reputation(indicator, indicator_type)

    async def perform_risk_assessment(self, agent_id: str = None) -> Dict[str, Any]:
        """Perform risk assessment via Indexer."""
        return await self._require_indexer().perform_risk_assessment(agent_id)

    async def get_top_security_threats(self, limit: int, time_range: str) -> Dict[str, Any]:
        """Get top security threats via Indexer."""
        return await self._require_indexer().get_top_security_threats(limit, time_range)

    async def generate_security_report(self, report_type: str, include_recommendations: bool) -> Dict[str, Any]:
        """Generate security report via Indexer."""
        return await self._require_indexer().generate_security_report(report_type, include_recommendations)

    async def run_compliance_check(self, framework: str, agent_id: str = None) -> Dict[str, Any]:
        """Run compliance check via Indexer."""
        return await self._require_indexer().run_compliance_check(framework, agent_id)

    # ------------------------------------------------------------------ #
    #  Agent methods — Wazuh Manager API                                  #
    # ------------------------------------------------------------------ #

    async def get_agents(self, **params) -> Dict[str, Any]:
        """Get agents from Wazuh."""
        # Map agent_id to agents_list (Wazuh API convention)
        agent_id = params.pop("agent_id", None)
        if agent_id:
            params["agents_list"] = agent_id
        # Remove None values
        params = {k: v for k, v in params.items() if v is not None}
        return await self._request("GET", "/agents", params=params)

    async def get_running_agents(self) -> Dict[str, Any]:
        """Get running agents."""
        return await self._request("GET", "/agents", params={"status": "active"})

    async def check_agent_health(self, agent_id: str) -> Dict[str, Any]:
        """Check agent health — composite of agent info + stats."""
        agent_info = await self._request("GET", f"/agents", params={"agents_list": agent_id})
        try:
            stats = await self._request("GET", f"/agents/{agent_id}/stats/agent")
        except Exception:
            stats = {"data": {"affected_items": []}}
        items = agent_info.get("data", {}).get("affected_items", [])
        agent = items[0] if items else {}
        return {
            "data": {
                "agent_id": agent_id,
                "status": agent.get("status", "unknown"),
                "name": agent.get("name", "unknown"),
                "ip": agent.get("ip", "unknown"),
                "os": agent.get("os", {}),
                "version": agent.get("version", "unknown"),
                "last_keep_alive": agent.get("lastKeepAlive", "unknown"),
                "stats": stats.get("data", {}),
            }
        }

    async def get_agent_processes(self, agent_id: str, limit: int) -> Dict[str, Any]:
        """Get agent processes via syscollector."""
        return await self._request("GET", f"/syscollector/{agent_id}/processes", params={"limit": limit})

    async def get_agent_ports(self, agent_id: str, limit: int) -> Dict[str, Any]:
        """Get agent ports via syscollector."""
        return await self._request("GET", f"/syscollector/{agent_id}/ports", params={"limit": limit})

    async def get_agent_configuration(self, agent_id: str) -> Dict[str, Any]:
        """Get agent configuration — group + shared config."""
        try:
            group_info = await self._request("GET", f"/agents", params={"agents_list": agent_id, "select": "group,name,id,ip,os.name,os.version,version"})
        except Exception:
            group_info = {"data": {"affected_items": []}}
        try:
            # Get the agent's active configuration for the logcollector component
            config_data = await self._request("GET", f"/agents/{agent_id}/config/logcollector/localfile")
        except Exception:
            config_data = {"data": {"affected_items": []}}
        return {
            "data": {
                "agent_info": group_info.get("data", {}).get("affected_items", []),
                "active_configuration": config_data.get("data", {}),
            }
        }

    # ------------------------------------------------------------------ #
    #  Vulnerability methods — delegated to Indexer                       #
    # ------------------------------------------------------------------ #

    async def get_vulnerabilities(self, **params) -> Dict[str, Any]:
        return await self._require_indexer().get_vulnerabilities(**params)

    async def get_critical_vulnerabilities(self, limit: int) -> Dict[str, Any]:
        return await self._require_indexer().get_critical_vulnerabilities(limit=limit)

    async def get_vulnerability_summary(self, time_range: str) -> Dict[str, Any]:
        return await self._require_indexer().get_vulnerability_summary()

    # ------------------------------------------------------------------ #
    #  System monitoring methods — Wazuh Manager API (fixed paths)        #
    # ------------------------------------------------------------------ #

    async def get_wazuh_statistics(self) -> Dict[str, Any]:
        """Get Wazuh manager statistics."""
        return await self._request("GET", "/manager/stats")

    async def get_weekly_stats(self) -> Dict[str, Any]:
        """Get weekly statistics."""
        return await self._request("GET", "/manager/stats/weekly")

    async def get_cluster_health(self) -> Dict[str, Any]:
        """Get cluster status (the actual endpoint)."""
        return await self._request("GET", "/cluster/status")

    async def get_cluster_nodes(self) -> Dict[str, Any]:
        """Get cluster nodes."""
        return await self._request("GET", "/cluster/nodes")

    async def get_rules_summary(self) -> Dict[str, Any]:
        """Get rules summary — query /rules and aggregate."""
        result = await self._request("GET", "/rules", params={"limit": 500})
        rules = result.get("data", {}).get("affected_items", [])
        total = result.get("data", {}).get("total_affected_items", len(rules))
        by_level = {}
        by_group = {}
        for r in rules:
            lvl = str(r.get("level", "unknown"))
            by_level[lvl] = by_level.get(lvl, 0) + 1
            for g in r.get("groups", []):
                by_group[g] = by_group.get(g, 0) + 1
        # Sort groups by count
        top_groups = sorted(by_group.items(), key=lambda x: x[1], reverse=True)[:20]
        return {
            "data": {
                "total_rules": total,
                "by_level": dict(sorted(by_level.items(), key=lambda x: int(x[0]) if x[0].isdigit() else 0, reverse=True)),
                "top_groups": [{"group": g, "count": c} for g, c in top_groups],
            }
        }

    async def get_remoted_stats(self) -> Dict[str, Any]:
        """Get remoted statistics."""
        return await self._request("GET", "/manager/stats/remoted")

    async def get_log_collector_stats(self) -> Dict[str, Any]:
        """Get analysisd (log analysis) statistics."""
        return await self._request("GET", "/manager/stats/analysisd")

    async def search_manager_logs(self, query: str, limit: int) -> Dict[str, Any]:
        """Search manager logs."""
        return await self._request("GET", "/manager/logs", params={"limit": limit, "search": query})

    async def get_manager_error_logs(self, limit: int) -> Dict[str, Any]:
        """Get manager error logs."""
        return await self._request("GET", "/manager/logs", params={"level": "error", "limit": limit})

    async def validate_connection(self) -> Dict[str, Any]:
        """Validate Wazuh connection."""
        try:
            result = await self._request("GET", "/")
            indexer_status = "not_configured"
            if self._indexer_client:
                try:
                    h = await self._indexer_client.health_check()
                    indexer_status = h.get("status", "unknown")
                except Exception as e:
                    indexer_status = f"error: {e}"
            return {"status": "connected", "manager": result, "indexer": indexer_status}
        except Exception as e:
            return {"status": "failed", "error": str(e)}

    async def get_manager_info(self) -> Dict[str, Any]:
        """Get Wazuh manager information."""
        return await self._request("GET", "/")

    # ------------------------------------------------------------------ #
    #  Additional Manager API methods                                     #
    # ------------------------------------------------------------------ #

    async def get_rules(self, **params) -> Dict[str, Any]:
        return await self._request("GET", "/rules", params=params)

    async def get_cluster_status(self) -> Dict[str, Any]:
        return await self._request("GET", "/cluster/status")

    async def search_logs(self, **params) -> Dict[str, Any]:
        return await self._request("GET", "/manager/logs", params=params)

    async def get_manager_stats(self, **params) -> Dict[str, Any]:
        return await self._request("GET", "/manager/stats", params=params)

    async def get_agent_stats(self, agent_id: str, component: str = "logcollector") -> Dict[str, Any]:
        return await self._request("GET", f"/agents/{agent_id}/stats/{component}")

    # ------------------------------------------------------------------ #
    #  HTTP request infrastructure                                        #
    # ------------------------------------------------------------------ #

    async def _rate_limit_check(self):
        """Check and enforce rate limiting."""
        current_time = time.time()
        self._request_times = [t for t in self._request_times if current_time - t < 60]
        if len(self._request_times) >= self._max_requests_per_minute:
            oldest_request_time = self._request_times[0]
            sleep_time = 60 - (current_time - oldest_request_time)
            if sleep_time > 0:
                print(f"⚠️ Rate limit reached ({self._max_requests_per_minute}/min). Waiting {sleep_time:.1f}s...")
                await asyncio.sleep(sleep_time)
                current_time = time.time()
                self._request_times = [t for t in self._request_times if current_time - t < 60]
        self._request_times.append(current_time)

    async def _request(self, method: str, endpoint: str, **kwargs) -> Dict[str, Any]:
        """Make authenticated request to Wazuh API with rate limiting, circuit breaker, and retry logic."""
        async with self._rate_limiter:
            await self._rate_limit_check()
            return await self._request_with_resilience(method, endpoint, **kwargs)

    @RetryConfig.WAZUH_API_RETRY
    async def _request_with_resilience(self, method: str, endpoint: str, **kwargs) -> Dict[str, Any]:
        """Execute request with circuit breaker and retry logic."""
        return await self._circuit_breaker._call(self._execute_request, method, endpoint, **kwargs)

    async def _execute_request(self, method: str, endpoint: str, **kwargs) -> Dict[str, Any]:
        """Execute the actual HTTP request to Wazuh API."""
        if not self.token:
            await self._authenticate()

        url = f"{self.config.base_url}{endpoint}"
        headers = {"Authorization": f"Bearer {self.token}"}

        try:
            response = await self.client.request(method, url, headers=headers, **kwargs)
            response.raise_for_status()

            data = response.json()
            if "data" not in data:
                raise ValueError(f"Invalid response structure from Wazuh API: {endpoint}")
            return data

        except httpx.HTTPStatusError as e:
            if e.response.status_code == 401:
                self.token = None
                await self._authenticate()
                headers = {"Authorization": f"Bearer {self.token}"}
                response = await self.client.request(method, url, headers=headers, **kwargs)
                response.raise_for_status()
                return response.json()
            else:
                logger.error(f"Wazuh API request failed: {e.response.status_code} - {e.response.text}")
                raise ValueError(f"Wazuh API request failed: {e.response.status_code} - {e.response.text}")
        except httpx.ConnectError:
            logger.error(f"Lost connection to Wazuh server at {self.config.wazuh_host}")
            raise ConnectionError(f"Lost connection to Wazuh server at {self.config.wazuh_host}")
        except httpx.TimeoutException:
            logger.error(f"Request timeout to Wazuh server")
            raise ConnectionError(f"Request timeout to Wazuh server")

    async def close(self):
        """Close the HTTP client and indexer client."""
        if self.client:
            await self.client.aclose()
        if self._indexer_client:
            await self._indexer_client.close()
