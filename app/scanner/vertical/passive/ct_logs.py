"""
Certificate Transparency logs scanner
Queries multiple CT log sources for subdomain discovery
"""

from typing import List, Set
import structlog
import aiohttp
import re

logger = structlog.get_logger()


class CTLogScanner:
    """
    Scans Certificate Transparency logs for subdomains
    Uses multiple sources: crt.sh, censys, tls.bufferover.run
    """
    
    def __init__(self, config, rate_limiter):
        self.config = config
        self.rate_limiter = rate_limiter
        self.logger = logger.bind(tool="ct_logs")
        
        # Get API keys if available
        self.censys_api_id = config.api_keys.get_key("censys_api_id")
        self.censys_api_secret = config.api_keys.get_key("censys_api_secret")
        self.bufferover_key = config.api_keys.get_key("bufferover")
    
    async def scan(self, domain: str) -> List[str]:
        """
        Scan CT logs for a domain
        
        Args:
            domain: Target domain
        
        Returns:
            List of discovered subdomains
        """
        self.logger.info("Starting CT log scan", domain=domain)
        
        all_subdomains: Set[str] = set()
        
        # Source 1: crt.sh (no API key required)
        crtsh_results = await self._scan_crtsh(domain)
        all_subdomains.update(crtsh_results)
        
        # Source 2: tls.bufferover.run (API key required)
        if self.bufferover_key:
            bufferover_results = await self._scan_bufferover(domain)
            all_subdomains.update(bufferover_results)
        
        # Source 3: Censys (API key required)
        if self.censys_api_id and self.censys_api_secret:
            censys_results = await self._scan_censys(domain)
            all_subdomains.update(censys_results)
        
        self.logger.info(
            "CT log scan complete",
            domain=domain,
            subdomains=len(all_subdomains)
        )
        
        return list(all_subdomains)
    
    async def _scan_crtsh(self, domain: str) -> List[str]:
        """Scan crt.sh for certificates"""
        await self.rate_limiter.acquire(tool="crtsh")
        
        url = "https://crt.sh/"
        params = {
            "q": f"%.{domain}",
            "output": "json"
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url,
                    params=params,
                    timeout=aiohttp.ClientTimeout(total=30)
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        subdomains = set()
                        
                        for entry in data:
                            name_value = entry.get("name_value", "")
                            # Parse subdomains from name_value
                            for line in name_value.split("\n"):
                                line = line.strip()
                                if line and domain in line:
                                    # Remove wildcards
                                    subdomain = line.replace("*.", "")
                                    if subdomain.endswith(domain):
                                        subdomains.add(subdomain)
                        
                        self.logger.info("crt.sh scan complete", count=len(subdomains))
                        return list(subdomains)
        
        except Exception as e:
            self.logger.error("crt.sh scan failed", error=str(e))
        
        return []
    
    async def _scan_bufferover(self, domain: str) -> List[str]:
        """Scan tls.bufferover.run"""
        await self.rate_limiter.acquire(tool="bufferover")
        
        url = f"https://tls.bufferover.run/dns?q=.{domain}"
        headers = {"x-api-key": self.bufferover_key}
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=30)
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        subdomains = set()
                        
                        # Parse results
                        results = data.get("Results", [])
                        for result in results:
                            parts = result.split(",")
                            if len(parts) > 0:
                                subdomain = parts[0]
                                if domain in subdomain:
                                    subdomains.add(subdomain)
                        
                        self.logger.info("bufferover scan complete", count=len(subdomains))
                        return list(subdomains)
        
        except Exception as e:
            self.logger.error("bufferover scan failed", error=str(e))
        
        return []
    
    async def _scan_censys(self, domain: str) -> List[str]:
        """Scan Censys for certificates"""
        await self.rate_limiter.acquire(tool="censys")
        
        url = "https://search.censys.io/api/v2/certificates/search"
        auth = aiohttp.BasicAuth(self.censys_api_id, self.censys_api_secret)
        params = {
            "q": f"names: *.{domain}",
            "per_page": 100
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url,
                    auth=auth,
                    params=params,
                    timeout=aiohttp.ClientTimeout(total=30)
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        subdomains = set()
                        
                        results = data.get("result", {}).get("hits", [])
                        for hit in results:
                            names = hit.get("names", [])
                            for name in names:
                                if domain in name:
                                    # Remove wildcards
                                    subdomain = name.replace("*.", "")
                                    if subdomain.endswith(domain):
                                        subdomains.add(subdomain)
                        
                        self.logger.info("censys scan complete", count=len(subdomains))
                        return list(subdomains)
        
        except Exception as e:
            self.logger.error("censys scan failed", error=str(e))
        
        return []

