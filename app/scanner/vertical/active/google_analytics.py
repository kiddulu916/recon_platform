"""
Google Analytics relationship tracking
Finds related domains via shared GA tracking codes
"""

from typing import List, Dict, Set
import structlog
import aiohttp
from bs4 import BeautifulSoup
import re

from app.scanner.tools.base import ToolWrapper

logger = structlog.get_logger()


class AnalyticsRelationshipsWrapper(ToolWrapper):
    """Wrapper for analyticsRelationships tool"""
    
    def __init__(self):
        super().__init__("analyticsrelationships", timeout=300)
    
    def get_command(self, ga_code: str) -> List[str]:
        return [
            self.tool_name,
            "-id", ga_code
        ]
    
    def parse_output(self, output: str) -> List[str]:
        """Parse related domains from output"""
        domains = []
        for line in output.splitlines():
            line = line.strip()
            if line and '.' in line and not line.startswith('#'):
                domains.append(line)
        return domains


class AnalyticsTracker:
    """
    Tracks related domains via Google Analytics codes
    Extracts GA codes from pages and finds related domains
    """
    
    def __init__(self, config, rate_limiter):
        self.config = config
        self.rate_limiter = rate_limiter
        self.logger = logger.bind(tool="google_analytics")
        
        self.analytics_tool = AnalyticsRelationshipsWrapper()
    
    async def track(
        self,
        subdomains: List[str]
    ) -> List[str]:
        """
        Find related domains via Google Analytics
        
        Args:
            subdomains: List of subdomains to analyze
        
        Returns:
            List of related domains
        """
        if not subdomains:
            return []
        
        self.logger.info("Starting Google Analytics tracking", targets=len(subdomains))
        
        ga_codes = set()
        related_domains = set()
        
        try:
            # Phase 1: Extract GA codes from subdomains
            for subdomain in subdomains[:50]:  # Limit to 50 subdomains
                codes = await self._extract_ga_codes(subdomain)
                ga_codes.update(codes)
            
            self.logger.info("Extracted GA codes", count=len(ga_codes))
            
            # Phase 2: Find related domains for each GA code
            for ga_code in list(ga_codes)[:10]:  # Limit to 10 GA codes
                try:
                    await self.rate_limiter.acquire(tool="analytics")
                    result = await self.analytics_tool.run(ga_code)
                    
                    if result.success:
                        related_domains.update(result.results)
                        self.logger.info(
                            "Found related domains",
                            ga_code=ga_code,
                            domains=len(result.results)
                        )
                except Exception as e:
                    self.logger.warning(
                        "Analytics tracking failed for code",
                        ga_code=ga_code,
                        error=str(e)
                    )
            
            self.logger.info(
                "Google Analytics tracking complete",
                total_domains=len(related_domains)
            )
            
            return list(related_domains)
        
        except Exception as e:
            self.logger.error("Google Analytics tracking failed", error=str(e))
            return []
    
    async def _extract_ga_codes(self, subdomain: str) -> Set[str]:
        """Extract Google Analytics codes from a subdomain"""
        codes = set()
        
        for protocol in ["https", "http"]:
            url = f"{protocol}://{subdomain}"
            
            try:
                await self.rate_limiter.acquire(tool="http_request")
                
                async with aiohttp.ClientSession() as session:
                    async with session.get(
                        url,
                        timeout=aiohttp.ClientTimeout(total=10),
                        allow_redirects=True
                    ) as response:
                        if response.status == 200:
                            html = await response.text()
                            
                            # Look for GA tracking codes
                            # Format: UA-XXXXXXXX-X or G-XXXXXXXXXX
                            ua_pattern = r'UA-\d+-\d+'
                            g_pattern = r'G-[A-Z0-9]+'
                            
                            ua_codes = re.findall(ua_pattern, html)
                            g_codes = re.findall(g_pattern, html)
                            
                            codes.update(ua_codes)
                            codes.update(g_codes)
                            
                            if codes:
                                break  # Found codes, no need to try http
            
            except Exception as e:
                self.logger.debug(
                    "Failed to extract GA codes",
                    url=url,
                    error=str(e)
                )
        
        return codes
