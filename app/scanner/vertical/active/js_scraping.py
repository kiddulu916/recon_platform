"""
JavaScript and source code scraping
Extracts subdomains and URLs from JavaScript files and web pages
"""

from typing import List, Set
import structlog
from pathlib import Path
import tempfile
from sqlalchemy.ext.asyncio import AsyncSession

from app.scanner.tools.base import ToolWrapper
from app.models.http_traffic import HTTPTraffic

logger = structlog.get_logger()


class GospiderWrapper(ToolWrapper):
    """Wrapper for Gospider web crawler"""
    
    def __init__(self):
        super().__init__("gospider", timeout=600)
    
    def get_command(self, targets_file: str, output_file: str) -> List[str]:
        return [
            self.tool_name,
            "-S", targets_file,  # Sites list
            "-o", output_file,  # Output directory
            "--json",
            "-d", "3",  # Depth
            "-c", "10",  # Concurrent requests
            "-t", "20",  # Threads
            "--quiet"
        ]
    
    def parse_output(self, output: str) -> List[str]:
        import json
        urls = []
        for line in output.splitlines():
            if line.strip():
                try:
                    data = json.loads(line)
                    if data.get("output"):
                        urls.append(data["output"])
                except:
                    pass
        return urls


class SecretFinderWrapper(ToolWrapper):
    """Wrapper for SecretFinder to extract secrets from JS"""
    
    def __init__(self, tools_dir: Path):
        super().__init__("python3", timeout=300)
        self.secretfinder_script = tools_dir / "SecretFinder" / "SecretFinder.py"
    
    def get_command(self, url: str) -> List[str]:
        return [
            self.tool_name,
            str(self.secretfinder_script),
            "-i", url,
            "-e"  # Extract endpoints
        ]
    
    def parse_output(self, output: str) -> List[str]:
        """Extract domains and subdomains from output"""
        import re
        domains = set()
        
        # Look for domain patterns in output
        domain_pattern = r'https?://([a-zA-Z0-9][-a-zA-Z0-9]*\.)+[a-zA-Z]{2,}'
        matches = re.findall(domain_pattern, output)
        
        for match in matches:
            domains.add(match.rstrip('.'))
        
        return list(domains)


class JSSourceScraper:
    """
    Scrapes JavaScript files and source code for subdomains
    Orchestrates Gospider, httpx, unfurl, secretfinder, and puredns
    """
    
    def __init__(self, config, rate_limiter):
        self.config = config
        self.rate_limiter = rate_limiter
        self.logger = logger.bind(tool="js_scraping")
        
        tools_dir = Path(config.tools.tools_directory if hasattr(config, 'tools') else "tools")
        self.gospider = GospiderWrapper()
        self.secretfinder = SecretFinderWrapper(tools_dir)
    
    async def scrape(
        self,
        session: AsyncSession,
        subdomains: List[str],
        domain_id: int
    ) -> List[str]:
        """
        Scrape JavaScript and source code for subdomains
        
        Args:
            session: Database session
            subdomains: List of subdomains to crawl
            domain_id: Domain ID
        
        Returns:
            List of discovered subdomains
        """
        if not subdomains:
            return []
        
        self.logger.info("Starting JS scraping", targets=len(subdomains))
        
        discovered = set()
        
        try:
            # Create temp files
            with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
                targets_file = f.name
                # Add http:// and https:// for each subdomain
                targets = []
                for sub in subdomains[:100]:  # Limit to first 100 subdomains
                    targets.append(f"https://{sub}")
                    targets.append(f"http://{sub}")
                f.write("\n".join(targets))
            
            with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
                output_dir = Path(f.name).parent / "gospider_output"
                output_dir.mkdir(exist_ok=True)
            
            # Run Gospider
            await self.rate_limiter.acquire(tool="gospider")
            result = await self.gospider.run(targets_file, str(output_dir))
            
            if result.success:
                # Parse discovered URLs
                urls = result.results
                self.logger.info("Gospider found URLs", count=len(urls))
                
                # Extract subdomains from URLs
                from urllib.parse import urlparse
                for url in urls:
                    try:
                        parsed = urlparse(url)
                        if parsed.netloc:
                            hostname = parsed.netloc.split(':')[0]
                            discovered.add(hostname)
                    except:
                        pass
                
                # Analyze JavaScript files with SecretFinder (sample only)
                js_urls = [url for url in urls if url.endswith('.js')][:20]  # Limit to 20 JS files
                
                for js_url in js_urls:
                    try:
                        await self.rate_limiter.acquire(tool="secretfinder")
                        sf_result = await self.secretfinder.run(js_url)
                        if sf_result.success:
                            discovered.update(sf_result.results)
                    except Exception as e:
                        self.logger.warning("SecretFinder failed for URL", url=js_url, error=str(e))
            
            # Cleanup
            Path(targets_file).unlink()
            
            self.logger.info(
                "JS scraping complete",
                discovered=len(discovered)
            )
            
            return list(discovered)
        
        except Exception as e:
            self.logger.error("JS scraping failed", error=str(e))
            return []
