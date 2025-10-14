"""
HTTP probing using httpx
Tests HTTP/HTTPS on discovered services
"""

from typing import List, Dict
import structlog
from sqlalchemy.ext.asyncio import AsyncSession
from pathlib import Path
import tempfile
import json

from app.scanner.tools.base import ToolWrapper
from app.models.domain import Subdomain
from app.models.http_traffic import HTTPTraffic

logger = structlog.get_logger()


class HttpxWrapper(ToolWrapper):
    """Wrapper for httpx HTTP prober"""
    
    def __init__(self):
        super().__init__("httpx", timeout=600)
    
    def get_command(
        self,
        targets_file: str,
        output_file: str
    ) -> List[str]:
        return [
            self.tool_name,
            "-l", targets_file,
            "-o", output_file,
            "-json",
            "-silent",
            "-status-code",
            "-title",
            "-tech-detect",
            "-server",
            "-follow-redirects"
        ]
    
    def parse_output(self, output: str) -> List[Dict]:
        results = []
        for line in output.splitlines():
            if line.strip():
                try:
                    data = json.loads(line)
                    results.append(data)
                except:
                    pass
        return results


class HTTPProber:
    """
    HTTP/HTTPS probing orchestrator
    Tests web services and logs HTTP traffic
    """
    
    def __init__(self, config, rate_limiter):
        self.config = config
        self.rate_limiter = rate_limiter
        self.logger = logger.bind(tool="http_prober")
        
        self.httpx = HttpxWrapper()
    
    async def probe(
        self,
        session: AsyncSession,
        subdomains: List[str],
        domain_id: int
    ) -> List[Dict]:
        """
        Probe HTTP/HTTPS on subdomains
        
        Args:
            session: Database session
            subdomains: List of subdomains to probe
            domain_id: Domain ID in database
        
        Returns:
            List of HTTP probe results
        """
        if not subdomains:
            return []
        
        self.logger.info("Starting HTTP probing", targets=len(subdomains))
        
        # Create temp files
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            targets_file = f.name
            f.write("\n".join(subdomains))
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            output_file = f.name
        
        try:
            # Run httpx
            await self.rate_limiter.acquire(tool="httpx")
            result = await self.httpx.run(targets_file, output_file)
            
            # Parse results
            results = []
            
            if Path(output_file).exists():
                content = Path(output_file).read_text()
                for line in content.splitlines():
                    if line.strip():
                        try:
                            data = json.loads(line)
                            results.append(data)
                        except:
                            pass
            
            self.logger.info("HTTP probing complete", results=len(results))
            
            # Save to database
            await self._save_http_results(session, results, domain_id)
            
            # Cleanup
            Path(targets_file).unlink()
            Path(output_file).unlink()
            
            return results
        
        except Exception as e:
            self.logger.error("HTTP probing failed", error=str(e))
            return []
    
    async def _save_http_results(
        self,
        session: AsyncSession,
        results: List[Dict],
        domain_id: int
    ):
        """Save HTTP probe results to database"""
        from sqlalchemy import select
        
        for result in results:
            try:
                url = result.get("url")
                if not url:
                    continue
                
                # Extract subdomain from URL
                from urllib.parse import urlparse
                parsed = urlparse(url)
                subdomain = parsed.netloc
                
                # Get subdomain record
                db_result = await session.execute(
                    select(Subdomain).where(
                        Subdomain.subdomain == subdomain,
                        Subdomain.domain_id == domain_id
                    )
                )
                subdomain_record = db_result.scalar_one_or_none()
                
                if subdomain_record:
                    # Update subdomain with HTTP info
                    status_code = result.get("status_code")
                    if parsed.scheme == "https":
                        subdomain_record.has_https = True
                        subdomain_record.https_status = status_code
                    else:
                        subdomain_record.has_http = True
                        subdomain_record.http_status = status_code
                    
                    subdomain_record.title = result.get("title")
                    subdomain_record.server_header = result.get("server")
                    subdomain_record.technologies = json.dumps(result.get("tech", []))
                    
                    # Create HTTP traffic log
                    http_traffic = HTTPTraffic(
                        subdomain_id=subdomain_record.id,
                        method="GET",
                        url=url,
                        path=parsed.path,
                        status_code=status_code,
                        response_headers=json.dumps(result.get("headers", {})),
                        scanner_module="httpx",
                        scan_purpose="http_probing"
                    )
                    session.add(http_traffic)
            
            except Exception as e:
                self.logger.warning("Failed to save HTTP result", error=str(e))
        
        await session.commit()

