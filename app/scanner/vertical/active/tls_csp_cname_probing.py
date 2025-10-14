"""
TLS, CSP, and CNAME probing
Extracts subdomains from TLS certificates, CSP headers, and CNAME records
"""

from typing import List, Set
import structlog
from pathlib import Path
import tempfile

from app.scanner.tools.base import ToolWrapper

logger = structlog.get_logger()


class CeroWrapper(ToolWrapper):
    """Wrapper for Cero TLS certificate enumeration"""
    
    def __init__(self):
        super().__init__("cero", timeout=300)
    
    def get_command(self, domain: str) -> List[str]:
        return [
            self.tool_name,
            domain
        ]
    
    def parse_output(self, output: str) -> List[str]:
        """Parse subdomains from certificate SANs"""
        subdomains = []
        for line in output.splitlines():
            line = line.strip()
            if line and '.' in line and not line.startswith('#'):
                # Remove wildcards
                subdomain = line.replace('*.', '')
                if subdomain:
                    subdomains.append(subdomain)
        return subdomains


class HttpxCSPWrapper(ToolWrapper):
    """Wrapper for httpx CSP header extraction"""
    
    def __init__(self):
        super().__init__("httpx", timeout=300)
    
    def get_command(self, targets_file: str, output_file: str) -> List[str]:
        return [
            self.tool_name,
            "-l", targets_file,
            "-csp-probe",  # Extract CSP headers
            "-json",
            "-o", output_file,
            "-silent"
        ]
    
    def parse_output(self, output: str) -> List[str]:
        """Extract domains from CSP headers"""
        import json
        import re
        domains = set()
        
        for line in output.splitlines():
            if line.strip():
                try:
                    data = json.loads(line)
                    csp = data.get("csp", "")
                    
                    if csp:
                        # Extract domains from CSP directives
                        # Look for patterns like: https://example.com or *.example.com
                        domain_pattern = r'https?://([a-zA-Z0-9][-a-zA-Z0-9]*\.)+[a-zA-Z]{2,}'
                        matches = re.findall(domain_pattern, csp)
                        
                        for match in matches:
                            # Clean up
                            domain = match.replace('*.', '').rstrip('/')
                            if domain:
                                domains.add(domain)
                
                except:
                    pass
        
        return list(domains)


class DnsxCNAMEWrapper(ToolWrapper):
    """Wrapper for dnsx CNAME probing"""
    
    def __init__(self):
        super().__init__("dnsx", timeout=300)
    
    def get_command(self, targets_file: str, output_file: str) -> List[str]:
        return [
            self.tool_name,
            "-l", targets_file,
            "-cname",
            "-resp-only",
            "-o", output_file,
            "-silent"
        ]
    
    def parse_output(self, output: str) -> List[str]:
        """Extract subdomains from CNAME records"""
        subdomains = []
        for line in output.splitlines():
            line = line.strip()
            if line and '.' in line:
                # Remove trailing dot
                subdomain = line.rstrip('.')
                subdomains.append(subdomain)
        return subdomains


class ActiveProbing:
    """
    Active probing for TLS certificates, CSP headers, and CNAME records
    Extracts subdomains from all three sources
    """
    
    def __init__(self, config, rate_limiter):
        self.config = config
        self.rate_limiter = rate_limiter
        self.logger = logger.bind(tool="active_probing")
        
        self.cero = CeroWrapper()
        self.httpx_csp = HttpxCSPWrapper()
        self.dnsx_cname = DnsxCNAMEWrapper()
    
    async def probe(
        self,
        domain: str,
        known_subdomains: List[str] = None
    ) -> List[str]:
        """
        Probe for subdomains via TLS, CSP, and CNAME
        
        Args:
            domain: Base domain
            known_subdomains: Previously discovered subdomains
        
        Returns:
            List of discovered subdomains
        """
        self.logger.info("Starting active probing", domain=domain)
        
        discovered = set()
        
        try:
            # Phase 1: TLS Certificate Probing with Cero
            await self.rate_limiter.acquire(tool="cero")
            cero_result = await self.cero.run(domain)
            
            if cero_result.success:
                discovered.update(cero_result.results)
                self.logger.info("Cero found subdomains", count=len(cero_result.results))
            
            # Phase 2: CSP Header Probing (on known subdomains)
            if known_subdomains:
                with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
                    targets_file = f.name
                    f.write("\n".join(known_subdomains[:100]))  # Limit to 100
                
                with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
                    csp_output = f.name
                
                await self.rate_limiter.acquire(tool="httpx")
                csp_result = await self.httpx_csp.run(targets_file, csp_output)
                
                if csp_result.success:
                    discovered.update(csp_result.results)
                    self.logger.info("CSP probing found domains", count=len(csp_result.results))
                
                # Cleanup
                Path(targets_file).unlink()
                Path(csp_output).unlink()
            
            # Phase 3: CNAME Probing (on known subdomains)
            if known_subdomains:
                with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
                    targets_file = f.name
                    f.write("\n".join(known_subdomains[:200]))  # Limit to 200
                
                with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
                    cname_output = f.name
                
                await self.rate_limiter.acquire(tool="dnsx")
                cname_result = await self.dnsx_cname.run(targets_file, cname_output)
                
                if cname_result.success:
                    discovered.update(cname_result.results)
                    self.logger.info("CNAME probing found subdomains", count=len(cname_result.results))
                
                # Cleanup
                Path(targets_file).unlink()
                Path(cname_output).unlink()
            
            self.logger.info(
                "Active probing complete",
                total=len(discovered)
            )
            
            return list(discovered)
        
        except Exception as e:
            self.logger.error("Active probing failed", error=str(e))
            return []
