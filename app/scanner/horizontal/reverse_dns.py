"""
Reverse DNS lookup using Mapcidr and Dnsx
Discovers subdomains from IP ranges via PTR records
"""

from typing import List, Dict
import structlog
from sqlalchemy.ext.asyncio import AsyncSession
from pathlib import Path
import tempfile
import json

from app.scanner.tools.base import ToolWrapper
from app.models.domain import Subdomain

logger = structlog.get_logger()


class MapcidrWrapper(ToolWrapper):
    """Wrapper for Mapcidr tool to expand IP ranges"""
    
    def __init__(self):
        super().__init__("mapcidr", timeout=60)
    
    def get_command(self, ip_ranges: List[str], output_file: str) -> List[str]:
        # Write IP ranges to temp file
        input_file = output_file + ".input"
        Path(input_file).write_text("\n".join(ip_ranges))
        
        return [
            self.tool_name,
            "-l", input_file,
            "-o", output_file,
            "-silent"
        ]
    
    def parse_output(self, output: str) -> List[str]:
        return [line.strip() for line in output.splitlines() if line.strip()]


class DnsxWrapper(ToolWrapper):
    """Wrapper for Dnsx tool for PTR lookups"""
    
    def __init__(self):
        super().__init__("dnsx", timeout=300)
    
    def get_command(self, input_file: str, output_file: str) -> List[str]:
        return [
            self.tool_name,
            "-l", input_file,
            "-ptr",
            "-resp-only",
            "-o", output_file,
            "-silent"
        ]
    
    def parse_output(self, output: str) -> List[str]:
        subdomains = []
        for line in output.splitlines():
            line = line.strip()
            if line and not line.startswith(';'):
                # Clean up PTR responses
                subdomain = line.rstrip('.')
                subdomains.append(subdomain)
        return subdomains


class ReverseDNS:
    """
    Performs reverse DNS lookups on IP ranges
    Uses Mapcidr to expand ranges and Dnsx for PTR queries
    """
    
    def __init__(self, config, rate_limiter):
        self.config = config
        self.rate_limiter = rate_limiter
        self.logger = logger.bind(tool="reverse_dns")
        self.mapcidr = MapcidrWrapper()
        self.dnsx = DnsxWrapper()
    
    async def enumerate(
        self,
        session: AsyncSession,
        ip_ranges: List[str],
        domain_id: int
    ) -> List[str]:
        """
        Perform reverse DNS enumeration on IP ranges
        
        Args:
            session: Database session
            ip_ranges: List of CIDR ranges
            domain_id: Domain ID in database
        
        Returns:
            List of discovered subdomains
        """
        if not ip_ranges:
            self.logger.info("No IP ranges provided for reverse DNS")
            return []
        
        self.logger.info("Starting reverse DNS enumeration", ranges=len(ip_ranges))
        
        try:
            # Step 1: Expand IP ranges using Mapcidr
            with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
                expanded_ips_file = f.name
            
            # Run mapcidr
            result = await self.mapcidr.run(ip_ranges, expanded_ips_file)
            
            if not result.success:
                self.logger.error("Mapcidr failed", error=result.error)
                return []
            
            expanded_ips = result.results
            self.logger.info("IP ranges expanded", total_ips=len(expanded_ips))
            
            # Step 2: Perform PTR lookups using Dnsx
            with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
                ptr_output_file = f.name
            
            # Write expanded IPs to input file for dnsx
            Path(expanded_ips_file).write_text("\n".join(expanded_ips))
            
            # Run dnsx
            await self.rate_limiter.acquire(tool="dnsx")
            ptr_result = await self.dnsx.run(expanded_ips_file, ptr_output_file)
            
            if not ptr_result.success:
                self.logger.error("Dnsx failed", error=ptr_result.error)
                return []
            
            subdomains = ptr_result.results
            self.logger.info("PTR records found", count=len(subdomains))
            
            # Step 3: Save subdomains to database
            saved_count = 0
            for subdomain in subdomains:
                try:
                    # Create subdomain record
                    subdomain_record = Subdomain(
                        subdomain=subdomain,
                        domain_id=domain_id,
                        discovery_method="reverse_dns",
                        discovery_sources=json.dumps(["reverse_dns"]),
                        resolves=True  # PTR record means it resolves
                    )
                    session.add(subdomain_record)
                    saved_count += 1
                except Exception as e:
                    self.logger.warning("Failed to save subdomain", subdomain=subdomain, error=str(e))
            
            await session.commit()
            
            self.logger.info(
                "Reverse DNS enumeration complete",
                discovered=len(subdomains),
                saved=saved_count
            )
            
            # Cleanup temp files
            try:
                Path(expanded_ips_file).unlink()
                Path(ptr_output_file).unlink()
            except:
                pass
            
            return subdomains
            
        except Exception as e:
            self.logger.error("Reverse DNS enumeration failed", error=str(e))
            return []

