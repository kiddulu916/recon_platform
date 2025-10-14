"""
ASN lookup using bgp.he.net
Discovers ASN numbers and associated IP ranges
"""

from typing import List, Dict, Optional
import structlog
import aiohttp
from bs4 import BeautifulSoup
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
import json
import re

from app.models.network import ASN, IPAddress

logger = structlog.get_logger()


class ASNLookup:
    """
    Discovers ASN information using bgp.he.net
    Extracts ASN numbers, organizations, and IP ranges
    """
    
    def __init__(self, config, rate_limiter):
        self.config = config
        self.rate_limiter = rate_limiter
        self.logger = logger.bind(tool="asn_lookup")
    
    async def lookup(
        self,
        session: AsyncSession,
        domain: str,
        domain_id: int
    ) -> List[Dict]:
        """
        Lookup ASN information for a domain
        
        Args:
            session: Database session
            domain: Target domain
            domain_id: Domain ID in database
        
        Returns:
            List of discovered ASN records
        """
        self.logger.info("Starting ASN lookup", domain=domain)
        
        try:
            # Step 1: Resolve domain to IP
            ip_address = await self._resolve_domain(domain)
            if not ip_address:
                self.logger.warning("Could not resolve domain", domain=domain)
                return []
            
            # Step 2: Lookup ASN for IP
            asn_info = await self._lookup_asn_for_ip(ip_address)
            if not asn_info:
                self.logger.warning("Could not find ASN", ip=ip_address)
                return []
            
            # Step 3: Get IP ranges for ASN
            ip_ranges = await self._get_asn_prefixes(asn_info["asn_number"])
            asn_info["ip_ranges"] = ip_ranges
            
            # Step 4: Save ASN to database
            asn_record = await self._save_asn(session, asn_info)
            
            await session.commit()
            
            self.logger.info(
                "ASN lookup complete",
                asn=asn_info["asn_number"],
                org=asn_info["organization"],
                prefixes=len(ip_ranges)
            )
            
            return [asn_info]
            
        except Exception as e:
            self.logger.error("ASN lookup failed", error=str(e))
            return []
    
    async def _resolve_domain(self, domain: str) -> Optional[str]:
        """Resolve domain to IP address using aiodns"""
        import aiodns
        
        try:
            resolver = aiodns.DNSResolver()
            result = await resolver.query(domain, 'A')
            if result:
                return result[0].host
        except Exception as e:
            self.logger.error("DNS resolution failed", domain=domain, error=str(e))
        return None
    
    async def _lookup_asn_for_ip(self, ip: str) -> Optional[Dict]:
        """Lookup ASN information for an IP using bgp.he.net"""
        await self.rate_limiter.acquire(tool="bgp.he.net")
        
        url = f"https://bgp.he.net/ip/{ip}"
        
        try:
            async with aiohttp.ClientSession() as http_session:
                async with http_session.get(url) as response:
                    if response.status == 200:
                        html = await response.text()
                        return self._parse_asn_page(html)
        except Exception as e:
            self.logger.error("Failed to lookup ASN", ip=ip, error=str(e))
        return None
    
    def _parse_asn_page(self, html: str) -> Optional[Dict]:
        """Parse bgp.he.net page to extract ASN information"""
        soup = BeautifulSoup(html, 'html.parser')
        
        try:
            # Find ASN number
            asn_link = soup.find('a', href=re.compile(r'/AS\d+'))
            if not asn_link:
                return None
            
            asn_text = asn_link.text.strip()
            asn_match = re.search(r'AS(\d+)', asn_text)
            if not asn_match:
                return None
            
            asn_number = int(asn_match.group(1))
            
            # Find organization name
            org_div = soup.find('div', id='header')
            organization = "Unknown"
            if org_div:
                # Extract organization from the page
                org_text = org_div.get_text()
                org_match = re.search(r'AS\d+\s+(.+)', org_text)
                if org_match:
                    organization = org_match.group(1).strip()
            
            return {
                "asn_number": asn_number,
                "organization": organization,
                "discovery_source": "bgp.he.net"
            }
            
        except Exception as e:
            self.logger.error("Failed to parse ASN page", error=str(e))
            return None
    
    async def _get_asn_prefixes(self, asn_number: int) -> List[str]:
        """Get IP prefixes for an ASN"""
        await self.rate_limiter.acquire(tool="bgp.he.net")
        
        url = f"https://bgp.he.net/AS{asn_number}#_prefixes"
        
        try:
            async with aiohttp.ClientSession() as http_session:
                async with http_session.get(url) as response:
                    if response.status == 200:
                        html = await response.text()
                        return self._parse_prefixes(html)
        except Exception as e:
            self.logger.error("Failed to get ASN prefixes", asn=asn_number, error=str(e))
        return []
    
    def _parse_prefixes(self, html: str) -> List[str]:
        """Parse IP prefixes from bgp.he.net ASN page"""
        soup = BeautifulSoup(html, 'html.parser')
        prefixes = []
        
        try:
            # Find table with prefixes
            tables = soup.find_all('table', id='table_prefixes4')
            for table in tables:
                rows = table.find_all('tr')
                for row in rows[1:]:  # Skip header
                    cells = row.find_all('td')
                    if cells:
                        prefix = cells[0].get_text().strip()
                        if '/' in prefix:
                            prefixes.append(prefix)
            
            self.logger.info(f"Found {len(prefixes)} prefixes")
            
        except Exception as e:
            self.logger.error("Failed to parse prefixes", error=str(e))
        
        return prefixes
    
    async def _save_asn(self, session: AsyncSession, asn_info: Dict) -> ASN:
        """Save ASN to database"""
        # Check if ASN exists
        result = await session.execute(
            select(ASN).where(ASN.asn_number == asn_info["asn_number"])
        )
        asn_record = result.scalar_one_or_none()
        
        if not asn_record:
            asn_record = ASN(
                asn_number=asn_info["asn_number"],
                organization=asn_info["organization"],
                ip_ranges=json.dumps(asn_info.get("ip_ranges", [])),
                discovery_source=asn_info["discovery_source"]
            )
            session.add(asn_record)
            await session.flush()
        else:
            # Update IP ranges if we have new ones
            existing_ranges = json.loads(asn_record.ip_ranges) if asn_record.ip_ranges else []
            new_ranges = asn_info.get("ip_ranges", [])
            combined_ranges = list(set(existing_ranges + new_ranges))
            asn_record.ip_ranges = json.dumps(combined_ranges)
        
        return asn_record

