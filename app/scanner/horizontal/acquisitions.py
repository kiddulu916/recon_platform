"""
Acquisition discovery using WhoIsXMLAPI
Finds company subsidiaries and acquired domains
"""

from typing import List, Dict, Optional
import structlog
import aiohttp
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
import json

from app.models.company import Company, CompanyAcquisition
from app.models.domain import Domain

logger = structlog.get_logger()


class AcquisitionDiscovery:
    """
    Discovers company acquisitions and subsidiaries using WhoIsXMLAPI
    """
    
    def __init__(self, config, rate_limiter):
        self.config = config
        self.rate_limiter = rate_limiter
        self.logger = logger.bind(tool="acquisition_discovery")
        self.api_key = config.api_keys.get_key("whoisxml")
    
    async def discover(
        self,
        session: AsyncSession,
        domain: str,
        domain_id: int
    ) -> List[Dict]:
        """
        Discover company acquisitions
        
        Args:
            session: Database session
            domain: Target domain
            domain_id: Domain ID in database
        
        Returns:
            List of discovered companies and acquisitions
        """
        if not self.api_key:
            self.logger.warning("WhoIsXMLAPI key not configured, skipping acquisition discovery")
            return []
        
        self.logger.info("Starting acquisition discovery", domain=domain)
        
        try:
            # Step 1: Get company information for the domain
            company_info = await self._get_company_info(domain)
            if not company_info:
                self.logger.info("No company information found", domain=domain)
                return []
            
            # Step 2: Create or update company record
            company = await self._save_company(session, company_info, domain_id)
            
            # Step 3: Query for acquisitions
            acquisitions = await self._get_acquisitions(company_info["name"])
            
            # Step 4: Save acquisitions to database
            results = []
            for acq_data in acquisitions:
                acquired_company = await self._save_company(session, acq_data["acquired"])
                
                # Create acquisition relationship
                acquisition = CompanyAcquisition(
                    parent_id=company.id,
                    acquired_id=acquired_company.id,
                    acquisition_date=acq_data.get("date"),
                    acquisition_price=acq_data.get("price"),
                    notes=acq_data.get("notes"),
                    source="whoisxml",
                )
                session.add(acquisition)
                
                # If acquired company has domains, add them to scan queue
                if acq_data["acquired"].get("domains"):
                    for acq_domain in acq_data["acquired"]["domains"]:
                        await self._add_domain_if_new(session, acq_domain, acquired_company.id)
                
                results.append({
                    "parent": company_info["name"],
                    "acquired": acq_data["acquired"]["name"],
                    "date": acq_data.get("date"),
                    "domains": acq_data["acquired"].get("domains", [])
                })
            
            await session.commit()
            
            self.logger.info(
                "Acquisition discovery complete",
                company=company_info["name"],
                acquisitions=len(results)
            )
            
            return results
            
        except Exception as e:
            self.logger.error("Acquisition discovery failed", error=str(e))
            return []
    
    async def _get_company_info(self, domain: str) -> Optional[Dict]:
        """Get company information from WhoIsXMLAPI"""
        await self.rate_limiter.acquire(tool="whoisxml")
        
        url = "https://www.whoisxmlapi.com/whoisserver/WhoisService"
        params = {
            "apiKey": self.api_key,
            "domainName": domain,
            "outputFormat": "JSON"
        }
        
        try:
            async with aiohttp.ClientSession() as http_session:
                async with http_session.get(url, params=params) as response:
                    if response.status == 200:
                        data = await response.json()
                        whois_record = data.get("WhoisRecord", {})
                        registrant = whois_record.get("registrant", {})
                        
                        if registrant.get("organization"):
                            return {
                                "name": registrant["organization"],
                                "website": domain,
                                "whois_data": json.dumps(whois_record)
                            }
            return None
        except Exception as e:
            self.logger.error("Failed to get company info", domain=domain, error=str(e))
            return None
    
    async def _get_acquisitions(self, company_name: str) -> List[Dict]:
        """
        Get acquisitions for a company
        Note: This is a placeholder - WhoIsXMLAPI doesn't have a direct
        acquisitions API. In practice, you'd use a service like Crunchbase API,
        or scrape data from sources like Wikipedia/Crunchbase
        """
        # Placeholder - would integrate with actual acquisition data source
        self.logger.info("Acquisition lookup not yet implemented", company=company_name)
        return []
    
    async def _save_company(
        self,
        session: AsyncSession,
        company_info: Dict,
        domain_id: Optional[int] = None
    ) -> Company:
        """Save or update company in database"""
        # Check if company exists
        result = await session.execute(
            select(Company).where(Company.name == company_info["name"])
        )
        company = result.scalar_one_or_none()
        
        if not company:
            company = Company(
                name=company_info["name"],
                website=company_info.get("website"),
                whois_data=company_info.get("whois_data"),
                discovery_source="whoisxml"
            )
            session.add(company)
            await session.flush()
        
        return company
    
    async def _add_domain_if_new(
        self,
        session: AsyncSession,
        domain: str,
        company_id: int
    ):
        """Add domain to database if it doesn't exist"""
        result = await session.execute(
            select(Domain).where(Domain.domain == domain)
        )
        existing = result.scalar_one_or_none()
        
        if not existing:
            new_domain = Domain(
                domain=domain,
                company_id=company_id,
                is_authorized=False,  # Requires manual authorization
                notes="Discovered via acquisition discovery"
            )
            session.add(new_domain)
            self.logger.info("Added new domain from acquisition", domain=domain)

