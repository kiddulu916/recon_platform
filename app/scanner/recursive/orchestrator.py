"""
Recursive enumeration orchestrator
Repeats enumeration workflow on newly discovered subdomains
"""

from typing import List, Set
import structlog
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.models.domain import Subdomain

logger = structlog.get_logger()


class RecursiveEnumerator:
    """
    Orchestrates recursive subdomain enumeration
    Repeats the enumeration workflow on newly discovered subdomains
    Uses Anew-like tracking to prevent infinite loops
    """
    
    def __init__(self, scanner_engine):
        self.scanner_engine = scanner_engine
        self.logger = logger.bind(component="recursive_enum")
        
        # Track visited subdomains to prevent loops
        self.visited: Set[str] = set()
    
    async def enumerate(
        self,
        session: AsyncSession,
        domain_id: int,
        max_depth: int = 2
    ):
        """
        Perform recursive enumeration
        
        Args:
            session: Database session
            domain_id: Domain ID
            max_depth: Maximum recursion depth
        """
        self.logger.info(
            "Starting recursive enumeration",
            max_depth=max_depth
        )
        
        try:
            for level in range(1, max_depth + 1):
                self.logger.info(f"Recursion level {level}/{max_depth}")
                
                # Get subdomains from previous level
                result = await session.execute(
                    select(Subdomain).where(
                        Subdomain.domain_id == domain_id,
                        Subdomain.recursion_level == level - 1
                    )
                )
                subdomains = result.scalars().all()
                
                if not subdomains:
                    self.logger.info(
                        f"No new subdomains at level {level - 1}, stopping recursion"
                    )
                    break
                
                # Filter out already visited subdomains
                new_targets = []
                for subdomain in subdomains:
                    if subdomain.subdomain not in self.visited:
                        new_targets.append(subdomain.subdomain)
                        self.visited.add(subdomain.subdomain)
                
                if not new_targets:
                    self.logger.info("All subdomains already visited, stopping recursion")
                    break
                
                self.logger.info(
                    f"Enumerating {len(new_targets)} new subdomains at level {level}"
                )
                
                # Run enumeration on each new subdomain
                for target in new_targets[:50]:  # Limit to 50 per level to avoid explosion
                    await self._enumerate_subdomain(
                        session,
                        target,
                        domain_id,
                        recursion_level=level
                    )
            
            self.logger.info(
                "Recursive enumeration complete",
                visited=len(self.visited)
            )
        
        except Exception as e:
            self.logger.error("Recursive enumeration failed", error=str(e))
    
    async def _enumerate_subdomain(
        self,
        session: AsyncSession,
        subdomain: str,
        domain_id: int,
        recursion_level: int
    ):
        """
        Enumerate a single subdomain
        Runs passive enumeration only to avoid being too aggressive
        """
        try:
            self.logger.info(
                "Enumerating subdomain",
                subdomain=subdomain,
                level=recursion_level
            )
            
            # Run passive enumeration
            new_subdomains = await self.scanner_engine.run_passive_enumeration(
                session,
                subdomain,
                domain_id,
                recursion_level=recursion_level
            )
            
            self.logger.info(
                "Subdomain enumeration complete",
                subdomain=subdomain,
                discovered=len(new_subdomains)
            )
        
        except Exception as e:
            self.logger.error(
                "Failed to enumerate subdomain",
                subdomain=subdomain,
                error=str(e)
            )
    
    def clear_visited(self):
        """Clear visited tracking (for new scan)"""
        self.visited.clear()
        self.logger.info("Cleared visited subdomains")
    
    def get_stats(self) -> dict:
        """Get recursion statistics"""
        return {
            "visited_count": len(self.visited),
            "visited_subdomains": list(self.visited)[:100]  # Return first 100
        }
