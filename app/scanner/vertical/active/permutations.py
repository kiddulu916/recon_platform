"""
Subdomain permutation generation using GoTator
Creates intelligent variations of known subdomains
"""

from typing import List
import structlog
from pathlib import Path
import tempfile

from app.scanner.tools.base import ToolWrapper

logger = structlog.get_logger()


class GoTatorWrapper(ToolWrapper):
    """Wrapper for GoTator permutation tool"""
    
    def __init__(self):
        super().__init__("gotator", timeout=60)
    
    def get_command(
        self,
        input_file: str,
        output_file: str,
        depth: int = 1
    ) -> List[str]:
        return [
            self.tool_name,
            "-sub", input_file,
            "-depth", str(depth),
            "-silent"
        ]
    
    def parse_output(self, output: str) -> List[str]:
        permutations = []
        for line in output.splitlines():
            line = line.strip()
            if line:
                permutations.append(line)
        return permutations


class PureDNSResolverWrapper(ToolWrapper):
    """Wrapper for PureDNS in resolve mode"""
    
    def __init__(self, resolvers_file: str):
        super().__init__("puredns", timeout=600)
        self.resolvers_file = resolvers_file
    
    def get_command(
        self,
        input_file: str,
        output_file: str
    ) -> List[str]:
        return [
            self.tool_name,
            "resolve",
            input_file,
            "-r", self.resolvers_file,
            "-w", output_file
        ]
    
    def parse_output(self, output: str) -> List[str]:
        return []


class SubdomainPermuter:
    """
    Generates and resolves subdomain permutations
    Uses GoTator for generation and PureDNS for resolution
    """
    
    def __init__(self, config, rate_limiter):
        self.config = config
        self.rate_limiter = rate_limiter
        self.logger = logger.bind(tool="permutations")
        
        # Get resolvers file
        tools_dir = Path(config.tools.tools_directory if hasattr(config, 'tools') else "tools")
        self.resolvers_file = str(tools_dir / "resolvers.txt")
        
        self.gotator = GoTatorWrapper()
        self.puredns_resolver = PureDNSResolverWrapper(self.resolvers_file)
    
    async def generate_and_resolve(
        self,
        domain: str,
        known_subdomains: List[str]
    ) -> List[str]:
        """
        Generate permutations and resolve them
        
        Args:
            domain: Base domain
            known_subdomains: List of known subdomains to permute
        
        Returns:
            List of resolved permutations
        """
        if not known_subdomains:
            self.logger.info("No known subdomains for permutation")
            return []
        
        self.logger.info("Starting subdomain permutation", count=len(known_subdomains))
        
        # Create temp files
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            input_file = f.name
            f.write("\n".join(known_subdomains))
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            permutations_file = f.name
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            resolved_file = f.name
        
        try:
            # Step 1: Generate permutations
            await self.rate_limiter.acquire(tool="gotator")
            result = await self.gotator.run(input_file, permutations_file)
            
            if not result.success:
                self.logger.error("GoTator failed", error=result.error)
                return []
            
            permutations = result.results
            self.logger.info("Permutations generated", count=len(permutations))
            
            # Write permutations to file for PureDNS
            Path(permutations_file).write_text("\n".join(permutations))
            
            # Step 2: Resolve permutations
            await self.rate_limiter.acquire(tool="puredns")
            resolve_result = await self.puredns_resolver.run(
                permutations_file,
                resolved_file
            )
            
            # Read resolved subdomains
            if Path(resolved_file).exists():
                resolved = Path(resolved_file).read_text().splitlines()
                resolved = [s.strip() for s in resolved if s.strip()]
                
                self.logger.info(
                    "Permutations resolved",
                    generated=len(permutations),
                    resolved=len(resolved)
                )
                
                # Cleanup
                Path(input_file).unlink()
                Path(permutations_file).unlink()
                Path(resolved_file).unlink()
                
                return resolved
            
            return []
        
        except Exception as e:
            self.logger.error("Permutation failed", error=str(e))
            return []

