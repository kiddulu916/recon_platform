"""
DNS brute-forcing using PureDNS
High-performance DNS resolution with wildcard filtering
"""

from typing import List
import structlog
from pathlib import Path
import tempfile

from app.scanner.tools.base import ToolWrapper

logger = structlog.get_logger()


class PureDNSWrapper(ToolWrapper):
    """Wrapper for PureDNS tool"""
    
    def __init__(self, resolvers_file: str):
        super().__init__("puredns", timeout=1800)  # 30 minutes for large wordlists
        self.resolvers_file = resolvers_file
    
    def get_command(
        self,
        domain: str,
        wordlist: str,
        output_file: str
    ) -> List[str]:
        return [
            self.tool_name,
            "bruteforce",
            wordlist,
            domain,
            "-r", self.resolvers_file,
            "-l", "10000",  # Rate limit
            "--wildcard-batch", "1000000",  # Wildcard batch size
            "-w", output_file
        ]
    
    def parse_output(self, output: str) -> List[str]:
        # PureDNS writes results to file, output is progress
        return []


class DNSBruteForcer:
    """
    DNS brute-force scanner using PureDNS
    Uses massive wordlists with intelligent wildcard filtering
    """
    
    def __init__(self, config, rate_limiter):
        self.config = config
        self.rate_limiter = rate_limiter
        self.logger = logger.bind(tool="dns_bruteforce")
        
        # Get paths from config
        tools_dir = Path(config.tools.tools_directory if hasattr(config, 'tools') else "tools")
        self.resolvers_file = str(tools_dir / "resolvers.txt")
        self.wordlist = str(tools_dir / "n0kovo_subdomains_huge.txt")
        
        self.puredns = PureDNSWrapper(self.resolvers_file)
    
    async def bruteforce(self, domain: str) -> List[str]:
        """
        Perform DNS brute-force on domain
        
        Args:
            domain: Target domain
        
        Returns:
            List of resolved subdomains
        """
        self.logger.info("Starting DNS brute-force", domain=domain, wordlist=self.wordlist)
        
        # Check if wordlist exists
        if not Path(self.wordlist).exists():
            self.logger.error("Wordlist not found", path=self.wordlist)
            return []
        
        if not Path(self.resolvers_file).exists():
            self.logger.error("Resolvers file not found", path=self.resolvers_file)
            return []
        
        # Create temp file for output
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            output_file = f.name
        
        try:
            # Run PureDNS
            await self.rate_limiter.acquire(tool="puredns")
            result = await self.puredns.run(domain, self.wordlist, output_file)
            
            # Read results from file
            if Path(output_file).exists():
                subdomains = Path(output_file).read_text().splitlines()
                subdomains = [s.strip() for s in subdomains if s.strip()]
                
                self.logger.info(
                    "DNS brute-force complete",
                    domain=domain,
                    found=len(subdomains)
                )
                
                # Cleanup
                Path(output_file).unlink()
                
                return subdomains
            else:
                self.logger.error("PureDNS output file not found")
                return []
        
        except Exception as e:
            self.logger.error("DNS brute-force failed", error=str(e))
            return []

