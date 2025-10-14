"""
Virtual Host (VHOST) discovery
Finds virtual hosts on IP addresses
"""

from typing import List, Dict
import structlog
from pathlib import Path
import tempfile

from app.scanner.tools.base import ToolWrapper

logger = structlog.get_logger()


class HostHunterWrapper(ToolWrapper):
    """Wrapper for HostHunter VHOST discovery"""
    
    def __init__(self, tools_dir: Path):
        super().__init__("python3", timeout=600)
        self.hosthunter_script = tools_dir / "HostHunter" / "hosthunter.py"
    
    def get_command(self, targets_file: str, output_file: str) -> List[str]:
        return [
            self.tool_name,
            str(self.hosthunter_script),
            "-f", targets_file,
            "-o", output_file
        ]
    
    def parse_output(self, output: str) -> List[str]:
        """Parse HostHunter output for discovered vhosts"""
        vhosts = []
        for line in output.splitlines():
            line = line.strip()
            if line and not line.startswith('#'):
                # Parse format: IP - hostname
                parts = line.split(' - ')
                if len(parts) >= 2:
                    vhosts.append(parts[1].strip())
        return vhosts


class GobusterVHostWrapper(ToolWrapper):
    """Wrapper for Gobuster in VHOST mode"""
    
    def __init__(self):
        super().__init__("gobuster", timeout=600)
    
    def get_command(
        self,
        url: str,
        wordlist: str,
        output_file: str
    ) -> List[str]:
        return [
            self.tool_name,
            "vhost",
            "-u", url,
            "-w", wordlist,
            "-o", output_file,
            "--append-domain",
            "-t", "50",  # Threads
            "-q"  # Quiet
        ]
    
    def parse_output(self, output: str) -> List[str]:
        """Parse gobuster vhost output"""
        vhosts = []
        for line in output.splitlines():
            if "Found:" in line or "Status: 200" in line:
                # Extract vhost from line
                parts = line.split()
                for part in parts:
                    if '.' in part and not part.startswith('http'):
                        vhosts.append(part.strip('[]'))
        return vhosts


class VHOSTDiscovery:
    """
    Discovers virtual hosts on IP addresses
    Uses HostHunter and Gobuster
    """
    
    def __init__(self, config, rate_limiter):
        self.config = config
        self.rate_limiter = rate_limiter
        self.logger = logger.bind(tool="vhost_discovery")
        
        tools_dir = Path(config.tools.tools_directory if hasattr(config, 'tools') else "tools")
        self.hosthunter = HostHunterWrapper(tools_dir)
        self.gobuster = GobusterVHostWrapper()
        
        # Wordlist for gobuster
        self.wordlist = tools_dir / "subdomains-top1000.txt"
    
    async def discover(
        self,
        ips: List[str],
        domain: str
    ) -> List[str]:
        """
        Discover virtual hosts
        
        Args:
            ips: List of IP addresses
            domain: Base domain
        
        Returns:
            List of discovered vhosts
        """
        if not ips:
            return []
        
        self.logger.info("Starting VHOST discovery", ips=len(ips))
        
        discovered_vhosts = set()
        
        try:
            # Phase 1: HostHunter (IP-based)
            with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
                ips_file = f.name
                f.write("\n".join(ips[:50]))  # Limit to 50 IPs
            
            with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
                output_file = f.name
            
            await self.rate_limiter.acquire(tool="hosthunter")
            result = await self.hosthunter.run(ips_file, output_file)
            
            if result.success:
                discovered_vhosts.update(result.results)
                self.logger.info("HostHunter found vhosts", count=len(result.results))
            
            # Cleanup
            Path(ips_file).unlink()
            Path(output_file).unlink()
            
            # Phase 2: Gobuster VHOST fuzzing (domain-based)
            if self.wordlist.exists():
                # Test against first IP only
                if ips:
                    test_url = f"http://{ips[0]}"
                    
                    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
                        gobuster_output = f.name
                    
                    await self.rate_limiter.acquire(tool="gobuster")
                    gb_result = await self.gobuster.run(
                        test_url,
                        str(self.wordlist),
                        gobuster_output
                    )
                    
                    if gb_result.success:
                        discovered_vhosts.update(gb_result.results)
                        self.logger.info("Gobuster found vhosts", count=len(gb_result.results))
                    
                    Path(gobuster_output).unlink()
            
            self.logger.info(
                "VHOST discovery complete",
                total=len(discovered_vhosts)
            )
            
            return list(discovered_vhosts)
        
        except Exception as e:
            self.logger.error("VHOST discovery failed", error=str(e))
            return []
