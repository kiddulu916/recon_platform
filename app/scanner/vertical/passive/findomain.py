"""
Findomain tool wrapper for passive subdomain enumeration
"""

from app.scanner.tools.base import ToolWrapper
from typing import List


class FindomainWrapper(ToolWrapper):
    """Wrapper for findomain tool"""
    
    def __init__(self):
        super().__init__("findomain", timeout=300)
    
    def get_command(self, domain: str) -> List[str]:
        return [
            self.tool_name,
            "-t", domain,
            "-q"  # Quiet mode
        ]
    
    def parse_output(self, output: str) -> List[str]:
        subdomains = []
        for line in output.splitlines():
            line = line.strip()
            if line and not line.startswith('#'):
                subdomains.append(line)
        return subdomains
