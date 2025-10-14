"""
Assetfinder tool wrapper for passive subdomain enumeration
"""

from app.scanner.tools.base import ToolWrapper
from typing import List


class AssetfinderWrapper(ToolWrapper):
    """Wrapper for assetfinder tool"""
    
    def __init__(self):
        super().__init__("assetfinder", timeout=180)
    
    def get_command(self, domain: str) -> List[str]:
        return [
            self.tool_name,
            "--subs-only",
            domain
        ]
    
    def parse_output(self, output: str) -> List[str]:
        subdomains = []
        for line in output.splitlines():
            line = line.strip()
            if line:
                subdomains.append(line)
        return subdomains

