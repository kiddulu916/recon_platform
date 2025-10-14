"""
GAU (GetAllUrls) tool wrapper for passive URL enumeration
"""

from app.scanner.tools.base import ToolWrapper
from typing import List
from urllib.parse import urlparse


class GAUWrapper(ToolWrapper):
    """Wrapper for gau (GetAllUrls) tool"""
    
    def __init__(self):
        super().__init__("gau", timeout=300)
    
    def get_command(self, domain: str) -> List[str]:
        return [
            self.tool_name,
            "--subs",  # Include subdomains
            domain
        ]
    
    def parse_output(self, output: str) -> List[str]:
        """Extract unique subdomains from URLs"""
        subdomains = set()
        for line in output.splitlines():
            line = line.strip()
            if line and line.startswith('http'):
                try:
                    parsed = urlparse(line)
                    if parsed.netloc:
                        subdomains.add(parsed.netloc)
                except:
                    pass
        return list(subdomains)
