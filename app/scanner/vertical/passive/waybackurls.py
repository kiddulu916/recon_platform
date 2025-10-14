"""
Waybackurls tool wrapper for passive URL enumeration from Wayback Machine
"""

from app.scanner.tools.base import ToolWrapper
from typing import List
from urllib.parse import urlparse


class WaybackurlsWrapper(ToolWrapper):
    """Wrapper for waybackurls tool"""
    
    def __init__(self):
        super().__init__("waybackurls", timeout=300)
    
    def get_command(self, domain: str) -> List[str]:
        return [
            self.tool_name,
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
                        # Remove port if present
                        hostname = parsed.netloc.split(':')[0]
                        subdomains.add(hostname)
                except:
                    pass
        return list(subdomains)
