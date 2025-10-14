"""
Amass tool wrapper for passive subdomain enumeration
"""

from app.scanner.tools.base import ToolWrapper
from typing import List


class AmassWrapper(ToolWrapper):
    """Wrapper for amass tool in passive mode"""
    
    def __init__(self):
        super().__init__("amass", timeout=600)
    
    def get_command(self, domain: str) -> List[str]:
        return [
            self.tool_name,
            "enum",
            "-passive",
            "-d", domain,
            "-timeout", "10"
        ]
    
    def parse_output(self, output: str) -> List[str]:
        subdomains = []
        for line in output.splitlines():
            line = line.strip()
            if line and not line.startswith('['):
                subdomains.append(line)
        return subdomains

