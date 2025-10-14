"""
GitHub-subdomains tool wrapper for finding subdomains from GitHub
"""

from app.scanner.tools.base import ToolWrapper
from typing import List


class GithubSubdomainsWrapper(ToolWrapper):
    """Wrapper for github-subdomains tool"""
    
    def __init__(self, github_token: str = None):
        super().__init__("github-subdomains", timeout=300)
        self.github_token = github_token
    
    def get_command(self, domain: str) -> List[str]:
        cmd = [
            self.tool_name,
            "-d", domain,
            "-raw"
        ]
        
        # Add token if available
        if self.github_token:
            cmd.extend(["-t", self.github_token])
        
        return cmd
    
    def parse_output(self, output: str) -> List[str]:
        subdomains = []
        for line in output.splitlines():
            line = line.strip()
            if line and not line.startswith('#'):
                subdomains.append(line)
        return subdomains
