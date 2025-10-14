"""
GitLab-subdomains tool wrapper for finding subdomains from GitLab
"""

from app.scanner.tools.base import ToolWrapper
from typing import List


class GitlabSubdomainsWrapper(ToolWrapper):
    """Wrapper for gitlab-subdomains tool"""
    
    def __init__(self, gitlab_token: str = None):
        super().__init__("gitlab-subdomains", timeout=300)
        self.gitlab_token = gitlab_token
    
    def get_command(self, domain: str) -> List[str]:
        cmd = [
            self.tool_name,
            "-d", domain
        ]
        
        # Add token if available
        if self.gitlab_token:
            cmd.extend(["-t", self.gitlab_token])
        
        return cmd
    
    def parse_output(self, output: str) -> List[str]:
        subdomains = []
        for line in output.splitlines():
            line = line.strip()
            if line and not line.startswith('#'):
                subdomains.append(line)
        return subdomains
