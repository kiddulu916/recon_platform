"""
Vulnerability Pattern Matcher

Detects indicators of common vulnerabilities.
"""

import re
from typing import Dict, Any, Optional
import structlog

logger = structlog.get_logger()


class VulnPatternMatcher:
    """Detects vulnerability indicators in HTTP traffic"""
    
    def __init__(self):
        self.logger = logger.bind(component="vuln_patterns")
        
        # SQL injection indicators
        self.sql_patterns = [
            re.compile(r'SQL syntax.*MySQL', re.IGNORECASE),
            re.compile(r'Warning.*mysql_', re.IGNORECASE),
            re.compile(r'valid MySQL result', re.IGNORECASE),
            re.compile(r'PostgreSQL.*ERROR', re.IGNORECASE),
            re.compile(r'ORA-\d{4,5}', re.IGNORECASE),
            re.compile(r'Microsoft SQL Server', re.IGNORECASE),
        ]
        
        # XSS reflection patterns
        self.xss_patterns = [
            re.compile(r'<script[^>]*>[^<]*alert\([^)]*\)', re.IGNORECASE),
            re.compile(r'<img[^>]*onerror', re.IGNORECASE),
        ]
        
        # SSRF indicators
        self.ssrf_patterns = [
            re.compile(r'169\.254\.169\.254'),  # AWS metadata
            re.compile(r'metadata\.google\.internal'),  # GCP metadata
            re.compile(r'169\.254\.169\.253'),  # Azure metadata (old)
        ]
        
        # Command injection indicators
        self.cmd_patterns = [
            re.compile(r'sh:\s+.*:\s+command not found', re.IGNORECASE),
            re.compile(r'bash:\s+.*:\s+command not found', re.IGNORECASE),
        ]
        
        # Path traversal indicators
        self.path_traversal_patterns = [
            re.compile(r'(\.\./){2,}'),
            re.compile(r'Failed to open stream.*\.\.'),
        ]
    
    def match(self, traffic_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Match vulnerability patterns"""
        response = traffic_data.get("response")
        if not response:
            return None
        
        content = response.get("content")
        if not content:
            return None
        
        try:
            text = content.decode('utf-8', errors='ignore')
        except:
            text = str(content)
        
        findings = []
        
        # Check SQL injection
        for pattern in self.sql_patterns:
            if pattern.search(text):
                findings.append({
                    "type": "sql_injection_indicator",
                    "severity": "critical",
                    "description": "Possible SQL injection vulnerability - database error exposed"
                })
                break
        
        # Check XSS reflection
        request = traffic_data.get("request", {})
        query_params = request.get("query_params", {})
        for param_name, param_values in query_params.items():
            for param_value in (param_values if isinstance(param_values, list) else [param_values]):
                if param_value and param_value in text:
                    findings.append({
                        "type": "xss_reflection",
                        "severity": "high",
                        "description": f"Parameter '{param_name}' reflected in response",
                        "parameter": param_name
                    })
                    break
        
        # Check SSRF indicators
        for pattern in self.ssrf_patterns:
            if pattern.search(text):
                findings.append({
                    "type": "ssrf_indicator",
                    "severity": "critical",
                    "description": "Possible SSRF - cloud metadata endpoint accessed"
                })
                break
        
        # Check command injection
        for pattern in self.cmd_patterns:
            if pattern.search(text):
                findings.append({
                    "type": "command_injection_indicator",
                    "severity": "critical",
                    "description": "Possible command injection - shell error exposed"
                })
                break
        
        # Check path traversal
        for pattern in self.path_traversal_patterns:
            if pattern.search(text):
                findings.append({
                    "type": "path_traversal_indicator",
                    "severity": "high",
                    "description": "Possible path traversal vulnerability"
                })
                break
        
        return {"findings": findings} if findings else None
