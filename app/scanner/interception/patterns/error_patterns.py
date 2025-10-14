"""
Error Pattern Matcher

Detects error conditions, stack traces, and debug information leakage.
"""

import re
from typing import Dict, Any, List, Optional
import structlog

logger = structlog.get_logger()


class ErrorPatternMatcher:
    """Detects errors and information leakage in HTTP responses"""
    
    def __init__(self):
        self.logger = logger.bind(component="error_patterns")
        
        # Stack trace patterns for different languages
        self.stack_trace_patterns = {
            "java": [
                re.compile(r'at\s+[\w\.$]+\([^)]*\)', re.MULTILINE),
                re.compile(r'Exception in thread', re.IGNORECASE),
                re.compile(r'java\.[\w\.]+Exception', re.IGNORECASE),
            ],
            "python": [
                re.compile(r'Traceback \(most recent call last\)', re.IGNORECASE),
                re.compile(r'File "([^"]+)", line (\d+)', re.MULTILINE),
                re.compile(r'\w+Error: .*', re.MULTILINE),
            ],
            "php": [
                re.compile(r'Fatal error:.*in\s+([^\s]+)\s+on line\s+(\d+)', re.IGNORECASE),
                re.compile(r'Warning:.*in\s+([^\s]+)\s+on line\s+(\d+)', re.IGNORECASE),
                re.compile(r'Parse error:.*', re.IGNORECASE),
            ],
            "nodejs": [
                re.compile(r'at\s+[\w\.<>]+\s+\([^)]*\)', re.MULTILINE),
                re.compile(r'Error:\s+.*', re.MULTILINE),
                re.compile(r'at\s+async\s+', re.IGNORECASE),
            ],
            "dotnet": [
                re.compile(r'at\s+[\w\.]+\.[^\s]+\(.*\)\s+in', re.MULTILINE),
                re.compile(r'System\.[\w\.]+Exception', re.IGNORECASE),
                re.compile(r'\.cs:line\s+\d+', re.IGNORECASE),
            ]
        }
        
        # Debug information patterns
        self.debug_patterns = [
            re.compile(r'DEBUG\s*[:=]?\s*true', re.IGNORECASE),
            re.compile(r'--debug', re.IGNORECASE),
            re.compile(r'X-Debug-Token', re.IGNORECASE),
            re.compile(r'Xdebug', re.IGNORECASE),
        ]
        
        # Framework version patterns
        self.version_patterns = [
            re.compile(r'(Laravel|Symfony|Django|Flask|Express|Spring)\s*v?(\d+\.\d+\.\d+)', re.IGNORECASE),
            re.compile(r'PHP/(\d+\.\d+\.\d+)', re.IGNORECASE),
            re.compile(r'Python/(\d+\.\d+\.\d+)', re.IGNORECASE),
        ]
    
    def match(self, traffic_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Match error patterns in traffic"""
        response = traffic_data.get("response")
        if not response:
            return None
        
        status_code = response.get("status_code")
        content = response.get("content")
        headers = response.get("headers", {})
        
        findings = []
        
        # Check for error status codes
        if status_code and status_code >= 500:
            findings.append({
                "type": "server_error",
                "severity": "high",
                "description": f"Server error status: {status_code}",
                "status_code": status_code
            })
        
        if not content:
            return {"findings": findings} if findings else None
        
        # Decode content
        try:
            text = content.decode('utf-8', errors='ignore')
        except:
            text = str(content)
        
        # Check for stack traces
        for language, patterns in self.stack_trace_patterns.items():
            for pattern in patterns:
                if pattern.search(text):
                    findings.append({
                        "type": "stack_trace",
                        "severity": "critical",
                        "description": f"{language.title()} stack trace detected",
                        "language": language
                    })
                    break  # One per language is enough
        
        # Check for debug information
        for pattern in self.debug_patterns:
            matches = pattern.findall(text)
            if matches:
                findings.append({
                    "type": "debug_info",
                    "severity": "medium",
                    "description": "Debug information detected",
                    "matches": len(matches)
                })
                break
        
        # Extract framework versions
        for pattern in self.version_patterns:
            matches = pattern.findall(text)
            for match in matches:
                findings.append({
                    "type": "version_disclosure",
                    "severity": "low",
                    "description": f"Framework version disclosed: {match}",
                    "version_info": match
                })
        
        return {"findings": findings} if findings else None
