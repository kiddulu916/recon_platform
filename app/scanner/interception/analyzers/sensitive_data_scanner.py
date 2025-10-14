"""
Sensitive Data Scanner

Detects sensitive information in HTTP traffic:
- API keys (AWS, Google, GitHub, etc.)
- JWT tokens
- Passwords
- Credit cards
- SSNs
- Private keys
- Email addresses
- Phone numbers

Uses pattern matching and entropy analysis.
"""

import re
import math
from typing import List, Dict, Any, Optional, Set
from collections import Counter
import structlog

logger = structlog.get_logger()


class SensitiveDataScanner:
    """
    Scans for sensitive data patterns in HTTP traffic
    
    Uses regex patterns and entropy analysis to identify secrets.
    """
    
    def __init__(self):
        self.logger = logger.bind(component="sensitive_data_scanner")
        
        # Precompiled patterns for common secrets
        self.patterns = {
            # API Keys
            "aws_access_key": {
                "pattern": re.compile(r'AKIA[0-9A-Z]{16}'),
                "severity": "critical",
                "min_entropy": 4.0
            },
            "aws_secret_key": {
                "pattern": re.compile(r'aws_secret_access_key["\']?\s*[:=]\s*["\']?([A-Za-z0-9/+=]{40})["\']?', re.IGNORECASE),
                "severity": "critical",
                "min_entropy": 4.5
            },
            "google_api_key": {
                "pattern": re.compile(r'AIza[0-9A-Za-z\-_]{35}'),
                "severity": "high",
                "min_entropy": 4.0
            },
            "github_token": {
                "pattern": re.compile(r'gh[ps]_[a-zA-Z0-9]{36}'),
                "severity": "critical",
                "min_entropy": 4.0
            },
            "github_oauth": {
                "pattern": re.compile(r'gho_[a-zA-Z0-9]{36}'),
                "severity": "critical",
                "min_entropy": 4.0
            },
            "slack_token": {
                "pattern": re.compile(r'xox[baprs]-([0-9a-zA-Z]{10,48})'),
                "severity": "high",
                "min_entropy": 4.0
            },
            "stripe_key": {
                "pattern": re.compile(r'sk_live_[0-9a-zA-Z]{24}'),
                "severity": "critical",
                "min_entropy": 4.0
            },
            
            # JWT Tokens
            "jwt": {
                "pattern": re.compile(r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*'),
                "severity": "medium",
                "min_entropy": 4.5
            },
            
            # Generic API Key patterns
            "generic_api_key": {
                "pattern": re.compile(r'(?:api[_-]?key|apikey|access[_-]?token)["\']?\s*[:=]\s*["\']?([a-zA-Z0-9\-_]{20,})["\']?', re.IGNORECASE),
                "severity": "high",
                "min_entropy": 4.0
            },
            
            # Private Keys
            "rsa_private_key": {
                "pattern": re.compile(r'-----BEGIN RSA PRIVATE KEY-----'),
                "severity": "critical",
                "min_entropy": 3.0
            },
            "openssh_private_key": {
                "pattern": re.compile(r'-----BEGIN OPENSSH PRIVATE KEY-----'),
                "severity": "critical",
                "min_entropy": 3.0
            },
            "pgp_private_key": {
                "pattern": re.compile(r'-----BEGIN PGP PRIVATE KEY BLOCK-----'),
                "severity": "critical",
                "min_entropy": 3.0
            },
            
            # Authentication
            "basic_auth": {
                "pattern": re.compile(r'Basic\s+([A-Za-z0-9+/=]{20,})'),
                "severity": "high",
                "min_entropy": 3.5
            },
            "bearer_token": {
                "pattern": re.compile(r'Bearer\s+([A-Za-z0-9\-._~+/]+=*)'),
                "severity": "medium",
                "min_entropy": 4.0
            },
            
            # Password patterns
            "password": {
                "pattern": re.compile(r'(?:password|passwd|pwd)["\']?\s*[:=]\s*["\']([^"\']{8,})["\']', re.IGNORECASE),
                "severity": "critical",
                "min_entropy": 3.0
            },
            
            # Credit Cards
            "credit_card": {
                "pattern": re.compile(r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})\b'),
                "severity": "critical",
                "min_entropy": 2.5
            },
            
            # Social Security Numbers
            "ssn": {
                "pattern": re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),
                "severity": "critical",
                "min_entropy": 2.0
            },
            
            # Email addresses
            "email": {
                "pattern": re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
                "severity": "low",
                "min_entropy": 2.5
            },
            
            # Phone numbers (US format)
            "phone_us": {
                "pattern": re.compile(r'\b(?:\+?1[-.]?)?\(?([0-9]{3})\)?[-.]?([0-9]{3})[-.]?([0-9]{4})\b'),
                "severity": "low",
                "min_entropy": 2.0
            },
            
            # IP Addresses (private ranges - potentially sensitive)
            "private_ip": {
                "pattern": re.compile(r'\b(?:10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.)\d{1,3}\.\d{1,3}\b'),
                "severity": "low",
                "min_entropy": 1.5
            }
        }
    
    def scan(
        self,
        request_body: Optional[bytes],
        response_body: Optional[bytes],
        request_headers: Optional[Dict[str, str]],
        response_headers: Optional[Dict[str, str]]
    ) -> Dict[str, Any]:
        """
        Scan for sensitive data
        
        Args:
            request_body: Request body content
            response_body: Response body content
            request_headers: Request headers
            response_headers: Response headers
        
        Returns:
            Dictionary with scan results
        """
        findings = []
        
        # Scan request body
        if request_body:
            body_findings = self._scan_content(request_body, "request_body")
            findings.extend(body_findings)
        
        # Scan response body
        if response_body:
            body_findings = self._scan_content(response_body, "response_body")
            findings.extend(body_findings)
        
        # Scan request headers
        if request_headers:
            header_findings = self._scan_headers(request_headers, "request_headers")
            findings.extend(header_findings)
        
        # Scan response headers
        if response_headers:
            header_findings = self._scan_headers(response_headers, "response_headers")
            findings.extend(header_findings)
        
        # Deduplicate and summarize
        findings = self._deduplicate_findings(findings)
        summary = self._summarize_findings(findings)
        
        return {
            "has_sensitive_data": len(findings) > 0,
            "findings": findings,
            "summary": summary,
            "severity_counts": self._count_by_severity(findings)
        }
    
    def _scan_content(self, content: bytes, location: str) -> List[Dict[str, Any]]:
        """Scan content for sensitive patterns"""
        findings = []
        
        try:
            # Decode content
            text = content.decode('utf-8', errors='ignore')
            
            # Apply all patterns
            for pattern_name, pattern_info in self.patterns.items():
                matches = pattern_info["pattern"].finditer(text)
                
                for match in matches:
                    matched_text = match.group(0)
                    
                    # Check entropy if required
                    entropy = self._calculate_entropy(matched_text)
                    if entropy < pattern_info["min_entropy"]:
                        continue
                    
                    # Mask the sensitive value
                    masked_value = self._mask_value(matched_text)
                    
                    findings.append({
                        "type": pattern_name,
                        "severity": pattern_info["severity"],
                        "location": location,
                        "matched_value": masked_value,
                        "position": match.start(),
                        "entropy": round(entropy, 2),
                        "context": self._extract_context(text, match.start(), match.end())
                    })
        
        except Exception as e:
            self.logger.error("Content scanning failed", error=str(e))
        
        return findings
    
    def _scan_headers(self, headers: Dict[str, str], location: str) -> List[Dict[str, Any]]:
        """Scan headers for sensitive patterns"""
        findings = []
        
        sensitive_header_names = [
            'authorization', 'x-api-key', 'api-key', 'x-auth-token',
            'x-access-token', 'cookie', 'set-cookie', 'x-csrf-token'
        ]
        
        for header_name, header_value in headers.items():
            header_lower = header_name.lower()
            
            # Check for known sensitive headers
            if any(sensitive in header_lower for sensitive in sensitive_header_names):
                findings.append({
                    "type": f"sensitive_header_{header_lower.replace('-', '_')}",
                    "severity": "medium",
                    "location": location,
                    "matched_value": f"{header_name}: {self._mask_value(header_value)}",
                    "entropy": self._calculate_entropy(header_value),
                    "context": f"Header: {header_name}"
                })
            
            # Apply patterns to header values
            for pattern_name, pattern_info in self.patterns.items():
                matches = pattern_info["pattern"].finditer(header_value)
                
                for match in matches:
                    matched_text = match.group(0)
                    
                    findings.append({
                        "type": pattern_name,
                        "severity": pattern_info["severity"],
                        "location": f"{location}.{header_name}",
                        "matched_value": self._mask_value(matched_text),
                        "entropy": self._calculate_entropy(matched_text),
                        "context": f"Header: {header_name}"
                    })
        
        return findings
    
    def _calculate_entropy(self, data: str) -> float:
        """
        Calculate Shannon entropy of data
        
        Higher entropy indicates more randomness (characteristic of secrets)
        """
        if not data:
            return 0.0
        
        # Count character frequencies
        counts = Counter(data)
        total = len(data)
        
        # Calculate entropy
        entropy = 0.0
        for count in counts.values():
            probability = count / total
            entropy -= probability * math.log2(probability)
        
        return entropy
    
    def _mask_value(self, value: str, show_chars: int = 4) -> str:
        """Mask sensitive value, showing only first/last few characters"""
        if len(value) <= show_chars * 2:
            return "*" * len(value)
        
        return f"{value[:show_chars]}...{value[-show_chars:]}"
    
    def _extract_context(self, text: str, start: int, end: int, context_size: int = 50) -> str:
        """Extract surrounding context for a match"""
        context_start = max(0, start - context_size)
        context_end = min(len(text), end + context_size)
        
        context = text[context_start:context_end]
        
        # Replace the actual match with placeholder
        match_len = end - start
        context = context.replace(text[start:end], "[REDACTED]")
        
        return context.strip()
    
    def _deduplicate_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Remove duplicate findings"""
        seen = set()
        unique = []
        
        for finding in findings:
            # Create a key for deduplication
            key = (
                finding["type"],
                finding["location"],
                finding.get("position", 0)
            )
            
            if key not in seen:
                seen.add(key)
                unique.append(finding)
        
        return unique
    
    def _summarize_findings(self, findings: List[Dict[str, Any]]) -> Dict[str, List[str]]:
        """Create summary of findings by type"""
        summary = {}
        
        for finding in findings:
            finding_type = finding["type"]
            if finding_type not in summary:
                summary[finding_type] = []
            
            summary[finding_type].append(finding["location"])
        
        return summary
    
    def _count_by_severity(self, findings: List[Dict[str, Any]]) -> Dict[str, int]:
        """Count findings by severity level"""
        counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0
        }
        
        for finding in findings:
            severity = finding.get("severity", "low")
            if severity in counts:
                counts[severity] += 1
        
        return counts
