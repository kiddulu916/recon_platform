"""
Pattern Matchers for Real-Time Traffic Analysis

Provides pattern-based detection for:
- Error conditions and stack traces
- Authentication flows and token management
- Vulnerability indicators
"""

from .error_patterns import ErrorPatternMatcher
from .auth_patterns import AuthPatternMatcher
from .vuln_patterns import VulnPatternMatcher

__all__ = [
    "ErrorPatternMatcher",
    "AuthPatternMatcher",
    "VulnPatternMatcher"
]
