"""
Authentication Pattern Matcher

Tracks authentication tokens, session management, and auth flows.
"""

import re
from typing import Dict, Any, Optional
import structlog

logger = structlog.get_logger()


class AuthPatternMatcher:
    """Detects authentication patterns and tracks auth state"""
    
    def __init__(self):
        self.logger = logger.bind(component="auth_patterns")
        self.session_store = {}  # In-memory session tracking
    
    def match(self, traffic_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Match authentication patterns"""
        request = traffic_data.get("request", {})
        response = traffic_data.get("response")
        
        findings = []
        
        # Check request headers for auth
        req_headers = request.get("headers", {})
        auth_token = self._extract_auth_token(req_headers)
        if auth_token:
            findings.append({
                "type": "auth_token_sent",
                "severity": "info",
                "description": "Authentication token present in request",
                "token_type": auth_token["type"]
            })
        
        if response:
            resp_headers = response.get("headers", {})
            
            # Check for new tokens in response
            new_token = self._extract_auth_token(resp_headers)
            if new_token:
                findings.append({
                    "type": "auth_token_received",
                    "severity": "info",
                    "description": "New authentication token received",
                    "token_type": new_token["type"]
                })
            
            # Check for session cookies
            set_cookie = resp_headers.get("set-cookie", "")
            if "sessionid" in set_cookie.lower() or "jsessionid" in set_cookie.lower():
                findings.append({
                    "type": "session_cookie_set",
                    "severity": "info",
                    "description": "Session cookie set",
                    "secure": "secure" in set_cookie.lower(),
                    "httponly": "httponly" in set_cookie.lower()
                })
        
        return {"findings": findings} if findings else None
    
    def _extract_auth_token(self, headers: Dict[str, str]) -> Optional[Dict[str, str]]:
        """Extract authentication token from headers"""
        auth_header = headers.get("authorization", "")
        if auth_header:
            if auth_header.startswith("Bearer "):
                return {"type": "bearer", "value": auth_header[7:20] + "..."}
            elif auth_header.startswith("Basic "):
                return {"type": "basic", "value": "***"}
        
        # Check for API key headers
        api_key_headers = ["x-api-key", "api-key", "apikey"]
        for header_name in api_key_headers:
            if header_name in headers:
                return {"type": "api_key", "value": "***"}
        
        return None
