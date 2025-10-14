"""
API Endpoint Detector

Identifies and characterizes API endpoints from HTTP traffic.
Detects REST, GraphQL, SOAP, and other API patterns.
"""

import re
import json as json_lib
from typing import Dict, Any, Optional, List
from urllib.parse import urlparse, parse_qs
import structlog

logger = structlog.get_logger()


class APIEndpointDetector:
    """
    Detects and analyzes API endpoints
    
    Identifies:
    - REST APIs
    - GraphQL endpoints
    - SOAP services
    - API versioning
    - Parameters and schemas
    """
    
    def __init__(self):
        self.logger = logger.bind(component="api_detector")
        
        # API patterns
        self.rest_patterns = [
            re.compile(r'/api/v?(\d+)/([a-z0-9\-_/]+)', re.IGNORECASE),
            re.compile(r'/rest/v?(\d+)/([a-z0-9\-_/]+)', re.IGNORECASE),
            re.compile(r'/v(\d+)/([a-z0-9\-_/]+)', re.IGNORECASE),
        ]
        
        self.graphql_indicators = [
            'query', 'mutation', 'subscription', '__schema', '__type'
        ]
        
        self.soap_indicators = [
            'soap:Envelope', 'soap:Body', 'xmlns:soap', 'wsdl'
        ]
    
    def detect(
        self,
        method: str,
        url: str,
        path: str,
        request_body: Optional[bytes],
        response_body: Optional[bytes],
        request_content_type: Optional[str],
        response_content_type: Optional[str],
        status_code: Optional[int]
    ) -> Dict[str, Any]:
        """
        Detect if this is an API endpoint and characterize it
        
        Args:
            method: HTTP method
            url: Full URL
            path: URL path
            request_body: Request body content
            response_body: Response body content
            request_content_type: Request Content-Type
            response_content_type: Response Content-Type
            status_code: Response status code
        
        Returns:
            Dictionary with API detection results
        """
        result = {
            "is_api": False,
            "api_type": None,
            "version": None,
            "endpoint_path": None,
            "parameters": {},
            "confidence": 0.0,
            "indicators": []
        }
        
        try:
            # Check REST patterns
            rest_result = self._check_rest_api(method, path, response_content_type)
            if rest_result["is_rest"]:
                result.update({
                    "is_api": True,
                    "api_type": "REST",
                    "version": rest_result["version"],
                    "endpoint_path": rest_result["endpoint_path"],
                    "confidence": rest_result["confidence"],
                    "indicators": rest_result["indicators"]
                })
            
            # Check GraphQL
            graphql_result = self._check_graphql(
                path,
                request_body,
                response_body,
                request_content_type,
                response_content_type
            )
            if graphql_result["is_graphql"]:
                result.update({
                    "is_api": True,
                    "api_type": "GraphQL",
                    "confidence": graphql_result["confidence"],
                    "indicators": graphql_result["indicators"]
                })
            
            # Check SOAP
            soap_result = self._check_soap(
                request_body,
                response_body,
                request_content_type,
                response_content_type
            )
            if soap_result["is_soap"]:
                result.update({
                    "is_api": True,
                    "api_type": "SOAP",
                    "confidence": soap_result["confidence"],
                    "indicators": soap_result["indicators"]
                })
            
            # Extract parameters
            if result["is_api"]:
                result["parameters"] = self._extract_parameters(
                    url,
                    request_body,
                    request_content_type
                )
            
            return result
        
        except Exception as e:
            self.logger.error("API detection failed", error=str(e))
            return result
    
    def _check_rest_api(
        self,
        method: str,
        path: str,
        response_content_type: Optional[str]
    ) -> Dict[str, Any]:
        """Check if this is a REST API endpoint"""
        result = {
            "is_rest": False,
            "version": None,
            "endpoint_path": None,
            "confidence": 0.0,
            "indicators": []
        }
        
        confidence = 0.0
        indicators = []
        
        # Check URL patterns
        for pattern in self.rest_patterns:
            match = pattern.search(path)
            if match:
                result["is_rest"] = True
                result["version"] = match.group(1)
                result["endpoint_path"] = path
                confidence += 0.4
                indicators.append(f"REST pattern matched: {pattern.pattern}")
                break
        
        # Check HTTP method (RESTful methods)
        if method in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']:
            confidence += 0.2
            indicators.append(f"RESTful method: {method}")
        
        # Check response content type
        if response_content_type:
            if 'json' in response_content_type.lower():
                confidence += 0.3
                indicators.append("JSON response")
            elif 'xml' in response_content_type.lower():
                confidence += 0.2
                indicators.append("XML response")
        
        # Check path structure (looks like resource path)
        if self._looks_like_resource_path(path):
            confidence += 0.1
            indicators.append("Resource-like path structure")
        
        result["confidence"] = min(confidence, 1.0)
        result["indicators"] = indicators
        
        if confidence >= 0.5:
            result["is_rest"] = True
        
        return result
    
    def _check_graphql(
        self,
        path: str,
        request_body: Optional[bytes],
        response_body: Optional[bytes],
        request_content_type: Optional[str],
        response_content_type: Optional[str]
    ) -> Dict[str, Any]:
        """Check if this is a GraphQL endpoint"""
        result = {
            "is_graphql": False,
            "confidence": 0.0,
            "indicators": []
        }
        
        confidence = 0.0
        indicators = []
        
        # Check path
        if '/graphql' in path.lower():
            confidence += 0.5
            indicators.append("GraphQL path")
        
        # Check request body
        if request_body:
            try:
                body_str = request_body.decode('utf-8', errors='ignore')
                
                # Check for GraphQL keywords
                for indicator in self.graphql_indicators:
                    if indicator in body_str:
                        confidence += 0.1
                        indicators.append(f"GraphQL keyword: {indicator}")
                
                # Check for GraphQL JSON structure
                try:
                    data = json_lib.loads(body_str)
                    if 'query' in data or 'mutation' in data:
                        confidence += 0.3
                        indicators.append("GraphQL query/mutation structure")
                except:
                    pass
            except:
                pass
        
        # Check response
        if response_body:
            try:
                body_str = response_body.decode('utf-8', errors='ignore')
                
                try:
                    data = json_lib.loads(body_str)
                    if 'data' in data or 'errors' in data:
                        confidence += 0.2
                        indicators.append("GraphQL response structure")
                except:
                    pass
            except:
                pass
        
        result["confidence"] = min(confidence, 1.0)
        result["indicators"] = indicators
        
        if confidence >= 0.5:
            result["is_graphql"] = True
        
        return result
    
    def _check_soap(
        self,
        request_body: Optional[bytes],
        response_body: Optional[bytes],
        request_content_type: Optional[str],
        response_content_type: Optional[str]
    ) -> Dict[str, Any]:
        """Check if this is a SOAP service"""
        result = {
            "is_soap": False,
            "confidence": 0.0,
            "indicators": []
        }
        
        confidence = 0.0
        indicators = []
        
        # Check content types
        if request_content_type:
            if 'soap' in request_content_type.lower():
                confidence += 0.5
                indicators.append("SOAP content type")
            elif 'xml' in request_content_type.lower():
                confidence += 0.1
                indicators.append("XML content type")
        
        # Check request body
        if request_body:
            try:
                body_str = request_body.decode('utf-8', errors='ignore')
                
                for indicator in self.soap_indicators:
                    if indicator in body_str:
                        confidence += 0.2
                        indicators.append(f"SOAP indicator: {indicator}")
            except:
                pass
        
        # Check response body
        if response_body:
            try:
                body_str = response_body.decode('utf-8', errors='ignore')
                
                for indicator in self.soap_indicators:
                    if indicator in body_str:
                        confidence += 0.2
                        indicators.append(f"SOAP indicator in response: {indicator}")
            except:
                pass
        
        result["confidence"] = min(confidence, 1.0)
        result["indicators"] = indicators
        
        if confidence >= 0.5:
            result["is_soap"] = True
        
        return result
    
    def _extract_parameters(
        self,
        url: str,
        request_body: Optional[bytes],
        request_content_type: Optional[str]
    ) -> Dict[str, Any]:
        """Extract API parameters from URL and body"""
        parameters = {
            "query": {},
            "path": [],
            "body": {}
        }
        
        # Extract query parameters
        parsed = urlparse(url)
        if parsed.query:
            parameters["query"] = parse_qs(parsed.query)
        
        # Extract path parameters (numeric IDs, UUIDs)
        path_parts = parsed.path.split('/')
        for part in path_parts:
            # Numeric ID
            if part.isdigit():
                parameters["path"].append({"type": "id", "value": part})
            # UUID
            elif re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', part, re.IGNORECASE):
                parameters["path"].append({"type": "uuid", "value": part})
        
        # Extract body parameters
        if request_body and request_content_type:
            if 'json' in request_content_type.lower():
                try:
                    body_str = request_body.decode('utf-8', errors='ignore')
                    data = json_lib.loads(body_str)
                    parameters["body"] = self._extract_json_schema(data)
                except:
                    pass
        
        return parameters
    
    def _extract_json_schema(self, data: Any, depth: int = 0) -> Dict[str, Any]:
        """Extract simplified JSON schema from data"""
        if depth > 3:  # Limit recursion
            return {"type": "nested"}
        
        if isinstance(data, dict):
            schema = {}
            for key, value in data.items():
                schema[key] = self._extract_json_schema(value, depth + 1)
            return {"type": "object", "properties": schema}
        
        elif isinstance(data, list):
            if data:
                return {"type": "array", "items": self._extract_json_schema(data[0], depth + 1)}
            return {"type": "array"}
        
        elif isinstance(data, bool):
            return {"type": "boolean"}
        
        elif isinstance(data, int):
            return {"type": "integer"}
        
        elif isinstance(data, float):
            return {"type": "number"}
        
        elif isinstance(data, str):
            return {"type": "string"}
        
        elif data is None:
            return {"type": "null"}
        
        else:
            return {"type": "unknown"}
    
    def _looks_like_resource_path(self, path: str) -> bool:
        """Check if path looks like a REST resource path"""
        # Resource paths typically have patterns like:
        # /users, /users/123, /posts/abc/comments
        parts = [p for p in path.split('/') if p]
        
        if len(parts) == 0:
            return False
        
        # Check if alternates between resources and IDs
        has_resource = False
        for part in parts:
            if part.isalpha() or '-' in part or '_' in part:
                has_resource = True
        
        return has_resource
