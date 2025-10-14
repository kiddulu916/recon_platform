"""
Content Analyzer Orchestrator

Coordinates all analyzers to provide comprehensive HTTP traffic analysis.
"""

import json
from typing import Dict, Any, Optional
import structlog

from .url_extractor import URLExtractor
from .api_detector import APIEndpointDetector
from .sensitive_data_scanner import SensitiveDataScanner

logger = structlog.get_logger()


class ContentAnalyzer:
    """
    Orchestrates all content analyzers
    
    Provides unified interface for analyzing HTTP traffic.
    """
    
    def __init__(self):
        self.logger = logger.bind(component="content_analyzer")
        
        # Initialize analyzers
        self.url_extractor = URLExtractor()
        self.api_detector = APIEndpointDetector()
        self.sensitive_scanner = SensitiveDataScanner()
    
    def analyze(self, traffic_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Perform comprehensive analysis of HTTP traffic
        
        Args:
            traffic_data: Traffic data dictionary from interceptor
        
        Returns:
            Dictionary with analysis results
        """
        try:
            request = traffic_data.get("request", {})
            response = traffic_data.get("response")
            
            # Build analysis result
            analysis = {
                "analyzed": True,
                "timestamp": traffic_data.get("timestamp"),
                "url": request.get("url"),
                "method": request.get("method"),
                "status_code": response.get("status_code") if response else None,
                "urls": {},
                "api": {},
                "sensitive_data": {},
                "errors": []
            }
            
            # Extract URLs from response
            if response:
                try:
                    url_results = self.url_extractor.extract(
                        response.get("content"),
                        response.get("content_type"),
                        request.get("url")
                    )
                    analysis["urls"] = url_results
                except Exception as e:
                    self.logger.error("URL extraction failed", error=str(e))
                    analysis["errors"].append(f"URL extraction: {str(e)}")
            
            # Detect API endpoints
            try:
                api_results = self.api_detector.detect(
                    method=request.get("method"),
                    url=request.get("url"),
                    path=request.get("path"),
                    request_body=request.get("content"),
                    response_body=response.get("content") if response else None,
                    request_content_type=request.get("content_type"),
                    response_content_type=response.get("content_type") if response else None,
                    status_code=response.get("status_code") if response else None
                )
                analysis["api"] = api_results
            except Exception as e:
                self.logger.error("API detection failed", error=str(e))
                analysis["errors"].append(f"API detection: {str(e)}")
            
            # Scan for sensitive data
            try:
                sensitive_results = self.sensitive_scanner.scan(
                    request_body=request.get("content"),
                    response_body=response.get("content") if response else None,
                    request_headers=request.get("headers"),
                    response_headers=response.get("headers") if response else None
                )
                analysis["sensitive_data"] = sensitive_results
            except Exception as e:
                self.logger.error("Sensitive data scanning failed", error=str(e))
                analysis["errors"].append(f"Sensitive data scan: {str(e)}")
            
            # Log summary
            self.logger.debug(
                "Analysis complete",
                url=request.get("url"),
                urls_found=analysis["urls"].get("total", 0),
                is_api=analysis["api"].get("is_api", False),
                has_sensitive=analysis["sensitive_data"].get("has_sensitive_data", False)
            )
            
            return analysis
        
        except Exception as e:
            self.logger.error("Analysis failed", error=str(e))
            return {
                "analyzed": False,
                "error": str(e)
            }
    
    def analyze_async(self, traffic_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Async wrapper for analysis
        
        Can be used in async contexts.
        """
        # Currently just calls sync version
        # Could be enhanced for true async processing
        return self.analyze(traffic_data)
