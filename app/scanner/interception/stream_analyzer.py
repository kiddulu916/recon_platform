"""
Stream Analyzer for Real-Time Traffic Analysis

Processes traffic as it flows through the proxy, applying pattern matching
and triggering alerts for critical findings.
"""

from typing import Dict, Any, Optional
import asyncio
import structlog

from .patterns.error_patterns import ErrorPatternMatcher
from .patterns.auth_patterns import AuthPatternMatcher
from .patterns.vuln_patterns import VulnPatternMatcher

logger = structlog.get_logger()


class StreamAnalyzer:
    """
    Real-time stream analyzer for HTTP traffic
    
    Analyzes traffic as it flows through the proxy without blocking.
    Triggers immediate alerts for critical findings.
    """
    
    def __init__(self, config, alert_manager=None):
        """
        Initialize stream analyzer
        
        Args:
            config: Application configuration
            alert_manager: Alert manager for notifications
        """
        self.config = config
        self.alert_manager = alert_manager
        self.logger = logger.bind(component="stream_analyzer")
        
        # Initialize pattern matchers
        self.error_matcher = ErrorPatternMatcher()
        self.auth_matcher = AuthPatternMatcher()
        self.vuln_matcher = VulnPatternMatcher()
        
        # Statistics
        self.stats = {
            "analyzed": 0,
            "alerts_generated": 0,
            "errors": 0
        }
    
    def analyze(self, traffic_data: Dict[str, Any]):
        """
        Analyze traffic in real-time (non-blocking)
        
        Args:
            traffic_data: Traffic data from interceptor
        """
        if not self.config.proxy.realtime_analysis_enabled:
            return
        
        # Create async task for non-blocking analysis
        asyncio.create_task(self._analyze_async(traffic_data))
    
    async def _analyze_async(self, traffic_data: Dict[str, Any]):
        """
        Async analysis implementation
        
        Args:
            traffic_data: Traffic data to analyze
        """
        try:
            self.stats["analyzed"] += 1
            
            results = {
                "url": traffic_data.get("request", {}).get("url"),
                "timestamp": traffic_data.get("timestamp"),
                "findings": []
            }
            
            # Apply error patterns
            if self.config.proxy.enable_error_detection:
                error_results = self.error_matcher.match(traffic_data)
                if error_results:
                    results["findings"].extend(error_results.get("findings", []))
            
            # Apply auth patterns
            auth_results = self.auth_matcher.match(traffic_data)
            if auth_results:
                results["findings"].extend(auth_results.get("findings", []))
            
            # Apply vulnerability patterns
            if self.config.proxy.enable_vulnerability_patterns:
                vuln_results = self.vuln_matcher.match(traffic_data)
                if vuln_results:
                    results["findings"].extend(vuln_results.get("findings", []))
            
            # Generate alerts for high/critical findings
            if results["findings"] and self.alert_manager:
                await self._generate_alerts(traffic_data, results)
            
            # Log summary
            if results["findings"]:
                self.logger.info(
                    "Stream analysis complete",
                    url=results["url"],
                    findings=len(results["findings"])
                )
        
        except Exception as e:
            self.logger.error("Stream analysis failed", error=str(e))
            self.stats["errors"] += 1
    
    async def _generate_alerts(self, traffic_data: Dict[str, Any], results: Dict[str, Any]):
        """
        Generate alerts for critical findings
        
        Args:
            traffic_data: Original traffic data
            results: Analysis results
        """
        if not self.config.proxy.enable_alerts:
            return
        
        for finding in results["findings"]:
            severity = finding.get("severity", "low")
            
            # Only alert on high/critical
            if severity in ["high", "critical"]:
                await self.alert_manager.create_alert(
                    traffic_data=traffic_data,
                    alert_type=finding.get("type"),
                    severity=severity,
                    title=finding.get("description"),
                    details=finding
                )
                
                self.stats["alerts_generated"] += 1
    
    def get_stats(self) -> Dict[str, Any]:
        """Get analyzer statistics"""
        return self.stats.copy()
