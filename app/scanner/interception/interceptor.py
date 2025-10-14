"""
mitmproxy Addon for HTTP Traffic Interception

Hooks into mitmproxy's event system to capture HTTP/HTTPS traffic,
extract context, and trigger real-time analysis.
"""

import json
import uuid
from typing import Optional
from datetime import datetime
from urllib.parse import urlparse
import structlog

from mitmproxy import http, ctx
from mitmproxy.net.http import Headers

from .context_manager import ContextManager, TrafficContext
from .certificate_manager import CertificateManager

logger = structlog.get_logger()


class ReconInterceptor:
    """
    mitmproxy addon for HTTP traffic interception
    
    This addon hooks into mitmproxy's event lifecycle:
    - request: Capture request, extract context
    - response: Capture response, trigger analysis
    - tls_established: Capture certificate details
    - error: Handle connection/request errors
    """
    
    def __init__(self, config, wal_writer, stream_analyzer):
        """
        Initialize the interceptor
        
        Args:
            config: Application configuration
            wal_writer: WAL writer for immediate persistence
            stream_analyzer: Stream analyzer for real-time analysis
        """
        self.config = config
        self.wal_writer = wal_writer
        self.stream_analyzer = stream_analyzer
        self.context_manager = ContextManager()
        self.cert_manager = CertificateManager(config)
        self.logger = logger.bind(component="interceptor")
        
        # Statistics
        self.stats = {
            "requests_captured": 0,
            "responses_captured": 0,
            "errors": 0,
            "tls_connections": 0
        }
    
    def load(self, loader):
        """
        Called when the addon is loaded
        
        Can be used to add custom options to mitmproxy
        """
        self.logger.info("ReconInterceptor addon loaded")
    
    def request(self, flow: http.HTTPFlow):
        """
        Called when a request is received
        
        Args:
            flow: mitmproxy HTTP flow object
        """
        try:
            # Extract context from headers
            headers_dict = dict(flow.request.headers)
            context = self.context_manager.extract_from_headers(headers_dict)
            
            # Store context in flow for later use
            flow.metadata["recon_context"] = context.to_dict() if context else None
            flow.metadata["request_timestamp"] = datetime.utcnow().isoformat()
            
            # Check if we should capture this request
            if not self._should_capture(flow):
                return
            
            self.stats["requests_captured"] += 1
            
            self.logger.debug(
                "Request captured",
                method=flow.request.method,
                url=flow.request.pretty_url,
                correlation_id=context.correlation_id if context else None
            )
        
        except Exception as e:
            self.logger.error("Error in request hook", error=str(e))
            self.stats["errors"] += 1
    
    def response(self, flow: http.HTTPFlow):
        """
        Called when a response is received
        
        This is where we capture the complete request/response pair
        and trigger analysis.
        
        Args:
            flow: mitmproxy HTTP flow object
        """
        try:
            # Check if we should capture this request
            if not self._should_capture(flow):
                return
            
            # Get stored context
            context_dict = flow.metadata.get("recon_context")
            context = TrafficContext.from_dict(context_dict) if context_dict else None
            
            # Calculate response time
            request_time = flow.metadata.get("request_timestamp")
            response_time_ms = None
            if request_time:
                request_dt = datetime.fromisoformat(request_time)
                response_dt = datetime.utcnow()
                response_time_ms = int((response_dt - request_dt).total_seconds() * 1000)
            
            # Build traffic data structure
            traffic_data = self._build_traffic_data(flow, context, response_time_ms)
            
            # Write to WAL for immediate persistence
            if self.wal_writer:
                self.wal_writer.write(traffic_data)
            
            # Trigger real-time stream analysis
            if self.stream_analyzer and self.config.proxy.realtime_analysis_enabled:
                self.stream_analyzer.analyze(traffic_data)
            
            self.stats["responses_captured"] += 1
            
            self.logger.debug(
                "Response captured",
                url=flow.request.pretty_url,
                status=flow.response.status_code,
                size=len(flow.response.content) if flow.response.content else 0,
                response_time_ms=response_time_ms
            )
        
        except Exception as e:
            self.logger.error("Error in response hook", error=str(e), url=flow.request.pretty_url)
            self.stats["errors"] += 1
    
    def tls_established(self, data):
        """
        Called when a TLS connection is established
        
        Captures certificate details for security analysis.
        
        Args:
            data: TLS connection data
        """
        try:
            if not hasattr(data, 'conn') or not hasattr(data.conn, 'certificate_list'):
                return
            
            conn = data.conn
            if not conn.certificate_list:
                return
            
            # Extract certificate information
            cert_chain = []
            for cert in conn.certificate_list:
                cert_info = self.cert_manager.extract_cert_info(cert.to_pem().encode())
                cert_chain.append(cert_info)
            
            # Store in connection metadata
            if hasattr(data, 'context'):
                data.context.cert_chain = cert_chain
            
            self.stats["tls_connections"] += 1
            
            if cert_chain:
                self.logger.debug(
                    "TLS established",
                    sni=conn.sni if hasattr(conn, 'sni') else None,
                    cert_subject=cert_chain[0].get("subject"),
                    cert_issuer=cert_chain[0].get("issuer")
                )
        
        except Exception as e:
            self.logger.error("Error in tls_established hook", error=str(e))
            self.stats["errors"] += 1
    
    def error(self, flow: http.HTTPFlow):
        """
        Called when an error occurs
        
        Args:
            flow: mitmproxy HTTP flow object
        """
        try:
            error_msg = str(flow.error) if flow.error else "Unknown error"
            
            self.logger.warning(
                "Flow error",
                url=flow.request.pretty_url if flow.request else "unknown",
                error=error_msg
            )
            
            # Still try to capture partial data for analysis
            if flow.request and self._should_capture(flow):
                context_dict = flow.metadata.get("recon_context")
                context = TrafficContext.from_dict(context_dict) if context_dict else None
                
                traffic_data = self._build_traffic_data(flow, context, None, error=error_msg)
                
                if self.wal_writer:
                    self.wal_writer.write(traffic_data)
            
            self.stats["errors"] += 1
        
        except Exception as e:
            self.logger.error("Error in error hook", error=str(e))
    
    def _should_capture(self, flow: http.HTTPFlow) -> bool:
        """
        Determine if this request should be captured
        
        Args:
            flow: mitmproxy HTTP flow object
        
        Returns:
            True if should capture, False otherwise
        """
        if not flow.request:
            return False
        
        # Check content type filtering
        if flow.response and flow.response.headers:
            content_type = flow.response.headers.get("content-type", "")
            for ignored in self.config.proxy.ignored_content_types:
                if content_type.startswith(ignored):
                    return False
        
        # Check if we only capture subdomain traffic
        if self.config.proxy.capture_only_subdomains:
            # Only capture if context is present (indicates scanner-initiated)
            context_dict = flow.metadata.get("recon_context")
            if not context_dict:
                return False
        
        return True
    
    def _build_traffic_data(
        self,
        flow: http.HTTPFlow,
        context: Optional[TrafficContext],
        response_time_ms: Optional[int],
        error: Optional[str] = None
    ) -> dict:
        """
        Build traffic data structure from flow
        
        Args:
            flow: mitmproxy HTTP flow object
            context: Traffic context
            response_time_ms: Response time in milliseconds
            error: Error message if any
        
        Returns:
            Dictionary with traffic data
        """
        # Parse URL
        parsed_url = urlparse(flow.request.pretty_url)
        
        # Build base structure
        traffic_data = {
            "id": str(uuid.uuid4()),
            "timestamp": datetime.utcnow().isoformat(),
            
            # Request
            "request": {
                "method": flow.request.method,
                "url": flow.request.pretty_url,
                "scheme": flow.request.scheme,
                "host": flow.request.host,
                "port": flow.request.port,
                "path": flow.request.path,
                "query_params": dict(flow.request.query) if flow.request.query else {},
                "headers": dict(flow.request.headers),
                "content": flow.request.content,
                "content_type": flow.request.headers.get("content-type"),
            },
            
            # Response (if available)
            "response": None,
            
            # Timing
            "response_time_ms": response_time_ms,
            
            # Context
            "context": context.to_dict() if context else {},
            
            # Error
            "error": error,
            
            # Certificate info (if HTTPS)
            "certificate": None
        }
        
        # Add response data if available
        if flow.response:
            traffic_data["response"] = {
                "status_code": flow.response.status_code,
                "reason": flow.response.reason,
                "headers": dict(flow.response.headers),
                "content": flow.response.content,
                "content_type": flow.response.headers.get("content-type"),
                "size": len(flow.response.content) if flow.response.content else 0
            }
        
        # Add certificate data if HTTPS
        if flow.request.scheme == "https" and hasattr(flow.server_conn, 'cert_chain'):
            cert_chain = getattr(flow.server_conn, 'cert_chain', None)
            if cert_chain:
                traffic_data["certificate"] = cert_chain
        
        return traffic_data
    
    def get_stats(self) -> dict:
        """Get interceptor statistics"""
        return self.stats.copy()
