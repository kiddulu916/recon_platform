"""
Context Manager for HTTP Traffic Tagging

Provides thread-safe context management for tagging HTTP requests with:
- Originating scanner module
- Scan purpose
- Scan job ID
- Domain ID
- Parent request correlation

Uses contextvars for async-safe context storage.
"""

import uuid
from contextvars import ContextVar
from typing import Optional, Dict, Any
from dataclasses import dataclass, asdict
import structlog

logger = structlog.get_logger()


@dataclass
class TrafficContext:
    """Context information for HTTP traffic"""
    
    # Identifiers
    correlation_id: str
    scan_job_id: Optional[int] = None
    domain_id: Optional[int] = None
    subdomain_id: Optional[int] = None
    
    # Scanner metadata
    scanner_module: Optional[str] = None  # horizontal, passive, active, probing
    scan_purpose: Optional[str] = None  # enumeration, probing, crawling, etc.
    
    # Hierarchy
    parent_correlation_id: Optional[str] = None
    depth: int = 0
    
    # Additional metadata
    metadata: Optional[Dict[str, Any]] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TrafficContext":
        """Create from dictionary"""
        return cls(**data)


# Context variable for storing current traffic context
_traffic_context: ContextVar[Optional[TrafficContext]] = ContextVar(
    "traffic_context", 
    default=None
)


class ContextManager:
    """
    Thread-safe context manager for HTTP traffic tagging
    
    Usage:
        # Set context before making HTTP requests
        context_manager.set_context(
            scan_job_id=123,
            domain_id=456,
            scanner_module="http_probing",
            scan_purpose="web_enumeration"
        )
        
        # Make HTTP requests (they'll be tagged with this context)
        response = await http_client.get(url)
        
        # Clear context when done
        context_manager.clear_context()
    """
    
    def __init__(self):
        self.logger = logger.bind(component="context_manager")
    
    def set_context(
        self,
        scan_job_id: Optional[int] = None,
        domain_id: Optional[int] = None,
        subdomain_id: Optional[int] = None,
        scanner_module: Optional[str] = None,
        scan_purpose: Optional[str] = None,
        parent_correlation_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> TrafficContext:
        """
        Set the current traffic context
        
        Returns:
            TrafficContext: The newly created context
        """
        # Generate a unique correlation ID
        correlation_id = str(uuid.uuid4())
        
        # Determine depth based on parent
        depth = 0
        if parent_correlation_id:
            parent = _traffic_context.get()
            if parent:
                depth = parent.depth + 1
        
        # Create context
        context = TrafficContext(
            correlation_id=correlation_id,
            scan_job_id=scan_job_id,
            domain_id=domain_id,
            subdomain_id=subdomain_id,
            scanner_module=scanner_module,
            scan_purpose=scan_purpose,
            parent_correlation_id=parent_correlation_id,
            depth=depth,
            metadata=metadata or {}
        )
        
        # Store in context var
        _traffic_context.set(context)
        
        self.logger.debug(
            "Context set",
            correlation_id=correlation_id,
            scanner_module=scanner_module,
            scan_purpose=scan_purpose
        )
        
        return context
    
    def get_context(self) -> Optional[TrafficContext]:
        """
        Get the current traffic context
        
        Returns:
            TrafficContext or None if no context is set
        """
        return _traffic_context.get()
    
    def clear_context(self):
        """Clear the current traffic context"""
        context = _traffic_context.get()
        if context:
            self.logger.debug("Context cleared", correlation_id=context.correlation_id)
        _traffic_context.set(None)
    
    def update_context(self, **kwargs):
        """
        Update the current context with new values
        
        Args:
            **kwargs: Fields to update
        """
        context = _traffic_context.get()
        if not context:
            self.logger.warning("Cannot update context: no context set")
            return
        
        # Update fields
        for key, value in kwargs.items():
            if hasattr(context, key):
                setattr(context, key, value)
        
        _traffic_context.set(context)
        
        self.logger.debug("Context updated", correlation_id=context.correlation_id)
    
    def create_child_context(
        self,
        scanner_module: Optional[str] = None,
        scan_purpose: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> TrafficContext:
        """
        Create a child context from the current context
        
        Useful for tracking chains of requests (e.g., redirects, resource loading)
        
        Returns:
            TrafficContext: The new child context
        """
        parent = _traffic_context.get()
        
        if not parent:
            self.logger.warning("No parent context to create child from")
            return self.set_context(
                scanner_module=scanner_module,
                scan_purpose=scan_purpose,
                metadata=metadata
            )
        
        # Create child with parent's data
        return self.set_context(
            scan_job_id=parent.scan_job_id,
            domain_id=parent.domain_id,
            subdomain_id=parent.subdomain_id,
            scanner_module=scanner_module or parent.scanner_module,
            scan_purpose=scan_purpose or parent.scan_purpose,
            parent_correlation_id=parent.correlation_id,
            metadata={**(parent.metadata or {}), **(metadata or {})}
        )
    
    def inject_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        """
        Inject context information into HTTP headers
        
        This allows the proxy to associate requests with their context.
        Headers are prefixed with X-Recon- to avoid conflicts.
        
        Args:
            headers: Original headers dictionary
        
        Returns:
            Updated headers with context information
        """
        context = _traffic_context.get()
        if not context:
            return headers
        
        # Create a copy to avoid modifying original
        updated_headers = dict(headers)
        
        # Add context headers
        updated_headers["X-Recon-Correlation-Id"] = context.correlation_id
        
        if context.scan_job_id:
            updated_headers["X-Recon-Scan-Job-Id"] = str(context.scan_job_id)
        
        if context.domain_id:
            updated_headers["X-Recon-Domain-Id"] = str(context.domain_id)
        
        if context.subdomain_id:
            updated_headers["X-Recon-Subdomain-Id"] = str(context.subdomain_id)
        
        if context.scanner_module:
            updated_headers["X-Recon-Scanner-Module"] = context.scanner_module
        
        if context.scan_purpose:
            updated_headers["X-Recon-Scan-Purpose"] = context.scan_purpose
        
        if context.parent_correlation_id:
            updated_headers["X-Recon-Parent-Correlation"] = context.parent_correlation_id
        
        updated_headers["X-Recon-Depth"] = str(context.depth)
        
        return updated_headers
    
    def extract_from_headers(self, headers: Dict[str, str]) -> Optional[TrafficContext]:
        """
        Extract context from HTTP headers
        
        Used by the proxy to reconstruct context from requests.
        
        Args:
            headers: Request headers
        
        Returns:
            TrafficContext or None if no context headers present
        """
        correlation_id = headers.get("X-Recon-Correlation-Id")
        if not correlation_id:
            return None
        
        context = TrafficContext(
            correlation_id=correlation_id,
            scan_job_id=int(headers["X-Recon-Scan-Job-Id"]) 
                if "X-Recon-Scan-Job-Id" in headers else None,
            domain_id=int(headers["X-Recon-Domain-Id"]) 
                if "X-Recon-Domain-Id" in headers else None,
            subdomain_id=int(headers["X-Recon-Subdomain-Id"]) 
                if "X-Recon-Subdomain-Id" in headers else None,
            scanner_module=headers.get("X-Recon-Scanner-Module"),
            scan_purpose=headers.get("X-Recon-Scan-Purpose"),
            parent_correlation_id=headers.get("X-Recon-Parent-Correlation"),
            depth=int(headers.get("X-Recon-Depth", "0"))
        )
        
        return context


# Global instance for easy access
context_manager = ContextManager()
