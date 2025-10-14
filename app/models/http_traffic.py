"""
HTTP traffic capture and analysis models
Critical for identifying vulnerabilities through traffic patterns
"""

from sqlalchemy import Column, String, Integer, DateTime, Boolean, ForeignKey, Text, Index, LargeBinary, Float
from sqlalchemy.orm import relationship
from datetime import datetime
from app.core.database import Base


class HTTPTraffic(Base):
    """Captured HTTP requests and responses"""
    __tablename__ = "http_traffic"
    
    id = Column(Integer, primary_key=True)
    subdomain_id = Column(Integer, ForeignKey("subdomains.id", ondelete="CASCADE"))
    
    # Request information
    method = Column(String(10), nullable=False)
    url = Column(Text, nullable=False)
    path = Column(String(500))
    query_params = Column(Text)  # JSON object of parameters
    
    # Request headers and body
    request_headers = Column(Text)  # JSON object
    request_body = Column(LargeBinary)  # Compressed binary data
    request_content_type = Column(String(100))
    
    # Response information
    status_code = Column(Integer)
    response_headers = Column(Text)  # JSON object
    response_body = Column(LargeBinary)  # Compressed binary data
    response_content_type = Column(String(100))
    response_size = Column(Integer)
    
    # Timing information
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    response_time_ms = Column(Integer)  # Response time in milliseconds
    
    # Analysis metadata
    scanner_module = Column(String(50))  # Which module initiated this request
    scan_purpose = Column(String(100))  # What the scan was trying to discover
    
    # Security indicators
    has_error = Column(Boolean, default=False)
    error_type = Column(String(50))  # SQL, XSS, XXE, etc.
    contains_sensitive_data = Column(Boolean, default=False)
    sensitive_data_types = Column(Text)  # JSON array of types found
    
    # Authentication and session
    requires_auth = Column(Boolean, default=False)
    auth_type = Column(String(50))  # Bearer, Basic, Cookie, etc.
    session_id = Column(String(255))  # To track session-based sequences
    
    # Phase 3: Enhanced fields for deep analysis
    # SSL/TLS Certificate information
    certificate_validation_errors = Column(Text)  # JSON array of validation errors
    certificate_fingerprint = Column(String(64))  # SHA256 fingerprint
    certificate_issuer = Column(String(255))
    certificate_subject = Column(String(255))
    
    # Request correlation and chaining
    correlation_id = Column(String(36), index=True)  # UUID for request grouping
    parent_traffic_id = Column(Integer, ForeignKey("http_traffic.id"))  # For redirects/chains
    redirect_chain = Column(Text)  # JSON array of redirect URLs
    
    # Analysis results
    is_analyzed = Column(Boolean, default=False, index=True)
    analysis_results = Column(Text)  # JSON of comprehensive analysis findings
    extracted_urls = Column(Text)  # JSON array of URLs found in response
    extracted_api_endpoints = Column(Text)  # JSON array of API endpoints
    sensitive_patterns_matched = Column(Text)  # JSON array of matched patterns
    
    # Relationships
    subdomain = relationship("Subdomain", back_populates="http_traffic")
    vulnerabilities = relationship("HTTPVulnerability", back_populates="http_traffic")
    children = relationship("HTTPTraffic", backref="parent", remote_side=[id])
    
    __table_args__ = (
        Index("idx_http_subdomain", "subdomain_id"),
        Index("idx_http_status", "status_code"),
        Index("idx_http_timestamp", "timestamp"),
        Index("idx_http_error", "has_error"),
        Index("idx_http_session", "session_id"),
        Index("idx_http_correlation", "correlation_id"),
        Index("idx_http_analyzed", "is_analyzed"),
    )


class APIEndpoint(Base):
    """Discovered API endpoints and their characteristics"""
    __tablename__ = "api_endpoints"
    
    id = Column(Integer, primary_key=True)
    subdomain_id = Column(Integer, ForeignKey("subdomains.id", ondelete="CASCADE"))
    
    # Endpoint information
    path = Column(String(500), nullable=False)
    method = Column(String(10))
    api_type = Column(String(30))  # REST, GraphQL, SOAP, etc.
    version = Column(String(20))
    
    # Parameters and structure
    parameters = Column(Text)  # JSON schema of parameters
    request_schema = Column(Text)  # JSON schema for requests
    response_schema = Column(Text)  # JSON schema for responses
    
    # Authentication
    requires_auth = Column(Boolean, default=False)
    auth_methods = Column(Text)  # JSON array of supported auth methods
    
    # Documentation
    documented = Column(Boolean, default=False)
    documentation_url = Column(String(500))
    description = Column(Text)
    
    # Security analysis
    rate_limited = Column(Boolean)
    allows_cors = Column(Boolean)
    cors_origins = Column(Text)  # JSON array of allowed origins
    exposes_sensitive_data = Column(Boolean, default=False)
    
    # Discovery metadata
    discovered_at = Column(DateTime, default=datetime.utcnow)
    discovery_method = Column(String(50))
    last_tested = Column(DateTime)
    
    __table_args__ = (
        Index("idx_api_subdomain_path", "subdomain_id", "path", unique=True),
        Index("idx_api_type", "api_type"),
    )


class HTTPTrafficWAL(Base):
    """Write-Ahead Log for HTTP traffic capture
    
    Provides immediate persistence before structured processing.
    This ensures no traffic is lost even if processing fails.
    """
    __tablename__ = "http_traffic_wal"
    
    id = Column(Integer, primary_key=True)
    wal_id = Column(String(36), unique=True, nullable=False, index=True)  # UUID
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    
    # Raw serialized data (msgpack format)
    raw_data = Column(LargeBinary, nullable=False)
    
    # Processing status
    processed = Column(Boolean, default=False, index=True)
    processing_attempts = Column(Integer, default=0)
    last_processing_attempt = Column(DateTime)
    error_message = Column(Text)
    
    # Link to processed record (once moved to HTTPTraffic)
    http_traffic_id = Column(Integer, ForeignKey("http_traffic.id"))
    
    __table_args__ = (
        Index("idx_wal_processed", "processed", "timestamp"),
    )


class SensitiveDataPattern(Base):
    """Patterns for detecting sensitive data in HTTP traffic
    
    Configurable patterns for identifying API keys, tokens, credentials,
    PII, and other sensitive information in requests/responses.
    """
    __tablename__ = "sensitive_data_patterns"
    
    id = Column(Integer, primary_key=True)
    
    # Pattern identification
    pattern_name = Column(String(100), nullable=False, unique=True)
    pattern_regex = Column(Text, nullable=False)
    pattern_type = Column(String(50), nullable=False)  # api_key, jwt, password, credit_card, etc.
    
    # Pattern metadata
    description = Column(Text)
    severity = Column(String(20), default="medium")  # low, medium, high, critical
    false_positive_likelihood = Column(String(20), default="low")
    
    # Pattern behavior
    active = Column(Boolean, default=True, index=True)
    case_sensitive = Column(Boolean, default=True)
    multiline = Column(Boolean, default=False)
    
    # Detection settings
    min_entropy = Column(Float)  # Minimum entropy for secret detection
    context_required = Column(Text)  # JSON array of context keywords
    exclusion_patterns = Column(Text)  # JSON array of patterns to exclude
    
    # Usage tracking
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    matches_count = Column(Integer, default=0)  # Track how often pattern matches
    last_matched = Column(DateTime)
    
    __table_args__ = (
        Index("idx_sensitive_data_pattern_type", "pattern_type"),
        Index("idx_sensitive_data_pattern_active", "active"),
    )


class TrafficAnalysisRule(Base):
    """Rules for real-time traffic analysis
    
    Defines conditions and actions for analyzing HTTP traffic patterns.
    Used for error detection, authentication tracking, vulnerability indicators.
    """
    __tablename__ = "traffic_analysis_rules"
    
    id = Column(Integer, primary_key=True)
    
    # Rule identification
    rule_name = Column(String(100), nullable=False, unique=True)
    rule_type = Column(String(50), nullable=False)  # error_detection, auth_tracking, vuln_indicator, etc.
    description = Column(Text)
    
    # Rule condition (JSON specification)
    condition = Column(Text, nullable=False)  # JSON: {status_code: 500, content_type: "text/html", ...}
    
    # Rule action (JSON specification)
    action = Column(Text, nullable=False)  # JSON: {type: "alert", severity: "high", ...}
    
    # Rule configuration
    priority = Column(Integer, default=50)  # Lower number = higher priority
    active = Column(Boolean, default=True, index=True)
    
    # Match criteria
    match_on_request = Column(Boolean, default=False)
    match_on_response = Column(Boolean, default=True)
    match_requires_all_conditions = Column(Boolean, default=True)  # AND vs OR logic
    
    # Rate limiting
    max_alerts_per_minute = Column(Integer, default=10)
    cooldown_seconds = Column(Integer, default=60)
    
    # Usage tracking
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    matches_count = Column(Integer, default=0)
    last_matched = Column(DateTime)
    
    __table_args__ = (
        Index("idx_rule_type", "rule_type"),
        Index("idx_rule_active", "active"),
        Index("idx_rule_priority", "priority"),
    )


class TrafficAlert(Base):
    """Real-time alerts generated from traffic analysis
    
    Stores alerts triggered by analysis rules for immediate review.
    """
    __tablename__ = "traffic_alerts"
    
    id = Column(Integer, primary_key=True)
    
    # Alert source
    http_traffic_id = Column(Integer, ForeignKey("http_traffic.id", ondelete="CASCADE"))
    rule_id = Column(Integer, ForeignKey("traffic_analysis_rules.id"))
    pattern_id = Column(Integer, ForeignKey("sensitive_data_patterns.id"))
    
    # Alert details
    alert_type = Column(String(50), nullable=False)  # error, sensitive_data, vulnerability, etc.
    severity = Column(String(20), nullable=False)  # low, medium, high, critical
    title = Column(String(500), nullable=False)
    description = Column(Text)
    
    # Evidence
    matched_content = Column(Text)  # What triggered the alert
    context = Column(Text)  # JSON with additional context
    
    # Status
    status = Column(String(20), default="new", index=True)  # new, reviewed, false_positive, acknowledged
    reviewed_at = Column(DateTime)
    reviewed_by = Column(String(100))
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    
    # Relationships
    http_traffic = relationship("HTTPTraffic")
    rule = relationship("TrafficAnalysisRule")
    pattern = relationship("SensitiveDataPattern")
    
    __table_args__ = (
        Index("idx_alert_status", "status", "created_at"),
        Index("idx_alert_severity", "severity"),
        Index("idx_alert_type", "alert_type"),
    )
