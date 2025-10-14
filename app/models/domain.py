"""
Domain and subdomain models for target tracking
These models represent the reconnaissance targets
"""

from sqlalchemy import Column, String, Integer, DateTime, Boolean, ForeignKey, Text, Index
from sqlalchemy.orm import relationship
from datetime import datetime
from app.core.database import Base


class Domain(Base):
    """Root domain being analyzed"""
    __tablename__ = "domains"
    
    id = Column(Integer, primary_key=True)
    domain = Column(String(255), unique=True, nullable=False, index=True)
    
    # Tracking information
    added_at = Column(DateTime, default=datetime.utcnow)
    last_scanned = Column(DateTime)
    scan_count = Column(Integer, default=0)
    
    # Authorization and scope
    is_authorized = Column(Boolean, default=False)  # Explicit authorization to scan
    scan_profile = Column(String(50), default="passive")
    notes = Column(Text)
    
    # Infrastructure information discovered
    registrar = Column(String(255))
    nameservers = Column(Text)  # JSON array of nameservers
    mx_records = Column(Text)  # JSON array of MX records
    
    # Company relationship
    company_id = Column(Integer, ForeignKey("companies.id"))
    
    # Relationships
    subdomains = relationship("Subdomain", back_populates="parent_domain", cascade="all, delete-orphan")
    scan_jobs = relationship("ScanJob", back_populates="domain", cascade="all, delete-orphan")
    company = relationship("Company", back_populates="domains")
    temporal_patterns = relationship("TemporalPattern", back_populates="domain", cascade="all, delete-orphan")
    spatial_patterns = relationship("SpatialPattern", back_populates="domain", cascade="all, delete-orphan")
    behavioral_patterns = relationship("BehavioralPattern", back_populates="domain", cascade="all, delete-orphan")
    # Note: Use AttackChain model from app.models.vulnerability for vulnerability chains
    predictive_analyses = relationship("PredictiveAnalysis", back_populates="domain", cascade="all, delete-orphan")
    attack_graphs = relationship("AttackGraph", back_populates="domain", cascade="all, delete-orphan")
    
    # Create indexes for common queries
    __table_args__ = (
        Index("idx_domain_authorized", "is_authorized"),
        Index("idx_domain_last_scan", "last_scanned"),
        Index("idx_domain_company", "company_id"),
    )


class Subdomain(Base):
    """Discovered subdomains of a root domain"""
    __tablename__ = "subdomains"
    
    id = Column(Integer, primary_key=True)
    subdomain = Column(String(255), nullable=False)
    domain_id = Column(Integer, ForeignKey("domains.id", ondelete="CASCADE"))
    
    # Discovery metadata
    discovered_at = Column(DateTime, default=datetime.utcnow)
    discovery_method = Column(String(50))  # CT_logs, DNS_brute, crawl, etc.
    discovery_sources = Column(Text)  # JSON array of all sources that found this subdomain
    recursion_level = Column(Integer, default=0)  # Depth in recursive enumeration
    
    # Resolution information
    resolves = Column(Boolean, default=False)
    ip_addresses = Column(Text)  # JSON array of resolved IPs
    cname_chain = Column(Text)  # JSON array showing CNAME resolution
    
    # Service identification
    has_http = Column(Boolean, default=False)
    has_https = Column(Boolean, default=False)
    http_status = Column(Integer)
    https_status = Column(Integer)
    
    # Content information
    title = Column(String(500))
    server_header = Column(String(255))
    technologies = Column(Text)  # JSON array of identified technologies
    
    # Relationships
    parent_domain = relationship("Domain", back_populates="subdomains")
    ip_associations = relationship("SubdomainIP", back_populates="subdomain", cascade="all, delete-orphan")
    http_traffic = relationship("HTTPTraffic", back_populates="subdomain", cascade="all, delete-orphan")
    favicon_hashes = relationship("FaviconHash", back_populates="subdomain", cascade="all, delete-orphan")
    temporal_patterns = relationship("TemporalPattern", back_populates="subdomain", cascade="all, delete-orphan")
    behavioral_patterns = relationship("BehavioralPattern", back_populates="subdomain", cascade="all, delete-orphan")
    predictive_analyses = relationship("PredictiveAnalysis", back_populates="subdomain", cascade="all, delete-orphan")
    
    # Unique constraint to prevent duplicates
    __table_args__ = (
        Index("idx_subdomain_domain", "subdomain", "domain_id", unique=True),
        Index("idx_subdomain_resolves", "resolves"),
        Index("idx_subdomain_recursion", "recursion_level"),
    )


class FaviconHash(Base):
    """Favicon hashes for technology fingerprinting"""
    __tablename__ = "favicon_hashes"
    
    id = Column(Integer, primary_key=True)
    subdomain_id = Column(Integer, ForeignKey("subdomains.id", ondelete="CASCADE"))
    
    # Hash information
    hash = Column(String(64), nullable=False, index=True)  # MD5 or mmh3 hash
    hash_type = Column(String(20), default="mmh3")  # mmh3, md5
    
    # Technology identification
    technology = Column(String(100))  # Identified technology/framework
    framework = Column(String(100))  # Framework if applicable
    confidence = Column(Integer)  # 0-100 confidence score
    
    # Discovery metadata
    discovered_at = Column(DateTime, default=datetime.utcnow)
    favicon_url = Column(String(500))
    
    # Relationships
    subdomain = relationship("Subdomain", back_populates="favicon_hashes")
    
    __table_args__ = (
        Index("idx_favicon_hash", "hash"),
        Index("idx_favicon_subdomain", "subdomain_id"),
        Index("idx_favicon_technology", "technology"),
    )
