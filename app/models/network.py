"""
Network-related models for IP addresses, ports, and services
These track the infrastructure layer of targets
"""

from sqlalchemy import Column, String, Integer, DateTime, Boolean, ForeignKey, Text, Index
from sqlalchemy.orm import relationship
from datetime import datetime
from app.core.database import Base


class ASN(Base):
    """Autonomous System Number tracking"""
    __tablename__ = "asns"
    
    id = Column(Integer, primary_key=True)
    asn_number = Column(Integer, unique=True, nullable=False, index=True)
    organization = Column(String(255))
    description = Column(Text)
    
    # IP ranges associated with this ASN
    ip_ranges = Column(Text)  # JSON array of CIDR ranges
    
    # Discovery metadata
    discovered_at = Column(DateTime, default=datetime.utcnow)
    last_updated = Column(DateTime, default=datetime.utcnow)
    discovery_source = Column(String(50))  # bgp.he.net, etc.
    
    # Country/Region
    country = Column(String(2))
    
    # Relationships
    ip_addresses = relationship("IPAddress", back_populates="asn_record")
    
    __table_args__ = (
        Index("idx_asn_number", "asn_number"),
        Index("idx_asn_org", "organization"),
    )


class IPAddress(Base):
    """IP addresses discovered during reconnaissance"""
    __tablename__ = "ip_addresses"
    
    id = Column(Integer, primary_key=True)
    ip = Column(String(45), unique=True, nullable=False, index=True)  # Supports IPv6
    version = Column(Integer, default=4)  # 4 or 6
    
    # Infrastructure identification
    asn = Column(Integer)  # ASN number (kept for backwards compatibility)
    asn_id = Column(Integer, ForeignKey("asns.id"))  # Link to ASN record
    asn_org = Column(String(255))
    country = Column(String(2))
    region = Column(String(255))
    city = Column(String(255))
    
    # Cloud provider detection
    cloud_provider = Column(String(50))  # AWS, Azure, GCP, etc.
    cloud_region = Column(String(50))
    is_cdn = Column(Boolean, default=False)
    cdn_provider = Column(String(50))
    
    # Scanning metadata
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)
    last_port_scan = Column(DateTime)
    
    # Relationships
    ports = relationship("Port", back_populates="ip_address", cascade="all, delete-orphan")
    subdomain_associations = relationship("SubdomainIP", back_populates="ip_address")
    asn_record = relationship("ASN", back_populates="ip_addresses")
    
    __table_args__ = (
        Index("idx_ip_cloud", "cloud_provider"),
        Index("idx_ip_asn", "asn"),
        Index("idx_ip_asn_id", "asn_id"),
    )


class Port(Base):
    """Open ports discovered on IP addresses"""
    __tablename__ = "ports"
    
    id = Column(Integer, primary_key=True)
    ip_id = Column(Integer, ForeignKey("ip_addresses.id", ondelete="CASCADE"))
    port = Column(Integer, nullable=False)
    protocol = Column(String(10), default="tcp")
    
    # Port state and service
    state = Column(String(20), default="open")  # open, filtered, closed
    service_name = Column(String(50))
    service_version = Column(String(255))
    service_banner = Column(Text)
    
    # Service fingerprinting
    service_confidence = Column(Integer)  # 0-100 confidence in service detection
    ssl_enabled = Column(Boolean, default=False)
    ssl_cert_subject = Column(Text)
    ssl_cert_issuer = Column(String(255))
    ssl_cert_expiry = Column(DateTime)
    
    # Vulnerability indicators
    cve_matches = Column(Text)  # JSON array of potential CVEs
    weak_cipher = Column(Boolean, default=False)
    outdated_version = Column(Boolean, default=False)
    
    # Scanning metadata
    discovered_at = Column(DateTime, default=datetime.utcnow)
    last_checked = Column(DateTime)
    
    # Relationships
    ip_address = relationship("IPAddress", back_populates="ports")
    vulnerabilities = relationship("Vulnerability", back_populates="port")
    
    __table_args__ = (
        Index("idx_port_ip_port", "ip_id", "port", unique=True),
        Index("idx_port_service", "service_name"),
    )


class SubdomainIP(Base):
    """Many-to-many relationship between subdomains and IPs"""
    __tablename__ = "subdomain_ips"
    
    id = Column(Integer, primary_key=True)
    subdomain_id = Column(Integer, ForeignKey("subdomains.id", ondelete="CASCADE"))
    ip_id = Column(Integer, ForeignKey("ip_addresses.id", ondelete="CASCADE"))
    
    # Resolution metadata
    resolved_at = Column(DateTime, default=datetime.utcnow)
    ttl = Column(Integer)  # DNS TTL value
    is_active = Column(Boolean, default=True)
    
    # Relationships
    subdomain = relationship("Subdomain", back_populates="ip_associations")
    ip_address = relationship("IPAddress", back_populates="subdomain_associations")
    
    __table_args__ = (
        Index("idx_subdomain_ip", "subdomain_id", "ip_id", unique=True),
    )