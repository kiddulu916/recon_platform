"""
Scan job tracking and orchestration models
These manage and monitor reconnaissance operations
"""

from sqlalchemy import (
    Column, String, Integer, DateTime, ForeignKey, Text, JSON, Index
)
from sqlalchemy.orm import relationship
from datetime import datetime
from app.core.database import Base


class ScanJob(Base):
    """Tracks individual scan jobs and their progress"""
    __tablename__ = "scan_jobs"

    id = Column(Integer, primary_key=True)
    # UUID for tracking
    job_id = Column(String(100), unique=True, nullable=False)
    domain_id = Column(Integer, ForeignKey("domains.id"))

    # Job configuration
    # full, subdomain, port, web, api
    scan_type = Column(String(50))
    # passive, normal, aggressive
    scan_profile = Column(String(50))
    configuration = Column(JSON)  # Full scan configuration

    # Job status
    # pending, running, completed, failed
    status = Column(String(20), default="pending")
    progress = Column(Integer, default=0)  # 0-100 percentage
    current_phase = Column(String(50))  # Current scanning phase

    # Timing
    created_at = Column(DateTime, default=datetime.utcnow)
    started_at = Column(DateTime)
    completed_at = Column(DateTime)
    estimated_completion = Column(DateTime)

    # Results summary
    subdomains_found = Column(Integer, default=0)
    ips_discovered = Column(Integer, default=0)
    ports_found = Column(Integer, default=0)
    vulnerabilities_identified = Column(Integer, default=0)

    # Error handling
    # JSON array of errors encountered
    errors = Column(Text)
    warnings = Column(Text)  # JSON array of warnings

    # Relationships
    domain = relationship("Domain", back_populates="scan_jobs")

    __table_args__ = (
        Index("idx_scan_status", "status"),
        Index("idx_scan_domain", "domain_id"),
        Index("idx_scan_created", "created_at"),
    )
