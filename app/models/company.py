"""
Company and acquisition tracking models
Track parent companies and their acquisitions
"""

from sqlalchemy import Column, String, Integer, DateTime, ForeignKey, Text, Index
from sqlalchemy.orm import relationship
from datetime import datetime
from app.core.database import Base


class Company(Base):
    """Company entity with acquisition tracking"""
    __tablename__ = "companies"
    
    id = Column(Integer, primary_key=True)
    name = Column(String(255), unique=True, nullable=False, index=True)
    parent_company_id = Column(Integer, ForeignKey("companies.id"))
    
    # Company information
    whois_data = Column(Text)  # JSON data from WHOIS lookup
    website = Column(String(255))
    description = Column(Text)
    
    # Discovery metadata
    discovered_at = Column(DateTime, default=datetime.utcnow)
    discovery_source = Column(String(50))  # whoisxml, manual, etc.
    
    # Relationships
    parent = relationship("Company", remote_side=[id], backref="subsidiaries")
    acquisitions_as_parent = relationship(
        "CompanyAcquisition",
        foreign_keys="CompanyAcquisition.parent_id",
        back_populates="parent_company",
        cascade="all, delete-orphan"
    )
    acquisitions_as_acquired = relationship(
        "CompanyAcquisition",
        foreign_keys="CompanyAcquisition.acquired_id",
        back_populates="acquired_company"
    )
    domains = relationship("Domain", back_populates="company")
    
    __table_args__ = (
        Index("idx_company_name", "name"),
        Index("idx_company_parent", "parent_company_id"),
    )


class CompanyAcquisition(Base):
    """Tracks acquisition relationships between companies"""
    __tablename__ = "company_acquisitions"
    
    id = Column(Integer, primary_key=True)
    parent_id = Column(Integer, ForeignKey("companies.id", ondelete="CASCADE"), nullable=False)
    acquired_id = Column(Integer, ForeignKey("companies.id", ondelete="CASCADE"), nullable=False)
    
    # Acquisition details
    acquisition_date = Column(DateTime)
    acquisition_price = Column(String(100))  # As string to handle "undisclosed", etc.
    notes = Column(Text)
    
    # Discovery metadata
    source = Column(String(100))  # WhoIsXMLAPI, manual, etc.
    discovered_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    parent_company = relationship(
        "Company",
        foreign_keys=[parent_id],
        back_populates="acquisitions_as_parent"
    )
    acquired_company = relationship(
        "Company",
        foreign_keys=[acquired_id],
        back_populates="acquisitions_as_acquired"
    )
    
    __table_args__ = (
        Index("idx_acquisition_parent", "parent_id"),
        Index("idx_acquisition_acquired", "acquired_id"),
        Index("idx_acquisition_unique", "parent_id", "acquired_id", unique=True),
    )

