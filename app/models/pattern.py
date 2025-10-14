"""
Pattern Recognition Models

Tracks discovered patterns across temporal, spatial, and behavioral dimensions.
Used for vulnerability chaining and predictive analysis.
"""

from datetime import datetime
from typing import Optional, Dict, Any
from sqlalchemy import Column, Integer, String, Float, DateTime, JSON, ForeignKey, Text, Boolean
from sqlalchemy.orm import relationship
from app.core.database import Base


class TemporalPattern(Base):
    """Temporal patterns - how application behavior changes over time"""
    __tablename__ = "temporal_patterns"

    id = Column(Integer, primary_key=True, index=True)
    domain_id = Column(Integer, ForeignKey("domains.id"), nullable=False)
    subdomain_id = Column(Integer, ForeignKey("subdomains.id"), nullable=True)

    pattern_type = Column(String(100), nullable=False)  # time_based_behavior, rate_limit_variation, auth_weakness_timing
    pattern_name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)

    # Time-based characteristics
    time_window_start = Column(DateTime, nullable=True)  # When pattern becomes active
    time_window_end = Column(DateTime, nullable=True)    # When pattern becomes inactive
    day_of_week = Column(String(20), nullable=True)      # Specific day pattern observed
    recurrence = Column(String(50), nullable=True)        # daily, weekly, hourly, etc.

    # Statistical data
    confidence = Column(Float, nullable=False, default=0.0)  # 0-1, how confident we are
    occurrence_count = Column(Integer, nullable=False, default=1)
    sample_size = Column(Integer, nullable=False, default=1)

    # Pattern details
    baseline_behavior = Column(JSON, nullable=True)       # Normal behavior metrics
    anomaly_behavior = Column(JSON, nullable=True)        # Anomalous behavior during pattern
    affected_endpoints = Column(JSON, nullable=True)      # List of affected URLs/endpoints

    # Security implications
    security_impact = Column(String(50), nullable=True)   # critical, high, medium, low, info
    exploitability = Column(Float, nullable=True)         # 0-1, how easy to exploit
    notes = Column(Text, nullable=True)

    # Metadata
    first_observed = Column(DateTime, nullable=False, default=datetime.utcnow)
    last_observed = Column(DateTime, nullable=False, default=datetime.utcnow)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    domain = relationship("Domain", back_populates="temporal_patterns")
    subdomain = relationship("Subdomain", back_populates="temporal_patterns")


class SpatialPattern(Base):
    """Spatial patterns - relationships between different infrastructure parts"""
    __tablename__ = "spatial_patterns"

    id = Column(Integer, primary_key=True, index=True)
    domain_id = Column(Integer, ForeignKey("domains.id"), nullable=False)

    pattern_type = Column(String(100), nullable=False)  # shared_auth, infrastructure_relationship, technology_cluster
    pattern_name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)

    # Spatial characteristics
    related_subdomains = Column(JSON, nullable=True)     # List of subdomain IDs in pattern
    related_ips = Column(JSON, nullable=True)            # List of IP addresses involved
    related_asns = Column(JSON, nullable=True)           # List of ASNs involved
    geographic_pattern = Column(JSON, nullable=True)     # Geographic distribution

    # Relationship details
    relationship_type = Column(String(100), nullable=True)  # shared_session, shared_db, shared_auth, same_infrastructure
    relationship_strength = Column(Float, nullable=False, default=0.0)  # 0-1, how strong the relationship
    evidence = Column(JSON, nullable=True)               # Evidence supporting the relationship

    # Statistical data
    confidence = Column(Float, nullable=False, default=0.0)
    node_count = Column(Integer, nullable=False, default=0)  # Number of nodes in pattern
    edge_count = Column(Integer, nullable=False, default=0)  # Number of connections

    # Security implications
    security_impact = Column(String(50), nullable=True)
    attack_surface_multiplier = Column(Float, nullable=True)  # How much this pattern expands attack surface
    lateral_movement_potential = Column(Float, nullable=True)  # 0-1, likelihood of lateral movement
    notes = Column(Text, nullable=True)

    # Metadata
    discovered_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    domain = relationship("Domain", back_populates="spatial_patterns")


class BehavioralPattern(Base):
    """Behavioral patterns - unusual responses that might indicate vulnerabilities"""
    __tablename__ = "behavioral_patterns"

    id = Column(Integer, primary_key=True, index=True)
    domain_id = Column(Integer, ForeignKey("domains.id"), nullable=False)
    subdomain_id = Column(Integer, ForeignKey("subdomains.id"), nullable=True)
    endpoint = Column(String(1000), nullable=True)

    pattern_type = Column(String(100), nullable=False)  # response_time_anomaly, error_pattern, input_reflection
    pattern_name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)

    # Behavioral characteristics
    trigger_conditions = Column(JSON, nullable=True)     # What inputs/conditions trigger this behavior
    normal_behavior = Column(JSON, nullable=True)        # Expected baseline behavior
    anomalous_behavior = Column(JSON, nullable=True)     # Observed anomalous behavior

    # Statistical analysis
    baseline_mean = Column(Float, nullable=True)         # Mean of baseline metric
    baseline_stddev = Column(Float, nullable=True)       # Standard deviation of baseline
    anomaly_mean = Column(Float, nullable=True)          # Mean of anomalous metric
    anomaly_stddev = Column(Float, nullable=True)        # Standard deviation of anomaly
    z_score = Column(Float, nullable=True)               # Statistical significance

    # Pattern details
    confidence = Column(Float, nullable=False, default=0.0)
    occurrence_count = Column(Integer, nullable=False, default=1)
    sample_size = Column(Integer, nullable=False, default=1)
    false_positive_likelihood = Column(Float, nullable=True)  # 0-1, estimated FP rate

    # Security implications
    security_impact = Column(String(50), nullable=True)
    potential_vulnerability_types = Column(JSON, nullable=True)  # List of vuln types this might indicate
    exploitability = Column(Float, nullable=True)
    notes = Column(Text, nullable=True)

    # Metadata
    first_observed = Column(DateTime, nullable=False, default=datetime.utcnow)
    last_observed = Column(DateTime, nullable=False, default=datetime.utcnow)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    domain = relationship("Domain", back_populates="behavioral_patterns")
    subdomain = relationship("Subdomain", back_populates="behavioral_patterns")


# Note: VulnerabilityChain has been consolidated with the AttackChain model in app.models.vulnerability
# Use AttackChain and AttackChainStep from vulnerability.py for comprehensive attack chain representation


class PredictiveAnalysis(Base):
    """Predictive vulnerability analysis based on technology stack and patterns"""
    __tablename__ = "predictive_analyses"

    id = Column(Integer, primary_key=True, index=True)
    domain_id = Column(Integer, ForeignKey("domains.id"), nullable=False)
    subdomain_id = Column(Integer, ForeignKey("subdomains.id"), nullable=True)

    prediction_type = Column(String(100), nullable=False)  # technology_based, pattern_based, configuration_based
    prediction_name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)

    # Prediction details
    predicted_vulnerability_types = Column(JSON, nullable=False)  # List of likely vulnerability types
    likelihood = Column(Float, nullable=False, default=0.0)  # 0-1, how likely the prediction
    confidence = Column(Float, nullable=False, default=0.0)  # 0-1, confidence in the prediction

    # Evidence supporting prediction
    technology_stack = Column(JSON, nullable=True)       # Detected technologies
    observed_patterns = Column(JSON, nullable=True)      # Patterns that informed prediction
    historical_data = Column(JSON, nullable=True)        # Similar cases from history
    configuration_indicators = Column(JSON, nullable=True)

    # Hunting guidance
    suggested_test_areas = Column(JSON, nullable=True)   # Where to focus manual testing
    suggested_payloads = Column(JSON, nullable=True)     # Specific test payloads to try
    suggested_tools = Column(JSON, nullable=True)        # Tools to use for validation
    priority = Column(Integer, nullable=False, default=5)  # 1-10, testing priority

    # Validation
    validated = Column(Boolean, nullable=False, default=False)
    validation_result = Column(String(50), nullable=True)  # confirmed, not_found, inconclusive
    validated_at = Column(DateTime, nullable=True)
    validated_by = Column(String(255), nullable=True)
    actual_findings = Column(JSON, nullable=True)        # What was actually found

    # Learning feedback
    prediction_accuracy = Column(Float, nullable=True)    # If validated, how accurate was it
    false_positive = Column(Boolean, nullable=False, default=False)
    notes = Column(Text, nullable=True)

    # Metadata
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    domain = relationship("Domain", back_populates="predictive_analyses")
    subdomain = relationship("Subdomain", back_populates="predictive_analyses")


class AttackGraph(Base):
    """Graph representation of attack paths through the infrastructure"""
    __tablename__ = "attack_graphs"

    id = Column(Integer, primary_key=True, index=True)
    domain_id = Column(Integer, ForeignKey("domains.id"), nullable=False)

    graph_name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)

    # Graph structure (stored as adjacency list)
    nodes = Column(JSON, nullable=False)                 # List of {id, type, label, data}
    edges = Column(JSON, nullable=False)                 # List of {source, target, type, weight}

    # Graph analysis
    node_count = Column(Integer, nullable=False, default=0)
    edge_count = Column(Integer, nullable=False, default=0)
    entry_points = Column(JSON, nullable=True)           # List of node IDs where attack can start
    critical_paths = Column(JSON, nullable=True)         # List of highest-impact attack paths

    # Risk analysis
    max_path_length = Column(Integer, nullable=True)     # Longest attack path
    avg_path_length = Column(Float, nullable=True)       # Average attack path length
    highest_impact_path = Column(JSON, nullable=True)    # Path with highest impact
    easiest_path = Column(JSON, nullable=True)           # Path with lowest complexity

    # Metadata
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    domain = relationship("Domain", back_populates="attack_graphs")
