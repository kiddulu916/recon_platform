"""
Advanced Pattern Recognition System

Multi-dimensional analysis:
- Temporal patterns: Time-based behaviors and weaknesses
- Spatial patterns: Infrastructure relationships and shared components
- Behavioral patterns: Anomalous responses and deviations

Outputs feed into vulnerability chaining and predictive analysis.
"""

from app.intelligence.pattern_recognition.temporal_analyzer import TemporalPatternAnalyzer
from app.intelligence.pattern_recognition.spatial_analyzer import SpatialPatternAnalyzer
from app.intelligence.pattern_recognition.behavioral_analyzer import BehavioralPatternAnalyzer
from app.intelligence.pattern_recognition.chaining_engine import VulnerabilityChainingEngine
from app.intelligence.pattern_recognition.predictive_analyzer import PredictiveVulnerabilityAnalyzer

__all__ = [
    'TemporalPatternAnalyzer',
    'SpatialPatternAnalyzer',
    'BehavioralPatternAnalyzer',
    'VulnerabilityChainingEngine',
    'PredictiveVulnerabilityAnalyzer',
]
