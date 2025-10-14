"""
AI-Powered Vulnerability Intelligence System

Transforms collected data into actionable security intelligence through:
- Vulnerability correlation and pattern matching
- Exploit database integration
- Context-aware risk scoring
- Machine learning-based anomaly detection
"""

from app.intelligence.correlation_engine import VulnerabilityCorrelationEngine
from app.intelligence.exploit_matcher import ExploitMatcher
from app.intelligence.risk_scorer import RiskScorer
from app.intelligence.pattern_learner import PatternLearner
from app.intelligence.orchestrator import VulnerabilityIntelligenceOrchestrator

__all__ = [
    'VulnerabilityCorrelationEngine',
    'ExploitMatcher',
    'RiskScorer',
    'PatternLearner',
    'VulnerabilityIntelligenceOrchestrator',
]
