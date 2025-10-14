"""
Vulnerability Intelligence Orchestrator

Coordinates all intelligence components:
- Vulnerability correlation
- Exploit matching
- Risk scoring
- Pattern learning
"""

from typing import List, Dict, Optional, Any
import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from app.intelligence.correlation_engine import VulnerabilityCorrelationEngine
from app.intelligence.exploit_matcher import ExploitMatcher
from app.intelligence.risk_scorer import RiskScorer
from app.intelligence.pattern_learner import PatternLearner
from app.models.vulnerability import Vulnerability
from app.models.http_traffic import HTTPTraffic
from app.models.network import Port

logger = structlog.get_logger()


class VulnerabilityIntelligenceOrchestrator:
    """
    Orchestrates AI-powered vulnerability intelligence

    Workflow:
    1. Correlation: Identify vulnerabilities from collected data
    2. Exploit Matching: Find available exploits
    3. Risk Scoring: Calculate context-aware risk scores
    4. Learning: Improve patterns from feedback
    """

    def __init__(self, config):
        self.config = config
        self.logger = logger.bind(component="vuln_intelligence")

        # Initialize components
        self.correlation_engine = VulnerabilityCorrelationEngine()
        self.exploit_matcher = ExploitMatcher(config)
        self.risk_scorer = RiskScorer(config)
        self.pattern_learner = PatternLearner()

        # Statistics
        self.stats = {
            "vulnerabilities_identified": 0,
            "exploits_matched": 0,
            "risk_scores_calculated": 0,
        }

    async def analyze_http_traffic(
        self,
        traffic: HTTPTraffic,
        db_session: AsyncSession
    ) -> List[Vulnerability]:
        """
        Analyze HTTP traffic for vulnerabilities

        Complete workflow:
        1. Detect vulnerabilities
        2. Match exploits
        3. Calculate risk scores
        """
        vulnerabilities = []

        # Step 1: Detect vulnerabilities
        detected = await self.correlation_engine.analyze_http_traffic(traffic, db_session)
        vulnerabilities.extend(detected)
        self.stats["vulnerabilities_identified"] += len(detected)

        # Step 2 & 3: For each vulnerability, match exploits and calculate risk
        for vuln in detected:
            # Match exploits
            exploits = await self.exploit_matcher.match_exploits(vuln, db_session)
            if exploits:
                self.stats["exploits_matched"] += len(exploits)

            # Calculate risk score
            risk_score = await self.risk_scorer.calculate_risk(vuln, db_session)
            self.stats["risk_scores_calculated"] += 1

            self.logger.info(
                "Vulnerability analyzed",
                vuln_id=vuln.id,
                type=vuln.type,
                severity=vuln.severity,
                risk_score=round(risk_score.final_risk_score, 2),
                exploits_found=len(exploits)
            )

        return vulnerabilities

    async def analyze_port_service(
        self,
        port: Port,
        db_session: AsyncSession
    ) -> List[Vulnerability]:
        """Analyze port/service for vulnerabilities"""
        vulnerabilities = []

        # Detect vulnerabilities
        detected = await self.correlation_engine.analyze_port_service(port, db_session)
        vulnerabilities.extend(detected)
        self.stats["vulnerabilities_identified"] += len(detected)

        # Match exploits and calculate risk
        for vuln in detected:
            exploits = await self.exploit_matcher.match_exploits(vuln, db_session)
            if exploits:
                self.stats["exploits_matched"] += len(exploits)

            risk_score = await self.risk_scorer.calculate_risk(vuln, db_session)
            self.stats["risk_scores_calculated"] += 1

        return vulnerabilities

    async def sync_threat_intelligence(
        self,
        db_session: AsyncSession
    ) -> Dict[str, Any]:
        """
        Synchronize threat intelligence databases

        Updates:
        - CVE database
        - Exploit database
        """
        self.logger.info("Synchronizing threat intelligence")

        results = {}

        # Sync exploit database
        exploit_stats = await self.exploit_matcher.sync_exploit_database(db_session)
        results["exploits"] = exploit_stats

        # Sync CVE database
        cve_stats = await self.exploit_matcher.sync_cve_database(db_session)
        results["cves"] = cve_stats

        self.logger.info("Threat intelligence sync complete", **results)
        return results

    async def process_feedback(
        self,
        vulnerability_id: int,
        is_true_positive: bool,
        reviewed_by: str,
        db_session: AsyncSession,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Process user feedback and trigger learning

        Args:
            vulnerability_id: Vulnerability ID
            is_true_positive: Feedback
            reviewed_by: Reviewer
            db_session: Database session
            **kwargs: Additional feedback data
        """
        # Record feedback
        feedback = await self.pattern_learner.process_feedback(
            vulnerability_id,
            is_true_positive,
            reviewed_by,
            db_session,
            comments=kwargs.get("comments"),
            suggested_severity=kwargs.get("suggested_severity")
        )

        return {
            "feedback_id": feedback.id,
            "status": "processed",
            "learning_triggered": True
        }

    async def get_statistics(self, db_session: AsyncSession) -> Dict[str, Any]:
        """Get intelligence statistics"""
        from sqlalchemy import select, func
        from app.models.vulnerability import Vulnerability, RiskScore

        # Count vulnerabilities by severity
        result = await db_session.execute(
            select(
                Vulnerability.severity,
                func.count(Vulnerability.id)
            ).group_by(Vulnerability.severity)
        )
        severity_counts = dict(result.all())

        # Count by risk category
        result = await db_session.execute(
            select(
                RiskScore.risk_category,
                func.count(RiskScore.id)
            ).group_by(RiskScore.risk_category)
        )
        risk_counts = dict(result.all())

        # Get pattern performance
        pattern_performance = await self.pattern_learner.get_pattern_performance(db_session)

        return {
            "session_stats": self.stats,
            "severity_distribution": severity_counts,
            "risk_distribution": risk_counts,
            "pattern_performance": pattern_performance
        }
