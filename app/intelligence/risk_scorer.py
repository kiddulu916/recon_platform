"""
Intelligent Risk Scoring Algorithm

Context-aware risk scoring that considers:
- Technical severity (CVSS, exploit availability)
- Environmental factors (exposure, asset criticality)
- Business context (production vs development, data sensitivity)
- Learning from user feedback
"""

import json
from typing import Dict, Optional, Any, List
from datetime import datetime
import structlog
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from app.models.vulnerability import (
    Vulnerability, RiskScore, VulnerabilityFeedback,
    ExploitDatabase, CVEDatabase
)
from app.models.domain import Subdomain, Domain
from app.models.network import Port, IPAddress

logger = structlog.get_logger()


class RiskScorer:
    """
    Context-aware risk scoring for vulnerabilities

    Scoring components:
    1. Technical Risk (40%):
       - CVSS score
       - Exploit availability
       - Exploit reliability
       - Attack complexity

    2. Environmental Risk (35%):
       - Exposure (public/internal)
       - Asset criticality
       - Data sensitivity

    3. Contextual Risk (25%):
       - Authentication requirements
       - Network access requirements
       - User interaction requirements
       - Business impact
       - Compliance impact
    """

    def __init__(self, config):
        self.config = config
        self.logger = logger.bind(component="risk_scorer")

        # Scoring weights
        self.weights = {
            "technical": 0.40,
            "environmental": 0.35,
            "contextual": 0.25,
        }

        # Technical sub-weights
        self.technical_weights = {
            "cvss": 0.40,
            "exploit_availability": 0.30,
            "exploit_reliability": 0.20,
            "attack_complexity": 0.10,
        }

        # Environmental sub-weights
        self.environmental_weights = {
            "exposure": 0.40,
            "asset_criticality": 0.35,
            "data_sensitivity": 0.25,
        }

        # Contextual sub-weights
        self.contextual_weights = {
            "authentication": 0.25,
            "network_access": 0.20,
            "user_interaction": 0.15,
            "business_impact": 0.25,
            "compliance_impact": 0.15,
        }

    async def calculate_risk(
        self,
        vulnerability: Vulnerability,
        db_session: AsyncSession
    ) -> RiskScore:
        """
        Calculate comprehensive risk score for vulnerability

        Args:
            vulnerability: Vulnerability to score
            db_session: Database session

        Returns:
            RiskScore object with detailed scoring
        """
        self.logger.info("Calculating risk score", vuln_id=vulnerability.id)

        # Calculate component scores
        technical_score = await self._calculate_technical_risk(vulnerability, db_session)
        environmental_score = await self._calculate_environmental_risk(vulnerability, db_session)
        contextual_score = await self._calculate_contextual_risk(vulnerability, db_session)

        # Calculate final score
        final_score = (
            technical_score["total"] * self.weights["technical"] +
            environmental_score["total"] * self.weights["environmental"] +
            contextual_score["total"] * self.weights["contextual"]
        )

        # Scale to 0-100
        final_score = final_score * 10

        # Apply AI adjustments based on learning
        ai_adjustment, ai_reasoning = await self._apply_ai_adjustment(
            vulnerability,
            final_score,
            db_session
        )

        final_score = final_score * ai_adjustment

        # Determine risk category
        risk_category = self._categorize_risk(final_score)

        # Create or update RiskScore
        result = await db_session.execute(
            select(RiskScore).where(RiskScore.vulnerability_id == vulnerability.id)
        )
        risk_score = result.scalar_one_or_none()

        if not risk_score:
            risk_score = RiskScore(vulnerability_id=vulnerability.id)
            db_session.add(risk_score)

        # Update all fields
        risk_score.cvss_score = technical_score["cvss"]
        risk_score.exploit_availability_score = technical_score["exploit_availability"]
        risk_score.exploit_reliability_score = technical_score["exploit_reliability"]
        risk_score.attack_complexity_score = technical_score["attack_complexity"]

        risk_score.exposure_score = environmental_score["exposure"]
        risk_score.asset_criticality_score = environmental_score["asset_criticality"]
        risk_score.data_sensitivity_score = environmental_score["data_sensitivity"]

        risk_score.authentication_required_penalty = contextual_score["authentication_penalty"]
        risk_score.network_access_score = contextual_score["network_access"]
        risk_score.user_interaction_penalty = contextual_score["user_interaction_penalty"]
        risk_score.business_impact_score = contextual_score["business_impact"]
        risk_score.compliance_impact_score = contextual_score["compliance_impact"]

        risk_score.technical_risk_score = technical_score["total"]
        risk_score.environmental_risk_score = environmental_score["total"]
        risk_score.final_risk_score = final_score
        risk_score.risk_category = risk_category

        risk_score.ai_adjustment_factor = ai_adjustment
        risk_score.ai_reasoning = ai_reasoning
        risk_score.updated_at = datetime.utcnow()

        await db_session.commit()

        self.logger.info(
            "Risk score calculated",
            vuln_id=vulnerability.id,
            final_score=round(final_score, 2),
            category=risk_category
        )

        return risk_score

    async def _calculate_technical_risk(
        self,
        vulnerability: Vulnerability,
        db_session: AsyncSession
    ) -> Dict[str, float]:
        """Calculate technical risk factors"""
        scores = {
            "cvss": 0.0,
            "exploit_availability": 0.0,
            "exploit_reliability": 0.0,
            "attack_complexity": 0.0,
            "total": 0.0
        }

        # CVSS score (0-10)
        if vulnerability.cvss_score:
            scores["cvss"] = vulnerability.cvss_score
        else:
            # Estimate from severity
            scores["cvss"] = self._severity_to_cvss(vulnerability.severity)

        # Exploit availability (0-10)
        if vulnerability.exploit_available:
            scores["exploit_availability"] = 8.0  # High if exploit exists

            # Check exploit database for more details
            if vulnerability.cve_id:
                exploit_score = await self._get_exploit_score(vulnerability.cve_id, db_session)
                scores["exploit_availability"] = max(scores["exploit_availability"], exploit_score)
        else:
            scores["exploit_availability"] = 2.0  # Low if no known exploit

        # Exploit reliability (0-10)
        scores["exploit_reliability"] = await self._get_exploit_reliability(vulnerability, db_session)

        # Attack complexity (0-10, inverse - lower complexity = higher score)
        complexity_map = {
            "Low": 9.0,
            "Medium": 5.0,
            "High": 2.0
        }
        scores["attack_complexity"] = complexity_map.get(
            vulnerability.exploitation_complexity or "Medium",
            5.0
        )

        # Calculate weighted total
        scores["total"] = (
            scores["cvss"] * self.technical_weights["cvss"] +
            scores["exploit_availability"] * self.technical_weights["exploit_availability"] +
            scores["exploit_reliability"] * self.technical_weights["exploit_reliability"] +
            scores["attack_complexity"] * self.technical_weights["attack_complexity"]
        )

        return scores

    async def _calculate_environmental_risk(
        self,
        vulnerability: Vulnerability,
        db_session: AsyncSession
    ) -> Dict[str, float]:
        """Calculate environmental risk factors"""
        scores = {
            "exposure": 0.0,
            "asset_criticality": 0.0,
            "data_sensitivity": 0.0,
            "total": 0.0
        }

        # Exposure (0-10)
        scores["exposure"] = await self._calculate_exposure(vulnerability, db_session)

        # Asset criticality (0-10)
        scores["asset_criticality"] = await self._calculate_asset_criticality(vulnerability, db_session)

        # Data sensitivity (0-10)
        scores["data_sensitivity"] = await self._calculate_data_sensitivity(vulnerability, db_session)

        # Calculate weighted total
        scores["total"] = (
            scores["exposure"] * self.environmental_weights["exposure"] +
            scores["asset_criticality"] * self.environmental_weights["asset_criticality"] +
            scores["data_sensitivity"] * self.environmental_weights["data_sensitivity"]
        )

        return scores

    async def _calculate_contextual_risk(
        self,
        vulnerability: Vulnerability,
        db_session: AsyncSession
    ) -> Dict[str, float]:
        """Calculate contextual risk factors"""
        scores = {
            "authentication_penalty": 0.0,
            "network_access": 0.0,
            "user_interaction_penalty": 0.0,
            "business_impact": 0.0,
            "compliance_impact": 0.0,
            "total": 0.0
        }

        # Authentication requirement (reduces score)
        if vulnerability.exploitable and vulnerability.exploitation_complexity:
            # If exploit requires auth, apply penalty
            scores["authentication_penalty"] = 0.7  # 30% reduction
        else:
            scores["authentication_penalty"] = 1.0  # No penalty

        # Network access (0-10)
        # Network > Adjacent > Local
        scores["network_access"] = 8.0  # Assume network accessible by default

        # User interaction (reduces score)
        # Estimate based on vulnerability type
        if vulnerability.type in ["xss", "csrf"]:
            scores["user_interaction_penalty"] = 0.8  # 20% reduction (requires user action)
        else:
            scores["user_interaction_penalty"] = 1.0  # No penalty

        # Business impact (0-10)
        scores["business_impact"] = await self._estimate_business_impact(vulnerability, db_session)

        # Compliance impact (0-10)
        scores["compliance_impact"] = self._estimate_compliance_impact(vulnerability)

        # Calculate total (authentication and user_interaction are multipliers, not additive)
        base_score = (
            scores["network_access"] * self.contextual_weights["network_access"] +
            scores["business_impact"] * self.contextual_weights["business_impact"] +
            scores["compliance_impact"] * self.contextual_weights["compliance_impact"]
        )

        # Apply penalties
        scores["total"] = base_score * scores["authentication_penalty"] * scores["user_interaction_penalty"]

        return scores

    async def _get_exploit_score(self, cve_id: str, db_session: AsyncSession) -> float:
        """Get exploit availability score from database"""
        try:
            result = await db_session.execute(
                select(CVEDatabase).where(CVEDatabase.cve_id == cve_id)
            )
            cve = result.scalar_one_or_none()

            if cve and cve.exploit_available:
                # Higher score for more mature exploits
                maturity_map = {
                    "High": 10.0,
                    "Functional": 8.0,
                    "Proof of Concept": 6.0
                }
                return maturity_map.get(cve.exploit_maturity or "Proof of Concept", 6.0)

        except Exception as e:
            self.logger.debug("Failed to get exploit score", error=str(e))

        return 2.0

    async def _get_exploit_reliability(
        self,
        vulnerability: Vulnerability,
        db_session: AsyncSession
    ) -> float:
        """Get exploit reliability score"""
        if not vulnerability.cve_id:
            return 5.0  # Default medium

        try:
            result = await db_session.execute(
                select(ExploitDatabase).where(
                    ExploitDatabase.cve_ids.like(f'%{vulnerability.cve_id}%')
                ).limit(1)
            )
            exploit = result.scalar_one_or_none()

            if exploit:
                reliability_map = {
                    "Excellent": 10.0,
                    "Good": 8.0,
                    "Average": 5.0,
                    "Low": 3.0
                }
                return reliability_map.get(exploit.reliability or "Average", 5.0)

        except Exception as e:
            self.logger.debug("Failed to get exploit reliability", error=str(e))

        return 5.0

    async def _calculate_exposure(
        self,
        vulnerability: Vulnerability,
        db_session: AsyncSession
    ) -> float:
        """Calculate exposure score"""
        # Check if the vulnerable asset is internet-facing
        exposure_score = 5.0  # Default medium

        try:
            if vulnerability.subdomain_id:
                # Web vulnerability - likely public
                exposure_score = 9.0

            elif vulnerability.port_id:
                # Port vulnerability - check if common port
                result = await db_session.execute(
                    select(Port).where(Port.id == vulnerability.port_id)
                )
                port = result.scalar_one_or_none()

                if port:
                    # Common internet-facing ports
                    public_ports = [80, 443, 8080, 8443, 22, 21, 25, 3389]
                    if port.port_number in public_ports:
                        exposure_score = 9.0
                    else:
                        exposure_score = 6.0

        except Exception as e:
            self.logger.debug("Failed to calculate exposure", error=str(e))

        return exposure_score

    async def _calculate_asset_criticality(
        self,
        vulnerability: Vulnerability,
        db_session: AsyncSession
    ) -> float:
        """Calculate asset criticality"""
        criticality = 5.0  # Default medium

        try:
            if vulnerability.subdomain_id:
                result = await db_session.execute(
                    select(Subdomain).where(Subdomain.id == vulnerability.subdomain_id)
                )
                subdomain = result.scalar_one_or_none()

                if subdomain:
                    # Check subdomain name for criticality indicators
                    critical_keywords = ["api", "admin", "dashboard", "prod", "production"]
                    if any(keyword in subdomain.subdomain.lower() for keyword in critical_keywords):
                        criticality = 9.0
                    elif "dev" in subdomain.subdomain.lower() or "test" in subdomain.subdomain.lower():
                        criticality = 4.0

        except Exception as e:
            self.logger.debug("Failed to calculate asset criticality", error=str(e))

        return criticality

    async def _calculate_data_sensitivity(
        self,
        vulnerability: Vulnerability,
        db_session: AsyncSession
    ) -> float:
        """Calculate data sensitivity"""
        sensitivity = 5.0  # Default medium

        # Estimate based on vulnerability type and affected component
        high_sensitivity_types = ["sqli", "lfi", "xxe", "ssrf"]
        if vulnerability.type in high_sensitivity_types:
            sensitivity = 8.0

        # Check for indicators in component names
        if vulnerability.affected_component:
            sensitive_keywords = ["user", "account", "payment", "auth", "admin"]
            if any(keyword in vulnerability.affected_component.lower() for keyword in sensitive_keywords):
                sensitivity = 9.0

        return sensitivity

    async def _estimate_business_impact(
        self,
        vulnerability: Vulnerability,
        db_session: AsyncSession
    ) -> float:
        """Estimate business impact"""
        impact = 5.0  # Default medium

        # Map vulnerability types to business impact
        impact_map = {
            "rce": 10.0,  # Critical - full system compromise
            "sqli": 9.0,  # Critical - data breach potential
            "xxe": 8.0,  # High - file access, SSRF
            "ssrf": 7.0,  # High - internal network access
            "lfi": 7.0,  # High - file access
            "xss": 6.0,  # Medium - session hijacking
            "csrf": 5.0,  # Medium - unauthorized actions
            "misconfiguration": 4.0,  # Low-Medium - information disclosure
        }

        impact = impact_map.get(vulnerability.type, 5.0)

        return impact

    def _estimate_compliance_impact(self, vulnerability: Vulnerability) -> float:
        """Estimate compliance/regulatory impact"""
        # High impact for data exposure vulnerabilities
        compliance_critical_types = ["sqli", "lfi", "xxe", "sensitive_data_exposure"]

        if vulnerability.type in compliance_critical_types:
            return 9.0

        return 5.0

    async def _apply_ai_adjustment(
        self,
        vulnerability: Vulnerability,
        current_score: float,
        db_session: AsyncSession
    ) -> tuple[float, str]:
        """
        Apply AI-based adjustments based on learned patterns

        Learns from user feedback to adjust scoring
        """
        adjustment_factor = 1.0
        reasoning = ""

        try:
            # Get feedback for similar vulnerabilities
            result = await db_session.execute(
                select(VulnerabilityFeedback).join(
                    Vulnerability
                ).where(
                    Vulnerability.type == vulnerability.type,
                    VulnerabilityFeedback.used_for_training == True
                ).limit(50)
            )
            feedback_records = result.scalars().all()

            if feedback_records:
                # Calculate adjustment based on historical feedback
                true_positives = sum(1 for f in feedback_records if f.is_true_positive)
                total = len(feedback_records)

                if total > 10:  # Require minimum sample size
                    tp_rate = true_positives / total

                    # If this type has high false positive rate, reduce score
                    if tp_rate < 0.5:
                        adjustment_factor = 0.7
                        reasoning = f"Historical false positive rate {(1-tp_rate)*100:.1f}% for {vulnerability.type}"
                    elif tp_rate > 0.9:
                        adjustment_factor = 1.1
                        reasoning = f"High confidence ({tp_rate*100:.1f}% accuracy) for {vulnerability.type}"

        except Exception as e:
            self.logger.debug("AI adjustment failed", error=str(e))

        return adjustment_factor, reasoning

    def _severity_to_cvss(self, severity: Optional[str]) -> float:
        """Convert severity string to CVSS-like score"""
        severity_map = {
            "Critical": 9.5,
            "High": 7.5,
            "Medium": 5.0,
            "Low": 2.5
        }
        return severity_map.get(severity or "Medium", 5.0)

    def _categorize_risk(self, score: float) -> str:
        """Categorize risk based on final score"""
        if score >= 90:
            return "Critical"
        elif score >= 70:
            return "High"
        elif score >= 40:
            return "Medium"
        else:
            return "Low"

    async def recalculate_all_risks(
        self,
        db_session: AsyncSession,
        domain_id: Optional[int] = None
    ) -> Dict[str, int]:
        """
        Recalculate risk scores for all vulnerabilities

        Useful after:
        - Learning from new feedback
        - Updating exploit database
        - Changing scoring parameters

        Args:
            db_session: Database session
            domain_id: Optional domain filter

        Returns:
            Statistics dictionary
        """
        self.logger.info("Recalculating all risk scores", domain_id=domain_id)

        stats = {
            "recalculated": 0,
            "errors": 0
        }

        try:
            query = select(Vulnerability).where(Vulnerability.status != "false_positive")

            if domain_id:
                query = query.where(Vulnerability.domain_id == domain_id)

            result = await db_session.execute(query)
            vulnerabilities = result.scalars().all()

            for vuln in vulnerabilities:
                try:
                    await self.calculate_risk(vuln, db_session)
                    stats["recalculated"] += 1
                except Exception as e:
                    self.logger.error("Risk recalculation failed", vuln_id=vuln.id, error=str(e))
                    stats["errors"] += 1

        except Exception as e:
            self.logger.error("Batch recalculation failed", error=str(e))

        self.logger.info("Risk recalculation complete", **stats)
        return stats
