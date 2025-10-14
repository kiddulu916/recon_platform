"""
Pattern Recognition Orchestrator

Coordinates all pattern recognition components to provide unified interface
for comprehensive vulnerability pattern analysis.

Workflow:
1. Temporal Pattern Analysis - Time-based behaviors
2. Spatial Pattern Analysis - Infrastructure relationships
3. Behavioral Pattern Analysis - Anomalous responses
4. Vulnerability Chaining - Combine patterns into attack chains
5. Predictive Analysis - Guide future testing (when available)
6. Comprehensive Reporting - Unified results
"""

import json
from typing import List, Dict, Optional, Any
from datetime import datetime
import structlog
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, func

from app.intelligence.pattern_recognition.temporal_analyzer import TemporalPatternAnalyzer
from app.intelligence.pattern_recognition.spatial_analyzer import SpatialPatternAnalyzer
from app.intelligence.pattern_recognition.behavioral_analyzer import BehavioralPatternAnalyzer
from app.intelligence.pattern_recognition.chaining_engine import VulnerabilityChainingEngine
from app.models.vulnerability import PatternRecognition, VulnerabilityChain
from app.models.pattern import PredictiveAnalysis
from app.models.domain import Domain, Subdomain

logger = structlog.get_logger()


class PatternRecognitionOrchestrator:
    """
    Orchestrates AI-powered pattern recognition system

    Complete workflow:
    1. Run temporal pattern analysis (time-based patterns)
    2. Run spatial pattern analysis (infrastructure relationships)
    3. Run behavioral pattern analysis (anomalies)
    4. Run vulnerability chaining (attack paths)
    5. Run predictive analysis (testing guidance)
    6. Generate comprehensive report
    """

    def __init__(self):
        self.logger = logger.bind(component="pattern_orchestrator")

        # Initialize analyzers
        self.temporal_analyzer = TemporalPatternAnalyzer()
        self.spatial_analyzer = SpatialPatternAnalyzer()
        self.behavioral_analyzer = BehavioralPatternAnalyzer()
        self.chaining_engine = VulnerabilityChainingEngine()

        # Statistics
        self.stats = {
            "temporal_patterns_found": 0,
            "spatial_patterns_found": 0,
            "behavioral_patterns_found": 0,
            "vulnerability_chains_found": 0,
            "predictions_generated": 0,
        }

    async def analyze_domain(
        self,
        domain_id: int,
        db_session: AsyncSession,
        enable_temporal: bool = True,
        enable_spatial: bool = True,
        enable_behavioral: bool = True,
        enable_chaining: bool = True,
        enable_predictive: bool = True,
        time_window_days: int = 30,
        lookback_days: int = 7,
        max_chain_length: int = 5
    ) -> Dict[str, Any]:
        """
        Run complete pattern recognition analysis on a domain

        Args:
            domain_id: Domain to analyze
            db_session: Database session
            enable_temporal: Run temporal analysis
            enable_spatial: Run spatial analysis
            enable_behavioral: Run behavioral analysis
            enable_chaining: Run vulnerability chaining
            enable_predictive: Run predictive analysis
            time_window_days: Time window for temporal analysis
            lookback_days: Lookback days for behavioral analysis
            max_chain_length: Maximum chain length for chaining

        Returns:
            Comprehensive analysis results
        """
        self.logger.info(
            "Starting domain pattern analysis",
            domain_id=domain_id,
            temporal=enable_temporal,
            spatial=enable_spatial,
            behavioral=enable_behavioral,
            chaining=enable_chaining,
            predictive=enable_predictive
        )

        analysis_start = datetime.utcnow()

        # Results storage
        results = {
            "domain_id": domain_id,
            "analysis_started_at": analysis_start,
            "analysis_completed_at": None,
            "temporal_patterns": {"count": 0, "patterns": []},
            "spatial_patterns": {"count": 0, "patterns": []},
            "behavioral_patterns": {"count": 0, "patterns": []},
            "vulnerability_chains": {"count": 0, "critical_count": 0, "chains": []},
            "predictions": {"count": 0, "high_priority_count": 0, "predictions": []},
            "critical_findings": [],
            "statistics": {}
        }

        try:
            # Verify domain exists
            domain = await self._get_domain(domain_id, db_session)
            if not domain:
                raise ValueError(f"Domain {domain_id} not found")

            # Phase 1: Temporal Pattern Analysis
            if enable_temporal:
                temporal_patterns = await self.run_pattern_analysis(
                    domain_id,
                    db_session,
                    analyzer_type="temporal",
                    time_window_days=time_window_days
                )
                results["temporal_patterns"]["count"] = len(temporal_patterns)
                results["temporal_patterns"]["patterns"] = temporal_patterns
                self.stats["temporal_patterns_found"] += len(temporal_patterns)
                self.logger.info("Temporal analysis complete", patterns=len(temporal_patterns))

            # Phase 2: Spatial Pattern Analysis
            if enable_spatial:
                spatial_patterns = await self.run_pattern_analysis(
                    domain_id,
                    db_session,
                    analyzer_type="spatial"
                )
                results["spatial_patterns"]["count"] = len(spatial_patterns)
                results["spatial_patterns"]["patterns"] = spatial_patterns
                self.stats["spatial_patterns_found"] += len(spatial_patterns)
                self.logger.info("Spatial analysis complete", patterns=len(spatial_patterns))

            # Phase 3: Behavioral Pattern Analysis
            if enable_behavioral:
                behavioral_patterns = await self.run_pattern_analysis(
                    domain_id,
                    db_session,
                    analyzer_type="behavioral",
                    lookback_days=lookback_days
                )
                results["behavioral_patterns"]["count"] = len(behavioral_patterns)
                results["behavioral_patterns"]["patterns"] = behavioral_patterns
                self.stats["behavioral_patterns_found"] += len(behavioral_patterns)
                self.logger.info("Behavioral analysis complete", patterns=len(behavioral_patterns))

            # Phase 4: Vulnerability Chaining
            if enable_chaining:
                chaining_results = await self.run_vulnerability_chaining(
                    domain_id,
                    db_session,
                    max_chain_length=max_chain_length
                )
                results["vulnerability_chains"]["count"] = chaining_results["chains_found"]
                results["vulnerability_chains"]["critical_count"] = chaining_results.get("critical_chains", 0)
                results["vulnerability_chains"]["chains"] = chaining_results["chains"]
                self.stats["vulnerability_chains_found"] += chaining_results["chains_found"]
                self.logger.info("Chaining analysis complete", chains=chaining_results["chains_found"])

            # Phase 5: Predictive Analysis (placeholder for future implementation)
            if enable_predictive:
                predictions = await self.run_predictive_analysis(
                    domain_id,
                    db_session,
                    results
                )
                results["predictions"]["count"] = len(predictions)
                results["predictions"]["high_priority_count"] = len([
                    p for p in predictions if p.get("priority", 0) >= 8
                ])
                results["predictions"]["predictions"] = predictions
                self.stats["predictions_generated"] += len(predictions)
                self.logger.info("Predictive analysis complete", predictions=len(predictions))

            # Compile critical findings
            critical_findings = await self.get_critical_findings(
                domain_id,
                db_session,
                results
            )
            results["critical_findings"] = critical_findings

            # Generate statistics
            statistics = await self.get_statistics(domain_id, db_session)
            results["statistics"] = statistics

            results["analysis_completed_at"] = datetime.utcnow()

            self.logger.info(
                "Domain pattern analysis complete",
                domain_id=domain_id,
                duration_seconds=(results["analysis_completed_at"] - analysis_start).total_seconds(),
                total_patterns=sum([
                    results["temporal_patterns"]["count"],
                    results["spatial_patterns"]["count"],
                    results["behavioral_patterns"]["count"]
                ]),
                chains=results["vulnerability_chains"]["count"],
                predictions=results["predictions"]["count"]
            )

            return results

        except Exception as e:
            self.logger.error(
                "Domain pattern analysis failed",
                domain_id=domain_id,
                error=str(e),
                error_type=type(e).__name__
            )
            raise

    async def run_pattern_analysis(
        self,
        domain_id: int,
        db_session: AsyncSession,
        analyzer_type: str = "temporal",
        **kwargs
    ) -> List[Dict[str, Any]]:
        """
        Run specific pattern analyzer

        Args:
            domain_id: Domain to analyze
            db_session: Database session
            analyzer_type: Type of analyzer (temporal, spatial, behavioral)
            **kwargs: Additional arguments for analyzer

        Returns:
            List of detected patterns
        """
        self.logger.info("Running pattern analysis", type=analyzer_type, domain_id=domain_id)

        try:
            patterns = []

            if analyzer_type == "temporal":
                # Temporal analysis runs per subdomain
                subdomains = await self._get_subdomains(domain_id, db_session)
                time_window_days = kwargs.get("time_window_days", 30)

                for subdomain in subdomains:
                    subdomain_patterns = await self.temporal_analyzer.analyze_subdomain(
                        subdomain.id,
                        db_session,
                        time_window_days=time_window_days
                    )
                    patterns.extend(subdomain_patterns)

            elif analyzer_type == "spatial":
                # Spatial analysis runs per domain
                patterns = await self.spatial_analyzer.analyze_domain(
                    domain_id,
                    db_session
                )

            elif analyzer_type == "behavioral":
                # Behavioral analysis runs per domain
                lookback_days = kwargs.get("lookback_days", 7)
                patterns = await self.behavioral_analyzer.analyze_domain(
                    domain_id,
                    db_session,
                    lookback_days=lookback_days
                )

            else:
                self.logger.warning("Unknown analyzer type", type=analyzer_type)
                return []

            # Convert patterns to dictionaries
            pattern_dicts = [self._pattern_to_dict(p) for p in patterns]

            self.logger.info(
                "Pattern analysis complete",
                type=analyzer_type,
                patterns_found=len(pattern_dicts)
            )

            return pattern_dicts

        except Exception as e:
            self.logger.error(
                "Pattern analysis failed",
                type=analyzer_type,
                error=str(e)
            )
            return []

    async def run_vulnerability_chaining(
        self,
        domain_id: int,
        db_session: AsyncSession,
        max_chain_length: int = 5
    ) -> Dict[str, Any]:
        """
        Run vulnerability chaining analysis

        Args:
            domain_id: Domain to analyze
            db_session: Database session
            max_chain_length: Maximum chain length

        Returns:
            Chaining analysis results
        """
        self.logger.info("Running vulnerability chaining", domain_id=domain_id)

        try:
            results = await self.chaining_engine.analyze_domain(
                domain_id,
                db_session,
                max_chain_length=max_chain_length
            )

            self.logger.info(
                "Vulnerability chaining complete",
                domain_id=domain_id,
                chains_found=results["chains_found"]
            )

            return results

        except Exception as e:
            self.logger.error(
                "Vulnerability chaining failed",
                domain_id=domain_id,
                error=str(e)
            )
            return {
                "domain_id": domain_id,
                "chains_found": 0,
                "chains": [],
                "error": str(e)
            }

    async def run_predictive_analysis(
        self,
        domain_id: int,
        db_session: AsyncSession,
        current_findings: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """
        Run predictive analysis to guide future testing

        Note: This is a placeholder implementation. The full predictive analyzer
        will be implemented separately.

        Args:
            domain_id: Domain to analyze
            db_session: Database session
            current_findings: Current pattern analysis results

        Returns:
            List of predictions
        """
        self.logger.info("Running predictive analysis", domain_id=domain_id)

        try:
            # Load existing predictions from database
            result = await db_session.execute(
                select(PredictiveAnalysis).where(
                    PredictiveAnalysis.domain_id == domain_id
                ).order_by(PredictiveAnalysis.likelihood.desc())
            )
            predictions = result.scalars().all()

            # Convert to dictionaries
            prediction_dicts = [self._prediction_to_dict(p) for p in predictions]

            # TODO: When predictive analyzer is implemented, call it here
            # from app.intelligence.pattern_recognition.predictive_analyzer import PredictiveVulnerabilityAnalyzer
            # predictive_analyzer = PredictiveVulnerabilityAnalyzer()
            # new_predictions = await predictive_analyzer.analyze_domain(
            #     domain_id,
            #     db_session,
            #     patterns=current_findings
            # )
            # prediction_dicts.extend(new_predictions)

            self.logger.info(
                "Predictive analysis complete",
                domain_id=domain_id,
                predictions=len(prediction_dicts)
            )

            return prediction_dicts

        except Exception as e:
            self.logger.error(
                "Predictive analysis failed",
                domain_id=domain_id,
                error=str(e)
            )
            return []

    async def get_critical_findings(
        self,
        domain_id: int,
        db_session: AsyncSession,
        analysis_results: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """
        Extract and prioritize critical findings from analysis

        Args:
            domain_id: Domain ID
            db_session: Database session
            analysis_results: Complete analysis results

        Returns:
            List of critical findings sorted by priority
        """
        self.logger.info("Extracting critical findings", domain_id=domain_id)

        critical_findings = []

        # Extract critical patterns
        for pattern in analysis_results.get("temporal_patterns", {}).get("patterns", []):
            if pattern.get("risk_level") in ["Critical", "High"]:
                critical_findings.append({
                    "type": "temporal_pattern",
                    "severity": pattern.get("risk_level"),
                    "name": pattern.get("pattern_name"),
                    "description": pattern.get("description"),
                    "category": pattern.get("pattern_category"),
                    "pattern_type": pattern.get("pattern_type"),
                    "anomaly_score": pattern.get("anomaly_score", 0),
                    "affected_assets": pattern.get("affected_assets", [])
                })

        for pattern in analysis_results.get("spatial_patterns", {}).get("patterns", []):
            if pattern.get("risk_level") in ["Critical", "High"]:
                critical_findings.append({
                    "type": "spatial_pattern",
                    "severity": pattern.get("risk_level"),
                    "name": pattern.get("pattern_name"),
                    "description": pattern.get("description"),
                    "category": pattern.get("pattern_category"),
                    "pattern_type": pattern.get("pattern_type"),
                    "anomaly_score": pattern.get("anomaly_score", 0),
                    "affected_assets": pattern.get("affected_assets", [])
                })

        for pattern in analysis_results.get("behavioral_patterns", {}).get("patterns", []):
            if pattern.get("risk_level") in ["Critical", "High"]:
                critical_findings.append({
                    "type": "behavioral_pattern",
                    "severity": pattern.get("risk_level"),
                    "name": pattern.get("pattern_name"),
                    "description": pattern.get("description"),
                    "category": pattern.get("pattern_category"),
                    "pattern_type": pattern.get("pattern_type"),
                    "anomaly_score": pattern.get("anomaly_score", 0),
                    "affected_assets": pattern.get("affected_assets", [])
                })

        # Extract critical vulnerability chains
        for chain in analysis_results.get("vulnerability_chains", {}).get("chains", []):
            if chain.get("severity") in ["Critical", "High"]:
                critical_findings.append({
                    "type": "vulnerability_chain",
                    "severity": chain.get("severity"),
                    "name": chain.get("chain_name"),
                    "description": chain.get("description"),
                    "chain_length": chain.get("chain_length"),
                    "risk_score": chain.get("risk_score", 0),
                    "feasibility": chain.get("feasibility", 0),
                    "impact_score": chain.get("impact_score", 0),
                    "priority": chain.get("priority", 0)
                })

        # Extract high-priority predictions
        for prediction in analysis_results.get("predictions", {}).get("predictions", []):
            if prediction.get("priority", 0) >= 8:
                critical_findings.append({
                    "type": "prediction",
                    "severity": "High",  # Predictions don't have severity
                    "name": prediction.get("prediction_name"),
                    "description": prediction.get("description"),
                    "likelihood": prediction.get("likelihood", 0),
                    "confidence": prediction.get("confidence", 0),
                    "priority": prediction.get("priority", 0)
                })

        # Sort by severity and score
        severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
        critical_findings.sort(
            key=lambda x: (
                severity_order.get(x.get("severity", "Low"), 3),
                -x.get("risk_score", x.get("anomaly_score", 0))
            )
        )

        self.logger.info(
            "Critical findings extracted",
            domain_id=domain_id,
            count=len(critical_findings)
        )

        return critical_findings

    async def get_statistics(
        self,
        domain_id: int,
        db_session: AsyncSession
    ) -> Dict[str, Any]:
        """
        Get comprehensive pattern recognition statistics

        Args:
            domain_id: Domain ID
            db_session: Database session

        Returns:
            Statistics dictionary
        """
        self.logger.info("Generating statistics", domain_id=domain_id)

        # Count patterns by category
        result = await db_session.execute(
            select(
                PatternRecognition.pattern_category,
                func.count(PatternRecognition.id)
            ).where(
                and_(
                    PatternRecognition.status == "active",
                    PatternRecognition.false_positive == False
                )
            ).group_by(PatternRecognition.pattern_category)
        )
        category_counts = dict(result.all())

        # Count patterns by risk level
        result = await db_session.execute(
            select(
                PatternRecognition.risk_level,
                func.count(PatternRecognition.id)
            ).where(
                and_(
                    PatternRecognition.status == "active",
                    PatternRecognition.false_positive == False
                )
            ).group_by(PatternRecognition.risk_level)
        )
        risk_counts = dict(result.all())

        # Count vulnerability chains by severity
        result = await db_session.execute(
            select(
                VulnerabilityChain.severity,
                func.count(VulnerabilityChain.id)
            ).where(
                and_(
                    VulnerabilityChain.domain_id == domain_id,
                    VulnerabilityChain.false_positive == False
                )
            ).group_by(VulnerabilityChain.severity)
        )
        chain_severity_counts = dict(result.all())

        # Count predictions by priority
        result = await db_session.execute(
            select(
                PredictiveAnalysis.priority,
                func.count(PredictiveAnalysis.id)
            ).where(
                and_(
                    PredictiveAnalysis.domain_id == domain_id,
                    PredictiveAnalysis.validated == False
                )
            ).group_by(PredictiveAnalysis.priority)
        )
        prediction_priority_counts = dict(result.all())

        statistics = {
            "session_stats": self.stats,
            "pattern_by_category": category_counts,
            "pattern_by_risk": risk_counts,
            "chains_by_severity": chain_severity_counts,
            "predictions_by_priority": prediction_priority_counts,
            "total_patterns": sum(category_counts.values()),
            "total_chains": sum(chain_severity_counts.values()),
            "total_predictions": sum(prediction_priority_counts.values())
        }

        self.logger.info("Statistics generated", domain_id=domain_id)

        return statistics

    # Helper methods

    async def _get_domain(
        self,
        domain_id: int,
        db_session: AsyncSession
    ) -> Optional[Domain]:
        """Get domain by ID"""
        result = await db_session.execute(
            select(Domain).where(Domain.id == domain_id)
        )
        return result.scalar_one_or_none()

    async def _get_subdomains(
        self,
        domain_id: int,
        db_session: AsyncSession
    ) -> List[Subdomain]:
        """Get all subdomains for a domain"""
        result = await db_session.execute(
            select(Subdomain).where(Subdomain.domain_id == domain_id)
        )
        return result.scalars().all()

    def _pattern_to_dict(self, pattern: PatternRecognition) -> Dict[str, Any]:
        """Convert PatternRecognition model to dictionary"""
        return {
            "id": pattern.id,
            "pattern_id": pattern.pattern_id,
            "pattern_category": pattern.pattern_category,
            "pattern_type": pattern.pattern_type,
            "pattern_name": pattern.pattern_name,
            "description": pattern.description,
            "evidence": json.loads(pattern.evidence) if pattern.evidence else {},
            "affected_assets": json.loads(pattern.affected_assets) if pattern.affected_assets else [],
            "frequency": pattern.frequency,
            "consistency": pattern.consistency,
            "anomaly_score": pattern.anomaly_score,
            "time_window_start": pattern.time_window_start.isoformat() if pattern.time_window_start else None,
            "time_window_end": pattern.time_window_end.isoformat() if pattern.time_window_end else None,
            "time_pattern": pattern.time_pattern,
            "relationship_type": pattern.relationship_type,
            "relationship_graph": json.loads(pattern.relationship_graph) if pattern.relationship_graph else {},
            "baseline_behavior": json.loads(pattern.baseline_behavior) if pattern.baseline_behavior else {},
            "observed_behavior": json.loads(pattern.observed_behavior) if pattern.observed_behavior else {},
            "deviation_score": pattern.deviation_score,
            "risk_level": pattern.risk_level,
            "potential_vulnerabilities": json.loads(pattern.potential_vulnerabilities) if pattern.potential_vulnerabilities else [],
            "exploitation_scenarios": json.loads(pattern.exploitation_scenarios) if pattern.exploitation_scenarios else [],
            "discovered_at": pattern.discovered_at.isoformat() if pattern.discovered_at else None,
            "last_observed": pattern.last_observed.isoformat() if pattern.last_observed else None,
            "observation_count": pattern.observation_count,
            "status": pattern.status,
            "validated": pattern.validated,
            "false_positive": pattern.false_positive
        }

    def _prediction_to_dict(self, prediction: PredictiveAnalysis) -> Dict[str, Any]:
        """Convert PredictiveAnalysis model to dictionary"""
        return {
            "id": prediction.id,
            "prediction_type": prediction.prediction_type,
            "prediction_name": prediction.prediction_name,
            "description": prediction.description,
            "predicted_vulnerability_types": json.loads(prediction.predicted_vulnerability_types) if prediction.predicted_vulnerability_types else [],
            "likelihood": prediction.likelihood,
            "confidence": prediction.confidence,
            "technology_stack": json.loads(prediction.technology_stack) if prediction.technology_stack else [],
            "observed_patterns": json.loads(prediction.observed_patterns) if prediction.observed_patterns else [],
            "suggested_test_areas": json.loads(prediction.suggested_test_areas) if prediction.suggested_test_areas else [],
            "suggested_payloads": json.loads(prediction.suggested_payloads) if prediction.suggested_payloads else [],
            "suggested_tools": json.loads(prediction.suggested_tools) if prediction.suggested_tools else [],
            "priority": prediction.priority,
            "validated": prediction.validated,
            "validation_result": prediction.validation_result,
            "created_at": prediction.created_at.isoformat() if prediction.created_at else None
        }
