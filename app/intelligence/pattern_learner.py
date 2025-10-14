"""
Pattern Learning System

Learns from user feedback to improve vulnerability detection:
- Trains on validated true/false positives
- Refines detection patterns
- Reduces false positive rates
- Adapts to environment-specific patterns
"""

import json
from typing import List, Dict, Optional, Any
from datetime import datetime, timedelta
import structlog
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_

from app.models.vulnerability import (
    VulnerabilityPattern, VulnerabilityFeedback, Vulnerability
)

logger = structlog.get_logger()


class PatternLearner:
    """
    Learns and refines vulnerability detection patterns

    Features:
    - Pattern performance tracking
    - Automatic threshold adjustment
    - False positive reduction
    - Confidence scoring improvement
    """

    def __init__(self):
        self.logger = logger.bind(component="pattern_learner")
        self.min_training_samples = 20  # Minimum feedback needed for retraining

    async def process_feedback(
        self,
        vulnerability_id: int,
        is_true_positive: bool,
        reviewed_by: str,
        db_session: AsyncSession,
        comments: Optional[str] = None,
        suggested_severity: Optional[str] = None
    ) -> VulnerabilityFeedback:
        """
        Process user feedback on vulnerability

        Args:
            vulnerability_id: ID of vulnerability
            is_true_positive: Whether this is a true positive
            reviewed_by: User who reviewed
            db_session: Database session
            comments: Optional feedback comments
            suggested_severity: Optional severity correction

        Returns:
            VulnerabilityFeedback record
        """
        # Get vulnerability
        result = await db_session.execute(
            select(Vulnerability).where(Vulnerability.id == vulnerability_id)
        )
        vulnerability = result.scalar_one_or_none()

        if not vulnerability:
            raise ValueError(f"Vulnerability {vulnerability_id} not found")

        # Create feedback record
        feedback = VulnerabilityFeedback(
            vulnerability_id=vulnerability_id,
            is_true_positive=is_true_positive,
            severity_correct=(suggested_severity is None or suggested_severity == vulnerability.severity),
            suggested_severity=suggested_severity,
            comments=comments,
            reviewed_by=reviewed_by,
            reviewed_at=datetime.utcnow()
        )

        db_session.add(feedback)

        # Update vulnerability status
        if is_true_positive:
            vulnerability.status = "confirmed"
            vulnerability.confirmed_at = datetime.utcnow()
        else:
            vulnerability.status = "false_positive"

        await db_session.commit()

        # Trigger pattern retraining if enough feedback
        await self._check_and_retrain(vulnerability.type, db_session)

        self.logger.info(
            "Feedback processed",
            vuln_id=vulnerability_id,
            is_tp=is_true_positive,
            reviewed_by=reviewed_by
        )

        return feedback

    async def _check_and_retrain(
        self,
        vuln_type: str,
        db_session: AsyncSession
    ):
        """Check if retraining is needed and trigger if so"""
        # Count feedback for this vulnerability type
        result = await db_session.execute(
            select(func.count(VulnerabilityFeedback.id)).join(
                Vulnerability
            ).where(
                and_(
                    Vulnerability.type == vuln_type,
                    VulnerabilityFeedback.used_for_training == False
                )
            )
        )
        pending_feedback_count = result.scalar()

        if pending_feedback_count >= self.min_training_samples:
            await self.retrain_patterns(vuln_type, db_session)

    async def retrain_patterns(
        self,
        vuln_type: str,
        db_session: AsyncSession
    ) -> Dict[str, Any]:
        """
        Retrain patterns for specific vulnerability type

        Args:
            vuln_type: Type of vulnerability
            db_session: Database session

        Returns:
            Training statistics
        """
        self.logger.info("Starting pattern retraining", vuln_type=vuln_type)

        # Get all feedback for this type
        result = await db_session.execute(
            select(VulnerabilityFeedback).join(
                Vulnerability
            ).where(
                Vulnerability.type == vuln_type
            )
        )
        all_feedback = result.scalars().all()

        if len(all_feedback) < self.min_training_samples:
            return {"status": "insufficient_data", "samples": len(all_feedback)}

        # Calculate metrics
        true_positives = sum(1 for f in all_feedback if f.is_true_positive)
        false_positives = len(all_feedback) - true_positives

        precision = true_positives / len(all_feedback) if all_feedback else 0

        # Get or create pattern
        result = await db_session.execute(
            select(VulnerabilityPattern).where(
                VulnerabilityPattern.vulnerability_type == vuln_type
            ).limit(1)
        )
        pattern = result.scalar_one_or_none()

        if not pattern:
            # Create new pattern
            pattern = VulnerabilityPattern(
                pattern_name=f"{vuln_type}_detection",
                pattern_type="ml_model",
                vulnerability_type=vuln_type,
                pattern_data=json.dumps({"type": vuln_type}),
                confidence_threshold=0.7
            )
            db_session.add(pattern)

        # Update pattern metrics
        pattern.true_positives = true_positives
        pattern.false_positives = false_positives
        pattern.precision = precision
        pattern.last_trained = datetime.utcnow()

        # Adjust confidence threshold based on precision
        if precision < 0.6:
            # High false positive rate - increase threshold
            pattern.confidence_threshold = min(0.9, pattern.confidence_threshold + 0.1)
        elif precision > 0.9:
            # Very accurate - can lower threshold to catch more
            pattern.confidence_threshold = max(0.5, pattern.confidence_threshold - 0.05)

        # Mark feedback as used for training
        for feedback in all_feedback:
            feedback.used_for_training = True

        await db_session.commit()

        self.logger.info(
            "Pattern retraining complete",
            vuln_type=vuln_type,
            precision=round(precision, 3),
            threshold=pattern.confidence_threshold
        )

        return {
            "status": "success",
            "vuln_type": vuln_type,
            "samples_trained": len(all_feedback),
            "precision": precision,
            "new_threshold": pattern.confidence_threshold
        }

    async def get_pattern_performance(
        self,
        db_session: AsyncSession,
        vuln_type: Optional[str] = None
    ) -> List[Dict]:
        """
        Get performance metrics for patterns

        Args:
            db_session: Database session
            vuln_type: Optional filter by vulnerability type

        Returns:
            List of pattern performance metrics
        """
        query = select(VulnerabilityPattern)

        if vuln_type:
            query = query.where(VulnerabilityPattern.vulnerability_type == vuln_type)

        result = await db_session.execute(query)
        patterns = result.scalars().all()

        performance = []
        for pattern in patterns:
            total = pattern.true_positives + pattern.false_positives
            performance.append({
                "pattern_name": pattern.pattern_name,
                "vuln_type": pattern.vulnerability_type,
                "accuracy": pattern.accuracy,
                "precision": pattern.precision,
                "recall": pattern.recall,
                "f1_score": pattern.f1_score,
                "total_predictions": total,
                "true_positives": pattern.true_positives,
                "false_positives": pattern.false_positives,
                "confidence_threshold": pattern.confidence_threshold,
                "last_trained": pattern.last_trained.isoformat() if pattern.last_trained else None
            })

        return performance
