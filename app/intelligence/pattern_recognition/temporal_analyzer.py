"""
Temporal Pattern Analyzer

Identifies time-based patterns and behaviors:
- Authentication strength variations over time
- Response time anomalies at specific hours
- Scheduled task patterns
- Time-based access control weaknesses
- Periodic behavior changes
"""

import json
import uuid
from typing import List, Dict, Optional, Any
from datetime import datetime, timedelta
from collections import defaultdict
import structlog
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, or_

from app.models.vulnerability import PatternRecognition
from app.models.http_traffic import HTTPTraffic
from app.models.domain import Subdomain

logger = structlog.get_logger()


class TemporalPatternAnalyzer:
    """
    Analyzes temporal patterns in application behavior

    Patterns detected:
    - Time-based authentication weaknesses
    - Response time variations by time of day
    - Scheduled maintenance windows
    - After-hours security degradation
    - Periodic configuration changes
    """

    def __init__(self):
        self.logger = logger.bind(component="temporal_analyzer")

    async def analyze_subdomain(
        self,
        subdomain_id: int,
        db_session: AsyncSession,
        time_window_days: int = 30
    ) -> List[PatternRecognition]:
        """
        Analyze temporal patterns for a subdomain

        Args:
            subdomain_id: Subdomain to analyze
            db_session: Database session
            time_window_days: Analysis window in days

        Returns:
            List of detected temporal patterns
        """
        self.logger.info("Analyzing temporal patterns", subdomain_id=subdomain_id)

        patterns = []

        # Get HTTP traffic for time window
        since = datetime.utcnow() - timedelta(days=time_window_days)
        result = await db_session.execute(
            select(HTTPTraffic).where(
                and_(
                    HTTPTraffic.subdomain_id == subdomain_id,
                    HTTPTraffic.timestamp >= since
                )
            ).order_by(HTTPTraffic.timestamp)
        )
        traffic = result.scalars().all()

        if len(traffic) < 10:  # Need minimum data
            return patterns

        # Analyze different temporal dimensions
        patterns.extend(await self._analyze_authentication_patterns(traffic, subdomain_id, db_session))
        patterns.extend(await self._analyze_response_time_patterns(traffic, subdomain_id, db_session))
        patterns.extend(await self._analyze_error_rate_patterns(traffic, subdomain_id, db_session))
        patterns.extend(await self._analyze_availability_patterns(traffic, subdomain_id, db_session))

        return patterns

    async def _analyze_authentication_patterns(
        self,
        traffic: List[HTTPTraffic],
        subdomain_id: int,
        db_session: AsyncSession
    ) -> List[PatternRecognition]:
        """Detect time-based authentication weaknesses"""
        patterns = []

        # Group traffic by hour of day
        hourly_auth = defaultdict(list)

        for req in traffic:
            if "/login" in req.path or "/auth" in req.path or req.status_code in [401, 403]:
                hour = req.timestamp.hour
                hourly_auth[hour].append(req)

        if not hourly_auth:
            return patterns

        # Calculate authentication failure rates by hour
        hourly_failure_rate = {}
        for hour, reqs in hourly_auth.items():
            failures = sum(1 for r in reqs if r.status_code in [401, 403])
            hourly_failure_rate[hour] = failures / len(reqs) if reqs else 0

        # Detect anomalous hours (significantly different failure rates)
        if len(hourly_failure_rate) > 3:
            avg_rate = sum(hourly_failure_rate.values()) / len(hourly_failure_rate)

            # Find hours with significantly lower failure rates (possible weakness)
            weak_hours = [
                hour for hour, rate in hourly_failure_rate.items()
                if rate < avg_rate * 0.5  # 50% less than average
            ]

            if weak_hours:
                pattern = PatternRecognition(
                    pattern_id=str(uuid.uuid4()),
                    pattern_category="temporal",
                    pattern_type="time_based_auth_weakness",
                    pattern_name=f"Reduced Authentication Enforcement During Hours: {weak_hours}",
                    description=f"Authentication failure rate drops significantly during hours {weak_hours}, suggesting weaker enforcement or different configuration.",
                    evidence=json.dumps({
                        "weak_hours": weak_hours,
                        "hourly_failure_rates": hourly_failure_rate,
                        "average_rate": avg_rate,
                        "sample_size": len(traffic)
                    }),
                    affected_assets=json.dumps([subdomain_id]),
                    frequency=len(weak_hours),
                    consistency=0.8,
                    anomaly_score=0.7,
                    time_window_start=traffic[0].timestamp,
                    time_window_end=traffic[-1].timestamp,
                    time_pattern="hourly",
                    risk_level="High",
                    potential_vulnerabilities=json.dumps(["time_based_access_control", "configuration_change"]),
                    exploitation_scenarios=json.dumps([
                        "Brute force attacks during weak hours",
                        "Credential stuffing at specific times",
                        "Automated attacks timed to bypass controls"
                    ])
                )

                db_session.add(pattern)
                patterns.append(pattern)

        await db_session.commit()
        return patterns

    async def _analyze_response_time_patterns(
        self,
        traffic: List[HTTPTraffic],
        subdomain_id: int,
        db_session: AsyncSession
    ) -> List[PatternRecognition]:
        """Detect suspicious response time patterns"""
        patterns = []

        # Group by hour and calculate average response times
        hourly_response_times = defaultdict(list)

        for req in traffic:
            if req.response_time_ms:
                hour = req.timestamp.hour
                hourly_response_times[hour].append(req.response_time_ms)

        if len(hourly_response_times) < 5:
            return patterns

        # Calculate averages
        hourly_avg = {}
        for hour, times in hourly_response_times.items():
            hourly_avg[hour] = sum(times) / len(times)

        overall_avg = sum(hourly_avg.values()) / len(hourly_avg)

        # Detect anomalously slow hours
        slow_hours = [
            hour for hour, avg in hourly_avg.items()
            if avg > overall_avg * 2  # 2x slower
        ]

        if slow_hours:
            pattern = PatternRecognition(
                pattern_id=str(uuid.uuid4()),
                pattern_category="temporal",
                pattern_type="response_time_anomaly",
                pattern_name=f"Abnormally Slow Response Times During Hours: {slow_hours}",
                description=f"Response times are significantly slower during hours {slow_hours}, possibly indicating scheduled tasks, backups, or resource constraints.",
                evidence=json.dumps({
                    "slow_hours": slow_hours,
                    "hourly_averages": hourly_avg,
                    "overall_average": overall_avg
                }),
                affected_assets=json.dumps([subdomain_id]),
                frequency=len(slow_hours),
                consistency=0.7,
                anomaly_score=0.6,
                time_window_start=traffic[0].timestamp,
                time_window_end=traffic[-1].timestamp,
                time_pattern="hourly",
                baseline_behavior=json.dumps({"avg_response_ms": overall_avg}),
                observed_behavior=json.dumps({"slow_hours": hourly_avg}),
                deviation_score=max(hourly_avg.values()) / overall_avg if overall_avg > 0 else 1,
                risk_level="Medium",
                potential_vulnerabilities=json.dumps(["resource_exhaustion", "dos_vulnerability"]),
                exploitation_scenarios=json.dumps([
                    "Timing attack exploitation",
                    "Resource exhaustion during peak load",
                    "Information leakage through timing"
                ])
            )

            db_session.add(pattern)
            patterns.append(pattern)

        await db_session.commit()
        return patterns

    async def _analyze_error_rate_patterns(
        self,
        traffic: List[HTTPTraffic],
        subdomain_id: int,
        db_session: AsyncSession
    ) -> List[PatternRecognition]:
        """Detect temporal error rate patterns"""
        patterns = []

        # Group errors by hour
        hourly_errors = defaultdict(lambda: {"total": 0, "errors": 0})

        for req in traffic:
            hour = req.timestamp.hour
            hourly_errors[hour]["total"] += 1
            if req.status_code and req.status_code >= 500:
                hourly_errors[hour]["errors"] += 1

        if len(hourly_errors) < 5:
            return patterns

        # Calculate error rates
        hourly_error_rate = {}
        for hour, counts in hourly_errors.items():
            if counts["total"] > 0:
                hourly_error_rate[hour] = counts["errors"] / counts["total"]

        avg_error_rate = sum(hourly_error_rate.values()) / len(hourly_error_rate)

        # Find high error hours
        high_error_hours = [
            hour for hour, rate in hourly_error_rate.items()
            if rate > avg_error_rate * 3  # 3x average
        ]

        if high_error_hours:
            pattern = PatternRecognition(
                pattern_id=str(uuid.uuid4()),
                pattern_category="temporal",
                pattern_type="periodic_error_spike",
                pattern_name=f"Elevated Error Rates During Hours: {high_error_hours}",
                description=f"Server errors spike significantly during hours {high_error_hours}, suggesting scheduled tasks, maintenance, or resource issues.",
                evidence=json.dumps({
                    "high_error_hours": high_error_hours,
                    "hourly_error_rates": hourly_error_rate,
                    "average_error_rate": avg_error_rate
                }),
                affected_assets=json.dumps([subdomain_id]),
                frequency=len(high_error_hours),
                consistency=0.75,
                anomaly_score=0.8,
                time_window_start=traffic[0].timestamp,
                time_window_end=traffic[-1].timestamp,
                time_pattern="hourly",
                risk_level="Medium",
                potential_vulnerabilities=json.dumps(["information_disclosure", "dos_vulnerability"]),
                exploitation_scenarios=json.dumps([
                    "Error-based information disclosure",
                    "Service disruption timing",
                    "Maintenance window exploitation"
                ])
            )

            db_session.add(pattern)
            patterns.append(pattern)

        await db_session.commit()
        return patterns

    async def _analyze_availability_patterns(
        self,
        traffic: List[HTTPTraffic],
        subdomain_id: int,
        db_session: AsyncSession
    ) -> List[PatternRecognition]:
        """Detect availability and uptime patterns"""
        patterns = []

        # Group by day of week
        daily_traffic = defaultdict(list)

        for req in traffic:
            day = req.timestamp.weekday()  # 0=Monday, 6=Sunday
            daily_traffic[day].append(req)

        if len(daily_traffic) < 3:
            return patterns

        # Calculate daily activity levels
        daily_activity = {day: len(reqs) for day, reqs in daily_traffic.items()}
        avg_activity = sum(daily_activity.values()) / len(daily_activity)

        # Find low activity days
        low_activity_days = [
            day for day, count in daily_activity.items()
            if count < avg_activity * 0.3  # Less than 30% of average
        ]

        if low_activity_days:
            day_names = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
            low_days_names = [day_names[d] for d in low_activity_days]

            pattern = PatternRecognition(
                pattern_id=str(uuid.uuid4()),
                pattern_category="temporal",
                pattern_type="reduced_availability",
                pattern_name=f"Reduced Activity on: {', '.join(low_days_names)}",
                description=f"Significantly reduced traffic/availability on {', '.join(low_days_names)}, suggesting scheduled downtime or reduced service hours.",
                evidence=json.dumps({
                    "low_activity_days": low_activity_days,
                    "daily_activity": daily_activity,
                    "average_activity": avg_activity
                }),
                affected_assets=json.dumps([subdomain_id]),
                frequency=len(low_activity_days),
                consistency=0.7,
                anomaly_score=0.5,
                time_window_start=traffic[0].timestamp,
                time_window_end=traffic[-1].timestamp,
                time_pattern="weekly",
                risk_level="Low",
                potential_vulnerabilities=json.dumps(["service_information"]),
                exploitation_scenarios=json.dumps([
                    "Service reconnaissance",
                    "Maintenance window identification",
                    "Timing-based attacks"
                ])
            )

            db_session.add(pattern)
            patterns.append(pattern)

        await db_session.commit()
        return patterns
