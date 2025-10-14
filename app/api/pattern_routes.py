"""
Pattern Recognition and Vulnerability Chaining API Routes

Endpoints for accessing advanced pattern recognition and vulnerability chaining capabilities.
"""

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, func, desc
from typing import Optional
from datetime import datetime

from app.models.domain import Domain
from app.models.pattern import (
    TemporalPattern,
    SpatialPattern,
    BehavioralPattern,
    PredictiveAnalysis,
    AttackGraph
)
from app.models.vulnerability import VulnerabilityChain
from app.intelligence.pattern_recognition.orchestrator import (
    PatternRecognitionOrchestrator
)

router = APIRouter(prefix="/api/patterns", tags=["Pattern Recognition"])


async def get_db():
    """Dependency to get database session"""
    from main import app_state
    async with app_state["db_manager"].get_session() as session:
        yield session


@router.post("/analyze/{domain_id}")
async def analyze_domain_patterns(
    domain_id: int,
    enable_temporal: bool = True,
    enable_spatial: bool = True,
    enable_behavioral: bool = True,
    enable_chaining: bool = True,
    enable_predictive: bool = True,
    time_window_days: int = 30,
    lookback_days: int = 7,
    max_chain_length: int = 5,
    db: AsyncSession = Depends(get_db)
):
    """
    Run complete pattern recognition analysis on a domain

    This endpoint orchestrates all pattern recognition components:
    - Temporal patterns (time-based behaviors)
    - Spatial patterns (infrastructure relationships)
    - Behavioral patterns (anomalies)
    - Vulnerability chains (attack paths)
    - Predictive analysis (testing guidance)
    """
    # Check domain exists
    stmt = select(Domain).where(Domain.id == domain_id)
    result = await db.execute(stmt)
    domain = result.scalar_one_or_none()

    if not domain:
        raise HTTPException(status_code=404, detail=f"Domain {domain_id} not found")

    # Run pattern recognition
    orchestrator = PatternRecognitionOrchestrator()

    try:
        results = await orchestrator.analyze_domain(
            domain_id=domain_id,
            db_session=db,
            enable_temporal=enable_temporal,
            enable_spatial=enable_spatial,
            enable_behavioral=enable_behavioral,
            enable_chaining=enable_chaining,
            enable_predictive=enable_predictive,
            time_window_days=time_window_days,
            lookback_days=lookback_days,
            max_chain_length=max_chain_length
        )

        return {
            "success": True,
            "domain": domain.domain,
            "domain_id": domain_id,
            "analysis_completed_at": results.get("analysis_completed_at", datetime.utcnow()).isoformat(),
            "summary": {
                "temporal_patterns": results["temporal_patterns"]["count"],
                "spatial_patterns": results["spatial_patterns"]["count"],
                "behavioral_patterns": results["behavioral_patterns"]["count"],
                "vulnerability_chains": results["vulnerability_chains"]["count"],
                "critical_chains": results["vulnerability_chains"].get("critical_count", 0),
                "predictions": results["predictions"]["count"],
                "critical_findings": len(results.get("critical_findings", []))
            },
            "results": results
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


@router.get("/temporal/{domain_id}")
async def get_temporal_patterns(
    domain_id: int,
    subdomain_id: Optional[int] = None,
    pattern_type: Optional[str] = None,
    min_confidence: float = Query(0.0, ge=0.0, le=1.0),
    limit: int = Query(100, ge=1, le=1000),
    db: AsyncSession = Depends(get_db)
):
    """
    Get temporal patterns for a domain

    Temporal patterns reveal time-based behaviors like:
    - Authentication weaknesses at specific times
    - Rate limiting variations
    - Maintenance windows
    - Time-based access control changes
    """
    stmt = select(TemporalPattern).where(TemporalPattern.domain_id == domain_id)

    if subdomain_id:
        stmt = stmt.where(TemporalPattern.subdomain_id == subdomain_id)

    if pattern_type:
        stmt = stmt.where(TemporalPattern.pattern_type == pattern_type)

    stmt = stmt.where(TemporalPattern.confidence >= min_confidence)
    stmt = stmt.order_by(desc(TemporalPattern.confidence))
    stmt = stmt.limit(limit)

    result = await db.execute(stmt)
    patterns = result.scalars().all()

    return {
        "success": True,
        "count": len(patterns),
        "patterns": [
            {
                "id": p.id,
                "pattern_type": p.pattern_type,
                "pattern_name": p.pattern_name,
                "description": p.description,
                "confidence": p.confidence,
                "security_impact": p.security_impact,
                "exploitability": p.exploitability,
                "time_window_start": p.time_window_start.isoformat() if p.time_window_start else None,
                "time_window_end": p.time_window_end.isoformat() if p.time_window_end else None,
                "recurrence": p.recurrence,
                "baseline_behavior": p.baseline_behavior,
                "anomaly_behavior": p.anomaly_behavior,
                "first_observed": p.first_observed.isoformat(),
                "last_observed": p.last_observed.isoformat()
            }
            for p in patterns
        ]
    }


@router.get("/spatial/{domain_id}")
async def get_spatial_patterns(
    domain_id: int,
    pattern_type: Optional[str] = None,
    min_confidence: float = Query(0.0, ge=0.0, le=1.0),
    limit: int = Query(100, ge=1, le=1000),
    db: AsyncSession = Depends(get_db)
):
    """
    Get spatial patterns for a domain

    Spatial patterns reveal infrastructure relationships like:
    - Shared authentication systems
    - Common hosting infrastructure
    - Technology clusters
    - Session/cookie sharing
    """
    stmt = select(SpatialPattern).where(SpatialPattern.domain_id == domain_id)

    if pattern_type:
        stmt = stmt.where(SpatialPattern.pattern_type == pattern_type)

    stmt = stmt.where(SpatialPattern.confidence >= min_confidence)
    stmt = stmt.order_by(desc(SpatialPattern.confidence))
    stmt = stmt.limit(limit)

    result = await db.execute(stmt)
    patterns = result.scalars().all()

    return {
        "success": True,
        "count": len(patterns),
        "patterns": [
            {
                "id": p.id,
                "pattern_type": p.pattern_type,
                "pattern_name": p.pattern_name,
                "description": p.description,
                "confidence": p.confidence,
                "security_impact": p.security_impact,
                "relationship_type": p.relationship_type,
                "relationship_strength": p.relationship_strength,
                "node_count": p.node_count,
                "edge_count": p.edge_count,
                "attack_surface_multiplier": p.attack_surface_multiplier,
                "lateral_movement_potential": p.lateral_movement_potential,
                "related_subdomains": p.related_subdomains,
                "evidence": p.evidence,
                "discovered_at": p.discovered_at.isoformat()
            }
            for p in patterns
        ]
    }


@router.get("/behavioral/{domain_id}")
async def get_behavioral_patterns(
    domain_id: int,
    subdomain_id: Optional[int] = None,
    pattern_type: Optional[str] = None,
    min_confidence: float = Query(0.0, ge=0.0, le=1.0),
    limit: int = Query(100, ge=1, le=1000),
    db: AsyncSession = Depends(get_db)
):
    """
    Get behavioral patterns for a domain

    Behavioral patterns reveal anomalous responses like:
    - Response time anomalies (timing attacks)
    - Error patterns (information disclosure)
    - Input reflection (XSS/injection indicators)
    - Status code anomalies
    - Response size anomalies
    """
    stmt = select(BehavioralPattern).where(BehavioralPattern.domain_id == domain_id)

    if subdomain_id:
        stmt = stmt.where(BehavioralPattern.subdomain_id == subdomain_id)

    if pattern_type:
        stmt = stmt.where(BehavioralPattern.pattern_type == pattern_type)

    stmt = stmt.where(BehavioralPattern.confidence >= min_confidence)
    stmt = stmt.order_by(desc(BehavioralPattern.confidence))
    stmt = stmt.limit(limit)

    result = await db.execute(stmt)
    patterns = result.scalars().all()

    return {
        "success": True,
        "count": len(patterns),
        "patterns": [
            {
                "id": p.id,
                "pattern_type": p.pattern_type,
                "pattern_name": p.pattern_name,
                "description": p.description,
                "confidence": p.confidence,
                "security_impact": p.security_impact,
                "exploitability": p.exploitability,
                "endpoint": p.endpoint,
                "trigger_conditions": p.trigger_conditions,
                "normal_behavior": p.normal_behavior,
                "anomalous_behavior": p.anomalous_behavior,
                "z_score": p.z_score,
                "potential_vulnerability_types": p.potential_vulnerability_types,
                "first_observed": p.first_observed.isoformat(),
                "last_observed": p.last_observed.isoformat()
            }
            for p in patterns
        ]
    }


@router.get("/chains/{domain_id}")
async def get_vulnerability_chains(
    domain_id: int,
    severity: Optional[str] = Query(None, regex="^(critical|high|medium|low)$"),
    attack_goal: Optional[str] = None,
    min_risk_score: float = Query(0.0, ge=0.0, le=100.0),
    verified_only: bool = False,
    limit: int = Query(100, ge=1, le=1000),
    db: AsyncSession = Depends(get_db)
):
    """
    Get vulnerability chains for a domain

    Vulnerability chains combine multiple vulnerabilities into complete attack paths:
    - Account takeover chains
    - Data exfiltration paths
    - Remote code execution sequences
    - Privilege escalation chains
    - Infrastructure compromise paths
    """
    stmt = select(VulnerabilityChain).where(VulnerabilityChain.domain_id == domain_id)

    if severity:
        stmt = stmt.where(VulnerabilityChain.severity == severity)

    if attack_goal:
        stmt = stmt.where(VulnerabilityChain.attack_goal == attack_goal)

    stmt = stmt.where(VulnerabilityChain.risk_score >= min_risk_score)

    if verified_only:
        stmt = stmt.where(VulnerabilityChain.verified == True)

    stmt = stmt.where(VulnerabilityChain.false_positive == False)
    stmt = stmt.order_by(desc(VulnerabilityChain.risk_score))
    stmt = stmt.limit(limit)

    result = await db.execute(stmt)
    chains = result.scalars().all()

    return {
        "success": True,
        "count": len(chains),
        "chains": [
            {
                "id": c.id,
                "chain_name": c.chain_name,
                "description": c.description,
                "attack_goal": c.attack_goal,
                "severity": c.severity,
                "risk_score": c.risk_score,
                "priority": c.priority,
                "chain_length": c.chain_length,
                "complexity": c.complexity,
                "complexity_score": c.complexity_score,
                "feasibility": c.feasibility,
                "impact_score": c.impact_score,
                "vulnerability_ids": c.vulnerability_ids,
                "steps": c.steps,
                "prerequisites": c.prerequisites,
                "required_skills": c.required_skills,
                "estimated_time": c.estimated_time,
                "impact_breakdown": c.impact_breakdown,
                "affected_assets": c.affected_assets,
                "detection_difficulty": c.detection_difficulty,
                "prevention_recommendations": c.prevention_recommendations,
                "verified": c.verified,
                "discovered_at": c.discovered_at.isoformat()
            }
            for c in chains
        ]
    }


@router.get("/chains/{domain_id}/{chain_id}")
async def get_vulnerability_chain_details(
    domain_id: int,
    chain_id: int,
    db: AsyncSession = Depends(get_db)
):
    """
    Get detailed information about a specific vulnerability chain
    """
    stmt = select(VulnerabilityChain).where(
        and_(
            VulnerabilityChain.id == chain_id,
            VulnerabilityChain.domain_id == domain_id
        )
    )
    result = await db.execute(stmt)
    chain = result.scalar_one_or_none()

    if not chain:
        raise HTTPException(status_code=404, detail=f"Chain {chain_id} not found")

    return {
        "success": True,
        "chain": {
            "id": chain.id,
            "chain_name": chain.chain_name,
            "description": chain.description,
            "attack_goal": chain.attack_goal,
            "severity": chain.severity,
            "risk_score": chain.risk_score,
            "priority": chain.priority,
            "chain_length": chain.chain_length,
            "complexity": chain.complexity,
            "complexity_score": chain.complexity_score,
            "feasibility": chain.feasibility,
            "impact_score": chain.impact_score,
            "vulnerability_ids": chain.vulnerability_ids,
            "pattern_ids": chain.pattern_ids,
            "steps": chain.steps,
            "prerequisites": chain.prerequisites,
            "required_skills": chain.required_skills,
            "estimated_time": chain.estimated_time,
            "impact_breakdown": chain.impact_breakdown,
            "affected_assets": chain.affected_assets,
            "detection_difficulty": chain.detection_difficulty,
            "prevention_recommendations": chain.prevention_recommendations,
            "remediation_steps": chain.remediation_steps,
            "verified": chain.verified,
            "verified_at": chain.verified_at.isoformat() if chain.verified_at else None,
            "verified_by": chain.verified_by,
            "false_positive": chain.false_positive,
            "notes": chain.notes,
            "discovered_at": chain.discovered_at.isoformat(),
            "created_at": chain.created_at.isoformat(),
            "updated_at": chain.updated_at.isoformat()
        }
    }


@router.get("/predictions/{domain_id}")
async def get_predictions(
    domain_id: int,
    subdomain_id: Optional[int] = None,
    prediction_type: Optional[str] = None,
    min_likelihood: float = Query(0.0, ge=0.0, le=1.0),
    min_priority: int = Query(1, ge=1, le=10),
    validated_only: bool = False,
    limit: int = Query(100, ge=1, le=1000),
    db: AsyncSession = Depends(get_db)
):
    """
    Get predictive vulnerability analysis for a domain

    Predictions guide manual testing by identifying likely vulnerabilities based on:
    - Technology stack (WordPress, Spring Boot, etc.)
    - Observed patterns (temporal, spatial, behavioral)
    - Configuration indicators (debug mode, directory listing, etc.)
    - Historical data (similar vulnerabilities in similar systems)
    """
    stmt = select(PredictiveAnalysis).where(PredictiveAnalysis.domain_id == domain_id)

    if subdomain_id:
        stmt = stmt.where(PredictiveAnalysis.subdomain_id == subdomain_id)

    if prediction_type:
        stmt = stmt.where(PredictiveAnalysis.prediction_type == prediction_type)

    stmt = stmt.where(PredictiveAnalysis.likelihood >= min_likelihood)
    stmt = stmt.where(PredictiveAnalysis.priority >= min_priority)

    if validated_only:
        stmt = stmt.where(PredictiveAnalysis.validated == True)

    stmt = stmt.where(PredictiveAnalysis.false_positive == False)
    stmt = stmt.order_by(desc(PredictiveAnalysis.priority))
    stmt = stmt.limit(limit)

    result = await db.execute(stmt)
    predictions = result.scalars().all()

    return {
        "success": True,
        "count": len(predictions),
        "predictions": [
            {
                "id": p.id,
                "prediction_type": p.prediction_type,
                "prediction_name": p.prediction_name,
                "description": p.description,
                "predicted_vulnerability_types": p.predicted_vulnerability_types,
                "likelihood": p.likelihood,
                "confidence": p.confidence,
                "priority": p.priority,
                "technology_stack": p.technology_stack,
                "observed_patterns": p.observed_patterns,
                "suggested_test_areas": p.suggested_test_areas,
                "suggested_payloads": p.suggested_payloads,
                "suggested_tools": p.suggested_tools,
                "validated": p.validated,
                "validation_result": p.validation_result,
                "created_at": p.created_at.isoformat()
            }
            for p in predictions
        ]
    }


@router.get("/attack-graph/{domain_id}")
async def get_attack_graph(
    domain_id: int,
    db: AsyncSession = Depends(get_db)
):
    """
    Get attack graph for a domain

    The attack graph visualizes relationships between vulnerabilities, patterns, and assets,
    showing how vulnerabilities can be chained together into attack paths.
    """
    stmt = select(AttackGraph).where(AttackGraph.domain_id == domain_id).order_by(desc(AttackGraph.created_at))
    result = await db.execute(stmt)
    graph = result.scalars().first()

    if not graph:
        return {
            "success": True,
            "graph": None,
            "message": "No attack graph found. Run pattern analysis first."
        }

    return {
        "success": True,
        "graph": {
            "id": graph.id,
            "graph_name": graph.graph_name,
            "description": graph.description,
            "node_count": graph.node_count,
            "edge_count": graph.edge_count,
            "nodes": graph.nodes,
            "edges": graph.edges,
            "entry_points": graph.entry_points,
            "critical_paths": graph.critical_paths,
            "max_path_length": graph.max_path_length,
            "avg_path_length": graph.avg_path_length,
            "highest_impact_path": graph.highest_impact_path,
            "easiest_path": graph.easiest_path,
            "created_at": graph.created_at.isoformat(),
            "updated_at": graph.updated_at.isoformat()
        }
    }


@router.get("/statistics/{domain_id}")
async def get_pattern_statistics(
    domain_id: int,
    db: AsyncSession = Depends(get_db)
):
    """
    Get comprehensive pattern recognition statistics for a domain
    """
    # Count patterns by type
    temporal_count = await db.scalar(
        select(func.count(TemporalPattern.id)).where(TemporalPattern.domain_id == domain_id)
    )

    spatial_count = await db.scalar(
        select(func.count(SpatialPattern.id)).where(SpatialPattern.domain_id == domain_id)
    )

    behavioral_count = await db.scalar(
        select(func.count(BehavioralPattern.id)).where(BehavioralPattern.domain_id == domain_id)
    )

    # Count chains by severity
    chain_stmt = select(
        VulnerabilityChain.severity,
        func.count(VulnerabilityChain.id)
    ).where(
        and_(
            VulnerabilityChain.domain_id == domain_id,
            VulnerabilityChain.false_positive == False
        )
    ).group_by(VulnerabilityChain.severity)

    chain_result = await db.execute(chain_stmt)
    chain_by_severity = dict(chain_result.all())

    # Count predictions by priority
    prediction_stmt = select(
        PredictiveAnalysis.priority,
        func.count(PredictiveAnalysis.id)
    ).where(
        and_(
            PredictiveAnalysis.domain_id == domain_id,
            PredictiveAnalysis.false_positive == False
        )
    ).group_by(PredictiveAnalysis.priority)

    prediction_result = await db.execute(prediction_stmt)
    prediction_by_priority = dict(prediction_result.all())

    return {
        "success": True,
        "domain_id": domain_id,
        "statistics": {
            "patterns": {
                "temporal": temporal_count or 0,
                "spatial": spatial_count or 0,
                "behavioral": behavioral_count or 0,
                "total": (temporal_count or 0) + (spatial_count or 0) + (behavioral_count or 0)
            },
            "chains": {
                "by_severity": {
                    "critical": chain_by_severity.get("critical", 0),
                    "high": chain_by_severity.get("high", 0),
                    "medium": chain_by_severity.get("medium", 0),
                    "low": chain_by_severity.get("low", 0)
                },
                "total": sum(chain_by_severity.values())
            },
            "predictions": {
                "by_priority": prediction_by_priority,
                "total": sum(prediction_by_priority.values())
            }
        }
    }


@router.post("/chains/{domain_id}/{chain_id}/verify")
async def verify_chain(
    domain_id: int,
    chain_id: int,
    verified: bool,
    verified_by: str,
    notes: Optional[str] = None,
    db: AsyncSession = Depends(get_db)
):
    """
    Mark a vulnerability chain as verified or false positive
    """
    stmt = select(VulnerabilityChain).where(
        and_(
            VulnerabilityChain.id == chain_id,
            VulnerabilityChain.domain_id == domain_id
        )
    )
    result = await db.execute(stmt)
    chain = result.scalar_one_or_none()

    if not chain:
        raise HTTPException(status_code=404, detail=f"Chain {chain_id} not found")

    chain.verified = verified
    chain.verified_at = datetime.utcnow()
    chain.verified_by = verified_by
    if notes:
        chain.notes = notes

    await db.commit()

    return {
        "success": True,
        "message": f"Chain {chain_id} marked as {'verified' if verified else 'unverified'}",
        "chain_id": chain_id
    }


@router.post("/chains/{domain_id}/{chain_id}/false-positive")
async def mark_chain_false_positive(
    domain_id: int,
    chain_id: int,
    is_false_positive: bool,
    verified_by: str,
    notes: Optional[str] = None,
    db: AsyncSession = Depends(get_db)
):
    """
    Mark a vulnerability chain as false positive
    """
    stmt = select(VulnerabilityChain).where(
        and_(
            VulnerabilityChain.id == chain_id,
            VulnerabilityChain.domain_id == domain_id
        )
    )
    result = await db.execute(stmt)
    chain = result.scalar_one_or_none()

    if not chain:
        raise HTTPException(status_code=404, detail=f"Chain {chain_id} not found")

    chain.false_positive = is_false_positive
    chain.verified_by = verified_by
    chain.verified_at = datetime.utcnow()
    if notes:
        chain.notes = notes

    await db.commit()

    return {
        "success": True,
        "message": f"Chain {chain_id} marked as {'false positive' if is_false_positive else 'valid'}",
        "chain_id": chain_id
    }
