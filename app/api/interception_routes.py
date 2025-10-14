"""
API Routes for HTTP Traffic Interception and Analysis

Provides endpoints for:
- Proxy server control
- Traffic inspection
- Alert management
- Pattern configuration
"""

from fastapi import APIRouter, HTTPException, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from typing import Optional

from app.models.http_traffic import (
    HTTPTraffic, TrafficAlert, SensitiveDataPattern, TrafficAnalysisRule
)

router = APIRouter(prefix="/api", tags=["interception"])

# Global proxy server instance (will be set by main.py)
_proxy_server = None
_traffic_processor = None


def set_proxy_server(proxy_server):
    """Set global proxy server instance"""
    global _proxy_server
    _proxy_server = proxy_server


def set_traffic_processor(processor):
    """Set global traffic processor instance"""
    global _traffic_processor
    _traffic_processor = processor


async def get_session():
    """Dependency to get database session"""
    from main import app_state
    async with app_state["db_manager"].get_session() as session:
        yield session


# Proxy Control Endpoints

@router.post("/proxy/start")
async def start_proxy():
    """Start the HTTP interception proxy"""
    if not _proxy_server:
        raise HTTPException(status_code=500, detail="Proxy server not initialized")
    
    if _proxy_server.is_running():
        raise HTTPException(status_code=400, detail="Proxy already running")
    
    try:
        await _proxy_server.start_async()
        return {"status": "started", "message": "Proxy server started successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to start proxy: {str(e)}")


@router.post("/proxy/stop")
async def stop_proxy():
    """Stop the HTTP interception proxy"""
    if not _proxy_server:
        raise HTTPException(status_code=500, detail="Proxy server not initialized")
    
    if not _proxy_server.is_running():
        raise HTTPException(status_code=400, detail="Proxy not running")
    
    try:
        await _proxy_server.stop_async()
        return {"status": "stopped", "message": "Proxy server stopped successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to stop proxy: {str(e)}")


@router.get("/proxy/status")
async def get_proxy_status():
    """Get proxy server status and statistics"""
    if not _proxy_server:
        return {"running": False, "error": "Proxy server not initialized"}
    
    status = _proxy_server.get_status()
    
    # Add processor stats if available
    if _traffic_processor:
        status["processor"] = _traffic_processor.get_stats()
    
    return status


# Traffic Inspection Endpoints

@router.get("/traffic")
async def list_traffic(
    session: AsyncSession = Depends(get_session),
    limit: int = Query(100, le=1000),
    offset: int = Query(0),
    subdomain_id: Optional[int] = None,
    status_code: Optional[int] = None,
    has_error: Optional[bool] = None,
    is_analyzed: Optional[bool] = None
):
    """
    List captured HTTP traffic with filtering
    
    Query parameters:
    - limit: Maximum number of results (default: 100, max: 1000)
    - offset: Pagination offset
    - subdomain_id: Filter by subdomain
    - status_code: Filter by HTTP status code
    - has_error: Filter by error status
    - is_analyzed: Filter by analysis status
    """
    query = select(HTTPTraffic).order_by(desc(HTTPTraffic.timestamp))
    
    # Apply filters
    if subdomain_id is not None:
        query = query.where(HTTPTraffic.subdomain_id == subdomain_id)
    if status_code is not None:
        query = query.where(HTTPTraffic.status_code == status_code)
    if has_error is not None:
        query = query.where(HTTPTraffic.has_error == has_error)
    if is_analyzed is not None:
        query = query.where(HTTPTraffic.is_analyzed == is_analyzed)
    
    # Apply pagination
    query = query.limit(limit).offset(offset)
    
    result = await session.execute(query)
    traffic = result.scalars().all()
    
    return {
        "traffic": [
            {
                "id": t.id,
                "method": t.method,
                "url": t.url,
                "status_code": t.status_code,
                "timestamp": t.timestamp.isoformat() if t.timestamp else None,
                "response_time_ms": t.response_time_ms,
                "scanner_module": t.scanner_module,
                "scan_purpose": t.scan_purpose,
                "has_error": t.has_error,
                "is_analyzed": t.is_analyzed,
            }
            for t in traffic
        ],
        "count": len(traffic),
        "limit": limit,
        "offset": offset
    }


@router.get("/traffic/{traffic_id}")
async def get_traffic_details(
    traffic_id: int,
    session: AsyncSession = Depends(get_session)
):
    """Get detailed information about a specific HTTP traffic entry"""
    result = await session.execute(
        select(HTTPTraffic).where(HTTPTraffic.id == traffic_id)
    )
    traffic = result.scalar_one_or_none()
    
    if not traffic:
        raise HTTPException(status_code=404, detail="Traffic entry not found")
    
    import json
    import gzip
    
    # Decompress bodies if needed
    request_body = None
    if traffic.request_body:
        try:
            request_body = gzip.decompress(traffic.request_body).decode('utf-8', errors='ignore')
        except:
            request_body = "[Binary data]"
    
    response_body = None
    if traffic.response_body:
        try:
            response_body = gzip.decompress(traffic.response_body).decode('utf-8', errors='ignore')
        except:
            response_body = "[Binary data]"
    
    return {
        "id": traffic.id,
        "method": traffic.method,
        "url": traffic.url,
        "path": traffic.path,
        "query_params": json.loads(traffic.query_params) if traffic.query_params else {},
        "request_headers": json.loads(traffic.request_headers) if traffic.request_headers else {},
        "request_body": request_body,
        "status_code": traffic.status_code,
        "response_headers": json.loads(traffic.response_headers) if traffic.response_headers else {},
        "response_body": response_body[:10000] if response_body else None,  # Limit size
        "response_size": traffic.response_size,
        "timestamp": traffic.timestamp.isoformat() if traffic.timestamp else None,
        "response_time_ms": traffic.response_time_ms,
        "scanner_module": traffic.scanner_module,
        "scan_purpose": traffic.scan_purpose,
        "correlation_id": traffic.correlation_id,
        "certificate_fingerprint": traffic.certificate_fingerprint,
        "has_error": traffic.has_error,
        "is_analyzed": traffic.is_analyzed,
        "analysis_results": json.loads(traffic.analysis_results) if traffic.analysis_results else None,
        "extracted_urls": json.loads(traffic.extracted_urls) if traffic.extracted_urls else [],
        "extracted_api_endpoints": json.loads(traffic.extracted_api_endpoints) if traffic.extracted_api_endpoints else []
    }


@router.get("/traffic/analysis")
async def get_analyzed_traffic(
    session: AsyncSession = Depends(get_session),
    limit: int = Query(100, le=1000),
    with_findings: bool = Query(True)
):
    """Get analyzed traffic with findings"""
    query = select(HTTPTraffic).where(HTTPTraffic.is_analyzed == True)
    
    if with_findings:
        query = query.where(HTTPTraffic.analysis_results.isnot(None))
    
    query = query.order_by(desc(HTTPTraffic.timestamp)).limit(limit)
    
    result = await session.execute(query)
    traffic = result.scalars().all()
    
    import json
    
    return {
        "traffic": [
            {
                "id": t.id,
                "url": t.url,
                "timestamp": t.timestamp.isoformat() if t.timestamp else None,
                "analysis_results": json.loads(t.analysis_results) if t.analysis_results else {}
            }
            for t in traffic
        ],
        "count": len(traffic)
    }


@router.post("/traffic/reanalyze/{traffic_id}")
async def reanalyze_traffic(
    traffic_id: int,
    session: AsyncSession = Depends(get_session)
):
    """Re-run analysis on a traffic entry"""
    # This would trigger re-analysis
    # For now, return placeholder
    return {
        "status": "queued",
        "message": f"Traffic {traffic_id} queued for re-analysis"
    }


# Alert Endpoints

@router.get("/traffic/alerts")
async def list_alerts(
    session: AsyncSession = Depends(get_session),
    limit: int = Query(100, le=1000),
    status: Optional[str] = None,
    severity: Optional[str] = None
):
    """List traffic alerts"""
    query = select(TrafficAlert).order_by(desc(TrafficAlert.created_at))
    
    if status:
        query = query.where(TrafficAlert.status == status)
    if severity:
        query = query.where(TrafficAlert.severity == severity)
    
    query = query.limit(limit)
    
    result = await session.execute(query)
    alerts = result.scalars().all()
    
    import json
    
    return {
        "alerts": [
            {
                "id": a.id,
                "alert_type": a.alert_type,
                "severity": a.severity,
                "title": a.title,
                "description": a.description,
                "status": a.status,
                "created_at": a.created_at.isoformat() if a.created_at else None
            }
            for a in alerts
        ],
        "count": len(alerts)
    }


# Pattern Management Endpoints

@router.post("/patterns/sensitive")
async def create_sensitive_pattern(
    pattern_data: dict,
    session: AsyncSession = Depends(get_session)
):
    """Create a new sensitive data pattern"""
    pattern = SensitiveDataPattern(
        pattern_name=pattern_data["pattern_name"],
        pattern_regex=pattern_data["pattern_regex"],
        pattern_type=pattern_data["pattern_type"],
        description=pattern_data.get("description"),
        severity=pattern_data.get("severity", "medium"),
        active=pattern_data.get("active", True)
    )
    
    session.add(pattern)
    await session.commit()
    await session.refresh(pattern)
    
    return {"id": pattern.id, "pattern_name": pattern.pattern_name}


@router.get("/patterns/sensitive")
async def list_sensitive_patterns(
    session: AsyncSession = Depends(get_session),
    active_only: bool = Query(True)
):
    """List sensitive data patterns"""
    query = select(SensitiveDataPattern)
    
    if active_only:
        query = query.where(SensitiveDataPattern.active == True)
    
    result = await session.execute(query)
    patterns = result.scalars().all()
    
    return {
        "patterns": [
            {
                "id": p.id,
                "pattern_name": p.pattern_name,
                "pattern_type": p.pattern_type,
                "severity": p.severity,
                "active": p.active,
                "matches_count": p.matches_count
            }
            for p in patterns
        ],
        "count": len(patterns)
    }


@router.post("/patterns/analysis")
async def create_analysis_rule(
    rule_data: dict,
    session: AsyncSession = Depends(get_session)
):
    """Create a new traffic analysis rule"""
    import json
    
    rule = TrafficAnalysisRule(
        rule_name=rule_data["rule_name"],
        rule_type=rule_data["rule_type"],
        description=rule_data.get("description"),
        condition=json.dumps(rule_data["condition"]),
        action=json.dumps(rule_data["action"]),
        priority=rule_data.get("priority", 50),
        active=rule_data.get("active", True)
    )
    
    session.add(rule)
    await session.commit()
    await session.refresh(rule)
    
    return {"id": rule.id, "rule_name": rule.rule_name}


@router.get("/patterns/analysis")
async def list_analysis_rules(
    session: AsyncSession = Depends(get_session),
    active_only: bool = Query(True)
):
    """List traffic analysis rules"""
    query = select(TrafficAnalysisRule)
    
    if active_only:
        query = query.where(TrafficAnalysisRule.active == True)
    
    query = query.order_by(TrafficAnalysisRule.priority)
    
    result = await session.execute(query)
    rules = result.scalars().all()
    
    return {
        "rules": [
            {
                "id": r.id,
                "rule_name": r.rule_name,
                "rule_type": r.rule_type,
                "priority": r.priority,
                "active": r.active,
                "matches_count": r.matches_count
            }
            for r in rules
        ],
        "count": len(rules)
    }
