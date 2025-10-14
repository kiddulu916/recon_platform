"""
WebSocket API Routes
Provides WebSocket endpoints for real-time communication
"""

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query
from typing import Optional
import structlog

from app.api.websocket import ws_manager

logger = structlog.get_logger()

router = APIRouter()


@router.websocket("/ws")
async def websocket_endpoint(
    websocket: WebSocket,
    domain_id: Optional[int] = Query(None, description="Filter updates by domain ID")
):
    """
    WebSocket endpoint for real-time scan updates

    Query Parameters:
    - domain_id (optional): Subscribe to updates for a specific domain only
                           If not provided, receives all global updates

    Message Types Sent:
    - connection_established: Initial connection confirmation
    - scan_progress: Scan progress updates
    - subdomain_discovered: New subdomain found
    - vulnerability_detected: New vulnerability detected
    - pattern_found: Pattern recognition result
    - scan_completed: Scan finished successfully
    - scan_failed: Scan encountered an error
    """
    await ws_manager.connect(websocket, domain_id)

    try:
        while True:
            # Keep the connection alive and listen for client messages
            data = await websocket.receive_text()

            # Currently we don't expect messages from the client,
            # but we could implement ping/pong or client commands here
            logger.debug("Received WebSocket message", data=data, domain_id=domain_id)

    except WebSocketDisconnect:
        await ws_manager.disconnect(websocket, domain_id)
        logger.info("WebSocket client disconnected", domain_id=domain_id)


@router.get("/ws/status")
async def websocket_status():
    """Get WebSocket connection statistics"""
    total_connections = ws_manager.get_connection_count()
    global_connections = len(ws_manager.global_connections)

    domain_stats = {
        domain_id: len(connections)
        for domain_id, connections in ws_manager.domain_connections.items()
    }

    return {
        "total_connections": total_connections,
        "global_connections": global_connections,
        "domain_connections": domain_stats
    }
