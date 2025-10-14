"""
WebSocket Manager for Real-Time Updates
Handles WebSocket connections and broadcasts scan progress updates
"""

import asyncio
import json
from typing import Dict, Set, Optional
from datetime import datetime
import structlog
from fastapi import WebSocket, WebSocketDisconnect

logger = structlog.get_logger()


class WebSocketManager:
    """Manages WebSocket connections and broadcasts messages"""

    def __init__(self):
        # Map of domain_id -> Set of WebSocket connections
        self.domain_connections: Dict[int, Set[WebSocket]] = {}
        # Global connections (not filtered by domain)
        self.global_connections: Set[WebSocket] = set()
        self._lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket, domain_id: Optional[int] = None):
        """Register a new WebSocket connection"""
        await websocket.accept()

        async with self._lock:
            if domain_id is not None:
                if domain_id not in self.domain_connections:
                    self.domain_connections[domain_id] = set()
                self.domain_connections[domain_id].add(websocket)
                logger.info("WebSocket connected", domain_id=domain_id,
                           total_connections=len(self.domain_connections[domain_id]))
            else:
                self.global_connections.add(websocket)
                logger.info("Global WebSocket connected",
                           total_connections=len(self.global_connections))

        # Send connection established message
        await self.send_personal_message(
            websocket,
            {
                "type": "connection_established",
                "data": {
                    "domain_id": domain_id,
                    "message": "WebSocket connection established"
                },
                "timestamp": datetime.utcnow().isoformat()
            }
        )

    async def disconnect(self, websocket: WebSocket, domain_id: Optional[int] = None):
        """Unregister a WebSocket connection"""
        async with self._lock:
            if domain_id is not None:
                if domain_id in self.domain_connections:
                    self.domain_connections[domain_id].discard(websocket)
                    if not self.domain_connections[domain_id]:
                        del self.domain_connections[domain_id]
                    logger.info("WebSocket disconnected", domain_id=domain_id)
            else:
                self.global_connections.discard(websocket)
                logger.info("Global WebSocket disconnected")

    async def send_personal_message(self, websocket: WebSocket, message: dict):
        """Send a message to a specific WebSocket connection"""
        try:
            await websocket.send_text(json.dumps(message))
        except Exception as e:
            logger.error("Failed to send WebSocket message", error=str(e))

    async def broadcast_to_domain(self, domain_id: int, message: dict):
        """Broadcast a message to all connections for a specific domain"""
        async with self._lock:
            connections = self.domain_connections.get(domain_id, set()).copy()

        if not connections:
            return

        message_json = json.dumps(message)
        disconnected = []

        for connection in connections:
            try:
                await connection.send_text(message_json)
            except WebSocketDisconnect:
                disconnected.append(connection)
            except Exception as e:
                logger.error("Failed to broadcast to WebSocket",
                           domain_id=domain_id, error=str(e))
                disconnected.append(connection)

        # Clean up disconnected clients
        if disconnected:
            async with self._lock:
                for conn in disconnected:
                    if domain_id in self.domain_connections:
                        self.domain_connections[domain_id].discard(conn)

    async def broadcast_global(self, message: dict):
        """Broadcast a message to all global connections"""
        async with self._lock:
            connections = self.global_connections.copy()

        if not connections:
            return

        message_json = json.dumps(message)
        disconnected = []

        for connection in connections:
            try:
                await connection.send_text(message_json)
            except WebSocketDisconnect:
                disconnected.append(connection)
            except Exception as e:
                logger.error("Failed to broadcast to global WebSocket", error=str(e))
                disconnected.append(connection)

        # Clean up disconnected clients
        if disconnected:
            async with self._lock:
                for conn in disconnected:
                    self.global_connections.discard(conn)

    async def broadcast_scan_progress(self, domain_id: int, scan_data: dict):
        """Broadcast scan progress update"""
        message = {
            "type": "scan_progress",
            "data": scan_data,
            "timestamp": datetime.utcnow().isoformat()
        }
        await self.broadcast_to_domain(domain_id, message)
        await self.broadcast_global(message)

    async def broadcast_subdomain_discovered(self, domain_id: int, subdomain_data: dict):
        """Broadcast new subdomain discovery"""
        message = {
            "type": "subdomain_discovered",
            "data": subdomain_data,
            "timestamp": datetime.utcnow().isoformat()
        }
        await self.broadcast_to_domain(domain_id, message)
        await self.broadcast_global(message)

    async def broadcast_vulnerability_detected(self, domain_id: int, vulnerability_data: dict):
        """Broadcast new vulnerability detection"""
        message = {
            "type": "vulnerability_detected",
            "data": vulnerability_data,
            "timestamp": datetime.utcnow().isoformat()
        }
        await self.broadcast_to_domain(domain_id, message)
        await self.broadcast_global(message)

    async def broadcast_pattern_found(self, domain_id: int, pattern_data: dict):
        """Broadcast new pattern recognition result"""
        message = {
            "type": "pattern_found",
            "data": pattern_data,
            "timestamp": datetime.utcnow().isoformat()
        }
        await self.broadcast_to_domain(domain_id, message)
        await self.broadcast_global(message)

    async def broadcast_scan_completed(self, domain_id: int, summary: dict):
        """Broadcast scan completion"""
        message = {
            "type": "scan_completed",
            "data": summary,
            "timestamp": datetime.utcnow().isoformat()
        }
        await self.broadcast_to_domain(domain_id, message)
        await self.broadcast_global(message)

    async def broadcast_scan_failed(self, domain_id: int, error: str):
        """Broadcast scan failure"""
        message = {
            "type": "scan_failed",
            "data": {
                "domain_id": domain_id,
                "error": error
            },
            "timestamp": datetime.utcnow().isoformat()
        }
        await self.broadcast_to_domain(domain_id, message)
        await self.broadcast_global(message)

    def get_connection_count(self, domain_id: Optional[int] = None) -> int:
        """Get number of active connections"""
        if domain_id is not None:
            return len(self.domain_connections.get(domain_id, set()))
        return len(self.global_connections) + sum(
            len(conns) for conns in self.domain_connections.values()
        )


# Global WebSocket manager instance
ws_manager = WebSocketManager()
