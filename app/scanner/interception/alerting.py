"""
Alert Manager for Real-Time Notifications

Manages alert generation, deduplication, and delivery.
"""

import asyncio
from typing import Dict, Any, Optional
from datetime import datetime, timedelta
from collections import defaultdict
import structlog

from app.core.database import async_session_maker
from app.models.http_traffic import TrafficAlert

logger = structlog.get_logger()


class AlertManager:
    """
    Manages real-time alerts from traffic analysis
    
    Features:
    - Alert deduplication
    - Rate limiting
    - Severity classification
    - Database persistence
    - Optional webhook delivery
    """
    
    def __init__(self, config):
        """
        Initialize alert manager
        
        Args:
            config: Application configuration
        """
        self.config = config
        self.logger = logger.bind(component="alert_manager")
        
        # Deduplication tracking (in-memory)
        self._recent_alerts = defaultdict(list)  # alert_key -> [timestamps]
        self._cleanup_interval = 300  # 5 minutes
        
        # Statistics
        self.stats = {
            "alerts_created": 0,
            "alerts_deduplicated": 0,
            "webhook_sent": 0,
            "errors": 0
        }
        
        # Start cleanup task
        asyncio.create_task(self._cleanup_loop())
    
    async def create_alert(
        self,
        traffic_data: Dict[str, Any],
        alert_type: str,
        severity: str,
        title: str,
        details: Dict[str, Any]
    ) -> Optional[int]:
        """
        Create a new alert
        
        Args:
            traffic_data: Original traffic data
            alert_type: Type of alert (error, sensitive_data, vulnerability, etc.)
            severity: Alert severity (low, medium, high, critical)
            title: Alert title/description
            details: Additional alert details
        
        Returns:
            Alert ID if created, None if deduplicated
        """
        try:
            # Check deduplication
            alert_key = self._generate_alert_key(traffic_data, alert_type, title)
            if self._is_duplicate(alert_key):
                self.stats["alerts_deduplicated"] += 1
                return None
            
            # Create alert in database
            async with async_session_maker() as session:
                alert = TrafficAlert(
                    # http_traffic_id will be set when traffic is processed
                    alert_type=alert_type,
                    severity=severity,
                    title=title,
                    description=details.get("description", ""),
                    matched_content=str(details.get("matched_content", "")),
                    context=str(details),
                    status="new"
                )
                
                session.add(alert)
                await session.commit()
                await session.refresh(alert)
                
                alert_id = alert.id
            
            # Track for deduplication
            self._track_alert(alert_key)
            
            # Send webhook if configured
            if self.config.proxy.alert_webhook_url:
                await self._send_webhook(alert_id, alert_type, severity, title, details)
            
            self.stats["alerts_created"] += 1
            
            self.logger.info(
                "Alert created",
                alert_id=alert_id,
                type=alert_type,
                severity=severity
            )
            
            return alert_id
        
        except Exception as e:
            self.logger.error("Failed to create alert", error=str(e))
            self.stats["errors"] += 1
            return None
    
    def _generate_alert_key(
        self,
        traffic_data: Dict[str, Any],
        alert_type: str,
        title: str
    ) -> str:
        """Generate unique key for alert deduplication"""
        url = traffic_data.get("request", {}).get("url", "")
        return f"{alert_type}:{url}:{title}"
    
    def _is_duplicate(self, alert_key: str) -> bool:
        """Check if alert is a duplicate within cooldown period"""
        if alert_key not in self._recent_alerts:
            return False
        
        # Check if any recent alert within cooldown
        cooldown = timedelta(seconds=60)  # 60 second cooldown
        cutoff = datetime.utcnow() - cooldown
        
        recent = [ts for ts in self._recent_alerts[alert_key] if ts > cutoff]
        self._recent_alerts[alert_key] = recent  # Clean up old entries
        
        return len(recent) > 0
    
    def _track_alert(self, alert_key: str):
        """Track alert for deduplication"""
        self._recent_alerts[alert_key].append(datetime.utcnow())
    
    async def _send_webhook(
        self,
        alert_id: int,
        alert_type: str,
        severity: str,
        title: str,
        details: Dict[str, Any]
    ):
        """Send alert via webhook"""
        try:
            import aiohttp
            
            payload = {
                "alert_id": alert_id,
                "type": alert_type,
                "severity": severity,
                "title": title,
                "details": details,
                "timestamp": datetime.utcnow().isoformat()
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self.config.proxy.alert_webhook_url,
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=5)
                ) as response:
                    if response.status == 200:
                        self.stats["webhook_sent"] += 1
                    else:
                        self.logger.warning(
                            "Webhook failed",
                            status=response.status
                        )
        
        except Exception as e:
            self.logger.error("Webhook send failed", error=str(e))
    
    async def _cleanup_loop(self):
        """Periodically clean up old alert tracking data"""
        while True:
            try:
                await asyncio.sleep(self._cleanup_interval)
                
                # Clean up old alerts
                cutoff = datetime.utcnow() - timedelta(minutes=10)
                for alert_key in list(self._recent_alerts.keys()):
                    recent = [ts for ts in self._recent_alerts[alert_key] if ts > cutoff]
                    if recent:
                        self._recent_alerts[alert_key] = recent
                    else:
                        del self._recent_alerts[alert_key]
            
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error("Cleanup loop error", error=str(e))
    
    def get_stats(self) -> Dict[str, Any]:
        """Get alert manager statistics"""
        return {
            **self.stats,
            "tracked_alert_keys": len(self._recent_alerts)
        }
