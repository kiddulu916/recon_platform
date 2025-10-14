"""
Service detection and fingerprinting
Identifies services running on open ports through banner analysis
"""

from typing import List, Dict, Optional
import structlog
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
import re

from app.models.network import Port, IPAddress

logger = structlog.get_logger()


class ServiceDetector:
    """
    Detects and fingerprints services on open ports
    Uses banner analysis, pattern matching, and version detection
    """
    
    def __init__(self, config, rate_limiter):
        self.config = config
        self.rate_limiter = rate_limiter
        self.logger = logger.bind(tool="service_detector")
        
        # Service fingerprints (banner patterns)
        self.fingerprints = self._load_fingerprints()
    
    def _load_fingerprints(self) -> Dict[str, Dict]:
        """Load service fingerprint patterns"""
        return {
            # HTTP Services
            "nginx": {
                "patterns": [r"nginx/(\d+\.\d+\.\d+)", r"Server: nginx"],
                "ports": [80, 443, 8080, 8443]
            },
            "apache": {
                "patterns": [r"Apache/(\d+\.\d+\.\d+)", r"Server: Apache"],
                "ports": [80, 443, 8080]
            },
            "iis": {
                "patterns": [r"Microsoft-IIS/(\d+\.\d+)", r"Server: Microsoft-IIS"],
                "ports": [80, 443]
            },
            "tomcat": {
                "patterns": [r"Apache-Coyote", r"Tomcat"],
                "ports": [8080, 8443, 8009]
            },
            
            # SSH
            "openssh": {
                "patterns": [r"SSH-2\.0-OpenSSH_(\d+\.\d+)"],
                "ports": [22]
            },
            
            # FTP
            "vsftpd": {
                "patterns": [r"220.*vsFTPd (\d+\.\d+\.\d+)"],
                "ports": [21]
            },
            "proftpd": {
                "patterns": [r"ProFTPD (\d+\.\d+\.\d+)"],
                "ports": [21]
            },
            
            # Database
            "mysql": {
                "patterns": [r"mysql", r"MySQL"],
                "ports": [3306]
            },
            "postgresql": {
                "patterns": [r"PostgreSQL"],
                "ports": [5432]
            },
            "mongodb": {
                "patterns": [r"MongoDB"],
                "ports": [27017]
            },
            "redis": {
                "patterns": [r"Redis"],
                "ports": [6379]
            },
            
            # Other services
            "smtp": {
                "patterns": [r"220.*SMTP", r"220.*ESMTP"],
                "ports": [25, 587]
            },
            "elasticsearch": {
                "patterns": [r"elasticsearch"],
                "ports": [9200, 9300]
            }
        }
    
    async def detect(
        self,
        session: AsyncSession,
        port_id: int
    ) -> Optional[Dict]:
        """
        Detect service on a port
        
        Args:
            session: Database session
            port_id: Port ID to analyze
        
        Returns:
            Dict with service information
        """
        # Get port record
        port = await session.get(Port, port_id)
        if not port:
            return None
        
        # Skip if service already detected
        if port.service_name and port.service_confidence and port.service_confidence > 80:
            return {
                "service_name": port.service_name,
                "service_version": port.service_version,
                "confidence": port.service_confidence
            }
        
        # Get banner if available
        banner = port.service_banner or ""
        
        # Try to identify service
        detected = self._identify_service(port.port, banner)
        
        if detected:
            # Update port record
            port.service_name = detected["service_name"]
            port.service_version = detected.get("version")
            port.service_confidence = detected["confidence"]
            
            # Check for known vulnerabilities
            if detected.get("version"):
                cves = await self._check_vulnerabilities(
                    detected["service_name"],
                    detected["version"]
                )
                if cves:
                    port.cve_matches = str(cves)
                    port.outdated_version = True
            
            await session.commit()
            
            self.logger.info(
                "Service detected",
                port=port.port,
                service=detected["service_name"],
                version=detected.get("version"),
                confidence=detected["confidence"]
            )
        
        return detected
    
    def _identify_service(
        self,
        port_number: int,
        banner: str
    ) -> Optional[Dict]:
        """Identify service from port and banner"""
        best_match = None
        best_confidence = 0
        
        for service_name, service_info in self.fingerprints.items():
            confidence = 0
            version = None
            
            # Check if port matches
            if port_number in service_info["ports"]:
                confidence += 30
            
            # Check banner patterns
            if banner:
                for pattern in service_info["patterns"]:
                    match = re.search(pattern, banner, re.IGNORECASE)
                    if match:
                        confidence += 50
                        # Try to extract version
                        if match.groups():
                            version = match.group(1)
                            confidence += 20
                        break
            
            # Update best match
            if confidence > best_confidence:
                best_confidence = confidence
                best_match = {
                    "service_name": service_name,
                    "version": version,
                    "confidence": min(confidence, 100)
                }
        
        return best_match
    
    async def _check_vulnerabilities(
        self,
        service_name: str,
        version: str
    ) -> List[str]:
        """
        Check for known vulnerabilities
        This is a placeholder - would integrate with CVE databases
        """
        # Placeholder for CVE checking
        # In production, would query NVD, CVE databases, or exploit-db
        known_vulns = {
            "openssh": {
                "7.4": ["CVE-2018-15473"],
                "6.6": ["CVE-2015-5600", "CVE-2015-6563"]
            },
            "nginx": {
                "1.10.0": ["CVE-2016-4450"],
                "1.9.5": ["CVE-2016-0742", "CVE-2016-0746"]
            },
            "apache": {
                "2.4.49": ["CVE-2021-41773", "CVE-2021-42013"],
                "2.4.29": ["CVE-2017-15710"]
            }
        }
        
        if service_name in known_vulns and version in known_vulns[service_name]:
            return known_vulns[service_name][version]
        
        return []
    
    async def batch_detect(
        self,
        session: AsyncSession,
        ip_id: int
    ) -> List[Dict]:
        """
        Detect services on all ports for an IP
        
        Args:
            session: Database session
            ip_id: IP address ID
        
        Returns:
            List of detected services
        """
        # Get all ports for this IP
        result = await session.execute(
            select(Port).where(
                Port.ip_id == ip_id,
                Port.state == "open"
            )
        )
        ports = result.scalars().all()
        
        detected_services = []
        for port in ports:
            service = await self.detect(session, port.id)
            if service:
                detected_services.append({
                    "port": port.port,
                    **service
                })
        
        self.logger.info(
            "Batch service detection complete",
            ip_id=ip_id,
            ports_analyzed=len(ports),
            services_detected=len(detected_services)
        )
        
        return detected_services
