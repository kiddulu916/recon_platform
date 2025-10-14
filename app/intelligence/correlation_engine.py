"""
Vulnerability Correlation Engine

Combines rule-based systems and machine learning to identify vulnerabilities:
- Rule-based: Known patterns, CVE signatures, version matching
- ML-based: Anomaly detection, pattern learning, behavior analysis
- Hybrid: Combines both approaches for maximum accuracy
"""

import re
import json
from typing import List, Dict, Optional, Any, Tuple
from datetime import datetime
from collections import defaultdict
import structlog
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.models.vulnerability import Vulnerability, VulnerabilityPattern, CVEDatabase
from app.models.http_traffic import HTTPTraffic
from app.models.network import Port
from app.models.domain import Subdomain

logger = structlog.get_logger()


class RuleBasedDetector:
    """
    Rule-based vulnerability detection

    Handles known patterns, signatures, and version-based detection
    """

    def __init__(self):
        self.logger = logger.bind(component="rule_based_detector")

        # Version-based vulnerability rules
        self.version_rules = self._load_version_rules()

        # Signature-based detection patterns
        self.signature_patterns = self._load_signature_patterns()

        # Configuration vulnerability patterns
        self.config_patterns = self._load_config_patterns()

    def _load_version_rules(self) -> List[Dict]:
        """Load rules for version-based vulnerability detection"""
        return [
            # Example rules - in production, load from database
            {
                "name": "Apache outdated",
                "product": "Apache",
                "vulnerable_versions": ["< 2.4.50"],
                "cve_ids": ["CVE-2021-41773", "CVE-2021-42013"],
                "severity": "Critical",
                "description": "Path traversal and RCE vulnerabilities"
            },
            {
                "name": "OpenSSL Heartbleed",
                "product": "OpenSSL",
                "vulnerable_versions": ["1.0.1", "1.0.1a", "1.0.1b", "1.0.1c", "1.0.1d", "1.0.1e", "1.0.1f"],
                "cve_ids": ["CVE-2014-0160"],
                "severity": "Critical",
                "description": "Buffer over-read vulnerability (Heartbleed)"
            },
            {
                "name": "nginx outdated",
                "product": "nginx",
                "vulnerable_versions": ["< 1.20.1"],
                "cve_ids": ["CVE-2021-23017"],
                "severity": "High",
                "description": "Off-by-one buffer overflow"
            },
        ]

    def _load_signature_patterns(self) -> Dict[str, List[Dict]]:
        """Load signature patterns for various vulnerability types"""
        return {
            "sqli": [
                {
                    "pattern": r"SQL syntax.*?error",
                    "indicators": ["mysql", "postgresql", "mssql", "oracle"],
                    "confidence": 0.9
                },
                {
                    "pattern": r"ORA-\d{5}",
                    "indicators": ["oracle"],
                    "confidence": 0.95
                },
                {
                    "pattern": r"pg_query\(\)",
                    "indicators": ["postgresql"],
                    "confidence": 0.85
                },
            ],
            "xss": [
                {
                    "pattern": r"<script[^>]*>.*?</script>",
                    "indicators": ["reflected"],
                    "confidence": 0.8
                },
                {
                    "pattern": r"javascript:",
                    "indicators": ["reflected"],
                    "confidence": 0.7
                },
            ],
            "xxe": [
                {
                    "pattern": r"<!ENTITY.*?SYSTEM",
                    "indicators": ["xml parsing"],
                    "confidence": 0.9
                },
            ],
            "ssrf": [
                {
                    "pattern": r"metadata\.google\.internal",
                    "indicators": ["gcp", "cloud"],
                    "confidence": 0.95
                },
                {
                    "pattern": r"169\.254\.169\.254",
                    "indicators": ["aws", "cloud"],
                    "confidence": 0.95
                },
            ],
            "lfi": [
                {
                    "pattern": r"(\.\.\/){3,}",
                    "indicators": ["path traversal"],
                    "confidence": 0.8
                },
                {
                    "pattern": r"\/etc\/passwd",
                    "indicators": ["unix", "linux"],
                    "confidence": 0.9
                },
            ],
            "rce": [
                {
                    "pattern": r"(bash|sh|cmd\.exe|powershell)",
                    "indicators": ["command injection"],
                    "confidence": 0.85
                },
            ],
        }

    def _load_config_patterns(self) -> List[Dict]:
        """Load patterns for configuration vulnerabilities"""
        return [
            {
                "name": "Directory Listing Enabled",
                "pattern": r"Index of /",
                "severity": "Medium",
                "cwe": "CWE-548"
            },
            {
                "name": "Debug Mode Enabled",
                "pattern": r"(debug\s*=\s*true|DEBUG\s*=\s*True|<debug>true</debug>)",
                "severity": "Medium",
                "cwe": "CWE-489"
            },
            {
                "name": "Stack Trace Exposed",
                "pattern": r"(Traceback|at\s+[A-Za-z0-9\.]+\([A-Za-z0-9\.]+:\d+\))",
                "severity": "Low",
                "cwe": "CWE-209"
            },
            {
                "name": "Sensitive File Exposed",
                "pattern": r"(\.env|\.git/config|wp-config\.php|web\.config)",
                "severity": "High",
                "cwe": "CWE-540"
            },
        ]

    async def detect_version_vulnerabilities(
        self,
        product: str,
        version: str,
        db_session: AsyncSession
    ) -> List[Dict]:
        """Detect vulnerabilities based on product version"""
        vulnerabilities = []

        # Check against version rules
        for rule in self.version_rules:
            if rule["product"].lower() in product.lower():
                if self._version_matches(version, rule["vulnerable_versions"]):
                    vulnerabilities.append({
                        "type": "version_vulnerability",
                        "name": rule["name"],
                        "severity": rule["severity"],
                        "cve_ids": rule["cve_ids"],
                        "description": rule["description"],
                        "confidence": 0.95,
                        "evidence": f"{product} {version}",
                    })

        # Check CVE database
        cve_vulns = await self._check_cve_database(product, version, db_session)
        vulnerabilities.extend(cve_vulns)

        return vulnerabilities

    async def _check_cve_database(
        self,
        product: str,
        version: str,
        db_session: AsyncSession
    ) -> List[Dict]:
        """Check product/version against CVE database"""
        vulnerabilities = []

        try:
            # Query CVE database
            result = await db_session.execute(
                select(CVEDatabase).where(
                    CVEDatabase.affected_products.like(f"%{product}%")
                ).limit(100)
            )
            cves = result.scalars().all()

            for cve in cves:
                # Parse affected versions
                affected_versions = json.loads(cve.affected_versions or "[]")

                if self._version_in_range(version, affected_versions):
                    vulnerabilities.append({
                        "type": "cve_match",
                        "name": f"{cve.cve_id} - {product} {version}",
                        "severity": cve.severity,
                        "cve_ids": [cve.cve_id],
                        "cvss_score": cve.cvss_v3_score or cve.cvss_v2_score,
                        "description": cve.description,
                        "confidence": 0.9,
                        "evidence": f"Version {version} matches CVE database",
                    })

        except Exception as e:
            self.logger.warning("CVE database check failed", error=str(e))

        return vulnerabilities

    def detect_signature_vulnerabilities(
        self,
        content: str,
        content_type: str = "response"
    ) -> List[Dict]:
        """Detect vulnerabilities using signature patterns"""
        vulnerabilities = []

        for vuln_type, patterns in self.signature_patterns.items():
            for pattern_def in patterns:
                if re.search(pattern_def["pattern"], content, re.IGNORECASE | re.DOTALL):
                    vulnerabilities.append({
                        "type": vuln_type,
                        "name": f"{vuln_type.upper()} Vulnerability Detected",
                        "severity": self._get_severity_for_type(vuln_type),
                        "confidence": pattern_def["confidence"],
                        "evidence": f"Pattern matched in {content_type}",
                        "pattern": pattern_def["pattern"],
                        "indicators": pattern_def["indicators"],
                    })

        return vulnerabilities

    def detect_configuration_issues(
        self,
        content: str,
        url: str
    ) -> List[Dict]:
        """Detect configuration and exposure issues"""
        issues = []

        for config_pattern in self.config_patterns:
            if re.search(config_pattern["pattern"], content, re.IGNORECASE):
                issues.append({
                    "type": "misconfiguration",
                    "name": config_pattern["name"],
                    "severity": config_pattern["severity"],
                    "cwe": config_pattern.get("cwe"),
                    "confidence": 0.85,
                    "evidence": f"Pattern found in response from {url}",
                })

        return issues

    def _version_matches(self, version: str, vulnerable_versions: List[str]) -> bool:
        """Check if version matches vulnerability criteria"""
        for vuln_ver in vulnerable_versions:
            if vuln_ver.startswith("<"):
                # Less than comparison
                target = vuln_ver.replace("< ", "").replace("<", "").strip()
                if self._compare_versions(version, target) < 0:
                    return True
            elif vuln_ver.startswith(">"):
                # Greater than comparison
                target = vuln_ver.replace("> ", "").replace(">", "").strip()
                if self._compare_versions(version, target) > 0:
                    return True
            elif version == vuln_ver:
                # Exact match
                return True

        return False

    def _version_in_range(self, version: str, version_ranges: List[str]) -> bool:
        """Check if version falls within specified ranges"""
        # Simplified version - in production, use proper version comparison library
        for range_spec in version_ranges:
            if version in range_spec or range_spec in version:
                return True
        return False

    def _compare_versions(self, v1: str, v2: str) -> int:
        """Compare two version strings"""
        def normalize(v):
            return [int(x) for x in re.sub(r'[a-zA-Z]+', '', v).split('.')]

        try:
            v1_parts = normalize(v1)
            v2_parts = normalize(v2)

            for i in range(max(len(v1_parts), len(v2_parts))):
                v1_part = v1_parts[i] if i < len(v1_parts) else 0
                v2_part = v2_parts[i] if i < len(v2_parts) else 0

                if v1_part < v2_part:
                    return -1
                elif v1_part > v2_part:
                    return 1

            return 0
        except:
            return 0

    def _get_severity_for_type(self, vuln_type: str) -> str:
        """Map vulnerability type to severity"""
        severity_map = {
            "sqli": "Critical",
            "rce": "Critical",
            "xxe": "High",
            "ssrf": "High",
            "xss": "Medium",
            "lfi": "High",
            "csrf": "Medium",
        }
        return severity_map.get(vuln_type, "Medium")


class MLBasedDetector:
    """
    Machine Learning-based vulnerability detection

    Uses anomaly detection and pattern learning to identify unusual behavior
    """

    def __init__(self):
        self.logger = logger.bind(component="ml_detector")
        self.baseline_models = {}

    async def detect_anomalies(
        self,
        traffic_data: List[HTTPTraffic],
        subdomain_id: int
    ) -> List[Dict]:
        """Detect anomalous behavior that might indicate vulnerabilities"""
        anomalies = []

        # Build baseline if not exists
        if subdomain_id not in self.baseline_models:
            await self._build_baseline(traffic_data, subdomain_id)

        baseline = self.baseline_models.get(subdomain_id, {})

        # Check for anomalies
        for traffic in traffic_data:
            anomaly_indicators = []

            # Unusual status codes
            if traffic.status_code and traffic.status_code >= 500:
                anomaly_indicators.append("server_error")

            # Unusual response times
            if traffic.response_time_ms and traffic.response_time_ms > baseline.get("avg_response_time", 1000) * 3:
                anomaly_indicators.append("slow_response")

            # Unusual response sizes
            if traffic.response_size and traffic.response_size > baseline.get("avg_response_size", 10000) * 5:
                anomaly_indicators.append("large_response")

            # Unusual headers
            if traffic.response_headers:
                try:
                    headers = json.loads(traffic.response_headers)
                    if "X-Debug" in headers or "X-Error" in headers:
                        anomaly_indicators.append("debug_headers")
                except:
                    pass

            if anomaly_indicators:
                anomalies.append({
                    "type": "anomaly_detected",
                    "name": "Behavioral Anomaly",
                    "severity": "Medium",
                    "confidence": 0.6,
                    "indicators": anomaly_indicators,
                    "evidence": f"Unusual behavior in {traffic.url}",
                    "traffic_id": traffic.id,
                })

        return anomalies

    async def _build_baseline(self, traffic_data: List[HTTPTraffic], subdomain_id: int):
        """Build baseline behavior model"""
        if not traffic_data:
            return

        response_times = [t.response_time_ms for t in traffic_data if t.response_time_ms]
        response_sizes = [t.response_size for t in traffic_data if t.response_size]

        self.baseline_models[subdomain_id] = {
            "avg_response_time": sum(response_times) / len(response_times) if response_times else 1000,
            "avg_response_size": sum(response_sizes) / len(response_sizes) if response_sizes else 10000,
            "common_status_codes": set(t.status_code for t in traffic_data if t.status_code),
        }


class VulnerabilityCorrelationEngine:
    """
    Main vulnerability correlation engine

    Combines rule-based and ML-based detection for comprehensive analysis
    """

    def __init__(self):
        self.logger = logger.bind(component="correlation_engine")
        self.rule_detector = RuleBasedDetector()
        self.ml_detector = MLBasedDetector()

    async def analyze_http_traffic(
        self,
        traffic: HTTPTraffic,
        db_session: AsyncSession
    ) -> List[Vulnerability]:
        """Analyze HTTP traffic for vulnerabilities"""
        vulnerabilities = []

        try:
            # Rule-based detection on response
            if traffic.response_body:
                try:
                    response_text = traffic.response_body.decode('utf-8', errors='ignore') if isinstance(traffic.response_body, bytes) else str(traffic.response_body)
                except:
                    response_text = ""

                # Signature-based detection
                sig_vulns = self.rule_detector.detect_signature_vulnerabilities(response_text, "response")
                vulnerabilities.extend(await self._create_vulnerabilities(sig_vulns, traffic, db_session))

                # Configuration issues
                config_issues = self.rule_detector.detect_configuration_issues(response_text, traffic.url)
                vulnerabilities.extend(await self._create_vulnerabilities(config_issues, traffic, db_session))

            # Version-based detection from headers
            if traffic.response_headers:
                try:
                    headers = json.loads(traffic.response_headers)
                    server_header = headers.get("Server", "")

                    if server_header:
                        # Extract product and version
                        product, version = self._parse_server_header(server_header)
                        if product and version:
                            ver_vulns = await self.rule_detector.detect_version_vulnerabilities(
                                product, version, db_session
                            )
                            vulnerabilities.extend(await self._create_vulnerabilities(ver_vulns, traffic, db_session))
                except:
                    pass

        except Exception as e:
            self.logger.error("Traffic analysis failed", traffic_id=traffic.id, error=str(e))

        return vulnerabilities

    async def analyze_port_service(
        self,
        port: Port,
        db_session: AsyncSession
    ) -> List[Vulnerability]:
        """Analyze port/service for vulnerabilities"""
        vulnerabilities = []

        if port.service_name and port.service_version:
            ver_vulns = await self.rule_detector.detect_version_vulnerabilities(
                port.service_name,
                port.service_version,
                db_session
            )
            vulnerabilities.extend(await self._create_vulnerabilities_for_port(ver_vulns, port, db_session))

        return vulnerabilities

    async def _create_vulnerabilities(
        self,
        detections: List[Dict],
        traffic: HTTPTraffic,
        db_session: AsyncSession
    ) -> List[Vulnerability]:
        """Create Vulnerability records from detections"""
        vulnerabilities = []

        for detection in detections:
            vuln = Vulnerability(
                type=detection.get("type", "unknown"),
                severity=detection.get("severity", "Medium"),
                cvss_score=detection.get("cvss_score"),
                cve_id=detection.get("cve_ids", [None])[0] if detection.get("cve_ids") else None,
                title=detection.get("name", "Vulnerability Detected"),
                description=detection.get("description", ""),
                subdomain_id=traffic.subdomain_id,
                evidence=detection.get("evidence", ""),
                confidence_score=detection.get("confidence", 0.5) * 100,
                status="new",
                discovered_at=datetime.utcnow()
            )

            db_session.add(vuln)
            vulnerabilities.append(vuln)

        await db_session.commit()
        return vulnerabilities

    async def _create_vulnerabilities_for_port(
        self,
        detections: List[Dict],
        port: Port,
        db_session: AsyncSession
    ) -> List[Vulnerability]:
        """Create Vulnerability records for port/service"""
        vulnerabilities = []

        for detection in detections:
            vuln = Vulnerability(
                type=detection.get("type", "service_vulnerability"),
                severity=detection.get("severity", "Medium"),
                cvss_score=detection.get("cvss_score"),
                cve_id=detection.get("cve_ids", [None])[0] if detection.get("cve_ids") else None,
                title=detection.get("name", "Service Vulnerability"),
                description=detection.get("description", ""),
                port_id=port.id,
                ip_id=port.ip_id,
                affected_component=f"{port.service_name}:{port.port_number}",
                affected_version=port.service_version,
                evidence=detection.get("evidence", ""),
                confidence_score=detection.get("confidence", 0.5) * 100,
                status="new",
                discovered_at=datetime.utcnow()
            )

            db_session.add(vuln)
            vulnerabilities.append(vuln)

        await db_session.commit()
        return vulnerabilities

    def _parse_server_header(self, server_header: str) -> Tuple[Optional[str], Optional[str]]:
        """Parse Server header to extract product and version"""
        # Example: "Apache/2.4.41 (Ubuntu)"
        match = re.match(r'([^/\s]+)/([^\s\(]+)', server_header)
        if match:
            return match.group(1), match.group(2)
        return None, None
