"""
Behavioral Pattern Analyzer

Identifies behavioral patterns and anomalies that indicate vulnerabilities:
- Response time anomalies (timing attacks, blind injection indicators)
- Error pattern analysis (error message leakage, stack traces)
- Input reflection patterns (XSS, injection indicators)
- Status code anomalies (unexpected responses)
- Response size anomalies (information leakage)
- Header anomalies (missing security headers, unusual patterns)
"""

import json
import uuid
import statistics
from typing import List, Dict, Optional, Any, Set
from datetime import datetime, timedelta
from collections import defaultdict, Counter
import re
import structlog
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, func

from app.models.vulnerability import PatternRecognition
from app.models.http_traffic import HTTPTraffic
from app.models.domain import Subdomain, Domain

logger = structlog.get_logger()


class BehavioralPatternAnalyzer:
    """
    Analyzes behavioral patterns in HTTP traffic to detect anomalies

    Patterns detected:
    - Response time anomalies (timing attacks, resource exhaustion)
    - Error message patterns (information leakage)
    - Input reflection (XSS, injection testing)
    - Status code anomalies (unexpected behaviors)
    - Response size anomalies (data leakage, enumeration)
    - Header anomalies (security misconfigurations)
    """

    # Constants for statistical analysis
    MIN_SAMPLE_SIZE = 10
    ANOMALY_Z_SCORE_THRESHOLD = 2.0  # 2 standard deviations
    MIN_CONFIDENCE = 0.7

    # Error patterns that indicate vulnerabilities
    ERROR_PATTERNS = {
        'sql_error': [
            r'SQL syntax.*?error',
            r'mysql_fetch',
            r'pg_query',
            r'sqlite3?.*?error',
            r'ORA-\d{5}',
            r'DB2 SQL error',
            r'ODBC.*?error',
            r'SQLServer JDBC Driver',
            r'Microsoft SQL Native Client error',
        ],
        'php_error': [
            r'PHP (Notice|Warning|Error|Parse error|Fatal error)',
            r'on line \d+',
            r'include\(.*?\):',
            r'require\(.*?\):',
        ],
        'java_error': [
            r'java\..*?Exception',
            r'at java\.',
            r'at javax\.',
            r'at org\.springframework',
            r'at com\.sun\.',
            r'\.java:\d+\)',
        ],
        'python_error': [
            r'Traceback \(most recent call last\)',
            r'File ".*?", line \d+',
            r'[A-Z][a-z]+Error:',
            r'django\..*?error',
            r'flask\..*?error',
        ],
        'asp_error': [
            r'ASP\.NET',
            r'System\..*?Exception',
            r'at System\.',
            r'Server Error in.*?Application',
            r'Microsoft VBScript',
        ],
        'nodejs_error': [
            r'at [A-Z][a-zA-Z]+\.',
            r'at .*?\.js:\d+:\d+',
            r'Error: .*?\n.*?at ',
        ],
    }

    # Sensitive information patterns
    SENSITIVE_PATTERNS = {
        'stack_trace': r'(?:Traceback|Exception|Error).*?(?:line \d+|\.(?:java|py|rb|js):\d+)',
        'file_path': r'(?:[A-Z]:\\|/(?:var|home|usr|opt))[\w/\\]+',
        'database_info': r'(?:host|server|database|schema|table)[\s=:]+\w+',
        'version_info': r'(?:version|v\.?|ver\.?)\s*[:\s]*\d+\.\d+(?:\.\d+)?',
        'internal_ip': r'\b(?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d+\.\d+\b',
    }

    def __init__(self):
        self.logger = logger.bind(component="behavioral_analyzer")

    async def analyze_domain(
        self,
        domain_id: int,
        db_session: AsyncSession,
        lookback_days: int = 7
    ) -> List[PatternRecognition]:
        """
        Analyze behavioral patterns for a domain

        Args:
            domain_id: Domain to analyze
            db_session: Database session
            lookback_days: Number of days to analyze

        Returns:
            List of detected behavioral patterns
        """
        self.logger.info("Analyzing behavioral patterns", domain_id=domain_id, lookback_days=lookback_days)

        patterns = []

        # Get all subdomains for this domain
        result = await db_session.execute(
            select(Subdomain).where(Subdomain.domain_id == domain_id)
        )
        subdomains = result.scalars().all()

        if not subdomains:
            self.logger.info("No subdomains found for domain", domain_id=domain_id)
            return patterns

        # Get HTTP traffic within time window
        since = datetime.utcnow() - timedelta(days=lookback_days)
        subdomain_ids = [s.id for s in subdomains]

        result = await db_session.execute(
            select(HTTPTraffic).where(
                and_(
                    HTTPTraffic.subdomain_id.in_(subdomain_ids),
                    HTTPTraffic.timestamp >= since
                )
            ).order_by(HTTPTraffic.timestamp)
        )
        traffic = result.scalars().all()

        if len(traffic) < self.MIN_SAMPLE_SIZE:
            self.logger.info("Insufficient traffic data for analysis",
                           traffic_count=len(traffic),
                           required=self.MIN_SAMPLE_SIZE)
            return patterns

        self.logger.info("Analyzing traffic data", traffic_count=len(traffic), subdomain_count=len(subdomains))

        # Run different behavioral analyses
        patterns.extend(await self._analyze_response_time_anomalies(traffic, domain_id, db_session))
        patterns.extend(await self._analyze_error_patterns(traffic, domain_id, db_session))
        patterns.extend(await self._analyze_input_reflection(traffic, domain_id, db_session))
        patterns.extend(await self._analyze_status_code_anomalies(traffic, domain_id, db_session))
        patterns.extend(await self._analyze_response_size_anomalies(traffic, domain_id, db_session))
        patterns.extend(await self._analyze_header_anomalies(traffic, domain_id, db_session))

        self.logger.info("Behavioral analysis complete", domain_id=domain_id, patterns_found=len(patterns))
        return patterns

    async def _analyze_response_time_anomalies(
        self,
        traffic: List[HTTPTraffic],
        domain_id: int,
        db_session: AsyncSession
    ) -> List[PatternRecognition]:
        """Detect response time anomalies that indicate timing attacks or resource issues"""
        patterns = []

        # Group traffic by endpoint (method + path)
        endpoint_timings = defaultdict(list)

        for req in traffic:
            if req.response_time_ms and req.response_time_ms > 0:
                endpoint = f"{req.method} {req.path or '/'}"
                endpoint_timings[endpoint].append({
                    'time': req.response_time_ms,
                    'subdomain_id': req.subdomain_id,
                    'url': req.url,
                    'status': req.status_code,
                    'timestamp': req.timestamp
                })

        # Analyze each endpoint for timing anomalies
        for endpoint, timings in endpoint_timings.items():
            if len(timings) < self.MIN_SAMPLE_SIZE:
                continue

            times = [t['time'] for t in timings]
            mean_time = statistics.mean(times)

            # Need at least some variance
            if len(set(times)) < 3:
                continue

            try:
                stdev_time = statistics.stdev(times)
            except statistics.StatisticsError:
                continue

            if stdev_time == 0:
                continue

            # Find anomalous requests using z-score
            anomalies = []
            for timing in timings:
                z_score = abs((timing['time'] - mean_time) / stdev_time)
                if z_score >= self.ANOMALY_Z_SCORE_THRESHOLD:
                    anomalies.append({
                        **timing,
                        'z_score': z_score,
                        'deviation_ms': abs(timing['time'] - mean_time)
                    })

            if not anomalies:
                continue

            # Determine if this is consistently slow or sporadically slow
            anomaly_rate = len(anomalies) / len(timings)

            # Categorize the anomaly
            if anomaly_rate > 0.3:
                # Consistently slow endpoint
                pattern_type = "consistently_slow_endpoint"
                risk_level = "Medium"
                description = (f"Endpoint {endpoint} shows consistently slow response times. "
                             f"Mean: {mean_time:.0f}ms, StdDev: {stdev_time:.0f}ms. "
                             f"{len(anomalies)} of {len(timings)} requests ({anomaly_rate*100:.1f}%) "
                             f"are anomalously slow. This may indicate resource exhaustion, "
                             f"inefficient queries, or processing bottlenecks.")
                potential_vulns = ["resource_exhaustion", "dos_vulnerability", "inefficient_processing"]
                scenarios = [
                    "Resource exhaustion through repeated slow requests",
                    "Timing-based enumeration of backend resources",
                    "Detection of expensive operations for DoS attacks"
                ]
            else:
                # Sporadic timing anomalies (more concerning for timing attacks)
                pattern_type = "timing_attack_indicator"
                risk_level = "High"
                description = (f"Endpoint {endpoint} shows sporadic timing anomalies. "
                             f"Mean: {mean_time:.0f}ms, but {len(anomalies)} requests show "
                             f"significant deviations (z-score > {self.ANOMALY_Z_SCORE_THRESHOLD}). "
                             f"This pattern may indicate timing-based attacks, blind injection attempts, "
                             f"or backend conditional processing based on input.")
                potential_vulns = ["timing_attack", "blind_sqli", "authentication_timing", "resource_enumeration"]
                scenarios = [
                    "Timing-based blind SQL injection",
                    "Authentication timing attacks to enumerate users",
                    "Conditional processing revealing sensitive operations",
                    "Backend resource enumeration through timing"
                ]

            # Calculate confidence based on sample size and anomaly clarity
            confidence = min(
                (len(timings) / 100) * 0.5 +  # More samples = higher confidence
                (min(stdev_time / mean_time, 1.0)) * 0.3 +  # Higher variance = higher confidence
                (min(len(anomalies) / 5, 1.0)) * 0.2,  # More anomalies = higher confidence
                0.95
            )

            if confidence < self.MIN_CONFIDENCE:
                continue

            # Get affected subdomains
            affected_subdomains = list(set(t['subdomain_id'] for t in anomalies))

            pattern = PatternRecognition(
                pattern_id=str(uuid.uuid4()),
                pattern_category="behavioral",
                pattern_type=pattern_type,
                pattern_name=f"Response Time Anomaly: {endpoint}",
                description=description,
                evidence=json.dumps({
                    "endpoint": endpoint,
                    "sample_size": len(timings),
                    "mean_response_ms": round(mean_time, 2),
                    "stdev_response_ms": round(stdev_time, 2),
                    "anomaly_count": len(anomalies),
                    "anomaly_rate": round(anomaly_rate, 3),
                    "min_time_ms": min(times),
                    "max_time_ms": max(times),
                    "z_score_threshold": self.ANOMALY_Z_SCORE_THRESHOLD,
                    "sample_anomalies": [
                        {
                            "time_ms": a['time'],
                            "z_score": round(a['z_score'], 2),
                            "deviation_ms": a['deviation_ms'],
                            "url": a['url'][:200]
                        }
                        for a in sorted(anomalies, key=lambda x: x['z_score'], reverse=True)[:5]
                    ]
                }),
                affected_assets=json.dumps(affected_subdomains),
                frequency=len(anomalies),
                consistency=confidence,
                anomaly_score=min(anomaly_rate * 2, 1.0),
                time_window_start=timings[0]['timestamp'],
                time_window_end=timings[-1]['timestamp'],
                baseline_behavior=json.dumps({
                    "mean_response_ms": round(mean_time, 2),
                    "stdev_response_ms": round(stdev_time, 2),
                    "sample_size": len(timings)
                }),
                observed_behavior=json.dumps({
                    "anomalies": len(anomalies),
                    "max_z_score": round(max(a['z_score'] for a in anomalies), 2),
                    "max_deviation_ms": max(a['deviation_ms'] for a in anomalies)
                }),
                deviation_score=max(a['z_score'] for a in anomalies) / self.ANOMALY_Z_SCORE_THRESHOLD,
                risk_level=risk_level,
                potential_vulnerabilities=json.dumps(potential_vulns),
                exploitation_scenarios=json.dumps(scenarios)
            )

            db_session.add(pattern)
            patterns.append(pattern)

        await db_session.commit()
        return patterns

    async def _analyze_error_patterns(
        self,
        traffic: List[HTTPTraffic],
        domain_id: int,
        db_session: AsyncSession
    ) -> List[PatternRecognition]:
        """Detect error message patterns that leak information"""
        patterns = []

        # Track errors by type and endpoint
        error_traffic = [t for t in traffic if t.status_code and t.status_code >= 400]

        if len(error_traffic) < self.MIN_SAMPLE_SIZE:
            return patterns

        # Analyze error responses for sensitive information leakage
        errors_with_leakage = defaultdict(list)

        for req in error_traffic:
            if not req.response_body:
                continue

            try:
                # Decompress and decode response
                response_text = req.response_body.decode('utf-8', errors='ignore')

                # Check for error patterns
                detected_patterns = {}
                for error_type, pattern_list in self.ERROR_PATTERNS.items():
                    for pattern in pattern_list:
                        if re.search(pattern, response_text, re.IGNORECASE):
                            detected_patterns[error_type] = True
                            break

                # Check for sensitive information
                sensitive_info = {}
                for info_type, pattern in self.SENSITIVE_PATTERNS.items():
                    matches = re.findall(pattern, response_text, re.IGNORECASE | re.MULTILINE)
                    if matches:
                        sensitive_info[info_type] = matches[:3]  # Keep first 3 examples

                if detected_patterns or sensitive_info:
                    endpoint = f"{req.method} {req.path or '/'}"
                    errors_with_leakage[endpoint].append({
                        'subdomain_id': req.subdomain_id,
                        'url': req.url,
                        'status_code': req.status_code,
                        'error_types': list(detected_patterns.keys()),
                        'sensitive_info': sensitive_info,
                        'response_preview': response_text[:500]
                    })
            except Exception as e:
                self.logger.debug("Error parsing response body", error=str(e))
                continue

        # Generate patterns for endpoints with information leakage
        for endpoint, errors in errors_with_leakage.items():
            if len(errors) < 2:  # Need at least 2 occurrences
                continue

            # Aggregate error types
            all_error_types = []
            all_sensitive_types = set()
            for error in errors:
                all_error_types.extend(error['error_types'])
                all_sensitive_types.update(error['sensitive_info'].keys())

            error_type_counts = Counter(all_error_types)

            # Determine severity based on what's leaked
            severity_score = 0
            critical_leaks = []

            if 'stack_trace' in all_sensitive_types:
                severity_score += 0.3
                critical_leaks.append("stack traces")
            if 'file_path' in all_sensitive_types:
                severity_score += 0.25
                critical_leaks.append("file paths")
            if 'database_info' in all_sensitive_types:
                severity_score += 0.2
                critical_leaks.append("database information")
            if 'internal_ip' in all_sensitive_types:
                severity_score += 0.15
                critical_leaks.append("internal IP addresses")
            if 'version_info' in all_sensitive_types:
                severity_score += 0.1
                critical_leaks.append("version information")

            if severity_score < 0.2:
                risk_level = "Low"
            elif severity_score < 0.4:
                risk_level = "Medium"
            else:
                risk_level = "High"

            affected_subdomains = list(set(e['subdomain_id'] for e in errors))

            pattern = PatternRecognition(
                pattern_id=str(uuid.uuid4()),
                pattern_category="behavioral",
                pattern_type="error_information_disclosure",
                pattern_name=f"Error Information Leakage: {endpoint}",
                description=(f"Endpoint {endpoint} leaks sensitive information in error responses. "
                           f"Detected {len(errors)} error responses containing: {', '.join(critical_leaks)}. "
                           f"Error types: {', '.join(error_type_counts.keys())}. "
                           f"This information helps attackers understand the technology stack, "
                           f"file structure, and potential attack vectors."),
                evidence=json.dumps({
                    "endpoint": endpoint,
                    "error_count": len(errors),
                    "error_types": dict(error_type_counts),
                    "sensitive_info_types": list(all_sensitive_types),
                    "severity_score": round(severity_score, 2),
                    "sample_errors": [
                        {
                            "url": e['url'][:200],
                            "status_code": e['status_code'],
                            "error_types": e['error_types'],
                            "sensitive_info": {k: v[:2] for k, v in e['sensitive_info'].items()},
                            "preview": e['response_preview'][:200]
                        }
                        for e in errors[:3]
                    ]
                }),
                affected_assets=json.dumps(affected_subdomains),
                frequency=len(errors),
                consistency=0.8,
                anomaly_score=severity_score,
                risk_level=risk_level,
                potential_vulnerabilities=json.dumps([
                    "information_disclosure",
                    "stack_trace_exposure",
                    "path_disclosure",
                    "technology_fingerprinting"
                ]),
                exploitation_scenarios=json.dumps([
                    "Technology stack fingerprinting from error messages",
                    "File path disclosure reveals directory structure",
                    "Database information aids in SQL injection",
                    "Internal IP addresses reveal network topology",
                    "Version information enables targeted exploit selection"
                ])
            )

            db_session.add(pattern)
            patterns.append(pattern)

        await db_session.commit()
        return patterns

    async def _analyze_input_reflection(
        self,
        traffic: List[HTTPTraffic],
        domain_id: int,
        db_session: AsyncSession
    ) -> List[PatternRecognition]:
        """Detect input reflection patterns that may indicate XSS or injection vulnerabilities"""
        patterns = []

        # Track requests with query parameters or POST bodies
        reflection_candidates = defaultdict(list)

        for req in traffic:
            if not req.response_body:
                continue

            # Extract potential input sources
            inputs = set()

            # Query parameters
            if req.query_params:
                try:
                    params = json.loads(req.query_params)
                    for value in params.values():
                        if isinstance(value, str) and len(value) >= 3:
                            inputs.add(value[:100])  # Limit length
                except:
                    pass

            # POST body (if text-based)
            if req.request_body and req.request_content_type and 'json' in req.request_content_type.lower():
                try:
                    body_text = req.request_body.decode('utf-8', errors='ignore')
                    body_data = json.loads(body_text)

                    def extract_values(obj):
                        if isinstance(obj, dict):
                            for v in obj.values():
                                extract_values(v)
                        elif isinstance(obj, list):
                            for item in obj:
                                extract_values(item)
                        elif isinstance(obj, str) and len(obj) >= 3:
                            inputs.add(obj[:100])

                    extract_values(body_data)
                except:
                    pass

            if not inputs:
                continue

            # Check if any inputs are reflected in response
            try:
                response_text = req.response_body.decode('utf-8', errors='ignore')

                reflected_inputs = []
                for input_val in inputs:
                    if input_val in response_text:
                        # Count occurrences
                        count = response_text.count(input_val)

                        # Check if it's in dangerous contexts (unescaped HTML/JS)
                        dangerous = False
                        context = []

                        # Simple heuristics for dangerous contexts
                        if re.search(rf'<[^>]*{re.escape(input_val)}[^>]*>', response_text):
                            dangerous = True
                            context.append("HTML_TAG")
                        if re.search(rf'<script[^>]*>.*?{re.escape(input_val)}.*?</script>', response_text, re.DOTALL):
                            dangerous = True
                            context.append("JAVASCRIPT")
                        if re.search(rf'on\w+\s*=\s*["\']?.*?{re.escape(input_val)}', response_text):
                            dangerous = True
                            context.append("EVENT_HANDLER")

                        reflected_inputs.append({
                            'value': input_val,
                            'count': count,
                            'dangerous': dangerous,
                            'contexts': context
                        })

                if reflected_inputs:
                    endpoint = f"{req.method} {req.path or '/'}"
                    reflection_candidates[endpoint].append({
                        'subdomain_id': req.subdomain_id,
                        'url': req.url,
                        'reflected_inputs': reflected_inputs,
                        'status_code': req.status_code
                    })
            except Exception as e:
                self.logger.debug("Error checking reflection", error=str(e))
                continue

        # Generate patterns for endpoints with reflected input
        for endpoint, reflections in reflection_candidates.items():
            if len(reflections) < 2:
                continue

            # Calculate dangerous reflection rate
            total_reflections = len(reflections)
            dangerous_count = sum(
                1 for r in reflections
                if any(inp['dangerous'] for inp in r['reflected_inputs'])
            )

            dangerous_rate = dangerous_count / total_reflections

            # Only report if there are dangerous reflections
            if dangerous_count == 0:
                continue

            # Determine risk level
            if dangerous_rate > 0.5:
                risk_level = "High"
            elif dangerous_rate > 0.2:
                risk_level = "Medium"
            else:
                risk_level = "Low"

            affected_subdomains = list(set(r['subdomain_id'] for r in reflections))

            # Collect context types
            all_contexts = set()
            for r in reflections:
                for inp in r['reflected_inputs']:
                    all_contexts.update(inp['contexts'])

            pattern = PatternRecognition(
                pattern_id=str(uuid.uuid4()),
                pattern_category="behavioral",
                pattern_type="input_reflection",
                pattern_name=f"Input Reflection Detected: {endpoint}",
                description=(f"Endpoint {endpoint} reflects user input in responses. "
                           f"{dangerous_count} of {total_reflections} requests ({dangerous_rate*100:.1f}%) "
                           f"show reflections in dangerous contexts: {', '.join(all_contexts)}. "
                           f"This may indicate potential XSS, injection vulnerabilities, or insufficient "
                           f"output encoding."),
                evidence=json.dumps({
                    "endpoint": endpoint,
                    "total_reflections": total_reflections,
                    "dangerous_reflections": dangerous_count,
                    "dangerous_rate": round(dangerous_rate, 3),
                    "contexts": list(all_contexts),
                    "sample_reflections": [
                        {
                            "url": r['url'][:200],
                            "reflected_inputs": [
                                {
                                    "value": inp['value'][:50],
                                    "count": inp['count'],
                                    "dangerous": inp['dangerous'],
                                    "contexts": inp['contexts']
                                }
                                for inp in r['reflected_inputs']
                            ]
                        }
                        for r in reflections[:3]
                    ]
                }),
                affected_assets=json.dumps(affected_subdomains),
                frequency=dangerous_count,
                consistency=0.8,
                anomaly_score=dangerous_rate,
                risk_level=risk_level,
                potential_vulnerabilities=json.dumps([
                    "xss",
                    "html_injection",
                    "javascript_injection",
                    "insufficient_output_encoding"
                ]),
                exploitation_scenarios=json.dumps([
                    "Reflected XSS attacks through unescaped input",
                    "JavaScript injection in event handlers",
                    "HTML injection to modify page content",
                    "DOM-based XSS exploitation"
                ])
            )

            db_session.add(pattern)
            patterns.append(pattern)

        await db_session.commit()
        return patterns

    async def _analyze_status_code_anomalies(
        self,
        traffic: List[HTTPTraffic],
        domain_id: int,
        db_session: AsyncSession
    ) -> List[PatternRecognition]:
        """Detect unusual status code patterns"""
        patterns = []

        # Group by endpoint and status code
        endpoint_statuses = defaultdict(lambda: Counter())

        for req in traffic:
            if req.status_code:
                endpoint = f"{req.method} {req.path or '/'}"
                endpoint_statuses[endpoint][req.status_code] += 1

        # Analyze each endpoint for status code anomalies
        for endpoint, status_counts in endpoint_statuses.items():
            total_requests = sum(status_counts.values())

            if total_requests < self.MIN_SAMPLE_SIZE:
                continue

            # Calculate status code distribution
            status_distribution = {
                status: count / total_requests
                for status, count in status_counts.items()
            }

            # Detect unusual patterns
            anomalies = []

            # High error rate (4xx or 5xx)
            error_codes = {s: c for s, c in status_counts.items() if s >= 400}
            if error_codes:
                error_rate = sum(error_codes.values()) / total_requests
                if error_rate > 0.3:  # More than 30% errors
                    anomalies.append({
                        'type': 'high_error_rate',
                        'error_rate': error_rate,
                        'error_codes': dict(error_codes)
                    })

            # Unusual redirect patterns (excessive 3xx)
            redirect_codes = {s: c for s, c in status_counts.items() if 300 <= s < 400}
            if redirect_codes:
                redirect_rate = sum(redirect_codes.values()) / total_requests
                if redirect_rate > 0.4:  # More than 40% redirects
                    anomalies.append({
                        'type': 'excessive_redirects',
                        'redirect_rate': redirect_rate,
                        'redirect_codes': dict(redirect_codes)
                    })

            # Unusual status code diversity (too many different codes)
            if len(status_counts) > 5:
                anomalies.append({
                    'type': 'high_status_diversity',
                    'unique_codes': len(status_counts),
                    'distribution': dict(status_distribution)
                })

            if not anomalies:
                continue

            # Determine risk level based on anomaly types
            has_high_errors = any(a['type'] == 'high_error_rate' for a in anomalies)
            error_rate = next((a['error_rate'] for a in anomalies if a['type'] == 'high_error_rate'), 0)

            if error_rate > 0.5:
                risk_level = "High"
            elif has_high_errors or len(anomalies) > 1:
                risk_level = "Medium"
            else:
                risk_level = "Low"

            pattern = PatternRecognition(
                pattern_id=str(uuid.uuid4()),
                pattern_category="behavioral",
                pattern_type="status_code_anomaly",
                pattern_name=f"Status Code Anomaly: {endpoint}",
                description=(f"Endpoint {endpoint} shows unusual status code patterns. "
                           f"Total requests: {total_requests}. "
                           f"Anomalies: {', '.join(a['type'] for a in anomalies)}. "
                           f"This may indicate misconfiguration, error handling issues, "
                           f"or potential attack attempts."),
                evidence=json.dumps({
                    "endpoint": endpoint,
                    "total_requests": total_requests,
                    "status_distribution": {str(k): round(v, 3) for k, v in status_distribution.items()},
                    "anomalies": anomalies
                }),
                affected_assets=json.dumps([]),  # Not subdomain-specific
                frequency=total_requests,
                consistency=0.7,
                anomaly_score=min(len(anomalies) * 0.3, 1.0),
                baseline_behavior=json.dumps({
                    "expected_success_rate": 0.9,
                    "expected_error_rate": 0.1
                }),
                observed_behavior=json.dumps({
                    "actual_distribution": {str(k): round(v, 3) for k, v in status_distribution.items()}
                }),
                deviation_score=len(anomalies) * 0.3,
                risk_level=risk_level,
                potential_vulnerabilities=json.dumps([
                    "misconfiguration",
                    "error_handling_issues",
                    "access_control_problems"
                ]),
                exploitation_scenarios=json.dumps([
                    "High error rates may indicate exploitable conditions",
                    "Excessive redirects could indicate redirect loops or open redirects",
                    "Status code diversity suggests inconsistent security posture"
                ])
            )

            db_session.add(pattern)
            patterns.append(pattern)

        await db_session.commit()
        return patterns

    async def _analyze_response_size_anomalies(
        self,
        traffic: List[HTTPTraffic],
        domain_id: int,
        db_session: AsyncSession
    ) -> List[PatternRecognition]:
        """Detect response size anomalies that may indicate information leakage"""
        patterns = []

        # Group by endpoint and analyze response sizes
        endpoint_sizes = defaultdict(list)

        for req in traffic:
            if req.response_size and req.response_size > 0:
                endpoint = f"{req.method} {req.path or '/'}"
                endpoint_sizes[endpoint].append({
                    'size': req.response_size,
                    'subdomain_id': req.subdomain_id,
                    'url': req.url,
                    'status_code': req.status_code
                })

        # Analyze each endpoint
        for endpoint, sizes in endpoint_sizes.items():
            if len(sizes) < self.MIN_SAMPLE_SIZE:
                continue

            size_values = [s['size'] for s in sizes]
            mean_size = statistics.mean(size_values)

            # Need variance to detect anomalies
            if len(set(size_values)) < 3:
                continue

            try:
                stdev_size = statistics.stdev(size_values)
            except statistics.StatisticsError:
                continue

            if stdev_size == 0:
                continue

            # Find anomalous responses
            anomalies = []
            for size_data in sizes:
                z_score = abs((size_data['size'] - mean_size) / stdev_size)
                if z_score >= self.ANOMALY_Z_SCORE_THRESHOLD:
                    anomalies.append({
                        **size_data,
                        'z_score': z_score,
                        'deviation_bytes': abs(size_data['size'] - mean_size)
                    })

            if not anomalies:
                continue

            # Calculate anomaly rate
            anomaly_rate = len(anomalies) / len(sizes)

            # Higher confidence for clear anomalies
            confidence = min(
                (len(sizes) / 100) * 0.4 +
                (min(stdev_size / mean_size, 1.0)) * 0.4 +
                (min(len(anomalies) / 5, 1.0)) * 0.2,
                0.95
            )

            if confidence < self.MIN_CONFIDENCE:
                continue

            # Determine risk level
            # Large responses might leak data, small responses might indicate enumeration
            max_deviation_ratio = max(a['deviation_bytes'] / mean_size for a in anomalies)

            if max_deviation_ratio > 2.0 or anomaly_rate > 0.2:
                risk_level = "Medium"
            else:
                risk_level = "Low"

            affected_subdomains = list(set(a['subdomain_id'] for a in anomalies))

            pattern = PatternRecognition(
                pattern_id=str(uuid.uuid4()),
                pattern_category="behavioral",
                pattern_type="response_size_anomaly",
                pattern_name=f"Response Size Anomaly: {endpoint}",
                description=(f"Endpoint {endpoint} shows response size anomalies. "
                           f"Mean: {mean_size:.0f} bytes, StdDev: {stdev_size:.0f} bytes. "
                           f"{len(anomalies)} of {len(sizes)} responses ({anomaly_rate*100:.1f}%) "
                           f"are anomalously sized. This may indicate information leakage, "
                           f"user enumeration, or data exposure vulnerabilities."),
                evidence=json.dumps({
                    "endpoint": endpoint,
                    "sample_size": len(sizes),
                    "mean_size_bytes": round(mean_size, 2),
                    "stdev_size_bytes": round(stdev_size, 2),
                    "anomaly_count": len(anomalies),
                    "anomaly_rate": round(anomaly_rate, 3),
                    "min_size_bytes": min(size_values),
                    "max_size_bytes": max(size_values),
                    "sample_anomalies": [
                        {
                            "size_bytes": a['size'],
                            "z_score": round(a['z_score'], 2),
                            "deviation_bytes": a['deviation_bytes'],
                            "url": a['url'][:200]
                        }
                        for a in sorted(anomalies, key=lambda x: x['z_score'], reverse=True)[:5]
                    ]
                }),
                affected_assets=json.dumps(affected_subdomains),
                frequency=len(anomalies),
                consistency=confidence,
                anomaly_score=min(anomaly_rate * 2, 1.0),
                baseline_behavior=json.dumps({
                    "mean_size_bytes": round(mean_size, 2),
                    "stdev_size_bytes": round(stdev_size, 2)
                }),
                observed_behavior=json.dumps({
                    "anomalies": len(anomalies),
                    "max_deviation_ratio": round(max_deviation_ratio, 2)
                }),
                deviation_score=max_deviation_ratio,
                risk_level=risk_level,
                potential_vulnerabilities=json.dumps([
                    "information_disclosure",
                    "user_enumeration",
                    "data_leakage",
                    "authentication_oracle"
                ]),
                exploitation_scenarios=json.dumps([
                    "Response size differences reveal valid vs invalid usernames",
                    "Larger responses leak sensitive data based on permissions",
                    "Size-based enumeration of resources",
                    "Timing oracle through size-dependent processing"
                ])
            )

            db_session.add(pattern)
            patterns.append(pattern)

        await db_session.commit()
        return patterns

    async def _analyze_header_anomalies(
        self,
        traffic: List[HTTPTraffic],
        domain_id: int,
        db_session: AsyncSession
    ) -> List[PatternRecognition]:
        """Detect security header anomalies and misconfigurations"""
        patterns = []

        # Security headers to check
        SECURITY_HEADERS = {
            'x-frame-options',
            'x-content-type-options',
            'x-xss-protection',
            'strict-transport-security',
            'content-security-policy',
            'referrer-policy',
            'permissions-policy'
        }

        # Group by subdomain and analyze headers
        subdomain_headers = defaultdict(lambda: {
            'total_requests': 0,
            'security_headers': Counter(),
            'missing_security_headers': Counter(),
            'unusual_headers': Counter()
        })

        for req in traffic:
            if not req.response_headers:
                continue

            try:
                headers = json.loads(req.response_headers)
                if not isinstance(headers, dict):
                    continue

                # Normalize header names
                header_keys = {k.lower(): k for k in headers.keys()}

                subdomain_headers[req.subdomain_id]['total_requests'] += 1

                # Check for security headers
                for sec_header in SECURITY_HEADERS:
                    if sec_header in header_keys:
                        subdomain_headers[req.subdomain_id]['security_headers'][sec_header] += 1
                    else:
                        subdomain_headers[req.subdomain_id]['missing_security_headers'][sec_header] += 1

                # Check for unusual or debugging headers
                debug_headers = [k for k in header_keys.keys() if any(
                    dbg in k for dbg in ['debug', 'trace', 'x-powered-by', 'server', 'x-aspnet-version']
                )]
                for dh in debug_headers:
                    subdomain_headers[req.subdomain_id]['unusual_headers'][dh] += 1

            except Exception as e:
                self.logger.debug("Error parsing headers", error=str(e))
                continue

        # Generate patterns for subdomains with security issues
        for subdomain_id, header_data in subdomain_headers.items():
            if header_data['total_requests'] < self.MIN_SAMPLE_SIZE:
                continue

            issues = []

            # Check for consistently missing security headers
            total = header_data['total_requests']
            for header, missing_count in header_data['missing_security_headers'].items():
                missing_rate = missing_count / total
                if missing_rate > 0.8:  # Missing in >80% of responses
                    issues.append({
                        'type': 'missing_security_header',
                        'header': header,
                        'missing_rate': missing_rate
                    })

            # Check for debugging headers
            for header, count in header_data['unusual_headers'].items():
                presence_rate = count / total
                if presence_rate > 0.5:  # Present in >50% of responses
                    issues.append({
                        'type': 'debug_header_exposure',
                        'header': header,
                        'presence_rate': presence_rate
                    })

            if not issues:
                continue

            # Determine risk level
            critical_headers_missing = sum(
                1 for i in issues
                if i['type'] == 'missing_security_header' and
                i['header'] in ['content-security-policy', 'strict-transport-security']
            )

            if critical_headers_missing >= 2 or len(issues) > 5:
                risk_level = "High"
            elif len(issues) > 2:
                risk_level = "Medium"
            else:
                risk_level = "Low"

            pattern = PatternRecognition(
                pattern_id=str(uuid.uuid4()),
                pattern_category="behavioral",
                pattern_type="security_header_misconfiguration",
                pattern_name=f"Security Header Issues on Subdomain {subdomain_id}",
                description=(f"Subdomain shows security header misconfigurations. "
                           f"{len(issues)} issues detected across {total} requests. "
                           f"Missing critical security headers and/or exposing debugging information."),
                evidence=json.dumps({
                    "subdomain_id": subdomain_id,
                    "total_requests": total,
                    "issues": issues,
                    "security_headers_present": dict(header_data['security_headers']),
                    "debug_headers": dict(header_data['unusual_headers'])
                }),
                affected_assets=json.dumps([subdomain_id]),
                frequency=len(issues),
                consistency=0.9,
                anomaly_score=min(len(issues) * 0.15, 1.0),
                risk_level=risk_level,
                potential_vulnerabilities=json.dumps([
                    "missing_security_headers",
                    "clickjacking",
                    "xss",
                    "information_disclosure",
                    "mime_sniffing"
                ]),
                exploitation_scenarios=json.dumps([
                    "Clickjacking attacks due to missing X-Frame-Options",
                    "XSS exploitation without Content-Security-Policy",
                    "Man-in-the-middle without HSTS",
                    "Technology fingerprinting from Server/X-Powered-By headers",
                    "MIME-type confusion attacks"
                ])
            )

            db_session.add(pattern)
            patterns.append(pattern)

        await db_session.commit()
        return patterns
