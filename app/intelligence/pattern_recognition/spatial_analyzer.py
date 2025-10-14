"""
Spatial Pattern Analyzer

Identifies spatial patterns and infrastructure relationships:
- Shared authentication systems between subdomains
- Infrastructure relationships (same IP, same ASN, same hosting)
- Technology clusters (similar tech stacks)
- Geographic patterns
- Session/cookie sharing between domains
"""

import json
import uuid
from typing import List, Dict, Optional, Set, Tuple
from datetime import datetime
from collections import defaultdict
import structlog
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, func

from app.models.vulnerability import PatternRecognition
from app.models.domain import Subdomain
from app.models.network import IPAddress, ASN, SubdomainIP
from app.models.http_traffic import HTTPTraffic

logger = structlog.get_logger()


class SpatialPatternAnalyzer:
    """
    Analyzes spatial patterns and relationships across infrastructure

    Patterns detected:
    - Shared authentication systems
    - Infrastructure clustering (IPs, ASNs, hosting)
    - Technology stack similarities
    - Geographic distribution
    - Session/cookie sharing relationships
    """

    def __init__(self):
        self.logger = logger.bind(component="spatial_analyzer")

    async def analyze_domain(
        self,
        domain_id: int,
        db_session: AsyncSession
    ) -> List[PatternRecognition]:
        """
        Analyze spatial patterns for a domain

        Args:
            domain_id: Domain to analyze
            db_session: Database session

        Returns:
            List of detected spatial patterns
        """
        self.logger.info("Analyzing spatial patterns", domain_id=domain_id)

        patterns = []

        # Get all subdomains for this domain
        result = await db_session.execute(
            select(Subdomain).where(Subdomain.domain_id == domain_id)
        )
        subdomains = result.scalars().all()

        if len(subdomains) < 2:  # Need at least 2 subdomains for relationships
            self.logger.info("Not enough subdomains for spatial analysis", count=len(subdomains))
            return patterns

        # Analyze different spatial dimensions
        patterns.extend(await self._analyze_shared_auth(subdomains, domain_id, db_session))
        patterns.extend(await self._analyze_infrastructure_relationships(subdomains, domain_id, db_session))
        patterns.extend(await self._analyze_technology_clusters(subdomains, domain_id, db_session))
        patterns.extend(await self._analyze_geographic_patterns(subdomains, domain_id, db_session))
        patterns.extend(await self._analyze_session_relationships(subdomains, domain_id, db_session))

        self.logger.info("Spatial analysis complete", domain_id=domain_id, patterns_found=len(patterns))
        return patterns

    async def _analyze_shared_auth(
        self,
        subdomains: List[Subdomain],
        domain_id: int,
        db_session: AsyncSession
    ) -> List[PatternRecognition]:
        """Detect shared authentication systems between subdomains"""
        patterns = []

        # Group subdomains by authentication patterns
        auth_groups = defaultdict(list)
        auth_indicators = {}

        for subdomain in subdomains:
            # Get HTTP traffic with auth-related headers
            result = await db_session.execute(
                select(HTTPTraffic).where(
                    and_(
                        HTTPTraffic.subdomain_id == subdomain.id,
                        HTTPTraffic.requires_auth == True
                    )
                ).limit(100)  # Sample recent auth traffic
            )
            traffic = result.scalars().all()

            if not traffic:
                continue

            # Analyze auth mechanisms
            auth_types = set()
            auth_domains = set()
            sso_indicators = []

            for req in traffic:
                if req.auth_type:
                    auth_types.add(req.auth_type)

                # Parse headers for auth indicators
                if req.request_headers:
                    try:
                        headers = json.loads(req.request_headers)

                        # Check for SSO/OAuth redirects
                        if 'location' in headers.get('response_headers', {}):
                            location = headers['response_headers']['location']
                            if any(sso in location.lower() for sso in ['oauth', 'saml', 'sso', 'auth0', 'okta']):
                                sso_indicators.append(location)
                                # Extract auth domain
                                from urllib.parse import urlparse
                                parsed = urlparse(location)
                                auth_domains.add(parsed.netloc)

                        # Check for JWT tokens
                        if 'authorization' in headers:
                            auth_header = headers['authorization']
                            if auth_header.startswith('Bearer '):
                                auth_types.add('JWT')
                    except:
                        pass

            # Create signature for this subdomain's auth
            auth_signature = {
                'auth_types': sorted(auth_types),
                'auth_domains': sorted(auth_domains),
                'has_sso': len(sso_indicators) > 0
            }

            if auth_types or auth_domains:
                signature_key = json.dumps(auth_signature, sort_keys=True)
                auth_groups[signature_key].append(subdomain.id)
                auth_indicators[subdomain.id] = {
                    'auth_types': list(auth_types),
                    'auth_domains': list(auth_domains),
                    'sso_examples': sso_indicators[:3]
                }

        # Find groups with shared authentication (3+ subdomains)
        for signature, subdomain_ids in auth_groups.items():
            if len(subdomain_ids) >= 3:
                auth_sig = json.loads(signature)

                # Calculate consistency score based on how many share this pattern
                consistency = len(subdomain_ids) / len(subdomains)

                # Determine risk level
                risk_level = "Medium"
                potential_vulns = ["authentication_bypass", "session_fixation"]
                scenarios = [
                    "Authentication bypass on one subdomain affects all",
                    "Shared session tokens allow cross-subdomain access",
                    "SSO misconfiguration exposes multiple services"
                ]

                # Higher risk if using custom/weak auth
                if not auth_sig['has_sso'] and len(subdomain_ids) >= 5:
                    risk_level = "High"
                    potential_vulns.append("weak_authentication")

                pattern = PatternRecognition(
                    pattern_id=str(uuid.uuid4()),
                    pattern_category="spatial",
                    pattern_type="shared_authentication",
                    pattern_name=f"Shared Authentication System Across {len(subdomain_ids)} Subdomains",
                    description=f"Multiple subdomains share the same authentication mechanism: {', '.join(auth_sig['auth_types']) if auth_sig['auth_types'] else 'Custom auth'}. "
                               f"{'Single Sign-On detected. ' if auth_sig['has_sso'] else ''}"
                               f"Compromise of authentication on one subdomain could affect all {len(subdomain_ids)} services.",
                    evidence=json.dumps({
                        "affected_subdomain_count": len(subdomain_ids),
                        "auth_signature": auth_sig,
                        "subdomain_details": {
                            str(sid): auth_indicators.get(sid, {})
                            for sid in subdomain_ids[:10]  # Limit evidence size
                        }
                    }),
                    affected_assets=json.dumps(subdomain_ids),
                    frequency=len(subdomain_ids),
                    consistency=consistency,
                    anomaly_score=0.6,
                    relationship_type="shared_auth",
                    relationship_graph=json.dumps({
                        "nodes": [{"id": sid, "type": "subdomain"} for sid in subdomain_ids],
                        "edges": [
                            {"source": subdomain_ids[i], "target": subdomain_ids[j], "type": "shared_auth"}
                            for i in range(len(subdomain_ids))
                            for j in range(i+1, len(subdomain_ids))
                        ][:50]  # Limit graph size
                    }),
                    risk_level=risk_level,
                    potential_vulnerabilities=json.dumps(potential_vulns),
                    exploitation_scenarios=json.dumps(scenarios)
                )

                db_session.add(pattern)
                patterns.append(pattern)

        await db_session.commit()
        return patterns

    async def _analyze_infrastructure_relationships(
        self,
        subdomains: List[Subdomain],
        domain_id: int,
        db_session: AsyncSession
    ) -> List[PatternRecognition]:
        """Find infrastructure commonalities (shared IPs, ASNs, hosting)"""
        patterns = []

        # Build infrastructure map
        ip_to_subdomains = defaultdict(set)
        asn_to_subdomains = defaultdict(set)
        cloud_to_subdomains = defaultdict(set)
        subdomain_infrastructure = {}

        for subdomain in subdomains:
            # Get IP associations
            result = await db_session.execute(
                select(SubdomainIP, IPAddress).join(
                    IPAddress, SubdomainIP.ip_id == IPAddress.id
                ).where(SubdomainIP.subdomain_id == subdomain.id)
            )
            associations = result.all()

            ips = []
            asns = []
            clouds = []

            for assoc, ip in associations:
                ips.append(ip.ip)
                ip_to_subdomains[ip.ip].add(subdomain.id)

                if ip.asn:
                    asns.append(ip.asn)
                    asn_to_subdomains[ip.asn].add(subdomain.id)

                if ip.cloud_provider:
                    clouds.append(ip.cloud_provider)
                    cloud_to_subdomains[ip.cloud_provider].add(subdomain.id)

            subdomain_infrastructure[subdomain.id] = {
                'ips': ips,
                'asns': list(set(asns)),
                'clouds': list(set(clouds))
            }

        # Detect shared IP patterns (significant sharing)
        for ip, subdomain_ids in ip_to_subdomains.items():
            # Only flag if 5+ subdomains share the same IP (significant clustering)
            if len(subdomain_ids) >= 5:
                consistency = len(subdomain_ids) / len(subdomains)

                # Get IP details
                result = await db_session.execute(
                    select(IPAddress).where(IPAddress.ip == ip)
                )
                ip_obj = result.scalar_one_or_none()

                risk_level = "Medium"
                if ip_obj and ip_obj.cloud_provider:
                    risk_level = "Low"  # Cloud hosting is more normal
                elif len(subdomain_ids) >= 10:
                    risk_level = "High"  # Many services on one IP is higher risk

                pattern = PatternRecognition(
                    pattern_id=str(uuid.uuid4()),
                    pattern_category="spatial",
                    pattern_type="shared_infrastructure",
                    pattern_name=f"Infrastructure Clustering: {len(subdomain_ids)} Subdomains on IP {ip}",
                    description=f"{len(subdomain_ids)} subdomains resolve to the same IP address {ip}. "
                               f"This creates a single point of failure and potential lateral movement opportunity. "
                               f"{'Cloud hosting: ' + ip_obj.cloud_provider if ip_obj and ip_obj.cloud_provider else 'Dedicated infrastructure'}",
                    evidence=json.dumps({
                        "shared_ip": ip,
                        "subdomain_count": len(subdomain_ids),
                        "asn": ip_obj.asn if ip_obj else None,
                        "asn_org": ip_obj.asn_org if ip_obj else None,
                        "cloud_provider": ip_obj.cloud_provider if ip_obj else None,
                        "country": ip_obj.country if ip_obj else None
                    }),
                    affected_assets=json.dumps(list(subdomain_ids)),
                    frequency=len(subdomain_ids),
                    consistency=consistency,
                    anomaly_score=0.5 if (ip_obj and ip_obj.cloud_provider) else 0.7,
                    relationship_type="shared_infrastructure",
                    relationship_graph=json.dumps({
                        "central_node": {"type": "ip", "value": ip},
                        "connected_subdomains": list(subdomain_ids)
                    }),
                    risk_level=risk_level,
                    potential_vulnerabilities=json.dumps([
                        "single_point_of_failure",
                        "lateral_movement",
                        "network_segmentation_issue"
                    ]),
                    exploitation_scenarios=json.dumps([
                        "Compromise one service to access others on same IP",
                        "Network-level attacks affect all services",
                        "Single infrastructure vulnerability impacts multiple services"
                    ])
                )

                db_session.add(pattern)
                patterns.append(pattern)

        # Detect ASN clustering
        for asn, subdomain_ids in asn_to_subdomains.items():
            if len(subdomain_ids) >= 8:  # Significant ASN concentration
                # Get ASN details
                result = await db_session.execute(
                    select(ASN).where(ASN.asn_number == asn)
                )
                asn_obj = result.scalar_one_or_none()

                consistency = len(subdomain_ids) / len(subdomains)

                pattern = PatternRecognition(
                    pattern_id=str(uuid.uuid4()),
                    pattern_category="spatial",
                    pattern_type="asn_clustering",
                    pattern_name=f"ASN Concentration: {len(subdomain_ids)} Subdomains in ASN{asn}",
                    description=f"{len(subdomain_ids)} subdomains are hosted within ASN{asn} "
                               f"({asn_obj.organization if asn_obj else 'Unknown'}). "
                               f"This indicates infrastructure centralization within a single autonomous system.",
                    evidence=json.dumps({
                        "asn": asn,
                        "organization": asn_obj.organization if asn_obj else None,
                        "country": asn_obj.country if asn_obj else None,
                        "subdomain_count": len(subdomain_ids)
                    }),
                    affected_assets=json.dumps(list(subdomain_ids)),
                    frequency=len(subdomain_ids),
                    consistency=consistency,
                    anomaly_score=0.4,
                    relationship_type="asn_clustering",
                    risk_level="Low",
                    potential_vulnerabilities=json.dumps(["infrastructure_reconnaissance"]),
                    exploitation_scenarios=json.dumps([
                        "ASN-wide reconnaissance reveals related infrastructure",
                        "Network-level attacks against hosting provider",
                        "BGP hijacking affects all services"
                    ])
                )

                db_session.add(pattern)
                patterns.append(pattern)

        await db_session.commit()
        return patterns

    async def _analyze_technology_clusters(
        self,
        subdomains: List[Subdomain],
        domain_id: int,
        db_session: AsyncSession
    ) -> List[PatternRecognition]:
        """Group subdomains by similar technology stacks"""
        patterns = []

        # Build technology map
        tech_to_subdomains = defaultdict(set)
        subdomain_techs = {}

        for subdomain in subdomains:
            if not subdomain.technologies:
                continue

            try:
                techs = json.loads(subdomain.technologies) if isinstance(subdomain.technologies, str) else subdomain.technologies
                if not techs:
                    continue

                # Normalize technology names
                normalized_techs = set()
                for tech in techs:
                    tech_lower = tech.lower()
                    normalized_techs.add(tech_lower)
                    tech_to_subdomains[tech_lower].add(subdomain.id)

                subdomain_techs[subdomain.id] = list(normalized_techs)
            except:
                continue

        # Find significant technology clusters
        for tech, subdomain_ids in tech_to_subdomains.items():
            # Only flag if 4+ subdomains use the same technology
            if len(subdomain_ids) >= 4:
                consistency = len(subdomain_ids) / len(subdomains)

                # Determine risk based on technology
                risk_level = "Low"
                potential_vulns = ["version_specific_vulnerabilities", "framework_misconfiguration"]

                # Higher risk for certain technologies with known issues
                high_risk_techs = ['wordpress', 'drupal', 'joomla', 'tomcat', 'struts', 'jenkins']
                if any(risk_tech in tech for risk_tech in high_risk_techs):
                    risk_level = "Medium"
                    potential_vulns.append("known_framework_vulnerabilities")

                pattern = PatternRecognition(
                    pattern_id=str(uuid.uuid4()),
                    pattern_category="spatial",
                    pattern_type="technology_cluster",
                    pattern_name=f"Technology Clustering: {len(subdomain_ids)} Services Using {tech.title()}",
                    description=f"{len(subdomain_ids)} subdomains are running {tech.title()}. "
                               f"Common technology creates shared vulnerability surface - "
                               f"a single CVE could impact all {len(subdomain_ids)} services simultaneously.",
                    evidence=json.dumps({
                        "technology": tech,
                        "subdomain_count": len(subdomain_ids),
                        "sample_subdomains": list(subdomain_ids)[:5]
                    }),
                    affected_assets=json.dumps(list(subdomain_ids)),
                    frequency=len(subdomain_ids),
                    consistency=consistency,
                    anomaly_score=0.3,
                    relationship_type="common_framework",
                    relationship_graph=json.dumps({
                        "technology": tech,
                        "subdomains": list(subdomain_ids)
                    }),
                    risk_level=risk_level,
                    potential_vulnerabilities=json.dumps(potential_vulns),
                    exploitation_scenarios=json.dumps([
                        f"Single {tech} vulnerability affects {len(subdomain_ids)} services",
                        "Mass exploitation via common framework CVE",
                        "Configuration template flaws replicated across services"
                    ])
                )

                db_session.add(pattern)
                patterns.append(pattern)

        # Detect technology stack similarities (multiple shared technologies)
        tech_stack_groups = defaultdict(list)
        for subdomain_id, techs in subdomain_techs.items():
            if len(techs) >= 2:  # At least 2 technologies
                stack_key = tuple(sorted(techs))
                tech_stack_groups[stack_key].append(subdomain_id)

        for tech_stack, subdomain_ids in tech_stack_groups.items():
            if len(subdomain_ids) >= 3:  # 3+ subdomains with identical stack
                consistency = len(subdomain_ids) / len(subdomains)

                pattern = PatternRecognition(
                    pattern_id=str(uuid.uuid4()),
                    pattern_category="spatial",
                    pattern_type="identical_tech_stack",
                    pattern_name=f"Identical Technology Stack on {len(subdomain_ids)} Subdomains",
                    description=f"{len(subdomain_ids)} subdomains use the same technology stack: {', '.join(tech_stack)}. "
                               f"This suggests template-based deployment or infrastructure-as-code, "
                               f"where configuration errors are systematically replicated.",
                    evidence=json.dumps({
                        "tech_stack": list(tech_stack),
                        "subdomain_count": len(subdomain_ids),
                        "affected_subdomains": list(subdomain_ids)
                    }),
                    affected_assets=json.dumps(list(subdomain_ids)),
                    frequency=len(subdomain_ids),
                    consistency=consistency,
                    anomaly_score=0.6,
                    relationship_type="identical_stack",
                    risk_level="Medium",
                    potential_vulnerabilities=json.dumps([
                        "systematic_misconfiguration",
                        "template_based_vulnerabilities",
                        "configuration_management_issues"
                    ]),
                    exploitation_scenarios=json.dumps([
                        "Single misconfiguration replicated across all instances",
                        "Infrastructure-as-code vulnerabilities affect entire deployment",
                        "Template-based attacks against standardized stack"
                    ])
                )

                db_session.add(pattern)
                patterns.append(pattern)

        await db_session.commit()
        return patterns

    async def _analyze_geographic_patterns(
        self,
        subdomains: List[Subdomain],
        domain_id: int,
        db_session: AsyncSession
    ) -> List[PatternRecognition]:
        """Detect geographic distribution patterns"""
        patterns = []

        # Build geographic map
        country_to_subdomains = defaultdict(set)
        region_to_subdomains = defaultdict(set)
        city_to_subdomains = defaultdict(set)

        for subdomain in subdomains:
            # Get IP geographic information
            result = await db_session.execute(
                select(SubdomainIP, IPAddress).join(
                    IPAddress, SubdomainIP.ip_id == IPAddress.id
                ).where(SubdomainIP.subdomain_id == subdomain.id)
            )
            associations = result.all()

            for assoc, ip in associations:
                if ip.country:
                    country_to_subdomains[ip.country].add(subdomain.id)
                if ip.region:
                    region_to_subdomains[ip.region].add(subdomain.id)
                if ip.city:
                    city_to_subdomains[ip.city].add(subdomain.id)

        # Detect geographic concentration
        total_with_geo = sum(len(subs) for subs in country_to_subdomains.values())

        if total_with_geo >= 5:  # Need meaningful data
            for country, subdomain_ids in country_to_subdomains.items():
                concentration_ratio = len(subdomain_ids) / total_with_geo

                # Flag if 70%+ infrastructure in single country
                if concentration_ratio >= 0.7 and len(subdomain_ids) >= 5:
                    pattern = PatternRecognition(
                        pattern_id=str(uuid.uuid4()),
                        pattern_category="spatial",
                        pattern_type="geographic_concentration",
                        pattern_name=f"Geographic Concentration: {int(concentration_ratio*100)}% in {country}",
                        description=f"{len(subdomain_ids)} subdomains ({int(concentration_ratio*100)}% of infrastructure) "
                                   f"are hosted in {country}. High geographic concentration creates "
                                   f"regional risk (jurisdiction, natural disasters, network outages).",
                        evidence=json.dumps({
                            "country": country,
                            "subdomain_count": len(subdomain_ids),
                            "concentration_percentage": int(concentration_ratio * 100),
                            "total_tracked": total_with_geo
                        }),
                        affected_assets=json.dumps(list(subdomain_ids)),
                        frequency=len(subdomain_ids),
                        consistency=concentration_ratio,
                        anomaly_score=0.5,
                        relationship_type="geographic_clustering",
                        risk_level="Low",
                        potential_vulnerabilities=json.dumps([
                            "regional_network_outage",
                            "jurisdictional_risk",
                            "single_point_of_failure"
                        ]),
                        exploitation_scenarios=json.dumps([
                            "Country-wide internet outage affects all services",
                            "Legal/regulatory actions in single jurisdiction",
                            "Regional DDoS or network attacks"
                        ])
                    )

                    db_session.add(pattern)
                    patterns.append(pattern)

            # Detect geographic diversity (positive pattern)
            if len(country_to_subdomains) >= 3 and total_with_geo >= 10:
                diversity_score = len(country_to_subdomains) / total_with_geo

                pattern = PatternRecognition(
                    pattern_id=str(uuid.uuid4()),
                    pattern_category="spatial",
                    pattern_type="geographic_distribution",
                    pattern_name=f"Geographic Distribution: Infrastructure Across {len(country_to_subdomains)} Countries",
                    description=f"Infrastructure is distributed across {len(country_to_subdomains)} countries, "
                               f"providing geographic redundancy and resilience. "
                               f"Countries: {', '.join(sorted(country_to_subdomains.keys()))}",
                    evidence=json.dumps({
                        "country_count": len(country_to_subdomains),
                        "distribution": {
                            country: len(subs)
                            for country, subs in sorted(country_to_subdomains.items(),
                                                       key=lambda x: len(x[1]),
                                                       reverse=True)
                        }
                    }),
                    affected_assets=json.dumps(list(range(1, total_with_geo + 1))),  # Placeholder
                    frequency=len(country_to_subdomains),
                    consistency=0.8,
                    anomaly_score=0.2,  # Low anomaly = good pattern
                    relationship_type="geographic_redundancy",
                    risk_level="Low",
                    potential_vulnerabilities=json.dumps(["information_disclosure"]),
                    exploitation_scenarios=json.dumps([
                        "Reconnaissance reveals global infrastructure footprint",
                        "Identifies jurisdictions with weaker security requirements"
                    ])
                )

                db_session.add(pattern)
                patterns.append(pattern)

        await db_session.commit()
        return patterns

    async def _analyze_session_relationships(
        self,
        subdomains: List[Subdomain],
        domain_id: int,
        db_session: AsyncSession
    ) -> List[PatternRecognition]:
        """Detect shared sessions and cookie relationships"""
        patterns = []

        # Track cookie domains and names across subdomains
        cookie_patterns = defaultdict(lambda: defaultdict(set))  # {cookie_name: {domain: set(subdomain_ids)}}
        session_sharing = defaultdict(set)  # {session_cookie_name: set(subdomain_ids)}

        for subdomain in subdomains:
            # Get HTTP traffic with cookies
            result = await db_session.execute(
                select(HTTPTraffic).where(
                    HTTPTraffic.subdomain_id == subdomain.id
                ).limit(50)  # Sample
            )
            traffic = result.scalars().all()

            for req in traffic:
                if not req.response_headers:
                    continue

                try:
                    headers = json.loads(req.response_headers)

                    # Parse Set-Cookie headers
                    set_cookie_headers = []
                    if isinstance(headers, dict):
                        if 'set-cookie' in headers:
                            set_cookie_headers = headers['set-cookie'] if isinstance(headers['set-cookie'], list) else [headers['set-cookie']]

                    for cookie_header in set_cookie_headers:
                        # Parse cookie
                        parts = cookie_header.split(';')
                        if not parts:
                            continue

                        cookie_name_value = parts[0].split('=', 1)
                        if len(cookie_name_value) < 2:
                            continue

                        cookie_name = cookie_name_value[0].strip()

                        # Extract cookie attributes
                        cookie_domain = None
                        is_session_cookie = False

                        for part in parts[1:]:
                            part = part.strip().lower()
                            if part.startswith('domain='):
                                cookie_domain = part.split('=', 1)[1]
                            elif 'httponly' in part or 'secure' in part:
                                is_session_cookie = True

                        # Track session cookies
                        if any(session_name in cookie_name.lower() for session_name in ['session', 'auth', 'token', 'sid', 'jsessionid']):
                            is_session_cookie = True
                            session_sharing[cookie_name].add(subdomain.id)

                        # Track cookie domains
                        if cookie_domain:
                            cookie_patterns[cookie_name][cookie_domain].add(subdomain.id)

                except Exception as e:
                    self.logger.debug("Error parsing cookies", error=str(e))
                    continue

        # Detect shared session cookies (3+ subdomains sharing same session cookie name)
        for cookie_name, subdomain_ids in session_sharing.items():
            if len(subdomain_ids) >= 3:
                consistency = len(subdomain_ids) / len(subdomains)

                # Check if cookie has domain attribute for cross-subdomain sharing
                shared_domain = None
                for domain, subs in cookie_patterns.get(cookie_name, {}).items():
                    if len(subs) >= 2:
                        shared_domain = domain
                        break

                risk_level = "High" if shared_domain and shared_domain.startswith('.') else "Medium"

                pattern = PatternRecognition(
                    pattern_id=str(uuid.uuid4()),
                    pattern_category="spatial",
                    pattern_type="shared_session",
                    pattern_name=f"Shared Session Cookie '{cookie_name}' Across {len(subdomain_ids)} Subdomains",
                    description=f"Session cookie '{cookie_name}' is used across {len(subdomain_ids)} subdomains"
                               f"{' with domain attribute: ' + shared_domain if shared_domain else ''}. "
                               f"Shared sessions enable cross-subdomain access and increase session hijacking impact.",
                    evidence=json.dumps({
                        "cookie_name": cookie_name,
                        "subdomain_count": len(subdomain_ids),
                        "cookie_domain": shared_domain,
                        "affected_subdomains": list(subdomain_ids)
                    }),
                    affected_assets=json.dumps(list(subdomain_ids)),
                    frequency=len(subdomain_ids),
                    consistency=consistency,
                    anomaly_score=0.7,
                    relationship_type="shared_session",
                    relationship_graph=json.dumps({
                        "session_cookie": cookie_name,
                        "domain_scope": shared_domain,
                        "shared_across": list(subdomain_ids)
                    }),
                    risk_level=risk_level,
                    potential_vulnerabilities=json.dumps([
                        "session_hijacking",
                        "cross_subdomain_access",
                        "session_fixation",
                        "cookie_theft"
                    ]),
                    exploitation_scenarios=json.dumps([
                        f"Steal session cookie from one subdomain, access all {len(subdomain_ids)} services",
                        "Session fixation attack affects multiple subdomains",
                        "XSS on one subdomain steals cookies for all services",
                        "Cross-subdomain session riding attacks"
                    ])
                )

                db_session.add(pattern)
                patterns.append(pattern)

        # Detect wildcard cookie domains (broader risk)
        for cookie_name, domain_dict in cookie_patterns.items():
            for cookie_domain, subdomain_ids in domain_dict.items():
                # Wildcard domain cookies (starts with .)
                if cookie_domain.startswith('.') and len(subdomain_ids) >= 4:

                    pattern = PatternRecognition(
                        pattern_id=str(uuid.uuid4()),
                        pattern_category="spatial",
                        pattern_type="wildcard_cookie_domain",
                        pattern_name=f"Wildcard Cookie Domain: '{cookie_name}' on {cookie_domain}",
                        description=f"Cookie '{cookie_name}' uses wildcard domain '{cookie_domain}', "
                                   f"making it accessible across all subdomains. "
                                   f"Observed on {len(subdomain_ids)} subdomains. "
                                   f"Wildcard cookies increase cross-subdomain attack surface.",
                        evidence=json.dumps({
                            "cookie_name": cookie_name,
                            "cookie_domain": cookie_domain,
                            "subdomain_count": len(subdomain_ids)
                        }),
                        affected_assets=json.dumps(list(subdomain_ids)),
                        frequency=len(subdomain_ids),
                        consistency=len(subdomain_ids) / len(subdomains),
                        anomaly_score=0.6,
                        relationship_type="wildcard_cookie",
                        risk_level="Medium",
                        potential_vulnerabilities=json.dumps([
                            "cross_subdomain_cookie_theft",
                            "subdomain_takeover_impact",
                            "cookie_injection"
                        ]),
                        exploitation_scenarios=json.dumps([
                            "Subdomain takeover allows cookie injection for all subdomains",
                            "XSS on any subdomain steals cookies for entire domain",
                            "Cookie tossing attacks across subdomain boundaries"
                        ])
                    )

                    db_session.add(pattern)
                    patterns.append(pattern)

        await db_session.commit()
        return patterns
