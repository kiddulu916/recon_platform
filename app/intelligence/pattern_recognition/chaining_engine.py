"""
Vulnerability Chaining Engine

Core component for combining multiple vulnerabilities into complete attack chains.
Builds attack graphs showing paths from entry point to goal and calculates
feasibility, complexity, and impact of complete attack chains.

This engine identifies critical attack paths that combine multiple weaknesses
for greater impact than individual findings.
"""

import json
import uuid
from typing import List, Dict, Optional, Any, Set, Tuple
from datetime import datetime
from collections import defaultdict, deque
import structlog
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, or_

try:
    import networkx as nx
except ImportError:
    # If networkx is not installed, provide a warning
    nx = None
    import warnings
    warnings.warn("networkx not installed. Install with: pip install networkx")

from app.models.vulnerability import (
    Vulnerability, RiskScore, VulnerabilityChain, PatternRecognition
)
from app.models.domain import Domain, Subdomain
from app.models.network import IPAddress, Port
from app.models.http_traffic import HTTPTraffic

logger = structlog.get_logger()


class AttackChainType:
    """Predefined attack chain types and their characteristics"""

    ACCOUNT_TAKEOVER = {
        "name": "Account Takeover",
        "goal": "Gain unauthorized access to user accounts",
        "severity_multiplier": 1.5,
        "required_capabilities": ["info_disclosure", "auth_weakness"],
        "typical_steps": [
            "Information disclosure reveals usernames",
            "User enumeration confirms valid accounts",
            "Weak authentication allows credential stuffing",
            "Password reset flaw enables account takeover"
        ]
    }

    DATA_EXFILTRATION = {
        "name": "Data Exfiltration",
        "goal": "Extract sensitive data from the system",
        "severity_multiplier": 1.8,
        "required_capabilities": ["auth_bypass", "data_access"],
        "typical_steps": [
            "Authentication bypass grants access",
            "IDOR vulnerability reveals other users' data",
            "Sensitive data exposure via API",
            "Mass data extraction"
        ]
    }

    REMOTE_CODE_EXECUTION = {
        "name": "Remote Code Execution",
        "goal": "Execute arbitrary code on the server",
        "severity_multiplier": 2.0,
        "required_capabilities": ["file_upload", "path_traversal", "code_exec"],
        "typical_steps": [
            "File upload allows malicious file",
            "Path traversal places file in executable location",
            "Code execution vulnerability triggers payload",
            "Remote shell established"
        ]
    }

    PRIVILEGE_ESCALATION = {
        "name": "Privilege Escalation",
        "goal": "Escalate from low-privileged to admin access",
        "severity_multiplier": 1.7,
        "required_capabilities": ["session_fixation", "csrf", "privilege_flaw"],
        "typical_steps": [
            "Session fixation creates known session",
            "CSRF vulnerability triggers admin action",
            "Privilege escalation grants admin rights",
            "Full administrative access achieved"
        ]
    }

    INFRASTRUCTURE_COMPROMISE = {
        "name": "Infrastructure Compromise",
        "goal": "Compromise infrastructure and lateral movement",
        "severity_multiplier": 1.9,
        "required_capabilities": ["subdomain_takeover", "lateral_movement"],
        "typical_steps": [
            "Subdomain takeover establishes foothold",
            "Shared authentication enables access",
            "Lateral movement to production systems",
            "Infrastructure-wide compromise"
        ]
    }


class AttackGraphBuilder:
    """
    Builds directed graphs representing attack paths

    Nodes: Vulnerabilities, patterns, assets
    Edges: Relationships (enables, requires, provides_access_to)
    """

    def __init__(self):
        self.logger = logger.bind(component="attack_graph_builder")
        if nx is None:
            raise ImportError("networkx is required. Install with: pip install networkx")

    def build_graph(
        self,
        vulnerabilities: List[Vulnerability],
        patterns: List[PatternRecognition],
        risk_scores: Dict[int, RiskScore]
    ) -> nx.DiGraph:
        """
        Build attack graph from vulnerabilities and patterns

        Args:
            vulnerabilities: List of discovered vulnerabilities
            patterns: List of recognized patterns
            risk_scores: Map of vulnerability_id -> RiskScore

        Returns:
            Directed graph representing attack paths
        """
        self.logger.info("Building attack graph", vuln_count=len(vulnerabilities))

        G = nx.DiGraph()

        # Add vulnerability nodes
        for vuln in vulnerabilities:
            G.add_node(
                f"vuln_{vuln.id}",
                type="vulnerability",
                data=vuln,
                vuln_type=vuln.type,
                severity=vuln.severity,
                risk_score=risk_scores.get(vuln.id),
                label=f"{vuln.type}: {vuln.title}"
            )

        # Add pattern nodes
        for pattern in patterns:
            G.add_node(
                f"pattern_{pattern.id}",
                type="pattern",
                data=pattern,
                pattern_type=pattern.pattern_type,
                risk_level=pattern.risk_level,
                label=f"Pattern: {pattern.pattern_name}"
            )

        # Add edges based on vulnerability relationships
        self._add_vulnerability_edges(G, vulnerabilities)

        # Add edges based on patterns
        self._add_pattern_edges(G, vulnerabilities, patterns)

        # Add edges based on common infrastructure
        self._add_infrastructure_edges(G, vulnerabilities)

        self.logger.info(
            "Attack graph built",
            nodes=G.number_of_nodes(),
            edges=G.number_of_edges()
        )

        return G

    def _add_vulnerability_edges(
        self,
        G: nx.DiGraph,
        vulnerabilities: List[Vulnerability]
    ):
        """Add edges based on how vulnerabilities can chain"""

        # Group vulnerabilities by location
        by_subdomain = defaultdict(list)
        by_port = defaultdict(list)
        by_ip = defaultdict(list)

        for vuln in vulnerabilities:
            if vuln.subdomain_id:
                by_subdomain[vuln.subdomain_id].append(vuln)
            if vuln.port_id:
                by_port[vuln.port_id].append(vuln)
            if vuln.ip_id:
                by_ip[vuln.ip_id].append(vuln)

        # Connect vulnerabilities on same asset
        for location_group in [by_subdomain, by_port, by_ip]:
            for vulns in location_group.values():
                self._connect_related_vulnerabilities(G, vulns)

    def _connect_related_vulnerabilities(
        self,
        G: nx.DiGraph,
        vulnerabilities: List[Vulnerability]
    ):
        """Connect vulnerabilities that can be chained together"""

        # Define vulnerability chaining rules
        chaining_rules = {
            # Info disclosure enables other attacks
            "info_disclosure": ["user_enumeration", "sqli", "xss", "csrf"],
            "sensitive_data_exposure": ["auth_bypass", "privilege_escalation"],

            # Auth weaknesses enable data access
            "auth_bypass": ["idor", "sqli", "data_access", "privilege_escalation"],
            "weak_auth": ["account_takeover", "session_hijacking"],
            "user_enumeration": ["credential_stuffing", "password_reset_flaw"],

            # File operations enable code execution
            "file_upload": ["path_traversal", "lfi", "rce"],
            "path_traversal": ["lfi", "rce", "code_execution"],
            "lfi": ["rce", "code_execution"],

            # Session issues enable privilege escalation
            "session_fixation": ["csrf", "privilege_escalation"],
            "csrf": ["privilege_escalation", "admin_action"],

            # Infrastructure issues enable lateral movement
            "subdomain_takeover": ["lateral_movement", "phishing", "xss"],
            "shared_infrastructure": ["lateral_movement", "privilege_escalation"],

            # Injection attacks enable data access
            "sqli": ["data_exfiltration", "auth_bypass", "rce"],
            "xxe": ["ssrf", "file_disclosure", "rce"],
            "ssrf": ["internal_network_access", "cloud_metadata"],

            # XSS enables session hijacking
            "xss": ["session_hijacking", "csrf", "phishing"],

            # IDOR enables data access
            "idor": ["data_exfiltration", "privilege_escalation"],
        }

        for i, vuln1 in enumerate(vulnerabilities):
            vuln1_type = vuln1.type.lower().replace(" ", "_")

            # Check if this vulnerability type can enable others
            enabled_types = chaining_rules.get(vuln1_type, [])

            for vuln2 in vulnerabilities[i+1:]:
                vuln2_type = vuln2.type.lower().replace(" ", "_")

                # Check if vuln1 enables vuln2
                if vuln2_type in enabled_types:
                    G.add_edge(
                        f"vuln_{vuln1.id}",
                        f"vuln_{vuln2.id}",
                        relationship="enables",
                        label=f"enables {vuln2_type}"
                    )

                # Check if vuln2 enables vuln1
                if vuln1_type in chaining_rules.get(vuln2_type, []):
                    G.add_edge(
                        f"vuln_{vuln2.id}",
                        f"vuln_{vuln1.id}",
                        relationship="enables",
                        label=f"enables {vuln1_type}"
                    )

    def _add_pattern_edges(
        self,
        G: nx.DiGraph,
        vulnerabilities: List[Vulnerability],
        patterns: List[PatternRecognition]
    ):
        """Add edges connecting patterns to vulnerabilities they affect"""

        for pattern in patterns:
            # Parse affected assets
            try:
                affected_assets = json.loads(pattern.affected_assets or "[]")
            except:
                affected_assets = []

            # Connect pattern to vulnerabilities on affected assets
            for vuln in vulnerabilities:
                # Check if vulnerability is on affected asset
                if self._is_vuln_affected_by_pattern(vuln, affected_assets):
                    G.add_edge(
                        f"pattern_{pattern.id}",
                        f"vuln_{vuln.id}",
                        relationship="affects",
                        label=f"Pattern affects vulnerability"
                    )

    def _add_infrastructure_edges(
        self,
        G: nx.DiGraph,
        vulnerabilities: List[Vulnerability]
    ):
        """Add edges for vulnerabilities on shared infrastructure"""

        # Group by domain (assuming they're related)
        by_domain = defaultdict(list)
        for vuln in vulnerabilities:
            if vuln.domain_id:
                by_domain[vuln.domain_id].append(vuln)

        # Connect vulnerabilities on same domain with infrastructure relationship
        for vulns in by_domain.values():
            if len(vulns) > 1:
                for i, vuln1 in enumerate(vulns):
                    for vuln2 in vulns[i+1:]:
                        # Add bidirectional edges for shared infrastructure
                        G.add_edge(
                            f"vuln_{vuln1.id}",
                            f"vuln_{vuln2.id}",
                            relationship="shared_infrastructure",
                            label="Same domain"
                        )
                        G.add_edge(
                            f"vuln_{vuln2.id}",
                            f"vuln_{vuln1.id}",
                            relationship="shared_infrastructure",
                            label="Same domain"
                        )

    def _is_vuln_affected_by_pattern(
        self,
        vuln: Vulnerability,
        affected_assets: List[Dict]
    ) -> bool:
        """Check if vulnerability is on an asset affected by pattern"""

        for asset in affected_assets:
            asset_type = asset.get("type")
            asset_id = asset.get("id")

            if asset_type == "subdomain" and vuln.subdomain_id == asset_id:
                return True
            if asset_type == "ip" and vuln.ip_id == asset_id:
                return True
            if asset_type == "port" and vuln.port_id == asset_id:
                return True

        return False


class ChainAnalyzer:
    """
    Analyzes attack graphs to find and score complete attack chains
    """

    def __init__(self):
        self.logger = logger.bind(component="chain_analyzer")

    def find_attack_chains(
        self,
        graph: nx.DiGraph,
        max_chain_length: int = 5,
        min_chain_length: int = 2
    ) -> List[Dict[str, Any]]:
        """
        Find complete attack chains in the graph

        Args:
            graph: Attack graph
            max_chain_length: Maximum chain length to consider
            min_chain_length: Minimum chain length to consider

        Returns:
            List of attack chains with metadata
        """
        self.logger.info("Finding attack chains")

        chains = []

        # Find all vulnerability nodes
        vuln_nodes = [n for n, d in graph.nodes(data=True) if d.get("type") == "vulnerability"]

        # Find chains between all pairs of vulnerabilities
        for source in vuln_nodes:
            for target in vuln_nodes:
                if source == target:
                    continue

                # Find all simple paths (no cycles)
                try:
                    paths = list(nx.all_simple_paths(
                        graph,
                        source,
                        target,
                        cutoff=max_chain_length
                    ))

                    for path in paths:
                        if len(path) >= min_chain_length:
                            chain = self._analyze_chain_path(graph, path)
                            if chain:
                                chains.append(chain)

                except nx.NetworkXNoPath:
                    continue
                except Exception as e:
                    self.logger.debug("Path finding error", error=str(e))

        # Deduplicate and sort by risk score
        chains = self._deduplicate_chains(chains)
        chains.sort(key=lambda c: c["risk_score"], reverse=True)

        self.logger.info("Attack chains found", count=len(chains))

        return chains

    def _analyze_chain_path(
        self,
        graph: nx.DiGraph,
        path: List[str]
    ) -> Optional[Dict[str, Any]]:
        """Analyze a path to create chain metadata"""

        # Extract vulnerability nodes from path
        vuln_nodes = [n for n in path if n.startswith("vuln_")]

        if len(vuln_nodes) < 2:
            return None

        # Get vulnerability data
        vulnerabilities = []
        for node in vuln_nodes:
            node_data = graph.nodes[node]
            vuln = node_data.get("data")
            if vuln:
                vulnerabilities.append(vuln)

        # Classify chain type
        chain_type = self._classify_chain_type(vulnerabilities)

        # Calculate feasibility
        feasibility = self._calculate_chain_feasibility(graph, vulnerabilities)

        # Calculate impact
        impact = self._calculate_chain_impact(vulnerabilities, chain_type)

        # Calculate risk score
        risk_score = feasibility * impact * 100

        # Determine severity
        severity = self._categorize_chain_severity(risk_score)

        # Generate exploitation scenario
        exploitation_scenario = self._generate_exploitation_scenario(
            vulnerabilities,
            chain_type,
            path,
            graph
        )

        return {
            "chain_id": str(uuid.uuid4()),
            "path": path,
            "vulnerability_ids": [v.id for v in vulnerabilities],
            "chain_type": chain_type,
            "chain_length": len(vulnerabilities),
            "feasibility": feasibility,
            "impact": impact,
            "risk_score": risk_score,
            "severity": severity,
            "exploitation_scenario": exploitation_scenario,
            "vulnerabilities": vulnerabilities
        }

    def _classify_chain_type(
        self,
        vulnerabilities: List[Vulnerability]
    ) -> str:
        """Classify the type of attack chain"""

        vuln_types = set(v.type.lower().replace(" ", "_") for v in vulnerabilities)

        # Check for RCE chain
        rce_indicators = {"file_upload", "path_traversal", "lfi", "rce", "code_execution"}
        if len(vuln_types & rce_indicators) >= 2:
            return "remote_code_execution"

        # Check for data exfiltration chain
        data_indicators = {"auth_bypass", "idor", "sqli", "data_access", "sensitive_data_exposure"}
        if len(vuln_types & data_indicators) >= 2:
            return "data_exfiltration"

        # Check for account takeover chain
        account_indicators = {"info_disclosure", "user_enumeration", "weak_auth", "password_reset_flaw"}
        if len(vuln_types & account_indicators) >= 2:
            return "account_takeover"

        # Check for privilege escalation chain
        priv_indicators = {"session_fixation", "csrf", "privilege_escalation", "auth_bypass"}
        if len(vuln_types & priv_indicators) >= 2:
            return "privilege_escalation"

        # Check for infrastructure compromise chain
        infra_indicators = {"subdomain_takeover", "lateral_movement", "shared_infrastructure"}
        if len(vuln_types & infra_indicators) >= 1:
            return "infrastructure_compromise"

        return "generic_attack_chain"

    def _calculate_chain_feasibility(
        self,
        graph: nx.DiGraph,
        vulnerabilities: List[Vulnerability]
    ) -> float:
        """
        Calculate feasibility of successfully exploiting the chain

        Factors:
        - Complexity of each step
        - Number of prerequisites
        - Authentication requirements
        - Skill level required

        Returns: 0.0 to 1.0 (1.0 = very feasible)
        """

        # Base feasibility
        feasibility = 1.0

        # Complexity penalty (more steps = harder)
        complexity_penalty = 1.0 / (1.0 + len(vulnerabilities) * 0.2)
        feasibility *= complexity_penalty

        # Check each vulnerability's complexity
        for vuln in vulnerabilities:
            complexity = vuln.exploitation_complexity or "Medium"

            if complexity == "High":
                feasibility *= 0.7
            elif complexity == "Medium":
                feasibility *= 0.85
            # Low complexity doesn't reduce feasibility

        # Authentication requirement penalty
        auth_required_count = sum(
            1 for v in vulnerabilities
            if v.exploitable and "auth" in (v.description or "").lower()
        )
        if auth_required_count > 0:
            feasibility *= (0.8 ** auth_required_count)

        # Ensure feasibility stays in valid range
        return max(0.01, min(1.0, feasibility))

    def _calculate_chain_impact(
        self,
        vulnerabilities: List[Vulnerability],
        chain_type: str
    ) -> float:
        """
        Calculate impact of successfully exploiting the chain

        Factors:
        - CIA triad impact (Confidentiality, Integrity, Availability)
        - Data sensitivity
        - Privilege level achieved
        - Business impact

        Returns: 0.0 to 1.0 (1.0 = critical impact)
        """

        # Base impact from chain type
        type_multipliers = {
            "remote_code_execution": 1.0,
            "data_exfiltration": 0.9,
            "infrastructure_compromise": 0.95,
            "privilege_escalation": 0.85,
            "account_takeover": 0.75,
            "generic_attack_chain": 0.6
        }
        base_impact = type_multipliers.get(chain_type, 0.6)

        # Aggregate severity of vulnerabilities
        severity_scores = {
            "Critical": 1.0,
            "High": 0.75,
            "Medium": 0.5,
            "Low": 0.25
        }

        avg_severity = sum(
            severity_scores.get(v.severity, 0.5)
            for v in vulnerabilities
        ) / len(vulnerabilities)

        # Combined impact
        impact = (base_impact * 0.6) + (avg_severity * 0.4)

        # Boost for chains with critical vulnerabilities
        if any(v.severity == "Critical" for v in vulnerabilities):
            impact *= 1.2

        # Ensure impact stays in valid range
        return max(0.1, min(1.0, impact))

    def _categorize_chain_severity(self, risk_score: float) -> str:
        """Categorize chain severity based on risk score"""

        if risk_score >= 85:
            return "Critical"
        elif risk_score >= 70:
            return "High"
        elif risk_score >= 40:
            return "Medium"
        else:
            return "Low"

    def _generate_exploitation_scenario(
        self,
        vulnerabilities: List[Vulnerability],
        chain_type: str,
        path: List[str],
        graph: nx.DiGraph
    ) -> Dict[str, Any]:
        """Generate detailed exploitation scenario with step-by-step instructions"""

        steps = []

        for i, vuln in enumerate(vulnerabilities):
            step_number = i + 1

            # Generate step description
            step_name = f"Step {step_number}: Exploit {vuln.type}"

            # Generate action based on vulnerability type
            action = self._generate_exploitation_action(vuln)

            # Generate expected result
            expected_result = self._generate_expected_result(vuln, i, len(vulnerabilities))

            # Determine what data/access this step provides
            provides = self._determine_step_provides(vuln)

            # Determine what this step requires from previous steps
            requires = self._determine_step_requires(vuln, i, vulnerabilities)

            steps.append({
                "step_number": step_number,
                "vulnerability_id": vuln.id,
                "vulnerability_type": vuln.type,
                "step_name": step_name,
                "description": vuln.title,
                "action": action,
                "expected_result": expected_result,
                "provides": provides,
                "requires": requires,
                "complexity": vuln.exploitation_complexity or "Medium",
                "evidence": vuln.evidence
            })

        # Generate overall scenario description
        scenario_description = self._generate_scenario_description(
            chain_type,
            vulnerabilities
        )

        # Estimate time to exploit
        time_estimate = self._estimate_exploitation_time(vulnerabilities)

        # Determine required skills
        required_skills = self._determine_required_skills(vulnerabilities)

        return {
            "description": scenario_description,
            "steps": steps,
            "total_steps": len(steps),
            "estimated_time": time_estimate,
            "required_skills": required_skills,
            "prerequisites": self._list_prerequisites(vulnerabilities),
            "detection_difficulty": self._estimate_detection_difficulty(vulnerabilities),
            "mitigation_priority": self._calculate_mitigation_priority(vulnerabilities)
        }

    def _generate_exploitation_action(self, vuln: Vulnerability) -> str:
        """Generate specific action for exploiting vulnerability"""

        type_actions = {
            "sqli": f"Execute SQL injection on {vuln.affected_component}: {vuln.evidence[:100]}",
            "xss": f"Inject malicious script into {vuln.affected_component}: {vuln.evidence[:100]}",
            "xxe": f"Send malicious XML to {vuln.affected_component} to access files",
            "ssrf": f"Manipulate {vuln.affected_component} to make internal requests",
            "lfi": f"Exploit file inclusion in {vuln.affected_component} to read local files",
            "rce": f"Execute arbitrary code via {vuln.affected_component}",
            "file_upload": f"Upload malicious file to {vuln.affected_component}",
            "path_traversal": f"Use path traversal on {vuln.affected_component} to access restricted files",
            "idor": f"Manipulate object reference in {vuln.affected_component} to access unauthorized data",
            "auth_bypass": f"Bypass authentication on {vuln.affected_component}",
            "csrf": f"Craft CSRF payload targeting {vuln.affected_component}",
            "info_disclosure": f"Retrieve sensitive information from {vuln.affected_component}",
        }

        vuln_type = vuln.type.lower().replace(" ", "_")
        action = type_actions.get(
            vuln_type,
            f"Exploit {vuln.type} vulnerability in {vuln.affected_component or 'target'}"
        )

        if vuln.reproduction_steps:
            action += f"\n\nReproduction: {vuln.reproduction_steps[:200]}"

        return action

    def _generate_expected_result(
        self,
        vuln: Vulnerability,
        step_index: int,
        total_steps: int
    ) -> str:
        """Generate expected result for exploitation step"""

        if step_index == total_steps - 1:
            # Final step
            return f"Complete attack goal. Full exploitation of {vuln.type} grants final objective access."

        type_results = {
            "sqli": "Extract database credentials, enumerate tables, or bypass authentication",
            "xss": "Execute JavaScript in victim's browser, steal session tokens",
            "xxe": "Read local files, SSRF to internal network, or DoS",
            "ssrf": "Access internal network, read cloud metadata, port scan internal hosts",
            "lfi": "Read sensitive configuration files, source code, or credentials",
            "rce": "Execute arbitrary system commands, establish reverse shell",
            "file_upload": "Uploaded file can be accessed and potentially executed",
            "path_traversal": "Access files outside intended directory, read sensitive data",
            "idor": "Access other users' data, manipulate unauthorized resources",
            "auth_bypass": "Gain authenticated access without valid credentials",
            "csrf": "Perform state-changing actions as authenticated user",
            "info_disclosure": "Obtain sensitive information useful for subsequent attacks",
        }

        vuln_type = vuln.type.lower().replace(" ", "_")
        return type_results.get(
            vuln_type,
            f"Successful exploitation provides access for next step"
        )

    def _determine_step_provides(self, vuln: Vulnerability) -> List[str]:
        """Determine what resources/access this step provides"""

        provides_map = {
            "info_disclosure": ["usernames", "configuration", "internal_paths"],
            "sqli": ["database_access", "credentials", "data"],
            "auth_bypass": ["authenticated_session", "user_access"],
            "xss": ["session_tokens", "user_context"],
            "file_upload": ["file_placement", "code_execution_prep"],
            "path_traversal": ["file_access", "directory_listing"],
            "lfi": ["file_read", "code_disclosure"],
            "rce": ["code_execution", "shell_access"],
            "idor": ["data_access", "object_manipulation"],
            "csrf": ["state_change", "action_execution"],
            "xxe": ["file_read", "ssrf_capability"],
            "ssrf": ["internal_access", "metadata_access"],
        }

        vuln_type = vuln.type.lower().replace(" ", "_")
        return provides_map.get(vuln_type, ["attack_surface"])

    def _determine_step_requires(
        self,
        vuln: Vulnerability,
        step_index: int,
        all_vulnerabilities: List[Vulnerability]
    ) -> List[str]:
        """Determine what this step requires from previous steps"""

        if step_index == 0:
            return ["external_network_access"]

        # Map what previous vulnerabilities provided
        previous_vulns = all_vulnerabilities[:step_index]
        available_resources = set()

        for prev in previous_vulns:
            available_resources.update(self._determine_step_provides(prev))

        # Determine what this vulnerability needs
        requires_map = {
            "sqli": ["endpoint_access"],
            "auth_bypass": ["endpoint_access"],
            "xss": ["endpoint_access"],
            "idor": ["authenticated_session", "valid_object_reference"],
            "csrf": ["authenticated_session"],
            "lfi": ["endpoint_access", "file_parameter"],
            "rce": ["code_execution_prep", "file_placement"],
            "path_traversal": ["endpoint_access", "file_parameter"],
        }

        vuln_type = vuln.type.lower().replace(" ", "_")
        return requires_map.get(vuln_type, ["prior_step_completion"])

    def _generate_scenario_description(
        self,
        chain_type: str,
        vulnerabilities: List[Vulnerability]
    ) -> str:
        """Generate overall description of the attack scenario"""

        type_descriptions = {
            "remote_code_execution": (
                f"This attack chain combines {len(vulnerabilities)} vulnerabilities to achieve "
                "remote code execution on the target system. The attacker can upload and execute "
                "arbitrary code, potentially gaining full system access."
            ),
            "data_exfiltration": (
                f"This attack chain uses {len(vulnerabilities)} linked vulnerabilities to "
                "bypass authentication and access sensitive data. The attacker can extract "
                "confidential information including user data, credentials, or business data."
            ),
            "account_takeover": (
                f"This attack chain exploits {len(vulnerabilities)} weaknesses to take over "
                "user accounts. The attacker can enumerate users, exploit authentication flaws, "
                "and gain unauthorized access to user accounts."
            ),
            "privilege_escalation": (
                f"This attack chain chains {len(vulnerabilities)} vulnerabilities to escalate "
                "privileges from low-privileged user to administrator. The attacker can perform "
                "administrative actions and access restricted functionality."
            ),
            "infrastructure_compromise": (
                f"This attack chain leverages {len(vulnerabilities)} infrastructure weaknesses "
                "to compromise the broader system. The attacker can move laterally, access "
                "additional systems, and expand their foothold."
            ),
        }

        description = type_descriptions.get(
            chain_type,
            f"This attack chain combines {len(vulnerabilities)} vulnerabilities for significant impact."
        )

        # Add vulnerability types
        vuln_types = ", ".join(set(v.type for v in vulnerabilities))
        description += f"\n\nVulnerabilities involved: {vuln_types}"

        return description

    def _estimate_exploitation_time(
        self,
        vulnerabilities: List[Vulnerability]
    ) -> str:
        """Estimate time required to exploit the chain"""

        # Base time per vulnerability
        time_per_vuln = {
            "Low": 15,      # 15 minutes
            "Medium": 60,   # 1 hour
            "High": 240,    # 4 hours
        }

        total_minutes = sum(
            time_per_vuln.get(v.exploitation_complexity or "Medium", 60)
            for v in vulnerabilities
        )

        if total_minutes < 60:
            return f"{total_minutes} minutes"
        elif total_minutes < 1440:  # Less than a day
            hours = total_minutes / 60
            return f"{hours:.1f} hours"
        else:
            days = total_minutes / 1440
            return f"{days:.1f} days"

    def _determine_required_skills(
        self,
        vulnerabilities: List[Vulnerability]
    ) -> str:
        """Determine skill level required to exploit chain"""

        # Check complexity
        complexities = [v.exploitation_complexity for v in vulnerabilities]

        if all(c == "Low" for c in complexities):
            return "Beginner"
        elif "High" in complexities:
            return "Advanced"
        else:
            return "Intermediate"

    def _list_prerequisites(
        self,
        vulnerabilities: List[Vulnerability]
    ) -> List[str]:
        """List prerequisites for exploiting the chain"""

        prerequisites = ["Network access to target"]

        # Check if any require authentication
        if any("auth" in (v.description or "").lower() for v in vulnerabilities):
            prerequisites.append("Valid user credentials")

        # Check for specific tool requirements
        vuln_types = set(v.type.lower() for v in vulnerabilities)

        if "sqli" in vuln_types:
            prerequisites.append("SQL injection tools (sqlmap, etc.)")

        if "xss" in vuln_types:
            prerequisites.append("XSS payload toolkit")

        if "file_upload" in vuln_types:
            prerequisites.append("Malicious file payloads")

        return prerequisites

    def _estimate_detection_difficulty(
        self,
        vulnerabilities: List[Vulnerability]
    ) -> str:
        """Estimate how difficult it is to detect this attack"""

        # More steps = easier to detect
        if len(vulnerabilities) > 4:
            return "Easy"
        elif len(vulnerabilities) > 2:
            return "Medium"
        else:
            return "Hard"

    def _calculate_mitigation_priority(
        self,
        vulnerabilities: List[Vulnerability]
    ) -> int:
        """Calculate priority for mitigating this chain (1-10)"""

        # Count critical and high severity
        critical_count = sum(1 for v in vulnerabilities if v.severity == "Critical")
        high_count = sum(1 for v in vulnerabilities if v.severity == "High")

        # Priority based on severity distribution
        priority = 5  # Base priority
        priority += critical_count * 2
        priority += high_count * 1

        # Cap at 10
        return min(10, priority)

    def _deduplicate_chains(
        self,
        chains: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Remove duplicate or very similar chains"""

        seen_vuln_sets = set()
        unique_chains = []

        for chain in chains:
            # Create signature from vulnerability IDs
            vuln_ids = tuple(sorted(chain["vulnerability_ids"]))

            if vuln_ids not in seen_vuln_sets:
                seen_vuln_sets.add(vuln_ids)
                unique_chains.append(chain)

        return unique_chains


class VulnerabilityChainingEngine:
    """
    Main vulnerability chaining engine

    Orchestrates:
    - Attack graph building
    - Chain discovery
    - Feasibility and impact analysis
    - Chain prioritization
    - Database persistence
    """

    def __init__(self):
        self.logger = logger.bind(component="chaining_engine")

        if nx is None:
            raise ImportError(
                "networkx is required for vulnerability chaining. "
                "Install with: pip install networkx"
            )

        self.graph_builder = AttackGraphBuilder()
        self.chain_analyzer = ChainAnalyzer()

    async def analyze_domain(
        self,
        domain_id: int,
        db_session: AsyncSession,
        max_chain_length: int = 5
    ) -> Dict[str, Any]:
        """
        Analyze a domain for vulnerability chains

        This is the main entry point for the chaining engine.

        Args:
            domain_id: Domain to analyze
            db_session: Database session
            max_chain_length: Maximum chain length to consider

        Returns:
            Analysis results with discovered chains
        """
        self.logger.info("Analyzing domain for vulnerability chains", domain_id=domain_id)

        try:
            # Load vulnerabilities
            vulnerabilities = await self._load_vulnerabilities(domain_id, db_session)

            if len(vulnerabilities) < 2:
                self.logger.info("Not enough vulnerabilities to chain", count=len(vulnerabilities))
                return {
                    "domain_id": domain_id,
                    "vulnerabilities_analyzed": len(vulnerabilities),
                    "chains_found": 0,
                    "chains": []
                }

            # Load patterns
            patterns = await self._load_patterns(domain_id, db_session)

            # Load risk scores
            risk_scores = await self._load_risk_scores(vulnerabilities, db_session)

            # Build attack graph
            graph = self.graph_builder.build_graph(vulnerabilities, patterns, risk_scores)

            # Find attack chains
            chains = self.chain_analyzer.find_attack_chains(
                graph,
                max_chain_length=max_chain_length
            )

            # Prioritize chains
            prioritized_chains = self._prioritize_chains(chains)

            # Save chains to database
            saved_chains = await self._save_chains(domain_id, prioritized_chains, db_session)

            self.logger.info(
                "Domain analysis complete",
                domain_id=domain_id,
                chains_found=len(saved_chains)
            )

            return {
                "domain_id": domain_id,
                "vulnerabilities_analyzed": len(vulnerabilities),
                "patterns_analyzed": len(patterns),
                "graph_nodes": graph.number_of_nodes(),
                "graph_edges": graph.number_of_edges(),
                "chains_found": len(saved_chains),
                "chains": [self._chain_to_dict(c) for c in saved_chains],
                "critical_chains": len([c for c in saved_chains if c.severity == "Critical"]),
                "high_chains": len([c for c in saved_chains if c.severity == "High"]),
            }

        except Exception as e:
            self.logger.error("Domain analysis failed", domain_id=domain_id, error=str(e))
            raise

    async def _load_vulnerabilities(
        self,
        domain_id: int,
        db_session: AsyncSession
    ) -> List[Vulnerability]:
        """Load all vulnerabilities for domain"""

        result = await db_session.execute(
            select(Vulnerability).where(
                and_(
                    Vulnerability.domain_id == domain_id,
                    Vulnerability.status != "false_positive"
                )
            )
        )

        return result.scalars().all()

    async def _load_patterns(
        self,
        domain_id: int,
        db_session: AsyncSession
    ) -> List[PatternRecognition]:
        """Load all patterns for domain"""

        result = await db_session.execute(
            select(PatternRecognition).where(
                and_(
                    PatternRecognition.domain_id == domain_id,
                    PatternRecognition.status == "active",
                    PatternRecognition.false_positive == False
                )
            )
        )

        return result.scalars().all()

    async def _load_risk_scores(
        self,
        vulnerabilities: List[Vulnerability],
        db_session: AsyncSession
    ) -> Dict[int, RiskScore]:
        """Load risk scores for vulnerabilities"""

        vuln_ids = [v.id for v in vulnerabilities]

        result = await db_session.execute(
            select(RiskScore).where(
                RiskScore.vulnerability_id.in_(vuln_ids)
            )
        )

        risk_scores = result.scalars().all()

        return {rs.vulnerability_id: rs for rs in risk_scores}

    def _prioritize_chains(
        self,
        chains: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Prioritize chains based on risk score and other factors

        Priority calculation:
        - Risk score (primary)
        - Chain length (shorter = higher priority)
        - Feasibility (more feasible = higher priority)
        - Impact (higher impact = higher priority)
        """

        for chain in chains:
            # Base priority from risk score (0-10 scale)
            priority = min(10, int(chain["risk_score"] / 10))

            # Adjust for chain length (prefer shorter chains)
            if chain["chain_length"] <= 2:
                priority = min(10, priority + 1)
            elif chain["chain_length"] >= 5:
                priority = max(1, priority - 1)

            # Adjust for feasibility
            if chain["feasibility"] > 0.8:
                priority = min(10, priority + 1)

            chain["priority"] = priority

        # Sort by priority (descending), then risk score (descending)
        chains.sort(key=lambda c: (c["priority"], c["risk_score"]), reverse=True)

        return chains

    async def _save_chains(
        self,
        domain_id: int,
        chains: List[Dict[str, Any]],
        db_session: AsyncSession
    ) -> List[VulnerabilityChain]:
        """Save vulnerability chains to database"""

        saved_chains = []

        for chain_data in chains:
            try:
                # Create VulnerabilityChain record
                chain = VulnerabilityChain(
                    domain_id=domain_id,
                    chain_name=f"{chain_data['chain_type'].replace('_', ' ').title()} Chain",
                    description=chain_data["exploitation_scenario"]["description"],
                    attack_goal=chain_data["chain_type"],
                    vulnerability_ids=json.dumps(chain_data["vulnerability_ids"]),
                    pattern_ids=json.dumps([]),  # Can be extended to include pattern IDs
                    steps=json.dumps(chain_data["exploitation_scenario"]["steps"]),
                    chain_length=chain_data["chain_length"],
                    complexity=self._map_feasibility_to_complexity(chain_data["feasibility"]),
                    complexity_score=1.0 - chain_data["feasibility"],
                    feasibility=chain_data["feasibility"],
                    prerequisites=json.dumps(chain_data["exploitation_scenario"]["prerequisites"]),
                    required_skills=chain_data["exploitation_scenario"]["required_skills"],
                    estimated_time=chain_data["exploitation_scenario"]["estimated_time"],
                    impact_score=chain_data["impact"],
                    impact_breakdown=json.dumps({
                        "confidentiality": chain_data["impact"],
                        "integrity": chain_data["impact"] * 0.8,
                        "availability": chain_data["impact"] * 0.6
                    }),
                    affected_assets=json.dumps([
                        {"vulnerability_id": vid, "type": "vulnerability"}
                        for vid in chain_data["vulnerability_ids"]
                    ]),
                    risk_score=chain_data["risk_score"],
                    severity=chain_data["severity"],
                    priority=chain_data["priority"],
                    detection_difficulty=chain_data["exploitation_scenario"]["detection_difficulty"],
                    prevention_recommendations=json.dumps([
                        f"Remediate vulnerability: {v.title}"
                        for v in chain_data["vulnerabilities"]
                    ]),
                    remediation_steps=json.dumps([
                        {"step": i+1, "action": f"Fix {v.type}: {v.title}"}
                        for i, v in enumerate(chain_data["vulnerabilities"])
                    ]),
                    discovered_at=datetime.utcnow(),
                    verified=False
                )

                db_session.add(chain)
                saved_chains.append(chain)

            except Exception as e:
                self.logger.error("Failed to save chain", error=str(e))

        await db_session.commit()

        self.logger.info("Chains saved", count=len(saved_chains))

        return saved_chains

    def _map_feasibility_to_complexity(self, feasibility: float) -> str:
        """Map feasibility score to complexity category"""

        if feasibility > 0.7:
            return "low"
        elif feasibility > 0.4:
            return "medium"
        else:
            return "high"

    def _chain_to_dict(self, chain: VulnerabilityChain) -> Dict[str, Any]:
        """Convert VulnerabilityChain model to dictionary"""

        return {
            "id": chain.id,
            "chain_name": chain.chain_name,
            "description": chain.description,
            "attack_goal": chain.attack_goal,
            "severity": chain.severity,
            "risk_score": chain.risk_score,
            "priority": chain.priority,
            "chain_length": chain.chain_length,
            "complexity": chain.complexity,
            "feasibility": chain.feasibility,
            "impact_score": chain.impact_score,
            "required_skills": chain.required_skills,
            "estimated_time": chain.estimated_time,
            "discovered_at": chain.discovered_at.isoformat() if chain.discovered_at else None,
        }
