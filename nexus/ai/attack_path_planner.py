"""
Nexus Attack Path Planning System

AI-powered attack path planning engine that analyzes the target environment,
identifies potential attack paths, and creates comprehensive attack strategies
to achieve campaign objectives with optimal success probability.
"""

import json
import time
import networkx as nx
from typing import Dict, List, Any, Optional, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum
import logging
from collections import defaultdict
import heapq

from .vulnerability_correlator import Vulnerability, VulnerabilityCluster, SeverityLevel
from .exploit_recommender import ExploitRecommendation, ExploitComplexity

logger = logging.getLogger(__name__)


class AttackPhase(Enum):
    """Attack phases in the kill chain"""
    RECONNAISSANCE = "reconnaissance"
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"
    CREDENTIAL_ACCESS = "credential_access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral_movement"
    COLLECTION = "collection"
    COMMAND_AND_CONTROL = "command_and_control"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"


class AttackObjective(Enum):
    """Campaign objectives"""
    DOMAIN_ADMIN = "domain_admin"
    DATA_EXFILTRATION = "data_exfiltration"
    SYSTEM_COMPROMISE = "system_compromise"
    NETWORK_MAPPING = "network_mapping"
    CREDENTIAL_HARVESTING = "credential_harvesting"
    PERSISTENCE_ESTABLISHMENT = "persistence_establishment"
    SERVICE_DISRUPTION = "service_disruption"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    LATERAL_MOVEMENT = "lateral_movement"


@dataclass
class AttackNode:
    """Node in the attack graph representing a system state"""
    node_id: str
    host: str
    user_context: str = "guest"
    privileges: str = "user"  # user, admin, system, root
    access_method: str = "none"
    services_accessible: List[str] = field(default_factory=list)
    data_accessible: List[str] = field(default_factory=list)
    network_position: str = "external"  # external, dmz, internal, domain
    compromised: bool = False
    value_score: float = 0.0  # Strategic value of this node
    
    def __post_init__(self):
        if not self.node_id:
            self.node_id = f"{self.host}_{self.user_context}_{self.privileges}"


@dataclass
class AttackEdge:
    """Edge in the attack graph representing an attack action"""
    edge_id: str
    source_node: AttackNode
    target_node: AttackNode
    attack_technique: str
    exploit_used: Optional[ExploitRecommendation] = None
    vulnerability_exploited: Optional[Vulnerability] = None
    
    # Attack characteristics
    success_probability: float = 0.5
    detection_probability: float = 0.5
    execution_time: int = 300  # seconds
    complexity: ExploitComplexity = ExploitComplexity.MEDIUM
    prerequisites: List[str] = field(default_factory=list)
    
    # MITRE ATT&CK mapping
    mitre_technique: Optional[str] = None
    mitre_tactic: Optional[str] = None
    
    def __post_init__(self):
        if not self.edge_id:
            self.edge_id = f"{self.source_node.node_id}_to_{self.target_node.node_id}_{self.attack_technique}"


@dataclass
class AttackPath:
    """Complete attack path from initial access to objective"""
    path_id: str
    name: str
    description: str
    objective: AttackObjective
    nodes: List[AttackNode]
    edges: List[AttackEdge]
    
    # Path metrics
    total_success_probability: float = 0.0
    total_detection_risk: float = 0.0
    estimated_time: int = 0  # seconds
    complexity_score: float = 0.0
    stealth_score: float = 0.0
    
    # Path characteristics
    phases_covered: List[AttackPhase] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    required_tools: List[str] = field(default_factory=list)
    prerequisites: List[str] = field(default_factory=list)
    
    # Execution details
    execution_steps: List[Dict[str, Any]] = field(default_factory=list)
    contingency_plans: List[str] = field(default_factory=list)
    cleanup_steps: List[str] = field(default_factory=list)
    
    created_at: float = field(default_factory=time.time)


class AttackGraph:
    """Graph representation of the attack surface"""
    
    def __init__(self):
        self.graph = nx.DiGraph()
        self.nodes: Dict[str, AttackNode] = {}
        self.edges: Dict[str, AttackEdge] = {}
    
    def add_node(self, node: AttackNode):
        """Add attack node to graph"""
        self.nodes[node.node_id] = node
        self.graph.add_node(node.node_id, **node.__dict__)
    
    def add_edge(self, edge: AttackEdge):
        """Add attack edge to graph"""
        self.edges[edge.edge_id] = edge
        self.graph.add_edge(
            edge.source_node.node_id,
            edge.target_node.node_id,
            **edge.__dict__
        )
    
    def get_paths(self, source_node_id: str, target_node_id: str, max_paths: int = 10) -> List[List[str]]:
        """Get all paths between two nodes"""
        try:
            paths = list(nx.all_simple_paths(
                self.graph, 
                source_node_id, 
                target_node_id, 
                cutoff=10  # Maximum path length
            ))
            return paths[:max_paths]
        except nx.NetworkXNoPath:
            return []
    
    def get_shortest_path(self, source_node_id: str, target_node_id: str) -> Optional[List[str]]:
        """Get shortest path between two nodes"""
        try:
            return nx.shortest_path(self.graph, source_node_id, target_node_id)
        except nx.NetworkXNoPath:
            return None
    
    def calculate_path_metrics(self, path_nodes: List[str]) -> Dict[str, float]:
        """Calculate metrics for a path"""
        if len(path_nodes) < 2:
            return {"success_probability": 0.0, "detection_risk": 0.0, "complexity": 0.0}
        
        success_prob = 1.0
        detection_risk = 0.0
        complexity_sum = 0.0
        
        for i in range(len(path_nodes) - 1):
            source = path_nodes[i]
            target = path_nodes[i + 1]
            
            if self.graph.has_edge(source, target):
                edge_data = self.graph[source][target]
                success_prob *= edge_data.get("success_probability", 0.5)
                detection_risk = max(detection_risk, edge_data.get("detection_probability", 0.5))
                
                complexity_map = {
                    ExploitComplexity.TRIVIAL: 1,
                    ExploitComplexity.EASY: 2,
                    ExploitComplexity.MEDIUM: 3,
                    ExploitComplexity.HARD: 4,
                    ExploitComplexity.EXPERT: 5
                }
                complexity_sum += complexity_map.get(edge_data.get("complexity", ExploitComplexity.MEDIUM), 3)
        
        return {
            "success_probability": success_prob,
            "detection_risk": detection_risk,
            "complexity": complexity_sum / (len(path_nodes) - 1) if len(path_nodes) > 1 else 0
        }


class AttackPathPlanner:
    """AI-powered attack path planning engine"""
    
    def __init__(self, ai_client, config):
        self.ai_client = ai_client
        self.config = config
        self.attack_graph = AttackGraph()
        self.planned_paths: Dict[str, AttackPath] = {}
        self.mitre_techniques = self._load_mitre_techniques()
    
    def _load_mitre_techniques(self) -> Dict[str, Dict[str, Any]]:
        """Load MITRE ATT&CK techniques database"""
        
        # Sample MITRE ATT&CK techniques (in real implementation, load from MITRE)
        return {
            "T1190": {
                "name": "Exploit Public-Facing Application",
                "tactic": "Initial Access",
                "description": "Exploit vulnerabilities in public-facing applications"
            },
            "T1078": {
                "name": "Valid Accounts",
                "tactic": "Initial Access",
                "description": "Use valid account credentials"
            },
            "T1059": {
                "name": "Command and Scripting Interpreter",
                "tactic": "Execution",
                "description": "Execute commands via interpreters"
            },
            "T1055": {
                "name": "Process Injection",
                "tactic": "Defense Evasion",
                "description": "Inject code into processes"
            },
            "T1003": {
                "name": "OS Credential Dumping",
                "tactic": "Credential Access",
                "description": "Dump credentials from OS"
            },
            "T1021": {
                "name": "Remote Services",
                "tactic": "Lateral Movement",
                "description": "Use remote services for lateral movement"
            }
        }
    
    async def build_attack_graph(self, vulnerabilities: List[Vulnerability], 
                               target_environment: Dict[str, Any]) -> AttackGraph:
        """Build attack graph from vulnerabilities and environment info"""
        
        self.attack_graph = AttackGraph()
        
        # 1. Create nodes for each discovered host
        await self._create_host_nodes(target_environment)
        
        # 2. Create edges based on vulnerabilities
        await self._create_vulnerability_edges(vulnerabilities)
        
        # 3. Create edges for lateral movement opportunities
        await self._create_lateral_movement_edges(target_environment)
        
        # 4. Create edges for privilege escalation
        await self._create_privilege_escalation_edges(vulnerabilities)
        
        # 5. Use AI to identify additional attack paths
        await self._ai_enhance_attack_graph(vulnerabilities, target_environment)
        
        logger.info(f"Built attack graph with {len(self.attack_graph.nodes)} nodes and {len(self.attack_graph.edges)} edges")
        return self.attack_graph
    
    async def _create_host_nodes(self, target_environment: Dict[str, Any]):
        """Create attack nodes for discovered hosts"""
        
        hosts = target_environment.get("discovered_hosts", [])
        
        for host_info in hosts:
            host = host_info.get("ip", host_info.get("hostname", "unknown"))
            
            # Create different privilege level nodes for each host
            privilege_levels = ["guest", "user", "admin", "system"]
            
            for priv in privilege_levels:
                node = AttackNode(
                    node_id=f"{host}_{priv}",
                    host=host,
                    user_context="unknown",
                    privileges=priv,
                    services_accessible=host_info.get("services", []),
                    network_position=self._determine_network_position(host, target_environment),
                    value_score=self._calculate_node_value(host, priv, host_info)
                )
                self.attack_graph.add_node(node)
    
    def _determine_network_position(self, host: str, target_environment: Dict[str, Any]) -> str:
        """Determine network position of host"""
        # Simple heuristic based on IP ranges
        if host.startswith("10.") or host.startswith("192.168.") or host.startswith("172."):
            return "internal"
        elif "dmz" in host.lower():
            return "dmz"
        else:
            return "external"
    
    def _calculate_node_value(self, host: str, privileges: str, host_info: Dict[str, Any]) -> float:
        """Calculate strategic value of a node"""
        value = 0.0
        
        # Base value by privilege level
        priv_values = {"guest": 1.0, "user": 3.0, "admin": 7.0, "system": 10.0}
        value += priv_values.get(privileges, 1.0)
        
        # Bonus for valuable services
        services = [s.get("service", "").lower() for s in host_info.get("services", [])]
        valuable_services = {"database": 3.0, "domain": 5.0, "web": 2.0, "file": 2.0}
        
        for service in services:
            for valuable_service, bonus in valuable_services.items():
                if valuable_service in service:
                    value += bonus
        
        return min(value, 10.0)  # Cap at 10
    
    async def _create_vulnerability_edges(self, vulnerabilities: List[Vulnerability]):
        """Create attack edges based on vulnerabilities"""
        
        for vuln in vulnerabilities:
            # Create edges for initial access vulnerabilities
            if vuln.vuln_type.value in ["network", "web_application"] and vuln.exploitable:
                await self._create_initial_access_edge(vuln)
            
            # Create edges for privilege escalation vulnerabilities
            if "privilege" in vuln.name.lower() or "escalation" in vuln.name.lower():
                await self._create_privilege_escalation_edge(vuln)
    
    async def _create_initial_access_edge(self, vulnerability: Vulnerability):
        """Create initial access edge from vulnerability"""
        
        # External attacker node (starting point)
        external_node = AttackNode(
            node_id="external_attacker",
            host="external",
            user_context="attacker",
            privileges="none",
            network_position="external"
        )
        
        if external_node.node_id not in self.attack_graph.nodes:
            self.attack_graph.add_node(external_node)
        
        # Target node (initial foothold)
        target_node_id = f"{vulnerability.host}_guest"
        if target_node_id in self.attack_graph.nodes:
            target_node = self.attack_graph.nodes[target_node_id]
            
            edge = AttackEdge(
                edge_id="",
                source_node=external_node,
                target_node=target_node,
                attack_technique=f"Exploit {vulnerability.name}",
                vulnerability_exploited=vulnerability,
                success_probability=0.8 if vulnerability.exploitable else 0.3,
                detection_probability=0.4,
                execution_time=600,
                complexity=ExploitComplexity.MEDIUM,
                mitre_technique="T1190"
            )
            
            self.attack_graph.add_edge(edge)
    
    async def _create_privilege_escalation_edge(self, vulnerability: Vulnerability):
        """Create privilege escalation edge from vulnerability"""
        
        # From user to admin on same host
        user_node_id = f"{vulnerability.host}_user"
        admin_node_id = f"{vulnerability.host}_admin"
        
        if user_node_id in self.attack_graph.nodes and admin_node_id in self.attack_graph.nodes:
            user_node = self.attack_graph.nodes[user_node_id]
            admin_node = self.attack_graph.nodes[admin_node_id]
            
            edge = AttackEdge(
                edge_id="",
                source_node=user_node,
                target_node=admin_node,
                attack_technique=f"Privilege Escalation via {vulnerability.name}",
                vulnerability_exploited=vulnerability,
                success_probability=0.7 if vulnerability.exploitable else 0.2,
                detection_probability=0.6,
                execution_time=300,
                complexity=ExploitComplexity.MEDIUM,
                mitre_technique="T1068"
            )
            
            self.attack_graph.add_edge(edge)
    
    async def _create_lateral_movement_edges(self, target_environment: Dict[str, Any]):
        """Create lateral movement edges between hosts"""
        
        hosts = target_environment.get("discovered_hosts", [])
        
        for i, host1 in enumerate(hosts):
            for host2 in hosts[i+1:]:
                host1_ip = host1.get("ip", host1.get("hostname"))
                host2_ip = host2.get("ip", host2.get("hostname"))
                
                # Check for lateral movement opportunities
                if self._can_lateral_move(host1, host2):
                    await self._create_lateral_movement_edge(host1_ip, host2_ip)
    
    def _can_lateral_move(self, host1: Dict[str, Any], host2: Dict[str, Any]) -> bool:
        """Check if lateral movement is possible between hosts"""
        
        # Check for common services that enable lateral movement
        lateral_services = ["smb", "ssh", "rdp", "winrm", "wmi"]
        
        host1_services = [s.get("service", "").lower() for s in host1.get("services", [])]
        host2_services = [s.get("service", "").lower() for s in host2.get("services", [])]
        
        return any(service in host1_services or service in host2_services for service in lateral_services)
    
    async def _create_lateral_movement_edge(self, host1: str, host2: str):
        """Create lateral movement edge between hosts"""
        
        # From admin on host1 to user on host2
        source_node_id = f"{host1}_admin"
        target_node_id = f"{host2}_user"
        
        if source_node_id in self.attack_graph.nodes and target_node_id in self.attack_graph.nodes:
            source_node = self.attack_graph.nodes[source_node_id]
            target_node = self.attack_graph.nodes[target_node_id]
            
            edge = AttackEdge(
                edge_id="",
                source_node=source_node,
                target_node=target_node,
                attack_technique="Lateral Movement via Remote Services",
                success_probability=0.6,
                detection_probability=0.5,
                execution_time=180,
                complexity=ExploitComplexity.MEDIUM,
                mitre_technique="T1021"
            )
            
            self.attack_graph.add_edge(edge)
    
    async def _create_privilege_escalation_edges(self, vulnerabilities: List[Vulnerability]):
        """Create privilege escalation edges for each host"""
        
        # Group vulnerabilities by host
        host_vulns = defaultdict(list)
        for vuln in vulnerabilities:
            host_vulns[vuln.host].append(vuln)
        
        for host, vulns in host_vulns.items():
            # Create edges from user to admin
            user_node_id = f"{host}_user"
            admin_node_id = f"{host}_admin"
            
            if user_node_id in self.attack_graph.nodes and admin_node_id in self.attack_graph.nodes:
                user_node = self.attack_graph.nodes[user_node_id]
                admin_node = self.attack_graph.nodes[admin_node_id]
                
                # Generic privilege escalation edge
                edge = AttackEdge(
                    edge_id="",
                    source_node=user_node,
                    target_node=admin_node,
                    attack_technique="Generic Privilege Escalation",
                    success_probability=0.4,
                    detection_probability=0.7,
                    execution_time=900,
                    complexity=ExploitComplexity.HARD,
                    mitre_technique="T1068"
                )
                
                self.attack_graph.add_edge(edge)
    
    async def _ai_enhance_attack_graph(self, vulnerabilities: List[Vulnerability], 
                                     target_environment: Dict[str, Any]):
        """Use AI to identify additional attack paths and techniques"""
        
        prompt = f"""Analyze this target environment and vulnerabilities to identify additional attack paths:

TARGET ENVIRONMENT:
{json.dumps(target_environment, indent=2)}

VULNERABILITIES:
{json.dumps([{
    "name": v.name,
    "host": v.host,
    "service": v.service,
    "type": v.vuln_type.value,
    "exploitable": v.exploitable
} for v in vulnerabilities[:10]], indent=2)}

Identify additional attack techniques and paths that could be used in this environment.
Consider:
1. Service-specific attack techniques
2. Operating system specific attacks
3. Network-based attacks
4. Social engineering opportunities
5. Physical security considerations

Return as JSON array of attack techniques:
[
  {{
    "technique_name": "technique name",
    "mitre_id": "T1234",
    "source_host": "source host or 'external'",
    "target_host": "target host",
    "source_privileges": "guest|user|admin|system",
    "target_privileges": "guest|user|admin|system",
    "success_probability": 0.0-1.0,
    "detection_probability": 0.0-1.0,
    "complexity": "trivial|easy|medium|hard|expert",
    "description": "detailed description"
  }}
]

Only return valid JSON."""

        try:
            from nexus.ai.ollama_client import GenerationRequest
            request = GenerationRequest(
                model=self.config.ai.model,
                prompt=prompt,
                system="You are a red team expert identifying attack techniques and paths.",
                temperature=0.4
            )
            
            response = await self.ai_client.generate(request)
            techniques = json.loads(response.response)
            
            # Add AI-identified techniques to graph
            for technique in techniques:
                await self._add_ai_technique_to_graph(technique)
                
        except Exception as e:
            logger.error(f"AI attack graph enhancement failed: {e}")
    
    async def _add_ai_technique_to_graph(self, technique: Dict[str, Any]):
        """Add AI-identified technique to attack graph"""
        
        source_host = technique.get("source_host", "external")
        target_host = technique.get("target_host", "unknown")
        source_privs = technique.get("source_privileges", "user")
        target_privs = technique.get("target_privileges", "user")
        
        source_node_id = f"{source_host}_{source_privs}"
        target_node_id = f"{target_host}_{target_privs}"
        
        # Create nodes if they don't exist
        if source_node_id not in self.attack_graph.nodes:
            source_node = AttackNode(
                node_id=source_node_id,
                host=source_host,
                privileges=source_privs
            )
            self.attack_graph.add_node(source_node)
        
        if target_node_id not in self.attack_graph.nodes:
            target_node = AttackNode(
                node_id=target_node_id,
                host=target_host,
                privileges=target_privs
            )
            self.attack_graph.add_node(target_node)
        
        # Create edge
        source_node = self.attack_graph.nodes[source_node_id]
        target_node = self.attack_graph.nodes[target_node_id]
        
        complexity_map = {
            "trivial": ExploitComplexity.TRIVIAL,
            "easy": ExploitComplexity.EASY,
            "medium": ExploitComplexity.MEDIUM,
            "hard": ExploitComplexity.HARD,
            "expert": ExploitComplexity.EXPERT
        }
        
        edge = AttackEdge(
            edge_id="",
            source_node=source_node,
            target_node=target_node,
            attack_technique=technique.get("technique_name", "Unknown Technique"),
            success_probability=technique.get("success_probability", 0.5),
            detection_probability=technique.get("detection_probability", 0.5),
            complexity=complexity_map.get(technique.get("complexity", "medium"), ExploitComplexity.MEDIUM),
            mitre_technique=technique.get("mitre_id")
        )
        
        self.attack_graph.add_edge(edge)
    
    async def plan_attack_paths(self, objective: AttackObjective,
                              target_environment: Dict[str, Any],
                              constraints: Dict[str, Any] = None) -> List[AttackPath]:
        """Plan attack paths to achieve the specified objective"""
        
        constraints = constraints or {}
        
        # 1. Identify target nodes based on objective
        target_nodes = self._identify_target_nodes(objective, target_environment)
        
        # 2. Find all possible paths to target nodes
        all_paths = []
        external_node_id = "external_attacker"
        
        for target_node_id in target_nodes:
            paths = self.attack_graph.get_paths(external_node_id, target_node_id, max_paths=20)
            for path in paths:
                all_paths.append(path)
        
        # 3. Convert paths to AttackPath objects with metrics
        attack_paths = []
        for i, path_nodes in enumerate(all_paths):
            if len(path_nodes) < 2:
                continue
                
            # Calculate path metrics
            metrics = self.attack_graph.calculate_path_metrics(path_nodes)
            
            # Create AttackPath object
            attack_path = AttackPath(
                path_id=f"path_{objective.value}_{i}",
                name=f"Attack Path to {objective.value.replace('_', ' ').title()}",
                description=f"Multi-step attack path to achieve {objective.value}",
                objective=objective,
                nodes=[self.attack_graph.nodes[node_id] for node_id in path_nodes if node_id in self.attack_graph.nodes],
                edges=self._get_path_edges(path_nodes),
                total_success_probability=metrics["success_probability"],
                total_detection_risk=metrics["detection_risk"],
                complexity_score=metrics["complexity"]
            )
            
            # Add execution steps
            attack_path.execution_steps = await self._generate_execution_steps(attack_path)
            
            attack_paths.append(attack_path)
        
        # 4. Filter and rank paths based on constraints
        filtered_paths = self._filter_paths_by_constraints(attack_paths, constraints)
        ranked_paths = self._rank_attack_paths(filtered_paths, constraints)
        
        # 5. Store planned paths
        for path in ranked_paths:
            self.planned_paths[path.path_id] = path
        
        logger.info(f"Generated {len(ranked_paths)} attack paths for objective {objective.value}")
        return ranked_paths[:constraints.get("max_paths", 10)]
    
    def _identify_target_nodes(self, objective: AttackObjective, target_environment: Dict[str, Any]) -> List[str]:
        """Identify target nodes based on campaign objective"""
        
        target_nodes = []
        
        if objective == AttackObjective.DOMAIN_ADMIN:
            # Look for domain controller nodes with admin privileges
            for node_id, node in self.attack_graph.nodes.items():
                if "domain" in node.host.lower() and node.privileges in ["admin", "system"]:
                    target_nodes.append(node_id)
        
        elif objective == AttackObjective.DATA_EXFILTRATION:
            # Look for nodes with valuable data access
            for node_id, node in self.attack_graph.nodes.items():
                if node.data_accessible or "database" in str(node.services_accessible).lower():
                    target_nodes.append(node_id)
        
        elif objective == AttackObjective.SYSTEM_COMPROMISE:
            # Look for high-value system nodes
            for node_id, node in self.attack_graph.nodes.items():
                if node.privileges in ["admin", "system"] and node.value_score > 5.0:
                    target_nodes.append(node_id)
        
        elif objective == AttackObjective.PRIVILEGE_ESCALATION:
            # Look for admin/system level nodes
            for node_id, node in self.attack_graph.nodes.items():
                if node.privileges in ["admin", "system"]:
                    target_nodes.append(node_id)
        
        elif objective == AttackObjective.LATERAL_MOVEMENT:
            # Look for internal network nodes
            for node_id, node in self.attack_graph.nodes.items():
                if node.network_position == "internal":
                    target_nodes.append(node_id)
        
        else:
            # Default: target high-value nodes
            for node_id, node in self.attack_graph.nodes.items():
                if node.value_score > 3.0:
                    target_nodes.append(node_id)
        
        return target_nodes[:20]  # Limit to top 20 targets
    
    def _get_path_edges(self, path_nodes: List[str]) -> List[AttackEdge]:
        """Get edges for a path"""
        edges = []
        
        for i in range(len(path_nodes) - 1):
            source_id = path_nodes[i]
            target_id = path_nodes[i + 1]
            
            # Find edge between these nodes
            for edge_id, edge in self.attack_graph.edges.items():
                if edge.source_node.node_id == source_id and edge.target_node.node_id == target_id:
                    edges.append(edge)
                    break
        
        return edges
    
    async def _generate_execution_steps(self, attack_path: AttackPath) -> List[Dict[str, Any]]:
        """Generate detailed execution steps for attack path"""
        
        steps = []
        
        for i, edge in enumerate(attack_path.edges):
            step = {
                "step_number": i + 1,
                "technique": edge.attack_technique,
                "source": edge.source_node.host,
                "target": edge.target_node.host,
                "mitre_technique": edge.mitre_technique,
                "estimated_time": edge.execution_time,
                "success_probability": edge.success_probability,
                "detection_risk": edge.detection_probability,
                "prerequisites": edge.prerequisites,
                "description": f"Execute {edge.attack_technique} from {edge.source_node.host} to {edge.target_node.host}"
            }
            steps.append(step)
        
        return steps
    
    def _filter_paths_by_constraints(self, paths: List[AttackPath], constraints: Dict[str, Any]) -> List[AttackPath]:
        """Filter attack paths based on constraints"""
        
        filtered = []
        
        for path in paths:
            # Check stealth requirements
            if constraints.get("stealth_required", False):
                if path.total_detection_risk > 0.7:
                    continue
            
            # Check complexity constraints
            max_complexity = constraints.get("max_complexity", 5.0)
            if path.complexity_score > max_complexity:
                continue
            
            # Check minimum success probability
            min_success = constraints.get("min_success_probability", 0.1)
            if path.total_success_probability < min_success:
                continue
            
            # Check maximum execution time
            max_time = constraints.get("max_execution_time", 7200)  # 2 hours default
            if path.estimated_time > max_time:
                continue
            
            filtered.append(path)
        
        return filtered
    
    def _rank_attack_paths(self, paths: List[AttackPath], constraints: Dict[str, Any]) -> List[AttackPath]:
        """Rank attack paths by suitability"""
        
        def calculate_score(path: AttackPath) -> float:
            score = 0.0
            
            # Success probability (40% weight)
            score += path.total_success_probability * 40
            
            # Stealth (30% weight) - lower detection risk is better
            score += (1.0 - path.total_detection_risk) * 30
            
            # Simplicity (20% weight) - lower complexity is better
            score += (5.0 - min(path.complexity_score, 5.0)) * 4  # Normalize to 0-20
            
            # Speed (10% weight) - shorter time is better
            max_time = 3600  # 1 hour reference
            time_score = max(0, (max_time - min(path.estimated_time, max_time)) / max_time)
            score += time_score * 10
            
            # Apply constraint-based bonuses
            if constraints.get("stealth_required", False) and path.total_detection_risk < 0.3:
                score += 10  # Stealth bonus
            
            if constraints.get("quick_wins_preferred", False) and path.complexity_score < 2.0:
                score += 15  # Quick win bonus
            
            return score
        
        # Sort by score (descending)
        ranked = sorted(paths, key=calculate_score, reverse=True)
        
        return ranked
    
    def get_path_summary(self, path_id: str) -> Optional[Dict[str, Any]]:
        """Get summary of a planned attack path"""
        
        if path_id not in self.planned_paths:
            return None
        
        path = self.planned_paths[path_id]
        
        return {
            "path_id": path.path_id,
            "name": path.name,
            "objective": path.objective.value,
            "success_probability": path.total_success_probability,
            "detection_risk": path.total_detection_risk,
            "complexity": path.complexity_score,
            "estimated_time": path.estimated_time,
            "steps_count": len(path.execution_steps),
            "mitre_techniques": path.mitre_techniques,
            "required_tools": path.required_tools
        }
    
    def get_all_planned_paths(self) -> List[Dict[str, Any]]:
        """Get summaries of all planned attack paths"""
        
        return [self.get_path_summary(path_id) for path_id in self.planned_paths.keys()]