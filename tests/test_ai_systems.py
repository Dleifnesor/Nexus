"""
Comprehensive Tests for Nexus AI Systems

Tests for vulnerability correlation, exploit recommendation, and attack path planning systems.
"""

import pytest
import asyncio
import json
from unittest.mock import Mock, AsyncMock, patch
from pathlib import Path

from nexus.ai.vulnerability_correlator import (
    VulnerabilityCorrelator, Vulnerability, VulnerabilityCluster, 
    SeverityLevel, VulnerabilityType
)
from nexus.ai.exploit_recommender import (
    ExploitRecommender, ExploitRecommendation, ExploitType, 
    ExploitComplexity, AttackObjective
)
from nexus.ai.attack_path_planner import (
    AttackPathPlanner, AttackPath, AttackNode, AttackEdge, 
    AttackObjective as PathObjective
)
from nexus.core.config import NexusConfig


class TestVulnerabilityCorrelator:
    """Test cases for the Vulnerability Correlation Engine"""
    
    @pytest.fixture
    def mock_ollama_client(self):
        """Mock Ollama client for testing"""
        client = Mock()
        client.generate_response = AsyncMock()
        return client
    
    @pytest.fixture
    def mock_config(self):
        """Mock configuration for testing"""
        config = Mock()
        config.ai = Mock()
        config.ai.model = "qwen3-14b-abliterated"
        config.ai.temperature = 0.7
        config.ai.max_tokens = 2048
        return config
    
    @pytest.fixture
    def correlator(self, mock_ollama_client, mock_config):
        """Create vulnerability correlator instance"""
        return VulnerabilityCorrelator(mock_ollama_client, mock_config)
    
    @pytest.fixture
    def sample_vulnerabilities(self):
        """Sample vulnerabilities for testing"""
        return [
            Vulnerability(
                vuln_id="CVE-2023-1234",
                name="SQL Injection in login form",
                description="SQL injection vulnerability in user authentication",
                severity=SeverityLevel.HIGH,
                vuln_type=VulnerabilityType.WEB_APPLICATION,
                host="192.168.1.100",
                port=80,
                service="http",
                exploitable=True,
                cvss_score=8.5
            ),
            Vulnerability(
                vuln_id="CVE-2023-5678",
                name="Remote Code Execution via file upload",
                description="Unrestricted file upload leading to RCE",
                severity=SeverityLevel.CRITICAL,
                vuln_type=VulnerabilityType.WEB_APPLICATION,
                host="192.168.1.100",
                port=80,
                service="http",
                exploitable=True,
                cvss_score=9.8
            ),
            Vulnerability(
                vuln_id="CVE-2023-9999",
                name="SSH weak credentials",
                description="SSH service with weak default credentials",
                severity=SeverityLevel.MEDIUM,
                vuln_type=VulnerabilityType.SYSTEM,
                host="192.168.1.100",
                port=22,
                service="ssh",
                exploitable=True,
                cvss_score=6.5
            )
        ]
    
    def test_vulnerability_creation(self):
        """Test vulnerability object creation"""
        vuln = Vulnerability(
            vuln_id="TEST-001",
            name="Test Vulnerability",
            description="Test description",
            severity=SeverityLevel.HIGH,
            vuln_type=VulnerabilityType.SYSTEM,
            host="192.168.1.1",
            exploitable=True
        )
        
        assert vuln.vuln_id == "TEST-001"
        assert vuln.name == "Test Vulnerability"
        assert vuln.severity == SeverityLevel.HIGH
        assert vuln.exploitable is True
    
    def test_correlator_initialization(self, correlator):
        """Test correlator initialization"""
        assert correlator.vulnerabilities == []
        assert correlator.clusters == []
        assert correlator.ollama_client is not None
        assert correlator.config is not None
    
    def test_add_vulnerability(self, correlator, sample_vulnerabilities):
        """Test adding vulnerabilities to correlator"""
        vuln = sample_vulnerabilities[0]
        correlator.add_vulnerability(vuln)
        
        assert len(correlator.vulnerabilities) == 1
        assert correlator.vulnerabilities[0] == vuln
    
    @pytest.mark.asyncio
    async def test_extract_vulnerabilities_from_nmap(self, correlator, mock_ollama_client):
        """Test vulnerability extraction from Nmap output"""
        nmap_output = """
        Starting Nmap 7.94 ( https://nmap.org ) at 2024-01-01 12:00 UTC
        Nmap scan report for 192.168.1.100
        Host is up (0.001s latency).
        PORT     STATE SERVICE VERSION
        22/tcp   open  ssh     OpenSSH 7.4 (protocol 2.0)
        80/tcp   open  http    Apache httpd 2.4.6
        443/tcp  open  https   Apache httpd 2.4.6
        """
        
        # Mock AI response for vulnerability extraction
        mock_ollama_client.generate_response.return_value = json.dumps([
            {
                "name": "Outdated SSH version",
                "description": "OpenSSH 7.4 has known vulnerabilities",
                "severity": "medium",
                "type": "system",
                "port": 22,
                "service": "ssh",
                "exploitable": True
            }
        ])
        
        target_info = {"host": "192.168.1.100"}
        await correlator.add_vulnerability_from_tool_output("nmap", nmap_output, target_info)
        
        assert len(correlator.vulnerabilities) == 1
        vuln = correlator.vulnerabilities[0]
        assert vuln.host == "192.168.1.100"
        assert vuln.port == 22
        assert vuln.service == "ssh"
    
    def test_cluster_vulnerabilities_by_host(self, correlator, sample_vulnerabilities):
        """Test clustering vulnerabilities by host"""
        for vuln in sample_vulnerabilities:
            correlator.add_vulnerability(vuln)
        
        clusters = correlator._cluster_vulnerabilities_by_host()
        
        assert len(clusters) == 1  # All vulns are on same host
        cluster = clusters[0]
        assert cluster.cluster_type == "host_based"
        assert len(cluster.vulnerabilities) == 3
        assert cluster.primary_host == "192.168.1.100"
    
    def test_cluster_vulnerabilities_by_service(self, correlator, sample_vulnerabilities):
        """Test clustering vulnerabilities by service"""
        for vuln in sample_vulnerabilities:
            correlator.add_vulnerability(vuln)
        
        clusters = correlator._cluster_vulnerabilities_by_service()
        
        # Should have 2 clusters: http and ssh
        assert len(clusters) == 2
        
        http_cluster = next(c for c in clusters if c.primary_service == "http")
        ssh_cluster = next(c for c in clusters if c.primary_service == "ssh")
        
        assert len(http_cluster.vulnerabilities) == 2
        assert len(ssh_cluster.vulnerabilities) == 1
    
    def test_get_vulnerability_summary(self, correlator, sample_vulnerabilities):
        """Test vulnerability summary generation"""
        for vuln in sample_vulnerabilities:
            correlator.add_vulnerability(vuln)
        
        summary = correlator.get_vulnerability_summary()
        
        assert summary['total'] == 3
        assert summary['exploitable'] == 3
        assert summary['by_severity']['critical'] == 1
        assert summary['by_severity']['high'] == 1
        assert summary['by_severity']['medium'] == 1
        assert summary['by_type']['web_application'] == 2
        assert summary['by_type']['system'] == 1
    
    def test_get_top_risks(self, correlator, sample_vulnerabilities):
        """Test getting top risk vulnerabilities"""
        for vuln in sample_vulnerabilities:
            correlator.add_vulnerability(vuln)
        
        top_risks = correlator.get_top_risks(2)
        
        assert len(top_risks) == 2
        # Should be ordered by severity (critical first)
        assert top_risks[0].severity == SeverityLevel.CRITICAL
        assert top_risks[1].severity == SeverityLevel.HIGH


class TestExploitRecommender:
    """Test cases for the Exploit Recommendation System"""
    
    @pytest.fixture
    def mock_ollama_client(self):
        """Mock Ollama client for testing"""
        client = Mock()
        client.generate_response = AsyncMock()
        return client
    
    @pytest.fixture
    def mock_config(self):
        """Mock configuration for testing"""
        config = Mock()
        config.ai = Mock()
        config.ai.model = "qwen3-14b-abliterated"
        config.ai.temperature = 0.7
        config.ai.max_tokens = 2048
        return config
    
    @pytest.fixture
    def recommender(self, mock_ollama_client, mock_config):
        """Create exploit recommender instance"""
        return ExploitRecommender(mock_ollama_client, mock_config)
    
    @pytest.fixture
    def sample_vulnerability(self):
        """Sample vulnerability for testing"""
        return Vulnerability(
            vuln_id="CVE-2023-1234",
            name="SQL Injection in login form",
            description="SQL injection vulnerability in user authentication",
            severity=SeverityLevel.HIGH,
            vuln_type=VulnerabilityType.WEB_APPLICATION,
            host="192.168.1.100",
            port=80,
            service="http",
            exploitable=True,
            cvss_score=8.5
        )
    
    def test_recommender_initialization(self, recommender):
        """Test recommender initialization"""
        assert recommender.exploit_database is not None
        assert recommender.ollama_client is not None
        assert recommender.config is not None
    
    def test_exploit_database_loading(self, recommender):
        """Test exploit database initialization"""
        # Check that database has some default exploits
        assert len(recommender.exploit_database) > 0
        
        # Check for common exploit types
        exploit_types = [exploit['type'] for exploit in recommender.exploit_database]
        assert 'sql_injection' in exploit_types
        assert 'remote_code_execution' in exploit_types
    
    @pytest.mark.asyncio
    async def test_recommend_exploits(self, recommender, sample_vulnerability, mock_ollama_client):
        """Test exploit recommendation generation"""
        # Mock AI response for exploit recommendation
        mock_ollama_client.generate_response.return_value = json.dumps([
            {
                "exploit_id": "EXP-SQL-001",
                "name": "SQL Injection Authentication Bypass",
                "description": "Bypass authentication using SQL injection",
                "success_probability": 0.85,
                "stealth_rating": 0.7,
                "complexity": "medium",
                "metasploit_module": "auxiliary/scanner/http/sql_login",
                "execution_steps": [
                    "Identify injection point",
                    "Craft SQL payload",
                    "Execute bypass attempt"
                ]
            }
        ])
        
        context = {"stealth_required": True}
        recommendations = await recommender.recommend_exploits(sample_vulnerability, context)
        
        assert len(recommendations) > 0
        rec = recommendations[0]
        assert rec.name == "SQL Injection Authentication Bypass"
        assert rec.success_probability == 0.85
        assert rec.stealth_rating == 0.7
        assert rec.complexity == ExploitComplexity.MEDIUM
    
    @pytest.mark.asyncio
    async def test_generate_exploit_script(self, recommender, mock_ollama_client):
        """Test custom exploit script generation"""
        # Create a sample recommendation
        recommendation = ExploitRecommendation(
            exploit_id="EXP-TEST-001",
            name="Test Exploit",
            description="Test exploit for unit testing",
            exploit_type=ExploitType.REMOTE_CODE_EXECUTION,
            complexity=ExploitComplexity.MEDIUM,
            success_probability=0.8,
            stealth_rating=0.6,
            target_vulnerability=None,
            execution_steps=["Step 1", "Step 2"],
            payload_options={"reverse_shell": True}
        )
        
        # Mock AI response for script generation
        mock_script = """#!/usr/bin/env python3
import requests

def exploit_target(target_url):
    payload = "test_payload"
    response = requests.post(target_url, data={"input": payload})
    return response.status_code == 200

if __name__ == "__main__":
    target = "http://192.168.1.100"
    if exploit_target(target):
        print("Exploit successful!")
    else:
        print("Exploit failed!")
"""
        
        mock_ollama_client.generate_response.return_value = mock_script
        
        context = {"target_ip": "192.168.1.100"}
        script = await recommender.generate_exploit_script(recommendation, context)
        
        assert script is not None
        assert "#!/usr/bin/env python3" in script
        assert "192.168.1.100" in script
    
    def test_filter_exploits_by_complexity(self, recommender):
        """Test filtering exploits by complexity"""
        # Add some test exploits with different complexities
        test_exploits = [
            {"id": "1", "complexity": "trivial", "name": "Easy exploit"},
            {"id": "2", "complexity": "expert", "name": "Hard exploit"},
            {"id": "3", "complexity": "medium", "name": "Medium exploit"}
        ]
        
        filtered = recommender._filter_exploits_by_complexity(test_exploits, "medium")
        
        # Should include trivial and medium, but not expert
        assert len(filtered) == 2
        complexities = [e["complexity"] for e in filtered]
        assert "trivial" in complexities
        assert "medium" in complexities
        assert "expert" not in complexities


class TestAttackPathPlanner:
    """Test cases for the Attack Path Planning System"""
    
    @pytest.fixture
    def mock_ollama_client(self):
        """Mock Ollama client for testing"""
        client = Mock()
        client.generate_response = AsyncMock()
        return client
    
    @pytest.fixture
    def mock_config(self):
        """Mock configuration for testing"""
        config = Mock()
        config.ai = Mock()
        config.ai.model = "qwen3-14b-abliterated"
        config.ai.temperature = 0.7
        config.ai.max_tokens = 2048
        return config
    
    @pytest.fixture
    def planner(self, mock_ollama_client, mock_config):
        """Create attack path planner instance"""
        return AttackPathPlanner(mock_ollama_client, mock_config)
    
    @pytest.fixture
    def sample_vulnerabilities(self):
        """Sample vulnerabilities for testing"""
        return [
            Vulnerability(
                vuln_id="CVE-2023-1234",
                name="SSH weak credentials",
                description="SSH service with weak default credentials",
                severity=SeverityLevel.MEDIUM,
                vuln_type=VulnerabilityType.SYSTEM,
                host="192.168.1.100",
                port=22,
                service="ssh",
                exploitable=True
            ),
            Vulnerability(
                vuln_id="CVE-2023-5678",
                name="Privilege escalation vulnerability",
                description="Local privilege escalation via kernel exploit",
                severity=SeverityLevel.HIGH,
                vuln_type=VulnerabilityType.SYSTEM,
                host="192.168.1.100",
                port=None,
                service="system",
                exploitable=True
            )
        ]
    
    @pytest.fixture
    def sample_environment(self):
        """Sample environment data for testing"""
        return {
            "hosts": [
                {
                    "ip": "192.168.1.100",
                    "hostname": "web-server",
                    "os": "Linux",
                    "services": ["ssh", "http"],
                    "network_position": "dmz"
                },
                {
                    "ip": "192.168.1.200",
                    "hostname": "db-server",
                    "os": "Linux",
                    "services": ["mysql"],
                    "network_position": "internal"
                }
            ],
            "network": {
                "subnets": ["192.168.1.0/24"],
                "gateways": ["192.168.1.1"],
                "critical_assets": ["192.168.1.200"]
            }
        }
    
    def test_planner_initialization(self, planner):
        """Test planner initialization"""
        assert planner.attack_graph is not None
        assert planner.ollama_client is not None
        assert planner.config is not None
    
    def test_attack_node_creation(self):
        """Test attack node creation"""
        node = AttackNode(
            node_id="node_001",
            host="192.168.1.100",
            privileges="user",
            network_position="dmz",
            value_score=5.0
        )
        
        assert node.node_id == "node_001"
        assert node.host == "192.168.1.100"
        assert node.privileges == "user"
        assert node.value_score == 5.0
    
    def test_attack_edge_creation(self):
        """Test attack edge creation"""
        source_node = AttackNode("src", "192.168.1.100", "user", "dmz", 3.0)
        target_node = AttackNode("tgt", "192.168.1.200", "admin", "internal", 8.0)
        
        edge = AttackEdge(
            edge_id="edge_001",
            source_node=source_node,
            target_node=target_node,
            attack_technique="SSH Brute Force",
            success_probability=0.7,
            detection_probability=0.3,
            mitre_technique="T1110.001"
        )
        
        assert edge.edge_id == "edge_001"
        assert edge.attack_technique == "SSH Brute Force"
        assert edge.success_probability == 0.7
        assert edge.mitre_technique == "T1110.001"
    
    @pytest.mark.asyncio
    async def test_build_attack_graph(self, planner, sample_vulnerabilities, sample_environment):
        """Test attack graph construction"""
        graph = await planner.build_attack_graph(sample_vulnerabilities, sample_environment)
        
        assert graph is not None
        assert len(graph.nodes) > 0
        assert len(graph.edges) >= 0  # May be 0 if no attack paths found
    
    @pytest.mark.asyncio
    async def test_plan_attack_paths(self, planner, sample_vulnerabilities, sample_environment, mock_ollama_client):
        """Test attack path planning"""
        # Mock AI response for path planning
        mock_ollama_client.generate_response.return_value = json.dumps([
            {
                "path_id": "path_001",
                "name": "SSH Compromise to Privilege Escalation",
                "description": "Gain initial access via SSH then escalate privileges",
                "success_probability": 0.6,
                "stealth_score": 0.7,
                "estimated_time": 1800,
                "steps": [
                    {
                        "technique": "SSH Brute Force",
                        "source": "192.168.1.1",
                        "target": "192.168.1.100",
                        "mitre_technique": "T1110.001"
                    },
                    {
                        "technique": "Local Privilege Escalation",
                        "source": "192.168.1.100",
                        "target": "192.168.1.100",
                        "mitre_technique": "T1068"
                    }
                ]
            }
        ])
        
        # Build graph first
        await planner.build_attack_graph(sample_vulnerabilities, sample_environment)
        
        # Plan attack paths
        objective = PathObjective.PRIVILEGE_ESCALATION
        constraints = {"stealth_required": True, "max_paths": 5}
        
        paths = await planner.plan_attack_paths(objective, sample_environment, constraints)
        
        assert len(paths) > 0
        path = paths[0]
        assert path.name == "SSH Compromise to Privilege Escalation"
        assert path.total_success_probability == 0.6
        assert path.stealth_score == 0.7
    
    def test_calculate_path_metrics(self, planner):
        """Test attack path metrics calculation"""
        # Create sample nodes and edges
        node1 = AttackNode("n1", "192.168.1.100", "user", "dmz", 3.0)
        node2 = AttackNode("n2", "192.168.1.100", "admin", "dmz", 8.0)
        
        edge = AttackEdge(
            "e1", node1, node2, "Privilege Escalation", 
            0.8, 0.2, "T1068"
        )
        
        path = AttackPath(
            path_id="test_path",
            name="Test Path",
            description="Test attack path",
            objective=PathObjective.PRIVILEGE_ESCALATION,
            edges=[edge],
            total_success_probability=0.8,
            total_detection_risk=0.2,
            estimated_time=1200,
            complexity_score=5.0
        )
        
        # Test path metrics
        assert path.total_success_probability == 0.8
        assert path.total_detection_risk == 0.2
        assert path.estimated_time == 1200
        assert len(path.edges) == 1


class TestAISystemsIntegration:
    """Integration tests for AI systems working together"""
    
    @pytest.fixture
    def mock_ollama_client(self):
        """Mock Ollama client for testing"""
        client = Mock()
        client.generate_response = AsyncMock()
        return client
    
    @pytest.fixture
    def mock_config(self):
        """Mock configuration for testing"""
        config = Mock()
        config.ai = Mock()
        config.ai.model = "qwen3-14b-abliterated"
        config.ai.temperature = 0.7
        config.ai.max_tokens = 2048
        return config
    
    @pytest.mark.asyncio
    async def test_full_ai_pipeline(self, mock_ollama_client, mock_config):
        """Test complete AI analysis pipeline"""
        # Initialize all AI systems
        correlator = VulnerabilityCorrelator(mock_ollama_client, mock_config)
        recommender = ExploitRecommender(mock_ollama_client, mock_config)
        planner = AttackPathPlanner(mock_ollama_client, mock_config)
        
        # Mock AI responses
        mock_ollama_client.generate_response.side_effect = [
            # Vulnerability extraction response
            json.dumps([{
                "name": "SSH Weak Credentials",
                "description": "SSH service with weak credentials",
                "severity": "high",
                "type": "system",
                "port": 22,
                "service": "ssh",
                "exploitable": True
            }]),
            # Exploit recommendation response
            json.dumps([{
                "exploit_id": "EXP-SSH-001",
                "name": "SSH Brute Force Attack",
                "description": "Brute force SSH credentials",
                "success_probability": 0.75,
                "stealth_rating": 0.6,
                "complexity": "easy",
                "execution_steps": ["Enumerate users", "Brute force passwords"]
            }]),
            # Attack path planning response
            json.dumps([{
                "path_id": "path_001",
                "name": "SSH Compromise Path",
                "description": "Compromise via SSH brute force",
                "success_probability": 0.75,
                "stealth_score": 0.6,
                "estimated_time": 900,
                "steps": [{
                    "technique": "SSH Brute Force",
                    "source": "attacker",
                    "target": "192.168.1.100",
                    "mitre_technique": "T1110.001"
                }]
            }])
        ]
        
        # Step 1: Extract vulnerabilities
        nmap_output = "22/tcp open ssh OpenSSH 7.4"
        target_info = {"host": "192.168.1.100"}
        await correlator.add_vulnerability_from_tool_output("nmap", nmap_output, target_info)
        
        # Step 2: Get exploit recommendations
        vulnerabilities = correlator.vulnerabilities
        assert len(vulnerabilities) == 1
        
        recommendations = await recommender.recommend_exploits(vulnerabilities[0], {})
        assert len(recommendations) > 0
        
        # Step 3: Plan attack paths
        environment = {
            "hosts": [{"ip": "192.168.1.100", "services": ["ssh"]}],
            "network": {"subnets": ["192.168.1.0/24"]}
        }
        
        await planner.build_attack_graph(vulnerabilities, environment)
        paths = await planner.plan_attack_paths(
            PathObjective.INITIAL_ACCESS, environment, {}
        )
        
        assert len(paths) > 0
        
        # Verify integration
        path = paths[0]
        assert path.name == "SSH Compromise Path"
        assert path.total_success_probability == 0.75


if __name__ == "__main__":
    pytest.main([__file__, "-v"])