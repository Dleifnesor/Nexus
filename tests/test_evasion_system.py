"""
Comprehensive Tests for Nexus Evasion System

Tests for evasion profiles, techniques, detection avoidance, and behavioral mimicry.
"""

import pytest
import asyncio
import json
from unittest.mock import Mock, AsyncMock, patch
from datetime import datetime, timedelta

from nexus.core.evasion import (
    EvasionManager, EvasionProfile, EvasionTechnique, DetectionRisk,
    TrafficPattern, EvasionIntegration
)
from nexus.core.config import NexusConfig


class TestEvasionManager:
    """Test cases for the Evasion Manager"""
    
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
        config.ai.model = "huihui_ai/qwen2.5-abliterate:14b"
        config.ai.temperature = 0.7
        config.ai.max_tokens = 2048
        return config
    
    @pytest.fixture
    def evasion_manager(self, mock_ollama_client, mock_config):
        """Create evasion manager instance"""
        return EvasionManager(mock_ollama_client, mock_config)
    
    def test_evasion_manager_initialization(self, evasion_manager):
        """Test evasion manager initialization"""
        assert evasion_manager.ollama_client is not None
        assert evasion_manager.config is not None
        assert evasion_manager.active_profile is None
        assert len(evasion_manager.profiles) > 0
        assert len(evasion_manager.traffic_patterns) > 0
        assert evasion_manager.detection_history == []
    
    def test_built_in_profiles_loaded(self, evasion_manager):
        """Test that built-in evasion profiles are loaded"""
        profiles = evasion_manager.get_available_profiles()
        
        # Check that key profiles exist
        assert "stealth_maximum" in profiles
        assert "stealth_balanced" in profiles
        assert "stealth_minimal" in profiles
        assert "red_team" in profiles
        assert "apt_simulation" in profiles
        
        # Verify profile structure
        max_stealth = profiles["stealth_maximum"]
        assert isinstance(max_stealth, EvasionProfile)
        assert max_stealth.name == "Maximum Stealth"
        assert max_stealth.detection_risk == DetectionRisk.VERY_LOW
        assert max_stealth.stealth_rating > 0.9
        assert len(max_stealth.techniques) > 5
    
    def test_traffic_patterns_loaded(self, evasion_manager):
        """Test that traffic patterns are loaded"""
        patterns = evasion_manager.traffic_patterns
        
        assert "normal_browsing" in patterns
        assert "api_client" in patterns
        assert "mobile_app" in patterns
        
        # Verify pattern structure
        browsing = patterns["normal_browsing"]
        assert isinstance(browsing, TrafficPattern)
        assert len(browsing.request_intervals) > 0
        assert len(browsing.user_agents) > 0
        assert len(browsing.headers) > 0
    
    def test_set_evasion_profile(self, evasion_manager):
        """Test setting evasion profile"""
        # Test valid profile
        assert evasion_manager.set_evasion_profile("stealth_balanced")
        assert evasion_manager.active_profile is not None
        assert evasion_manager.active_profile.name == "Balanced Stealth"
        
        # Test invalid profile
        assert not evasion_manager.set_evasion_profile("nonexistent_profile")
    
    @pytest.mark.asyncio
    async def test_timing_randomization(self, evasion_manager):
        """Test timing randomization functionality"""
        # Without active profile
        base_delay = 5.0
        result = await evasion_manager.apply_timing_randomization(base_delay)
        assert result == base_delay  # Should return unchanged
        
        # With active profile
        evasion_manager.set_evasion_profile("stealth_balanced")
        result = await evasion_manager.apply_timing_randomization(base_delay)
        assert result != base_delay  # Should be randomized
        assert result > 0.1  # Minimum delay
        assert result < base_delay * 3  # Reasonable upper bound
    
    def test_payload_encoding(self, evasion_manager):
        """Test payload encoding functionality"""
        test_payload = "SELECT * FROM users"
        
        # Without active profile
        result = evasion_manager.apply_payload_encoding(test_payload)
        assert result == test_payload  # Should return unchanged
        
        # With active profile
        evasion_manager.set_evasion_profile("stealth_balanced")
        
        # Test different encoding types
        base64_result = evasion_manager.apply_payload_encoding(test_payload, "base64")
        assert base64_result != test_payload
        assert len(base64_result) > 0
        
        url_result = evasion_manager.apply_payload_encoding(test_payload, "url")
        assert url_result != test_payload
        assert "%20" in url_result or "+" in url_result  # URL encoding
        
        hex_result = evasion_manager.apply_payload_encoding(test_payload, "hex")
        assert hex_result != test_payload
        assert all(c in "0123456789abcdef" for c in hex_result)
    
    def test_user_agent_rotation(self, evasion_manager):
        """Test user agent rotation"""
        # Without active profile
        ua1 = evasion_manager.get_random_user_agent()
        assert "Mozilla" in ua1  # Should return default
        
        # With active profile
        evasion_manager.set_evasion_profile("stealth_balanced")
        
        # Get multiple user agents
        user_agents = set()
        for _ in range(10):
            ua = evasion_manager.get_random_user_agent()
            user_agents.add(ua)
            assert "Mozilla" in ua or "curl" in ua or "python" in ua
        
        # Should have some variety (not all the same)
        assert len(user_agents) > 1
    
    def test_decoy_traffic_generation(self, evasion_manager):
        """Test decoy traffic generation"""
        target_url = "https://example.com"
        
        # Without active profile
        decoys = evasion_manager.generate_decoy_requests(target_url)
        assert len(decoys) == 0  # Should return empty list
        
        # With active profile
        evasion_manager.set_evasion_profile("red_team")
        decoys = evasion_manager.generate_decoy_requests(target_url, 3)
        
        assert len(decoys) == 3
        for decoy in decoys:
            assert "url" in decoy
            assert decoy["url"].startswith(target_url)
            assert "method" in decoy
            assert "headers" in decoy
            assert "delay" in decoy
            assert decoy["delay"] > 0
    
    @pytest.mark.asyncio
    async def test_behavioral_mimicry(self, evasion_manager):
        """Test behavioral mimicry functionality"""
        # Without active profile
        behavior = await evasion_manager.apply_behavioral_mimicry("web_scan")
        assert behavior == {}  # Should return empty dict
        
        # With active profile
        evasion_manager.set_evasion_profile("stealth_balanced")
        
        # Test different operation types
        web_behavior = await evasion_manager.apply_behavioral_mimicry("web_scan")
        assert "request_interval" in web_behavior
        assert "user_agent" in web_behavior
        assert "headers" in web_behavior
        
        api_behavior = await evasion_manager.apply_behavioral_mimicry("api_test")
        assert "request_interval" in api_behavior
        
        # Behaviors should be different for different operation types
        assert web_behavior != api_behavior
    
    def test_payload_fragmentation(self, evasion_manager):
        """Test payload fragmentation"""
        test_payload = "This is a test payload for fragmentation"
        
        # Without active profile
        fragments = evasion_manager.fragment_payload(test_payload)
        assert fragments == [test_payload]  # Should return unchanged
        
        # With active profile
        evasion_manager.set_evasion_profile("stealth_maximum")
        fragments = evasion_manager.fragment_payload(test_payload, 8)
        
        assert len(fragments) > 1
        assert "".join(fragments) == test_payload  # Should reconstruct original
        assert all(len(frag) <= 8 for frag in fragments[:-1])  # All but last should be max size
    
    def test_detection_probability_calculation(self, evasion_manager):
        """Test detection probability calculation"""
        operation_params = {
            "request_rate": 5,
            "payload_size": 500,
            "target": "example.com"
        }
        
        # Without active profile
        prob_no_profile = evasion_manager.calculate_detection_probability(operation_params)
        assert 0.0 <= prob_no_profile <= 1.0
        
        # With minimal stealth profile
        evasion_manager.set_evasion_profile("stealth_minimal")
        prob_minimal = evasion_manager.calculate_detection_probability(operation_params)
        
        # With maximum stealth profile
        evasion_manager.set_evasion_profile("stealth_maximum")
        prob_maximum = evasion_manager.calculate_detection_probability(operation_params)
        
        # Maximum stealth should have lower detection probability
        assert prob_maximum < prob_minimal
        assert prob_maximum < prob_no_profile
        
        # All probabilities should be valid
        assert 0.0 <= prob_minimal <= 1.0
        assert 0.0 <= prob_maximum <= 1.0
    
    @pytest.mark.asyncio
    async def test_ai_evasion_strategy_generation(self, evasion_manager, mock_ollama_client):
        """Test AI-powered evasion strategy generation"""
        target_info = {
            "host": "example.com",
            "services": ["http", "https"],
            "os": "Linux",
            "security_controls": ["firewall", "ids"]
        }
        
        # Mock AI response
        mock_strategy = {
            "timing_pattern": "randomized_intervals",
            "encoding_method": "base64",
            "obfuscation": "user_agent_rotation",
            "mimicry": "normal_browsing",
            "rationale": "Target has IDS, recommend high stealth"
        }
        
        mock_ollama_client.generate_response.return_value = json.dumps(mock_strategy)
        
        strategy = await evasion_manager.generate_ai_evasion_strategy(target_info, "web_scan")
        
        assert strategy == mock_strategy
        assert "timing_pattern" in strategy
        assert "encoding_method" in strategy
        assert "rationale" in strategy
        
        # Verify AI was called with appropriate prompt
        mock_ollama_client.generate_response.assert_called_once()
        call_args = mock_ollama_client.generate_response.call_args[0][0]
        assert "example.com" in call_args
        assert "web_scan" in call_args
    
    def test_detection_event_logging(self, evasion_manager):
        """Test detection event logging"""
        event_details = {
            "target": "example.com",
            "operation": "port_scan",
            "request_rate": 10
        }
        
        # Log an event
        evasion_manager.log_detection_event("scan_detected", event_details)
        
        assert len(evasion_manager.detection_history) == 1
        event = evasion_manager.detection_history[0]
        
        assert event["event_type"] == "scan_detected"
        assert event["details"] == event_details
        assert "timestamp" in event
        assert "detection_probability" in event
        
        # Test history limit
        for i in range(1005):  # Exceed the 1000 limit
            evasion_manager.log_detection_event(f"test_event_{i}", {"test": i})
        
        assert len(evasion_manager.detection_history) == 1000  # Should be capped
    
    def test_evasion_report_generation(self, evasion_manager):
        """Test evasion report generation"""
        # Without active profile
        report = evasion_manager.get_evasion_report()
        assert "error" in report
        
        # With active profile
        evasion_manager.set_evasion_profile("stealth_balanced")
        
        # Add some test events
        for i in range(5):
            evasion_manager.log_detection_event("test_event", {"test": i})
        
        report = evasion_manager.get_evasion_report()
        
        assert "active_profile" in report
        assert "statistics" in report
        assert "recommendations" in report
        
        # Verify profile info
        profile_info = report["active_profile"]
        assert profile_info["name"] == "Balanced Stealth"
        assert "techniques" in profile_info
        assert "stealth_rating" in profile_info
        
        # Verify statistics
        stats = report["statistics"]
        assert stats["total_events"] == 5
        assert "average_detection_probability" in stats


class TestEvasionIntegration:
    """Test cases for Evasion Integration"""
    
    @pytest.fixture
    def mock_evasion_manager(self):
        """Mock evasion manager for testing"""
        manager = Mock()
        manager.apply_timing_randomization = AsyncMock(return_value=2.5)
        manager.apply_behavioral_mimicry = AsyncMock(return_value={
            "user_agent": "Mozilla/5.0 Test",
            "headers": {"Accept": "text/html"}
        })
        manager.generate_decoy_requests = Mock(return_value=[
            {"url": "http://example.com/test", "method": "GET"}
        ])
        manager.apply_payload_encoding = Mock(return_value="encoded_payload")
        manager.get_random_user_agent = Mock(return_value="Mozilla/5.0 Test")
        return manager
    
    @pytest.fixture
    def evasion_integration(self, mock_evasion_manager):
        """Create evasion integration instance"""
        return EvasionIntegration(mock_evasion_manager)
    
    @pytest.mark.asyncio
    async def test_prepare_tool_execution(self, evasion_integration, mock_evasion_manager):
        """Test tool execution preparation with evasion"""
        tool_name = "nmap"
        target = "192.168.1.100"
        params = {"timeout": 300}
        
        result = await evasion_integration.prepare_tool_execution(tool_name, target, params)
        
        # Should have added delay
        assert "delay" in result
        assert result["delay"] == 2.5
        
        # Should have applied behavioral mimicry
        assert "user_agent" in result
        assert result["user_agent"] == "Mozilla/5.0 Test"
        
        # Verify mocks were called
        mock_evasion_manager.apply_timing_randomization.assert_called_once()
        mock_evasion_manager.apply_behavioral_mimicry.assert_called_once_with(tool_name)
    
    @pytest.mark.asyncio
    async def test_web_tool_preparation(self, evasion_integration, mock_evasion_manager):
        """Test preparation for web scanning tools"""
        tool_name = "nikto"
        target = "https://example.com"
        params = {}
        
        result = await evasion_integration.prepare_tool_execution(tool_name, target, params)
        
        # Should have decoy requests for web tools
        assert "decoy_requests" in result
        mock_evasion_manager.generate_decoy_requests.assert_called_once_with(target)
    
    @pytest.mark.asyncio
    async def test_injection_tool_preparation(self, evasion_integration, mock_evasion_manager):
        """Test preparation for injection testing tools"""
        tool_name = "sqlmap"
        target = "https://example.com"
        params = {"payload": "' OR 1=1--"}
        
        result = await evasion_integration.prepare_tool_execution(tool_name, target, params)
        
        # Should have encoded payload
        assert result["payload"] == "encoded_payload"
        mock_evasion_manager.apply_payload_encoding.assert_called_once_with("' OR 1=1--")
    
    def test_stealth_headers_generation(self, evasion_integration, mock_evasion_manager):
        """Test stealth header generation"""
        headers = evasion_integration.get_stealth_headers("web_scan")
        
        assert "User-Agent" in headers
        assert "Accept" in headers
        assert "Accept-Language" in headers
        assert "Connection" in headers
        
        # Test API-specific headers
        api_headers = evasion_integration.get_stealth_headers("api_test")
        assert api_headers["Content-Type"] == "application/json"
        assert api_headers["Accept"] == "application/json"


class TestEvasionProfiles:
    """Test cases for evasion profiles"""
    
    def test_evasion_profile_creation(self):
        """Test evasion profile creation"""
        profile = EvasionProfile(
            name="Test Profile",
            description="Test description",
            techniques=[EvasionTechnique.TIMING_RANDOMIZATION, EvasionTechnique.PAYLOAD_ENCODING],
            detection_risk=DetectionRisk.LOW,
            performance_impact=0.3,
            stealth_rating=0.7,
            complexity="medium"
        )
        
        assert profile.name == "Test Profile"
        assert len(profile.techniques) == 2
        assert profile.detection_risk == DetectionRisk.LOW
        assert profile.stealth_rating == 0.7
    
    def test_traffic_pattern_creation(self):
        """Test traffic pattern creation"""
        pattern = TrafficPattern(
            name="Test Pattern",
            description="Test description",
            request_intervals=[1.0, 2.0, 3.0],
            burst_patterns=[5, 10],
            idle_periods=[30.0, 60.0],
            user_agents=["Mozilla/5.0 Test"],
            headers={"Accept": ["text/html"]}
        )
        
        assert pattern.name == "Test Pattern"
        assert len(pattern.request_intervals) == 3
        assert len(pattern.burst_patterns) == 2
        assert len(pattern.user_agents) == 1


class TestEvasionTechniques:
    """Test cases for individual evasion techniques"""
    
    @pytest.fixture
    def evasion_manager(self):
        """Create evasion manager for technique testing"""
        mock_client = Mock()
        mock_config = Mock()
        return EvasionManager(mock_client, mock_config)
    
    def test_timing_randomization_bounds(self, evasion_manager):
        """Test timing randomization stays within reasonable bounds"""
        evasion_manager.set_evasion_profile("stealth_maximum")
        
        base_delays = [1.0, 5.0, 10.0, 30.0]
        
        for base_delay in base_delays:
            # Test multiple randomizations
            results = []
            for _ in range(100):
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                result = loop.run_until_complete(
                    evasion_manager.apply_timing_randomization(base_delay)
                )
                loop.close()
                results.append(result)
            
            # All results should be positive
            assert all(r > 0 for r in results)
            
            # Should have some variation
            assert len(set(results)) > 1
            
            # Should be within reasonable bounds
            assert all(r < base_delay * 5 for r in results)
    
    def test_encoding_reversibility(self, evasion_manager):
        """Test that encoding techniques preserve data integrity"""
        evasion_manager.set_evasion_profile("stealth_maximum")
        
        test_payloads = [
            "SELECT * FROM users",
            "<script>alert('xss')</script>",
            "../../etc/passwd",
            "' OR 1=1--",
            "admin'; DROP TABLE users;--"
        ]
        
        for payload in test_payloads:
            # Test base64 encoding
            encoded = evasion_manager.apply_payload_encoding(payload, "base64")
            assert encoded != payload
            
            # Should be valid base64
            import base64
            try:
                decoded = base64.b64decode(encoded).decode()
                assert decoded == payload
            except Exception:
                pytest.fail(f"Base64 encoding failed for payload: {payload}")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])