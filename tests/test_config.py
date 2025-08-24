"""
Test Configuration Management

Tests for the Nexus configuration system including loading,
validation, and management of configuration settings.
"""

import os
import tempfile
import pytest
import yaml
from pathlib import Path

from nexus.core.config import NexusConfig, AIConfig, ToolConfig, SafetyConfig


class TestNexusConfig:
    """Test cases for NexusConfig class"""
    
    def test_default_config_creation(self):
        """Test creating config with defaults"""
        config = NexusConfig()
        
        assert config.ai.model == "huihui_ai/qwen2.5-coder-abliterate:14b"
        assert config.ai.ollama_url == "http://localhost:11434"
        assert config.ai.temperature == 0.7
        assert config.safety.scope_validation is True
        assert config.safety.rate_limiting is True
    
    def test_config_validation_valid(self):
        """Test validation with valid configuration"""
        config = NexusConfig()
        # Should not raise any exception
        config.validate_config()
    
    def test_config_validation_invalid_temperature(self):
        """Test validation with invalid temperature"""
        config = NexusConfig()
        config.ai.temperature = 3.0  # Invalid: > 2.0
        
        with pytest.raises(ValueError, match="AI temperature must be between 0.0 and 2.0"):
            config.validate_config()
    
    def test_config_validation_invalid_url(self):
        """Test validation with invalid Ollama URL"""
        config = NexusConfig()
        config.ai.ollama_url = "invalid-url"
        
        with pytest.raises(ValueError, match="AI ollama_url must be a valid HTTP/HTTPS URL"):
            config.validate_config()
    
    def test_config_save_and_load(self):
        """Test saving and loading configuration"""
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = os.path.join(temp_dir, "test_config.yaml")
            
            # Create and modify config
            config = NexusConfig()
            config.ai.temperature = 0.5
            config.safety.max_concurrent_scans = 3
            
            # Save config
            config.save_config(config_path)
            
            # Load config
            new_config = NexusConfig(config_path)
            
            assert new_config.ai.temperature == 0.5
            assert new_config.safety.max_concurrent_scans == 3
    
    def test_tool_config_management(self):
        """Test tool configuration management"""
        config = NexusConfig()
        
        # Add new tool config
        tool_config = ToolConfig(
            path="/usr/bin/test-tool",
            default_args=["--test"],
            timeout=120,
            enabled=True
        )
        
        config.set_tool_config("test-tool", tool_config)
        
        # Retrieve tool config
        retrieved_config = config.get_tool_config("test-tool")
        
        assert retrieved_config is not None
        assert retrieved_config.path == "/usr/bin/test-tool"
        assert retrieved_config.default_args == ["--test"]
        assert retrieved_config.timeout == 120
        assert retrieved_config.enabled is True
    
    def test_custom_settings(self):
        """Test custom settings management"""
        config = NexusConfig()
        
        # Set custom setting
        config.set_setting("custom_key", "custom_value")
        
        # Get custom setting
        value = config.get_setting("custom_key")
        assert value == "custom_value"
        
        # Get non-existent setting with default
        default_value = config.get_setting("non_existent", "default")
        assert default_value == "default"
    
    def test_config_to_dict(self):
        """Test configuration serialization to dictionary"""
        config = NexusConfig()
        config_dict = config.to_dict()
        
        assert "ai" in config_dict
        assert "tools" in config_dict
        assert "safety" in config_dict
        assert "logging" in config_dict
        assert "reporting" in config_dict
        assert "database" in config_dict
        
        # Check AI config structure
        assert "model" in config_dict["ai"]
        assert "ollama_url" in config_dict["ai"]
        assert "temperature" in config_dict["ai"]


class TestAIConfig:
    """Test cases for AIConfig dataclass"""
    
    def test_ai_config_defaults(self):
        """Test AI config default values"""
        ai_config = AIConfig()
        
        assert ai_config.model == "huihui_ai/qwen2.5-coder-abliterate:14b"
        assert ai_config.ollama_url == "http://localhost:11434"
        assert ai_config.temperature == 0.7
        assert ai_config.max_tokens == 2048
        assert ai_config.timeout == 300
        assert ai_config.retry_attempts == 3
        assert ai_config.retry_delay == 5
    
    def test_ai_config_custom_values(self):
        """Test AI config with custom values"""
        ai_config = AIConfig(
            model="custom-model",
            ollama_url="http://remote:11434",
            temperature=0.9,
            max_tokens=4096,
            timeout=600
        )
        
        assert ai_config.model == "custom-model"
        assert ai_config.ollama_url == "http://remote:11434"
        assert ai_config.temperature == 0.9
        assert ai_config.max_tokens == 4096
        assert ai_config.timeout == 600


class TestToolConfig:
    """Test cases for ToolConfig dataclass"""
    
    def test_tool_config_defaults(self):
        """Test tool config default values"""
        tool_config = ToolConfig(path="/usr/bin/tool")
        
        assert tool_config.path == "/usr/bin/tool"
        assert tool_config.default_args == []
        assert tool_config.timeout == 300
        assert tool_config.enabled is True
        assert tool_config.custom_params == {}
    
    def test_tool_config_custom_values(self):
        """Test tool config with custom values"""
        tool_config = ToolConfig(
            path="/custom/path/tool",
            default_args=["--arg1", "--arg2"],
            timeout=600,
            enabled=False,
            custom_params={"param1": "value1"}
        )
        
        assert tool_config.path == "/custom/path/tool"
        assert tool_config.default_args == ["--arg1", "--arg2"]
        assert tool_config.timeout == 600
        assert tool_config.enabled is False
        assert tool_config.custom_params == {"param1": "value1"}


class TestSafetyConfig:
    """Test cases for SafetyConfig dataclass"""
    
    def test_safety_config_defaults(self):
        """Test safety config default values"""
        safety_config = SafetyConfig()
        
        assert safety_config.scope_validation is True
        assert safety_config.rate_limiting is True
        assert safety_config.max_concurrent_scans == 5
        assert safety_config.confirmation_required is False
        assert safety_config.emergency_contacts == []
        assert safety_config.max_requests_per_minute == 60
        assert safety_config.dangerous_command_blocking is True
    
    def test_safety_config_custom_values(self):
        """Test safety config with custom values"""
        safety_config = SafetyConfig(
            scope_validation=False,
            rate_limiting=False,
            max_concurrent_scans=10,
            confirmation_required=True,
            emergency_contacts=["admin@example.com"],
            max_requests_per_minute=120,
            dangerous_command_blocking=False
        )
        
        assert safety_config.scope_validation is False
        assert safety_config.rate_limiting is False
        assert safety_config.max_concurrent_scans == 10
        assert safety_config.confirmation_required is True
        assert safety_config.emergency_contacts == ["admin@example.com"]
        assert safety_config.max_requests_per_minute == 120
        assert safety_config.dangerous_command_blocking is False


class TestConfigFileHandling:
    """Test cases for configuration file handling"""
    
    def test_load_yaml_config(self):
        """Test loading configuration from YAML file"""
        config_data = {
            "ai": {
                "model": "test-model",
                "temperature": 0.8,
                "max_tokens": 1024
            },
            "safety": {
                "scope_validation": False,
                "max_concurrent_scans": 3
            },
            "tools": {
                "nmap": {
                    "path": "/custom/nmap",
                    "timeout": 300,
                    "enabled": True
                }
            }
        }
        
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = os.path.join(temp_dir, "test_config.yaml")
            
            # Write test config
            with open(config_path, 'w') as f:
                yaml.dump(config_data, f)
            
            # Load config
            config = NexusConfig(config_path)
            
            assert config.ai.model == "test-model"
            assert config.ai.temperature == 0.8
            assert config.ai.max_tokens == 1024
            assert config.safety.scope_validation is False
            assert config.safety.max_concurrent_scans == 3
            assert "nmap" in config.tools
            assert config.tools["nmap"].path == "/custom/nmap"
    
    def test_config_file_not_found(self):
        """Test handling of missing configuration file"""
        # Should not raise exception, should use defaults
        config = NexusConfig("/non/existent/path.yaml")
        
        # Should have default values
        assert config.ai.model == "huihui_ai/qwen2.5-coder-abliterate:14b"
        assert config.safety.scope_validation is True
    
    def test_invalid_yaml_config(self):
        """Test handling of invalid YAML configuration"""
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = os.path.join(temp_dir, "invalid_config.yaml")
            
            # Write invalid YAML
            with open(config_path, 'w') as f:
                f.write("invalid: yaml: content: [")
            
            # Should not raise exception, should use defaults
            config = NexusConfig(config_path)
            
            # Should have default values
            assert config.ai.model == "huihui_ai/qwen2.5-coder-abliterate:14b"


if __name__ == "__main__":
    pytest.main([__file__])