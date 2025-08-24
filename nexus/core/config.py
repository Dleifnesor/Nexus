"""
Nexus Configuration Management

Handles loading, validation, and management of Nexus configuration
including AI settings, tool configurations, safety parameters, and
user preferences.
"""

import os
import yaml
import json
from pathlib import Path
from typing import Dict, Any, Optional, List, Union
from dataclasses import dataclass, field
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


@dataclass
class AIConfig:
    """AI configuration settings"""
    model: str = "huihui_ai/qwen2.5-coder-abliterate:14b"
    ollama_url: str = "http://localhost:11434"
    temperature: float = 0.7
    max_tokens: int = 2048
    timeout: int = 300
    retry_attempts: int = 3
    retry_delay: int = 5


@dataclass
class ToolConfig:
    """Individual tool configuration"""
    path: str
    default_args: List[str] = field(default_factory=list)
    timeout: int = 300
    enabled: bool = True
    custom_params: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SafetyConfig:
    """Safety and security configuration"""
    scope_validation: bool = True
    rate_limiting: bool = True
    max_concurrent_scans: int = 5
    confirmation_required: bool = False
    emergency_contacts: List[str] = field(default_factory=list)
    max_requests_per_minute: int = 60
    dangerous_command_blocking: bool = True


@dataclass
class LoggingConfig:
    """Logging configuration"""
    level: str = "INFO"
    file: Optional[str] = None
    format: str = "json"
    max_size: str = "100MB"
    backup_count: int = 5
    console_output: bool = True


@dataclass
class ReportingConfig:
    """Reporting configuration"""
    output_dir: str = "~/.nexus/reports"
    formats: List[str] = field(default_factory=lambda: ["html", "json", "pdf"])
    template_dir: str = "~/.nexus/templates"
    auto_generate: bool = True
    include_screenshots: bool = True


@dataclass
class DatabaseConfig:
    """Database configuration"""
    path: str = "~/.nexus/data/nexus.db"
    backup_interval: int = 3600  # 1 hour
    max_backups: int = 10
    encryption_enabled: bool = True


class NexusConfig:
    """Main configuration manager for Nexus"""
    
    DEFAULT_CONFIG_PATHS = [
        "~/.nexus/config/config.yaml",
        "/etc/nexus/config.yaml",
        "./config/config.yaml"
    ]
    
    def __init__(self, config_path: Optional[str] = None):
        self.config_path = config_path
        self.ai = AIConfig()
        self.tools: Dict[str, ToolConfig] = {}
        self.safety = SafetyConfig()
        self.logging = LoggingConfig()
        self.reporting = ReportingConfig()
        self.database = DatabaseConfig()
        self.custom_settings: Dict[str, Any] = {}
        
        # Load configuration
        self.load_config()
        
        # Validate configuration
        self.validate_config()
    
    def load_config(self) -> None:
        """Load configuration from file"""
        config_file = self._find_config_file()
        
        if not config_file:
            logger.warning("No configuration file found, using defaults")
            self._load_default_tools()
            return
        
        try:
            with open(config_file, 'r') as f:
                config_data = yaml.safe_load(f)
            
            self._parse_config_data(config_data)
            logger.info(f"Configuration loaded from {config_file}")
            
        except Exception as e:
            logger.error(f"Failed to load configuration: {e}")
            self._load_default_tools()
    
    def _find_config_file(self) -> Optional[str]:
        """Find the configuration file to use"""
        if self.config_path:
            if os.path.exists(os.path.expanduser(self.config_path)):
                return os.path.expanduser(self.config_path)
            else:
                logger.error(f"Specified config file not found: {self.config_path}")
                return None
        
        # Search default paths
        for path in self.DEFAULT_CONFIG_PATHS:
            expanded_path = os.path.expanduser(path)
            if os.path.exists(expanded_path):
                return expanded_path
        
        return None
    
    def _parse_config_data(self, config_data: Dict[str, Any]) -> None:
        """Parse configuration data from loaded file"""
        
        # AI configuration
        if 'ai' in config_data:
            ai_config = config_data['ai']
            self.ai = AIConfig(
                model=ai_config.get('model', self.ai.model),
                ollama_url=ai_config.get('ollama_url', self.ai.ollama_url),
                temperature=ai_config.get('temperature', self.ai.temperature),
                max_tokens=ai_config.get('max_tokens', self.ai.max_tokens),
                timeout=ai_config.get('timeout', self.ai.timeout),
                retry_attempts=ai_config.get('retry_attempts', self.ai.retry_attempts),
                retry_delay=ai_config.get('retry_delay', self.ai.retry_delay)
            )
        
        # Tools configuration
        if 'tools' in config_data:
            for tool_name, tool_config in config_data['tools'].items():
                self.tools[tool_name] = ToolConfig(
                    path=tool_config.get('path', ''),
                    default_args=tool_config.get('default_args', []),
                    timeout=tool_config.get('timeout', 300),
                    enabled=tool_config.get('enabled', True),
                    custom_params=tool_config.get('custom_params', {})
                )
        else:
            self._load_default_tools()
        
        # Safety configuration
        if 'safety' in config_data:
            safety_config = config_data['safety']
            self.safety = SafetyConfig(
                scope_validation=safety_config.get('scope_validation', True),
                rate_limiting=safety_config.get('rate_limiting', True),
                max_concurrent_scans=safety_config.get('max_concurrent_scans', 5),
                confirmation_required=safety_config.get('confirmation_required', False),
                emergency_contacts=safety_config.get('emergency_contacts', []),
                max_requests_per_minute=safety_config.get('max_requests_per_minute', 60),
                dangerous_command_blocking=safety_config.get('dangerous_command_blocking', True)
            )
        
        # Logging configuration
        if 'logging' in config_data:
            logging_config = config_data['logging']
            self.logging = LoggingConfig(
                level=logging_config.get('level', 'INFO'),
                file=logging_config.get('file'),
                format=logging_config.get('format', 'json'),
                max_size=logging_config.get('max_size', '100MB'),
                backup_count=logging_config.get('backup_count', 5),
                console_output=logging_config.get('console_output', True)
            )
        
        # Reporting configuration
        if 'reporting' in config_data:
            reporting_config = config_data['reporting']
            self.reporting = ReportingConfig(
                output_dir=reporting_config.get('output_dir', '~/.nexus/reports'),
                formats=reporting_config.get('formats', ['html', 'json', 'pdf']),
                template_dir=reporting_config.get('template_dir', '~/.nexus/templates'),
                auto_generate=reporting_config.get('auto_generate', True),
                include_screenshots=reporting_config.get('include_screenshots', True)
            )
        
        # Database configuration
        if 'database' in config_data:
            db_config = config_data['database']
            self.database = DatabaseConfig(
                path=db_config.get('path', '~/.nexus/data/nexus.db'),
                backup_interval=db_config.get('backup_interval', 3600),
                max_backups=db_config.get('max_backups', 10),
                encryption_enabled=db_config.get('encryption_enabled', True)
            )
        
        # Custom settings
        self.custom_settings = config_data.get('custom', {})
    
    def _load_default_tools(self) -> None:
        """Load default tool configurations"""
        default_tools = {
            'nmap': ToolConfig(
                path=self._find_tool_path('nmap'),
                default_args=['-sS', '-sV', '-O'],
                timeout=600
            ),
            'metasploit': ToolConfig(
                path='/usr/share/metasploit-framework',
                timeout=900,
                custom_params={'msfconsole': '/usr/bin/msfconsole'}
            ),
            'sqlmap': ToolConfig(
                path=self._find_tool_path('sqlmap'),
                timeout=1800
            ),
            'gobuster': ToolConfig(
                path=self._find_tool_path('gobuster'),
                timeout=300,
                custom_params={'wordlist': '/usr/share/wordlists/dirb/common.txt'}
            ),
            'nikto': ToolConfig(
                path=self._find_tool_path('nikto'),
                timeout=600
            ),
            'hydra': ToolConfig(
                path=self._find_tool_path('hydra'),
                timeout=900
            ),
            'john': ToolConfig(
                path=self._find_tool_path('john'),
                timeout=1800
            )
        }
        
        # Only add tools that are actually available
        for tool_name, tool_config in default_tools.items():
            if tool_config.path and os.path.exists(tool_config.path):
                self.tools[tool_name] = tool_config
            else:
                logger.warning(f"Tool {tool_name} not found at {tool_config.path}")
    
    def _find_tool_path(self, tool_name: str) -> str:
        """Find the path to a tool executable"""
        import shutil
        path = shutil.which(tool_name)
        return path if path else f"/usr/bin/{tool_name}"
    
    def validate_config(self) -> None:
        """Validate configuration settings"""
        errors = []
        
        # Validate AI configuration
        if not self.ai.ollama_url.startswith(('http://', 'https://')):
            errors.append("AI ollama_url must be a valid HTTP/HTTPS URL")
        
        if not (0.0 <= self.ai.temperature <= 2.0):
            errors.append("AI temperature must be between 0.0 and 2.0")
        
        if self.ai.max_tokens < 1:
            errors.append("AI max_tokens must be positive")
        
        # Validate tool configurations
        for tool_name, tool_config in self.tools.items():
            if tool_config.enabled and not tool_config.path:
                errors.append(f"Tool {tool_name} is enabled but has no path configured")
        
        # Validate safety configuration
        if self.safety.max_concurrent_scans < 1:
            errors.append("Safety max_concurrent_scans must be positive")
        
        if self.safety.max_requests_per_minute < 1:
            errors.append("Safety max_requests_per_minute must be positive")
        
        # Validate logging configuration
        valid_log_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
        if self.logging.level not in valid_log_levels:
            errors.append(f"Logging level must be one of: {valid_log_levels}")
        
        # Validate reporting configuration
        if not self.reporting.formats:
            errors.append("At least one reporting format must be specified")
        
        if errors:
            error_msg = "Configuration validation failed:\n" + "\n".join(f"- {error}" for error in errors)
            raise ValueError(error_msg)
        
        logger.info("Configuration validation passed")
    
    def save_config(self, path: Optional[str] = None) -> None:
        """Save current configuration to file"""
        save_path = path or self.config_path or os.path.expanduser("~/.nexus/config/config.yaml")
        
        # Ensure directory exists
        os.makedirs(os.path.dirname(save_path), exist_ok=True)
        
        config_data = {
            'ai': {
                'model': self.ai.model,
                'ollama_url': self.ai.ollama_url,
                'temperature': self.ai.temperature,
                'max_tokens': self.ai.max_tokens,
                'timeout': self.ai.timeout,
                'retry_attempts': self.ai.retry_attempts,
                'retry_delay': self.ai.retry_delay
            },
            'tools': {
                name: {
                    'path': config.path,
                    'default_args': config.default_args,
                    'timeout': config.timeout,
                    'enabled': config.enabled,
                    'custom_params': config.custom_params
                }
                for name, config in self.tools.items()
            },
            'safety': {
                'scope_validation': self.safety.scope_validation,
                'rate_limiting': self.safety.rate_limiting,
                'max_concurrent_scans': self.safety.max_concurrent_scans,
                'confirmation_required': self.safety.confirmation_required,
                'emergency_contacts': self.safety.emergency_contacts,
                'max_requests_per_minute': self.safety.max_requests_per_minute,
                'dangerous_command_blocking': self.safety.dangerous_command_blocking
            },
            'logging': {
                'level': self.logging.level,
                'file': self.logging.file,
                'format': self.logging.format,
                'max_size': self.logging.max_size,
                'backup_count': self.logging.backup_count,
                'console_output': self.logging.console_output
            },
            'reporting': {
                'output_dir': self.reporting.output_dir,
                'formats': self.reporting.formats,
                'template_dir': self.reporting.template_dir,
                'auto_generate': self.reporting.auto_generate,
                'include_screenshots': self.reporting.include_screenshots
            },
            'database': {
                'path': self.database.path,
                'backup_interval': self.database.backup_interval,
                'max_backups': self.database.max_backups,
                'encryption_enabled': self.database.encryption_enabled
            },
            'custom': self.custom_settings
        }
        
        try:
            with open(save_path, 'w') as f:
                yaml.dump(config_data, f, default_flow_style=False, indent=2)
            
            logger.info(f"Configuration saved to {save_path}")
            
        except Exception as e:
            logger.error(f"Failed to save configuration: {e}")
            raise
    
    def get_tool_config(self, tool_name: str) -> Optional[ToolConfig]:
        """Get configuration for a specific tool"""
        return self.tools.get(tool_name)
    
    def set_tool_config(self, tool_name: str, config: ToolConfig) -> None:
        """Set configuration for a specific tool"""
        self.tools[tool_name] = config
    
    def get_setting(self, key: str, default: Any = None) -> Any:
        """Get a custom setting value"""
        return self.custom_settings.get(key, default)
    
    def set_setting(self, key: str, value: Any) -> None:
        """Set a custom setting value"""
        self.custom_settings[key] = value
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary"""
        return {
            'ai': self.ai.__dict__,
            'tools': {name: config.__dict__ for name, config in self.tools.items()},
            'safety': self.safety.__dict__,
            'logging': self.logging.__dict__,
            'reporting': self.reporting.__dict__,
            'database': self.database.__dict__,
            'custom': self.custom_settings
        }
    
    def get_timestamp(self) -> str:
        """Get current timestamp in ISO format"""
        return datetime.now().isoformat()
    
    def __str__(self) -> str:
        """String representation of configuration"""
        return json.dumps(self.to_dict(), indent=2, default=str)