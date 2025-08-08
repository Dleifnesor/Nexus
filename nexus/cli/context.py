"""
Nexus CLI Context

Provides context management for CLI commands with configuration,
client initialization, and state management.
"""

import click
from typing import Optional
from nexus.core.config import NexusConfig
from nexus.ai.ollama_client import OllamaClient
from nexus.tools.kali_tools import KaliToolsManager
from nexus.core.script_generator import CustomScriptGenerator


class NexusContext:
    """Context object to pass configuration and state between commands"""
    
    def __init__(self):
        self.config: Optional[NexusConfig] = None
        self.ollama_client: Optional[OllamaClient] = None
        self.tools_manager: Optional[KaliToolsManager] = None
        self.script_generator: Optional[CustomScriptGenerator] = None
        self.verbose: bool = False
        self.config_path: Optional[str] = None
    
    def load_config(self, config_path: Optional[str] = None):
        """Load Nexus configuration"""
        try:
            self.config = NexusConfig(config_path or self.config_path)
        except Exception as e:
            raise click.ClickException(f"Configuration error: {e}")
    
    def get_ollama_client(self) -> OllamaClient:
        """Get or create Ollama client"""
        if not self.ollama_client:
            if not self.config:
                self.load_config()
            
            self.ollama_client = OllamaClient(
                base_url=self.config.ai.ollama_url,
                timeout=self.config.ai.timeout
            )
        
        return self.ollama_client
    
    def get_tools_manager(self) -> KaliToolsManager:
        """Get or create tools manager"""
        if not self.tools_manager:
            self.tools_manager = KaliToolsManager()
        return self.tools_manager
    
    def get_script_generator(self) -> CustomScriptGenerator:
        """Get or create script generator"""
        if not self.script_generator:
            if not self.config:
                self.load_config()
            
            ollama_client = self.get_ollama_client()
            self.script_generator = CustomScriptGenerator(ollama_client, self.config)
        
        return self.script_generator


# Global context decorator
pass_context = click.make_pass_decorator(NexusContext, ensure=True)