"""
Nexus AI-Powered Penetration Testing Tool

A comprehensive AI-driven penetration testing automation framework
designed for professional red team assessments and authorized
penetration testing engagements.

Author: Nexus Development Team
Version: 1.0.0
License: MIT
"""

__version__ = "1.0.0"
__author__ = "Nexus Development Team"
__email__ = "nexus@security.tools"
__description__ = "AI-Powered Penetration Testing Automation Tool"

# Core imports - only import what actually exists
from .core.config import NexusConfig
from .ai.ollama_client import OllamaClient

__all__ = [
    "NexusConfig",
    "OllamaClient"
]