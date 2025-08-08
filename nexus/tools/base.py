"""
Base Tool Adapter

Base classes and interfaces for tool integration in Nexus.
Provides common functionality for all penetration testing tools.
"""

import time
import subprocess
import logging
from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)


class ToolStatus(Enum):
    """Tool execution status"""
    SUCCESS = "success"
    FAILED = "failed"
    TIMEOUT = "timeout"
    ERROR = "error"


@dataclass
class ToolResult:
    """Result of tool execution"""
    tool_name: str
    command: str
    status: ToolStatus
    raw_output: str
    parsed_data: Dict[str, Any]
    execution_time: float
    error_message: Optional[str] = None
    return_code: Optional[int] = None


class BaseToolAdapter(ABC):
    """Base class for all tool adapters"""
    
    def __init__(self, tool_path: str, default_args: List[str] = None):
        self.tool_path = tool_path
        self.default_args = default_args or []
        self.timeout = 300  # 5 minutes default
        self.logger = logging.getLogger(f"nexus.tools.{self.__class__.__name__}")
    
    @abstractmethod
    def build_command(self, target: str, **kwargs) -> List[str]:
        """Build the command to execute"""
        pass
    
    @abstractmethod
    def parse_output(self, raw_output: str) -> Dict[str, Any]:
        """Parse tool output into structured data"""
        pass
    
    def execute(self, target: str, **kwargs) -> ToolResult:
        """Execute the tool and return parsed results"""
        start_time = time.time()
        command = self.build_command(target, **kwargs)
        command_str = " ".join(command)
        
        self.logger.info(f"Executing: {command_str}")
        
        try:
            # Set timeout from kwargs or use default
            timeout = kwargs.get('timeout', self.timeout)
            
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=kwargs.get('working_directory')
            )
            
            execution_time = time.time() - start_time
            
            if result.returncode == 0:
                parsed_data = self.parse_output(result.stdout)
                status = ToolStatus.SUCCESS
                error_message = None
            else:
                # Some tools output to stderr even on success
                output_to_parse = result.stdout if result.stdout else result.stderr
                parsed_data = self.parse_output(output_to_parse)
                status = ToolStatus.FAILED
                error_message = result.stderr
            
            return ToolResult(
                tool_name=self.__class__.__name__,
                command=command_str,
                status=status,
                raw_output=result.stdout,
                parsed_data=parsed_data,
                execution_time=execution_time,
                error_message=error_message,
                return_code=result.returncode
            )
            
        except subprocess.TimeoutExpired:
            execution_time = time.time() - start_time
            self.logger.error(f"Tool execution timed out after {timeout} seconds")
            
            return ToolResult(
                tool_name=self.__class__.__name__,
                command=command_str,
                status=ToolStatus.TIMEOUT,
                raw_output="",
                parsed_data={},
                execution_time=execution_time,
                error_message=f"Command timed out after {timeout} seconds",
                return_code=-1
            )
            
        except Exception as e:
            execution_time = time.time() - start_time
            self.logger.error(f"Tool execution failed: {e}")
            
            return ToolResult(
                tool_name=self.__class__.__name__,
                command=command_str,
                status=ToolStatus.ERROR,
                raw_output="",
                parsed_data={},
                execution_time=execution_time,
                error_message=str(e),
                return_code=-1
            )
    
    def validate_target(self, target: str) -> bool:
        """Validate target format (can be overridden by subclasses)"""
        if not target or not target.strip():
            return False
        return True
    
    def get_tool_info(self) -> Dict[str, Any]:
        """Get information about this tool"""
        return {
            'name': self.__class__.__name__,
            'path': self.tool_path,
            'default_args': self.default_args,
            'timeout': self.timeout
        }


class NetworkToolAdapter(BaseToolAdapter):
    """Base class for network-based tools"""
    
    def validate_target(self, target: str) -> bool:
        """Validate network target (IP, hostname, or URL)"""
        if not super().validate_target(target):
            return False
        
        # Basic validation for network targets
        import re
        
        # IP address pattern
        ip_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        
        # Hostname pattern
        hostname_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
        
        # URL pattern
        url_pattern = r'^https?://.+'
        
        return (re.match(ip_pattern, target) or 
                re.match(hostname_pattern, target) or 
                re.match(url_pattern, target))


class WebToolAdapter(BaseToolAdapter):
    """Base class for web application tools"""
    
    def validate_target(self, target: str) -> bool:
        """Validate web target (URL)"""
        if not super().validate_target(target):
            return False
        
        return target.startswith(('http://', 'https://'))
    
    def build_headers(self, **kwargs) -> Dict[str, str]:
        """Build HTTP headers for web requests"""
        headers = {
            'User-Agent': kwargs.get('user_agent', 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36')
        }
        
        # Add custom headers
        custom_headers = kwargs.get('headers', {})
        headers.update(custom_headers)
        
        return headers


class DatabaseToolAdapter(BaseToolAdapter):
    """Base class for database tools"""
    
    def validate_target(self, target: str) -> bool:
        """Validate database target"""
        if not super().validate_target(target):
            return False
        
        # Database targets can be connection strings or hostnames
        return True


class WirelessToolAdapter(BaseToolAdapter):
    """Base class for wireless tools"""
    
    def validate_target(self, target: str) -> bool:
        """Validate wireless target (interface, BSSID, etc.)"""
        if not super().validate_target(target):
            return False
        
        # Wireless targets can be interfaces or MAC addresses
        import re
        
        # MAC address pattern
        mac_pattern = r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$'
        
        # Interface pattern (e.g., wlan0, wlan0mon)
        interface_pattern = r'^[a-zA-Z]+[0-9]+(?:mon)?$'
        
        return (re.match(mac_pattern, target) or 
                re.match(interface_pattern, target))


class FileToolAdapter(BaseToolAdapter):
    """Base class for file-based tools"""
    
    def validate_target(self, target: str) -> bool:
        """Validate file target"""
        if not super().validate_target(target):
            return False
        
        import os
        return os.path.exists(target) or target == '-'  # '-' for stdin


class PasswordToolAdapter(BaseToolAdapter):
    """Base class for password attack tools"""
    
    def build_wordlist_args(self, **kwargs) -> List[str]:
        """Build wordlist arguments"""
        args = []
        
        wordlist = kwargs.get('wordlist')
        if wordlist:
            args.extend(['-w', wordlist])
        
        return args
    
    def build_credential_args(self, **kwargs) -> List[str]:
        """Build credential arguments"""
        args = []
        
        username = kwargs.get('username')
        if username:
            args.extend(['-l', username])
        
        username_list = kwargs.get('username_list')
        if username_list:
            args.extend(['-L', username_list])
        
        password = kwargs.get('password')
        if password:
            args.extend(['-p', password])
        
        password_list = kwargs.get('password_list')
        if password_list:
            args.extend(['-P', password_list])
        
        return args


class ExploitToolAdapter(BaseToolAdapter):
    """Base class for exploitation tools"""
    
    def build_payload_args(self, **kwargs) -> List[str]:
        """Build payload arguments"""
        args = []
        
        payload = kwargs.get('payload')
        if payload:
            args.extend(['--payload', payload])
        
        lhost = kwargs.get('lhost')
        if lhost:
            args.extend(['--lhost', lhost])
        
        lport = kwargs.get('lport')
        if lport:
            args.extend(['--lport', str(lport)])
        
        return args


class ForensicsToolAdapter(BaseToolAdapter):
    """Base class for forensics tools"""
    
    def build_output_args(self, **kwargs) -> List[str]:
        """Build output arguments for forensics tools"""
        args = []
        
        output_dir = kwargs.get('output_dir')
        if output_dir:
            args.extend(['-o', output_dir])
        
        output_format = kwargs.get('output_format')
        if output_format:
            args.extend(['-f', output_format])
        
        return args