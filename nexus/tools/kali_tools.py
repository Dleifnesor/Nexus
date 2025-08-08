"""
Kali Linux Tools Manager

Comprehensive manager for all Kali Linux penetration testing tools
with automatic detection, configuration, and intelligent execution.
"""

import os
import yaml
import subprocess
import shutil
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from pathlib import Path
import logging

from .base import BaseToolAdapter, ToolResult, ToolStatus

logger = logging.getLogger(__name__)


@dataclass
class KaliToolInfo:
    """Information about a Kali tool"""
    name: str
    path: str
    category: str
    description: str
    default_args: List[str]
    timeout: int
    enabled: bool
    available: bool = False
    version: Optional[str] = None


class KaliToolsManager:
    """Manager for all Kali Linux penetration testing tools"""
    
    def __init__(self, config_path: Optional[str] = None):
        self.tools: Dict[str, KaliToolInfo] = {}
        self.adapters: Dict[str, BaseToolAdapter] = {}
        self.config_path = config_path or self._find_kali_tools_config()
        self.load_tools_configuration()
        self.detect_available_tools()
        self.create_adapters()
    
    def _find_kali_tools_config(self) -> str:
        """Find the Kali tools configuration file"""
        possible_paths = [
            "config/kali_tools.yaml",
            "~/.nexus/config/kali_tools.yaml",
            "/etc/nexus/kali_tools.yaml"
        ]
        
        for path in possible_paths:
            expanded_path = os.path.expanduser(path)
            if os.path.exists(expanded_path):
                return expanded_path
        
        # Return default path if none found
        return "config/kali_tools.yaml"
    
    def load_tools_configuration(self):
        """Load tools configuration from YAML file"""
        try:
            with open(self.config_path, 'r') as f:
                config = yaml.safe_load(f)
            
            # Parse all tool categories
            for category_name, category_tools in config.items():
                for tool_name, tool_config in category_tools.items():
                    self.tools[tool_name] = KaliToolInfo(
                        name=tool_name,
                        path=tool_config.get('path', ''),
                        category=tool_config.get('category', 'unknown'),
                        description=tool_config.get('description', ''),
                        default_args=tool_config.get('default_args', []),
                        timeout=tool_config.get('timeout', 300),
                        enabled=tool_config.get('enabled', True)
                    )
            
            logger.info(f"Loaded {len(self.tools)} tool configurations")
            
        except Exception as e:
            logger.error(f"Failed to load Kali tools configuration: {e}")
            self.tools = {}
    
    def detect_available_tools(self):
        """Detect which tools are actually available on the system"""
        available_count = 0
        
        for tool_name, tool_info in self.tools.items():
            # Check if tool exists at specified path
            if os.path.exists(tool_info.path):
                tool_info.available = True
                tool_info.version = self._get_tool_version(tool_name, tool_info.path)
                available_count += 1
            else:
                # Try to find tool in PATH
                which_path = shutil.which(tool_name)
                if which_path:
                    tool_info.path = which_path
                    tool_info.available = True
                    tool_info.version = self._get_tool_version(tool_name, which_path)
                    available_count += 1
                else:
                    tool_info.available = False
        
        logger.info(f"Detected {available_count}/{len(self.tools)} available tools")
    
    def _get_tool_version(self, tool_name: str, tool_path: str) -> Optional[str]:
        """Get version information for a tool"""
        version_args = {
            'nmap': ['--version'],
            'metasploit': ['--version'],
            'sqlmap': ['--version'],
            'gobuster': ['version'],
            'nikto': ['-Version'],
            'hydra': ['-h'],
            'john': ['--version'],
            'aircrack-ng': ['--version'],
            'wireshark': ['--version'],
            'burpsuite': ['--version']
        }
        
        args = version_args.get(tool_name, ['--version'])
        
        try:
            result = subprocess.run(
                [tool_path] + args,
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                # Extract version from output (first line usually)
                version_line = result.stdout.split('\n')[0]
                return version_line.strip()
            else:
                # Some tools output version to stderr
                version_line = result.stderr.split('\n')[0]
                return version_line.strip()
                
        except Exception:
            return None
    
    def create_adapters(self):
        """Create tool adapters for available tools"""
        for tool_name, tool_info in self.tools.items():
            if tool_info.available and tool_info.enabled:
                adapter = self._create_tool_adapter(tool_name, tool_info)
                if adapter:
                    self.adapters[tool_name] = adapter
        
        logger.info(f"Created {len(self.adapters)} tool adapters")
    
    def _create_tool_adapter(self, tool_name: str, tool_info: KaliToolInfo) -> Optional[BaseToolAdapter]:
        """Create a specific tool adapter"""
        
        # Specialized adapters for complex tools
        specialized_adapters = {
            'nmap': NmapAdapter,
            'metasploit': MetasploitAdapter,
            'sqlmap': SQLMapAdapter,
            'gobuster': GobusterAdapter,
            'nikto': NiktoAdapter,
            'hydra': HydraAdapter,
            'john': JohnAdapter,
            'aircrack-ng': AircrackAdapter,
            'wireshark': WiresharkAdapter,
            'burpsuite': BurpSuiteAdapter
        }
        
        if tool_name in specialized_adapters:
            try:
                return specialized_adapters[tool_name](tool_info.path, tool_info.default_args)
            except Exception as e:
                logger.error(f"Failed to create specialized adapter for {tool_name}: {e}")
        
        # Generic adapter for simple tools
        return GenericKaliToolAdapter(tool_name, tool_info)
    
    def get_available_tools(self) -> List[str]:
        """Get list of available tool names"""
        return [name for name, info in self.tools.items() if info.available and info.enabled]
    
    def get_tools_by_category(self, category: str) -> List[str]:
        """Get tools by category"""
        return [
            name for name, info in self.tools.items() 
            if info.category == category and info.available and info.enabled
        ]
    
    def get_tool_info(self, tool_name: str) -> Optional[KaliToolInfo]:
        """Get information about a specific tool"""
        return self.tools.get(tool_name)
    
    def get_tool_adapter(self, tool_name: str) -> Optional[BaseToolAdapter]:
        """Get adapter for a specific tool"""
        return self.adapters.get(tool_name)
    
    def execute_tool(self, tool_name: str, target: str, **kwargs) -> ToolResult:
        """Execute a tool with given parameters"""
        adapter = self.get_tool_adapter(tool_name)
        if not adapter:
            return ToolResult(
                tool_name=tool_name,
                command="",
                status=ToolStatus.ERROR,
                raw_output="",
                parsed_data={},
                execution_time=0,
                error_message=f"Tool '{tool_name}' not available"
            )
        
        return adapter.execute(target, **kwargs)
    
    def get_tool_categories(self) -> List[str]:
        """Get all available tool categories"""
        categories = set()
        for tool_info in self.tools.values():
            if tool_info.available and tool_info.enabled:
                categories.add(tool_info.category)
        return sorted(list(categories))
    
    def get_system_report(self) -> Dict[str, Any]:
        """Generate system report of available tools"""
        report = {
            'total_tools': len(self.tools),
            'available_tools': len([t for t in self.tools.values() if t.available]),
            'enabled_tools': len([t for t in self.tools.values() if t.enabled]),
            'categories': {},
            'tools': {}
        }
        
        # Categorize tools
        for tool_name, tool_info in self.tools.items():
            category = tool_info.category
            if category not in report['categories']:
                report['categories'][category] = {
                    'total': 0,
                    'available': 0,
                    'tools': []
                }
            
            report['categories'][category]['total'] += 1
            report['categories'][category]['tools'].append(tool_name)
            
            if tool_info.available:
                report['categories'][category]['available'] += 1
            
            # Tool details
            report['tools'][tool_name] = {
                'path': tool_info.path,
                'category': tool_info.category,
                'description': tool_info.description,
                'available': tool_info.available,
                'enabled': tool_info.enabled,
                'version': tool_info.version
            }
        
        return report


class GenericKaliToolAdapter(BaseToolAdapter):
    """Generic adapter for Kali tools"""
    
    def __init__(self, tool_name: str, tool_info: KaliToolInfo):
        super().__init__(tool_info.path, tool_info.default_args)
        self.tool_name = tool_name
        self.tool_info = tool_info
        self.timeout = tool_info.timeout
    
    def build_command(self, target: str, **kwargs) -> List[str]:
        """Build command for generic tool execution"""
        command = [self.tool_path] + self.default_args.copy()
        
        # Add target
        if target:
            command.append(target)
        
        # Add additional arguments
        for key, value in kwargs.items():
            if key.startswith('arg_'):
                # Direct argument
                command.append(str(value))
            elif key == 'output_file':
                command.extend(['-o', str(value)])
            elif key == 'verbose':
                if value:
                    command.append('-v')
            elif key == 'quiet':
                if value:
                    command.append('-q')
        
        return command
    
    def parse_output(self, raw_output: str) -> Dict[str, Any]:
        """Generic output parsing"""
        return {
            'raw_output': raw_output,
            'lines': raw_output.split('\n'),
            'tool': self.tool_name,
            'success': True
        }


# Specialized adapters for complex tools
class NmapAdapter(BaseToolAdapter):
    """Specialized adapter for Nmap"""
    
    def build_command(self, target: str, **kwargs) -> List[str]:
        command = [self.tool_path]
        
        # Scan type
        scan_type = kwargs.get('scan_type', 'syn')
        if scan_type == 'syn':
            command.append('-sS')
        elif scan_type == 'tcp':
            command.append('-sT')
        elif scan_type == 'udp':
            command.append('-sU')
        elif scan_type == 'ping':
            command.append('-sn')
        
        # Service detection
        if kwargs.get('service_detection', True):
            command.append('-sV')
        
        # OS detection
        if kwargs.get('os_detection', False):
            command.append('-O')
        
        # Aggressive scan
        if kwargs.get('aggressive', False):
            command.append('-A')
        
        # Scripts
        scripts = kwargs.get('scripts', [])
        if scripts:
            command.extend(['--script', ','.join(scripts)])
        
        # Timing
        timing = kwargs.get('timing', 3)
        command.extend(['-T', str(timing)])
        
        # Ports
        ports = kwargs.get('ports', '1-65535')
        command.extend(['-p', str(ports)])
        
        # Output format
        output_format = kwargs.get('output_format', 'normal')
        if output_format == 'xml':
            command.append('-oX')
            command.append('-')
        elif output_format == 'grepable':
            command.append('-oG')
            command.append('-')
        
        # Target
        command.append(target)
        
        return command
    
    def parse_output(self, raw_output: str) -> Dict[str, Any]:
        """Parse Nmap output"""
        parsed_data = {
            'hosts': [],
            'open_ports': [],
            'services': [],
            'os_info': None
        }
        
        current_host = None
        lines = raw_output.split('\n')
        
        for line in lines:
            line = line.strip()
            
            # Host detection
            if line.startswith('Nmap scan report for'):
                if current_host:
                    parsed_data['hosts'].append(current_host)
                
                host_info = line.replace('Nmap scan report for ', '')
                current_host = {
                    'host': host_info,
                    'ports': [],
                    'services': []
                }
            
            # Port detection
            elif '/' in line and ('open' in line or 'closed' in line or 'filtered' in line):
                if current_host:
                    parts = line.split()
                    if len(parts) >= 3:
                        port_info = parts[0]
                        state = parts[1]
                        service = parts[2] if len(parts) > 2 else 'unknown'
                        
                        port_data = {
                            'port': port_info,
                            'state': state,
                            'service': service
                        }
                        
                        current_host['ports'].append(port_data)
                        
                        if state == 'open':
                            parsed_data['open_ports'].append({
                                'host': current_host['host'],
                                'port': port_info,
                                'service': service
                            })
        
        # Add last host
        if current_host:
            parsed_data['hosts'].append(current_host)
        
        return parsed_data


class MetasploitAdapter(BaseToolAdapter):
    """Specialized adapter for Metasploit"""
    
    def build_command(self, target: str, **kwargs) -> List[str]:
        # Metasploit requires resource scripts for automation
        exploit = kwargs.get('exploit')
        payload = kwargs.get('payload')
        options = kwargs.get('options', {})
        
        # Create temporary resource script
        import tempfile
        script_content = []
        
        if exploit:
            script_content.append(f"use {exploit}")
            script_content.append(f"set RHOSTS {target}")
            
            if payload:
                script_content.append(f"set PAYLOAD {payload}")
            
            for key, value in options.items():
                script_content.append(f"set {key} {value}")
            
            script_content.extend([
                "check",
                "exploit -z",
                "exit"
            ])
        
        # Write script to temporary file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.rc', delete=False) as f:
            f.write('\n'.join(script_content))
            script_file = f.name
        
        return [self.tool_path, '-q', '-r', script_file]
    
    def parse_output(self, raw_output: str) -> Dict[str, Any]:
        """Parse Metasploit output"""
        return {
            'exploit_success': 'Meterpreter session' in raw_output or 'Command shell session' in raw_output,
            'sessions': self._extract_sessions(raw_output),
            'vulnerabilities': self._extract_vulnerabilities(raw_output),
            'errors': self._extract_errors(raw_output)
        }
    
    def _extract_sessions(self, output: str) -> List[Dict[str, Any]]:
        """Extract session information"""
        sessions = []
        lines = output.split('\n')
        
        for line in lines:
            if 'session' in line.lower() and 'opened' in line.lower():
                sessions.append({'info': line.strip()})
        
        return sessions
    
    def _extract_vulnerabilities(self, output: str) -> List[str]:
        """Extract vulnerability information"""
        vulns = []
        if 'appears to be vulnerable' in output.lower():
            vulns.append('Target appears vulnerable')
        return vulns
    
    def _extract_errors(self, output: str) -> List[str]:
        """Extract error information"""
        errors = []
        lines = output.split('\n')
        
        for line in lines:
            if any(keyword in line.lower() for keyword in ['error', 'failed', 'exception']):
                errors.append(line.strip())
        
        return errors


class SQLMapAdapter(BaseToolAdapter):
    """Specialized adapter for SQLMap"""
    
    def build_command(self, target: str, **kwargs) -> List[str]:
        command = [self.tool_path]
        
        # Target URL
        if target.startswith('http'):
            command.extend(['-u', target])
        else:
            command.extend(['-r', target])  # Request file
        
        # Parameters to test
        params = kwargs.get('parameters', [])
        if params:
            command.extend(['-p', ','.join(params)])
        
        # Database management system
        dbms = kwargs.get('dbms')
        if dbms:
            command.extend(['--dbms', dbms])
        
        # Risk and level
        risk = kwargs.get('risk', 1)
        level = kwargs.get('level', 1)
        command.extend(['--risk', str(risk), '--level', str(level)])
        
        # Techniques
        technique = kwargs.get('technique', 'BEUSTQ')
        command.extend(['--technique', technique])
        
        # Batch mode
        command.extend(['--batch', '--no-cast'])
        
        # Data extraction
        if kwargs.get('dump_all', False):
            command.append('--dump-all')
        elif kwargs.get('dump_tables'):
            command.extend(['-T', kwargs['dump_tables'], '--dump'])
        
        # Enumeration
        if kwargs.get('enumerate_dbs', False):
            command.append('--dbs')
        if kwargs.get('enumerate_tables', False):
            command.append('--tables')
        if kwargs.get('enumerate_columns', False):
            command.append('--columns')
        
        return command
    
    def parse_output(self, raw_output: str) -> Dict[str, Any]:
        """Parse SQLMap output"""
        return {
            'vulnerable': 'sqlmap identified the following injection point' in raw_output,
            'injection_points': self._extract_injection_points(raw_output),
            'databases': self._extract_databases(raw_output),
            'tables': self._extract_tables(raw_output),
            'data': self._extract_data(raw_output)
        }
    
    def _extract_injection_points(self, output: str) -> List[Dict[str, Any]]:
        """Extract SQL injection points"""
        points = []
        # Implementation would parse injection point details
        return points
    
    def _extract_databases(self, output: str) -> List[str]:
        """Extract database names"""
        databases = []
        # Implementation would parse database names
        return databases
    
    def _extract_tables(self, output: str) -> List[Dict[str, str]]:
        """Extract table information"""
        tables = []
        # Implementation would parse table information
        return tables
    
    def _extract_data(self, output: str) -> Dict[str, Any]:
        """Extract dumped data"""
        data = {}
        # Implementation would parse dumped data
        return data


# Additional specialized adapters would be implemented similarly
class GobusterAdapter(GenericKaliToolAdapter):
    """Specialized adapter for Gobuster"""
    pass

class NiktoAdapter(GenericKaliToolAdapter):
    """Specialized adapter for Nikto"""
    pass

class HydraAdapter(GenericKaliToolAdapter):
    """Specialized adapter for Hydra"""
    pass

class JohnAdapter(GenericKaliToolAdapter):
    """Specialized adapter for John the Ripper"""
    pass

class AircrackAdapter(GenericKaliToolAdapter):
    """Specialized adapter for Aircrack-ng"""
    pass

class WiresharkAdapter(GenericKaliToolAdapter):
    """Specialized adapter for Wireshark"""
    pass

class BurpSuiteAdapter(GenericKaliToolAdapter):
    """Specialized adapter for Burp Suite"""
    pass