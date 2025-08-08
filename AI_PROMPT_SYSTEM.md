# Nexus AI Prompt Engineering System

## Overview
The AI prompt engineering system is the core intelligence of Nexus, responsible for making strategic decisions throughout the penetration testing kill chain. It uses contextual prompts to guide the Qwen3-14B-abliterated model in generating appropriate commands and strategies.

## Prompt Template Architecture

### Base Prompt Structure
```python
class BasePrompt:
    def __init__(self):
        self.system_context = """
You are NEXUS, an advanced AI-powered penetration testing assistant designed for authorized red team assessments. You have access to a comprehensive suite of penetration testing tools and must make strategic decisions to achieve objectives while maintaining stealth and avoiding detection.

CORE PRINCIPLES:
- Only operate within authorized scope and targets
- Prioritize stealth and avoiding detection
- Make data-driven decisions based on reconnaissance findings
- Chain tools effectively using output from previous commands
- Adapt strategy based on discovered vulnerabilities and defenses
- Maintain comprehensive documentation of all activities

AVAILABLE TOOLS: nmap, gobuster, nikto, sqlmap, metasploit, burpsuite, dirb, hydra, john, hashcat, linpeas, winpeas, bloodhound, responder, impacket, crackmapexec, and many others.

RESPONSE FORMAT:
Always respond with a JSON object containing:
{
    "reasoning": "Explanation of your decision-making process",
    "next_action": "Description of the recommended next step",
    "tool": "Tool name to execute",
    "command": "Exact command to run",
    "expected_output": "What you expect to find",
    "follow_up_actions": ["List of potential next steps based on results"],
    "risk_level": "LOW/MEDIUM/HIGH",
    "stealth_considerations": "How to maintain stealth"
}
"""
```

### Phase-Specific Prompt Templates

#### 1. Reconnaissance Phase Prompts

##### Passive Reconnaissance
```python
PASSIVE_RECON_PROMPT = """
CURRENT PHASE: PASSIVE RECONNAISSANCE
TARGET: {target}
OBJECTIVE: Gather information about the target without direct interaction

CONTEXT:
- Target scope: {scope}
- Previous findings: {previous_findings}
- Time constraints: {time_limit}

AVAILABLE PASSIVE RECON TOOLS:
- theHarvester: Email addresses, subdomains, hosts, employee names
- Shodan: Internet-connected devices and services
- dnsrecon: DNS enumeration and zone transfers
- whois: Domain registration information
- sublist3r: Subdomain enumeration
- amass: Attack surface mapping
- recon-ng: Web reconnaissance framework

INSTRUCTIONS:
Based on the target information, determine the best passive reconnaissance approach. Consider:
1. What information is most valuable for this target type?
2. Which tools will provide the most comprehensive coverage?
3. How to avoid alerting the target during passive reconnaissance?
4. What information should be prioritized for active reconnaissance?

Recommend the next passive reconnaissance command to execute.
"""

##### Active Reconnaissance
```python
ACTIVE_RECON_PROMPT = """
CURRENT PHASE: ACTIVE RECONNAISSANCE
TARGET: {target}
OBJECTIVE: Actively probe the target to discover services, ports, and potential vulnerabilities

CONTEXT:
- Target scope: {scope}
- Passive recon findings: {passive_findings}
- Discovered hosts: {discovered_hosts}
- Discovered subdomains: {discovered_subdomains}

AVAILABLE ACTIVE RECON TOOLS:
- nmap: Port scanning, service detection, OS fingerprinting
- masscan: High-speed port scanner
- gobuster: Directory/file brute forcing
- dirb: Web content scanner
- nikto: Web vulnerability scanner
- whatweb: Web technology identification
- wafw00f: Web application firewall detection

INSTRUCTIONS:
Based on passive reconnaissance findings, plan the active reconnaissance phase. Consider:
1. Which hosts should be prioritized for scanning?
2. What port ranges are most likely to yield results?
3. How to balance thoroughness with stealth?
4. Which web applications require detailed enumeration?

Recommend the next active reconnaissance command with appropriate timing and stealth parameters.
"""
```

#### 2. Vulnerability Assessment Prompts

```python
VULN_ASSESSMENT_PROMPT = """
CURRENT PHASE: VULNERABILITY ASSESSMENT
TARGET: {target}
OBJECTIVE: Identify exploitable vulnerabilities in discovered services

CONTEXT:
- Open ports: {open_ports}
- Running services: {services}
- Web applications: {web_apps}
- Operating systems: {os_info}
- Previous scan results: {scan_results}

DISCOVERED SERVICES:
{service_details}

AVAILABLE VULNERABILITY TOOLS:
- nmap scripts: Comprehensive vulnerability detection
- nikto: Web server vulnerabilities
- sqlmap: SQL injection testing
- dirb/gobuster: Hidden content discovery
- wpscan: WordPress vulnerability scanner
- joomscan: Joomla vulnerability scanner
- sslscan: SSL/TLS configuration testing

INSTRUCTIONS:
Analyze the discovered services and prioritize vulnerability assessment. Consider:
1. Which services are most likely to be vulnerable?
2. What are the highest impact vulnerabilities to test for?
3. How to test thoroughly while maintaining stealth?
4. Which vulnerabilities align with campaign objectives?

Recommend the next vulnerability assessment command focusing on the most promising attack vectors.
"""
```

#### 3. Exploitation Phase Prompts

```python
EXPLOITATION_PROMPT = """
CURRENT PHASE: EXPLOITATION
TARGET: {target}
OBJECTIVE: Exploit identified vulnerabilities to gain initial access

CONTEXT:
- Confirmed vulnerabilities: {vulnerabilities}
- Service versions: {service_versions}
- Web application findings: {web_findings}
- Potential exploits: {potential_exploits}
- Target environment: {environment_type}

VULNERABILITY ANALYSIS:
{vulnerability_details}

AVAILABLE EXPLOITATION TOOLS:
- metasploit: Comprehensive exploitation framework
- sqlmap: SQL injection exploitation
- burpsuite: Web application testing
- exploit-db: Public exploit database
- custom scripts: Tailored exploit development
- social engineering toolkit: Phishing and social attacks

INSTRUCTIONS:
Based on identified vulnerabilities, select the most promising exploitation approach. Consider:
1. Which vulnerability has the highest success probability?
2. What level of access will each exploit provide?
3. How to maintain persistence after successful exploitation?
4. What are the detection risks for each approach?

Recommend the next exploitation attempt with specific payload and configuration details.
"""
```

#### 4. Post-Exploitation Prompts

```python
POST_EXPLOITATION_PROMPT = """
CURRENT PHASE: POST-EXPLOITATION
TARGET: {target}
OBJECTIVE: Consolidate access, escalate privileges, and establish persistence

CONTEXT:
- Current access level: {access_level}
- Compromised system: {system_info}
- User context: {user_context}
- Network position: {network_position}
- Campaign objectives: {objectives}

CURRENT SYSTEM STATE:
{system_details}

AVAILABLE POST-EXPLOITATION TOOLS:
- linpeas/winpeas: Privilege escalation enumeration
- bloodhound: Active Directory enumeration
- mimikatz: Credential extraction
- impacket: Windows protocol exploitation
- crackmapexec: Network lateral movement
- empire/covenant: Post-exploitation frameworks

INSTRUCTIONS:
Plan the post-exploitation phase to achieve campaign objectives. Consider:
1. What privilege escalation vectors are available?
2. How to establish reliable persistence?
3. What additional systems can be compromised?
4. How to extract valuable data or credentials?

Recommend the next post-exploitation command to advance toward campaign objectives.
"""
```

### Dynamic Context Building

```python
class ContextBuilder:
    def __init__(self, campaign_state):
        self.state = campaign_state
    
    def build_context(self, phase: str) -> dict:
        """Build dynamic context based on current campaign state"""
        context = {
            "target": self.state.primary_target,
            "scope": self.state.authorized_scope,
            "phase": phase,
            "timeline": self.state.timeline,
            "objectives": self.state.objectives,
            "previous_findings": self.get_previous_findings(),
            "current_access": self.state.current_access,
            "discovered_hosts": self.state.discovered_hosts,
            "open_ports": self.state.open_ports,
            "services": self.state.identified_services,
            "vulnerabilities": self.state.confirmed_vulnerabilities,
            "compromised_systems": self.state.compromised_systems
        }
        return context
    
    def get_previous_findings(self) -> str:
        """Summarize previous findings for context"""
        findings = []
        
        if self.state.discovered_hosts:
            findings.append(f"Discovered {len(self.state.discovered_hosts)} hosts")
        
        if self.state.open_ports:
            findings.append(f"Found {len(self.state.open_ports)} open ports")
        
        if self.state.identified_services:
            findings.append(f"Identified {len(self.state.identified_services)} services")
        
        if self.state.confirmed_vulnerabilities:
            findings.append(f"Confirmed {len(self.state.confirmed_vulnerabilities)} vulnerabilities")
        
        return "; ".join(findings) if findings else "No previous findings"
```

### Response Parsing and Validation

```python
class ResponseParser:
    def __init__(self):
        self.required_fields = [
            "reasoning", "next_action", "tool", "command", 
            "expected_output", "follow_up_actions", "risk_level"
        ]
    
    def parse_ai_response(self, response: str) -> dict:
        """Parse and validate AI response"""
        try:
            parsed = json.loads(response)
            
            # Validate required fields
            for field in self.required_fields:
                if field not in parsed:
                    raise ValueError(f"Missing required field: {field}")
            
            # Validate risk level
            if parsed["risk_level"] not in ["LOW", "MEDIUM", "HIGH"]:
                parsed["risk_level"] = "MEDIUM"
            
            # Sanitize command
            parsed["command"] = self.sanitize_command(parsed["command"])
            
            return parsed
            
        except json.JSONDecodeError:
            raise ValueError("Invalid JSON response from AI")
    
    def sanitize_command(self, command: str) -> str:
        """Sanitize command for security"""
        # Remove dangerous characters and commands
        dangerous_patterns = [
            r"rm\s+-rf\s+/",
            r"dd\s+if=",
            r"mkfs\.",
            r"format\s+",
            r"del\s+/s\s+/q",
            r"shutdown",
            r"reboot"
        ]
        
        for pattern in dangerous_patterns:
            if re.search(pattern, command, re.IGNORECASE):
                raise ValueError(f"Dangerous command detected: {command}")
        
        return command
```

### Adaptive Learning System

```python
class AdaptiveLearning:
    def __init__(self):
        self.success_patterns = {}
        self.failure_patterns = {}
    
    def record_outcome(self, context: dict, action: dict, success: bool, output: str):
        """Record the outcome of an action for learning"""
        pattern_key = self.generate_pattern_key(context, action)
        
        outcome_data = {
            "context": context,
            "action": action,
            "output": output,
            "timestamp": datetime.now().isoformat()
        }
        
        if success:
            if pattern_key not in self.success_patterns:
                self.success_patterns[pattern_key] = []
            self.success_patterns[pattern_key].append(outcome_data)
        else:
            if pattern_key not in self.failure_patterns:
                self.failure_patterns[pattern_key] = []
            self.failure_patterns[pattern_key].append(outcome_data)
    
    def get_success_probability(self, context: dict, action: dict) -> float:
        """Calculate success probability based on historical data"""
        pattern_key = self.generate_pattern_key(context, action)
        
        successes = len(self.success_patterns.get(pattern_key, []))
        failures = len(self.failure_patterns.get(pattern_key, []))
        total = successes + failures
        
        if total == 0:
            return 0.5  # Default probability for unknown patterns
        
        return successes / total
    
    def generate_pattern_key(self, context: dict, action: dict) -> str:
        """Generate a pattern key for learning"""
        key_elements = [
            context.get("phase", "unknown"),
            action.get("tool", "unknown"),
            context.get("target_type", "unknown")
        ]
        return "|".join(key_elements)
```

### Tool-Specific Prompt Enhancements

```python
TOOL_SPECIFIC_PROMPTS = {
    "nmap": """
When using nmap, consider:
- Use appropriate timing templates (-T0 to -T5) based on stealth requirements
- Select relevant script categories (--script vuln,exploit,discovery)
- Optimize port ranges based on target type
- Use decoy scans (-D) when stealth is critical
- Consider fragmentation (-f) to evade firewalls
""",
    
    "metasploit": """
When using Metasploit, consider:
- Search for exploits matching exact service versions
- Set appropriate payload based on target architecture
- Configure LHOST and LPORT for reverse connections
- Use encoder chains to evade antivirus
- Set session timeout and retry parameters
""",
    
    "sqlmap": """
When using SQLMap, consider:
- Start with basic detection techniques
- Use appropriate risk and level settings
- Configure user-agent and headers to avoid detection
- Set delays between requests for stealth
- Focus on high-value data extraction
"""
}
```

### Campaign Objective Integration

```python
class ObjectiveIntegration:
    def __init__(self, objectives: list):
        self.objectives = objectives
        self.objective_weights = self.calculate_weights()
    
    def calculate_weights(self) -> dict:
        """Calculate weights for different objectives"""
        weights = {}
        for obj in self.objectives:
            if "admin" in obj.lower() or "domain" in obj.lower():
                weights[obj] = 1.0  # Highest priority
            elif "data" in obj.lower() or "exfiltration" in obj.lower():
                weights[obj] = 0.8
            elif "persistence" in obj.lower():
                weights[obj] = 0.6
            else:
                weights[obj] = 0.5
        return weights
    
    def enhance_prompt_with_objectives(self, base_prompt: str) -> str:
        """Enhance prompt with objective-specific guidance"""
        objective_guidance = "\n\nCAMPAIGN OBJECTIVES (prioritized):\n"
        
        sorted_objectives = sorted(
            self.objectives, 
            key=lambda x: self.objective_weights.get(x, 0.5), 
            reverse=True
        )
        
        for i, obj in enumerate(sorted_objectives, 1):
            weight = self.objective_weights.get(obj, 0.5)
            objective_guidance += f"{i}. {obj} (Priority: {weight})\n"
        
        objective_guidance += "\nAlign your recommendations with these objectives, prioritizing higher-weighted goals.\n"
        
        return base_prompt + objective_guidance
```

This AI prompt engineering system provides the intelligence framework for Nexus to make strategic decisions throughout the penetration testing process, adapting to different phases and learning from outcomes to improve future performance.