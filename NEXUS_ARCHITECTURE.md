# Nexus AI-Powered Penetration Testing Tool - Architecture Design

## Overview
Nexus is a comprehensive AI-powered penetration testing automation tool designed for professional red team assessments and authorized penetration testing engagements. It leverages the Qwen3-14B-abliterated model via Ollama to automate the entire kill chain from reconnaissance through persistence.

## Core Architecture

### System Components

```mermaid
graph TB
    A[CLI Interface] --> B[Core Engine]
    B --> C[AI Decision Engine]
    C --> D[Ollama Integration]
    B --> E[Tool Manager]
    E --> F[Reconnaissance Module]
    E --> G[Vulnerability Scanner]
    E --> H[Exploitation Framework]
    E --> I[Persistence Module]
    B --> J[Data Pipeline]
    J --> K[Evidence Collector]
    J --> L[Report Generator]
    B --> M[Configuration Manager]
    B --> N[Safety Controller]
    
    F --> F1[Passive Recon]
    F --> F2[Active Recon]
    F1 --> F1A[OSINT Tools]
    F1 --> F1B[DNS Enumeration]
    F1 --> F1C[Subdomain Discovery]
    F2 --> F2A[Port Scanning]
    F2 --> F2B[Service Detection]
    F2 --> F2C[Web Crawling]
    
    G --> G1[Network Scanning]
    G --> G2[Web App Testing]
    G --> G3[Service Analysis]
    
    H --> H1[Exploit Selection]
    H --> H2[Payload Generation]
    H --> H3[Execution Engine]
    
    I --> I1[Backdoor Installation]
    I --> I2[Privilege Escalation]
    I --> I3[Lateral Movement]
```

### AI Decision Engine Architecture

```mermaid
graph LR
    A[Current State] --> B[Context Analyzer]
    B --> C[Prompt Generator]
    C --> D[Ollama Model]
    D --> E[Response Parser]
    E --> F[Action Validator]
    F --> G[Command Generator]
    G --> H[Execution Queue]
    H --> I[Tool Executor]
    I --> J[Result Processor]
    J --> K[State Updater]
    K --> A
```

## Technical Specifications

### Core Technologies
- **Language**: Python 3.9+
- **AI Model**: Qwen3-14B-abliterated via Ollama
- **Database**: SQLite for local data storage
- **Configuration**: YAML/JSON configuration files
- **Logging**: Structured logging with JSON output
- **CLI Framework**: Click or Typer
- **Async Processing**: asyncio for concurrent operations

### Directory Structure
```
nexus/
├── nexus/
│   ├── __init__.py
│   ├── core/
│   │   ├── __init__.py
│   │   ├── engine.py              # Main orchestration engine
│   │   ├── ai_decision.py         # AI decision making logic
│   │   ├── state_manager.py       # Campaign state management
│   │   └── config.py              # Configuration management
│   ├── ai/
│   │   ├── __init__.py
│   │   ├── ollama_client.py       # Ollama integration
│   │   ├── prompt_templates.py    # AI prompt templates
│   │   ├── response_parser.py     # AI response parsing
│   │   └── context_builder.py     # Context building for AI
│   ├── modules/
│   │   ├── __init__.py
│   │   ├── reconnaissance/
│   │   │   ├── __init__.py
│   │   │   ├── passive.py         # Passive reconnaissance
│   │   │   ├── active.py          # Active reconnaissance
│   │   │   └── osint.py           # OSINT gathering
│   │   ├── scanning/
│   │   │   ├── __init__.py
│   │   │   ├── network.py         # Network scanning
│   │   │   ├── web.py             # Web application scanning
│   │   │   └── service.py         # Service enumeration
│   │   ├── exploitation/
│   │   │   ├── __init__.py
│   │   │   ├── exploit_db.py      # Exploit database integration
│   │   │   ├── metasploit.py      # Metasploit integration
│   │   │   ├── web_exploits.py    # Web application exploits
│   │   │   └── payload_gen.py     # Payload generation
│   │   └── persistence/
│   │       ├── __init__.py
│   │       ├── backdoors.py       # Backdoor installation
│   │       ├── privilege_esc.py   # Privilege escalation
│   │       └── lateral_move.py    # Lateral movement
│   ├── tools/
│   │   ├── __init__.py
│   │   ├── base.py                # Base tool interface
│   │   ├── nmap.py                # Nmap integration
│   │   ├── gobuster.py            # Gobuster integration
│   │   ├── sqlmap.py              # SQLMap integration
│   │   ├── nikto.py               # Nikto integration
│   │   └── metasploit.py          # Metasploit integration
│   ├── data/
│   │   ├── __init__.py
│   │   ├── pipeline.py            # Data processing pipeline
│   │   ├── storage.py             # Data storage management
│   │   └── evidence.py            # Evidence collection
│   ├── safety/
│   │   ├── __init__.py
│   │   ├── scope_validator.py     # Scope validation
│   │   ├── rate_limiter.py        # Rate limiting
│   │   └── safety_checks.py       # Safety mechanisms
│   ├── reporting/
│   │   ├── __init__.py
│   │   ├── generator.py           # Report generation
│   │   ├── templates/             # Report templates
│   │   └── exporters.py           # Export formats
│   └── cli/
│       ├── __init__.py
│       ├── main.py                # Main CLI entry point
│       ├── commands.py            # CLI commands
│       └── utils.py               # CLI utilities
├── config/
│   ├── default.yaml               # Default configuration
│   ├── prompts/                   # AI prompt templates
│   └── tools.yaml                 # Tool configurations
├── scripts/
│   ├── install.sh                 # Kali Linux installation script
│   └── setup_ollama.sh            # Ollama setup script
├── tests/
│   ├── unit/
│   ├── integration/
│   └── fixtures/
├── docs/
│   ├── installation.md
│   ├── usage.md
│   └── api.md
├── requirements.txt
├── setup.py
├── pyproject.toml
└── README.md
```

## Kill Chain Implementation

### Phase 1: Reconnaissance
- **Passive Reconnaissance**
  - OSINT gathering using tools like theHarvester, Shodan API
  - DNS enumeration with dnsrecon, fierce
  - Subdomain discovery with Sublist3r, Amass
  - Social media and public information gathering

- **Active Reconnaissance**
  - Port scanning with Nmap (TCP/UDP, service detection)
  - Web crawling and directory enumeration with Gobuster, Dirb
  - Service banner grabbing and version detection
  - SSL/TLS certificate analysis

### Phase 2: Scanning & Enumeration
- **Network Scanning**
  - Comprehensive port scans with timing optimization
  - Service version detection and OS fingerprinting
  - Vulnerability scanning with Nessus/OpenVAS integration

- **Web Application Testing**
  - Automated web app scanning with Nikto, OWASP ZAP
  - SQL injection testing with SQLMap
  - XSS and other web vulnerability detection

### Phase 3: Exploitation
- **Vulnerability Assessment**
  - CVE database correlation
  - Exploit availability checking via Exploit-DB
  - Custom exploit generation based on discovered services

- **Exploitation Execution**
  - Metasploit integration for automated exploitation
  - Custom payload generation and delivery
  - Web application exploit automation
  - Buffer overflow and memory corruption exploits

### Phase 4: Post-Exploitation & Persistence
- **Initial Access Consolidation**
  - Shell stabilization and upgrade
  - System information gathering
  - User and privilege enumeration

- **Privilege Escalation**
  - Automated privilege escalation using tools like LinPEAS, WinPEAS
  - Kernel exploit identification and execution
  - Service misconfiguration exploitation

- **Persistence Mechanisms**
  - Backdoor installation (web shells, reverse shells)
  - Registry/cron job persistence
  - Service creation and modification
  - User account creation

- **Lateral Movement**
  - Network discovery and mapping
  - Credential harvesting and reuse
  - Pass-the-hash and pass-the-ticket attacks
  - SMB and RDP exploitation

## AI Integration Strategy

### Prompt Engineering Framework
```python
class PromptTemplate:
    def __init__(self, phase: str, context: dict):
        self.phase = phase
        self.context = context
    
    def generate_prompt(self) -> str:
        # Generate contextual prompts based on current phase and findings
        pass
```

### Decision Making Process
1. **Context Analysis**: Analyze current state, available data, and objectives
2. **Option Generation**: Generate possible next actions based on current phase
3. **Risk Assessment**: Evaluate potential impact and detection risk
4. **Action Selection**: Choose optimal action based on success probability
5. **Command Generation**: Generate specific tool commands with parameters
6. **Execution Planning**: Plan execution timing and dependencies

### Learning and Adaptation
- **Result Analysis**: Parse tool outputs and extract actionable intelligence
- **Strategy Adjustment**: Modify approach based on discovered information
- **Tool Selection**: Choose appropriate tools based on target characteristics
- **Parameter Optimization**: Adjust tool parameters for better results

## Configuration System

### Global Configuration (`~/.nexus/config.yaml`)
```yaml
ai:
  model: "huihui_ai/qwen2.5-abliterate:14b"
  ollama_url: "http://localhost:11434"
  temperature: 0.7
  max_tokens: 2048

tools:
  nmap:
    path: "/usr/bin/nmap"
    default_args: ["-sS", "-O", "-sV"]
  metasploit:
    path: "/usr/share/metasploit-framework"
    database: "postgresql://nexus:password@localhost/msf"

safety:
  scope_validation: true
  rate_limiting: true
  max_concurrent_scans: 5
  confirmation_required: false

logging:
  level: "INFO"
  file: "~/.nexus/logs/nexus.log"
  format: "json"

reporting:
  output_dir: "~/.nexus/reports"
  formats: ["html", "json", "pdf"]
```

### Campaign Configuration
```yaml
campaign:
  name: "Red Team Assessment 2024"
  target_scope:
    - "192.168.1.0/24"
    - "example.com"
    - "*.example.com"
  excluded_hosts:
    - "192.168.1.1"
  objectives:
    - "Domain Admin Access"
    - "Data Exfiltration"
    - "Persistence"
  timeline:
    start: "2024-01-01T00:00:00Z"
    end: "2024-01-07T23:59:59Z"
```

## Safety and Ethical Considerations

### Scope Validation
- IP range and domain validation against authorized targets
- Real-time scope checking before each action
- Automatic blocking of out-of-scope activities

### Rate Limiting and Stealth
- Configurable delays between operations
- Traffic shaping to avoid detection
- Randomized timing patterns

### Evidence Collection
- Comprehensive logging of all activities
- Screenshot and output capture
- Chain of custody maintenance
- Automated report generation

### Emergency Controls
- Kill switch functionality
- Activity suspension mechanisms
- Rollback capabilities for persistence mechanisms

## Installation and Deployment

### Kali Linux Installation Script
```bash
#!/bin/bash
# Install Nexus on Kali Linux

# Install Ollama
curl -fsSL https://ollama.ai/install.sh | sh

# Pull the required model
ollama pull huihui_ai/qwen2.5-coder-abliterate:14b

# Install Python dependencies
pip3 install -r requirements.txt

# Install Nexus globally
pip3 install -e .

# Create configuration directory
mkdir -p ~/.nexus/{config,logs,reports}

# Copy default configuration
cp config/default.yaml ~/.nexus/config/config.yaml

# Make nexus command available globally
ln -sf $(which nexus) /usr/local/bin/nexus

echo "Nexus installation complete!"
echo "Run 'nexus --help' to get started"
```

## Usage Examples

### Basic Campaign Execution
```bash
# Start a new campaign
nexus campaign create --name "Test Assessment" --target "192.168.1.0/24"

# Run automated assessment
nexus run --campaign "Test Assessment" --prompt "Perform comprehensive penetration test"

# Check campaign status
nexus status --campaign "Test Assessment"

# Generate report
nexus report --campaign "Test Assessment" --format html
```

### Configuration Management
```bash
# Configure AI model
nexus config set ai.model "custom-model"

# Configure Ollama URL for remote instance
nexus config set ai.ollama_url "http://192.168.1.100:11434"

# View current configuration
nexus config show
```

This architecture provides a comprehensive foundation for building the Nexus AI-powered penetration testing tool with full automation capabilities while maintaining professional standards and safety mechanisms.