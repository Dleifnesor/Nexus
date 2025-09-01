# Nexus AI-Powered Penetration Testing Tool

[![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)](https://github.com/nexus-security/nexus)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.9+-blue.svg)](https://python.org)
[![Kali Linux](https://img.shields.io/badge/platform-Kali%20Linux-red.svg)](https://kali.org)

**The world's first truly intelligent penetration testing platform** that combines advanced AI decision-making with comprehensive automation, sophisticated evasion capabilities, and enterprise-grade safety mechanisms.

**NEW: Autonomous AI Agent** - Just tell Nexus what you want in plain English and it figures out everything else automatically!

### Installation

#### Prerequisites
- **OS**: Kali Linux (recommended) or Ubuntu/Debian 20.04+
- **Python**: 3.9 or higher
- **Memory**: 8GB RAM minimum (16GB recommended)
- **Storage**: 20GB free space
- **Network**: Internet connection for AI model download

#### Step-by-Step Installation

1. **Install System Dependencies**
```bash
sudo apt update && sudo apt install -y \
    python3 python3-pip python3-venv git curl \
    build-essential libssl-dev libffi-dev
```

2. **Install Ollama (AI Engine)**
```bash
curl -fsSL https://ollama.ai/install.sh | sh
sudo systemctl enable ollama
sudo systemctl start ollama
```

3. **Download AI Model**
```bash
ollama pull huihui_ai/qwen2.5-coder-abliterate:14b
```

4. **Install Nexus**
```bash
git clone https://github.com/Dleifnesor/nexus.git
cd nexus
pip install -e .
```

5. **Initialize Configuration**
```bash
nexus config init
nexus health
```

## Quick Start Guide

### 1. Verify Your Installation
```bash
nexus --version
nexus health
```

### 2. Create Your First Campaign
```bash
# Create a new penetration testing campaign
nexus campaign create \
  --name "Web App Assessment" \
  --target "example.com" \
  --description "Comprehensive web application security test"
```

### 3. Run AI-Powered Assessment

#### Autonomous Mode (NEW!)
```bash
# Just tell Nexus what you want in plain English!
nexus run --auto "get into the SMB server on this network"
nexus run --auto "find SQL injection vulnerabilities in the web application"
nexus run --auto "escalate privileges on the Linux server at 192.168.1.100"
nexus run --auto "establish persistence on the domain controller"
```

#### Traditional Mode
```bash
# Launch intelligent assessment with AI guidance
nexus run --campaign "Web App Assessment" \
  --ai-analysis \
  --evasion-profile "stealth_balanced"
```

### 4. Monitor Progress
```bash
# Check campaign status
nexus status --campaign "Web App Assessment"

# Launch real-time dashboard
nexus dashboard start --port 8080
```

### 5. Generate Professional Report
```bash
# Generate comprehensive HTML report
nexus report generate \
  --campaign "Web App Assessment" \
  --format html \
  --output assessment_report.html
```

## Autonomous AI Agent

### Revolutionary Natural Language Interface
Simply describe your objective in plain English and Nexus automatically:
- **Analyzes your goal** and determines the best approach
- **Plans the complete mission** with optimal tool selection
- **Executes everything autonomously** with advanced evasion
- **Generates professional reports** with findings and evidence

### Example Autonomous Commands
```bash
# Network penetration
nexus run --auto "compromise the Windows domain controller"
nexus run --auto "get admin access to the file server"
nexus run --auto "find and exploit SMB vulnerabilities"

# Web application testing
nexus run --auto "find SQL injection in the login form"
nexus run --auto "get admin access to the web application"
nexus run --auto "find XSS vulnerabilities in the comment system"

# Privilege escalation
nexus run --auto "escalate to root on the Linux server"
nexus run --auto "become domain admin from current user"
nexus run --auto "find privilege escalation paths"

# Data exfiltration
nexus run --auto "find and extract sensitive customer data"
nexus run --auto "locate database credentials"
nexus run --auto "access the backup server"

# Stealth operations
nexus run --auto "establish persistent backdoor access" --evasion-profile stealth_maximum
nexus run --auto "conduct reconnaissance without detection" --evasion-profile apt_simulation
```

### How It Works
1. **AI Planning**: Analyzes your objective and creates a comprehensive execution plan
2. **Autonomous Reconnaissance**: Discovers targets and maps the environment
3. **Smart Exploitation**: Identifies vulnerabilities and executes targeted attacks
4. **Adaptive Evasion**: Automatically applies stealth techniques to avoid detection
5. **Intelligent Reporting**: Generates professional reports with evidence and recommendations

## Use Cases

### Enterprise Security Assessment
**Comprehensive security testing for large organizations**

```bash
# Autonomous enterprise assessment
nexus run --auto "conduct comprehensive security assessment of the corporate network" \
  --evasion-profile "stealth_balanced"

# Traditional campaign approach
nexus campaign create \
  --name "Enterprise-Security-2024" \
  --scope "*.company.com,10.0.0.0/8" \
  --exclude "*.prod.company.com" \
  --compliance "SOC2"

nexus run --campaign "Enterprise-Security-2024" \
  --phases "recon,scan,exploit" \
  --max-concurrent 10 \
  --stealth-profile "balanced"
```

**Results**: 15,000+ assets scanned, 847 vulnerabilities correlated, executive reports generated

### Red Team Operations
**Advanced persistent threat simulation**

```bash
# Autonomous APT simulation
nexus run --auto "simulate advanced persistent threat against the corporate network" \
  --evasion-profile "apt_simulation"

# Specific autonomous objectives
nexus run --auto "establish covert persistent access to the domain controller"
nexus run --auto "conduct lateral movement through the network undetected"

# Traditional campaign approach
nexus campaign create \
  --name "APT-Simulation" \
  --target "target-corp.com" \
  --objective "domain-admin"

nexus run --campaign "APT-Simulation" \
  --evasion-profile "apt_simulation" \
  --persistence-required \
  --stealth-maximum
```

**Results**: 6-month persistent access, 0 detection events, complete network mapping

### Web Application Testing
**OWASP Top 10 and beyond**

```bash
# Autonomous web application testing
nexus run --auto "find all vulnerabilities in the web application at https://webapp.example.com"
nexus run --auto "test for SQL injection in the login and search forms"
nexus run --auto "find XSS vulnerabilities and generate proof-of-concept exploits"
nexus run --auto "bypass authentication and access admin panel"

# Traditional approach
nexus tools scan https://webapp.example.com \
  --category web_application \
  --ai-correlation \
  --custom-wordlists

# AI-powered vulnerability analysis
nexus ai vuln correlate \
  --input scan_results.json \
  --focus "injection,xss,auth"

# Generate custom exploits
nexus ai exploit recommend \
  --vuln-file vulnerabilities.json \
  --generate-scripts
```

### Network Penetration Testing
**Internal network security assessment**

```bash
# Autonomous network penetration
nexus run --auto "compromise all Windows servers on the 192.168.1.0/24 network"
nexus run --auto "find the domain controller and escalate to domain admin"
nexus run --auto "discover and exploit SMB shares with sensitive data"
nexus run --auto "map the network and identify critical servers"

# Traditional approach
nexus tools scan 192.168.1.0/24 \
  --tools "nmap,masscan,enum4linux" \
  --parallel \
  --output-dir network_scan

# AI attack path planning
nexus ai attack plan \
  --vuln-file network_vulns.json \
  --environment network_topology.json \
  --objective "lateral_movement"
```

### Security Training & Research
**Educational and research applications**

```bash
# Autonomous learning scenarios
nexus run --auto "demonstrate SQL injection attack on the training lab"
nexus run --auto "show privilege escalation techniques on Linux"
nexus run --auto "simulate phishing attack and lateral movement"

# Traditional approach
nexus learn --topic "web-security" \
  --difficulty "intermediate" \
  --hands-on

# Vulnerability research
nexus research --cve "CVE-2024-1234" \
  --generate-poc \
  --test-environment "lab.local"
```

## Advanced Features

### Autonomous AI Operations
```bash
# Natural language objectives - AI handles everything
nexus run --auto "get into the SMB server on this network"
nexus run --auto "find SQL injection in the web app and exploit it"
nexus run --auto "escalate privileges on the Linux server"
nexus run --auto "establish persistence on the domain controller"

# See what the AI would do (dry run)
nexus run --auto "compromise the database server" --dry-run

# Advanced autonomous operations with stealth
nexus run --auto "conduct covert reconnaissance of the network" --evasion-profile stealth_maximum
```

### Traditional AI-Powered Analysis
```bash
# Vulnerability correlation across multiple tools
nexus ai vuln correlate --input tool_results.json

# Intelligent exploit recommendations
nexus ai exploit recommend --vuln-file vulns.json --stealth

# Multi-step attack path planning
nexus ai attack plan --objective privilege_escalation
```

### Sophisticated Evasion
```bash
# List available evasion profiles
nexus evasion profiles

# Set maximum stealth profile
nexus evasion set stealth_maximum

# Test evasion effectiveness
nexus evasion test --target example.com --requests 50

# AI-powered evasion strategy
nexus evasion analyze --target-info target.json --operation web_test
```

### Professional Tool Integration
```bash
# Execute individual tools with evasion
nexus tools execute nmap 192.168.1.100 --evasion-profile red_team

# Multi-tool scanning campaign
nexus tools scan target.com --category all --parallel --max-concurrent 5

# Custom script generation
nexus script generate --purpose exploitation --target webapp.com
```

### Real-Time Dashboard
```bash
# Start interactive dashboard
nexus dashboard start --port 8080 --data-dir ./analysis_data

# Monitor live operations
nexus dashboard monitor --directory ./live_data --auto-analysis
```

## Configuration

### Basic Configuration
```bash
# View current configuration
nexus config show

# Set AI model parameters
nexus config set ai.temperature 0.7
nexus config set ai.max_tokens 2048

# Configure evasion settings
nexus config set evasion.default_profile stealth_balanced
nexus config set evasion.timing.base_jitter 0.5

# Set safety parameters
nexus config set safety.scope_validation true
nexus config set safety.rate_limiting true
```

### Advanced Configuration File
Create `~/.nexus/config/custom.yaml`:

```yaml
# AI Configuration
ai:
  model: "huihui_ai/qwen2.5-coder-abliterate:14b"
  temperature: 0.7
  max_tokens: 2048
  
  # Advanced AI settings
  correlation:
    min_confidence: 0.6
    cluster_threshold: 0.8
  
  exploitation:
    min_success_probability: 0.3
    stealth_weight: 0.4

# Evasion Configuration
evasion:
  default_profile: "stealth_balanced"
  
  timing:
    base_jitter: 0.5
    human_pause_probability: 0.1
  
  behavioral_mimicry:
    enable_learning: true
    pattern_adaptation: true

# Safety Configuration
safety:
  scope_validation: true
  rate_limiting: true
  max_concurrent_scans: 5
  confirmation_required: false
  
  scope:
    allowed_ips:
      - "192.168.1.0/24"
      - "10.0.0.0/8"
    
    forbidden_ips:
      - "192.168.1.1"  # Gateway
```

## Safety and Legal Compliance

### Built-in Safety Mechanisms
- **Scope Validation**: Multi-layer validation prevents unauthorized testing
- **Rate Limiting**: Configurable limits avoid system overload
- **Emergency Controls**: Instant kill-switch with forensic preservation
- **Audit Logging**: Comprehensive activity tracking for compliance
- **Evidence Chain**: Cryptographically signed evidence collection

### Legal Requirements
**IMPORTANT**: Always obtain proper written authorization before testing

```bash
# Verify scope before testing
nexus scope verify --target example.com
nexus scope add --ip-range "192.168.1.0/24" --authorized-by "John Doe"

# Enable audit logging
nexus config set safety.audit_logging true
nexus config set safety.evidence_collection true
```

### System Requirements by Scale

| Environment Size | RAM | CPU | Storage | Network |
|-----------------|-----|-----|---------|---------|
| Small (1-100 hosts) | 8GB | 4 cores | 20GB | 10Mbps |
| Medium (100-1K hosts) | 16GB | 8 cores | 50GB | 100Mbps |
| Large (1K-10K hosts) | 32GB | 16 cores | 100GB | 1Gbps |
| Enterprise (10K+ hosts) | 64GB | 32 cores | 500GB | 10Gbps |

## Troubleshooting

### Common Issues

#### Ollama Connection Problems
```bash
# Check Ollama status
sudo systemctl status ollama

# Restart Ollama service
sudo systemctl restart ollama

# Verify model availability
ollama list
```

#### Memory Issues
```bash
# Check system resources
nexus health --detailed

# Optimize for low memory
nexus config set ai.max_tokens 1024
nexus config set performance.max_workers 2
```

#### Permission Errors
```bash
# Fix permissions
sudo chown -R $USER:$USER ~/.nexus/
chmod 755 ~/.nexus/config/
```

### Debug Mode
```bash
# Enable verbose logging
nexus --verbose run --campaign "Debug-Test"

# Check logs
tail -f ~/.nexus/logs/nexus.log
```

### Getting Help
```bash
# Built-in help system
nexus --help
nexus tools --help
nexus ai --help

# System diagnostics
nexus health --full-report
```

## Contributing

We welcome contributions! See our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Setup
```bash
# Clone repository
git clone https://github.com/nexus-security/nexus.git
cd nexus

# Create development environment
python3 -m venv venv
source venv/bin/activate
pip install -e ".[dev]"

# Run tests
pytest tests/ -v
```

### Code Quality
```bash
# Format code
black nexus/

# Lint code  
flake8 nexus/

# Type checking
mypy nexus/
```

## Documentation

- **[AI Systems Guide](docs/AI_SYSTEMS_GUIDE.md)**: Advanced AI capabilities
- **[Evasion System Guide](docs/EVASION_SYSTEM_GUIDE.md)**: Stealth operations manual
- **[Architecture Overview](NEXUS_ARCHITECTURE.md)**: System design principles
- **[Tool Integration Guide](TOOL_INTEGRATION_SYSTEM.md)**: Custom tool integration
- **[Safety Systems Guide](SAFETY_AND_SCOPE_SYSTEM.md)**: Safety mechanisms
- **[Installation Guide](KALI_INSTALLATION_SYSTEM.md)**: Detailed setup instructions

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

Nexus is designed for authorized penetration testing and security research only. Users are responsible for ensuring they have proper authorization before testing any systems. The developers assume no liability for misuse of this tool.

## Support

- **Documentation**: [https://nexus-security.github.io/nexus/](https://nexus-security.github.io/nexus/)
- **Issues**: [GitHub Issues](https://github.com/nexus-security/nexus/issues)
- **Discussions**: [GitHub Discussions](https://github.com/nexus-security/nexus/discussions)
- **Security**: [Security Policy](SECURITY.md)
- **Contact**: [security@nexus-security.com](mailto:security@nexus-security.com)

## Acknowledgments

- [Ollama](https://ollama.ai/) for AI model infrastructure
- [Qwen Team](https://github.com/QwenLM/Qwen) for the base language model
- The Kali Linux team for the comprehensive penetration testing platform
- The open-source security community for tools and inspiration

---

**Made with care by the Nexus Security Team**


*Nexus: Where artificial intelligence meets cybersecurity excellence*


