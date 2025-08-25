# Nexus AI Systems Guide

This guide covers the advanced AI-powered capabilities of Nexus, including vulnerability correlation, exploit recommendation, and attack path planning systems.

## Overview

Nexus incorporates three sophisticated AI systems that work together to provide intelligent penetration testing automation:

1. **Vulnerability Correlation Engine** - Analyzes and correlates vulnerabilities from multiple tools
2. **Exploit Recommendation System** - Recommends appropriate exploits with success probability assessment
3. **Attack Path Planning System** - Plans multi-step attack paths to achieve campaign objectives

## Vulnerability Correlation Engine

### Purpose
The Vulnerability Correlation Engine analyzes vulnerabilities discovered by various tools and identifies relationships, clusters, and attack chains that might not be obvious when viewing individual findings.

### Key Features
- **Multi-tool Integration**: Extracts vulnerabilities from Nmap, Nikto, SQLMap, and 100+ other tools
- **AI-Powered Analysis**: Uses Qwen3-14B-abliterated model for intelligent vulnerability analysis
- **Clustering Algorithms**: Groups related vulnerabilities by host, service, attack vector, and impact
- **Risk Assessment**: Calculates comprehensive risk scores using CVSS and contextual factors
- **Attack Chain Identification**: Identifies sequences of vulnerabilities that can be chained together

### Usage Examples

#### Basic Vulnerability Correlation
```bash
# Correlate vulnerabilities from tool results
nexus ai vuln correlate --input tool_results.json --output correlation_report.json

# View correlation results in table format
nexus ai vuln correlate --input tool_results.json --format table
```

#### Advanced Correlation with Filtering
```bash
# Correlate only high-severity vulnerabilities
nexus ai vuln correlate --input results.json --min-severity high

# Focus on specific host
nexus ai vuln correlate --input results.json --target 192.168.1.100
```

### Input Format
The correlation engine expects tool results in JSON format:
```json
{
  "nmap": {
    "target_info": {"host": "192.168.1.100"},
    "raw_output": "Nmap scan results...",
    "parsed_data": {...}
  },
  "nikto": {
    "target_info": {"host": "192.168.1.100"},
    "raw_output": "Nikto scan results...",
    "parsed_data": {...}
  }
}
```

### Output Format
Correlation results include:
```json
{
  "summary": {
    "total": 25,
    "exploitable": 12,
    "clusters": 5,
    "by_severity": {"critical": 2, "high": 8, "medium": 10, "low": 5}
  },
  "top_risks": [...],
  "clusters": [
    {
      "id": "cluster_001",
      "type": "host_based",
      "risk_score": 8.5,
      "vulnerabilities": [...],
      "description": "Web application vulnerabilities on 192.168.1.100"
    }
  ]
}
```

## Exploit Recommendation System

### Purpose
The Exploit Recommendation System matches discovered vulnerabilities to appropriate exploits, providing success probability assessments and generating custom exploit scripts.

### Key Features
- **Comprehensive Database**: Integrates Metasploit modules, Exploit-DB entries, and custom exploits
- **Success Probability**: AI-calculated success rates based on target environment and vulnerability details
- **Stealth Assessment**: Evaluates detection probability and provides stealth ratings
- **Custom Script Generation**: Creates tailored exploit scripts using AI
- **MITRE ATT&CK Mapping**: Maps exploits to standardized attack techniques

### Usage Examples

#### Basic Exploit Recommendation
```bash
# Get exploit recommendations for vulnerabilities
nexus ai exploit recommend --vuln-file vulnerabilities.json

# Filter by complexity and prioritize stealth
nexus ai exploit recommend --vuln-file vulns.json --complexity medium --stealth
```

#### Custom Script Generation
```bash
# Generate custom exploit script
nexus ai exploit generate-script --recommendation-id EXP-001 \
  --recommendations-file recommendations.json \
  --attacker-ip 192.168.1.50 \
  --output custom_exploit.py
```

### Recommendation Criteria
The system evaluates exploits based on:
- **Vulnerability Match**: How well the exploit targets the specific vulnerability
- **Environment Compatibility**: Target OS, service versions, network position
- **Success Probability**: Historical success rates and environmental factors
- **Stealth Rating**: Likelihood of detection by security controls
- **Complexity**: Required skill level and time investment

### Output Format
Exploit recommendations include:
```json
{
  "exploit_id": "EXP-SQL-001",
  "name": "SQL Injection Authentication Bypass",
  "description": "Bypass authentication using SQL injection",
  "target_vulnerability": "CVE-2023-1234",
  "success_probability": 0.85,
  "stealth_rating": 0.7,
  "complexity": "medium",
  "metasploit_module": "auxiliary/scanner/http/sql_login",
  "execution_steps": [
    "Identify injection point in login form",
    "Craft SQL payload to bypass authentication",
    "Execute payload and verify access"
  ],
  "requirements": ["Web application access", "SQL injection point"],
  "mitre_techniques": ["T1190", "T1078"]
}
```

## Attack Path Planning System

### Purpose
The Attack Path Planning System constructs attack graphs and plans multi-step attack paths to achieve specific campaign objectives using graph theory and AI analysis.

### Key Features
- **Graph-Based Modeling**: Models target environment as nodes (system states) and edges (attack actions)
- **Multi-Objective Planning**: Supports various objectives like initial access, privilege escalation, persistence
- **Path Optimization**: Finds optimal paths considering success probability, stealth, and time
- **MITRE ATT&CK Integration**: Maps attack techniques to standardized framework
- **Constraint Handling**: Respects stealth requirements, time limits, and complexity constraints

### Usage Examples

#### Basic Attack Path Planning
```bash
# Plan attack paths for privilege escalation
nexus ai attack plan --vuln-file vulnerabilities.json \
  --environment environment.json \
  --objective privilege_escalation \
  --max-paths 5
```

#### Stealth-Focused Planning
```bash
# Plan stealthy attack paths
nexus ai attack plan --vuln-file vulns.json \
  --environment env.json \
  --objective persistence \
  --stealth \
  --output attack_paths.json
```

#### Attack Graph Visualization
```bash
# Generate attack graph for visualization
nexus ai attack graph --vuln-file vulns.json \
  --environment env.json \
  --output graph.json \
  --format dot

# Convert to image using Graphviz
dot -Tpng graph.dot -o attack_graph.png
```

### Environment Format
The planner requires environment data describing the target:
```json
{
  "hosts": [
    {
      "ip": "192.168.1.100",
      "hostname": "web-server",
      "os": "Linux",
      "services": ["ssh", "http", "mysql"],
      "network_position": "dmz",
      "value_score": 7.5
    }
  ],
  "network": {
    "subnets": ["192.168.1.0/24", "10.0.0.0/8"],
    "gateways": ["192.168.1.1"],
    "critical_assets": ["192.168.1.200"],
    "security_controls": ["firewall", "ids"]
  }
}
```

### Attack Path Output
Planned attack paths include:
```json
{
  "path_id": "path_001",
  "name": "SSH Compromise to Domain Admin",
  "description": "Multi-step path from initial SSH access to domain admin",
  "objective": "privilege_escalation",
  "total_success_probability": 0.65,
  "total_detection_risk": 0.25,
  "estimated_time": 3600,
  "complexity_score": 6.5,
  "stealth_score": 0.75,
  "phases_covered": ["initial_access", "privilege_escalation", "persistence"],
  "mitre_techniques": ["T1110.001", "T1068", "T1053.003"],
  "required_tools": ["hydra", "linpeas", "crontab"],
  "execution_steps": [
    {
      "step": 1,
      "technique": "SSH Brute Force",
      "source": "attacker",
      "target": "192.168.1.100",
      "success_probability": 0.8,
      "detection_probability": 0.3,
      "estimated_time": 900,
      "tools": ["hydra"],
      "mitre_technique": "T1110.001"
    }
  ]
}
```

## AI Analysis Dashboard

### Purpose
The AI Analysis Dashboard provides real-time monitoring and analysis of AI-powered penetration testing operations.

### Features
- **Real-time Monitoring**: Live updates of AI analysis progress
- **System Status**: Health checks for all AI components
- **Data Analysis**: Automatic processing of new vulnerability data
- **Interactive Reports**: HTML and JSON report generation
- **File Monitoring**: Automatic detection of new analysis data

### Usage Examples

#### Start Dashboard
```bash
# Start interactive dashboard
nexus dashboard start --port 8080 --data-dir /path/to/analysis/data

# Start with custom refresh interval
nexus dashboard start --auto-refresh 60 --host 0.0.0.0
```

#### Batch Analysis
```bash
# Analyze collected data
nexus dashboard analyze --input-dir ./analysis_data --output report.html --format html

# Generate JSON report
nexus dashboard analyze --input-dir ./data --output analysis.json --format json
```

#### Monitor Directory
```bash
# Monitor for new analysis files
nexus dashboard monitor --directory ./live_data --interval 30 --action analyze
```

## Integration with Main Nexus Workflow

### Automated Integration
The AI systems integrate seamlessly with Nexus campaigns:

```bash
# Run campaign with AI analysis
nexus run --campaign "web_app_test" --ai-analysis

# The workflow automatically:
# 1. Runs reconnaissance tools
# 2. Correlates discovered vulnerabilities
# 3. Recommends appropriate exploits
# 4. Plans attack paths to objectives
# 5. Executes planned attacks
# 6. Generates comprehensive reports
```

### Manual Integration
For custom workflows, use AI systems individually:

```bash
# Step 1: Run tools and collect data
nexus tools scan 192.168.1.100 --output-dir ./scan_results

# Step 2: Correlate vulnerabilities
nexus ai vuln correlate --input ./scan_results/summary.json --output vulns.json

# Step 3: Get exploit recommendations
nexus ai exploit recommend --vuln-file vulns.json --output exploits.json

# Step 4: Plan attack paths
nexus ai attack plan --vuln-file vulns.json --environment env.json --output paths.json

# Step 5: Generate custom scripts
nexus ai exploit generate-script --recommendation-id EXP-001 --recommendations-file exploits.json
```

## Configuration

### AI Model Settings
Configure AI behavior in `~/.nexus/config/default.yaml`:

```yaml
ai:
  model: "huihui_ai/qwen2.5-abliterate:14b"
  temperature: 0.7
  max_tokens: 2048
  timeout: 300
  
  # Vulnerability correlation settings
  correlation:
    min_confidence: 0.6
    cluster_threshold: 0.8
    max_clusters: 20
  
  # Exploit recommendation settings
  exploitation:
    min_success_probability: 0.3
    stealth_weight: 0.4
    complexity_weight: 0.3
  
  # Attack path planning settings
  planning:
    max_path_length: 10
    max_paths: 20
    optimization_weight:
      success: 0.4
      stealth: 0.3
      time: 0.3
```

### Performance Tuning
For optimal performance:

1. **GPU Acceleration**: Use GPU-enabled Ollama for faster AI inference
2. **Model Selection**: Choose appropriate model size based on hardware
3. **Batch Processing**: Process multiple vulnerabilities together
4. **Caching**: Enable result caching for repeated analyses

## Best Practices

### Vulnerability Correlation
1. **Clean Input Data**: Ensure tool outputs are properly formatted
2. **Context Information**: Provide comprehensive target information
3. **Regular Updates**: Keep vulnerability databases current
4. **Manual Review**: Always review AI-generated correlations

### Exploit Recommendation
1. **Environment Accuracy**: Provide accurate target environment details
2. **Success Validation**: Test recommended exploits in safe environments
3. **Stealth Considerations**: Balance success probability with detection risk
4. **Legal Compliance**: Ensure all exploits comply with engagement scope

### Attack Path Planning
1. **Complete Mapping**: Provide comprehensive environment topology
2. **Objective Clarity**: Clearly define campaign objectives
3. **Constraint Setting**: Set appropriate stealth and time constraints
4. **Path Validation**: Validate planned paths before execution

## Troubleshooting

### Common Issues

#### Ollama Connection Errors
```bash
# Check Ollama status
nexus health

# Restart Ollama service
sudo systemctl restart ollama

# Check model availability
ollama list
```

#### Low-Quality Recommendations
- Verify input data quality and completeness
- Check AI model temperature settings
- Ensure sufficient context information
- Review and update exploit databases

#### Performance Issues
- Monitor system resources during AI operations
- Consider using smaller models for resource-constrained environments
- Enable result caching
- Process data in smaller batches

### Debug Mode
Enable verbose logging for troubleshooting:
```bash
nexus --verbose ai vuln correlate --input data.json
```

## Advanced Topics

### Custom AI Prompts
Modify AI prompts for specific use cases by editing prompt templates in `nexus/ai/prompts/`.

### Database Extensions
Extend exploit databases by adding custom entries to `config/custom_exploits.yaml`.

### Integration APIs
Use the Python API for custom integrations:

```python
from nexus.ai.vulnerability_correlator import VulnerabilityCorrelator
from nexus.ai.exploit_recommender import ExploitRecommender
from nexus.ai.attack_path_planner import AttackPathPlanner

# Initialize AI systems
correlator = VulnerabilityCorrelator(ollama_client, config)
recommender = ExploitRecommender(ollama_client, config)
planner = AttackPathPlanner(ollama_client, config)

# Use in custom workflows
vulnerabilities = await correlator.extract_vulnerabilities(tool_output)
exploits = await recommender.recommend_exploits(vulnerabilities[0])
paths = await planner.plan_attack_paths(objective, environment)
```

## Security Considerations

### AI Model Security
- Use trusted AI models from verified sources
- Regularly update models to latest versions
- Monitor for model poisoning or adversarial inputs
- Implement input validation and sanitization

### Data Privacy
- Ensure sensitive target data is handled securely
- Use local AI models to avoid data transmission
- Implement proper data retention policies
- Encrypt stored analysis results

### Operational Security
- Validate all AI-generated recommendations
- Implement human oversight for critical decisions
- Maintain audit logs of AI operations
- Follow responsible disclosure practices

---

For more information, see the [main documentation](../README.md) or visit the [Nexus GitHub repository](https://github.com/nexus-security/nexus).