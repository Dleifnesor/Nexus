# Nexus Evasion System Guide

This guide covers the comprehensive evasion capabilities of Nexus, designed to avoid detection during penetration testing operations while maintaining operational effectiveness.

## Overview

The Nexus Evasion System provides sophisticated detection avoidance capabilities through multiple layers of obfuscation, timing manipulation, behavioral mimicry, and AI-powered strategy generation. It's designed for professional red team operations where stealth is critical.

## Key Features

### 🥷 Multi-Layer Evasion
- **Timing Randomization**: Intelligent delays and jitter to avoid pattern detection
- **Traffic Obfuscation**: Payload encoding, fragmentation, and protocol manipulation
- **Behavioral Mimicry**: Mimics legitimate user and application behavior patterns
- **Decoy Traffic**: Generates legitimate-looking requests to mask real attacks

### 🤖 AI-Powered Strategy
- **Target Analysis**: AI analyzes target environment to recommend optimal evasion strategies
- **Dynamic Adaptation**: Adjusts techniques based on detected security controls
- **Success Probability**: Calculates detection probability for different approaches
- **Custom Recommendations**: Generates tailored evasion strategies for specific scenarios

### 📊 Detection Monitoring
- **Real-time Assessment**: Continuously monitors detection probability
- **Event Logging**: Tracks potential detection events for analysis
- **Performance Metrics**: Measures evasion effectiveness over time
- **Adaptive Learning**: Learns from detection events to improve future operations

## Evasion Profiles

Nexus includes several built-in evasion profiles optimized for different scenarios:

### Maximum Stealth Profile
```bash
nexus evasion set stealth_maximum
```

**Best for**: High-security environments, red team exercises, APT simulation
- **Stealth Rating**: 95%
- **Performance Impact**: 80%
- **Detection Risk**: Very Low
- **Complexity**: Expert

**Active Techniques**:
- Timing Randomization with extended jitter
- Traffic Fragmentation and reassembly
- Multi-layer Payload Encoding
- User Agent Rotation with realistic patterns
- Protocol Tunneling through legitimate channels
- Extensive Decoy Traffic generation
- Advanced Behavioral Mimicry
- Encryption Obfuscation

### Balanced Stealth Profile
```bash
nexus evasion set stealth_balanced
```

**Best for**: Standard penetration tests, moderate security environments
- **Stealth Rating**: 75%
- **Performance Impact**: 40%
- **Detection Risk**: Low
- **Complexity**: Medium

**Active Techniques**:
- Timing Randomization
- Payload Encoding (Base64, URL, Hex)
- User Agent Rotation
- Behavioral Mimicry patterns

### Minimal Stealth Profile
```bash
nexus evasion set stealth_minimal
```

**Best for**: Low-security environments, time-sensitive assessments
- **Stealth Rating**: 50%
- **Performance Impact**: 10%
- **Detection Risk**: Medium
- **Complexity**: Easy

**Active Techniques**:
- Basic Timing Randomization
- User Agent Rotation

### Red Team Profile
```bash
nexus evasion set red_team
```

**Best for**: Red team operations, advanced persistent threat simulation
- **Stealth Rating**: 90%
- **Performance Impact**: 60%
- **Detection Risk**: Very Low
- **Complexity**: Hard

**Active Techniques**:
- Advanced Timing Patterns
- Traffic Fragmentation
- Multi-encoding Payloads
- Sophisticated Behavioral Mimicry
- Decoy Traffic Campaigns
- Steganographic Communication

### APT Simulation Profile
```bash
nexus evasion set apt_simulation
```

**Best for**: Advanced persistent threat simulation, nation-state actor mimicry
- **Stealth Rating**: 92%
- **Performance Impact**: 70%
- **Detection Risk**: Very Low
- **Complexity**: Expert

**Active Techniques**:
- Long-term Timing Patterns
- Advanced Behavioral Mimicry
- Encryption Obfuscation
- Protocol Tunneling
- Steganographic Data Hiding

## Usage Examples

### Basic Evasion Operations

#### View Available Profiles
```bash
# List all evasion profiles
nexus evasion profiles

# View profiles in JSON format
nexus evasion profiles --format json
```

#### Set Active Profile
```bash
# Set balanced stealth profile
nexus evasion set stealth_balanced

# Check current status
nexus evasion status

# View detailed status
nexus evasion status --detailed
```

### Advanced Evasion Operations

#### Test Evasion Effectiveness
```bash
# Test evasion against target
nexus evasion test --target https://example.com --operation web_scan --requests 20

# Test with specific operation type
nexus evasion test --target 192.168.1.100 --operation port_scan --requests 50
```

#### AI-Powered Strategy Generation
```bash
# Analyze target and generate strategy
nexus evasion analyze --target-info target_analysis.json --operation web_app_test

# Save analysis results
nexus evasion analyze --target-info target.json --operation api_test --output strategy.json
```

#### Generate Evasion Reports
```bash
# Generate text report
nexus evasion report

# Generate JSON report
nexus evasion report --format json --output evasion_report.json
```

### Integration with Tool Execution

#### Manual Tool Integration
```bash
# Run tools with evasion applied automatically
nexus tools execute nmap 192.168.1.100 --evasion-profile stealth_maximum

# Web scanning with evasion
nexus tools execute nikto https://example.com --evasion-profile red_team
```

#### Campaign Integration
```bash
# Run campaign with evasion profile
nexus run --campaign "Web Assessment" --evasion-profile stealth_balanced

# High-stealth red team operation
nexus run --target 192.168.1.0/24 --evasion-profile apt_simulation
```

## Evasion Techniques Deep Dive

### 1. Timing Randomization

Timing randomization prevents pattern-based detection by introducing intelligent delays and jitter.

**How it works**:
- Analyzes base timing requirements
- Applies randomization based on stealth rating
- Includes occasional longer pauses to mimic human behavior
- Adapts to different operation types

**Configuration**:
```yaml
evasion:
  timing:
    base_jitter: 0.5          # Base jitter factor
    human_pause_probability: 0.1  # Chance of longer pause
    max_pause_duration: 30.0   # Maximum pause in seconds
```

**Example**:
```python
# Base delay of 2 seconds becomes 1.5-4.5 seconds with jitter
# 10% chance of 5-30 second pause to mimic human behavior
```

### 2. Payload Encoding

Multi-layer payload encoding prevents signature-based detection.

**Supported Encodings**:
- **Base64**: Standard base64 encoding
- **URL Encoding**: Single and double URL encoding
- **Hex Encoding**: Hexadecimal representation
- **Unicode Encoding**: Unicode escape sequences
- **Custom Encoding**: AI-generated encoding schemes

**Example**:
```bash
# Original payload
SELECT * FROM users WHERE id=1

# Base64 encoded
U0VMRUNUICogRlJPTSB1c2VycyBXSEVSRSBpZD0x

# Double URL encoded
%2553%2545%254C%2545%2543%2554%2520%252A%2520...
```

### 3. Behavioral Mimicry

Mimics legitimate user and application behavior patterns to blend in with normal traffic.

**Traffic Patterns**:

#### Normal Web Browsing
- Request intervals: 2.5-20 seconds
- Burst patterns: 1-5 requests
- Idle periods: 30-300 seconds
- Realistic user agents and headers

#### API Client Behavior
- Request intervals: 1-5 seconds
- Burst patterns: 5-20 requests
- Shorter idle periods: 10-60 seconds
- API-specific headers and user agents

#### Mobile Application Traffic
- Request intervals: 3-30 seconds
- Burst patterns: 2-6 requests
- Longer idle periods: 60-600 seconds
- Mobile-specific user agents

**Configuration**:
```yaml
evasion:
  behavioral_mimicry:
    patterns:
      normal_browsing:
        request_intervals: [2.5, 5.0, 8.0, 12.0, 15.0, 20.0]
        burst_patterns: [1, 2, 3, 5]
        idle_periods: [30.0, 60.0, 120.0, 300.0]
```

### 4. Traffic Fragmentation

Breaks large payloads into smaller fragments to avoid size-based detection.

**How it works**:
- Splits payloads into configurable fragment sizes
- Sends fragments with delays between them
- Reassembles on target side if needed
- Randomizes fragment sizes for additional obfuscation

**Example**:
```python
# Original payload: "SELECT * FROM users WHERE admin=1"
# Fragmented into 8-byte chunks:
# Fragment 1: "SELECT *"
# Fragment 2: " FROM us"
# Fragment 3: "ers WHER"
# Fragment 4: "E admin="
# Fragment 5: "1"
```

### 5. Decoy Traffic Generation

Generates legitimate-looking requests to mask real attack traffic.

**Decoy Types**:
- **Static Resource Requests**: CSS, JS, images, favicon
- **Common Page Requests**: index, about, contact, login
- **API Status Checks**: health, status, version endpoints
- **Search Queries**: Legitimate search terms and patterns

**Configuration**:
```yaml
evasion:
  decoy_traffic:
    ratio: 3                    # 3 decoy requests per real request
    legitimate_paths:
      - "/"
      - "/index.html"
      - "/favicon.ico"
      - "/robots.txt"
    delay_range: [1.0, 10.0]   # Random delay between decoys
```

### 6. User Agent Rotation

Rotates through realistic user agent strings to avoid fingerprinting.

**User Agent Categories**:
- **Desktop Browsers**: Chrome, Firefox, Safari, Edge
- **Mobile Browsers**: Mobile Chrome, Safari, Samsung Browser
- **API Clients**: curl, wget, Python requests, Postman
- **Custom Agents**: Tool-specific or custom user agents

**Smart Rotation**:
- Maintains consistency within sessions
- Matches user agents to operation types
- Uses statistically common user agents
- Avoids suspicious or outdated agents

## AI-Powered Evasion Strategy

### Target Analysis

The AI system analyzes target environments to recommend optimal evasion strategies:

```json
{
  "target_info": {
    "host": "example.com",
    "services": ["http", "https", "ssh"],
    "os": "Linux",
    "security_controls": ["firewall", "ids", "waf"],
    "response_times": [0.1, 0.2, 0.15],
    "error_patterns": ["403", "429", "503"]
  }
}
```

**AI Analysis Output**:
```json
{
  "recommended_profile": "red_team",
  "timing_strategy": {
    "pattern": "randomized_intervals",
    "base_delay": 5.0,
    "jitter_factor": 2.0,
    "rationale": "IDS detected - use extended delays"
  },
  "encoding_strategy": {
    "primary": "double_url",
    "fallback": "base64",
    "rationale": "WAF present - use double encoding"
  },
  "behavioral_strategy": {
    "pattern": "normal_browsing",
    "decoy_ratio": 5,
    "rationale": "Mimic legitimate user traffic"
  },
  "risk_assessment": {
    "detection_probability": 0.15,
    "confidence": 0.85,
    "factors": ["IDS signatures", "rate limiting", "geo-blocking"]
  }
}
```

### Dynamic Adaptation

The system adapts strategies based on real-time feedback:

1. **Response Analysis**: Monitors HTTP response codes and timing
2. **Error Pattern Detection**: Identifies blocking or rate limiting
3. **Success Rate Tracking**: Measures technique effectiveness
4. **Strategy Adjustment**: Modifies approach based on results

## Configuration

### Global Evasion Settings

```yaml
evasion:
  # Default profile for new operations
  default_profile: "stealth_balanced"
  
  # Global evasion settings
  global:
    enable_ai_strategy: true
    adaptive_learning: true
    detection_threshold: 0.7
    
  # Timing configuration
  timing:
    base_jitter: 0.5
    human_pause_probability: 0.1
    max_pause_duration: 30.0
    
  # Encoding configuration
  encoding:
    default_method: "auto"
    fallback_methods: ["base64", "url", "hex"]
    custom_encoders: true
    
  # Behavioral mimicry
  behavioral_mimicry:
    enable_learning: true
    pattern_adaptation: true
    session_consistency: true
    
  # Decoy traffic
  decoy_traffic:
    default_ratio: 3
    max_concurrent: 5
    legitimate_only: true
    
  # Detection monitoring
  monitoring:
    log_events: true
    alert_threshold: 0.8
    history_retention: 7  # days
```

### Profile-Specific Settings

```yaml
evasion:
  profiles:
    custom_stealth:
      name: "Custom High Stealth"
      description: "Custom profile for specific environment"
      techniques:
        - timing_randomization
        - payload_encoding
        - behavioral_mimicry
        - decoy_traffic
        - traffic_fragmentation
      
      settings:
        timing:
          jitter_factor: 3.0
          min_delay: 2.0
          max_delay: 30.0
        
        encoding:
          methods: ["base64", "double_url", "hex"]
          randomize_method: true
        
        behavioral:
          pattern: "normal_browsing"
          consistency_level: 0.8
        
        decoy:
          ratio: 5
          burst_size: 3
```

## Best Practices

### 1. Profile Selection

**High-Security Environments**:
- Use `stealth_maximum` or `apt_simulation`
- Accept higher performance impact for better stealth
- Enable all available evasion techniques

**Standard Assessments**:
- Use `stealth_balanced` for good stealth with reasonable performance
- Monitor detection probability and adjust if needed

**Time-Sensitive Operations**:
- Use `stealth_minimal` for basic evasion with minimal delay
- Focus on critical techniques like timing randomization

### 2. Target Analysis

**Always Analyze First**:
```bash
# Gather target information
nexus tools execute nmap target.com --output target_scan.json

# Generate evasion strategy
nexus evasion analyze --target-info target_scan.json --operation web_test
```

**Consider Security Controls**:
- **WAF Present**: Use encoding and fragmentation
- **IDS/IPS Active**: Increase timing delays and use decoys
- **Rate Limiting**: Reduce request frequency and use longer delays
- **Geo-blocking**: Consider proxy chains or VPN usage

### 3. Monitoring and Adaptation

**Watch for Detection Indicators**:
- HTTP 403/429 responses
- Connection timeouts or resets
- Unusual response times
- CAPTCHA challenges

**Adapt Strategies**:
```bash
# Check current detection probability
nexus evasion status --detailed

# Generate updated strategy if detection risk is high
nexus evasion analyze --target-info updated_target.json --operation current_op
```

### 4. Performance Optimization

**Balance Stealth vs Speed**:
- Start with balanced profile
- Increase stealth if detection occurs
- Reduce stealth for time-critical operations

**Monitor Resource Usage**:
- High-stealth profiles use more CPU and memory
- Decoy traffic increases network usage
- Encoding/decoding adds processing overhead

## Integration Examples

### Tool Integration

```python
from nexus.core.evasion import EvasionManager, EvasionIntegration

# Initialize evasion system
evasion_manager = EvasionManager(ollama_client, config)
evasion_manager.set_evasion_profile("red_team")

# Integrate with tool execution
integration = EvasionIntegration(evasion_manager)

# Prepare tool execution with evasion
params = await integration.prepare_tool_execution("nmap", "192.168.1.100", {
    "args": ["-sS", "-sV"],
    "timeout": 300
})

# Execute with evasion applied
result = tool_manager.execute_tool("nmap", "192.168.1.100", **params)
```

### Campaign Integration

```python
# Campaign with evasion profile
campaign_config = {
    "name": "Stealth Assessment",
    "targets": ["192.168.1.0/24"],
    "evasion_profile": "stealth_maximum",
    "phases": ["recon", "scan", "exploit"]
}

# AI will automatically apply evasion techniques
campaign = Campaign(campaign_config)
await campaign.execute()
```

## Troubleshooting

### Common Issues

#### High Detection Probability
```bash
# Check current status
nexus evasion status --detailed

# Generate new strategy
nexus evasion analyze --target-info target.json --operation current

# Switch to higher stealth profile
nexus evasion set stealth_maximum
```

#### Performance Issues
```bash
# Check performance impact
nexus evasion profiles

# Switch to lower impact profile
nexus evasion set stealth_minimal

# Optimize specific techniques
nexus config set evasion.decoy_traffic.ratio 1
```

#### Encoding Problems
```bash
# Test encoding methods
nexus evasion test --target example.com --operation injection_test

# Check encoding configuration
nexus config show evasion.encoding

# Reset to default encoding
nexus config set evasion.encoding.default_method auto
```

### Debug Mode

Enable verbose evasion logging:
```bash
nexus --verbose evasion test --target example.com
```

Check evasion logs:
```bash
tail -f ~/.nexus/logs/evasion.log
```

## Security Considerations

### Operational Security
- **Profile Selection**: Choose appropriate profiles for target environment
- **Detection Monitoring**: Continuously monitor for detection indicators
- **Adaptive Response**: Be prepared to change strategies if detected
- **Evidence Management**: Ensure evasion logs don't compromise operations

### Legal and Ethical Use
- **Authorization**: Only use on authorized targets
- **Scope Compliance**: Ensure evasion techniques comply with engagement scope
- **Documentation**: Maintain records of evasion techniques used
- **Responsible Disclosure**: Follow responsible disclosure practices

### Technical Security
- **Configuration Security**: Protect evasion configuration files
- **Log Security**: Secure evasion logs and detection history
- **Network Security**: Use secure channels for AI strategy generation
- **Data Protection**: Protect target analysis data and strategies

---

For more information, see the [main documentation](../README.md) or the [AI Systems Guide](AI_SYSTEMS_GUIDE.md).