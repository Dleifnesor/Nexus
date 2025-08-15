# Nexus Auto-Installation Guide

## Quick Start

Run the comprehensive auto-installer from the main directory:

```bash
chmod +x auto-install.sh
./auto-install.sh
```

That's it! The script handles everything automatically.

## What It Does

The [`auto-install.sh`](auto-install.sh) script is a comprehensive All-In-One (AIO) installer that:

### 🔧 **Automatic Fixes**
- ✅ **Python Version Compatibility**: Automatically detects Python 3.11 vs 3.12+ and installs compatible packages
- ✅ **Mitmproxy Issues**: Fixes the SyntaxError with mitmproxy on Python < 3.12
- ✅ **Broken Packages**: Automatically repairs broken package dependencies
- ✅ **System Recovery**: Comprehensive error recovery between installation steps

### 🚀 **Complete Installation**
- ✅ **System Updates**: Updates and upgrades all system packages
- ✅ **Dependencies**: Installs all required system libraries and tools
- ✅ **Penetration Testing Tools**: Installs 25+ Kali security tools
- ✅ **GitHub Tools**: Clones and installs PEASS-ng, SecLists, AutoRecon, etc.
- ✅ **Python Libraries**: Installs 25+ security-focused Python packages
- ✅ **Ollama AI Engine**: Downloads and configures the AI engine
- ✅ **AI Model**: Downloads the 8GB Qwen3-14B-abliterated model
- ✅ **Nexus Framework**: Installs the main Nexus application
- ✅ **Configuration**: Sets up all config directories and files
- ✅ **CLI Setup**: Creates global `nexus` command
- ✅ **Environment**: Configures all environment variables

### 📊 **Progress Tracking**
- Real-time progress indicators (Step X/12)
- Colored output for easy reading
- Comprehensive logging
- Health check verification
- Final system status report

## Features

### Error Handling
- **Graceful Degradation**: Continues installation even if some components fail
- **Retry Logic**: Multiple attempts with error recovery between retries
- **Safe Execution**: Wrapper functions that handle command failures
- **Package Recovery**: Automatic fixing of broken package dependencies
- **Compatibility Detection**: Automatic Python version detection and fixes

### User Experience
- **Interactive Prompts**: Confirms before starting installation
- **Progress Indicators**: Shows current step and percentage complete
- **Colored Output**: Easy-to-read status messages
- **Comprehensive Logging**: Detailed information about each step
- **Final Summary**: Complete system status and quick start commands

### Compatibility
- **Kali Linux Optimized**: Designed specifically for Kali Linux
- **Debian Compatible**: Works on other Debian-based systems
- **Python Version Agnostic**: Handles both Python 3.11 and 3.12+
- **Architecture Independent**: Works on different hardware architectures

## Installation Time & Requirements

- **Time**: 30-60 minutes (depending on internet speed)
- **Disk Space**: ~15GB required
- **Internet**: Required for downloads
- **Permissions**: Must run as regular user with sudo access

## What Gets Installed

### System Tools
```
nmap, masscan, gobuster, dirb, nikto, sqlmap, hydra, john, hashcat,
metasploit-framework, enum4linux, smbclient, dnsrecon, sublist3r,
amass, theharvester, whatweb, wpscan, exploitdb, searchsploit,
crackmapexec, impacket-scripts, bloodhound, neo4j, responder
```

### GitHub Tools
```
PEASS-ng (LinPEAS/WinPEAS), SecLists, PayloadsAllTheThings,
AutoRecon, Impacket (latest), BloodHound.py
```

### Python Libraries
```
requests, beautifulsoup4, lxml, selenium, scapy, pycryptodome,
paramiko, netaddr, dnspython, python-nmap, shodan, censys,
virustotal-api, networkx, matplotlib, plotly, pandas, numpy,
asyncio, aiohttp, click, pyyaml, jinja2, colorama, tqdm, rich, typer
```

### AI Components
```
Ollama AI Engine, Qwen3-14B-abliterated Model (8GB)
```

## After Installation

### Quick Start Commands
```bash
nexus --version                                    # Check version
nexus health                                       # System health check
nexus --auto "find vulnerabilities in example.com" # Autonomous mode
nexus evasion profiles                             # List evasion profiles
nexus tools list                                   # List available tools
```

### Autonomous AI Examples
```bash
nexus run --auto "get into the SMB server on this network"
nexus run --auto "find SQL injection in the web app"
nexus run --auto "escalate privileges on the Linux server"
```

### Configuration Files
- **Main Config**: `~/.nexus/config/default.yaml`
- **Advanced Config**: `~/.nexus/config/example_advanced.yaml`
- **Tools Config**: `~/.nexus/config/kali_tools.yaml`
- **Logs**: `~/.nexus/logs/`
- **Reports**: `~/.nexus/reports/`

## Troubleshooting

### If Installation Fails
1. **Check Prerequisites**: Ensure you're on Kali Linux with sudo access
2. **Check Internet**: Verify internet connection for downloads
3. **Check Space**: Ensure at least 15GB free disk space
4. **Retry**: The script has built-in retry logic, try running again
5. **Manual Fix**: Check `MITMPROXY_FIX_README.md` for specific issues

### Common Issues
- **Mitmproxy Errors**: Automatically fixed by the script
- **Broken Packages**: Automatically repaired during installation
- **Ollama Issues**: Try `sudo systemctl restart ollama`
- **Permission Errors**: Ensure running as regular user, not root

### Getting Help
- **Documentation**: Check `./docs/` directory
- **Logs**: Check `~/.nexus/logs/` for detailed error information
- **Health Check**: Run `nexus health` to diagnose issues
- **Test Script**: Run `bash scripts/test_mitmproxy_fix.sh` for compatibility testing

## Manual Installation

If you prefer manual control, you can use the individual scripts:

```bash
# Test compatibility first
bash scripts/test_mitmproxy_fix.sh

# Run enhanced install script
bash scripts/install.sh

# Or fix mitmproxy issues only
bash scripts/fix_mitmproxy.sh
```

## Security Notice

⚠️ **IMPORTANT**: This tool is for authorized penetration testing only. Only use on systems you own or have explicit permission to test. Unauthorized use is illegal and unethical.

## Success Indicators

After installation, you should see:
- ✅ Nexus CLI working (`nexus --version`)
- ✅ Ollama running (`systemctl status ollama`)
- ✅ Python imports working (`python3 -c "import nexus"`)
- ✅ No broken packages (`dpkg --configure -a`)
- ✅ All environment variables set

The auto-installer provides a complete, robust installation experience with comprehensive error handling and automatic fixes for common issues.