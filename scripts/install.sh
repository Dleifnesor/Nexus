#!/bin/bash

# Nexus AI-Powered Penetration Testing Tool
# Automated Installation Script for Kali Linux
# 
# This script installs Nexus and all its dependencies on Kali Linux
# including Ollama, the AI model, and all required penetration testing tools.

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
check_root() {
    if [[ $EUID -eq 0 ]]; then
        log_error "This script should not be run as root for security reasons."
        log_info "Please run as a regular user with sudo privileges."
        exit 1
    fi
}

# Check if running on Kali Linux
check_kali() {
    if ! grep -q "Kali" /etc/os-release 2>/dev/null; then
        log_warning "This script is optimized for Kali Linux."
        log_warning "It may work on other Debian-based systems but is not guaranteed."
        read -p "Continue anyway? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    else
        log_success "Kali Linux detected"
    fi
}

# Update system packages
update_system() {
    log_info "Updating system packages..."
    sudo apt update && sudo apt upgrade -y
    log_success "System packages updated"
}

# Install system dependencies
install_system_deps() {
    log_info "Installing system dependencies..."
    
    local packages=(
        "python3"
        "python3-pip"
        "python3-venv"
        "python3-dev"
        "git"
        "curl"
        "wget"
        "build-essential"
        "libssl-dev"
        "libffi-dev"
        "libxml2-dev"
        "libxslt1-dev"
        "zlib1g-dev"
        "libjpeg-dev"
        "libpq-dev"
        "sqlite3"
        "libsqlite3-dev"
        "graphviz"
        "graphviz-dev"
        "pkg-config"
        "dos2unix"
    )
    
    for package in "${packages[@]}"; do
        if ! dpkg -l | grep -q "^ii  $package "; then
            log_info "Installing $package..."
            sudo apt install -y "$package"
        else
            log_info "$package is already installed"
        fi
    done
    
    log_success "System dependencies installed"
}

# Install penetration testing tools
install_pentest_tools() {
    log_info "Installing penetration testing tools..."
    
    # Update Kali repositories first
    sudo apt update
    
    # Core Kali tools that should be available
    local kali_tools=(
        "nmap"
        "masscan"
        "gobuster"
        "dirb"
        "nikto"
        "sqlmap"
        "hydra"
        "john"
        "hashcat"
        "metasploit-framework"
        "enum4linux"
        "smbclient"
        "dnsrecon"
        "sublist3r"
        "amass"
        "theharvester"
        "whatweb"
        "wpscan"
        "exploitdb"
        "searchsploit"
        "crackmapexec"
        "impacket-scripts"
        "bloodhound"
        "neo4j"
        "responder"
    )
    
    for tool in "${kali_tools[@]}"; do
        if ! command -v "$tool" &> /dev/null && ! dpkg -l | grep -q "^ii  $tool "; then
            log_info "Installing $tool..."
            sudo apt install -y "$tool" || log_warning "Failed to install $tool - may not be available in repositories"
        else
            log_info "$tool is already available"
        fi
    done
    
    # Install additional tools from GitHub if needed
    install_github_tools
    
    # Install Python security tools
    install_python_security_tools
    
    log_success "Penetration testing tools installed"
}

# Install tools from GitHub
install_github_tools() {
    local tools_dir="/opt/pentest-tools"
    
    if [[ ! -d "$tools_dir" ]]; then
        sudo mkdir -p "$tools_dir"
        sudo chown $USER:$USER "$tools_dir"
    fi
    
    cd "$tools_dir"
    
    # LinPEAS and WinPEAS
    if [[ ! -d "PEASS-ng" ]]; then
        log_info "Installing PEASS-ng (LinPEAS/WinPEAS)..."
        git clone https://github.com/carlospolop/PEASS-ng.git
        chmod +x PEASS-ng/linPEAS/linpeas.sh
    fi
    
    # SecLists wordlists
    if [[ ! -d "SecLists" ]]; then
        log_info "Installing SecLists wordlists..."
        git clone https://github.com/danielmiessler/SecLists.git
    fi
    
    # PayloadsAllTheThings
    if [[ ! -d "PayloadsAllTheThings" ]]; then
        log_info "Installing PayloadsAllTheThings..."
        git clone https://github.com/swisskyrepo/PayloadsAllTheThings.git
    fi
    
    # AutoRecon
    if [[ ! -d "AutoRecon" ]]; then
        log_info "Installing AutoRecon..."
        git clone https://github.com/Tib3rius/AutoRecon.git
        cd AutoRecon
        sudo python3 -m pip install -r requirements.txt
        cd ..
    fi
    
    # Impacket (latest version)
    if [[ ! -d "impacket" ]]; then
        log_info "Installing latest Impacket..."
        git clone https://github.com/SecureAuthCorp/impacket.git
        cd impacket
        sudo python3 -m pip install .
        cd ..
    fi
    
    # BloodHound.py
    if [[ ! -d "BloodHound.py" ]]; then
        log_info "Installing BloodHound.py..."
        git clone https://github.com/fox-it/BloodHound.py.git
        cd BloodHound.py
        sudo python3 -m pip install .
        cd ..
    fi
    
    # Update PATH to include tools directory
    if ! grep -q "$tools_dir" ~/.bashrc; then
        echo "export PATH=\$PATH:$tools_dir" >> ~/.bashrc
        echo "export PATH=\$PATH:$tools_dir/PEASS-ng/linPEAS" >> ~/.bashrc
        echo "export PATH=\$PATH:$tools_dir/AutoRecon" >> ~/.bashrc
    fi
    
    cd - > /dev/null
}

# Install Python security tools
install_python_security_tools() {
    log_info "Installing Python security tools..."
    
    local python_tools=(
        "requests"
        "beautifulsoup4"
        "lxml"
        "selenium"
        "scapy"
        "pycryptodome"
        "paramiko"
        "netaddr"
        "dnspython"
        "python-nmap"
        "shodan"
        "censys"
        "virustotal-api"
        "networkx"
        "matplotlib"
        "plotly"
        "pandas"
        "numpy"
        "asyncio"
        "aiohttp"
        "click"
        "pyyaml"
        "jinja2"
        "colorama"
        "tqdm"
        "rich"
        "typer"
    )
    
    for tool in "${python_tools[@]}"; do
        log_info "Installing Python package: $tool"
        sudo python3 -m pip install "$tool" || log_warning "Failed to install $tool"
    done
}

# Install Ollama
install_ollama() {
    log_info "Installing Ollama..."
    
    if command -v ollama &> /dev/null; then
        log_info "Ollama is already installed"
        return
    fi
    
    # Download and install Ollama
    curl -fsSL https://ollama.ai/install.sh | sh
    
    # Create ollama user and group if they don't exist
    if ! id "ollama" &>/dev/null; then
        sudo useradd -r -s /bin/false -d /usr/share/ollama -m ollama
    fi
    
    # Create systemd service file
    sudo tee /etc/systemd/system/ollama.service > /dev/null << 'EOF'
[Unit]
Description=Ollama Service
After=network-online.target

[Service]
ExecStart=/usr/local/bin/ollama serve
User=ollama
Group=ollama
Restart=always
RestartSec=3
Environment="PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
Environment="OLLAMA_HOST=0.0.0.0"

[Install]
WantedBy=default.target
EOF
    
    # Start Ollama service
    sudo systemctl daemon-reload
    sudo systemctl enable ollama
    sudo systemctl start ollama
    
    # Wait for Ollama to start
    log_info "Waiting for Ollama to start..."
    sleep 10
    
    # Verify Ollama installation
    if command -v ollama &> /dev/null && systemctl is-active --quiet ollama; then
        log_success "Ollama installed and running successfully"
    else
        log_error "Ollama installation failed"
        exit 1
    fi
}

# Download AI model
download_ai_model() {
    log_info "Downloading AI model (this may take a while - up to 8GB download)..."
    
    # Check if model is already available
    if ollama list | grep -q "qwen3-14b-abliterated"; then
        log_info "AI model is already downloaded"
        return
    fi
    
    # Download the model with retry logic
    local max_retries=3
    local retry_count=0
    
    while [ $retry_count -lt $max_retries ]; do
        log_info "Downloading AI model (attempt $((retry_count + 1))/$max_retries)..."
        
        if ollama pull mlabonne/Qwen3-14B-abliterated; then
            break
        else
            retry_count=$((retry_count + 1))
            if [ $retry_count -lt $max_retries ]; then
                log_warning "Download failed, retrying in 30 seconds..."
                sleep 30
            fi
        fi
    done
    
    # Verify model download
    if ollama list | grep -q "qwen3-14b-abliterated"; then
        log_success "AI model downloaded successfully"
    else
        log_error "AI model download failed after $max_retries attempts"
        log_error "You can manually download it later with: ollama pull mlabonne/Qwen3-14B-abliterated"
        # Don't exit - continue with installation
    fi
}

# Install Nexus
install_nexus() {
    log_info "Installing Nexus..."
    
    # Convert line endings for all Python files (in case developed on Windows)
    log_info "Converting line endings to Unix format..."
    find . -name "*.py" -type f -exec dos2unix {} \; 2>/dev/null || true
    find . -name "*.sh" -type f -exec dos2unix {} \; 2>/dev/null || true
    find . -name "*.yaml" -type f -exec dos2unix {} \; 2>/dev/null || true
    find . -name "*.yml" -type f -exec dos2unix {} \; 2>/dev/null || true
    find . -name "*.txt" -type f -exec dos2unix {} \; 2>/dev/null || true
    find . -name "*.md" -type f -exec dos2unix {} \; 2>/dev/null || true
    
    # Create virtual environment
    if [[ ! -d "venv" ]]; then
        python3 -m venv venv
    fi
    
    # Activate virtual environment
    source venv/bin/activate
    
    # Upgrade pip and install wheel
    pip install --upgrade pip wheel setuptools
    
    # Install Nexus dependencies first
    if [[ -f "requirements.txt" ]]; then
        pip install -r requirements.txt
    fi
    
    # Install Nexus in development mode
    pip install -e .
    
    # Verify installation
    if python -c "import nexus" 2>/dev/null; then
        log_success "Nexus installed successfully"
    else
        log_error "Nexus installation failed"
        exit 1
    fi
    
    deactivate
}

# Create configuration directories
create_config_dirs() {
    log_info "Creating configuration directories..."
    
    local config_dirs=(
        "$HOME/.nexus"
        "$HOME/.nexus/config"
        "$HOME/.nexus/logs"
        "$HOME/.nexus/reports"
        "$HOME/.nexus/data"
        "$HOME/.nexus/scripts"
        "$HOME/.nexus/evidence"
        "$HOME/.nexus/wordlists"
        "$HOME/.nexus/payloads"
    )
    
    for dir in "${config_dirs[@]}"; do
        if [[ ! -d "$dir" ]]; then
            mkdir -p "$dir"
            log_info "Created directory: $dir"
        fi
    done
    
    # Copy default configuration
    if [[ -f "config/default.yaml" && ! -f "$HOME/.nexus/config/default.yaml" ]]; then
        cp config/default.yaml "$HOME/.nexus/config/"
        log_info "Copied default configuration"
    fi
    
    # Copy advanced configuration example
    if [[ -f "config/example_advanced.yaml" && ! -f "$HOME/.nexus/config/example_advanced.yaml" ]]; then
        cp config/example_advanced.yaml "$HOME/.nexus/config/"
        log_info "Copied advanced configuration example"
    fi
    
    # Copy Kali tools configuration
    if [[ -f "config/kali_tools.yaml" && ! -f "$HOME/.nexus/config/kali_tools.yaml" ]]; then
        cp config/kali_tools.yaml "$HOME/.nexus/config/"
        log_info "Copied Kali tools configuration"
    fi
    
    # Set proper permissions
    chmod 700 "$HOME/.nexus"
    chmod 600 "$HOME/.nexus/config"/* 2>/dev/null || true
    
    log_success "Configuration directories created"
}

# Create CLI wrapper script
create_cli_wrapper() {
    log_info "Creating CLI wrapper script..."
    
    local wrapper_script="/usr/local/bin/nexus"
    local nexus_dir="$(pwd)"
    
    sudo tee "$wrapper_script" > /dev/null << EOF
#!/bin/bash
# Nexus CLI Wrapper Script
# Automatically activates the virtual environment and runs Nexus

NEXUS_DIR="$nexus_dir"
VENV_DIR="\$NEXUS_DIR/venv"

# Check if virtual environment exists
if [[ ! -d "\$VENV_DIR" ]]; then
    echo "Error: Nexus virtual environment not found at \$VENV_DIR"
    echo "Please run the installation script again."
    exit 1
fi

# Change to Nexus directory
cd "\$NEXUS_DIR" || exit 1

# Activate virtual environment
source "\$VENV_DIR/bin/activate"

# Set Python path
export PYTHONPATH="\$NEXUS_DIR:\$PYTHONPATH"

# Run Nexus with all arguments
python -m nexus.cli.main "\$@"

# Deactivate virtual environment
deactivate
EOF
    
    sudo chmod +x "$wrapper_script"
    log_success "CLI wrapper script created at $wrapper_script"
}

# Configure environment variables
configure_environment() {
    log_info "Configuring environment variables..."
    
    local env_vars="
# Nexus AI Penetration Testing Tool Environment Variables
export NEXUS_HOME=\"$HOME/.nexus\"
export NEXUS_CONFIG=\"\$NEXUS_HOME/config/default.yaml\"
export NEXUS_TOOLS_DIR=\"/opt/pentest-tools\"
export NEXUS_WORDLISTS=\"\$NEXUS_HOME/wordlists:/opt/pentest-tools/SecLists:/usr/share/wordlists\"
export OLLAMA_HOST=\"http://localhost:11434\"

# Add pentest tools to PATH
export PATH=\"\$PATH:/opt/pentest-tools\"
export PATH=\"\$PATH:/opt/pentest-tools/PEASS-ng/linPEAS\"
export PATH=\"\$PATH:/opt/pentest-tools/AutoRecon\"
"
    
    # Add to .bashrc if not already present
    if ! grep -q "NEXUS_HOME" ~/.bashrc; then
        echo "$env_vars" >> ~/.bashrc
        log_info "Added environment variables to ~/.bashrc"
    fi
    
    # Add to .zshrc if it exists
    if [[ -f ~/.zshrc ]] && ! grep -q "NEXUS_HOME" ~/.zshrc; then
        echo "$env_vars" >> ~/.zshrc
        log_info "Added environment variables to ~/.zshrc"
    fi
    
    log_success "Environment variables configured"
}

# Run system health check
run_health_check() {
    log_info "Running comprehensive system health check..."
    
    # Test Nexus CLI
    if nexus --version &> /dev/null; then
        log_success "Nexus CLI is working"
    else
        log_error "Nexus CLI test failed"
        return 1
    fi
    
    # Test Ollama connection
    local ollama_status
    if ollama_status=$(nexus health 2>&1) && echo "$ollama_status" | grep -q "Ollama: Connected"; then
        log_success "Ollama connection is working"
    else
        log_warning "Ollama connection test failed - may need manual configuration"
        log_info "Try: sudo systemctl restart ollama"
    fi
    
    # Test core penetration testing tools
    local test_tools=("nmap" "gobuster" "nikto" "sqlmap" "hydra")
    local working_tools=0
    
    for tool in "${test_tools[@]}"; do
        if command -v "$tool" &> /dev/null; then
            log_success "$tool is available"
            working_tools=$((working_tools + 1))
        else
            log_warning "$tool is not available"
        fi
    done
    
    log_info "Core tools available: $working_tools/${#test_tools[@]}"
    
    # Test Python imports
    local python_imports=("requests" "yaml" "click" "asyncio")
    local working_imports=0
    
    for import in "${python_imports[@]}"; do
        if python3 -c "import $import" 2>/dev/null; then
            working_imports=$((working_imports + 1))
        else
            log_warning "Python module $import not available"
        fi
    done
    
    log_info "Python modules available: $working_imports/${#python_imports[@]}"
    
    # Check disk space
    local available_space
    available_space=$(df -h . | awk 'NR==2 {print $4}')
    log_info "Available disk space: $available_space"
    
    # Check memory
    local available_memory
    available_memory=$(free -h | awk 'NR==2 {print $7}')
    log_info "Available memory: $available_memory"
    
    log_success "Health check completed"
}

# Create desktop shortcut (optional)
create_desktop_shortcut() {
    if [[ -d "$HOME/Desktop" ]]; then
        log_info "Creating desktop shortcut..."
        
        cat > "$HOME/Desktop/Nexus.desktop" << EOF
[Desktop Entry]
Version=1.0
Type=Application
Name=Nexus AI Penetration Testing
Comment=AI-Powered Penetration Testing Tool
Exec=gnome-terminal -- nexus --help
Icon=applications-security
Terminal=true
Categories=Security;Network;
EOF
        
        chmod +x "$HOME/Desktop/Nexus.desktop"
        log_info "Desktop shortcut created"
    fi
}

# Main installation function
main() {
    echo "=================================================="
    echo "🔥 Nexus AI-Powered Penetration Testing Tool"
    echo "   Automated Installation Script for Kali Linux"
    echo "=================================================="
    echo
    
    check_root
    check_kali
    
    log_info "Starting Nexus installation..."
    
    update_system
    install_system_deps
    install_pentest_tools
    install_ollama
    download_ai_model
    install_nexus
    create_config_dirs
    create_cli_wrapper
    configure_environment
    create_desktop_shortcut
    
    echo
    echo "=================================================="
    log_success "Nexus installation completed successfully!"
    echo "=================================================="
    echo
    
    log_info "Running final health check..."
    run_health_check
    
    echo
    echo "🚀 Quick Start Commands:"
    echo "   nexus --version                                    # Check version"
    echo "   nexus health                                       # System health check"
    echo "   nexus --auto \"find vulnerabilities in example.com\" # Autonomous mode"
    echo "   nexus evasion profiles                             # List evasion profiles"
    echo "   nexus tools list                                   # List available tools"
    echo
    echo "🤖 Autonomous AI Examples:"
    echo "   nexus run --auto \"get into the SMB server on this network\""
    echo "   nexus run --auto \"find SQL injection in the web app\""
    echo "   nexus run --auto \"escalate privileges on the Linux server\""
    echo
    echo "📚 Documentation:"
    echo "   https://github.com/nexus-security/nexus/docs"
    echo
    echo "⚠️  IMPORTANT:"
    echo "   - Only use on authorized targets with proper permission"
    echo "   - Restart your terminal or run: source ~/.bashrc"
    echo "   - If Ollama fails, try: sudo systemctl restart ollama"
    echo
    log_success "Installation complete! Happy hacking! 🔥"
}

# Run main function
main "$@"