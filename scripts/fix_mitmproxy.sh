#!/bin/bash

# Fix mitmproxy Python compatibility issue
# This script resolves the mitmproxy installation problem on Python < 3.12

set -e

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

echo "=================================================="
echo "🔧 Nexus Mitmproxy Compatibility Fix"
echo "   Resolving Python version compatibility issues"
echo "=================================================="
echo

# Get Python version
python_version=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
log_info "Current Python version: $python_version"

if [[ "$python_version" < "3.12" ]]; then
    log_warning "Python version is less than 3.12, fixing mitmproxy compatibility..."
    
    # Force remove broken mitmproxy package
    log_info "Removing broken mitmproxy package..."
    sudo dpkg --remove --force-remove-reinstreq mitmproxy 2>/dev/null || true
    sudo dpkg --remove --force-depends mitmproxy 2>/dev/null || true
    
    # Clean up package database
    log_info "Cleaning up package database..."
    sudo apt --fix-broken install -y || true
    sudo dpkg --configure -a || true
    
    # Mark mitmproxy as held to prevent automatic installation
    log_info "Preventing automatic mitmproxy installation..."
    echo "mitmproxy hold" | sudo dpkg --set-selections 2>/dev/null || true
    
    # Install compatible mitmproxy via pip
    log_info "Installing compatible mitmproxy via pip..."
    sudo python3 -m pip install --upgrade pip
    sudo python3 -m pip install "mitmproxy<11.0.0" || {
        log_warning "Failed to install mitmproxy 10.x, trying older version..."
        sudo python3 -m pip install "mitmproxy<10.0.0" || log_error "Failed to install compatible mitmproxy"
    }
    
    # Verify installation
    if python3 -c "import mitmproxy" 2>/dev/null; then
        log_success "Compatible mitmproxy installed successfully"
        mitmproxy_version=$(python3 -c "import mitmproxy; print(mitmproxy.__version__)" 2>/dev/null || echo "unknown")
        log_info "Installed mitmproxy version: $mitmproxy_version"
    else
        log_warning "Mitmproxy installation verification failed, but system should continue working"
    fi
    
    # Final cleanup
    log_info "Final system cleanup..."
    sudo apt update || true
    sudo apt --fix-broken install -y || true
    sudo dpkg --configure -a || true
    
    log_success "Mitmproxy compatibility fix completed"
else
    log_info "Python version is 3.12+, no compatibility fix needed"
fi

echo
log_success "Fix completed! You can now continue with the Nexus installation."
echo