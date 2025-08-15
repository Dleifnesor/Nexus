#!/bin/bash

# Nexus Installation Fix Script
# This script fixes common installation issues with Nexus

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

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
echo "🔧 Nexus Installation Fix Script"
echo "=================================================="
echo

# Get current directory
NEXUS_DIR="$(pwd)"
log_info "Current Nexus directory: $NEXUS_DIR"

# Check if we're in the right directory
if [[ ! -f "nexus/__init__.py" ]] && [[ ! -f "setup.py" ]]; then
    log_error "This doesn't appear to be the Nexus directory"
    log_info "Please run this script from the Nexus root directory"
    exit 1
fi

# Create virtual environment if it doesn't exist
if [[ ! -d "venv" ]]; then
    log_info "Creating Python virtual environment..."
    if python3 -m venv venv; then
        log_success "Virtual environment created successfully"
    else
        log_error "Failed to create virtual environment"
        exit 1
    fi
else
    log_info "Virtual environment already exists"
fi

# Activate virtual environment
log_info "Activating virtual environment..."
source venv/bin/activate

# Upgrade pip
log_info "Upgrading pip..."
pip install --upgrade pip wheel setuptools

# Install requirements
if [[ -f "requirements.txt" ]]; then
    log_info "Installing requirements..."
    pip install -r requirements.txt
fi

# Install Nexus in development mode
log_info "Installing Nexus in development mode..."
pip install -e .

# Verify installation
if python -c "import nexus" 2>/dev/null; then
    log_success "Nexus installed successfully"
else
    log_warning "Nexus installation verification failed"
fi

# Update CLI wrapper
log_info "Updating CLI wrapper..."
NEXUS_ABSOLUTE_DIR="$(realpath "$NEXUS_DIR")"

sudo tee /usr/local/bin/nexus > /dev/null << EOF
#!/bin/bash
# Nexus CLI Wrapper Script
# Automatically activates the virtual environment and runs Nexus

NEXUS_DIR="$NEXUS_ABSOLUTE_DIR"
VENV_DIR="\$NEXUS_DIR/venv"

# Check if virtual environment exists
if [[ ! -d "\$VENV_DIR" ]]; then
    echo "Error: Nexus virtual environment not found at \$VENV_DIR"
    echo "Please run the fix_nexus_installation.sh script."
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

sudo chmod +x /usr/local/bin/nexus
log_success "CLI wrapper updated"

# Test installation
log_info "Testing Nexus installation..."
deactivate

if nexus --version 2>/dev/null; then
    log_success "Nexus is working correctly!"
else
    log_warning "Nexus test failed, but installation may still work"
fi

echo
echo "=================================================="
log_success "🎉 Nexus installation fix completed!"
echo "=================================================="
echo
echo "Try running: nexus --version"
echo