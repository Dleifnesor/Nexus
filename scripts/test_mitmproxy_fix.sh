#!/bin/bash

# Test script to verify mitmproxy compatibility fix
# This script tests the mitmproxy installation and Python compatibility

set +e

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
echo "🧪 Nexus Mitmproxy Compatibility Test"
echo "   Testing Python version compatibility fixes"
echo "=================================================="
echo

# Test 1: Check Python version
log_info "Test 1: Checking Python version..."
python_version=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>/dev/null || echo "unknown")
log_info "Python version: $python_version"

if [[ "$python_version" == "unknown" ]]; then
    log_error "Failed to detect Python version"
    exit 1
elif [[ "$python_version" < "3.12" ]]; then
    log_info "Python version is less than 3.12 - compatibility fixes should be applied"
else
    log_info "Python version is 3.12+ - no compatibility fixes needed"
fi

# Test 2: Check if mitmproxy package is broken
log_info "Test 2: Checking for broken mitmproxy package..."
if dpkg -l 2>/dev/null | grep -q "^iU.*mitmproxy" || dpkg -l 2>/dev/null | grep -q "^iF.*mitmproxy"; then
    log_warning "Broken mitmproxy package detected - fix needed"
    broken_package=true
else
    log_success "No broken mitmproxy package detected"
    broken_package=false
fi

# Test 3: Check if dpkg configuration is broken
log_info "Test 3: Checking dpkg configuration..."
if ! dpkg --configure -a 2>/dev/null; then
    log_warning "dpkg configuration issues detected"
    dpkg_broken=true
else
    log_success "dpkg configuration is clean"
    dpkg_broken=false
fi

# Test 4: Test mitmproxy import
log_info "Test 4: Testing mitmproxy import..."
import_result=$(python3 -c "import mitmproxy; print('Import successful')" 2>&1)
if echo "$import_result" | grep -q "SyntaxError"; then
    log_error "Mitmproxy import failed with SyntaxError - compatibility issue detected"
    import_failed=true
elif echo "$import_result" | grep -q "Import successful"; then
    log_success "Mitmproxy import successful"
    import_failed=false
    mitmproxy_version=$(python3 -c "import mitmproxy; print(mitmproxy.__version__)" 2>/dev/null || echo "unknown")
    log_info "Mitmproxy version: $mitmproxy_version"
elif echo "$import_result" | grep -q "ModuleNotFoundError"; then
    log_info "Mitmproxy not installed - this is expected if using system packages"
    import_failed=false
else
    log_warning "Mitmproxy import test inconclusive: $import_result"
    import_failed=false
fi

# Test 5: Check if fix is needed
log_info "Test 5: Determining if fix is needed..."
fix_needed=false

if [[ "$broken_package" == "true" ]] || [[ "$dpkg_broken" == "true" ]] || [[ "$import_failed" == "true" ]]; then
    fix_needed=true
fi

if [[ "$python_version" < "3.12" ]] && [[ "$fix_needed" == "true" ]]; then
    log_warning "Mitmproxy compatibility fix is needed"
    echo
    echo "🔧 To fix this issue, run:"
    echo "   bash scripts/install.sh"
    echo
    echo "The enhanced install script will automatically:"
    echo "   - Remove broken mitmproxy packages"
    echo "   - Install compatible mitmproxy version via pip"
    echo "   - Fix any remaining package issues"
    echo
elif [[ "$fix_needed" == "false" ]]; then
    log_success "No mitmproxy compatibility issues detected"
    echo
    echo "✅ Your system appears to be working correctly!"
    echo "   You can proceed with the Nexus installation."
    echo
else
    log_info "System status is unclear, but installation should handle any issues"
    echo
    echo "ℹ️  Run the installation script to ensure everything is properly configured:"
    echo "   bash scripts/install.sh"
    echo
fi

# Summary
echo "=================================================="
echo "📊 Test Summary:"
echo "   Python Version: $python_version"
echo "   Broken Package: $broken_package"
echo "   DPKG Issues: $dpkg_broken"
echo "   Import Failed: $import_failed"
echo "   Fix Needed: $fix_needed"
echo "=================================================="

if [[ "$fix_needed" == "true" ]]; then
    exit 1
else
    exit 0
fi