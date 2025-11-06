#!/bin/bash
################################################################################
# DASH LTPA Integration Diagnostics Tool - Setup Script
#
# This script sets up the diagnostic tool environment
#
# Usage:
#   ./setup.sh
#
################################################################################

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo "========================================================================"
echo "DASH LTPA Integration Diagnostics Tool - Setup"
echo "========================================================================"
echo ""

# Check Python 3
echo -n "Checking Python 3... "
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
    echo -e "${GREEN}OK${NC} (version $PYTHON_VERSION)"
else
    echo -e "${RED}FAILED${NC}"
    echo "Python 3 is required. Please install Python 3.6 or later."
    exit 1
fi

# Check pip
echo -n "Checking pip... "
if command -v pip3 &> /dev/null; then
    echo -e "${GREEN}OK${NC}"
else
    echo -e "${YELLOW}WARNING${NC} - pip3 not found, attempting to install packages anyway"
fi

# Install Python dependencies
echo ""
echo "Installing Python dependencies..."
pip3 install --user requests urllib3 2>&1 | grep -v "Requirement already satisfied" || true
echo -e "${GREEN}Python dependencies installed${NC}"

# Check wsadmin (optional)
echo ""
echo -n "Checking wsadmin... "
if [ -n "$WAS_HOME" ] && [ -f "$WAS_HOME/bin/wsadmin.sh" ]; then
    echo -e "${GREEN}OK${NC} (found at $WAS_HOME)"
else
    echo -e "${YELLOW}WARNING${NC}"
    echo "WAS_HOME not set or wsadmin not found."
    echo "Configuration audit module will not be available."
    echo "Set WAS_HOME environment variable if WebSphere is installed."
fi

# Check oc CLI (optional)
echo ""
echo -n "Checking OpenShift CLI (oc)... "
if command -v oc &> /dev/null; then
    OC_VERSION=$(oc version --client 2>&1 | head -1)
    echo -e "${GREEN}OK${NC} ($OC_VERSION)"
else
    echo -e "${YELLOW}WARNING${NC}"
    echo "OpenShift CLI (oc) not found."
    echo "Clock skew detection with OpenShift pods will not be available."
fi

# Create configuration file if it doesn't exist
echo ""
echo "Setting up configuration..."
CONFIG_FILE="${PROJECT_ROOT}/config/diagnostics.conf"

if [ ! -f "$CONFIG_FILE" ]; then
    cat > "$CONFIG_FILE" <<EOF
# DASH LTPA Integration Diagnostics - Configuration
# Edit this file to configure your environment

# WebSphere Configuration
WAS_HOME="${WAS_HOME:-/opt/IBM/WebSphere/AppServer}"
WAS_LOG_DIR="\${WAS_HOME}/profiles/AppSrv01/logs/server1"

# DASH Configuration
DASH_URL="https://localhost:9443/dash/api/roles"
DASH_USERNAME=""
DASH_PASSWORD=""
LTPA_TOKEN=""

# OpenShift Configuration (for clock skew detection)
OPENSHIFT_NAMESPACE=""
OPENSHIFT_POD=""

# Remote Host Configuration (alternative to OpenShift)
REMOTE_HOST=""
REMOTE_USER=""

# Stress Test Configuration
STRESS_MODE="steady"           # steady, burst, soak
STRESS_DURATION="60"           # seconds
STRESS_RATE="10"               # requests per second
STRESS_NO_VERIFY_SSL=""        # Set to "true" to disable SSL verification (testing only!)

# Correlation Configuration
CORRELATION_WINDOW="5"         # minutes
EOF

    echo -e "${GREEN}Configuration file created:${NC} $CONFIG_FILE"
    echo "Please edit this file to configure your environment."
else
    echo -e "${GREEN}Configuration file already exists:${NC} $CONFIG_FILE"
fi

# Create output directory
OUTPUT_BASE="${PROJECT_ROOT}/output"
mkdir -p "$OUTPUT_BASE"
echo -e "${GREEN}Output directory created:${NC} $OUTPUT_BASE"

# Make scripts executable
echo ""
echo "Setting script permissions..."
chmod +x "${PROJECT_ROOT}/bin/run_diagnostics.sh"
chmod +x "${PROJECT_ROOT}/modules/config_auditor/extract_config.py"
chmod +x "${PROJECT_ROOT}/modules/config_auditor/analyze_config.py"
chmod +x "${PROJECT_ROOT}/modules/log_analyzer/parser.py"
chmod +x "${PROJECT_ROOT}/modules/log_analyzer/patterns.py"
chmod +x "${PROJECT_ROOT}/modules/log_analyzer/correlation.py"
chmod +x "${PROJECT_ROOT}/modules/stress_tester/ltpa_simulator.py"
chmod +x "${PROJECT_ROOT}/utils/clock_skew_detector.py"
echo -e "${GREEN}Script permissions updated${NC}"

# Summary
echo ""
echo "========================================================================"
echo "Setup Complete!"
echo "========================================================================"
echo ""
echo "Next steps:"
echo "  1. Edit configuration: ${CONFIG_FILE}"
echo "  2. Run diagnostics: ${PROJECT_ROOT}/bin/run_diagnostics.sh --mode quick"
echo ""
echo "For detailed usage instructions, see: ${PROJECT_ROOT}/README.md"
echo ""
