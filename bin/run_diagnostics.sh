#!/bin/bash
################################################################################
# DASH LTPA Integration Diagnostics Tool - Main Orchestrator
#
# This script orchestrates all diagnostic modules to troubleshoot LTPA/SSO
# integration issues between OpenShift (TCE) and DASH/WebSphere.
#
# Usage:
#   ./run_diagnostics.sh --mode <quick|full|stress|investigate>
#
# Author: Claude Code
# Version: 1.0
################################################################################

set -e  # Exit on error

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Output directory
OUTPUT_DIR="${PROJECT_ROOT}/output/$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUTPUT_DIR"

# Log file
LOG_FILE="${OUTPUT_DIR}/diagnostics.log"

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

################################################################################
# Functions
################################################################################

log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1" | tee -a "$LOG_FILE"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1" | tee -a "$LOG_FILE"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a "$LOG_FILE"
}

log_warn() {
    echo -e "${YELLOW}[WARNING]${NC} $1" | tee -a "$LOG_FILE"
}

print_header() {
    echo ""
    echo "========================================================================"
    echo "$1"
    echo "========================================================================"
    echo ""
}

check_prerequisites() {
    log "Checking prerequisites..."

    # Check Python 3
    if ! command -v python3 &> /dev/null; then
        log_error "Python 3 is not installed"
        exit 1
    fi

    # Check wsadmin (if running config audit)
    if [ "$MODE" != "stress" ] && [ -z "$WAS_HOME" ]; then
        log_warn "WAS_HOME not set - WebSphere configuration audit will be skipped"
    fi

    log_success "Prerequisites check passed"
}

load_config() {
    # Load configuration from file if exists
    CONFIG_FILE="${PROJECT_ROOT}/config/diagnostics.conf"

    if [ -f "$CONFIG_FILE" ]; then
        log "Loading configuration from $CONFIG_FILE"
        source "$CONFIG_FILE"
    else
        log_warn "Configuration file not found: $CONFIG_FILE"
        log_warn "Using default values"
    fi

    # Set defaults if not configured
    WAS_LOG_DIR="${WAS_LOG_DIR:-/opt/IBM/WebSphere/AppServer/profiles/AppSrv01/logs/server1}"
    DASH_URL="${DASH_URL:-https://localhost:9443/dash/api/roles}"
    LTPA_TOKEN="${LTPA_TOKEN:-}"
}

run_config_audit() {
    print_header "MODULE 1: WebSphere Configuration Audit"

    if [ -z "$WAS_HOME" ]; then
        log_warn "WAS_HOME not set - skipping configuration audit"
        return
    fi

    log "Extracting WebSphere configuration..."

    local config_json="${OUTPUT_DIR}/was_config.json"
    local config_report="${OUTPUT_DIR}/config_report.html"

    # Run wsadmin extraction script
    "$WAS_HOME/bin/wsadmin.sh" -lang jython \
        -f "${PROJECT_ROOT}/modules/config_auditor/extract_config.py" \
        -output "$config_json" 2>&1 | tee -a "$LOG_FILE"

    if [ -f "$config_json" ]; then
        log_success "Configuration extracted to $config_json"

        # Analyze configuration
        log "Analyzing configuration..."
        python3 "${PROJECT_ROOT}/modules/config_auditor/analyze_config.py" \
            --config "$config_json" \
            --report "$config_report" 2>&1 | tee -a "$LOG_FILE"

        if [ -f "$config_report" ]; then
            log_success "Configuration report generated: $config_report"
        fi
    else
        log_error "Configuration extraction failed"
    fi
}

run_log_analysis() {
    print_header "MODULE 2: Log Analysis"

    if [ ! -d "$WAS_LOG_DIR" ]; then
        log_error "WebSphere log directory not found: $WAS_LOG_DIR"
        return
    fi

    log "Analyzing WebSphere logs in $WAS_LOG_DIR..."

    local log_analysis_json="${OUTPUT_DIR}/log_analysis.json"

    python3 "${PROJECT_ROOT}/modules/log_analyzer/parser.py" \
        --log-dir "$WAS_LOG_DIR" \
        --output "$log_analysis_json" \
        --verbose 2>&1 | tee -a "$LOG_FILE"

    if [ -f "$log_analysis_json" ]; then
        log_success "Log analysis completed: $log_analysis_json"
    else
        log_error "Log analysis failed"
    fi
}

run_correlation() {
    print_header "MODULE 2b: Event Correlation"

    if [ -z "$FAILURE_TIME" ]; then
        log_warn "No failure time specified - skipping correlation"
        return
    fi

    log "Correlating events around failure time: $FAILURE_TIME"

    local log_analysis_json="${OUTPUT_DIR}/log_analysis.json"
    local correlation_report="${OUTPUT_DIR}/correlation_report.txt"

    if [ ! -f "$log_analysis_json" ]; then
        log_error "Log analysis JSON not found - run log analysis first"
        return
    fi

    python3 "${PROJECT_ROOT}/modules/log_analyzer/correlation.py" \
        --log-analysis "$log_analysis_json" \
        --failure-time "$FAILURE_TIME" \
        --window "${CORRELATION_WINDOW:-5}" \
        --output "$correlation_report" 2>&1 | tee -a "$LOG_FILE"

    if [ -f "$correlation_report" ]; then
        log_success "Correlation report generated: $correlation_report"
        echo ""
        cat "$correlation_report"
    fi
}

run_clock_skew_check() {
    print_header "MODULE 3: Clock Skew Detection"

    log "Checking clock skew..."

    local clock_output="${OUTPUT_DIR}/clock_skew.json"

    # Check NTP status on local server
    python3 "${PROJECT_ROOT}/utils/clock_skew_detector.py" \
        --ntp-status 2>&1 | tee -a "$LOG_FILE"

    # If OpenShift details provided, check skew with pod
    if [ -n "$OPENSHIFT_NAMESPACE" ] && [ -n "$OPENSHIFT_POD" ]; then
        log "Checking clock skew with OpenShift pod..."
        python3 "${PROJECT_ROOT}/utils/clock_skew_detector.py" \
            --openshift \
            --namespace "$OPENSHIFT_NAMESPACE" \
            --pod "$OPENSHIFT_POD" \
            --output "$clock_output" 2>&1 | tee -a "$LOG_FILE"
    elif [ -n "$REMOTE_HOST" ]; then
        log "Checking clock skew with remote host..."
        python3 "${PROJECT_ROOT}/utils/clock_skew_detector.py" \
            --remote-host "$REMOTE_HOST" \
            --remote-user "$REMOTE_USER" \
            --output "$clock_output" 2>&1 | tee -a "$LOG_FILE"
    else
        log_warn "No remote host or OpenShift pod specified - skipping remote clock check"
    fi
}

run_stress_test() {
    print_header "MODULE 4: LTPA Integration Stress Test"

    if [ -z "$DASH_URL" ]; then
        log_error "DASH_URL not configured"
        return
    fi

    log "Running stress test against $DASH_URL..."

    local stress_output="${OUTPUT_DIR}/stress_test_results.json"

    local token_arg=""
    if [ -n "$LTPA_TOKEN" ]; then
        token_arg="--token $LTPA_TOKEN"
    elif [ -n "$DASH_USERNAME" ] && [ -n "$DASH_PASSWORD" ]; then
        token_arg="--username $DASH_USERNAME --password $DASH_PASSWORD"
    else
        log_error "No LTPA token or credentials provided for stress test"
        return
    fi

    python3 "${PROJECT_ROOT}/modules/stress_tester/ltpa_simulator.py" \
        --url "$DASH_URL" \
        $token_arg \
        --mode "${STRESS_MODE:-steady}" \
        --duration "${STRESS_DURATION:-60}" \
        --rate "${STRESS_RATE:-10}" \
        --output "$stress_output" \
        ${STRESS_NO_VERIFY_SSL:+--no-verify-ssl} \
        2>&1 | tee -a "$LOG_FILE"

    if [ -f "$stress_output" ]; then
        log_success "Stress test results: $stress_output"
    fi
}

generate_final_report() {
    print_header "Generating Final Report"

    local report_file="${OUTPUT_DIR}/FINAL_REPORT.txt"

    {
        echo "========================================================================"
        echo "DASH LTPA INTEGRATION DIAGNOSTICS - FINAL REPORT"
        echo "========================================================================"
        echo "Generated: $(date)"
        echo "Mode: $MODE"
        echo ""
        echo "========================================================================"
        echo "OUTPUT FILES"
        echo "========================================================================"
        echo ""

        find "$OUTPUT_DIR" -type f | while read -r file; do
            echo "  - $(basename "$file")"
        done

        echo ""
        echo "========================================================================"
        echo "SUMMARY"
        echo "========================================================================"
        echo ""

        # Configuration audit summary
        if [ -f "${OUTPUT_DIR}/was_config.json" ]; then
            echo "Configuration Audit:"
            python3 -c "
import json, sys
with open('${OUTPUT_DIR}/was_config.json', 'r') as f:
    data = json.load(f)
    print(f\"  LTPA Timeout: {data.get('ltpa_config', {}).get('timeout_minutes', 'N/A')} minutes\")
    print(f\"  SSO Enabled: {data.get('sso_config', {}).get('enabled', False)}\")
    print(f\"  SSO Domain: {data.get('sso_config', {}).get('domain', 'N/A')}\")
    print(f\"  Critical Issues: {len(data.get('issues', []))}\")
    print(f\"  Warnings: {len(data.get('warnings', []))}\")
" 2>/dev/null || echo "  (Analysis unavailable)"
            echo ""
        fi

        # Log analysis summary
        if [ -f "${OUTPUT_DIR}/log_analysis.json" ]; then
            echo "Log Analysis:"
            python3 -c "
import json
with open('${OUTPUT_DIR}/log_analysis.json', 'r') as f:
    data = json.load(f)
    stats = data.get('statistics', {})
    print(f\"  Total Security Events: {stats.get('total_entries', 0)}\")
    print(f\"  Errors: {stats.get('by_severity', {}).get('ERROR', 0)}\")
    print(f\"  Warnings: {stats.get('by_severity', {}).get('WARNING', 0)}\")
    print(f\"  Long GC Events: {stats.get('long_gc_events', 0)}\")
" 2>/dev/null || echo "  (Analysis unavailable)"
            echo ""
        fi

        # Stress test summary
        if [ -f "${OUTPUT_DIR}/stress_test_results.json" ]; then
            echo "Stress Test:"
            python3 -c "
import json
with open('${OUTPUT_DIR}/stress_test_results.json', 'r') as f:
    data = json.load(f)
    stats = data.get('statistics', {})
    print(f\"  Total Requests: {stats.get('total_requests', 0)}\")
    print(f\"  Success Rate: {100 - stats.get('failure_rate', 0):.2f}%\")
    print(f\"  Avg Response Time: {stats.get('avg_response_time_ms', 0):.2f}ms\")
    print(f\"  P95 Response Time: {stats.get('p95_response_time_ms', 0):.2f}ms\")
" 2>/dev/null || echo "  (Results unavailable)"
            echo ""
        fi

        echo "========================================================================"
        echo "RECOMMENDATIONS"
        echo "========================================================================"
        echo ""
        echo "1. Review configuration report (HTML) for critical issues"
        echo "2. Check correlation report if investigating specific failure"
        echo "3. Verify clock synchronization between DASH and OpenShift"
        echo "4. Review stress test results for failure patterns"
        echo ""
        echo "For detailed guidance, see:"
        echo "  - ${PROJECT_ROOT}/docs/DIAGNOSTIC_STRATEGY.md"
        echo "  - ${PROJECT_ROOT}/docs/TRACE_CONFIGURATION.md"
        echo ""
        echo "========================================================================"

    } > "$report_file"

    log_success "Final report generated: $report_file"
    echo ""
    cat "$report_file"
}

################################################################################
# Main Execution
################################################################################

# Parse arguments
MODE="quick"
FAILURE_TIME=""
CORRELATION_WINDOW=5

while [[ $# -gt 0 ]]; do
    case $1 in
        --mode)
            MODE="$2"
            shift 2
            ;;
        --failure-time)
            FAILURE_TIME="$2"
            shift 2
            ;;
        --window)
            CORRELATION_WINDOW="$2"
            shift 2
            ;;
        --help)
            echo "Usage: $0 --mode <quick|full|stress|investigate> [OPTIONS]"
            echo ""
            echo "Modes:"
            echo "  quick       - Quick configuration and log scan (5 min)"
            echo "  full        - Full analysis without stress test (30 min)"
            echo "  stress      - Run stress test only"
            echo "  investigate - Targeted investigation around failure time"
            echo ""
            echo "Options:"
            echo "  --failure-time \"YYYY-MM-DD HH:MM:SS\"  - Failure timestamp for correlation"
            echo "  --window MINUTES                       - Correlation window (default: 5)"
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Banner
clear
echo "========================================================================"
echo "    DASH LTPA INTEGRATION DIAGNOSTICS TOOL"
echo "    Mode: $MODE"
echo "    Output: $OUTPUT_DIR"
echo "========================================================================"
echo ""

# Load configuration
load_config

# Check prerequisites
check_prerequisites

# Execute based on mode
case $MODE in
    quick)
        run_config_audit
        run_clock_skew_check
        ;;
    full)
        run_config_audit
        run_log_analysis
        run_clock_skew_check
        ;;
    stress)
        run_stress_test
        ;;
    investigate)
        if [ -z "$FAILURE_TIME" ]; then
            log_error "investigate mode requires --failure-time parameter"
            exit 1
        fi
        run_log_analysis
        run_correlation
        run_clock_skew_check
        ;;
    *)
        log_error "Invalid mode: $MODE"
        exit 1
        ;;
esac

# Generate final report
generate_final_report

log_success "Diagnostics complete! Results in: $OUTPUT_DIR"
