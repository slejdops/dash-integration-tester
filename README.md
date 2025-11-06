# DASH LTPA Integration Diagnostics Tool

A comprehensive automated troubleshooting toolkit for diagnosing intermittent LTPA token validation failures between OpenShift-hosted applications (TCE) and JazzSM DASH running on WebSphere Application Server 8.5.5.24.

## Problem Statement

This tool addresses critical, intermittent issues in production JazzSM DASH environments:

- **Unstable user session management** - Sessions drop unexpectedly
- **LTPA token validation failures** - Intermittent authentication errors
- **OpenShift SSO integration issues** - TCE application cannot fetch user roles from DASH
- **Authorization errors** - Valid users denied access sporadically

## Features

### 1. WebSphere Configuration Auditor
- Extracts and validates LTPA configuration (timeout, keys, domain)
- Checks session management settings for race conditions
- Analyzes thread pool configuration
- Validates SSO cookie settings
- **Critical detection**: Identifies session timeout > LTPA timeout mismatches

### 2. Advanced Log Analyzer & Correlation Engine
- Parses SystemOut.log, SystemErr.log, and FFDC files
- Pattern-matches 40+ security error signatures
- Correlates events with reported failure timestamps
- Identifies GC pauses, thread exhaustion, and LTPA errors
- Generates root cause analysis with confidence scoring

### 3. Clock Skew Detector
- Detects time synchronization issues between DASH and OpenShift
- Monitors NTP status on local and remote servers
- Continuous monitoring mode for tracking drift over time
- **Answers**: "Is clock skew causing token validation failures?"

### 4. LTPA Integration Stress Tester (TCE Simulator)
- Simulates OpenShift TCE calling DASH servlet with LTPA token
- Supports steady load, burst, and soak test modes
- Tracks success rate, response times, and failure patterns
- Reproduces intermittent failures on demand

### 5. Automated Correlation & Reporting
- Correlates all diagnostic data into unified HTML reports
- Provides actionable remediation steps
- Exports JSON data for integration with monitoring systems

## Architecture

```
dash-integration-tester/
├── bin/
│   ├── run_diagnostics.sh       # Main orchestrator
│   └── setup.sh                  # Environment setup
├── modules/
│   ├── config_auditor/
│   │   ├── extract_config.py    # wsadmin Jython script
│   │   └── analyze_config.py    # Python analyzer
│   ├── log_analyzer/
│   │   ├── patterns.py          # Security error patterns
│   │   ├── parser.py            # Log parsing engine
│   │   └── correlation.py       # Event correlation
│   └── stress_tester/
│       └── ltpa_simulator.py    # LTPA token tester
├── utils/
│   └── clock_skew_detector.py   # Clock synchronization checker
├── config/
│   └── diagnostics.conf         # Configuration file
└── docs/
    ├── ARCHITECTURE.md           # Detailed architecture
    ├── DIAGNOSTIC_STRATEGY.md    # Quick start troubleshooting
    └── TRACE_CONFIGURATION.md    # WebSphere trace settings
```

## Quick Start

### Prerequisites

- Python 3.6+
- WebSphere Application Server 8.5.5+ (for configuration audit)
- Access to WebSphere log directory
- (Optional) OpenShift CLI (oc) for clock skew detection with pods

### Installation

```bash
# Clone the repository
cd /opt/diagnostics
git clone <repository-url> dash-ltpa-diagnostics
cd dash-ltpa-diagnostics

# Run setup
./bin/setup.sh

# Edit configuration
vi config/diagnostics.conf
```

### Basic Usage

```bash
# Quick scan (5 minutes)
./bin/run_diagnostics.sh --mode quick

# Full analysis (30 minutes)
./bin/run_diagnostics.sh --mode full

# Investigate specific failure
./bin/run_diagnostics.sh --mode investigate \
  --failure-time "2025-11-06 14:32:15" \
  --window 5

# Run stress test only
./bin/run_diagnostics.sh --mode stress
```

## Detailed Usage

### Mode 1: Quick Scan

Fastest diagnostic mode - runs configuration audit and clock skew check only.

```bash
./bin/run_diagnostics.sh --mode quick
```

**Duration**: 5 minutes
**Ideal for**: Initial assessment, pre-change validation

**Outputs**:
- `was_config.json` - WebSphere configuration snapshot
- `config_report.html` - Configuration analysis with critical findings
- `clock_skew.json` - Clock synchronization status

### Mode 2: Full Analysis

Comprehensive analysis without stress testing.

```bash
./bin/run_diagnostics.sh --mode full
```

**Duration**: 30 minutes
**Ideal for**: Post-incident analysis, periodic health checks

**Outputs**:
- All quick scan outputs plus:
- `log_analysis.json` - Parsed security events from logs
- Detailed event categorization and statistics

### Mode 3: Investigate (Targeted)

Correlates log events around a specific failure timestamp.

```bash
./bin/run_diagnostics.sh --mode investigate \
  --failure-time "2025-11-06 14:32:15" \
  --window 10
```

**Parameters**:
- `--failure-time`: Exact timestamp of TCE failure (format: "YYYY-MM-DD HH:MM:SS")
- `--window`: Time window in minutes (default: 5)

**Duration**: 15 minutes
**Ideal for**: Root cause analysis of specific incident

**Outputs**:
- All full analysis outputs plus:
- `correlation_report.txt` - Root cause analysis with confidence scoring
- Probable root cause identification
- Actionable remediation steps

### Mode 4: Stress Test

Simulates TCE integration to reproduce failures.

```bash
./bin/run_diagnostics.sh --mode stress
```

**Configuration** (in `config/diagnostics.conf`):
```bash
DASH_URL="https://dash.example.com:9443/dash/api/roles"
LTPA_TOKEN="AAECAzQ3ODA..."  # Or use username/password
STRESS_MODE="steady"          # steady, burst, soak
STRESS_DURATION="300"         # 5 minutes
STRESS_RATE="20"              # 20 requests/second
```

**Test Modes**:

1. **Steady**: Constant request rate over time
   ```bash
   STRESS_MODE="steady"
   STRESS_DURATION="300"    # 5 minutes
   STRESS_RATE="10"         # 10 req/sec
   ```

2. **Burst**: High concurrency for short duration
   ```bash
   STRESS_MODE="burst"
   # (Edit Python script for requests/threads)
   ```

3. **Soak**: Low rate over extended period (catches timing issues)
   ```bash
   STRESS_MODE="soak"
   STRESS_DURATION="3600"   # 1 hour
   STRESS_RATE="1"          # 1 req/sec
   ```

**Outputs**:
- `stress_test_results.json` - Full test metrics
- Success/failure rate
- Response time percentiles (P50, P95, P99)
- Failure timestamps for log correlation

## Configuration

Edit `config/diagnostics.conf`:

```bash
# WebSphere
WAS_HOME="/opt/IBM/WebSphere/AppServer"
WAS_LOG_DIR="${WAS_HOME}/profiles/AppSrv01/logs/server1"

# DASH Endpoint
DASH_URL="https://dash.example.com:9443/dash/api/roles"

# LTPA Token (get from browser cookie after login)
LTPA_TOKEN="AAECAzQ3ODA..."

# Or use credentials (tool will acquire token)
DASH_USERNAME="admin"
DASH_PASSWORD="password"

# OpenShift (for clock skew detection)
OPENSHIFT_NAMESPACE="tce-prod"
OPENSHIFT_POD="tce-app-5d7f8c9b-xk2lp"
```

### Getting an LTPA Token

**Method 1: Browser DevTools**
1. Log into DASH via browser
2. Open DevTools (F12) → Application → Cookies
3. Find `LTPAToken2` cookie
4. Copy the value

**Method 2: Curl**
```bash
curl -v -k -c cookies.txt -X POST \
  "https://dash.example.com:9443/ibm/console/login.do" \
  -d "username=admin&password=password&action=Log in"

# Extract LTPAToken2 from cookies.txt
grep LTPAToken2 cookies.txt
```

## Module-Specific Usage

### Configuration Auditor (Standalone)

```bash
# Extract configuration
$WAS_HOME/bin/wsadmin.sh -lang jython \
  -f modules/config_auditor/extract_config.py \
  -output /tmp/was_config.json

# Analyze configuration
python3 modules/config_auditor/analyze_config.py \
  --config /tmp/was_config.json \
  --report /tmp/config_report.html

# Open report in browser
firefox /tmp/config_report.html
```

### Log Analyzer (Standalone)

```bash
# Parse logs
python3 modules/log_analyzer/parser.py \
  --log-dir $WAS_HOME/profiles/AppSrv01/logs/server1 \
  --output /tmp/log_analysis.json \
  --verbose

# Filter by time window
python3 modules/log_analyzer/parser.py \
  --log-dir $WAS_HOME/profiles/AppSrv01/logs/server1 \
  --time-filter "2025-11-06 14:32:15" \
  --output /tmp/filtered_logs.json

# Filter by category
python3 modules/log_analyzer/parser.py \
  --log-dir $WAS_HOME/profiles/AppSrv01/logs/server1 \
  --category-filter "LTPA_EXPIRED,LTPA_SIGNATURE_INVALID" \
  --output /tmp/ltpa_errors.json
```

### Correlation Engine (Standalone)

```bash
# Correlate events with failure
python3 modules/log_analyzer/correlation.py \
  --log-analysis /tmp/log_analysis.json \
  --failure-time "2025-11-06 14:32:15" \
  --window 5 \
  --output /tmp/correlation_report.txt

# View report
cat /tmp/correlation_report.txt
```

### Clock Skew Detector (Standalone)

```bash
# Check local NTP status
python3 utils/clock_skew_detector.py --ntp-status

# Check skew with OpenShift pod
python3 utils/clock_skew_detector.py \
  --openshift \
  --namespace tce-prod \
  --pod tce-app-5d7f8c9b-xk2lp

# Check skew with remote host via SSH
python3 utils/clock_skew_detector.py \
  --remote-host openshift-node.example.com \
  --remote-user admin

# Continuous monitoring (1 hour, sample every 60 seconds)
python3 utils/clock_skew_detector.py \
  --openshift \
  --namespace tce-prod \
  --pod tce-app-5d7f8c9b-xk2lp \
  --continuous \
  --duration 60 \
  --interval 60 \
  --output /tmp/clock_monitoring.json
```

### Stress Tester (Standalone)

```bash
# Steady load test
python3 modules/stress_tester/ltpa_simulator.py \
  --url "https://dash.example.com:9443/dash/api/roles" \
  --token "AAECAzQ3ODA..." \
  --mode steady \
  --duration 300 \
  --rate 10 \
  --output /tmp/stress_results.json

# Burst test
python3 modules/stress_tester/ltpa_simulator.py \
  --url "https://dash.example.com:9443/dash/api/roles" \
  --token "AAECAzQ3ODA..." \
  --mode burst \
  --requests 1000 \
  --threads 50 \
  --output /tmp/burst_results.json

# With username/password (auto-acquire token)
python3 modules/stress_tester/ltpa_simulator.py \
  --url "https://dash.example.com:9443/dash/api/roles" \
  --username admin \
  --password password \
  --mode steady \
  --duration 60 \
  --rate 5
```

## Interpreting Results

### Critical Findings

The tool identifies these critical issues automatically:

1. **Session Timeout > LTPA Timeout**
   - **Symptom**: Users have valid sessions but expired LTPA tokens
   - **Fix**: Set session timeout = LTPA timeout - 10 minutes
   - **Location**: `config_report.html` → "Session Timeout Exceeds LTPA Timeout"

2. **Clock Skew > 30 Seconds**
   - **Symptom**: Tokens appear expired immediately
   - **Fix**: Synchronize clocks via NTP
   - **Location**: `clock_skew.json` → severity: "CRITICAL"

3. **SSO Domain Not Configured**
   - **Symptom**: LTPA cookie not sent to OpenShift
   - **Fix**: Set SSO domain to `.example.com` (note leading dot)
   - **Location**: `config_report.html` → "SSO Domain Not Configured"

4. **LTPA Key Regeneration During Production**
   - **Symptom**: Sudden widespread authentication failures
   - **Fix**: Schedule key regeneration during maintenance windows
   - **Location**: `correlation_report.txt` → "LTPA_KEY_GENERATED" events

5. **Thread Pool Exhaustion**
   - **Symptom**: Servlet timeouts during role fetching
   - **Fix**: Increase Web Container max threads
   - **Location**: `config_report.html` → "Thread Pool Near Exhaustion"

### Stress Test Interpretation

- **Failure Rate < 0.1%**: Acceptable (transient network issues)
- **Failure Rate 0.1-1%**: Investigate (intermittent issue present)
- **Failure Rate > 1%**: Critical (systemic issue)

**Response Time Guidelines**:
- **P50 < 100ms**: Excellent
- **P95 < 500ms**: Acceptable
- **P99 > 1000ms**: Investigate slow queries/backend

## Troubleshooting

### "wsadmin not found"

```bash
# Set WAS_HOME environment variable
export WAS_HOME=/opt/IBM/WebSphere/AppServer

# Or edit config/diagnostics.conf
```

### "Permission denied" on log files

```bash
# Run as wasadmin user
sudo -u wasadmin ./bin/run_diagnostics.sh --mode quick

# Or add current user to wasadmin group
```

### "oc command not found"

Clock skew detection with OpenShift requires OpenShift CLI:

```bash
# Install oc CLI
# See: https://docs.openshift.com/container-platform/latest/cli_reference/openshift_cli/getting-started-cli.html

# Or use SSH-based remote host check instead
```

### Stress test SSL errors

```bash
# For testing with self-signed certificates ONLY:
STRESS_NO_VERIFY_SSL="true" ./bin/run_diagnostics.sh --mode stress

# Better: Import DASH certificate into system trust store
```

## Best Practices

1. **Baseline First**: Run `--mode quick` in healthy state to establish baseline
2. **Capture During Failure**: Run `--mode investigate` immediately when TCE reports failure
3. **Continuous Monitoring**: Schedule hourly `--mode quick` and retain reports
4. **Correlate with TCE Logs**: Compare failure timestamps between DASH and TCE
5. **Test After Changes**: Run `--mode stress` after configuration changes

## Advanced Topics

### Enabling WebSphere Security Traces

See `docs/TRACE_CONFIGURATION.md` for detailed trace strings.

**Quick Reference**:
```bash
# Runtime trace (no restart)
$WAS_HOME/bin/wsadmin.sh -lang jython
wsadmin> server = AdminControl.completeObjectName('type=Server,name=server1,*')
wsadmin> traceSpec = 'com.ibm.ws.security.ltpa.*=all:com.ibm.ws.security.token.*=all'
wsadmin> AdminControl.setAttribute(server, 'traceSpecification', traceSpec)

# Disable after capturing
wsadmin> AdminControl.setAttribute(server, 'traceSpecification', '*=info')
```

### Custom Pattern Development

Add custom error patterns to `modules/log_analyzer/patterns.py`:

```python
CUSTOM_PATTERNS = [
    {
        'pattern': r'CUSTOM_ERROR_\d{4}',
        'severity': 'ERROR',
        'category': 'CUSTOM_ERROR',
        'description': 'Custom error pattern',
        'probable_cause': 'Application-specific issue',
        'remediation': 'Check application logs'
    }
]
```

## Documentation

- **[ARCHITECTURE.md](docs/ARCHITECTURE.md)** - Detailed design and data flow
- **[DIAGNOSTIC_STRATEGY.md](docs/DIAGNOSTIC_STRATEGY.md)** - Manual troubleshooting steps
- **[TRACE_CONFIGURATION.md](docs/TRACE_CONFIGURATION.md)** - WebSphere trace specifications

## Specific Questions Answered

### 1. What DASH-side traces should we enable for OpenShift requests?

**Answer**: See `docs/TRACE_CONFIGURATION.md` - Recommended trace string:

```
com.ibm.ws.security.ltpa.*=all:com.ibm.ws.security.token.*=all:com.ibm.ws.security.web.WebAuthenticator=all:com.ibm.issw.dash.*=finest
```

This captures:
- LTPA token validation (including expiration timestamps)
- Cookie extraction from requests
- Authentication flow
- DASH servlet processing

**Overhead**: ~2-5 MB/hour at medium traffic
**Duration**: Enable for 30-60 minutes during TCE testing

### 2. Could clock skew be causing intermittent failures?

**Answer**: **YES** - The clock skew detector specifically tests for this:

```bash
python3 utils/clock_skew_detector.py \
  --openshift \
  --namespace tce-prod \
  --pod tce-app-xxxxx
```

**How LTPA validation uses time**:
- Tokens contain `exp` (expiration) timestamp
- DASH compares token `exp` vs current server time
- If clock skew > 30 seconds, tokens appear expired

**Example**:
```
OpenShift time: 14:32:45 UTC (30 seconds ahead)
DASH time:      14:32:15 UTC
Token issued:   14:32:45 UTC (appears "in the future" to DASH)
Result:         DASH rejects token as not yet valid (nbf check fails)
```

The tool detects this by:
1. Extracting timestamps from trace logs
2. Comparing OpenShift pod time vs DASH server time
3. Flagging skew > 5 seconds as WARNING, > 30 seconds as CRITICAL

## Support

For issues or questions:
1. Check `docs/DIAGNOSTIC_STRATEGY.md` for immediate troubleshooting
2. Review generated reports in `output/` directory
3. Collect diagnostic bundle for support escalation

## License

Internal IBM tool - Confidential

## Version

1.0.0 - Initial release
