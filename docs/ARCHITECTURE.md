# DASH LTPA Integration Diagnostics Tool - Architecture

## Overview

This automated troubleshooting tool is designed to diagnose and isolate intermittent LTPA token validation failures between OpenShift-hosted applications (TCE) and JazzSM DASH running on WebSphere Application Server 8.5.5.24.

## Problem Statement

**Primary Symptoms:**
- Intermittent user session drops in DASH
- Unstable LTPAToken cookie handling
- OpenShift TCE application experiencing sporadic role-fetching failures
- Authorization errors in TCE when calling DASH servlet for user role validation

**Root Cause Candidates:**
1. LTPA token timeout misalignment between DASH and client expectations
2. Clock skew between OpenShift containers and WebSphere hosts
3. SSL/TLS handshake failures (certificate expiry, trust store issues)
4. WebSphere thread pool exhaustion during high load
5. LTPA key regeneration events coinciding with token validation
6. Session timeout race conditions (HTTP session vs LTPA timeout)
7. Cookie domain/path scoping preventing token propagation
8. GC pauses on DASH JVM correlating with failures

## Architecture Components

```
┌─────────────────────────────────────────────────────────────────┐
│                    DASH Diagnostics Tool                        │
│                    (Master Orchestrator)                         │
└────────────┬────────────────────────────────────────────────────┘
             │
             ├─────► Module 1: Configuration Auditor
             │       ├── wsadmin/Jython config extractor
             │       ├── security.xml parser & validator
             │       ├── LTPA settings analyzer
             │       └── Session/cookie configuration checker
             │
             ├─────► Module 2: Log Analyzer & Correlator
             │       ├── SystemOut.log parser
             │       ├── SystemErr.log parser
             │       ├── FFDC analyzer
             │       ├── SECJ error pattern matcher
             │       └── Temporal correlation engine
             │
             ├─────► Module 3: SSL/Trust Store Validator
             │       ├── Certificate expiry checker
             │       ├── Trust store analyzer
             │       ├── Signer certificate validator
             │       └── TLS handshake tester
             │
             ├─────► Module 4: Integration Stress Tester
             │       ├── LTPA token generator/validator
             │       ├── Role-fetching servlet simulator
             │       ├── Load generator
             │       └── Response time/error tracker
             │
             └─────► Module 5: Supporting Utilities
                     ├── Clock skew detector
                     ├── Thread dump analyzer
                     ├── GC log parser
                     └── Report generator (HTML/JSON)
```

## Module 1: WebSphere & JazzSM Configuration Auditor

### Purpose
Extract and validate critical WebSphere configuration against SSO/LTPA best practices.

### Implementation Approach
- **Primary Tool**: wsadmin Jython scripts
- **Extraction Method**: AdminConfig and AdminControl APIs
- **Output**: JSON-formatted configuration snapshot

### Key Validations

#### 1.1 LTPA Configuration
```python
# Extract via wsadmin
security = AdminConfig.list('Security')
ltpa = AdminConfig.list('LTPA', security)

Checks:
- LTPA token timeout (default 120 min, check if too short)
- LTPA keys expiration date
- Last key generation timestamp
- Key generation interval
- Interoperability mode settings
```

#### 1.2 Session Management
```python
# Check session timeout vs LTPA timeout
deployment_manager = AdminConfig.list('SessionManager')

Validations:
- HTTP session timeout < LTPA timeout (prevent race condition)
- Session persistence mode (Memory/DB/None)
- Cookie settings (maxAge, domain, secure, httpOnly)
- Enable URL rewriting (should be false for security)
```

#### 1.3 Web Container Thread Pool
```python
# Check for potential exhaustion
server = AdminConfig.getid('/Server:server1/')
threadPool = AdminConfig.list('ThreadPool', server)

Alerts:
- Maximum thread pool size
- Current active threads (via AdminControl during runtime)
- Hung thread threshold
- Queue depth and rejections
```

#### 1.4 Cookie Configuration
```python
# LTPAToken2 cookie specifics
webContainer = AdminConfig.list('WebContainer')

Critical Checks:
- Cookie domain scope (must be accessible to OpenShift if cross-domain)
- HttpOnly flag (recommended: true)
- Secure flag (should be true if HTTPS)
- SameSite attribute (8.5.5.24 may not support, check backport)
```

### Output Format
```json
{
  "timestamp": "2025-11-06T10:30:00Z",
  "was_version": "8.5.5.24",
  "ltpa_config": {
    "timeout_minutes": 120,
    "key_expiry": "2026-01-15",
    "last_regeneration": "2025-01-15",
    "issues": ["WARNING: Keys expire in 70 days"]
  },
  "session_config": {
    "timeout_minutes": 30,
    "ltpa_timeout_minutes": 120,
    "race_condition_risk": false
  },
  "thread_pool": {
    "max_threads": 50,
    "warning": "Max threads may be insufficient for production load"
  }
}
```

## Module 2: Advanced Log Analyzer & Correlation Engine

### Purpose
Parse WebSphere logs to identify security errors and correlate with reported failure times.

### Log Sources
1. **SystemOut.log** - Application and security trace
2. **SystemErr.log** - Exceptions and stack traces
3. **FFDC logs** - First Failure Data Capture incidents
4. **native_stderr.log** - JVM crashes (if applicable)

### Pattern Matching Strategy

#### 2.1 LTPA-Specific Errors
```regex
Patterns to detect:
- SECJ0314E.*LTPA.*token.*expired
- SECJ0369E.*authentication.*failed
- SECJ0374E.*LTPA.*signature.*invalid
- CWWSS8043E.*Single.*sign.*on.*failed
- SESN0008E.*session.*not.*found
- SESN0307W.*invalidated.*session
```

#### 2.2 Temporal Correlation
```python
Algorithm:
1. Accept user input: "TCE failure timestamp: 2025-11-05 14:32:15"
2. Create time window: ±5 minutes around failure
3. Search all logs for:
   - SECJ errors in window
   - GC events > 1 second
   - Thread pool exhaustion warnings
   - LTPA key regeneration events
4. Output: Correlation report showing causality candidates
```

#### 2.3 GC Correlation
```python
# Parse native_stdout.log or verbosegc logs
Pattern: <gc.*type="global".*totalTime="(\d+)" />

If GC pause > 3000ms and overlaps with failure window:
  Flag as "HIGH PROBABILITY ROOT CAUSE"
```

### Output Format
```json
{
  "analysis_period": "2025-11-05 14:27:15 to 14:37:15",
  "tce_failure_time": "2025-11-05 14:32:15",
  "correlated_events": [
    {
      "timestamp": "2025-11-05 14:32:12",
      "log_file": "SystemOut.log",
      "severity": "ERROR",
      "code": "SECJ0314E",
      "message": "LTPA token expired",
      "correlation_confidence": "HIGH"
    },
    {
      "timestamp": "2025-11-05 14:32:10",
      "event_type": "GC",
      "duration_ms": 4500,
      "correlation_confidence": "MEDIUM"
    }
  ]
}
```

## Module 3: SSL & Trust Store Validator

### Purpose
Validate SSL/TLS configuration and certificate chain between DASH and OpenShift.

### Implementation Approach
- Use Java keytool for local trust store inspection
- OpenSSL s_client for remote endpoint testing
- Python ssl library for programmatic validation

### Validations

#### 3.1 Certificate Expiry
```bash
# Extract all certs from WebSphere trust store
keytool -list -v -keystore $WAS_HOME/profiles/[profile]/config/cells/[cell]/trust.p12 \
  -storepass WebAS

Check:
- Certificates expiring within 90 days
- Expired certificates
- Self-signed certificates (potential trust issues)
```

#### 3.2 Trust Store Completeness
```python
Algorithm:
1. Determine OpenShift ingress endpoint for TCE
2. Extract server certificate chain from endpoint
3. Verify each cert in chain exists in WebSphere trust store
4. Flag missing intermediate CAs
```

#### 3.3 TLS Handshake Test
```bash
# Simulate handshake from DASH server
openssl s_client -connect openshift-tce-endpoint:443 \
  -CAfile $WAS_HOME/.../trust.pem \
  -showcerts

Success criteria:
- Handshake completes
- No "Verify return code" errors
- Protocol version is TLS 1.2+ (1.0/1.1 deprecated)
```

## Module 4: Integration Stress Tester (TCE Simulator)

### Purpose
Reproduce the intermittent failure by stress-testing the DASH role-fetching servlet.

### Architecture
```
┌──────────────┐         HTTPS + LTPA Token        ┌──────────────┐
│   Stress     │────────────────────────────────────►│  DASH Role   │
│   Tester     │         (Cookie: LTPAToken2=...)   │  Servlet     │
│   (Python)   │◄────────────────────────────────────│  (/tce/role) │
└──────────────┘         JSON: {roles: [...]}       └──────────────┘
     │
     ├─ Metrics Collector
     │  ├─ Success count
     │  ├─ Failure count
     │  ├─ Response time histogram
     │  └─ HTTP status codes
     │
     └─ Failure Logger
        └─ Captures exact request/response on failure
```

### Implementation Details

#### 4.1 LTPA Token Acquisition
```python
Option 1: Manual supply (admin provides valid token)
Option 2: Programmatic login via DASH login form
Option 3: Use wsadmin to generate test token (if API available)

Token format:
Cookie: LTPAToken2=AAECAzQ3...[base64]...
```

#### 4.2 Load Patterns
```python
Test scenarios:
1. Steady state: 10 req/sec for 30 minutes
2. Burst: 100 req/sec for 1 minute
3. Soak: 1 req/sec for 24 hours (catch timing issues)
4. Time-boundary: Requests at :00 seconds (catch key regeneration)
```

#### 4.3 Failure Detection
```python
A request is considered FAILED if:
- HTTP status != 200
- Response time > 5 seconds
- Response body missing expected 'roles' field
- SSL handshake error
- Connection timeout

On failure:
1. Log full request headers
2. Log response (if any)
3. Record exact timestamp (for log correlation)
4. Capture system metrics (CPU, memory, GC)
```

### Output Format
```json
{
  "test_run_id": "stress-20251106-103000",
  "duration_seconds": 1800,
  "total_requests": 18000,
  "successful": 17892,
  "failed": 108,
  "failure_rate": 0.006,
  "avg_response_time_ms": 45,
  "p95_response_time_ms": 120,
  "p99_response_time_ms": 450,
  "failures_by_type": {
    "http_500": 50,
    "timeout": 30,
    "ssl_error": 28
  },
  "failure_timestamps": [
    "2025-11-06T10:32:15.234Z",
    "2025-11-06T10:45:03.112Z"
  ]
}
```

## Module 5: Clock Skew Detection

### Purpose
Detect and quantify time synchronization issues between OpenShift and DASH.

### Methodology

#### 5.1 LTPA Token Timestamp Analysis
```python
LTPA tokens contain:
- Issue time (nbf - not before)
- Expiry time (exp - expiration)

Algorithm:
1. Capture LTPA token from DASH
2. Decode base64 payload
3. Extract nbf timestamp
4. Compare with current system time on DASH server
5. Skew = DASH_time - LTPA_nbf_time

Threshold:
- Skew > 5 seconds: WARNING
- Skew > 30 seconds: CRITICAL (likely causing validation failures)
```

#### 5.2 NTP Status Check
```bash
# On DASH server
ntpq -p
timedatectl status

# On OpenShift (via oc exec)
oc exec <tce-pod> -- date -u
oc exec <tce-pod> -- ntpq -p
```

#### 5.3 Continuous Monitoring
```python
# Sample clock skew every 60 seconds for 1 hour
for i in range(60):
    skew = detect_clock_skew()
    if abs(skew) > 5:
        alert("Clock skew detected: {} seconds".format(skew))
    sleep(60)
```

## Data Flow Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│ 1. CONFIGURATION EXTRACTION PHASE                               │
│    wsadmin → Extract configs → Validate → JSON snapshot         │
└─────────────────────────────────────────────────────────────────┘
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│ 2. LOG ANALYSIS PHASE                                           │
│    Parse logs → Pattern match → Temporal correlation → Report   │
└─────────────────────────────────────────────────────────────────┘
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│ 3. SSL VALIDATION PHASE                                         │
│    Check certs → Validate trust → Test handshake → Report       │
└─────────────────────────────────────────────────────────────────┘
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│ 4. STRESS TEST PHASE                                            │
│    Generate load → Monitor failures → Correlate → Report        │
└─────────────────────────────────────────────────────────────────┘
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│ 5. REPORT GENERATION                                            │
│    Aggregate results → Root cause analysis → HTML/JSON report   │
└─────────────────────────────────────────────────────────────────┘
```

## Technology Stack

- **Configuration Extraction**: wsadmin (Jython 2.7)
- **Log Analysis**: Python 3.x (regex, pandas for correlation)
- **SSL Validation**: OpenSSL, Java keytool, Python ssl module
- **Stress Testing**: Python 3.x (requests library)
- **Orchestration**: Bash shell scripts
- **Reporting**: Python (Jinja2 for HTML templates)

## Deployment Model

### Installation
```bash
# On DASH WebSphere server
cd /opt/diagnostics
git clone <repo> dash-ltpa-diagnostics
cd dash-ltpa-diagnostics
./bin/setup.sh

Setup script actions:
1. Validates Python 3.x availability
2. Installs required Python packages (requests, pandas, jinja2)
3. Validates wsadmin availability
4. Creates output directory structure
5. Validates access to WAS logs and config
```

### Execution Modes

#### Mode 1: Quick Scan (5 minutes)
```bash
./bin/run_diagnostics.sh --mode quick
# Runs config audit + last 1 hour of logs
```

#### Mode 2: Full Analysis (30 minutes)
```bash
./bin/run_diagnostics.sh --mode full
# All modules except stress test
```

#### Mode 3: Stress Test Only
```bash
./bin/run_diagnostics.sh --mode stress --duration 3600 --rate 10
# Runs load test for 1 hour at 10 req/sec
```

#### Mode 4: Targeted Investigation
```bash
./bin/run_diagnostics.sh --mode investigate \
  --failure-time "2025-11-06 14:32:15" \
  --window 300
# Correlates logs around specific failure timestamp
```

## Security Considerations

1. **Credential Handling**
   - Never log LTPA token values (only first/last 4 chars)
   - Trust store passwords read from encrypted config
   - wsadmin credentials via prompt or secure vault

2. **Log Sanitization**
   - Redact user IDs in output reports
   - Redact IP addresses if required
   - PII filtering for GDPR compliance

3. **File Permissions**
   - Tool runs as wasadmin user
   - Output files: 640 permissions
   - No world-readable output

## Extensibility

### Plugin Architecture
```python
# modules/plugins/custom_validator.py
class CustomValidator:
    def validate(self, config):
        # Custom validation logic
        return ValidationResult(...)

# Automatically loaded by main orchestrator
```

### Custom Pattern Files
```yaml
# config/custom_patterns.yaml
security_patterns:
  - regex: "CUSTOM_ERROR_\\d{4}"
    severity: ERROR
    description: "Custom security error"
```

## Performance Considerations

- Log parsing uses streaming (not loading entire file into memory)
- Parallel execution of independent modules
- Configurable sampling rate for large log files
- Rate limiting on stress test to avoid DoS

## Next Steps

See **DIAGNOSTIC_STRATEGY.md** for immediate troubleshooting steps while this tool is being deployed.
