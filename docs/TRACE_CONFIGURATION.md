# WebSphere Security Trace Configuration for LTPA Diagnostics

## Purpose

This document provides detailed trace specifications for diagnosing LTPA token validation issues in WebSphere Application Server 8.5.5.24, specifically targeting OpenShift integration requests without overwhelming system logs.

## Core Question: Optimal Trace String for OpenShift TCE Requests

### Recommended Trace Specification

```
com.ibm.ws.security.ltpa.*=all:com.ibm.ws.security.token.*=all:com.ibm.ws.security.web.WebAuthenticator=all:com.ibm.ws.security.web.WebAppSecurityCollaboratorImpl=all:com.ibm.issw.dash.*=finest
```

### Component Breakdown

#### 1. `com.ibm.ws.security.ltpa.*=all`
**Captures:**
- LTPA token parsing and validation
- Token expiration checks
- Token signature verification
- LTPA key loading and validation
- Token creation (for new logins)

**Sample Output:**
```
[11/6/25 14:32:15:123] LTPA          > com.ibm.ws.security.ltpa.LTPAToken validateToken ENTRY
[11/6/25 14:32:15:124] LTPA          3 Token received: LTPATOKEN2=AAECAzQ3ODA...
[11/6/25 14:32:15:125] LTPA          3 Token expiration time: 1730907135000
[11/6/25 14:32:15:126] LTPA          3 Current server time:   1730905935000
[11/6/25 14:32:15:127] LTPA          3 Time until expiry: 1200000 ms (20 minutes)
[11/6/25 14:32:15:128] LTPA          3 Token signature validation: SUCCESS
[11/6/25 14:32:15:129] LTPA          < com.ibm.ws.security.ltpa.LTPAToken validateToken RETURN Subject: {Principal=user@REALM}
```

**Why Important:**
- Directly shows if token is expired
- **Reveals clock skew**: Compare "Token expiration time" vs "Current server time"
- Shows signature validation failures (indicates key mismatch)

#### 2. `com.ibm.ws.security.token.*=all`
**Captures:**
- Token cache operations (WAS caches validated tokens)
- Token recreation attempts
- Token attribute extraction (username, realm, groups)

**Sample Output:**
```
[11/6/25 14:32:15:130] SecurityToken 3 Checking token cache for user: user@REALM
[11/6/25 14:32:15:131] SecurityToken 3 Cache MISS - validating token
[11/6/25 14:32:15:135] SecurityToken 3 Token validated, caching for 600 seconds
[11/6/25 14:32:15:136] SecurityToken 3 Extracted attributes: {uniqueId=user@REALM, groups=[group1,group2]}
```

**Why Important:**
- Cache misses indicate performance issues
- Shows if token attributes (groups) are being extracted correctly
- Helps identify role-fetching failures due to missing groups

#### 3. `com.ibm.ws.security.web.WebAuthenticator=all`
**Captures:**
- HTTP request authentication flow
- Cookie extraction from request
- SSO token lookup
- Authentication result (success/failure)

**Sample Output:**
```
[11/6/25 14:32:15:100] WebAuth       > authenticate ENTRY URI=/tce/roles
[11/6/25 14:32:15:101] WebAuth       3 Found SSO cookie: LTPAToken2
[11/6/25 14:32:15:102] WebAuth       3 Cookie domain: .example.com
[11/6/25 14:32:15:103] WebAuth       3 Cookie path: /
[11/6/25 14:32:15:140] WebAuth       3 Authentication result: SUCCESS
[11/6/25 14:32:15:141] WebAuth       < authenticate RETURN Subject: {Principal=user@REALM}
```

**Why Important:**
- Shows if LTPAToken2 cookie is present in request
- Identifies cookie domain/path issues
- **Critical for OpenShift integration**: Confirms cookie is being sent from TCE

#### 4. `com.ibm.ws.security.web.WebAppSecurityCollaboratorImpl=all`
**Captures:**
- Authorization decisions (role checks)
- Security constraint enforcement
- Access control decisions

**Sample Output:**
```
[11/6/25 14:32:15:150] WebAppSec     > authorize ENTRY URI=/tce/roles, User=user@REALM
[11/6/25 14:32:15:151] WebAppSec     3 Checking security constraints for URI: /tce/roles
[11/6/25 14:32:15:152] WebAppSec     3 Required roles: [DashUser]
[11/6/25 14:32:15:153] WebAppSec     3 User roles: [DashUser, DashAdmin]
[11/6/25 14:32:15:154] WebAppSec     3 Authorization: GRANTED
[11/6/25 14:32:15:155] WebAppSec     < authorize RETURN true
```

**Why Important:**
- Shows role-checking logic
- Identifies authorization failures even after successful authentication
- **Directly relates to TCE role-fetching**: If servlet requires roles user doesn't have

#### 5. `com.ibm.issw.dash.*=finest`
**Captures:**
- DASH application-level processing
- Custom LTPA handling within DASH
- Role-fetching servlet logic (if instrumented)

**Note:** Package name `com.ibm.issw.dash` is an assumption. Verify actual DASH package:
```bash
# Extract DASH WAR and check package structure:
cd $WAS_HOME/profiles/<profile>/installedApps/<cell>
unzip -l dash.ear | grep -i servlet
unzip -p dash.ear dash.war WEB-INF/classes | jar tf - | head -20
```

**If DASH uses different package:**
Replace `com.ibm.issw.dash.*=finest` with actual package (e.g., `com.ibm.jazz.dash.*=finest`)

**Sample Output (Expected):**
```
[11/6/25 14:32:15:160] DashServlet   > RoleFetchServlet.doGet ENTRY
[11/6/25 14:32:15:161] DashServlet   3 Extracting user from Subject
[11/6/25 14:32:15:162] DashServlet   3 User: user@REALM
[11/6/25 14:32:15:163] DashServlet   3 Querying role database for user
[11/6/25 14:32:15:165] DashServlet   3 Found roles: [DashUser, DashAdmin]
[11/6/25 14:32:15:166] DashServlet   < RoleFetchServlet.doGet RETURN 200
```

---

## How This Trace Configuration Avoids Log Overwhelm

### What We're NOT Tracing

#### ❌ `*=all` (Global trace)
**Problem:** Captures everything - thousands of lines per second
**Impact:** 10GB+ logs in minutes, obscures relevant data

#### ❌ `com.ibm.ws.webcontainer.*=all`
**Problem:** Logs every HTTP request detail (headers, parameters, routing)
**Impact:** Useful for HTTP-level debugging, but overkill for LTPA issues

#### ❌ `com.ibm.ws.security.registry.*=all`
**Problem:** Logs LDAP/AD queries, user registry lookups
**Impact:** Only needed if authentication fails AFTER LTPA validation (i.e., realm issues)

#### ❌ `com.ibm.ws.session.*=all`
**Problem:** Logs session creation, invalidation, persistence
**Impact:** Useful for session management issues, but not for LTPA token validation

### Trace Scope Estimation

With recommended trace string, expect:
- **Low traffic** (< 10 req/min): ~500 KB/hour
- **Medium traffic** (100 req/min): ~5 MB/hour
- **High traffic** (1000 req/min): ~50 MB/hour

**Rule of Thumb:** If your current SystemOut.log is 100 MB/day, expect 300-400 MB/day with these traces.

### Trace Filtering (Advanced)

If logs are still too large, use log filtering (WAS 8.5.5+):
```bash
# In wsadmin:
server = AdminControl.completeObjectName('type=Server,name=server1,*')

# Enable trace with filtering:
traceSpec = 'com.ibm.ws.security.ltpa.*=all:com.ibm.ws.security.token.*=all'
filterSpec = '*=enabled'  # Default: log all messages
AdminControl.setAttribute(server, 'traceSpecification', traceSpec)
```

**Custom Filter Example:**
Only log LTPA traces if they contain "FAILED" or "expired":
```bash
# Requires custom log handler (advanced) - use log parsing tool instead
```

---

## Clock Skew Detection via Traces

### How LTPA Tokens Encode Time

LTPA tokens (LTPAToken2) are encrypted and signed, but validation traces reveal timing data.

**Trace Output Example (Successful Validation):**
```
[11/6/25 14:32:15:125] LTPA 3 Token expiration time: 1730907135000  (epoch milliseconds)
[11/6/25 14:32:15:126] LTPA 3 Current server time:   1730905935000  (epoch milliseconds)
[11/6/25 14:32:15:127] LTPA 3 Time until expiry:     1200000 ms (20 minutes)
```

**Calculation:**
```
Token expiration: 1730907135000 ms = Wed Nov 6 14:52:15 UTC 2025
Current server:   1730905935000 ms = Wed Nov 6 14:32:15 UTC 2025
Difference:       1200000 ms = 20 minutes ✓ (valid)
```

### Clock Skew Scenario 1: OpenShift Clock AHEAD by 60 seconds

**Trace Output:**
```
[11/6/25 14:32:15:125] LTPA 3 Token expiration time: 1730907135000
[11/6/25 14:32:15:126] LTPA 3 Current server time:   1730905995000  ← 60 seconds later
[11/6/25 14:32:15:127] LTPA 3 Time until expiry:     1140000 ms (19 minutes)
[11/6/25 14:32:15:128] LTPA 3 Token signature validation: SUCCESS
```

**Impact:**
- Token appears to expire 1 minute earlier than intended
- Not immediately problematic, but reduces effective timeout
- If token is already near expiry, may push it over the edge

### Clock Skew Scenario 2: DASH Clock AHEAD by 60 seconds

**Trace Output:**
```
[11/6/25 14:32:15:125] LTPA 3 Token expiration time: 1730907135000
[11/6/25 14:32:15:126] LTPA 3 Current server time:   1730905935000  ← 60 seconds earlier
[11/6/25 14:32:15:127] LTPA 3 Time until expiry:     1260000 ms (21 minutes)
```

**Impact:**
- Token appears to have longer validity
- Less likely to cause immediate failures
- May mask underlying timeout issues

### Clock Skew Scenario 3: CRITICAL - OpenShift Clock BEHIND by 5 minutes

**Trace Output:**
```
[11/6/25 14:32:15:125] LTPA 3 Token expiration time: 1730906835000  ← Issued 5 min ago
[11/6/25 14:32:15:126] LTPA 3 Current server time:   1730907135000  ← Current time
[11/6/25 14:32:15:127] LTPA E Time until expiry:     -300000 ms (EXPIRED)
[11/6/25 14:32:15:128] LTPA E Token validation FAILED: Token expired
[11/6/25 14:32:15:129] LTPA < validateToken RETURN null
```

**Impact:**
- **ROOT CAUSE of intermittent failures**
- Token appears expired immediately upon arrival at DASH
- Explains why same user/token works sometimes (if clock drift is gradual)

### Automated Clock Skew Detection Algorithm

```python
# Parse trace output
token_expiry_epoch = 1730907135000  # From trace
server_time_epoch = 1730905935000   # From trace

# Calculate expected token age (LTPA timeout is typically 120 min)
expected_token_lifetime_ms = 120 * 60 * 1000  # 7200000 ms

# Calculate token issue time
token_issue_time = token_expiry_epoch - expected_token_lifetime_ms

# Calculate apparent clock skew
clock_skew_ms = server_time_epoch - token_issue_time

# Evaluate
if abs(clock_skew_ms) > 5000:  # 5 seconds
    print(f"WARNING: Clock skew detected: {clock_skew_ms/1000} seconds")
if abs(clock_skew_ms) > 30000:  # 30 seconds
    print(f"CRITICAL: Clock skew will cause token failures")
```

---

## Trace String Variations by Scenario

### Scenario A: Minimal Trace (Production-Safe, Low Volume)
**Use Case:** Continuous monitoring in production without performance impact
```
com.ibm.ws.security.ltpa.LTPAToken=all:com.ibm.ws.security.web.WebAuthenticator=all
```
**Captures:** Only token validation and authentication results
**Log Volume:** ~100 KB/hour (medium traffic)

### Scenario B: Role-Fetching Focus
**Use Case:** Specifically debugging TCE role-fetching failures
```
com.ibm.ws.security.ltpa.*=all:com.ibm.ws.security.token.*=all:com.ibm.ws.security.web.WebAppSecurityCollaboratorImpl=all:com.ibm.issw.dash.RoleFetchServlet=finest
```
**Captures:** Token validation + authorization decisions + servlet processing
**Log Volume:** ~2 MB/hour (medium traffic)

### Scenario C: Full Security Audit
**Use Case:** Comprehensive security troubleshooting (short duration only)
```
com.ibm.ws.security.*=all:com.ibm.issw.dash.*=finest
```
**Captures:** All security subsystem activity
**Log Volume:** ~20 MB/hour (medium traffic)
**WARNING:** Use for max 15 minutes during isolated test

### Scenario D: SSL/TLS Handshake Issues
**Use Case:** If suspecting certificate or SSL problems
```
com.ibm.ws.security.ltpa.*=all:com.ibm.jsse2.*=all:SSL=all
```
**Captures:** LTPA validation + SSL handshake details + certificate validation
**Log Volume:** ~5 MB/hour (medium traffic)

---

## Trace Enabling Methods

### Method 1: Runtime Trace (No Restart, Immediate Effect)

```bash
cd $WAS_HOME/bin
./wsadmin.sh -lang jython -username <admin> -password <pwd>

# Enable trace:
wsadmin> server = AdminControl.completeObjectName('type=Server,name=server1,*')
wsadmin> traceSpec = 'com.ibm.ws.security.ltpa.*=all:com.ibm.ws.security.token.*=all:com.ibm.ws.security.web.WebAuthenticator=all:com.ibm.ws.security.web.WebAppSecurityCollaboratorImpl=all:com.ibm.issw.dash.*=finest'
wsadmin> AdminControl.setAttribute(server, 'traceSpecification', traceSpec)

# Verify:
wsadmin> print AdminControl.getAttribute(server, 'traceSpecification')

# Disable trace:
wsadmin> AdminControl.setAttribute(server, 'traceSpecification', '*=info')
```

**Pros:**
- Immediate effect (no restart)
- Ideal for capturing specific incident
- Easy to enable/disable

**Cons:**
- Lost on server restart
- Must re-enable manually

### Method 2: Persistent Trace (Survives Restart)

#### Via WebSphere Admin Console:
1. Navigate to: **Troubleshooting → Logs and trace → server1 → Diagnostic Trace**
2. Click **Configuration** tab
3. **Trace Specification** field: Paste trace string
4. **Trace Output** settings:
   - File name: `trace.log` (default)
   - Maximum file size: 100 MB
   - Maximum number of historical files: 10
5. Click **Apply**, then **Save** to master configuration
6. Restart server

#### Via wsadmin (Persistent):
```bash
wsadmin> server = AdminConfig.getid('/Server:server1/')
wsadmin> ts = AdminConfig.list('TraceService', server)
wsadmin> AdminConfig.modify(ts, [['traceSpecification', traceSpec]])
wsadmin> AdminConfig.save()
# Restart required
```

**Pros:**
- Survives restarts
- Centrally managed

**Cons:**
- Requires restart to take effect
- Risk of forgetting to disable (continuous overhead)

### Method 3: Temporary Trace File (Separate from SystemOut.log)

```bash
# In wsadmin (runtime):
server = AdminControl.completeObjectName('type=Server,name=server1,*')
traceSpec = 'com.ibm.ws.security.ltpa.*=all:...'
AdminControl.setAttribute(server, 'traceSpecification', traceSpec)

# Redirect trace to separate file:
AdminControl.invoke(server, 'setTraceOutput', ['file=/opt/logs/ltpa_trace.log', 'info'])
```

**Pros:**
- Keeps security traces separate from application logs
- Easier to parse and share with IBM Support
- Doesn't bloat SystemOut.log

**Cons:**
- Requires runtime scripting

---

## Trace Output Parsing Strategies

### Strategy 1: Real-Time Monitoring
```bash
# Tail trace output as it's generated:
tail -f $WAS_HOME/profiles/<profile>/logs/server1/trace.log | grep -E "LTPA|WebAuth|SECJ"

# Filter for failures only:
tail -f trace.log | grep -E "FAILED|EXPIRED|INVALID|SECJ[0-9]{4}E"
```

### Strategy 2: Post-Incident Analysis
```bash
# Extract all LTPA-related entries from last hour:
grep -E "LTPA|Token" trace.log | grep "$(date -d '1 hour ago' '+%m/%d/%y')"

# Correlate with specific failure timestamp:
# Example: TCE reported failure at 14:32:15
grep "14:32:1[0-9]" trace.log | grep -E "LTPA|WebAuth"
```

### Strategy 3: Automated Correlation (Python Script)
```python
#!/usr/bin/env python3
import re
from datetime import datetime, timedelta

failure_time = datetime(2025, 11, 6, 14, 32, 15)
window = timedelta(minutes=5)

with open('trace.log', 'r') as f:
    for line in f:
        # Extract timestamp from trace line:
        # [11/6/25 14:32:15:123] LTPA ...
        match = re.match(r'\[(\d+/\d+/\d+) (\d+:\d+:\d+):\d+\]', line)
        if match:
            log_time = datetime.strptime(f"{match.group(1)} {match.group(2)}", "%m/%d/%y %H:%M:%S")
            if abs((log_time - failure_time).total_seconds()) < window.total_seconds():
                if 'LTPA' in line or 'SECJ' in line or 'FAILED' in line:
                    print(line.strip())
```

---

## Trace String Testing Checklist

Before enabling traces in production:

- [ ] Verify trace string syntax (no typos in package names)
- [ ] Test in DEV/TEST environment first
- [ ] Measure log growth rate over 15 minutes
- [ ] Confirm disk space available (recommend 10GB free)
- [ ] Set log file size limits (prevent disk exhaustion)
- [ ] Document enable/disable procedure
- [ ] Schedule trace duration (max 1 hour unless actively monitored)
- [ ] Notify team of increased log verbosity
- [ ] Prepare log analysis tools/scripts
- [ ] Plan trace disablement immediately after capture

---

## IBM Support Engagement

If escalating to IBM Support, provide:
1. **Trace logs** with recommended specification (this document)
2. **Collector output**: `collector.sh` from WAS bin directory
3. **FFDC files** from time of failure
4. **Thread dumps** if performance degradation observed
5. **Must-gather info**:
   - WAS version: `versionInfo.sh -maintenancePackages`
   - JDK version: `java -version`
   - OS version: `uname -a`
   - LTPA config: Output of wsadmin LTPA queries
   - Exact failure timestamp and frequency

---

## Quick Reference: Common Trace Patterns

### Pattern: Token Expired
```
LTPA.*Time until expiry.*-\d+.*EXPIRED
```

### Pattern: Signature Validation Failed
```
LTPA.*signature.*validation.*FAILED
```

### Pattern: Authentication Success
```
WebAuth.*Authentication result: SUCCESS
```

### Pattern: Authorization Denied
```
WebAppSec.*Authorization.*DENIED
```

### Pattern: Clock Skew Indicator
```
LTPA.*Time until expiry.*-\d{6,}  # Negative value > 100 seconds
```

---

## Conclusion

**Recommended Starting Point:**
```
com.ibm.ws.security.ltpa.*=all:com.ibm.ws.security.token.*=all:com.ibm.ws.security.web.WebAuthenticator=all:com.ibm.issw.dash.*=finest
```

This trace configuration provides:
- ✅ Complete LTPA token validation visibility
- ✅ Clock skew detection capability
- ✅ Cookie propagation verification
- ✅ Minimal performance impact
- ✅ Manageable log volume

**Enable for 30-60 minutes during TCE integration testing to capture intermittent failures.**
