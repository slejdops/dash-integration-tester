# Immediate Diagnostic Strategy for DASH LTPA Integration Issues

## Executive Summary

This document provides an actionable, prioritized list of manual diagnostic steps to perform **immediately** on your DASH/WebSphere environment while the automated tool is being deployed. These steps are ordered by likelihood of identifying the root cause based on the symptom profile.

## Priority 1: LTPA Token Timeout Mismatch (Most Likely)

### Hypothesis
HTTP session timeout exceeds LTPA token timeout, creating a race condition where users have valid sessions but expired tokens.

### Manual Verification Steps

#### Step 1.1: Extract Current LTPA Timeout
```bash
# Connect to wsadmin
cd $WAS_HOME/bin
./wsadmin.sh -lang jython -username <admin> -password <pwd>

# In wsadmin console:
wsadmin> security = AdminConfig.list('Security')
wsadmin> ltpa = AdminConfig.list('LTPA', security)
wsadmin> print AdminConfig.show(ltpa)

# Look for: timeout=<value>  (in MINUTES)
# Default: 120 minutes
```

**Expected Output:**
```
{timeout 120}
{keysFileName ${USER_INSTALL_ROOT}/etc/security/ltpa.keys}
...
```

#### Step 1.2: Extract Session Timeout
```bash
# Still in wsadmin:
wsadmin> servers = AdminConfig.list('Server').splitlines()
wsadmin> for server in servers:
wsadmin>     sm = AdminConfig.list('SessionManager', server)
wsadmin>     if sm:
wsadmin>         print "Server:", AdminConfig.showAttribute(server, 'name')
wsadmin>         print "Session timeout:", AdminConfig.showAttribute(sm, 'sessionTimeout')
wsadmin>         print "---"

# sessionTimeout is in MINUTES
```

#### Step 1.3: Compare Values
```
IF sessionTimeout > LTPA timeout:
    → ROOT CAUSE IDENTIFIED
    → Users retain HTTP session after LTPA expires
    → Servlet sees valid session but invalid LTPA

RECOMMENDED FIX:
Set sessionTimeout = (LTPA timeout - 10) minutes
This provides 10-minute safety buffer
```

**Immediate Fix Command:**
```bash
# In wsadmin (adjust server name):
server = AdminConfig.getid('/Server:server1/')
sm = AdminConfig.list('SessionManager', server)
AdminConfig.modify(sm, [['sessionTimeout', '110']])  # If LTPA is 120
AdminConfig.save()

# Restart required:
exit
./stopServer.sh server1
./startServer.sh server1
```

---

## Priority 2: Clock Skew Between OpenShift and WebSphere

### Hypothesis
Time difference between TCE (OpenShift) and DASH causes LTPA token to appear expired prematurely.

### Manual Verification Steps

#### Step 2.1: Check WebSphere Server Time
```bash
# On DASH host:
date -u
# Output: Wed Nov  6 14:32:15 UTC 2025

# Check NTP sync status:
ntpq -p
# Look for "*" indicating synced reference
# Or use:
timedatectl status
# Look for: "System clock synchronized: yes"
```

#### Step 2.2: Check OpenShift Pod Time
```bash
# Get TCE pod name:
oc get pods -n <tce-namespace> | grep tce

# Check time in pod:
oc exec -n <tce-namespace> <tce-pod-name> -- date -u

# Compare output with DASH server time
```

#### Step 2.3: Calculate Skew
```
Time difference calculation:
OpenShift time: 14:32:45 UTC
DASH time:      14:32:15 UTC
Skew:           +30 seconds

THRESHOLDS:
  0-5 seconds:   OK (within tolerance)
  5-30 seconds:  CONCERNING (may cause intermittent failures)
  >30 seconds:   CRITICAL (will cause frequent failures)
```

**Critical Detail for LTPA:**
LTPA tokens include:
- `nbf` (not before) timestamp
- `exp` (expiration) timestamp

If OpenShift clock is **ahead** by 30 seconds:
- Token appears to be issued "in the future" from DASH's perspective
- DASH rejects token as not yet valid

If OpenShift clock is **behind** by 30 seconds:
- Token appears older than it is
- May cause premature expiration

**Immediate Fix:**
```bash
# On DASH host (requires root):
systemctl stop ntpd
ntpdate -s time.nist.gov
systemctl start ntpd

# On OpenShift:
# Usually managed by cluster chrony config
# Escalate to OpenShift admin if skew detected
```

---

## Priority 3: Enable Targeted WebSphere Security Tracing

### Hypothesis
We need detailed traces of LTPA validation without overwhelming the logs.

### Recommended Trace String

#### For OpenShift Request Tracing Only:
```
com.ibm.ws.security.ltpa.*=all
com.ibm.ws.security.token.*=all
com.ibm.ws.security.web.*=all
com.ibm.issw.dash.*=finest
```

**Why This Trace String:**
- `com.ibm.ws.security.ltpa.*=all` - Captures token validation, key operations
- `com.ibm.ws.security.token.*=all` - Token parsing and expiration checks
- `com.ibm.ws.security.web.*=all` - Cookie handling, SSO flow
- `com.ibm.issw.dash.*=finest` - DASH servlet processing (if DASH uses this package)

**Does NOT include:**
- `*=all` (too noisy)
- `com.ibm.ws.security.registry.*` (user registry - not needed unless realm issues)
- `com.ibm.ws.webcontainer.*` (web container - only needed for HTTP-level issues)

#### Enable Tracing via wsadmin (Runtime - No Restart):
```bash
./wsadmin.sh -lang jython -username <admin> -password <pwd>

wsadmin> server = AdminControl.completeObjectName('type=Server,name=server1,*')
wsadmin> traceSpec = 'com.ibm.ws.security.ltpa.*=all:com.ibm.ws.security.token.*=all:com.ibm.ws.security.web.*=all:com.ibm.issw.dash.*=finest'
wsadmin> AdminControl.setAttribute(server, 'traceSpecification', traceSpec)

# Verify:
wsadmin> print AdminControl.getAttribute(server, 'traceSpecification')
```

#### Enable Tracing via Console (Permanent):
1. Navigate to: **Troubleshooting → Logs and Trace → server1 → Diagnostic Trace**
2. Configuration tab
3. Trace Specification: Paste trace string above
4. Save
5. Restart server

#### Capture Duration:
```
Enable traces for 15-30 minutes during peak TCE usage
Monitor SystemOut.log size:
  tail -f $WAS_HOME/profiles/<profile>/logs/server1/SystemOut.log

Look for patterns like:
  [LTPA] token validation started for user: <user>
  [LTPA] token expiration: <timestamp>
  [LTPA] current server time: <timestamp>
  [LTPA] validation result: SUCCESS/FAILED
```

**IMPORTANT:** Disable traces after capturing:
```bash
wsadmin> AdminControl.setAttribute(server, 'traceSpecification', '*=info')
```

---

## Priority 4: Analyze Recent FFDC Logs

### Hypothesis
WebSphere has captured First Failure Data Capture incidents related to security errors.

### Manual Verification Steps

#### Step 4.1: Locate FFDC Files
```bash
cd $WAS_HOME/profiles/<profile>/logs/ffdc

# List recent FFDC files (last 7 days):
find . -name "*.txt" -mtime -7 -exec ls -lh {} \;

# Search for LTPA-related incidents:
grep -l "LTPA\|SECJ\|SSO" *.txt
```

#### Step 4.2: Analyze Key FFDC Fields
```bash
# For each suspicious FFDC file:
cat ffdc_XXXXX.txt

Look for:
1. Exception Name: (e.g., com.ibm.websphere.security.auth.WSLoginFailedException)
2. Source ID: (indicates which component failed)
3. Probe ID: (unique failure point in code)
4. Stack Trace: (exact line of failure)
```

#### Step 4.3: Correlate with Failure Times
```bash
# FFDC files include timestamp in name: ffdc_YYYYMMDD_HHMMSS_<sequence>.txt

# If TCE reported failure at: 2025-11-06 14:32:15
# Look for FFDC files near that time:
ls -lh ffdc_20251106_14*.txt

# Check if timestamp matches ±5 minutes
```

**Common LTPA-Related FFDC Signatures:**
```
Exception: com.ibm.websphere.security.auth.WSLoginFailedException
+ "LTPA token is expired"
  → Confirms timeout issue

Exception: javax.security.auth.login.LoginException
+ "CWWSS8043E: Single sign-on (SSO) failed"
  → SSO mechanism breakdown

Exception: com.ibm.websphere.security.WSSecurityException
+ "signature validation failed"
  → LTPA key mismatch or corruption
```

---

## Priority 5: Check for LTPA Key Regeneration Events

### Hypothesis
LTPA keys are being regenerated during production hours, invalidating active tokens.

### Manual Verification Steps

#### Step 5.1: Check LTPA Key File Timestamps
```bash
cd $WAS_HOME/profiles/<profile>/config/cells/<cell>/security

ls -lh ltpa.keys
# Check "Modify" timestamp

# If modified recently (within last 7 days):
stat ltpa.keys
```

#### Step 5.2: Search Logs for Key Generation Events
```bash
cd $WAS_HOME/profiles/<profile>/logs/server1

# Search for key generation messages:
grep -i "LTPA.*key.*generat" SystemOut.log
grep -i "SECJ0013I" SystemOut.log  # "LTPA keys have been created"

# Output example:
# [11/6/25 14:00:00:123] SECJ0013I: LTPA keys have been created in file: /opt/IBM/...
```

#### Step 5.3: Correlate Key Regeneration with Failures
```
IF key regeneration timestamp matches failure window:
  → ROOT CAUSE IDENTIFIED
  → All tokens issued with old key become invalid
  → Explains sudden widespread failures

RECOMMENDED FIX:
  - Schedule key regeneration during maintenance windows only
  - Increase key lifetime if regenerating too frequently
  - Implement gradual key rollover (requires multi-member setup)
```

**Check Key Regeneration Schedule:**
```bash
# In wsadmin:
security = AdminConfig.list('Security')
ltpa = AdminConfig.list('LTPA', security)
print AdminConfig.show(ltpa)

# Look for any automated regeneration settings
# (Note: 8.5.5.24 may not have automated regeneration - usually manual)
```

---

## Priority 6: Thread Pool Exhaustion Check

### Hypothesis
Web container thread pool exhaustion causes servlet timeouts during role fetching.

### Manual Verification Steps

#### Step 6.1: Check Current Thread Pool Configuration
```bash
# In wsadmin:
server = AdminConfig.getid('/Server:server1/')
wc = AdminConfig.list('WebContainer', server)
tp = AdminConfig.showAttribute(wc, 'threadPool')
print AdminConfig.show(tp)

# Look for:
# maximumSize: <value>  (default: 50)
# minimumSize: <value>  (default: 10)
```

#### Step 6.2: Check Runtime Thread Pool Statistics
```bash
# In wsadmin:
server = AdminControl.completeObjectName('type=Server,name=server1,*')
perfMbean = AdminControl.queryNames('type=ThreadPoolStats,name=WebContainer,*', None)

if perfMbean:
    print AdminControl.getAttribute(perfMbean, 'activeCount')
    print AdminControl.getAttribute(perfMbean, 'poolSize')
    print AdminControl.getAttribute(perfMbean, 'maxPoolSize')
```

#### Step 6.3: Analyze Thread Dumps During Failures
```bash
# Generate thread dump manually:
./wsadmin.sh -lang jython
wsadmin> server = AdminControl.completeObjectName('type=Server,name=server1,*')
wsadmin> AdminControl.invoke(server, 'dumpThreads')

# Thread dump written to:
$WAS_HOME/profiles/<profile>/logs/server1/javacore.*.txt

# Analyze for hung threads:
grep -A 10 "WebContainer" javacore.*.txt | grep "State:"
# Look for many threads in "Runnable" or "Blocked" state
```

**Warning Signs:**
- `activeCount` consistently near `maxPoolSize`
- Many threads stuck in `BLOCKED` or `WAITING` state
- Frequent `WSVR0605W: Thread "<name>" has been active for <time> milliseconds`

**Immediate Mitigation:**
```bash
# Increase thread pool size (in wsadmin):
server = AdminConfig.getid('/Server:server1/')
wc = AdminConfig.list('WebContainer', server)
tp = AdminConfig.showAttribute(wc, 'threadPool')
AdminConfig.modify(tp, [['maximumSize', '100']])  # Increase from 50
AdminConfig.save()

# Restart required
```

---

## Priority 7: SSL/Certificate Validation

### Hypothesis
SSL handshake failures between OpenShift and DASH causing intermittent connection drops.

### Manual Verification Steps

#### Step 7.1: Identify OpenShift TCE Endpoint
```bash
# Get route hostname:
oc get route -n <tce-namespace>

# Example output:
# NAME   HOST                                      PORT
# tce    tce-app.apps.openshift.example.com       443
```

#### Step 7.2: Test SSL Handshake from DASH Server
```bash
# From DASH host, test connection to OpenShift:
openssl s_client -connect tce-app.apps.openshift.example.com:443 -showcerts

# Check output for:
# 1. "Verify return code: 0 (ok)" ← GOOD
# 2. "Verify return code: 20 (unable to get local issuer certificate)" ← BAD
# 3. Certificate expiry dates
```

#### Step 7.3: Check WebSphere Trust Store
```bash
cd $WAS_HOME/profiles/<profile>/config/cells/<cell>

# List trust store contents:
keytool -list -keystore trust.p12 -storepass WebAS -storetype PKCS12

# Look for:
# - OpenShift cluster CA certificate
# - OpenShift ingress certificate
# - Any intermediate CAs

# Search for specific alias:
keytool -list -keystore trust.p12 -storepass WebAS -storetype PKCS12 | grep -i openshift
```

#### Step 7.4: Check Certificate Expiry
```bash
# Detailed certificate info:
keytool -list -v -keystore trust.p12 -storepass WebAS -storetype PKCS12 | grep -A 5 "Valid"

# Look for "Valid until" dates
# Flag any certificates expiring within 30 days
```

#### Step 7.5: Test Reverse Connection (DASH → OpenShift)
```bash
# If DASH needs to call back to OpenShift:
curl -v https://tce-app.apps.openshift.example.com/health

# Check for SSL errors:
# - "SSL certificate problem: unable to get local issuer certificate"
# - "SSL certificate problem: certificate has expired"
```

**Immediate Fix if Certificate Missing:**
```bash
# Export OpenShift cert:
oc get secret router-certs-default -n openshift-ingress -o jsonpath='{.data.tls\.crt}' | base64 -d > openshift-ingress.crt

# Import into WebSphere trust store:
cd $WAS_HOME/profiles/<profile>/config/cells/<cell>
keytool -import -file /tmp/openshift-ingress.crt \
  -alias openshift-ingress-ca \
  -keystore trust.p12 \
  -storepass WebAS \
  -storetype PKCS12 \
  -noprompt

# Restart WebSphere
```

---

## Priority 8: Cookie Domain Scope Validation

### Hypothesis
LTPAToken2 cookie domain scope prevents OpenShift from reading the cookie.

### Manual Verification Steps

#### Step 8.1: Capture LTPAToken Cookie from Browser
```bash
# Have user:
1. Log into DASH via browser
2. Open Developer Tools (F12)
3. Navigate to: Application → Cookies → <dash-hostname>
4. Locate: LTPAToken2
5. Copy cookie details:
   - Domain: <value>
   - Path: <value>
   - Secure: <value>
   - HttpOnly: <value>
   - SameSite: <value>
```

#### Step 8.2: Compare with OpenShift Hostname
```
DASH hostname:       dash.example.com
OpenShift hostname:  tce-app.apps.openshift.example.com

Cookie domain:       .example.com  ← GOOD (both match)
Cookie domain:       dash.example.com  ← BAD (too specific, OpenShift can't read)
Cookie domain:       <not set>  ← DEPENDS (browser default behavior)
```

#### Step 8.3: Check WebSphere SSO Domain Configuration
```bash
# In wsadmin:
security = AdminConfig.list('Security')
sso = AdminConfig.list('SingleSignon', security)
print AdminConfig.show(sso)

# Look for:
# domainName: <value>
# enabled: true
# requiresSSL: true (should be true for production)
```

**Immediate Fix if Domain Too Restrictive:**
```bash
# In wsadmin:
security = AdminConfig.list('Security')
sso = AdminConfig.list('SingleSignon', security)
AdminConfig.modify(sso, [['domainName', '.example.com']])  # Note leading dot
AdminConfig.save()

# Restart required
```

---

## Priority 9: Review Application-Specific DASH Servlet

### Hypothesis
The DASH role-fetching servlet itself has bugs or mishandles expired tokens.

### Manual Verification Steps

#### Step 9.1: Identify the Servlet
```bash
# Locate DASH application WAR/EAR:
cd $WAS_HOME/profiles/<profile>/installedApps/<cell>

# Find DASH application:
find . -name "*dash*.ear" -o -name "*dash*.war"

# Extract and review web.xml:
unzip -p <dash-app>.ear <dash-app>.war WEB-INF/web.xml | grep -A 10 "servlet-name.*role"
```

#### Step 9.2: Review Servlet Source Code (If Available)
```java
// Look for code like:
HttpServletRequest request = ...;
Cookie[] cookies = request.getCookies();
// Check: Does servlet properly handle missing/expired LTPA token?

// Anti-pattern:
String ltpa = findLTPACookie(cookies);
Subject subject = validateLTPAToken(ltpa);  // ← What if validation fails?
return getUserRoles(subject);  // ← NullPointerException if subject is null?

// Better pattern:
try {
    Subject subject = validateLTPAToken(ltpa);
    return getUserRoles(subject);
} catch (TokenExpiredException e) {
    response.setStatus(401);
    return error("Token expired");
}
```

#### Step 9.3: Check Servlet Logs for Exceptions
```bash
cd $WAS_HOME/profiles/<profile>/logs/server1

# Search for exceptions in role-fetching servlet:
grep -B 5 -A 10 "RoleFetchServlet\|/tce/role" SystemOut.log | grep -i exception

# Common exceptions:
# - NullPointerException (poor error handling)
# - IllegalStateException (session already invalidated)
# - WebSecurityException (LTPA validation failed)
```

---

## Priority 10: Garbage Collection Analysis

### Hypothesis
Long GC pauses coincide with TCE failures, causing timeouts.

### Manual Verification Steps

#### Step 10.1: Enable GC Logging (If Not Already)
```bash
# Check if GC logging is enabled:
ps aux | grep java | grep server1 | grep -o "verbose:gc"

# If not enabled, add to JVM args:
# Navigate to console: Servers → Server Types → WebSphere application servers
# → server1 → Process definition → Java Virtual Machine
# Generic JVM arguments: -verbose:gc -Xverbosegclog:$WAS_HOME/profiles/<profile>/logs/server1/verbosegc.log

# Restart required
```

#### Step 10.2: Analyze Existing GC Logs
```bash
cd $WAS_HOME/profiles/<profile>/logs/server1

# If using native_stdout.log:
grep "<gc " native_stdout.log | grep "type=\"global\""

# Extract GC pause times:
grep "<gc " native_stdout.log | grep -o "totalTime=\"[0-9]*\"" | cut -d'"' -f2

# Calculate max pause:
grep "<gc " native_stdout.log | grep -o "totalTime=\"[0-9]*\"" | cut -d'"' -f2 | sort -n | tail -1
```

#### Step 10.3: Correlate GC Pauses with Failure Times
```bash
# Example: TCE failure at 2025-11-06 14:32:15
# Search GC logs for events around that time:

grep "2025-11-06T14:3[0-2]" native_stdout.log | grep "<gc "

# If you find GC pause > 3000ms (3 seconds) within ±1 minute of failure:
#   → HIGH PROBABILITY ROOT CAUSE
```

**GC Pause Thresholds:**
- < 100ms: Normal
- 100-1000ms: Acceptable
- 1000-3000ms: Concerning (may cause slowness)
- > 3000ms: **Critical** (will cause timeouts)

**Immediate Mitigation:**
```bash
# Tune GC settings (requires JVM restart):
# Add to Generic JVM arguments:
-Xgcpolicy:gencon         # Generational concurrent GC (recommended)
-Xmx4096m -Xms4096m       # Increase heap if memory available
-Xmn1024m                 # Increase nursery size (25% of heap)
```

---

## Diagnostic Workflow Diagram

```
START
  │
  ├─► [P1] Check LTPA vs Session Timeout
  │     ├─► Mismatch found? → FIX & TEST
  │     └─► OK → Continue
  │
  ├─► [P2] Check Clock Skew
  │     ├─► Skew > 5 sec? → FIX & TEST
  │     └─► OK → Continue
  │
  ├─► [P3] Enable Security Traces
  │     └─► Capture for 30 min → Analyze
  │
  ├─► [P4] Review FFDC Logs
  │     ├─► LTPA errors found? → Investigate cause
  │     └─► None → Continue
  │
  ├─► [P5] Check LTPA Key Regeneration
  │     ├─► Recent regen? → Schedule change
  │     └─► OK → Continue
  │
  ├─► [P6] Check Thread Pool
  │     ├─► Exhaustion detected? → Increase size
  │     └─► OK → Continue
  │
  ├─► [P7] Validate SSL/Certs
  │     ├─► Issues found? → Import certs
  │     └─► OK → Continue
  │
  ├─► [P8] Check Cookie Domain
  │     ├─► Too restrictive? → Broaden domain
  │     └─► OK → Continue
  │
  ├─► [P9] Review Servlet Code
  │     └─► Identify error handling gaps
  │
  └─► [P10] Analyze GC Pauses
        ├─► Long pauses? → Tune GC
        └─► OK → Escalate to automated tool
```

---

## Quick Reference: One-Line Diagnostics

```bash
# LTPA timeout:
./wsadmin.sh -c "print AdminConfig.show(AdminConfig.list('LTPA'))" | grep timeout

# Session timeout:
./wsadmin.sh -c "sm = AdminConfig.list('SessionManager'); print AdminConfig.showAttribute(sm, 'sessionTimeout')"

# Clock skew:
date -u && oc exec <pod> -- date -u

# Recent FFDC:
find $WAS_HOME/profiles/*/logs/ffdc -name "*.txt" -mtime -1

# Thread pool size:
./wsadmin.sh -c "print AdminControl.getAttribute(AdminControl.queryNames('type=ThreadPoolStats,name=WebContainer,*', None), 'activeCount')"

# Certificate expiry:
keytool -list -v -keystore trust.p12 -storepass WebAS | grep "Valid until" | sort

# GC max pause:
grep -o "totalTime=\"[0-9]*\"" native_stdout.log | cut -d'"' -f2 | sort -n | tail -1

# Last LTPA key mod:
stat $WAS_HOME/profiles/*/config/cells/*/security/ltpa.keys
```

---

## Next Steps

1. **Execute Priority 1-3** immediately (highest probability, quickest to verify)
2. **Enable traces** and capture during next TCE failure window
3. **Document findings** in a timestamped log for correlation
4. **Deploy automated tool** for continuous monitoring

Once manual diagnostics narrow down the issue, the automated tool will provide:
- Continuous monitoring
- Stress testing to reproduce on demand
- Automated correlation analysis
- Comprehensive reporting

Refer to **TRACE_CONFIGURATION.md** for detailed trace string explanations.
