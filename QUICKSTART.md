# Quick Start Guide - DASH LTPA Diagnostics

## 5-Minute Setup

```bash
# 1. Clone and setup
cd /opt/diagnostics
git clone <repo> dash-ltpa-diagnostics
cd dash-ltpa-diagnostics
./bin/setup.sh

# 2. Configure (edit these 3 values minimum)
vi config/diagnostics.conf
# Set: WAS_HOME, WAS_LOG_DIR, DASH_URL

# 3. Run quick diagnostic
./bin/run_diagnostics.sh --mode quick

# 4. View results
ls -lh output/latest/
```

## Common Scenarios

### Scenario 1: TCE Just Reported a Failure

```bash
# Capture failure time and run investigation
./bin/run_diagnostics.sh --mode investigate \
  --failure-time "2025-11-06 14:32:15"

# Check correlation report
cat output/*/correlation_report.txt
```

### Scenario 2: Need to Reproduce Intermittent Issue

```bash
# Edit config to add LTPA token
vi config/diagnostics.conf
# Set: LTPA_TOKEN="AAECAzQ3..." (get from browser)

# Run stress test (5 min, 20 req/sec)
STRESS_DURATION=300 STRESS_RATE=20 \
  ./bin/run_diagnostics.sh --mode stress

# Review failures
cat output/*/stress_test_results.json | grep -A 5 "failure_rate"
```

### Scenario 3: Suspect Clock Skew

```bash
# Quick check with OpenShift pod
python3 utils/clock_skew_detector.py \
  --openshift \
  --namespace tce-prod \
  --pod tce-app-xxxxx

# If skew > 5 seconds, synchronize NTP
```

### Scenario 4: Weekly Health Check

```bash
# Run full analysis
./bin/run_diagnostics.sh --mode full

# Archive results
tar czf dash_health_$(date +%Y%m%d).tar.gz output/latest/
```

## What to Look For

### In config_report.html
- ❌ "Session Timeout Exceeds LTPA Timeout" → **FIX IMMEDIATELY**
- ❌ "SSO Domain Not Configured" → **CRITICAL**
- ⚠️ "Thread Pool Maximum Too Small" → Increase if load is high

### In correlation_report.txt
- "PROBABLE ROOT CAUSE: LTPA_EXPIRED" → Check LTPA timeout & clock skew
- "PROBABLE ROOT CAUSE: GC_PAUSE" → Tune JVM
- "PROBABLE ROOT CAUSE: THREAD_POOL_EXHAUSTED" → Increase threads

### In stress test results
- Failure rate > 1% → Issue reproduced, check failure timestamps
- P99 > 1000ms → Performance issue

## Emergency Commands

```bash
# Get LTPA timeout NOW
$WAS_HOME/bin/wsadmin.sh -c "
ltpa = AdminConfig.list('LTPA')
print AdminConfig.showAttribute(ltpa, 'timeout')
"

# Get session timeout NOW
$WAS_HOME/bin/wsadmin.sh -c "
sm = AdminConfig.list('SessionManager')
print AdminConfig.showAttribute(sm, 'sessionTimeout')
"

# Check for recent LTPA errors in last hour
grep -i "LTPA\|SECJ" $WAS_LOG_DIR/SystemOut.log | tail -50

# Check clock skew immediately
date -u && ssh openshift-node date -u
```

## Next Steps

After running diagnostics:

1. **Read the generated `FINAL_REPORT.txt`** in output directory
2. **Follow recommendations** in config_report.html
3. **If critical issues found**: See `docs/DIAGNOSTIC_STRATEGY.md` for immediate fixes
4. **If intermittent issues**: Run stress test to reproduce

## Need Help?

- **Immediate troubleshooting**: `docs/DIAGNOSTIC_STRATEGY.md`
- **Trace configuration**: `docs/TRACE_CONFIGURATION.md`
- **Architecture details**: `docs/ARCHITECTURE.md`
- **Full manual**: `README.md`
