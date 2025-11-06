#!/usr/bin/env python3
"""
Event Correlation Engine for LTPA Diagnostics
Correlates log events with reported failure times and identifies patterns
"""

import json
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from pathlib import Path


class CorrelationEngine:
    """Correlates security events, GC pauses, and failures"""

    def __init__(self, log_analysis_data: Dict[str, Any]):
        self.data = log_analysis_data
        self.correlations = []

    def correlate_with_failure(self, failure_time: datetime, window_minutes: int = 5):
        """Correlate log events with a specific failure timestamp"""
        print(f"[INFO] Correlating events around failure time: {failure_time}")

        start_time = failure_time - timedelta(minutes=window_minutes)
        end_time = failure_time + timedelta(minutes=window_minutes)

        correlated_events = []

        # Correlate log entries
        for entry in self.data.get('entries', []):
            if not entry.get('timestamp'):
                continue

            try:
                entry_time = datetime.fromisoformat(entry['timestamp'])
                time_diff = (entry_time - failure_time).total_seconds()

                if start_time <= entry_time <= end_time:
                    confidence = self._calculate_confidence(entry, abs(time_diff))

                    correlated_events.append({
                        'type': 'log_entry',
                        'timestamp': entry['timestamp'],
                        'time_diff_seconds': time_diff,
                        'severity': entry['severity'],
                        'category': entry['matched_patterns'][0]['category'] if entry['matched_patterns'] else 'UNKNOWN',
                        'description': entry['line'][:200],
                        'confidence': confidence,
                        'source_file': entry['file'],
                        'line_number': entry['line_number'],
                        'matched_patterns': entry['matched_patterns']
                    })

            except (ValueError, KeyError) as e:
                continue

        # Correlate GC events
        for gc_event in self.data.get('gc_events', []):
            if not gc_event.get('timestamp'):
                continue

            try:
                gc_time = datetime.fromisoformat(gc_event['timestamp'])
                time_diff = (gc_time - failure_time).total_seconds()

                if start_time <= gc_time <= end_time:
                    # GC pauses > 3 seconds are highly suspicious
                    duration_ms = gc_event['duration_ms']
                    confidence = 'HIGH' if duration_ms > 3000 else 'MEDIUM'

                    correlated_events.append({
                        'type': 'gc_event',
                        'timestamp': gc_event['timestamp'],
                        'time_diff_seconds': time_diff,
                        'duration_ms': duration_ms,
                        'confidence': confidence,
                        'description': f"Garbage collection pause: {duration_ms}ms"
                    })

            except (ValueError, KeyError):
                continue

        # Sort by time proximity to failure
        correlated_events.sort(key=lambda x: abs(x['time_diff_seconds']))

        # Analyze correlation
        analysis = self._analyze_correlation(correlated_events, failure_time)

        return {
            'failure_time': failure_time.isoformat(),
            'window_minutes': window_minutes,
            'total_correlated_events': len(correlated_events),
            'events': correlated_events,
            'analysis': analysis
        }

    def _calculate_confidence(self, entry: Dict[str, Any], time_diff_seconds: float) -> str:
        """Calculate confidence level of correlation"""
        # Critical errors within 10 seconds = HIGH confidence
        if entry['severity'] == 'ERROR' and time_diff_seconds < 10:
            return 'HIGH'

        # LTPA/SSO errors within 30 seconds = HIGH confidence
        for pattern in entry.get('matched_patterns', []):
            if pattern['category'].startswith('LTPA_') or pattern['category'].startswith('SSO_'):
                if time_diff_seconds < 30:
                    return 'HIGH'
                elif time_diff_seconds < 120:
                    return 'MEDIUM'

        # Thread pool exhaustion = MEDIUM confidence
        if any(p['category'].startswith('THREAD_POOL') for p in entry.get('matched_patterns', [])):
            return 'MEDIUM'

        # Other errors within 60 seconds = MEDIUM confidence
        if entry['severity'] == 'ERROR' and time_diff_seconds < 60:
            return 'MEDIUM'

        return 'LOW'

    def _analyze_correlation(self, events: List[Dict[str, Any]], failure_time: datetime) -> Dict[str, Any]:
        """Analyze correlated events to identify probable root cause"""
        analysis = {
            'probable_root_cause': None,
            'contributing_factors': [],
            'recommendations': []
        }

        # Count events by type
        ltpa_errors = [e for e in events if e.get('category', '').startswith('LTPA_')]
        sso_errors = [e for e in events if e.get('category', '').startswith('SSO_')]
        gc_events = [e for e in events if e['type'] == 'gc_event']
        thread_errors = [e for e in events if e.get('category', '').startswith('THREAD_POOL')]
        session_errors = [e for e in events if e.get('category', '').startswith('SESSION_')]

        # Determine root cause based on event patterns

        # 1. Long GC pause immediately before failure
        critical_gc = [g for g in gc_events if g['duration_ms'] > 3000 and abs(g['time_diff_seconds']) < 5]
        if critical_gc:
            analysis['probable_root_cause'] = {
                'category': 'GC_PAUSE',
                'confidence': 'HIGH',
                'description': f"Long garbage collection pause ({critical_gc[0]['duration_ms']}ms) occurred {abs(critical_gc[0]['time_diff_seconds']):.1f} seconds before failure",
                'remediation': "Tune JVM garbage collection settings. Consider increasing heap size or switching to G1GC."
            }
            analysis['recommendations'].append("Analyze heap usage and GC patterns over time")
            analysis['recommendations'].append("Consider increasing -Xmx and -Xmn settings")

        # 2. LTPA token expiration
        elif any(e.get('category') == 'LTPA_EXPIRED' for e in ltpa_errors):
            analysis['probable_root_cause'] = {
                'category': 'LTPA_EXPIRED',
                'confidence': 'HIGH',
                'description': "LTPA token expired error detected",
                'remediation': "Verify LTPA timeout configuration and check for clock skew between client and server"
            }
            analysis['recommendations'].append("Run clock skew detection utility")
            analysis['recommendations'].append("Verify LTPA timeout is sufficient (recommended: 120 minutes)")
            analysis['recommendations'].append("Check session timeout < LTPA timeout")

        # 3. LTPA signature validation failure
        elif any(e.get('category') == 'LTPA_SIGNATURE_INVALID' for e in ltpa_errors):
            analysis['probable_root_cause'] = {
                'category': 'LTPA_KEY_MISMATCH',
                'confidence': 'HIGH',
                'description': "LTPA signature validation failed - key mismatch likely",
                'remediation': "Verify LTPA keys are synchronized across all servers in SSO domain"
            }
            analysis['recommendations'].append("Check LTPA keys file modification time for recent regeneration")
            analysis['recommendations'].append("Export and compare LTPA keys across all servers")

        # 4. SSO cookie missing
        elif any(e.get('category') == 'SSO_COOKIE_MISSING' for e in sso_errors):
            analysis['probable_root_cause'] = {
                'category': 'COOKIE_DOMAIN_ISSUE',
                'confidence': 'MEDIUM',
                'description': "SSO cookie not present in request",
                'remediation': "Verify SSO domain matches client hostname and cookie is being sent"
            }
            analysis['recommendations'].append("Check SSO domain configuration (should start with '.')")
            analysis['recommendations'].append("Verify OpenShift ingress hostname matches SSO domain")
            analysis['recommendations'].append("Inspect browser/client cookie jar for LTPAToken2")

        # 5. Thread pool exhaustion
        elif thread_errors:
            analysis['probable_root_cause'] = {
                'category': 'THREAD_POOL_EXHAUSTED',
                'confidence': 'MEDIUM',
                'description': "Web container thread pool exhaustion detected",
                'remediation': "Increase thread pool maximum size or investigate hung threads"
            }
            analysis['recommendations'].append("Generate thread dump during failure window")
            analysis['recommendations'].append("Increase Web Container thread pool maximum size")
            analysis['recommendations'].append("Investigate slow database queries or backend services")

        # 6. Session not found
        elif session_errors:
            analysis['probable_root_cause'] = {
                'category': 'SESSION_EXPIRED',
                'confidence': 'MEDIUM',
                'description': "HTTP session not found or expired",
                'remediation': "Verify session timeout configuration and session persistence"
            }
            analysis['recommendations'].append("Check session timeout vs LTPA timeout")
            analysis['recommendations'].append("Verify session persistence is functioning")

        # 7. Generic errors present but no clear root cause
        elif events:
            analysis['probable_root_cause'] = {
                'category': 'UNKNOWN',
                'confidence': 'LOW',
                'description': f"{len(events)} events detected in failure window but no clear root cause pattern",
                'remediation': "Manual investigation required - review all correlated events"
            }
            analysis['recommendations'].append("Enable security traces for more detailed logging")
            analysis['recommendations'].append("Review application-level logs")

        # Identify contributing factors
        if gc_events and not critical_gc:
            analysis['contributing_factors'].append("Multiple GC events detected - may contribute to latency")

        if len(ltpa_errors) > 1:
            analysis['contributing_factors'].append("Multiple LTPA errors suggest systemic authentication issue")

        return analysis

    def generate_report(self, failure_time: datetime, window_minutes: int = 5) -> str:
        """Generate human-readable correlation report"""
        correlation = self.correlate_with_failure(failure_time, window_minutes)

        report = []
        report.append("=" * 70)
        report.append("CORRELATION ANALYSIS REPORT")
        report.append("=" * 70)
        report.append(f"Failure Time: {correlation['failure_time']}")
        report.append(f"Analysis Window: ±{window_minutes} minutes")
        report.append(f"Correlated Events: {correlation['total_correlated_events']}")
        report.append("")

        # Root cause
        analysis = correlation['analysis']
        if analysis['probable_root_cause']:
            rc = analysis['probable_root_cause']
            report.append("PROBABLE ROOT CAUSE:")
            report.append(f"  Category: {rc['category']}")
            report.append(f"  Confidence: {rc['confidence']}")
            report.append(f"  Description: {rc['description']}")
            report.append(f"  Remediation: {rc['remediation']}")
            report.append("")

        # Contributing factors
        if analysis['contributing_factors']:
            report.append("CONTRIBUTING FACTORS:")
            for factor in analysis['contributing_factors']:
                report.append(f"  - {factor}")
            report.append("")

        # Recommendations
        if analysis['recommendations']:
            report.append("RECOMMENDATIONS:")
            for rec in analysis['recommendations']:
                report.append(f"  - {rec}")
            report.append("")

        # Top correlated events
        report.append("TOP CORRELATED EVENTS:")
        report.append("")
        for i, event in enumerate(correlation['events'][:10], 1):
            time_diff = event['time_diff_seconds']
            sign = '+' if time_diff > 0 else ''
            report.append(f"{i}. [{sign}{time_diff:.1f}s] {event['type'].upper()} - {event.get('category', 'N/A')}")
            report.append(f"   Confidence: {event['confidence']}")
            report.append(f"   {event['description'][:100]}")
            report.append("")

        report.append("=" * 70)

        return "\n".join(report)


def main():
    """Command-line interface for correlation engine"""
    import argparse

    parser = argparse.ArgumentParser(description='Correlate log events with failure time')
    parser.add_argument('--log-analysis', required=True, help='Path to log analysis JSON file')
    parser.add_argument('--failure-time', required=True, help='Failure timestamp: YYYY-MM-DD HH:MM:SS')
    parser.add_argument('--window', type=int, default=5, help='Time window in minutes (default: 5)')
    parser.add_argument('--output', help='Output report file (optional)')

    args = parser.parse_args()

    # Load log analysis data
    with open(args.log_analysis, 'r') as f:
        log_data = json.load(f)

    # Parse failure time
    try:
        failure_time = datetime.strptime(args.failure_time, "%Y-%m-%d %H:%M:%S")
    except ValueError as e:
        print(f"[ERROR] Invalid failure time format: {e}")
        return 1

    # Run correlation
    engine = CorrelationEngine(log_data)
    report = engine.generate_report(failure_time, args.window)

    # Print to console
    print(report)

    # Save to file if requested
    if args.output:
        with open(args.output, 'w') as f:
            f.write(report)
        print(f"\n[SUCCESS] Report saved to {args.output}")

    return 0


if __name__ == '__main__':
    import sys
    sys.exit(main())
