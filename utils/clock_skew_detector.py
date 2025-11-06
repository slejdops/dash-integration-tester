#!/usr/bin/env python3
"""
Clock Skew Detection Utility for LTPA Diagnostics
Detects time synchronization issues between DASH server and OpenShift
"""

import subprocess
import re
import time
import sys
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List
import base64
import json


class ClockSkewDetector:
    """Detect clock skew between servers"""

    def __init__(self):
        self.measurements = []

    def get_local_time(self) -> datetime:
        """Get current local server time in UTC"""
        return datetime.utcnow()

    def get_remote_time_via_ssh(self, hostname: str, username: str = None) -> Optional[datetime]:
        """Get remote server time via SSH"""
        try:
            ssh_cmd = ['ssh']
            if username:
                ssh_cmd.append(f'{username}@{hostname}')
            else:
                ssh_cmd.append(hostname)

            ssh_cmd.extend(['date', '-u', '+%Y-%m-%d %H:%M:%S'])

            result = subprocess.run(
                ssh_cmd,
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode == 0:
                time_str = result.stdout.strip()
                return datetime.strptime(time_str, '%Y-%m-%d %H:%M:%S')
            else:
                print(f"[ERROR] SSH command failed: {result.stderr}")
                return None

        except subprocess.TimeoutExpired:
            print(f"[ERROR] SSH command timed out")
            return None
        except Exception as e:
            print(f"[ERROR] Failed to get remote time via SSH: {e}")
            return None

    def get_openshift_pod_time(self, namespace: str, pod_name: str) -> Optional[datetime]:
        """Get time from OpenShift pod via oc exec"""
        try:
            cmd = [
                'oc', 'exec',
                '-n', namespace,
                pod_name,
                '--',
                'date', '-u', '+%Y-%m-%d %H:%M:%S'
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode == 0:
                time_str = result.stdout.strip()
                return datetime.strptime(time_str, '%Y-%m-%d %H:%M:%S')
            else:
                print(f"[ERROR] oc exec failed: {result.stderr}")
                return None

        except subprocess.TimeoutExpired:
            print(f"[ERROR] oc exec timed out")
            return None
        except FileNotFoundError:
            print(f"[ERROR] 'oc' command not found. Is OpenShift CLI installed?")
            return None
        except Exception as e:
            print(f"[ERROR] Failed to get OpenShift pod time: {e}")
            return None

    def get_ntp_status_local(self) -> Dict[str, Any]:
        """Get NTP synchronization status on local server"""
        status = {
            'synchronized': False,
            'stratum': None,
            'reference': None,
            'offset_ms': None,
            'method': None
        }

        # Try timedatectl (systemd-based systems)
        try:
            result = subprocess.run(
                ['timedatectl', 'status'],
                capture_output=True,
                text=True,
                timeout=5
            )

            if result.returncode == 0:
                status['method'] = 'timedatectl'

                # Parse output
                for line in result.stdout.split('\n'):
                    if 'System clock synchronized' in line:
                        status['synchronized'] = 'yes' in line.lower()
                    elif 'NTP service' in line:
                        status['ntp_service'] = 'active' in line.lower()

                return status

        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        # Try ntpq (traditional NTP)
        try:
            result = subprocess.run(
                ['ntpq', '-p'],
                capture_output=True,
                text=True,
                timeout=5
            )

            if result.returncode == 0:
                status['method'] = 'ntpq'

                # Look for asterisk (*) indicating current sync source
                for line in result.stdout.split('\n'):
                    if line.startswith('*'):
                        status['synchronized'] = True
                        parts = line.split()
                        if len(parts) >= 2:
                            status['reference'] = parts[0][1:]  # Remove asterisk

                return status

        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        # Try chronyc (chrony-based systems)
        try:
            result = subprocess.run(
                ['chronyc', 'tracking'],
                capture_output=True,
                text=True,
                timeout=5
            )

            if result.returncode == 0:
                status['method'] = 'chronyc'

                for line in result.stdout.split('\n'):
                    if 'Reference ID' in line:
                        status['synchronized'] = True
                        parts = line.split(':')
                        if len(parts) == 2:
                            status['reference'] = parts[1].strip()
                    elif 'System time' in line:
                        # Extract offset in seconds
                        match = re.search(r'([-\d.]+)\s+seconds', line)
                        if match:
                            status['offset_ms'] = float(match.group(1)) * 1000

                return status

        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        status['method'] = 'unavailable'
        return status

    def calculate_skew(self, local_time: datetime, remote_time: datetime) -> float:
        """Calculate clock skew in seconds (positive = remote is ahead)"""
        skew = (remote_time - local_time).total_seconds()
        return skew

    def detect_skew_between_servers(self, remote_host: str, remote_user: str = None,
                                    openshift_mode: bool = False,
                                    namespace: str = None, pod_name: str = None) -> Dict[str, Any]:
        """Detect clock skew between local and remote server"""
        print(f"[INFO] Measuring clock skew...")

        # Get local time
        local_time = self.get_local_time()
        print(f"[INFO] Local time (UTC): {local_time}")

        # Get remote time
        if openshift_mode:
            if not namespace or not pod_name:
                print("[ERROR] OpenShift mode requires namespace and pod_name")
                return None

            remote_time = self.get_openshift_pod_time(namespace, pod_name)
            remote_label = f"OpenShift pod {namespace}/{pod_name}"
        else:
            remote_time = self.get_remote_time_via_ssh(remote_host, remote_user)
            remote_label = f"Remote host {remote_host}"

        if not remote_time:
            print(f"[ERROR] Could not retrieve remote time from {remote_label}")
            return None

        print(f"[INFO] {remote_label} time (UTC): {remote_time}")

        # Calculate skew
        # Note: We re-measure local time to account for network latency
        local_time_after = self.get_local_time()
        avg_local_time = local_time + (local_time_after - local_time) / 2

        skew_seconds = self.calculate_skew(avg_local_time, remote_time)

        result = {
            'local_time': str(local_time),
            'remote_time': str(remote_time),
            'remote_label': remote_label,
            'skew_seconds': skew_seconds,
            'skew_milliseconds': skew_seconds * 1000,
            'severity': self.assess_skew_severity(skew_seconds)
        }

        self.measurements.append(result)

        return result

    def assess_skew_severity(self, skew_seconds: float) -> str:
        """Assess severity of clock skew"""
        abs_skew = abs(skew_seconds)

        if abs_skew < 1:
            return 'OK'
        elif abs_skew < 5:
            return 'WARNING'
        elif abs_skew < 30:
            return 'CONCERNING'
        else:
            return 'CRITICAL'

    def decode_ltpa_token_time(self, ltpa_token: str) -> Dict[str, Any]:
        """
        Attempt to extract timestamp information from LTPA token
        Note: LTPA tokens are encrypted, but we can try to decode the wrapper
        This is a best-effort approach and may not work for all LTPA token formats
        """
        try:
            # LTPA tokens are base64-encoded, but encrypted
            # We can't decrypt without the key, but we might find timestamp metadata

            # Try to decode as base64
            decoded = base64.b64decode(ltpa_token + '==')  # Add padding if needed

            # Look for timestamp-like patterns (Unix epoch timestamps)
            # This is speculative and may not work
            timestamp_pattern = re.compile(b'\x00\x00\x00\x00([\x00-\xff]{8})')

            print("[WARN] LTPA token decryption not implemented")
            print("[INFO] LTPA tokens are encrypted and require LTPA keys to decrypt")
            print("[INFO] Use WebSphere trace logs to extract token timestamps instead")

            return {
                'success': False,
                'message': 'LTPA token decryption requires LTPA private key'
            }

        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }

    def continuous_monitoring(self, remote_host: str, duration_minutes: int = 60,
                             interval_seconds: int = 60, **kwargs):
        """Continuously monitor clock skew over time"""
        print(f"[INFO] Starting continuous monitoring for {duration_minutes} minutes")
        print(f"[INFO] Sampling every {interval_seconds} seconds")

        end_time = datetime.now() + timedelta(minutes=duration_minutes)
        sample_count = 0

        while datetime.now() < end_time:
            sample_count += 1
            print(f"\n[INFO] Sample {sample_count}")

            result = self.detect_skew_between_servers(remote_host, **kwargs)

            if result:
                skew = result['skew_seconds']
                severity = result['severity']

                print(f"[{severity}] Clock skew: {skew:+.3f} seconds ({skew*1000:+.1f} ms)")

                if severity in ['CONCERNING', 'CRITICAL']:
                    print(f"[ALERT] Significant clock skew detected!")

            time.sleep(interval_seconds)

        # Print summary
        self.print_monitoring_summary()

    def print_monitoring_summary(self):
        """Print summary of continuous monitoring"""
        if not self.measurements:
            print("[INFO] No measurements recorded")
            return

        skews = [m['skew_seconds'] for m in self.measurements]

        print("\n" + "=" * 70)
        print("CONTINUOUS MONITORING SUMMARY")
        print("=" * 70)
        print(f"Total samples: {len(skews)}")
        print(f"Average skew: {sum(skews)/len(skews):+.3f} seconds")
        print(f"Min skew:     {min(skews):+.3f} seconds")
        print(f"Max skew:     {max(skews):+.3f} seconds")
        print(f"Std dev:      {(sum((s - sum(skews)/len(skews))**2 for s in skews) / len(skews))**0.5:.3f} seconds")

        critical_count = sum(1 for m in self.measurements if m['severity'] == 'CRITICAL')
        concerning_count = sum(1 for m in self.measurements if m['severity'] == 'CONCERNING')

        if critical_count > 0:
            print(f"\n[CRITICAL] {critical_count} samples had critical clock skew (>30 seconds)")
        if concerning_count > 0:
            print(f"[WARN] {concerning_count} samples had concerning clock skew (5-30 seconds)")

        print("=" * 70)

    def export_measurements(self, output_file: str):
        """Export measurements to JSON file"""
        data = {
            'monitoring_start': str(self.measurements[0]['local_time']) if self.measurements else None,
            'monitoring_end': str(self.measurements[-1]['local_time']) if self.measurements else None,
            'total_samples': len(self.measurements),
            'measurements': self.measurements
        }

        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2)

        print(f"[SUCCESS] Measurements exported to {output_file}")


def main():
    """Command-line interface for clock skew detector"""
    import argparse

    parser = argparse.ArgumentParser(description='Detect clock skew between servers')
    parser.add_argument('--remote-host', help='Remote hostname for SSH')
    parser.add_argument('--remote-user', help='SSH username (optional)')
    parser.add_argument('--openshift', action='store_true', help='Use OpenShift pod instead of SSH')
    parser.add_argument('--namespace', help='OpenShift namespace')
    parser.add_argument('--pod', help='OpenShift pod name')
    parser.add_argument('--continuous', action='store_true', help='Continuous monitoring mode')
    parser.add_argument('--duration', type=int, default=60, help='Duration in minutes (default: 60)')
    parser.add_argument('--interval', type=int, default=60, help='Sampling interval in seconds (default: 60)')
    parser.add_argument('--ntp-status', action='store_true', help='Show local NTP status only')
    parser.add_argument('--output', help='Export measurements to JSON file')

    args = parser.parse_args()

    detector = ClockSkewDetector()

    # Show NTP status only
    if args.ntp_status:
        print("[INFO] Checking local NTP synchronization status...")
        status = detector.get_ntp_status_local()

        print(f"\nNTP Status:")
        print(f"  Method: {status['method']}")
        print(f"  Synchronized: {status['synchronized']}")
        if status.get('reference'):
            print(f"  Reference: {status['reference']}")
        if status.get('offset_ms'):
            print(f"  Offset: {status['offset_ms']:.2f} ms")

        return 0

    # Validate arguments
    if not args.openshift and not args.remote_host:
        print("[ERROR] Must specify either --remote-host or --openshift mode")
        return 1

    if args.openshift and (not args.namespace or not args.pod):
        print("[ERROR] OpenShift mode requires --namespace and --pod")
        return 1

    # Build kwargs
    kwargs = {
        'openshift_mode': args.openshift
    }

    if args.openshift:
        kwargs['namespace'] = args.namespace
        kwargs['pod_name'] = args.pod
    else:
        kwargs['remote_user'] = args.remote_user

    # Run detection
    if args.continuous:
        detector.continuous_monitoring(
            args.remote_host or 'openshift',
            duration_minutes=args.duration,
            interval_seconds=args.interval,
            **kwargs
        )
    else:
        result = detector.detect_skew_between_servers(args.remote_host or 'openshift', **kwargs)

        if result:
            print(f"\n{'='*70}")
            print("CLOCK SKEW DETECTION RESULT")
            print('='*70)
            print(f"Local time:        {result['local_time']}")
            print(f"Remote time:       {result['remote_time']}")
            print(f"Remote location:   {result['remote_label']}")
            print(f"Clock skew:        {result['skew_seconds']:+.3f} seconds ({result['skew_milliseconds']:+.1f} ms)")
            print(f"Severity:          {result['severity']}")

            if result['severity'] == 'CRITICAL':
                print("\n[CRITICAL] Clock skew exceeds 30 seconds!")
                print("This WILL cause LTPA token validation failures.")
                print("Action required: Synchronize clocks via NTP immediately.")
            elif result['severity'] == 'CONCERNING':
                print("\n[WARN] Clock skew is concerning (5-30 seconds)")
                print("This may cause intermittent LTPA token validation failures.")
                print("Recommended: Verify NTP configuration and synchronize clocks.")
            elif result['severity'] == 'WARNING':
                print("\n[WARN] Minor clock skew detected (1-5 seconds)")
                print("Monitor for potential issues. Consider improving NTP sync.")
            else:
                print("\n[OK] Clock skew is within acceptable range.")

            print('='*70)

    # Export measurements if requested
    if args.output and detector.measurements:
        detector.export_measurements(args.output)

    return 0


if __name__ == '__main__':
    sys.exit(main())
