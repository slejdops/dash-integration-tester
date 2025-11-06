#!/usr/bin/env python3
"""
LTPA Integration Stress Tester - TCE Simulator
Simulates OpenShift TCE application calling DASH role-fetching servlet with LTPA token
"""

import requests
import time
import json
import sys
import threading
import statistics
from datetime import datetime
from typing import Dict, Any, List, Optional
from urllib3.exceptions import InsecureRequestWarning

# Suppress SSL warnings (for testing only - DO NOT do this in production)
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)


class LTPAStressTester:
    """Stress tests DASH servlet with LTPA token authentication"""

    def __init__(self, config: Dict[str, Any]):
        self.dash_url = config['dash_url']
        self.ltpa_token = config.get('ltpa_token')
        self.username = config.get('username')
        self.password = config.get('password')
        self.verify_ssl = config.get('verify_ssl', True)
        self.timeout = config.get('timeout', 10)

        # Metrics
        self.total_requests = 0
        self.successful_requests = 0
        self.failed_requests = 0
        self.response_times = []
        self.failure_details = []
        self.lock = threading.Lock()

    def acquire_ltpa_token(self) -> Optional[str]:
        """Acquire LTPA token by logging into DASH"""
        if self.ltpa_token:
            print(f"[INFO] Using provided LTPA token: {self.ltpa_token[:10]}...")
            return self.ltpa_token

        if not self.username or not self.password:
            print("[ERROR] No LTPA token provided and no username/password for login")
            return None

        print(f"[INFO] Attempting to acquire LTPA token via login for user: {self.username}")

        # Try to login and extract LTPA token from cookies
        # This is DASH-specific and may need adjustment
        login_url = f"{self.dash_url}/ibm/console/login.do"

        try:
            session = requests.Session()
            response = session.post(
                login_url,
                data={
                    'username': self.username,
                    'password': self.password,
                    'action': 'Log in'
                },
                verify=self.verify_ssl,
                timeout=self.timeout
            )

            # Extract LTPAToken2 from cookies
            ltpa_cookie = session.cookies.get('LTPAToken2')
            if ltpa_cookie:
                print(f"[SUCCESS] Acquired LTPA token: {ltpa_cookie[:10]}...")
                self.ltpa_token = ltpa_cookie
                return ltpa_cookie
            else:
                print("[ERROR] Login succeeded but no LTPAToken2 cookie found")
                print(f"Available cookies: {list(session.cookies.keys())}")
                return None

        except requests.exceptions.RequestException as e:
            print(f"[ERROR] Failed to acquire LTPA token: {e}")
            return None

    def call_role_servlet(self) -> Dict[str, Any]:
        """Call DASH role-fetching servlet with LTPA token"""
        start_time = time.time()

        result = {
            'timestamp': datetime.now().isoformat(),
            'success': False,
            'status_code': None,
            'response_time_ms': 0,
            'error': None,
            'response_body': None
        }

        # Prepare cookies with LTPA token
        cookies = {
            'LTPAToken2': self.ltpa_token
        }

        try:
            response = requests.get(
                self.dash_url,
                cookies=cookies,
                verify=self.verify_ssl,
                timeout=self.timeout
            )

            response_time = (time.time() - start_time) * 1000  # Convert to ms
            result['response_time_ms'] = response_time
            result['status_code'] = response.status_code

            if response.status_code == 200:
                result['success'] = True
                result['response_body'] = response.text[:500]  # Limit body size

                # Try to parse JSON response (if role servlet returns JSON)
                try:
                    json_data = response.json()
                    result['roles'] = json_data.get('roles', [])
                except json.JSONDecodeError:
                    pass

            else:
                result['error'] = f"HTTP {response.status_code}: {response.reason}"
                result['response_body'] = response.text[:500]

        except requests.exceptions.Timeout:
            result['error'] = "Request timeout"
            result['response_time_ms'] = self.timeout * 1000

        except requests.exceptions.SSLError as e:
            result['error'] = f"SSL error: {str(e)[:200]}"
            result['response_time_ms'] = (time.time() - start_time) * 1000

        except requests.exceptions.ConnectionError as e:
            result['error'] = f"Connection error: {str(e)[:200]}"
            result['response_time_ms'] = (time.time() - start_time) * 1000

        except Exception as e:
            result['error'] = f"Unexpected error: {str(e)[:200]}"
            result['response_time_ms'] = (time.time() - start_time) * 1000

        return result

    def record_result(self, result: Dict[str, Any]):
        """Record test result in metrics"""
        with self.lock:
            self.total_requests += 1

            if result['success']:
                self.successful_requests += 1
                self.response_times.append(result['response_time_ms'])
            else:
                self.failed_requests += 1
                self.failure_details.append(result)

    def run_single_test(self) -> Dict[str, Any]:
        """Run a single test request"""
        result = self.call_role_servlet()
        self.record_result(result)
        return result

    def run_steady_load(self, duration_seconds: int, requests_per_second: float):
        """Run steady load test"""
        print(f"[INFO] Running steady load: {requests_per_second} req/sec for {duration_seconds} seconds")

        start_time = time.time()
        interval = 1.0 / requests_per_second

        while (time.time() - start_time) < duration_seconds:
            request_start = time.time()

            result = self.run_single_test()

            # Print status every 100 requests
            if self.total_requests % 100 == 0:
                success_rate = (self.successful_requests / self.total_requests) * 100
                print(f"[PROGRESS] Requests: {self.total_requests}, Success: {success_rate:.1f}%")

            # Sleep to maintain requested rate
            elapsed = time.time() - request_start
            sleep_time = max(0, interval - elapsed)
            time.sleep(sleep_time)

    def run_burst_test(self, num_requests: int, concurrent_threads: int):
        """Run burst test with concurrent requests"""
        print(f"[INFO] Running burst test: {num_requests} requests with {concurrent_threads} threads")

        requests_per_thread = num_requests // concurrent_threads
        threads = []

        def worker(count: int):
            for _ in range(count):
                self.run_single_test()

        for _ in range(concurrent_threads):
            t = threading.Thread(target=worker, args=(requests_per_thread,))
            t.start()
            threads.append(t)

        for t in threads:
            t.join()

    def run_soak_test(self, duration_hours: int, requests_per_minute: float = 1):
        """Run long-duration soak test"""
        duration_seconds = duration_hours * 3600
        requests_per_second = requests_per_minute / 60
        self.run_steady_load(duration_seconds, requests_per_second)

    def get_statistics(self) -> Dict[str, Any]:
        """Get test statistics"""
        stats = {
            'total_requests': self.total_requests,
            'successful_requests': self.successful_requests,
            'failed_requests': self.failed_requests,
            'failure_rate': 0,
            'avg_response_time_ms': 0,
            'min_response_time_ms': 0,
            'max_response_time_ms': 0,
            'p50_response_time_ms': 0,
            'p95_response_time_ms': 0,
            'p99_response_time_ms': 0
        }

        if self.total_requests > 0:
            stats['failure_rate'] = (self.failed_requests / self.total_requests) * 100

        if self.response_times:
            stats['avg_response_time_ms'] = statistics.mean(self.response_times)
            stats['min_response_time_ms'] = min(self.response_times)
            stats['max_response_time_ms'] = max(self.response_times)
            stats['p50_response_time_ms'] = statistics.median(self.response_times)

            sorted_times = sorted(self.response_times)
            p95_index = int(len(sorted_times) * 0.95)
            p99_index = int(len(sorted_times) * 0.99)
            stats['p95_response_time_ms'] = sorted_times[p95_index] if p95_index < len(sorted_times) else 0
            stats['p99_response_time_ms'] = sorted_times[p99_index] if p99_index < len(sorted_times) else 0

        return stats

    def print_summary(self):
        """Print test summary"""
        stats = self.get_statistics()

        print("\n" + "=" * 70)
        print("STRESS TEST SUMMARY")
        print("=" * 70)
        print(f"Total Requests:      {stats['total_requests']}")
        print(f"Successful:          {stats['successful_requests']}")
        print(f"Failed:              {stats['failed_requests']}")
        print(f"Failure Rate:        {stats['failure_rate']:.2f}%")
        print("")
        print("Response Times (ms):")
        print(f"  Average:           {stats['avg_response_time_ms']:.2f}")
        print(f"  Min:               {stats['min_response_time_ms']:.2f}")
        print(f"  Max:               {stats['max_response_time_ms']:.2f}")
        print(f"  Median (P50):      {stats['p50_response_time_ms']:.2f}")
        print(f"  P95:               {stats['p95_response_time_ms']:.2f}")
        print(f"  P99:               {stats['p99_response_time_ms']:.2f}")

        if self.failure_details:
            print("\n" + "-" * 70)
            print(f"FAILURE DETAILS (showing first 10 of {len(self.failure_details)}):")
            print("-" * 70)

            for i, failure in enumerate(self.failure_details[:10], 1):
                print(f"\n{i}. [{failure['timestamp']}]")
                print(f"   Status: {failure['status_code']}")
                print(f"   Error: {failure['error']}")
                print(f"   Response Time: {failure['response_time_ms']:.2f}ms")

        print("\n" + "=" * 70)

    def export_results(self, output_file: str):
        """Export results to JSON file"""
        data = {
            'test_config': {
                'dash_url': self.dash_url,
                'verify_ssl': self.verify_ssl,
                'timeout': self.timeout
            },
            'statistics': self.get_statistics(),
            'failure_details': self.failure_details,
            'failure_timestamps': [f['timestamp'] for f in self.failure_details]
        }

        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2)

        print(f"[SUCCESS] Results exported to {output_file}")


def main():
    """Command-line interface for stress tester"""
    import argparse

    parser = argparse.ArgumentParser(description='LTPA Integration Stress Tester')
    parser.add_argument('--url', required=True, help='DASH role servlet URL')
    parser.add_argument('--token', help='LTPA token value (LTPAToken2 cookie)')
    parser.add_argument('--username', help='Username for token acquisition')
    parser.add_argument('--password', help='Password for token acquisition')
    parser.add_argument('--mode', choices=['steady', 'burst', 'soak'], default='steady',
                        help='Test mode (default: steady)')
    parser.add_argument('--duration', type=int, default=60,
                        help='Test duration in seconds for steady mode (default: 60)')
    parser.add_argument('--rate', type=float, default=10,
                        help='Requests per second for steady mode (default: 10)')
    parser.add_argument('--requests', type=int, default=1000,
                        help='Total requests for burst mode (default: 1000)')
    parser.add_argument('--threads', type=int, default=10,
                        help='Concurrent threads for burst mode (default: 10)')
    parser.add_argument('--no-verify-ssl', action='store_true',
                        help='Disable SSL certificate verification (testing only)')
    parser.add_argument('--timeout', type=int, default=10,
                        help='Request timeout in seconds (default: 10)')
    parser.add_argument('--output', help='Output JSON file for results')

    args = parser.parse_args()

    # Build config
    config = {
        'dash_url': args.url,
        'ltpa_token': args.token,
        'username': args.username,
        'password': args.password,
        'verify_ssl': not args.no_verify_ssl,
        'timeout': args.timeout
    }

    # Initialize tester
    tester = LTPAStressTester(config)

    # Acquire LTPA token if not provided
    if not tester.ltpa_token:
        if not tester.acquire_ltpa_token():
            print("[ERROR] Failed to acquire LTPA token. Exiting.")
            return 1

    # Run test based on mode
    print(f"\n[INFO] Starting {args.mode} test...")
    start_time = time.time()

    try:
        if args.mode == 'steady':
            tester.run_steady_load(args.duration, args.rate)
        elif args.mode == 'burst':
            tester.run_burst_test(args.requests, args.threads)
        elif args.mode == 'soak':
            # Soak mode runs for hours
            hours = args.duration / 3600
            tester.run_soak_test(int(hours), args.rate * 60)

    except KeyboardInterrupt:
        print("\n[INFO] Test interrupted by user")

    elapsed_time = time.time() - start_time
    print(f"\n[INFO] Test completed in {elapsed_time:.2f} seconds")

    # Print summary
    tester.print_summary()

    # Export results
    if args.output:
        tester.export_results(args.output)

    # Exit with error code if failures detected
    if tester.failed_requests > 0:
        print(f"\n[WARN] {tester.failed_requests} failures detected")
        return 1
    else:
        print("\n[SUCCESS] All requests succeeded")
        return 0


if __name__ == '__main__':
    sys.exit(main())
