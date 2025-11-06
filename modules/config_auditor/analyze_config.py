#!/usr/bin/env python3
"""
WebSphere Configuration Analyzer for LTPA Diagnostics
Analyzes JSON configuration extracted by extract_config.py (Jython script)

Usage:
    python3 analyze_config.py --config /tmp/was_config.json --report /tmp/config_report.html
"""

import json
import sys
import argparse
from datetime import datetime
from typing import Dict, List, Any

class ConfigAnalyzer:
    """Analyzes WebSphere configuration for LTPA/SSO issues"""

    def __init__(self, config_file: str):
        self.config_file = config_file
        self.config = {}
        self.findings = {
            'critical': [],
            'high': [],
            'medium': [],
            'low': [],
            'info': []
        }

    def load_config(self):
        """Load JSON configuration file"""
        try:
            with open(self.config_file, 'r') as f:
                self.config = json.load(f)
            print(f"[INFO] Loaded configuration from {self.config_file}")
            return True
        except FileNotFoundError:
            print(f"[ERROR] Configuration file not found: {self.config_file}")
            return False
        except json.JSONDecodeError as e:
            print(f"[ERROR] Invalid JSON in configuration file: {e}")
            return False

    def add_finding(self, severity: str, title: str, description: str, remediation: str = ""):
        """Add a finding to the results"""
        self.findings[severity].append({
            'title': title,
            'description': description,
            'remediation': remediation
        })

    def analyze_ltpa_config(self):
        """Analyze LTPA configuration"""
        print("[INFO] Analyzing LTPA configuration...")

        ltpa = self.config.get('ltpa_config', {})
        timeout = ltpa.get('timeout_minutes')

        if not timeout:
            self.add_finding(
                'critical',
                'LTPA Timeout Not Configured',
                'LTPA timeout value could not be extracted from configuration.',
                'Verify LTPA is properly configured in WebSphere security settings.'
            )
            return

        # Check timeout value
        if timeout < 30:
            self.add_finding(
                'high',
                'LTPA Timeout Too Short',
                f'LTPA timeout is {timeout} minutes, which is very short and will cause frequent re-authentication.',
                'Consider increasing LTPA timeout to at least 60 minutes (120 recommended).'
            )
        elif timeout < 60:
            self.add_finding(
                'medium',
                'LTPA Timeout Below Recommended',
                f'LTPA timeout is {timeout} minutes. While functional, 120 minutes is recommended for production.',
                'Consider increasing LTPA timeout to 120 minutes for better user experience.'
            )
        else:
            self.add_finding(
                'info',
                'LTPA Timeout Acceptable',
                f'LTPA timeout is {timeout} minutes, which is within acceptable range.',
                ''
            )

        # Check keys file path
        keys_file = ltpa.get('keys_file', '')
        if keys_file:
            self.add_finding(
                'info',
                'LTPA Keys File Location',
                f'LTPA keys file: {keys_file}',
                'Verify this file exists and has proper permissions (600). Check modification date for recent key regeneration.'
            )

    def analyze_session_config(self):
        """Analyze session management configuration"""
        print("[INFO] Analyzing session management configuration...")

        ltpa_timeout = self.config.get('ltpa_config', {}).get('timeout_minutes')
        servers = self.config.get('servers', [])

        if not ltpa_timeout:
            return

        for server in servers:
            server_name = server.get('name', 'Unknown')
            session_timeout = server.get('session_timeout_minutes')

            if not session_timeout:
                self.add_finding(
                    'medium',
                    f'Session Timeout Not Configured - {server_name}',
                    f'Server "{server_name}" does not have session timeout configured.',
                    'Configure session timeout in Session Management settings.'
                )
                continue

            # Critical check: session timeout vs LTPA timeout
            if session_timeout > ltpa_timeout:
                self.add_finding(
                    'critical',
                    f'Session Timeout Exceeds LTPA Timeout - {server_name}',
                    f'Server "{server_name}" has session timeout ({session_timeout} min) greater than LTPA timeout ({ltpa_timeout} min). '
                    f'This creates a race condition where users can have valid HTTP sessions but expired LTPA tokens, causing authentication failures.',
                    f'Set session timeout to {ltpa_timeout - 10} minutes (LTPA timeout minus 10-minute safety buffer).'
                )
            elif session_timeout == ltpa_timeout:
                self.add_finding(
                    'high',
                    f'Session Timeout Equals LTPA Timeout - {server_name}',
                    f'Server "{server_name}" has session timeout equal to LTPA timeout ({session_timeout} min). '
                    f'No safety margin exists - timing variations could cause intermittent failures.',
                    f'Set session timeout to {ltpa_timeout - 10} minutes for safety buffer.'
                )
            elif ltpa_timeout - session_timeout < 5:
                self.add_finding(
                    'medium',
                    f'Insufficient Session/LTPA Timeout Margin - {server_name}',
                    f'Server "{server_name}" has only {ltpa_timeout - session_timeout} minute difference between session ({session_timeout} min) and LTPA ({ltpa_timeout} min) timeouts.',
                    f'Increase margin to at least 10 minutes for safety.'
                )
            else:
                self.add_finding(
                    'info',
                    f'Session Timeout Properly Configured - {server_name}',
                    f'Server "{server_name}" has session timeout ({session_timeout} min) safely below LTPA timeout ({ltpa_timeout} min).',
                    ''
                )

            # Check cookie security
            if not server.get('cookie_secure', False):
                self.add_finding(
                    'high',
                    f'Session Cookie Not Secured - {server_name}',
                    f'Server "{server_name}" session cookie does not have Secure flag set. Cookies may be transmitted over HTTP.',
                    'Enable "Cookie Secure" flag in Session Management cookie settings.'
                )

            if not server.get('cookie_http_only', False):
                self.add_finding(
                    'medium',
                    f'Session Cookie Not HttpOnly - {server_name}',
                    f'Server "{server_name}" session cookie does not have HttpOnly flag. JavaScript can access cookies (XSS risk).',
                    'Enable "HttpOnly" flag in Session Management cookie settings.'
                )

    def analyze_sso_config(self):
        """Analyze SSO configuration"""
        print("[INFO] Analyzing SSO configuration...")

        sso = self.config.get('sso_config', {})

        if not sso.get('enabled', False):
            self.add_finding(
                'high',
                'SSO Not Enabled',
                'Single Sign-On (SSO) is not enabled. LTPA tokens will not be used for SSO.',
                'Enable SSO in Security → Global Security → Single Sign-On (SSO).'
            )
            return

        # Check SSO domain
        domain = sso.get('domain', '')
        if not domain or domain == '':
            self.add_finding(
                'critical',
                'SSO Domain Not Configured',
                'SSO is enabled but domain is not set. LTPA cookies will be scoped to server hostname only, preventing SSO to OpenShift or other domains.',
                'Set SSO domain to parent domain (e.g., ".example.com") to allow cookie sharing across subdomains.'
            )
        elif not domain.startswith('.'):
            self.add_finding(
                'high',
                'SSO Domain Missing Leading Dot',
                f'SSO domain is "{domain}" but should start with "." (e.g., ".{domain}") for proper subdomain cookie sharing.',
                f'Change SSO domain to ".{domain}" in SSO configuration.'
            )
        else:
            self.add_finding(
                'info',
                'SSO Domain Configured',
                f'SSO domain is "{domain}", which allows cookie sharing across subdomains.',
                'Verify OpenShift ingress hostname matches this domain (e.g., tce.example.com).'
            )

        # Check SSL requirement
        if not sso.get('requires_ssl', False):
            self.add_finding(
                'critical',
                'SSO Does Not Require SSL',
                'SSO is configured to allow LTPA tokens over HTTP. This is a severe security risk - tokens can be intercepted.',
                'Enable "Requires SSL" in SSO configuration to enforce HTTPS-only cookie transmission.'
            )
        else:
            self.add_finding(
                'info',
                'SSO Requires SSL',
                'SSO properly requires SSL for cookie transmission.',
                ''
            )

    def analyze_thread_pools(self):
        """Analyze thread pool configuration"""
        print("[INFO] Analyzing thread pool configuration...")

        thread_pools = self.config.get('thread_pools', {})

        for server_name, pool in thread_pools.items():
            max_size = pool.get('max_size')
            min_size = pool.get('min_size')
            active_now = pool.get('active_threads_now')

            if max_size and max_size < 50:
                self.add_finding(
                    'medium',
                    f'Thread Pool Maximum Too Small - {server_name}',
                    f'Server "{server_name}" Web Container thread pool maximum is {max_size}, which may be insufficient for production load.',
                    f'Increase maximum thread pool size to at least 100 for production environments.'
                )

            if active_now is not None and max_size:
                utilization = (active_now / max_size) * 100
                if utilization > 90:
                    self.add_finding(
                        'critical',
                        f'Thread Pool Near Exhaustion - {server_name}',
                        f'Server "{server_name}" thread pool is {utilization:.1f}% utilized ({active_now}/{max_size}). Servlet requests may be queued or rejected.',
                        f'Increase thread pool maximum size or investigate thread contention (check for hung threads).'
                    )
                elif utilization > 70:
                    self.add_finding(
                        'high',
                        f'Thread Pool High Utilization - {server_name}',
                        f'Server "{server_name}" thread pool is {utilization:.1f}% utilized ({active_now}/{max_size}).',
                        f'Monitor thread pool usage and consider increasing maximum size.'
                    )
                else:
                    self.add_finding(
                        'info',
                        f'Thread Pool Utilization Normal - {server_name}',
                        f'Server "{server_name}" thread pool is {utilization:.1f}% utilized ({active_now}/{max_size}).',
                        ''
                    )

    def analyze_issues_and_warnings(self):
        """Analyze issues and warnings from extraction script"""
        print("[INFO] Analyzing issues and warnings from extraction...")

        issues = self.config.get('issues', [])
        warnings = self.config.get('warnings', [])

        for issue in issues:
            self.add_finding(
                'critical',
                'Configuration Issue Detected',
                issue,
                'Investigate and resolve this issue as identified by configuration extraction.'
            )

        for warning in warnings:
            self.add_finding(
                'medium',
                'Configuration Warning',
                warning,
                'Review this warning and determine if action is needed.'
            )

    def run_analysis(self):
        """Run all analysis checks"""
        if not self.load_config():
            return False

        self.analyze_ltpa_config()
        self.analyze_session_config()
        self.analyze_sso_config()
        self.analyze_thread_pools()
        self.analyze_issues_and_warnings()

        return True

    def print_summary(self):
        """Print analysis summary to console"""
        print("\n" + "=" * 70)
        print("CONFIGURATION ANALYSIS SUMMARY")
        print("=" * 70)

        total_findings = sum(len(findings) for findings in self.findings.values())
        print(f"Total Findings: {total_findings}")
        print(f"  Critical: {len(self.findings['critical'])}")
        print(f"  High:     {len(self.findings['high'])}")
        print(f"  Medium:   {len(self.findings['medium'])}")
        print(f"  Low:      {len(self.findings['low'])}")
        print(f"  Info:     {len(self.findings['info'])}")

        # Print critical findings
        if self.findings['critical']:
            print("\n" + "!" * 70)
            print("CRITICAL FINDINGS (Immediate Action Required):")
            print("!" * 70)
            for i, finding in enumerate(self.findings['critical'], 1):
                print(f"\n{i}. {finding['title']}")
                print(f"   Description: {finding['description']}")
                if finding['remediation']:
                    print(f"   Remediation: {finding['remediation']}")

        # Print high findings
        if self.findings['high']:
            print("\n" + "-" * 70)
            print("HIGH PRIORITY FINDINGS:")
            print("-" * 70)
            for i, finding in enumerate(self.findings['high'], 1):
                print(f"\n{i}. {finding['title']}")
                print(f"   Description: {finding['description']}")
                if finding['remediation']:
                    print(f"   Remediation: {finding['remediation']}")

        print("\n" + "=" * 70)

    def generate_html_report(self, output_file: str):
        """Generate HTML report"""
        print(f"[INFO] Generating HTML report: {output_file}")

        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>WebSphere LTPA Configuration Analysis Report</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 20px;
            background-color: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            padding: 30px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        h1 {{
            color: #333;
            border-bottom: 3px solid #0066cc;
            padding-bottom: 10px;
        }}
        h2 {{
            color: #555;
            margin-top: 30px;
            border-bottom: 2px solid #ddd;
            padding-bottom: 8px;
        }}
        .summary {{
            background-color: #f0f7ff;
            padding: 20px;
            border-radius: 5px;
            margin: 20px 0;
        }}
        .summary-stats {{
            display: flex;
            justify-content: space-around;
            margin-top: 15px;
        }}
        .stat {{
            text-align: center;
        }}
        .stat-number {{
            font-size: 36px;
            font-weight: bold;
        }}
        .stat-label {{
            font-size: 14px;
            color: #666;
        }}
        .finding {{
            margin: 20px 0;
            padding: 15px;
            border-left: 5px solid;
            background-color: #fafafa;
        }}
        .critical {{ border-left-color: #d32f2f; background-color: #ffebee; }}
        .high {{ border-left-color: #f57c00; background-color: #fff3e0; }}
        .medium {{ border-left-color: #fbc02d; background-color: #fffde7; }}
        .low {{ border-left-color: #0288d1; background-color: #e1f5fe; }}
        .info {{ border-left-color: #388e3c; background-color: #e8f5e9; }}
        .finding-title {{
            font-weight: bold;
            font-size: 16px;
            margin-bottom: 10px;
        }}
        .finding-description {{
            margin-bottom: 10px;
            line-height: 1.6;
        }}
        .finding-remediation {{
            background-color: white;
            padding: 10px;
            border-radius: 3px;
            font-style: italic;
        }}
        .config-info {{
            background-color: #f9f9f9;
            padding: 15px;
            border-radius: 5px;
            margin: 20px 0;
        }}
        .config-row {{
            display: flex;
            margin: 8px 0;
        }}
        .config-label {{
            font-weight: bold;
            width: 200px;
        }}
        .critical-count {{ color: #d32f2f; }}
        .high-count {{ color: #f57c00; }}
        .medium-count {{ color: #fbc02d; }}
        .timestamp {{
            color: #666;
            font-size: 12px;
            margin-top: 20px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>WebSphere LTPA Configuration Analysis Report</h1>
        <div class="timestamp">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>

        <div class="summary">
            <h2>Summary</h2>
            <div class="config-row">
                <div class="config-label">WebSphere Version:</div>
                <div>{self.config.get('was_version', 'Unknown')}</div>
            </div>
            <div class="config-row">
                <div class="config-label">Cell:</div>
                <div>{self.config.get('cell', 'Unknown')}</div>
            </div>
            <div class="config-row">
                <div class="config-label">Node:</div>
                <div>{self.config.get('node', 'Unknown')}</div>
            </div>
            <div class="config-row">
                <div class="config-label">Configuration Extracted:</div>
                <div>{self.config.get('timestamp', 'Unknown')}</div>
            </div>

            <div class="summary-stats">
                <div class="stat">
                    <div class="stat-number critical-count">{len(self.findings['critical'])}</div>
                    <div class="stat-label">Critical</div>
                </div>
                <div class="stat">
                    <div class="stat-number high-count">{len(self.findings['high'])}</div>
                    <div class="stat-label">High</div>
                </div>
                <div class="stat">
                    <div class="stat-number medium-count">{len(self.findings['medium'])}</div>
                    <div class="stat-label">Medium</div>
                </div>
                <div class="stat">
                    <div class="stat-number">{len(self.findings['low'])}</div>
                    <div class="stat-label">Low</div>
                </div>
                <div class="stat">
                    <div class="stat-number">{len(self.findings['info'])}</div>
                    <div class="stat-label">Info</div>
                </div>
            </div>
        </div>
"""

        # Add findings by severity
        for severity in ['critical', 'high', 'medium', 'low', 'info']:
            if self.findings[severity]:
                html += f"<h2>{severity.upper()} Findings</h2>\n"
                for finding in self.findings[severity]:
                    html += f"""
        <div class="finding {severity}">
            <div class="finding-title">{finding['title']}</div>
            <div class="finding-description">{finding['description']}</div>
"""
                    if finding['remediation']:
                        html += f"""
            <div class="finding-remediation">
                <strong>Remediation:</strong> {finding['remediation']}
            </div>
"""
                    html += "        </div>\n"

        html += """
    </div>
</body>
</html>
"""

        try:
            with open(output_file, 'w') as f:
                f.write(html)
            print(f"[SUCCESS] HTML report generated: {output_file}")
            return True
        except Exception as e:
            print(f"[ERROR] Failed to write HTML report: {e}")
            return False


def main():
    parser = argparse.ArgumentParser(description='Analyze WebSphere configuration for LTPA issues')
    parser.add_argument('--config', required=True, help='Path to configuration JSON file')
    parser.add_argument('--report', help='Path to output HTML report (optional)')

    args = parser.parse_args()

    analyzer = ConfigAnalyzer(args.config)

    if not analyzer.run_analysis():
        sys.exit(1)

    analyzer.print_summary()

    if args.report:
        analyzer.generate_html_report(args.report)

    # Exit with error code if critical findings exist
    if analyzer.findings['critical']:
        print("\n[ERROR] Critical findings detected - exit code 1")
        sys.exit(1)
    else:
        print("\n[SUCCESS] Analysis complete - exit code 0")
        sys.exit(0)


if __name__ == '__main__':
    main()
