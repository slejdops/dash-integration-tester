#!/usr/bin/env python3
"""
LTPA Token Testing Web Application
Flask app for interactive LTPA cookie testing and validation
"""

from flask import Flask, render_template, request, redirect, url_for, session, jsonify, make_response
import requests
import base64
import json
import os
from datetime import datetime, timedelta
from urllib.parse import urlparse
import logging

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'ltpa-test-secret-key-change-in-production')
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = False  # Set to True if using HTTPS

# Configuration from environment variables
DASH_BASE_URL = os.environ.get('DASH_URL', 'https://localhost:9443')
DASH_ROLE_ENDPOINT = os.environ.get('DASH_ROLE_ENDPOINT', '/dash/api/roles')
VERIFY_SSL = os.environ.get('VERIFY_SSL', 'false').lower() == 'true'

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Disable SSL warnings for testing
if not VERIFY_SSL:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


@app.route('/')
def index():
    """Main dashboard"""
    ltpa_token = request.cookies.get('LTPAToken2') or session.get('ltpa_token')

    context = {
        'has_token': bool(ltpa_token),
        'token_preview': ltpa_token[:20] + '...' if ltpa_token else None,
        'dash_url': DASH_BASE_URL,
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }

    return render_template('index.html', **context)


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login to DASH and acquire LTPA token"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if not username or not password:
            return render_template('login.html', error='Username and password required')

        # Attempt to login to DASH
        login_url = f"{DASH_BASE_URL}/ibm/console/login.do"

        try:
            logger.info(f"Attempting login to {login_url} as {username}")

            # Create session to maintain cookies
            dash_session = requests.Session()

            # POST login credentials
            response = dash_session.post(
                login_url,
                data={
                    'username': username,
                    'password': password,
                    'action': 'Log in'
                },
                verify=VERIFY_SSL,
                timeout=10,
                allow_redirects=True
            )

            logger.info(f"Login response status: {response.status_code}")
            logger.info(f"Cookies received: {list(dash_session.cookies.keys())}")

            # Check for LTPA token in cookies
            ltpa_token = dash_session.cookies.get('LTPAToken2')

            if ltpa_token:
                logger.info(f"LTPA token acquired: {ltpa_token[:20]}...")

                # Store in session
                session['ltpa_token'] = ltpa_token
                session['username'] = username
                session['acquired_at'] = datetime.now().isoformat()

                # Create response and set cookie
                resp = make_response(redirect(url_for('token_info')))
                resp.set_cookie('LTPAToken2', ltpa_token,
                               max_age=7200,  # 2 hours
                               httponly=True,
                               samesite='Lax')

                return resp
            else:
                error = "Login succeeded but no LTPA token received. Available cookies: " + \
                        ", ".join(dash_session.cookies.keys())
                logger.error(error)
                return render_template('login.html', error=error)

        except requests.exceptions.RequestException as e:
            error = f"Login failed: {str(e)}"
            logger.error(error)
            return render_template('login.html', error=error)

    return render_template('login.html')


@app.route('/manual-token', methods=['GET', 'POST'])
def manual_token():
    """Manually input LTPA token for testing"""
    if request.method == 'POST':
        ltpa_token = request.form.get('token', '').strip()

        if not ltpa_token:
            return render_template('manual_token.html', error='Token is required')

        # Store in session
        session['ltpa_token'] = ltpa_token
        session['username'] = 'manual-input'
        session['acquired_at'] = datetime.now().isoformat()

        # Set cookie
        resp = make_response(redirect(url_for('token_info')))
        resp.set_cookie('LTPAToken2', ltpa_token,
                       max_age=7200,
                       httponly=True,
                       samesite='Lax')

        return resp

    return render_template('manual_token.html')


@app.route('/token-info')
def token_info():
    """Display LTPA token information"""
    ltpa_token = request.cookies.get('LTPAToken2') or session.get('ltpa_token')

    if not ltpa_token:
        return redirect(url_for('index'))

    # Attempt to decode token (partial - LTPA tokens are encrypted)
    token_info = {
        'token': ltpa_token,
        'length': len(ltpa_token),
        'acquired_at': session.get('acquired_at', 'Unknown'),
        'username': session.get('username', 'Unknown'),
        'base64_decoded_length': None,
        'appears_valid': len(ltpa_token) > 100  # Basic sanity check
    }

    # Try to decode as base64 to get length
    try:
        decoded = base64.b64decode(ltpa_token + '==')  # Add padding
        token_info['base64_decoded_length'] = len(decoded)
    except Exception as e:
        token_info['decode_error'] = str(e)

    return render_template('token_info.html', token=token_info)


@app.route('/test-role-fetch', methods=['GET', 'POST'])
def test_role_fetch():
    """Test DASH role-fetching endpoint (simulating TCE)"""
    ltpa_token = request.cookies.get('LTPAToken2') or session.get('ltpa_token')

    if not ltpa_token:
        return redirect(url_for('index'))

    result = None

    if request.method == 'POST':
        endpoint = request.form.get('endpoint', DASH_ROLE_ENDPOINT)
        full_url = f"{DASH_BASE_URL}{endpoint}"

        logger.info(f"Testing role fetch: {full_url}")

        start_time = datetime.now()

        try:
            # Make request with LTPA token
            response = requests.get(
                full_url,
                cookies={'LTPAToken2': ltpa_token},
                verify=VERIFY_SSL,
                timeout=10
            )

            end_time = datetime.now()
            elapsed_ms = (end_time - start_time).total_seconds() * 1000

            result = {
                'success': response.status_code == 200,
                'status_code': response.status_code,
                'status_text': response.reason,
                'response_time_ms': round(elapsed_ms, 2),
                'timestamp': start_time.isoformat(),
                'headers': dict(response.headers),
                'body': response.text[:1000],  # Limit body size
                'url': full_url
            }

            # Try to parse JSON response
            try:
                result['json_data'] = response.json()
            except:
                result['json_data'] = None

            logger.info(f"Role fetch result: {response.status_code} in {elapsed_ms:.2f}ms")

        except requests.exceptions.RequestException as e:
            end_time = datetime.now()
            elapsed_ms = (end_time - start_time).total_seconds() * 1000

            result = {
                'success': False,
                'error': str(e),
                'response_time_ms': round(elapsed_ms, 2),
                'timestamp': start_time.isoformat(),
                'url': full_url
            }

            logger.error(f"Role fetch failed: {e}")

    return render_template('test_role_fetch.html',
                          result=result,
                          default_endpoint=DASH_ROLE_ENDPOINT,
                          dash_url=DASH_BASE_URL)


@app.route('/stress-test', methods=['GET', 'POST'])
def stress_test():
    """Run mini stress test from browser"""
    ltpa_token = request.cookies.get('LTPAToken2') or session.get('ltpa_token')

    if not ltpa_token:
        return redirect(url_for('index'))

    if request.method == 'POST':
        endpoint = request.form.get('endpoint', DASH_ROLE_ENDPOINT)
        num_requests = int(request.form.get('num_requests', 10))

        # Limit to reasonable number
        num_requests = min(num_requests, 100)

        full_url = f"{DASH_BASE_URL}{endpoint}"

        results = {
            'total_requests': num_requests,
            'successful': 0,
            'failed': 0,
            'response_times': [],
            'failures': [],
            'start_time': datetime.now().isoformat()
        }

        for i in range(num_requests):
            start = datetime.now()

            try:
                response = requests.get(
                    full_url,
                    cookies={'LTPAToken2': ltpa_token},
                    verify=VERIFY_SSL,
                    timeout=10
                )

                elapsed = (datetime.now() - start).total_seconds() * 1000
                results['response_times'].append(elapsed)

                if response.status_code == 200:
                    results['successful'] += 1
                else:
                    results['failed'] += 1
                    results['failures'].append({
                        'request_num': i + 1,
                        'status_code': response.status_code,
                        'error': response.reason
                    })

            except Exception as e:
                elapsed = (datetime.now() - start).total_seconds() * 1000
                results['response_times'].append(elapsed)
                results['failed'] += 1
                results['failures'].append({
                    'request_num': i + 1,
                    'error': str(e)
                })

        # Calculate statistics
        if results['response_times']:
            results['avg_response_time'] = round(sum(results['response_times']) / len(results['response_times']), 2)
            results['min_response_time'] = round(min(results['response_times']), 2)
            results['max_response_time'] = round(max(results['response_times']), 2)

            sorted_times = sorted(results['response_times'])
            p95_index = int(len(sorted_times) * 0.95)
            results['p95_response_time'] = round(sorted_times[p95_index], 2)

        results['failure_rate'] = round((results['failed'] / results['total_requests']) * 100, 2)
        results['end_time'] = datetime.now().isoformat()

        return render_template('stress_test.html',
                              results=results,
                              default_endpoint=DASH_ROLE_ENDPOINT)

    return render_template('stress_test.html',
                          default_endpoint=DASH_ROLE_ENDPOINT)


@app.route('/logout')
def logout():
    """Clear session and LTPA cookie"""
    session.clear()

    resp = make_response(redirect(url_for('index')))
    resp.set_cookie('LTPAToken2', '', expires=0)

    return resp


@app.route('/health')
def health():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'dash_url': DASH_BASE_URL,
        'verify_ssl': VERIFY_SSL
    })


@app.route('/api/token-status')
def api_token_status():
    """API endpoint to check if user has valid token"""
    ltpa_token = request.cookies.get('LTPAToken2') or session.get('ltpa_token')

    return jsonify({
        'has_token': bool(ltpa_token),
        'username': session.get('username'),
        'acquired_at': session.get('acquired_at')
    })


if __name__ == '__main__':
    # Run in development mode
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('DEBUG', 'false').lower() == 'true'

    app.run(host='0.0.0.0', port=port, debug=debug)
