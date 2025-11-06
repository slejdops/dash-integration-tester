#!/usr/bin/env jython
"""
WebSphere Configuration Extractor for LTPA Diagnostics
Jython script to run via wsadmin to extract security and session configuration

Usage:
    wsadmin.sh -lang jython -f extract_config.py -output /tmp/was_config.json

Requirements:
    - WebSphere Application Server 8.5.5+
    - wsadmin connectivity to DASH server
    - Read access to configuration
"""

import sys
import json
import re
from java.util import Date
from java.text import SimpleDateFormat

# Output file path (override with -output parameter)
output_file = '/tmp/was_config.json'

# Parse command-line arguments
for i in range(len(sys.argv)):
    if sys.argv[i] == '-output' and i + 1 < len(sys.argv):
        output_file = sys.argv[i + 1]

print "[INFO] WebSphere LTPA Configuration Extractor"
print "[INFO] Output file: " + output_file

# Initialize result dictionary
config_data = {
    'timestamp': str(Date()),
    'was_version': '',
    'cell': '',
    'node': '',
    'servers': [],
    'ltpa_config': {},
    'session_config': {},
    'sso_config': {},
    'thread_pools': {},
    'cookie_config': {},
    'security_enabled': False,
    'issues': [],
    'warnings': []
}

def safe_get_attribute(obj, attr_name):
    """Safely get attribute, return None if not found"""
    try:
        return AdminConfig.showAttribute(obj, attr_name)
    except:
        return None

def parse_timeout_value(timeout_str):
    """Convert timeout string to integer, handle None"""
    if timeout_str is None or timeout_str == '':
        return None
    try:
        return int(timeout_str)
    except:
        return None

# ========================================================================
# 1. EXTRACT WEBSPHERE VERSION AND CELL INFO
# ========================================================================
print "[INFO] Extracting WebSphere version and cell info..."

try:
    # Get version via AdminTask (WAS 8.5+)
    version_info = AdminTask.getNodeBaseProductVersion(['-nodeName', AdminControl.getNode()])
    config_data['was_version'] = version_info
except:
    try:
        # Fallback: parse from server info
        servers = AdminConfig.list('Server').splitlines()
        if servers:
            server = servers[0]
            config_data['was_version'] = AdminConfig.showAttribute(server, 'processType')
    except:
        config_data['was_version'] = 'Unknown'

# Get cell, node, server info
try:
    cell = AdminControl.getCell()
    config_data['cell'] = cell

    node = AdminControl.getNode()
    config_data['node'] = node

    print "[INFO] Cell: " + cell
    print "[INFO] Node: " + node
except Exception, e:
    print "[ERROR] Failed to get cell/node info: " + str(e)

# ========================================================================
# 2. EXTRACT LTPA CONFIGURATION
# ========================================================================
print "[INFO] Extracting LTPA configuration..."

try:
    security = AdminConfig.list('Security')
    if security:
        config_data['security_enabled'] = True

        # Get LTPA configuration
        ltpa = AdminConfig.list('LTPA', security)
        if ltpa:
            timeout = safe_get_attribute(ltpa, 'timeout')
            keys_file = safe_get_attribute(ltpa, 'keysFileName')

            config_data['ltpa_config'] = {
                'timeout_minutes': parse_timeout_value(timeout),
                'keys_file': keys_file,
                'config_id': ltpa
            }

            print "[INFO] LTPA timeout: " + str(timeout) + " minutes"
            print "[INFO] LTPA keys file: " + str(keys_file)

            # Check if timeout is too short
            timeout_int = parse_timeout_value(timeout)
            if timeout_int and timeout_int < 60:
                warning = "LTPA timeout is less than 60 minutes (current: " + str(timeout_int) + "), may cause frequent re-authentication"
                config_data['warnings'].append(warning)
                print "[WARN] " + warning
        else:
            config_data['issues'].append("LTPA configuration not found")
            print "[ERROR] LTPA configuration not found"
    else:
        config_data['security_enabled'] = False
        config_data['issues'].append("Security is not enabled on this server")
        print "[ERROR] Security is not enabled"

except Exception, e:
    error_msg = "Failed to extract LTPA config: " + str(e)
    config_data['issues'].append(error_msg)
    print "[ERROR] " + error_msg

# ========================================================================
# 3. EXTRACT SSO (SINGLE SIGN-ON) CONFIGURATION
# ========================================================================
print "[INFO] Extracting SSO configuration..."

try:
    security = AdminConfig.list('Security')
    if security:
        sso = AdminConfig.list('SingleSignon', security)
        if sso:
            enabled = safe_get_attribute(sso, 'enabled')
            domain = safe_get_attribute(sso, 'domainName')
            requires_ssl = safe_get_attribute(sso, 'requiresSSL')

            config_data['sso_config'] = {
                'enabled': enabled == 'true',
                'domain': domain,
                'requires_ssl': requires_ssl == 'true',
                'config_id': sso
            }

            print "[INFO] SSO enabled: " + str(enabled)
            print "[INFO] SSO domain: " + str(domain)
            print "[INFO] SSO requires SSL: " + str(requires_ssl)

            # Validate SSO domain
            if not domain or domain == '':
                warning = "SSO domain is not set - cookies will be scoped to server hostname only"
                config_data['warnings'].append(warning)
                print "[WARN] " + warning

            # Check SSL requirement
            if requires_ssl != 'true':
                warning = "SSO does not require SSL - LTPA tokens may be transmitted over HTTP (security risk)"
                config_data['warnings'].append(warning)
                print "[WARN] " + warning
        else:
            config_data['warnings'].append("SSO configuration not found")
            print "[WARN] SSO configuration not found"

except Exception, e:
    error_msg = "Failed to extract SSO config: " + str(e)
    config_data['issues'].append(error_msg)
    print "[ERROR] " + error_msg

# ========================================================================
# 4. EXTRACT SESSION MANAGEMENT CONFIGURATION (PER SERVER)
# ========================================================================
print "[INFO] Extracting session management configuration..."

try:
    servers = AdminConfig.list('Server').splitlines()

    for server_id in servers:
        server_name = safe_get_attribute(server_id, 'name')

        # Skip nodeagent and dmgr
        if server_name in ['nodeagent', 'dmgr']:
            continue

        print "[INFO] Checking server: " + server_name

        server_info = {
            'name': server_name,
            'session_timeout_minutes': None,
            'enable_cookies': None,
            'cookie_name': None,
            'cookie_domain': None,
            'cookie_path': None,
            'cookie_secure': None,
            'cookie_http_only': None,
            'cookie_max_age': None,
            'session_persistence': None
        }

        # Get SessionManager
        session_mgr = AdminConfig.list('SessionManager', server_id)
        if session_mgr:
            session_timeout = safe_get_attribute(session_mgr, 'sessionTimeout')
            enable_cookies = safe_get_attribute(session_mgr, 'enableCookies')

            session_timeout_int = parse_timeout_value(session_timeout)
            server_info['session_timeout_minutes'] = session_timeout_int
            server_info['enable_cookies'] = enable_cookies == 'true'

            print "[INFO]   Session timeout: " + str(session_timeout) + " minutes"
            print "[INFO]   Cookies enabled: " + str(enable_cookies)

            # Get SessionCookie config (WAS 7.0+)
            try:
                cookie_cfg = AdminConfig.list('Cookie', session_mgr)
                if cookie_cfg:
                    server_info['cookie_name'] = safe_get_attribute(cookie_cfg, 'name')
                    server_info['cookie_domain'] = safe_get_attribute(cookie_cfg, 'domain')
                    server_info['cookie_path'] = safe_get_attribute(cookie_cfg, 'path')
                    server_info['cookie_secure'] = safe_get_attribute(cookie_cfg, 'secure') == 'true'
                    server_info['cookie_http_only'] = safe_get_attribute(cookie_cfg, 'httpOnly') == 'true'
                    server_info['cookie_max_age'] = parse_timeout_value(safe_get_attribute(cookie_cfg, 'maximumAge'))
            except:
                pass

            # Get session persistence mode
            try:
                session_db = AdminConfig.list('SessionDatabasePersistence', session_mgr)
                if session_db:
                    server_info['session_persistence'] = 'database'
                else:
                    server_info['session_persistence'] = 'memory'
            except:
                server_info['session_persistence'] = 'unknown'

            # CRITICAL CHECK: Session timeout vs LTPA timeout
            ltpa_timeout = config_data['ltpa_config'].get('timeout_minutes')
            if session_timeout_int and ltpa_timeout:
                if session_timeout_int > ltpa_timeout:
                    issue = "CRITICAL: Server '" + server_name + "' session timeout (" + str(session_timeout_int) + \
                            " min) exceeds LTPA timeout (" + str(ltpa_timeout) + " min) - RACE CONDITION LIKELY"
                    config_data['issues'].append(issue)
                    print "[ERROR] " + issue
                elif session_timeout_int == ltpa_timeout:
                    warning = "Server '" + server_name + "' session timeout equals LTPA timeout - no safety margin"
                    config_data['warnings'].append(warning)
                    print "[WARN] " + warning
                else:
                    print "[OK] Session timeout < LTPA timeout (safe)"

        config_data['servers'].append(server_info)

except Exception, e:
    error_msg = "Failed to extract session config: " + str(e)
    config_data['issues'].append(error_msg)
    print "[ERROR] " + error_msg

# ========================================================================
# 5. EXTRACT WEB CONTAINER THREAD POOL CONFIGURATION
# ========================================================================
print "[INFO] Extracting Web Container thread pool configuration..."

try:
    servers = AdminConfig.list('Server').splitlines()

    for server_id in servers:
        server_name = safe_get_attribute(server_id, 'name')

        # Skip nodeagent and dmgr
        if server_name in ['nodeagent', 'dmgr']:
            continue

        # Get Web Container
        web_container = AdminConfig.list('WebContainer', server_id)
        if web_container:
            thread_pool_ref = safe_get_attribute(web_container, 'threadPool')

            if thread_pool_ref:
                # Get thread pool attributes
                min_size = safe_get_attribute(thread_pool_ref, 'minimumSize')
                max_size = safe_get_attribute(thread_pool_ref, 'maximumSize')
                inactivity_timeout = safe_get_attribute(thread_pool_ref, 'inactivityTimeout')
                is_growable = safe_get_attribute(thread_pool_ref, 'isGrowable')

                thread_pool_info = {
                    'server': server_name,
                    'min_size': parse_timeout_value(min_size),
                    'max_size': parse_timeout_value(max_size),
                    'inactivity_timeout': parse_timeout_value(inactivity_timeout),
                    'is_growable': is_growable == 'true'
                }

                config_data['thread_pools'][server_name] = thread_pool_info

                print "[INFO] Server: " + server_name
                print "[INFO]   Thread pool min: " + str(min_size)
                print "[INFO]   Thread pool max: " + str(max_size)

                # Check if max size is too small
                max_size_int = parse_timeout_value(max_size)
                if max_size_int and max_size_int < 50:
                    warning = "Server '" + server_name + "' Web Container max threads (" + str(max_size_int) + \
                              ") may be insufficient for production load"
                    config_data['warnings'].append(warning)
                    print "[WARN] " + warning

except Exception, e:
    error_msg = "Failed to extract thread pool config: " + str(e)
    config_data['issues'].append(error_msg)
    print "[ERROR] " + error_msg

# ========================================================================
# 6. EXTRACT RUNTIME THREAD POOL STATISTICS (IF SERVER IS RUNNING)
# ========================================================================
print "[INFO] Attempting to extract runtime thread pool statistics..."

try:
    server_mbeans = AdminControl.queryNames('type=ThreadPoolStats,*', None)
    if server_mbeans:
        mbean_list = server_mbeans.split('\n')

        for mbean in mbean_list:
            if 'WebContainer' in mbean:
                try:
                    active_count = AdminControl.getAttribute(mbean, 'activeCount')
                    pool_size = AdminControl.getAttribute(mbean, 'poolSize')

                    # Extract server name from MBean
                    server_match = re.search(r'process=([^,]+)', mbean)
                    if server_match:
                        server_name = server_match.group(1)

                        if server_name in config_data['thread_pools']:
                            config_data['thread_pools'][server_name]['active_threads_now'] = int(active_count)
                            config_data['thread_pools'][server_name]['pool_size_now'] = int(pool_size)

                            print "[INFO] Server: " + server_name + " - Active threads: " + active_count + "/" + pool_size

                            # Check for near-exhaustion
                            if int(active_count) > int(pool_size) * 0.8:
                                warning = "Server '" + server_name + "' thread pool is " + \
                                          str(int(float(active_count)/float(pool_size)*100)) + "% utilized - near exhaustion"
                                config_data['warnings'].append(warning)
                                print "[WARN] " + warning
                except Exception, e2:
                    print "[WARN] Could not get runtime stats for WebContainer: " + str(e2)
    else:
        print "[INFO] No running servers found for runtime statistics"

except Exception, e:
    print "[INFO] Runtime statistics not available (server may not be running): " + str(e)

# ========================================================================
# 7. EXTRACT COOKIE CONFIGURATION FROM WEB CONTAINER
# ========================================================================
print "[INFO] Extracting cookie configuration from Web Container..."

try:
    servers = AdminConfig.list('Server').splitlines()

    for server_id in servers:
        server_name = safe_get_attribute(server_id, 'name')

        if server_name in ['nodeagent', 'dmgr']:
            continue

        web_container = AdminConfig.list('WebContainer', server_id)
        if web_container:
            # Get SessionManager cookies (already done above, but check for LTPA-specific)
            session_mgr = AdminConfig.list('SessionManager', server_id)

            if session_mgr:
                # Note: LTPA cookie settings are global (SSO config), not per-server
                # Session cookie settings were already captured above
                pass

except Exception, e:
    print "[WARN] Could not extract additional cookie config: " + str(e)

# ========================================================================
# 8. GENERATE SUMMARY AND RECOMMENDATIONS
# ========================================================================
print "\n[INFO] ========================================="
print "[INFO] CONFIGURATION EXTRACTION SUMMARY"
print "[INFO] ========================================="
print "[INFO] Security Enabled: " + str(config_data['security_enabled'])
print "[INFO] LTPA Timeout: " + str(config_data['ltpa_config'].get('timeout_minutes', 'N/A')) + " minutes"
print "[INFO] SSO Enabled: " + str(config_data['sso_config'].get('enabled', False))
print "[INFO] SSO Domain: " + str(config_data['sso_config'].get('domain', 'N/A'))
print "[INFO] Number of Servers: " + str(len(config_data['servers']))
print "[INFO] Issues Found: " + str(len(config_data['issues']))
print "[INFO] Warnings Found: " + str(len(config_data['warnings']))

if config_data['issues']:
    print "\n[ERROR] CRITICAL ISSUES FOUND:"
    for issue in config_data['issues']:
        print "[ERROR]   - " + issue

if config_data['warnings']:
    print "\n[WARN] WARNINGS:"
    for warning in config_data['warnings']:
        print "[WARN]   - " + warning

# ========================================================================
# 9. WRITE OUTPUT TO JSON FILE
# ========================================================================
print "\n[INFO] Writing configuration to: " + output_file

try:
    # Convert to JSON string (Jython doesn't have json module, build manually)
    json_output = "{\n"
    json_output += '  "timestamp": "' + str(config_data['timestamp']) + '",\n'
    json_output += '  "was_version": "' + str(config_data['was_version']) + '",\n'
    json_output += '  "cell": "' + str(config_data['cell']) + '",\n'
    json_output += '  "node": "' + str(config_data['node']) + '",\n'
    json_output += '  "security_enabled": ' + str(config_data['security_enabled']).lower() + ',\n'

    # LTPA config
    json_output += '  "ltpa_config": {\n'
    json_output += '    "timeout_minutes": ' + str(config_data['ltpa_config'].get('timeout_minutes', 'null')) + ',\n'
    json_output += '    "keys_file": "' + str(config_data['ltpa_config'].get('keys_file', '')) + '"\n'
    json_output += '  },\n'

    # SSO config
    json_output += '  "sso_config": {\n'
    json_output += '    "enabled": ' + str(config_data['sso_config'].get('enabled', False)).lower() + ',\n'
    json_output += '    "domain": "' + str(config_data['sso_config'].get('domain', '')) + '",\n'
    json_output += '    "requires_ssl": ' + str(config_data['sso_config'].get('requires_ssl', False)).lower() + '\n'
    json_output += '  },\n'

    # Servers (simplified)
    json_output += '  "servers": [\n'
    for i, server in enumerate(config_data['servers']):
        json_output += '    {\n'
        json_output += '      "name": "' + str(server['name']) + '",\n'
        json_output += '      "session_timeout_minutes": ' + str(server.get('session_timeout_minutes', 'null')) + ',\n'
        json_output += '      "cookie_domain": "' + str(server.get('cookie_domain', '')) + '",\n'
        json_output += '      "cookie_secure": ' + str(server.get('cookie_secure', False)).lower() + ',\n'
        json_output += '      "cookie_http_only": ' + str(server.get('cookie_http_only', False)).lower() + '\n'
        json_output += '    }' + (',' if i < len(config_data['servers']) - 1 else '') + '\n'
    json_output += '  ],\n'

    # Thread pools (simplified)
    json_output += '  "thread_pools": {\n'
    pool_keys = config_data['thread_pools'].keys()
    for i, server_name in enumerate(pool_keys):
        pool = config_data['thread_pools'][server_name]
        json_output += '    "' + server_name + '": {\n'
        json_output += '      "min_size": ' + str(pool.get('min_size', 'null')) + ',\n'
        json_output += '      "max_size": ' + str(pool.get('max_size', 'null')) + ',\n'
        json_output += '      "active_threads_now": ' + str(pool.get('active_threads_now', 'null')) + '\n'
        json_output += '    }' + (',' if i < len(pool_keys) - 1 else '') + '\n'
    json_output += '  },\n'

    # Issues
    json_output += '  "issues": [\n'
    for i, issue in enumerate(config_data['issues']):
        json_output += '    "' + issue.replace('"', '\\"') + '"' + (',' if i < len(config_data['issues']) - 1 else '') + '\n'
    json_output += '  ],\n'

    # Warnings
    json_output += '  "warnings": [\n'
    for i, warning in enumerate(config_data['warnings']):
        json_output += '    "' + warning.replace('"', '\\"') + '"' + (',' if i < len(config_data['warnings']) - 1 else '') + '\n'
    json_output += '  ]\n'

    json_output += '}\n'

    # Write to file
    output = open(output_file, 'w')
    output.write(json_output)
    output.close()

    print "[SUCCESS] Configuration exported to: " + output_file
    print "[INFO] You can now analyze this file with the Python analyzer tool"

except Exception, e:
    print "[ERROR] Failed to write output file: " + str(e)
    print "[INFO] Configuration data:"
    print config_data

print "\n[INFO] Extraction complete!"
