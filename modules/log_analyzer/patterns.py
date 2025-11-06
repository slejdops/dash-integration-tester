#!/usr/bin/env python3
"""
WebSphere Security Error Patterns for LTPA Diagnostics
Defines regex patterns for identifying LTPA, SSO, and security-related errors
"""

import re
from typing import List, Dict, Any

class SecurityPatterns:
    """Security error patterns for WebSphere log analysis"""

    # LTPA Token Errors
    LTPA_PATTERNS = [
        {
            'pattern': r'SECJ0314E.*LTPA.*token.*expired',
            'severity': 'ERROR',
            'category': 'LTPA_EXPIRED',
            'description': 'LTPA token has expired',
            'probable_cause': 'Token age exceeded LTPA timeout, or clock skew between client and server',
            'remediation': 'Check LTPA timeout configuration and verify NTP synchronization'
        },
        {
            'pattern': r'SECJ0369E.*authentication.*failed',
            'severity': 'ERROR',
            'category': 'AUTH_FAILED',
            'description': 'Authentication failed',
            'probable_cause': 'Invalid credentials, LTPA token validation failure, or user registry unavailable',
            'remediation': 'Check user registry connectivity and LTPA token validity'
        },
        {
            'pattern': r'SECJ0374E.*LTPA.*signature.*invalid',
            'severity': 'ERROR',
            'category': 'LTPA_SIGNATURE_INVALID',
            'description': 'LTPA token signature validation failed',
            'probable_cause': 'LTPA keys mismatch between token issuer and validator, or token tampering',
            'remediation': 'Verify LTPA keys are synchronized across all servers in SSO domain'
        },
        {
            'pattern': r'SECJ0118E.*LTPA.*key.*invalid',
            'severity': 'ERROR',
            'category': 'LTPA_KEY_INVALID',
            'description': 'LTPA key is invalid or corrupted',
            'probable_cause': 'LTPA keys file is corrupted or has incorrect permissions',
            'remediation': 'Regenerate LTPA keys and distribute to all servers'
        },
        {
            'pattern': r'SECJ0232E.*LTPA.*token.*validation.*failed',
            'severity': 'ERROR',
            'category': 'LTPA_VALIDATION_FAILED',
            'description': 'LTPA token validation failed (generic)',
            'probable_cause': 'Token format invalid, expired, or signature mismatch',
            'remediation': 'Enable security trace to identify specific validation failure reason'
        }
    ]

    # SSO Errors
    SSO_PATTERNS = [
        {
            'pattern': r'CWWSS8043E.*Single.*sign.*on.*failed',
            'severity': 'ERROR',
            'category': 'SSO_FAILED',
            'description': 'Single Sign-On (SSO) failed',
            'probable_cause': 'SSO configuration mismatch, LTPA token missing or invalid',
            'remediation': 'Check SSO domain configuration and LTPA token presence in request'
        },
        {
            'pattern': r'CWWSS8020E.*SSO.*cookie.*missing',
            'severity': 'ERROR',
            'category': 'SSO_COOKIE_MISSING',
            'description': 'SSO cookie (LTPAToken2) not found in request',
            'probable_cause': 'Cookie not sent by client, domain mismatch, or client cookie disabled',
            'remediation': 'Verify SSO domain matches client hostname and cookies are enabled'
        }
    ]

    # Session Errors
    SESSION_PATTERNS = [
        {
            'pattern': r'SESN0008E.*session.*not.*found',
            'severity': 'ERROR',
            'category': 'SESSION_NOT_FOUND',
            'description': 'HTTP session not found (likely invalidated or expired)',
            'probable_cause': 'Session timeout exceeded, server restart, or session persistence failure',
            'remediation': 'Check session timeout configuration vs LTPA timeout'
        },
        {
            'pattern': r'SESN0307W.*invalidated.*session',
            'severity': 'WARNING',
            'category': 'SESSION_INVALIDATED',
            'description': 'Session was invalidated',
            'probable_cause': 'Explicit logout, session timeout, or programmatic invalidation',
            'remediation': 'Normal if user logged out; investigate if unexpected'
        },
        {
            'pattern': r'SESN0202E.*session.*manager.*error',
            'severity': 'ERROR',
            'category': 'SESSION_MANAGER_ERROR',
            'description': 'Session manager encountered an error',
            'probable_cause': 'Session persistence database issue or session manager configuration error',
            'remediation': 'Check session persistence configuration and database connectivity'
        }
    ]

    # Thread Pool Exhaustion
    THREAD_POOL_PATTERNS = [
        {
            'pattern': r'WSVR0605W.*Thread.*has been active for \d+ milliseconds',
            'severity': 'WARNING',
            'category': 'HUNG_THREAD',
            'description': 'Thread has been active for extended period (possible hang)',
            'probable_cause': 'Slow backend service, database deadlock, or infinite loop',
            'remediation': 'Analyze thread dump to identify what thread is doing'
        },
        {
            'pattern': r'WSVR0606W.*Thread.*appears.*hung',
            'severity': 'ERROR',
            'category': 'HUNG_THREAD_DETECTED',
            'description': 'Thread appears to be hung',
            'probable_cause': 'Deadlock, waiting on unresponsive resource, or infinite loop',
            'remediation': 'Generate thread dump and analyze for deadlocks or blocking operations'
        },
        {
            'pattern': r'ThreadPool.*exhausted',
            'severity': 'ERROR',
            'category': 'THREAD_POOL_EXHAUSTED',
            'description': 'Thread pool has no available threads',
            'probable_cause': 'High request volume, slow request processing, or thread leaks',
            'remediation': 'Increase thread pool maximum size or investigate slow requests'
        }
    ]

    # Garbage Collection (from native logs)
    GC_PATTERNS = [
        {
            'pattern': r'<gc.*type="global".*totalTime="(\d+)"',
            'severity': 'INFO',
            'category': 'GC_EVENT',
            'description': 'Garbage collection event',
            'probable_cause': 'Normal JVM memory management',
            'remediation': 'Monitor for excessive GC frequency or duration'
        }
    ]

    # LTPA Key Regeneration
    LTPA_KEY_PATTERNS = [
        {
            'pattern': r'SECJ0013I.*LTPA.*keys.*created',
            'severity': 'INFO',
            'category': 'LTPA_KEY_GENERATED',
            'description': 'LTPA keys have been created or regenerated',
            'probable_cause': 'Administrative key regeneration or initial setup',
            'remediation': 'All active LTPA tokens issued with old keys are now invalid'
        },
        {
            'pattern': r'LTPA.*key.*regenerat',
            'severity': 'INFO',
            'category': 'LTPA_KEY_REGENERATED',
            'description': 'LTPA keys regenerated',
            'probable_cause': 'Scheduled key regeneration or manual trigger',
            'remediation': 'Verify key regeneration was intentional; may cause widespread auth failures'
        }
    ]

    # SSL/TLS Errors
    SSL_PATTERNS = [
        {
            'pattern': r'SSLHandshakeException',
            'severity': 'ERROR',
            'category': 'SSL_HANDSHAKE_FAILED',
            'description': 'SSL/TLS handshake failed',
            'probable_cause': 'Certificate validation failure, protocol mismatch, or cipher suite incompatibility',
            'remediation': 'Check certificate validity, trust store configuration, and TLS protocol versions'
        },
        {
            'pattern': r'CertPathBuilderException.*unable to find valid certification path',
            'severity': 'ERROR',
            'category': 'CERT_VALIDATION_FAILED',
            'description': 'Certificate validation failed - chain of trust broken',
            'probable_cause': 'Missing intermediate CA or root CA in trust store',
            'remediation': 'Import missing certificates into WebSphere trust store'
        },
        {
            'pattern': r'CertificateExpiredException',
            'severity': 'ERROR',
            'category': 'CERT_EXPIRED',
            'description': 'SSL certificate has expired',
            'probable_cause': 'Certificate validity period has ended',
            'remediation': 'Renew and import updated certificate'
        }
    ]

    # Authorization Errors
    AUTHZ_PATTERNS = [
        {
            'pattern': r'SECJ0053E.*Authorization.*failed',
            'severity': 'ERROR',
            'category': 'AUTHZ_FAILED',
            'description': 'Authorization failed - user lacks required role',
            'probable_cause': 'User does not have required role/group for resource',
            'remediation': 'Verify user role assignments and security constraints'
        },
        {
            'pattern': r'CWWSS9400E.*Forbidden',
            'severity': 'ERROR',
            'category': 'FORBIDDEN',
            'description': 'Access forbidden (HTTP 403)',
            'probable_cause': 'User authenticated but not authorized for resource',
            'remediation': 'Check security role mappings in application deployment descriptor'
        }
    ]

    # All patterns combined
    ALL_PATTERNS = (
        LTPA_PATTERNS +
        SSO_PATTERNS +
        SESSION_PATTERNS +
        THREAD_POOL_PATTERNS +
        GC_PATTERNS +
        LTPA_KEY_PATTERNS +
        SSL_PATTERNS +
        AUTHZ_PATTERNS
    )

    @classmethod
    def compile_patterns(cls) -> List[Dict[str, Any]]:
        """Compile all regex patterns for efficient matching"""
        compiled = []
        for pattern_def in cls.ALL_PATTERNS:
            compiled.append({
                'regex': re.compile(pattern_def['pattern'], re.IGNORECASE),
                'severity': pattern_def['severity'],
                'category': pattern_def['category'],
                'description': pattern_def['description'],
                'probable_cause': pattern_def['probable_cause'],
                'remediation': pattern_def['remediation']
            })
        return compiled

    @classmethod
    def get_patterns_by_category(cls, category: str) -> List[Dict[str, Any]]:
        """Get all patterns for a specific category"""
        return [p for p in cls.ALL_PATTERNS if p['category'].startswith(category)]

    @classmethod
    def get_critical_patterns(cls) -> List[Dict[str, Any]]:
        """Get patterns for critical errors only"""
        return [p for p in cls.ALL_PATTERNS if p['severity'] == 'ERROR']


class TimestampExtractor:
    """Extract timestamps from WebSphere log lines"""

    # WebSphere timestamp formats
    # [11/6/25 14:32:15:123 UTC]
    WAS_TIMESTAMP_PATTERN = re.compile(
        r'\[(\d+/\d+/\d+)\s+(\d+:\d+:\d+):\d+(?:\s+\w+)?\]'
    )

    # Alternative: [2025-11-06T14:32:15.123Z]
    ISO_TIMESTAMP_PATTERN = re.compile(
        r'\[?(\d{4}-\d{2}-\d{2})[T\s](\d{2}:\d{2}:\d{2})'
    )

    @classmethod
    def extract_timestamp(cls, line: str) -> str:
        """Extract timestamp from log line"""
        # Try WAS format first
        match = cls.WAS_TIMESTAMP_PATTERN.search(line)
        if match:
            date_part = match.group(1)
            time_part = match.group(2)
            # Convert MM/DD/YY to YYYY-MM-DD
            parts = date_part.split('/')
            if len(parts) == 3:
                month, day, year = parts
                # Convert 2-digit year to 4-digit
                if len(year) == 2:
                    year = '20' + year
                return f"{year}-{month.zfill(2)}-{day.zfill(2)} {time_part}"

        # Try ISO format
        match = cls.ISO_TIMESTAMP_PATTERN.search(line)
        if match:
            return f"{match.group(1)} {match.group(2)}"

        return None

    @classmethod
    def extract_gc_duration(cls, line: str) -> int:
        """Extract GC duration from GC log line (returns milliseconds)"""
        match = re.search(r'totalTime="(\d+)"', line)
        if match:
            return int(match.group(1))
        return 0


class LogLineClassifier:
    """Classify log lines by content type"""

    @staticmethod
    def is_stack_trace(line: str) -> bool:
        """Check if line is part of a stack trace"""
        return (
            line.strip().startswith('at ') or
            line.strip().startswith('Caused by:') or
            line.strip().startswith('... ') or
            'Exception' in line or
            'Error' in line
        )

    @staticmethod
    def is_ffdc_marker(line: str) -> bool:
        """Check if line indicates FFDC file creation"""
        return 'FFDC' in line and ('created' in line or 'Incident' in line)

    @staticmethod
    def get_severity_from_line(line: str) -> str:
        """Extract severity level from log line"""
        if re.search(r'\s+E\s+', line) or 'ERROR' in line.upper():
            return 'ERROR'
        elif re.search(r'\s+W\s+', line) or 'WARN' in line.upper():
            return 'WARNING'
        elif re.search(r'\s+I\s+', line) or 'INFO' in line.upper():
            return 'INFO'
        elif re.search(r'\s+A\s+', line) or 'AUDIT' in line.upper():
            return 'AUDIT'
        else:
            return 'UNKNOWN'


# Test function
if __name__ == '__main__':
    print("Security Pattern Definitions")
    print("=" * 70)

    print(f"\nTotal patterns defined: {len(SecurityPatterns.ALL_PATTERNS)}")
    print(f"LTPA patterns: {len(SecurityPatterns.LTPA_PATTERNS)}")
    print(f"SSO patterns: {len(SecurityPatterns.SSO_PATTERNS)}")
    print(f"Session patterns: {len(SecurityPatterns.SESSION_PATTERNS)}")
    print(f"Thread pool patterns: {len(SecurityPatterns.THREAD_POOL_PATTERNS)}")
    print(f"GC patterns: {len(SecurityPatterns.GC_PATTERNS)}")
    print(f"SSL patterns: {len(SecurityPatterns.SSL_PATTERNS)}")

    # Test timestamp extraction
    print("\n" + "=" * 70)
    print("Timestamp Extraction Tests")
    print("=" * 70)

    test_lines = [
        "[11/6/25 14:32:15:123 UTC] SECJ0314E: LTPA token expired",
        "[2025-11-06T14:32:15.123Z] ERROR: Authentication failed",
        "[11/06/25 9:05:30:456] INFO: Server started"
    ]

    for line in test_lines:
        timestamp = TimestampExtractor.extract_timestamp(line)
        print(f"Line: {line}")
        print(f"Extracted: {timestamp}\n")
