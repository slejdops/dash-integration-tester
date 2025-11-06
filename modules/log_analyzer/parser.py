#!/usr/bin/env python3
"""
WebSphere Log Parser for LTPA Diagnostics
Parses SystemOut.log, SystemErr.log, and FFDC files for security errors
"""

import re
import os
import sys
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from pathlib import Path

# Import pattern definitions
try:
    from .patterns import SecurityPatterns, TimestampExtractor, LogLineClassifier
except ImportError:
    from patterns import SecurityPatterns, TimestampExtractor, LogLineClassifier


class LogEntry:
    """Represents a single log entry with metadata"""

    def __init__(self, timestamp: Optional[str], line: str, file_path: str, line_number: int):
        self.timestamp = timestamp
        self.line = line
        self.file_path = file_path
        self.line_number = line_number
        self.severity = LogLineClassifier.get_severity_from_line(line)
        self.matched_patterns = []
        self.stack_trace = []

    def add_stack_trace_line(self, line: str):
        """Add a line to the stack trace"""
        self.stack_trace.append(line)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            'timestamp': self.timestamp,
            'line': self.line.strip(),
            'file': os.path.basename(self.file_path),
            'line_number': self.line_number,
            'severity': self.severity,
            'matched_patterns': [
                {
                    'category': p['category'],
                    'description': p['description'],
                    'probable_cause': p['probable_cause'],
                    'remediation': p['remediation']
                }
                for p in self.matched_patterns
            ],
            'stack_trace': self.stack_trace[:10]  # Limit stack trace length
        }


class LogParser:
    """Parse WebSphere log files for security-related events"""

    def __init__(self, log_directory: str, verbose: bool = False):
        self.log_directory = Path(log_directory)
        self.verbose = verbose
        self.compiled_patterns = SecurityPatterns.compile_patterns()
        self.entries = []
        self.gc_events = []

    def parse_file(self, file_path: Path, patterns_filter: List[str] = None):
        """Parse a single log file"""
        if not file_path.exists():
            print(f"[WARN] Log file not found: {file_path}")
            return

        print(f"[INFO] Parsing {file_path.name}...")

        line_count = 0
        match_count = 0
        current_entry = None

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    line_count += 1

                    # Extract timestamp
                    timestamp = TimestampExtractor.extract_timestamp(line)

                    # Check if this is a continuation of previous entry (stack trace)
                    if current_entry and LogLineClassifier.is_stack_trace(line):
                        current_entry.add_stack_trace_line(line.strip())
                        continue

                    # This is a new log entry
                    if timestamp or line_num == 1:
                        current_entry = LogEntry(timestamp, line, str(file_path), line_num)

                        # Match against patterns
                        for pattern_def in self.compiled_patterns:
                            # Skip if patterns_filter specified and this pattern doesn't match
                            if patterns_filter and pattern_def['category'] not in patterns_filter:
                                continue

                            if pattern_def['regex'].search(line):
                                current_entry.matched_patterns.append(pattern_def)
                                match_count += 1

                                if self.verbose:
                                    print(f"[MATCH] {pattern_def['category']}: {line.strip()[:80]}")

                        # Add to entries if it matched any pattern
                        if current_entry.matched_patterns:
                            self.entries.append(current_entry)

                        # Special handling for GC events
                        if 'GC_EVENT' in [p['category'] for p in current_entry.matched_patterns]:
                            gc_duration = TimestampExtractor.extract_gc_duration(line)
                            if gc_duration > 1000:  # Only track GC > 1 second
                                self.gc_events.append({
                                    'timestamp': timestamp,
                                    'duration_ms': gc_duration,
                                    'file': str(file_path),
                                    'line_number': line_num
                                })

        except Exception as e:
            print(f"[ERROR] Failed to parse {file_path}: {e}")

        print(f"[INFO] Parsed {line_count} lines, found {match_count} matches in {file_path.name}")

    def parse_system_out(self):
        """Parse SystemOut.log"""
        system_out = self.log_directory / "SystemOut.log"
        self.parse_file(system_out)

    def parse_system_err(self):
        """Parse SystemErr.log"""
        system_err = self.log_directory / "SystemErr.log"
        self.parse_file(system_err)

    def parse_ffdc_files(self):
        """Parse FFDC files"""
        print(f"[INFO] Searching for FFDC files in {self.log_directory / 'ffdc'}...")

        ffdc_dir = self.log_directory / "ffdc"
        if not ffdc_dir.exists():
            print(f"[WARN] FFDC directory not found: {ffdc_dir}")
            return

        ffdc_files = list(ffdc_dir.glob("*.txt"))
        print(f"[INFO] Found {len(ffdc_files)} FFDC files")

        # Limit to most recent 50 files to avoid overwhelming analysis
        ffdc_files.sort(key=lambda x: x.stat().st_mtime, reverse=True)
        for ffdc_file in ffdc_files[:50]:
            self.parse_file(ffdc_file)

    def parse_gc_logs(self):
        """Parse native_stdout.log or verbosegc logs for GC events"""
        # Try various GC log names
        gc_log_candidates = [
            "native_stdout.log",
            "verbosegc.log",
            "gc.log"
        ]

        for gc_log_name in gc_log_candidates:
            gc_log = self.log_directory / gc_log_name
            if gc_log.exists():
                print(f"[INFO] Parsing GC log: {gc_log.name}")
                self.parse_file(gc_log, patterns_filter=['GC_EVENT'])
                break

    def parse_all(self):
        """Parse all standard WebSphere log files"""
        self.parse_system_out()
        self.parse_system_err()
        self.parse_ffdc_files()
        self.parse_gc_logs()

    def filter_by_time_window(self, center_time: datetime, window_minutes: int = 5):
        """Filter entries to those within time window of specified time"""
        print(f"[INFO] Filtering entries within ±{window_minutes} minutes of {center_time}")

        filtered_entries = []
        start_time = center_time - timedelta(minutes=window_minutes)
        end_time = center_time + timedelta(minutes=window_minutes)

        for entry in self.entries:
            if not entry.timestamp:
                continue

            try:
                # Parse timestamp
                entry_time = datetime.strptime(entry.timestamp, "%Y-%m-%d %H:%M:%S")

                if start_time <= entry_time <= end_time:
                    filtered_entries.append(entry)

            except ValueError as e:
                if self.verbose:
                    print(f"[WARN] Could not parse timestamp: {entry.timestamp} - {e}")

        print(f"[INFO] Filtered to {len(filtered_entries)} entries (from {len(self.entries)} total)")
        return filtered_entries

    def filter_by_category(self, categories: List[str]):
        """Filter entries by pattern category"""
        filtered_entries = []

        for entry in self.entries:
            for pattern in entry.matched_patterns:
                if pattern['category'] in categories:
                    filtered_entries.append(entry)
                    break

        print(f"[INFO] Filtered to {len(filtered_entries)} entries matching categories {categories}")
        return filtered_entries

    def get_statistics(self) -> Dict[str, Any]:
        """Get statistics about parsed entries"""
        category_counts = {}
        severity_counts = {'ERROR': 0, 'WARNING': 0, 'INFO': 0, 'UNKNOWN': 0}

        for entry in self.entries:
            severity_counts[entry.severity] = severity_counts.get(entry.severity, 0) + 1

            for pattern in entry.matched_patterns:
                category = pattern['category']
                category_counts[category] = category_counts.get(category, 0) + 1

        return {
            'total_entries': len(self.entries),
            'by_severity': severity_counts,
            'by_category': category_counts,
            'gc_events': len(self.gc_events),
            'long_gc_events': len([g for g in self.gc_events if g['duration_ms'] > 3000])
        }

    def print_summary(self):
        """Print summary of parsed results"""
        stats = self.get_statistics()

        print("\n" + "=" * 70)
        print("LOG ANALYSIS SUMMARY")
        print("=" * 70)
        print(f"Total matching log entries: {stats['total_entries']}")
        print(f"\nBy Severity:")
        for severity, count in sorted(stats['by_severity'].items()):
            if count > 0:
                print(f"  {severity}: {count}")

        print(f"\nBy Category:")
        for category, count in sorted(stats['by_category'].items(), key=lambda x: x[1], reverse=True):
            if count > 0:
                print(f"  {category}: {count}")

        if stats['gc_events'] > 0:
            print(f"\nGarbage Collection:")
            print(f"  Total GC events: {stats['gc_events']}")
            print(f"  Long GC pauses (>3s): {stats['long_gc_events']}")

            if stats['long_gc_events'] > 0:
                print("\n  Long GC Events:")
                for gc in sorted(self.gc_events, key=lambda x: x['duration_ms'], reverse=True)[:5]:
                    print(f"    {gc['timestamp']}: {gc['duration_ms']}ms")

    def export_to_json(self) -> Dict[str, Any]:
        """Export parsed entries to JSON-serializable format"""
        return {
            'analysis_timestamp': datetime.now().isoformat(),
            'log_directory': str(self.log_directory),
            'statistics': self.get_statistics(),
            'entries': [entry.to_dict() for entry in self.entries],
            'gc_events': self.gc_events
        }


def main():
    """Command-line interface for log parser"""
    import argparse
    import json

    parser = argparse.ArgumentParser(description='Parse WebSphere logs for LTPA/security issues')
    parser.add_argument('--log-dir', required=True, help='Path to WebSphere log directory')
    parser.add_argument('--output', help='Output JSON file (optional)')
    parser.add_argument('--time-filter', help='Filter to time window: "YYYY-MM-DD HH:MM:SS" (±5 min)')
    parser.add_argument('--category-filter', help='Filter by category (comma-separated)')
    parser.add_argument('--verbose', action='store_true', help='Verbose output')

    args = parser.parse_args()

    # Initialize parser
    log_parser = LogParser(args.log_dir, verbose=args.verbose)

    # Parse all logs
    log_parser.parse_all()

    # Apply filters if specified
    entries_to_display = log_parser.entries

    if args.time_filter:
        try:
            center_time = datetime.strptime(args.time_filter, "%Y-%m-%d %H:%M:%S")
            entries_to_display = log_parser.filter_by_time_window(center_time)
        except ValueError as e:
            print(f"[ERROR] Invalid time format: {e}")
            sys.exit(1)

    if args.category_filter:
        categories = [c.strip() for c in args.category_filter.split(',')]
        entries_to_display = log_parser.filter_by_category(categories)

    # Print summary
    log_parser.print_summary()

    # Print matching entries
    if entries_to_display:
        print("\n" + "=" * 70)
        print("MATCHING LOG ENTRIES")
        print("=" * 70)

        for entry in entries_to_display[:50]:  # Limit to first 50
            print(f"\n[{entry.timestamp}] {entry.severity} - {os.path.basename(entry.file_path)}:{entry.line_number}")
            print(f"  {entry.line.strip()}")

            for pattern in entry.matched_patterns:
                print(f"  → {pattern['category']}: {pattern['description']}")

            if entry.stack_trace:
                print(f"  Stack trace ({len(entry.stack_trace)} lines):")
                for trace_line in entry.stack_trace[:3]:
                    print(f"    {trace_line}")

    # Export to JSON if requested
    if args.output:
        data = log_parser.export_to_json()
        # Override entries with filtered ones if filters applied
        if entries_to_display != log_parser.entries:
            data['entries'] = [e.to_dict() for e in entries_to_display]

        with open(args.output, 'w') as f:
            json.dump(data, f, indent=2)
        print(f"\n[SUCCESS] Exported results to {args.output}")


if __name__ == '__main__':
    main()
