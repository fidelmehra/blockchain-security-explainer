#!/usr/bin/env python3
"""
scanner.py - CLI entrypoint for the Solidity Vulnerability Scanner
Author: Fidel Mehra
Usage:
  python scanner.py <file_or_dir> [--format text|json]
"""

import argparse
import sys
import os
from analyser.engine import ScanEngine
from analyser.reporter import Reporter

def collect_sol_files(path):
    if os.path.isfile(path):
        return [path] if path.endswith(".sol") else []
    sol_files = []
    for root, _, files in os.walk(path):
        for f in files:
            if f.endswith(".sol"):
                sol_files.append(os.path.join(root, f))
    return sol_files

def main():
    parser = argparse.ArgumentParser(
        description="Lightweight Solidity smart contract vulnerability scanner"
    )
    parser.add_argument("target", help="Solidity file or directory to scan")
    parser.add_argument(
        "--format", choices=["text", "json"], default="text",
        help="Output format (default: text)"
    )
    parser.add_argument(
        "--min-severity", choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
        default="LOW", help="Minimum severity to report"
    )
    args = parser.parse_args()

    sol_files = collect_sol_files(args.target)
    if not sol_files:
        print(f"No .sol files found at: {args.target}")
        sys.exit(1)

    engine = ScanEngine()
    all_findings = []
    for filepath in sol_files:
        findings = engine.scan(filepath)
        all_findings.extend(findings)

    reporter = Reporter(format=args.format, min_severity=args.min_severity)
    reporter.report(all_findings)

    critical = sum(1 for f in all_findings if f["severity"] == "CRITICAL")
    sys.exit(1 if critical > 0 else 0)

if __name__ == "__main__":
    main()
