"""
analyser/engine.py
Orchestrates all vulnerability rules over a Solidity source file.
Author: Fidel Mehra
"""

import re
from .rules import reentrancy, tx_origin, low_level, overflow, selfdestruct, timestamp, delegatecall, zero_address

ALL_RULES = [
    reentrancy,
    tx_origin,
    low_level,
    overflow,
    selfdestruct,
    timestamp,
    delegatecall,
    zero_address,
]

class ScanEngine:
    def __init__(self, rules=None):
        self.rules = rules or ALL_RULES

    def scan(self, filepath):
        """Scan a single .sol file and return a list of findings."""
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            source = f.read()

        lines = source.splitlines()
        functions = self._extract_functions(source)
        findings = []

        for rule_module in self.rules:
            try:
                results = rule_module.check(source, lines, functions, filepath)
                findings.extend(results)
            except Exception as e:
                findings.append({
                    "rule_id": "ERR",
                    "severity": "LOW",
                    "file": filepath,
                    "line": 0,
                    "code": "",
                    "message": f"Rule {rule_module.__name__} error: {e}"
                })

        return findings

    def _extract_functions(self, source):
        """
        Extract individual function bodies as (name, start_line, body_text) tuples.
        Uses a brace-counting approach - not a full parser, but handles most patterns.
        """
        functions = []
        fn_header = re.compile(
            r'function\s+(\w+)\s*\([^)]*\)[^{]*\{',
            re.MULTILINE | re.DOTALL
        )
        lines = source.splitlines()

        for match in fn_header.finditer(source):
            name = match.group(1)
            start = match.start()
            start_line = source[:start].count('\n') + 1

            # Count braces to find end of function
            depth = 0
            i = match.start()
            body_start = source.find('{', i)
            i = body_start
            while i < len(source):
                if source[i] == '{':
                    depth += 1
                elif source[i] == '}':
                    depth -= 1
                    if depth == 0:
                        body = source[body_start:i+1]
                        functions.append((name, start_line, body))
                        break
                i += 1

        return functions
