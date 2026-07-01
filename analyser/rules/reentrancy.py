"""Rule: reentrancy detector.

Flags functions that make external calls (.call / .transfer / .send)
BEFORE updating state variables, which is the classic reentrancy pattern.
"""
import re
from collections import namedtuple

Finding = namedtuple('Finding', ['rule', 'severity', 'fn_name', 'line', 'detail'])

# Patterns that indicate an external call
_EXT_CALL = re.compile(
    r'(\.call\s*[({]|\.transfer\s*\(|\.send\s*\(|address\([^)]+\)\.call)',
    re.IGNORECASE
)
# Patterns that indicate a state-variable update (simplified)
_STATE_WRITE = re.compile(
    r'(balances|balance|totalSupply|owner|approved|allowance)\s*[\[\(]?.*?\s*[-+]?=(?!=)',
    re.IGNORECASE
)


def check(fn_name: str, body: str, start_line: int = 0):
    """Return a list of Finding if the function looks reentrancy-prone."""
    findings = []
    lines = body.splitlines()
    first_ext_call_line = None
    state_write_after_call = False

    for i, line in enumerate(lines):
        abs_line = start_line + i
        if first_ext_call_line is None and _EXT_CALL.search(line):
            first_ext_call_line = abs_line
        if first_ext_call_line is not None and _STATE_WRITE.search(line):
            state_write_after_call = True
            findings.append(Finding(
                rule='reentrancy',
                severity='HIGH',
                fn_name=fn_name,
                line=abs_line,
                detail=(
                    f'State variable mutated on line {abs_line} '
                    f'AFTER external call on line {first_ext_call_line}. '
                    'Apply Checks-Effects-Interactions pattern.'
                )
            ))
            break  # one finding per function is enough

    return findings
