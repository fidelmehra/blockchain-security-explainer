"""Rule: low-level call usage (.call, .delegatecall, .staticcall).

Low-level calls bypass Solidity type checks and don't revert on failure
unless the return value is manually checked.
"""
import re
from collections import namedtuple

Finding = namedtuple('Finding', ['rule', 'severity', 'fn_name', 'line', 'detail'])

_LOW_LEVEL = re.compile(
    r'\.(?:call|delegatecall|staticcall)\s*[({]',
    re.IGNORECASE
)
_RETURN_CHECK = re.compile(r'\(bool\s+\w+', re.IGNORECASE)


def check(fn_name: str, body: str, start_line: int = 0):
    findings = []
    lines = body.splitlines()
    for i, line in enumerate(lines):
        if _LOW_LEVEL.search(line):
            # Check same line or next line for return-value capture
            context = line + (lines[i + 1] if i + 1 < len(lines) else '')
            if not _RETURN_CHECK.search(context):
                findings.append(Finding(
                    rule='low_level_call',
                    severity='HIGH',
                    fn_name=fn_name,
                    line=start_line + i,
                    detail=(
                        f'Unchecked low-level call on line {start_line + i}. '
                        'Capture return value: (bool success, ) = addr.call{...}(data); '
                        'require(success, "call failed");'
                    )
                ))
    return findings
