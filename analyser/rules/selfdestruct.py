"""Rule: selfdestruct / suicide usage.

selfdestruct sends contract ETH balance to an arbitrary address and
destroys contract bytecode. It should never be callable by untrusted
parties and is deprecated in newer EVM versions (EIP-6049).
"""
import re
from collections import namedtuple

Finding = namedtuple('Finding', ['rule', 'severity', 'fn_name', 'line', 'detail'])

_SELFDESTRUCT = re.compile(r'\b(selfdestruct|suicide)\s*\(', re.IGNORECASE)


def check(fn_name: str, body: str, start_line: int = 0):
    findings = []
    for i, line in enumerate(body.splitlines()):
        if _SELFDESTRUCT.search(line):
            findings.append(Finding(
                rule='selfdestruct',
                severity='CRITICAL',
                fn_name=fn_name,
                line=start_line + i,
                detail=(
                    f'selfdestruct() found on line {start_line + i} in function "{fn_name}". '
                    'Ensure it is protected by onlyOwner or equivalent. '
                    'Consider removing it entirely (EIP-6049 deprecation).'
                )
            ))
    return findings
