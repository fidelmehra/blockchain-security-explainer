"""Rule: unchecked ERC-20 return values.

ERC-20 tokens like USDT do not revert on failure - they return false.
Failing to check this can silently lose funds.
"""
import re
from collections import namedtuple

Finding = namedtuple('Finding', ['rule', 'severity', 'fn_name', 'line', 'detail'])

# Standalone .transfer() / .transferFrom() not preceded by a boolean assignment
_TRANSFER = re.compile(
    r'(?<!bool\s\w{1,40}\s=\s)\b\w+\.transferFrom?\s*\(',
    re.IGNORECASE
)
_BOOL_ASSIGN = re.compile(r'bool\s+\w+\s*=', re.IGNORECASE)


def check(fn_name: str, body: str, start_line: int = 0):
    findings = []
    for i, line in enumerate(body.splitlines()):
        stripped = line.strip()
        # Flag transfer/transferFrom that are bare statements (not assigned)
        if _TRANSFER.search(stripped) and not _BOOL_ASSIGN.search(stripped):
            # Skip if wrapped in require() - that's fine
            if not stripped.startswith('require'):
                findings.append(Finding(
                    rule='unchecked_return',
                    severity='MEDIUM',
                    fn_name=fn_name,
                    line=start_line + i,
                    detail=(
                        f'ERC-20 return value not checked on line {start_line + i}. '
                        'Wrap with SafeERC20 or require(token.transfer(...), "failed");'
                    )
                ))
    return findings
