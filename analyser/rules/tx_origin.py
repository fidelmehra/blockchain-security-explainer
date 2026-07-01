"""Rule: tx.origin authentication.

Using tx.origin for authorisation is dangerous: a malicious contract
called by the legitimate user can hijack the call.
"""
import re
from collections import namedtuple

Finding = namedtuple('Finding', ['rule', 'severity', 'fn_name', 'line', 'detail'])

_TX_ORIGIN = re.compile(r'tx\.origin', re.IGNORECASE)


def check(fn_name: str, body: str, start_line: int = 0):
    findings = []
    for i, line in enumerate(body.splitlines()):
        if _TX_ORIGIN.search(line):
            findings.append(Finding(
                rule='tx_origin',
                severity='MEDIUM',
                fn_name=fn_name,
                line=start_line + i,
                detail=(
                    'tx.origin used for authorisation. '
                    'Replace with msg.sender to prevent phishing attacks.'
                )
            ))
    return findings
