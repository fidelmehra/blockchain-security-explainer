"""Rules package – each module exposes a `check(fn_name, body)` function
that returns a list of Finding namedtuples.
"""
from analyser.rules import reentrancy, tx_origin, low_level_call, unchecked_return, selfdestruct

ALL_RULES = [
    reentrancy,
    tx_origin,
    low_level_call,
    unchecked_return,
    selfdestruct,
]
