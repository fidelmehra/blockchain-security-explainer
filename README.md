# solidity-vuln-scanner

**Author: Fidel Mehra**

A Python-based static analysis tool that scans Solidity smart contracts for known vulnerability patterns — without requiring compilation or external tooling. Detects issues that have caused hundreds of millions in real-world losses.

## Problem It Solves

Existing tools like Slither and Mythril are powerful but heavyweight — they require a full Solidity compiler setup, ABI resolution, and significant overhead. This tool fills the gap for:
- **Quick CI/CD pre-commit hooks** that need lightweight scanning
- **Learning / auditing workflows** where you want transparent, readable detection logic
- **Custom rule authoring** without learning a DSL

## Vulnerability Patterns Detected

| ID | Pattern | Real-World Example |
|----|---------|-------------------|
| V01 | Reentrancy (`external call before state update`) | The DAO Hack ($60M, 2016) |
| V02 | `tx.origin` authentication | Phishing wallet drains |
| V03 | Unchecked low-level calls (`call`, `send`, `delegatecall`) | King of Ether bug |
| V04 | Integer overflow/underflow (pre-0.8.x) | BEC Token ($900M, 2018) |
| V05 | Unprotected `selfdestruct` | Parity Wallet ($30M, 2017) |
| V06 | Block timestamp dependence | Randomness manipulation |
| V07 | Unprotected `DELEGATECALL` | Parity Library Hack |
| V08 | Hardcoded `address(0)` checks missing | Token burn exploits |

## Quick Start

```bash
git clone https://github.com/fidelmehra/blockchain-security-explainer
cd blockchain-security-explainer
pip install -r requirements.txt

# Scan a single file
python scanner.py contracts/VulnerableToken.sol

# Scan a directory
python scanner.py contracts/

# JSON output (for CI integration)
python scanner.py contracts/ --format json
```

## Example Output

```
[CRITICAL] V01 Reentrancy detected
  File: contracts/VulnerableToken.sol
  Line: 42
  Code: token.transfer(msg.sender, amount);
  Note: External call precedes state update on line 44 (balances[msg.sender] = 0)

[HIGH]     V02 tx.origin authentication
  File: contracts/VulnerableToken.sol
  Line: 18
  Code: require(tx.origin == owner);
  Note: Use msg.sender instead - tx.origin is spoofable via intermediary contract

[MEDIUM]   V06 Block timestamp dependence
  File: contracts/VulnerableToken.sol
  Line: 77
  Code: require(block.timestamp > deadline);
  Note: Miners can manipulate block.timestamp by ~30s

Summary: 3 issues found (1 CRITICAL, 1 HIGH, 1 MEDIUM)
```

## Architecture

```
scanner.py           # CLI entrypoint
analyser/
  engine.py          # Orchestrates rule execution over AST/regex IR
  rules/
    reentrancy.py    # V01 - CEI pattern violation detection
    tx_origin.py     # V02 - tx.origin auth
    low_level.py     # V03 - unchecked call/send/delegatecall
    overflow.py      # V04 - arithmetic without SafeMath / pre-0.8
    selfdestruct.py  # V05 - unprotected selfdestruct
    timestamp.py     # V06 - block.timestamp in conditions
    delegatecall.py  # V07 - unprotected delegatecall
    zero_address.py  # V08 - missing address(0) checks
  reporter.py        # Terminal + JSON output formatting
contracts/
  VulnerableToken.sol   # Deliberately vulnerable test contract
  SafeToken.sol         # Fixed version for comparison
tests/
  test_rules.py         # Unit tests per vulnerability rule
```

## Methodology

The scanner uses a two-pass approach:
1. **Regex IR pass** — fast pattern matching for obvious signatures
2. **Context-aware pass** — tracks call/state-update ordering within function bodies to catch CEI violations

This avoids the false negative problem of purely regex-based tools while remaining dependency-light.

## Requirements

```
python >= 3.9
colorama
```

## Limitations & Future Work
- No full AST parsing (planned: integrate `py-solc-ast`)
- No cross-contract taint tracking (planned)
- Currently targets Solidity 0.6–0.8.x patterns

## References
- [SWC Registry](https://swcregistry.io/) — Smart Contract Weakness Classification
- [Consensys Best Practices](https://consensys.github.io/smart-contract-best-practices/)
- The DAO attack post-mortem, Parity multi-sig incident reports
