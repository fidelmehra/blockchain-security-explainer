# Blockchain Security Demos - Author: Fidel Mehra
# Demonstrates: hashing, ECDSA signatures, replay attacks, 51% attack concepts

import hashlib
import os
import time
from ecdsa import SigningKey, SECP256k1, BadSignatureError

# ============================================================
# 1. SHA-256 & SHA-3 Hashing
# ============================================================
def demo_hashing():
    print("\n=== 1. Hashing Demo ===")
    msg = b"Blockchain Security by Fidel Mehra"
    sha256 = hashlib.sha256(msg).hexdigest()
    sha3   = hashlib.sha3_256(msg).hexdigest()
    print(f"Message : {msg.decode()}")
    print(f"SHA-256 : {sha256}")
    print(f"SHA3-256: {sha3}")
    # Avalanche effect
    msg2 = b"Blockchain Security by Fidel Mehra."
    sha256_2 = hashlib.sha256(msg2).hexdigest()
    diff = sum(a != b for a, b in zip(sha256, sha256_2))
    print(f"\nAvalanche: 1-char change => {diff}/64 hex chars differ")

# ============================================================
# 2. ECDSA Key Generation, Signing & Verification
# ============================================================
def demo_ecdsa():
    print("\n=== 2. ECDSA Signature Demo ===")
    sk = SigningKey.generate(curve=SECP256k1)
    vk = sk.get_verifying_key()
    print(f"Private key: {sk.to_string().hex()[:20]}...")
    print(f"Public key : {vk.to_string().hex()[:20]}...")

    tx = b"Send 1 BTC to Alice"
    sig = sk.sign(tx)
    print(f"\nTransaction: {tx.decode()}")
    print(f"Signature  : {sig.hex()[:20]}...")

    try:
        vk.verify(sig, tx)
        print("Verification: VALID")
    except BadSignatureError:
        print("Verification: INVALID")

    # Tampered tx
    tampered = b"Send 10 BTC to Eve"
    try:
        vk.verify(sig, tampered)
        print("Tampered tx: VALID (bad!)")
    except BadSignatureError:
        print("Tampered tx: INVALID (good - signature mismatch)")

# ============================================================
# 3. Merkle Tree Construction
# ============================================================
def merkle_root(txs):
    if len(txs) == 1:
        return txs[0]
    if len(txs) % 2 != 0:
        txs.append(txs[-1])  # duplicate last tx
    next_level = []
    for i in range(0, len(txs), 2):
        combined = txs[i] + txs[i+1]
        next_level.append(hashlib.sha256(combined.encode()).hexdigest())
    return merkle_root(next_level)

def demo_merkle():
    print("\n=== 3. Merkle Tree Demo ===")
    transactions = ["tx1: Alice->Bob 1BTC", "tx2: Bob->Carol 0.5BTC",
                    "tx3: Carol->Dave 0.2BTC", "tx4: Eve->Frank 2BTC"]
    hashed = [hashlib.sha256(t.encode()).hexdigest() for t in transactions]
    root = merkle_root(hashed)
    print(f"Transactions: {transactions}")
    print(f"Merkle Root : {root}")

# ============================================================
# 4. Proof-of-Work (Mining Simulation)
# ============================================================
def demo_pow(difficulty=4):
    print(f"\n=== 4. Proof-of-Work (difficulty={difficulty}) ===")
    prefix = '0' * difficulty
    data = "Block #100 | prev_hash=abc123 | txs=[tx1,tx2,tx3]"
    nonce = 0
    start = time.time()
    while True:
        candidate = f"{data}|nonce={nonce}"
        h = hashlib.sha256(candidate.encode()).hexdigest()
        if h.startswith(prefix):
            elapsed = time.time() - start
            print(f"Nonce found : {nonce}")
            print(f"Hash        : {h}")
            print(f"Time taken  : {elapsed:.3f}s")
            break
        nonce += 1

# ============================================================
# 5. Private Key / Public Key / Address Generation
# ============================================================
def demo_wallet():
    print("\n=== 5. Wallet Key Generation ===")
    private_key = os.urandom(32)
    sk = SigningKey.from_string(private_key, curve=SECP256k1)
    vk = sk.get_verifying_key()
    pub_bytes = vk.to_string()
    address = "0x" + hashlib.sha256(pub_bytes).hexdigest()[-40:]
    print(f"Private Key : {private_key.hex()}")
    print(f"Public Key  : {pub_bytes.hex()[:40]}...")
    print(f"Address     : {address}")

# ============================================================
# Run All Demos
# ============================================================
if __name__ == "__main__":
    demo_hashing()
    demo_ecdsa()
    demo_merkle()
    demo_pow(difficulty=4)
    demo_wallet()
    print("\nAll blockchain security demos complete.")
