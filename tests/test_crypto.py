#!/usr/bin/env python3
"""Verify the from-scratch secp256k1 implementation.

Hand-written elliptic-curve code is exactly the kind of thing that is subtly
wrong in ways that still appear to work: a broken implementation happily signs
and verifies its own signatures while producing points that are not on the
curve or a group order that is wrong. So this checks against PUBLISHED test
vectors and curve invariants, not just round-trips.

Run:  python3 tests/test_crypto.py
"""

import os
import sys

sys.path.insert(0, os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "blockchain-node"))

from node import crypto as c   # noqa: E402

failures, passes = [], []


def check(name, condition, detail=""):
    (passes if condition else failures).append(name if condition else f"{name}: {detail}")
    print(("  ok    " if condition else "  FAIL  ") + name + (f"  {detail}" if not condition else ""))


# --- Published scalar multiples of the generator ---------------------------
# Source: standard secp256k1 test vectors (SEC 2 / widely republished).
VECTORS = {
    1:  (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
         0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8),
    2:  (0xC6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5,
         0x1AE168FEA63DC339A3C58419466CEAEEF7F632653266D0E1236431A950CFE52A),
    3:  (0xF9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9,
         0x388F7B0F632DE8140FE337E62A37F3566500A99934C2231B6CB9FD7584B8E672),
    15: (0xD7924D4F7D43EA965A465AE3095FF41131E5946F3C85F79E44ADBCF8E27E080E,
         0x581E2872A86C72A683842EC228CC6DEFEA40AF2BD896D3A5C504DC9FF6A26B58),
}

print("\npublished test vectors")
for k, expected in VECTORS.items():
    check(f"{k}G matches published vector", c.point_mul(k, c.G) == expected)

print("\ncurve invariants")
for k in (1, 2, 3, 15, 9999, c.N - 1):
    x, y = c.point_mul(k, c.G)
    check(f"{k if k < 9999 else 'large'}G satisfies y^2 = x^3 + 7",
          (y * y - (x * x * x + 7)) % c.P == 0)
check("N*G is the point at infinity", c.point_mul(c.N, c.G) is None)
check("(N-1)G + G is the point at infinity",
      c.point_add(c.point_mul(c.N - 1, c.G), c.G) is None)

print("\nRFC 6979 deterministic nonces")
h = c.sha3(b"determinism")
check("identical inputs produce identical signatures", c.sign(1, h) == c.sign(1, h))
check("different messages produce different signatures",
      c.sign(1, h) != c.sign(1, c.sha3(b"other")))

print("\nsign / verify")
all_ok = True
for _ in range(25):
    k = c.generate_private_key()
    pub = c.private_to_public(k)
    msg = c.sha3(os.urandom(32))
    if not c.verify(pub, msg, c.sign(k, msg)):
        all_ok = False
        break
check("25 random sign/verify round trips", all_ok)

print("\nnegative cases (these must all be rejected)")
k1, k2 = c.generate_private_key(), c.generate_private_key()
pub1, pub2 = c.private_to_public(k1), c.private_to_public(k2)
msg = c.sha3(b"the real message")
sig = c.sign(k1, msg)
r, s = sig

check("rejects a different public key", not c.verify(pub2, msg, sig))
check("rejects a tampered message", not c.verify(pub1, c.sha3(b"the fake message"), sig))
check("rejects a tampered r", not c.verify(pub1, msg, (r ^ 1, s)))
check("rejects a tampered s", not c.verify(pub1, msg, (r, s ^ 1)))
check("rejects r = 0", not c.verify(pub1, msg, (0, s)))
check("rejects s = 0", not c.verify(pub1, msg, (r, 0)))
check("rejects r >= N", not c.verify(pub1, msg, (c.N, s)))

print("\nsignature malleability (EIP-2 low-s rule)")
# Both s and N-s verify under textbook ECDSA. If high-s were accepted, an
# attacker could flip a validator's signature into a second, different-looking
# signature over the same block - and the slashing detector, which keys on
# "did this validator sign two different things", would report a false
# double-signing offence. This rule is load-bearing for BC-004.
check("produces only low-s signatures", s <= c.N // 2)
check("rejects the malleated high-s form", not c.verify(pub1, msg, (r, c.N - s)))

print("\nserialization")
check("public key round trip", c.deserialize_pubkey(c.serialize_pubkey(pub1)) == pub1)
check("signature round trip", c.deserialize_sig(c.serialize_sig(sig)) == sig)
addr = c.public_to_address(pub1)
check("address is 20 bytes of hex", addr.startswith("0x") and len(addr) == 42)
check("address derivation is deterministic", c.public_to_address(pub1) == addr)
check("distinct keys give distinct addresses", c.public_to_address(pub2) != addr)

print(f"\n{'=' * 70}")
print(f"  {len(passes)} passed, {len(failures)} failed")
print("=" * 70)
if failures:
    print("\nFAILURES:")
    for f in failures:
        print(f"  x {f}")
    sys.exit(1)
print("\nsecp256k1 implementation verified against published vectors.\n")
sys.exit(0)
