"""secp256k1 ECDSA, implemented from scratch.

WHY NO LIBRARY: this node has zero third-party crypto dependencies, so it runs
anywhere Python does. The curve is the real secp256k1 Ethereum uses, and
signatures are real ECDSA -- which matters for this project, because the
slashing detection in consensus.py is only meaningful if a validator signature
genuinely binds a validator identity to a block. A HMAC stand-in would make
double-sign detection a simulation of a simulation.

SECURITY WARNING: this is a readable reference implementation for a testnet
whose keys are generated at startup and thrown away. It is NOT constant-time,
makes no attempt to resist side-channel attacks, and must never be used to
hold value. Use `coincurve` (libsecp256k1 bindings) for anything real.

HASHING NOTE: Ethereum uses Keccak-256, which differs from the finalised
NIST SHA3-256 standard in its padding rule. Python's hashlib ships SHA3-256,
not Keccak-256, so this node uses SHA3-256 throughout. Addresses produced here
are therefore NOT Ethereum-compatible. That is a deliberate, documented
simplification: this chain is a monitored workload, not a wallet.
"""

import hashlib
import hmac
import os

# secp256k1 domain parameters (SEC 2, section 2.4.1).
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
A = 0
B = 7
GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
G = (GX, GY)


def _inv(x: int, m: int) -> int:
    """Modular inverse. Python 3.8+ pow() handles negative exponents."""
    return pow(x, -1, m)


def point_add(p1, p2):
    """Add two points on the curve, in affine coordinates."""
    if p1 is None:
        return p2
    if p2 is None:
        return p1

    x1, y1 = p1
    x2, y2 = p2

    if x1 == x2 and (y1 + y2) % P == 0:
        return None  # point at infinity

    if p1 == p2:
        # Tangent line: lambda = (3x^2 + a) / 2y
        lam = (3 * x1 * x1 + A) * _inv(2 * y1, P) % P
    else:
        lam = (y2 - y1) * _inv(x2 - x1, P) % P

    x3 = (lam * lam - x1 - x2) % P
    y3 = (lam * (x1 - x3) - y1) % P
    return (x3, y3)


def point_mul(k: int, point=G):
    """Scalar multiplication by double-and-add.

    Deliberately simple and NOT constant-time: the loop branches on the bits
    of k, which leaks the private key through timing to anyone who can measure
    it. Acceptable only because these keys are ephemeral testnet keys.
    """
    if k % N == 0 or point is None:
        return None
    if k < 0:
        x, y = point_mul(-k, point)
        return (x, (-y) % P)

    result = None
    addend = point
    while k:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        k >>= 1
    return result


def sha3(data: bytes) -> bytes:
    return hashlib.sha3_256(data).digest()


def generate_private_key() -> int:
    """A uniformly random scalar in [1, N-1]."""
    while True:
        k = int.from_bytes(os.urandom(32), "big")
        if 1 <= k < N:
            return k


def private_to_public(privkey: int) -> tuple:
    return point_mul(privkey, G)


def public_to_address(pubkey: tuple) -> str:
    """Address = last 20 bytes of SHA3-256 over the uncompressed public key.

    Mirrors Ethereum's construction (hash the 64-byte public key, take the low
    20 bytes) but with SHA3-256 rather than Keccak-256, so the addresses look
    right and are not interchangeable with real ones.
    """
    x, y = pubkey
    raw = x.to_bytes(32, "big") + y.to_bytes(32, "big")
    return "0x" + sha3(raw)[-20:].hex()


def _deterministic_k(privkey: int, msg_hash: bytes) -> int:
    """RFC 6979 deterministic nonce.

    Using a random nonce here would be a correctness hazard rather than just a
    style choice: if the same nonce is ever reused across two signatures, the
    private key is recoverable from the pair by simple algebra. Deterministic
    nonces remove that failure mode entirely, and they make the node's
    behaviour reproducible across runs, which matters for a demo that has to
    show the same attack twice.
    """
    key_bytes = privkey.to_bytes(32, "big")
    v = b"\x01" * 32
    k = b"\x00" * 32

    k = hmac.new(k, v + b"\x00" + key_bytes + msg_hash, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    k = hmac.new(k, v + b"\x01" + key_bytes + msg_hash, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()

    while True:
        v = hmac.new(k, v, hashlib.sha256).digest()
        candidate = int.from_bytes(v, "big")
        if 1 <= candidate < N:
            return candidate
        k = hmac.new(k, v + b"\x00", hashlib.sha256).digest()
        v = hmac.new(k, v, hashlib.sha256).digest()


def sign(privkey: int, msg_hash: bytes) -> tuple:
    """ECDSA sign. Returns (r, s) with s normalised to the low half of N."""
    z = int.from_bytes(msg_hash, "big")

    while True:
        k = _deterministic_k(privkey, msg_hash)
        point = point_mul(k, G)
        r = point[0] % N
        if r == 0:
            continue
        s = (_inv(k, N) * (z + r * privkey)) % N
        if s == 0:
            continue

        # Low-s normalisation (EIP-2 / BIP-62). Both s and N-s are valid
        # signatures over the same message, so without this rule an attacker
        # can flip one into the other and produce a second distinct-looking
        # signature for the same block. For a chain whose security monitoring
        # keys on "did this validator sign two different things", that
        # malleability would produce false double-sign alerts.
        if s > N // 2:
            s = N - s
        return (r, s)


def verify(pubkey: tuple, msg_hash: bytes, signature: tuple) -> bool:
    r, s = signature
    if not (1 <= r < N and 1 <= s < N):
        return False
    if s > N // 2:
        return False  # reject malleable high-s signatures outright

    z = int.from_bytes(msg_hash, "big")
    w = _inv(s, N)
    u1 = (z * w) % N
    u2 = (r * w) % N

    point = point_add(point_mul(u1, G), point_mul(u2, pubkey))
    if point is None:
        return False
    return point[0] % N == r


def serialize_pubkey(pubkey: tuple) -> str:
    """Uncompressed SEC1 encoding: 0x04 || X || Y."""
    x, y = pubkey
    return "0x04" + x.to_bytes(32, "big").hex() + y.to_bytes(32, "big").hex()


def deserialize_pubkey(encoded: str) -> tuple:
    raw = bytes.fromhex(encoded.removeprefix("0x"))
    if len(raw) != 65 or raw[0] != 0x04:
        raise ValueError("expected 65-byte uncompressed SEC1 public key")
    return (int.from_bytes(raw[1:33], "big"), int.from_bytes(raw[33:65], "big"))


def serialize_sig(signature: tuple) -> str:
    r, s = signature
    return "0x" + r.to_bytes(32, "big").hex() + s.to_bytes(32, "big").hex()


def deserialize_sig(encoded: str) -> tuple:
    raw = bytes.fromhex(encoded.removeprefix("0x"))
    if len(raw) != 64:
        raise ValueError("expected 64-byte signature")
    return (int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big"))
