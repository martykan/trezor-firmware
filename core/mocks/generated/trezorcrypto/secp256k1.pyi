from typing import *
from buffer_types import *


# upymod/modtrezorcrypto/modtrezorcrypto-secp256k1.h
def generate_secret() -> bytes:
    """
    Generate secret key.
    """


# upymod/modtrezorcrypto/modtrezorcrypto-secp256k1.h
def publickey(secret_key: AnyBytes, compressed: bool = True) -> bytes:
    """
    Computes public key from secret key.
    """
CANONICAL_SIG_ETHEREUM: int = 1
CANONICAL_SIG_EOS: int = 2


# upymod/modtrezorcrypto/modtrezorcrypto-secp256k1.h
def sign(
    secret_key: AnyBytes,
    digest: AnyBytes,
    compressed: bool = True,
    canonical: int | None = None,
) -> bytes:
    """
    Uses secret key to produce the signature of the digest.
    """


# upymod/modtrezorcrypto/modtrezorcrypto-secp256k1.h
def verify(
    public_key: AnyBytes, signature: AnyBytes, digest: AnyBytes
) -> bool:
    """
    Uses public key to verify the signature of the digest.
    Returns True on success.
    """


# upymod/modtrezorcrypto/modtrezorcrypto-secp256k1.h
def verify_recover(signature: AnyBytes, digest: AnyBytes) -> bytes:
    """
    Uses signature of the digest to verify the digest and recover the public
    key. Returns public key on success, None if the signature is invalid.
    """


# upymod/modtrezorcrypto/modtrezorcrypto-secp256k1.h
def multiply(secret_key: AnyBytes, public_key: AnyBytes) -> bytes:
    """
    Multiplies point defined by public_key with scalar defined by
    secret_key. Useful for ECDH.
    """


# upymod/modtrezorcrypto/modtrezorcrypto-secp256k1.h
def scalar_add(s1: AnyBytes, s2: AnyBytes) -> bytes:
    """
    Adds 2 scalar values defined by s1 and s2.
    """


# upymod/modtrezorcrypto/modtrezorcrypto-secp256k1.h
def scalar_multiply(s1: AnyBytes, s2: AnyBytes) -> bytes:
    """
    Multiplies 2 scalar values defined by s1 and s2.
    """
