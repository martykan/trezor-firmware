from trezor.messages import BlindSignatureDLEQ

DOMAIN_SEPARATOR = b"Secp256k1_HashToCurve_Cashu_"


# Sign Blinded Message
#
# `C_ = k * B_`, where:
# * `k` is the private key of mint
# * `B_` is the blinded message
def sign_message(
    mint_secret_key: bytes,  # k
    blinded_message: bytes,  # B'
) -> bytes:
    from trezor.crypto.curve import secp256k1

    return secp256k1.multiply(mint_secret_key, blinded_message)


# NUT-00
def hash_to_curve(message: bytes) -> bytes:
    from trezor.crypto.hashlib import sha256
    from trezor.crypto.curve import bip340

    msg_to_hash = sha256(DOMAIN_SEPARATOR + message).digest()
    counter = 0
    while counter < 2**16:
        _hash = sha256(msg_to_hash + counter.to_bytes(4, "little")).digest()
        if bip340.verify_publickey(_hash):
            return b"\x02" + _hash  # compressed point format
        counter += 1
    # it should never reach this point
    raise ValueError("No valid point found")


# Verify Unblinded Message
# `k*hash_to_curve(x) == C`, where:
# * `k` is the private key of mint
# * `C` is the unblinded message
# * `x` is the original secret message
def verify_message(
    mint_secret_key: bytes,  # k
    unblinded_message: bytes,  # C
    secret: bytes,  # msg
) -> bool:
    from trezor.crypto.curve import secp256k1

    y = hash_to_curve(secret)

    expected_unblinded_message = secp256k1.multiply(mint_secret_key, y)

    # only check x coordinate of curve point
    return unblinded_message[1:32] == expected_unblinded_message[1:32]


def calculate_dleq(
    blinded_signature: bytes,  # C'
    blinded_message: bytes,  # B'
    mint_public_key: bytes,  # A
    mint_secret_key: bytes,  # a
) -> BlindSignatureDLEQ | None:
    from trezor.crypto.hashlib import sha256
    from trezor.crypto.curve import secp256k1

    from ubinascii import hexlify

    # Random nonce
    r = secp256k1.generate_secret()

    # R1 = r*G
    r1 = secp256k1.publickey(r, False)

    # R2 = r*B'
    r2 = secp256k1.multiply(r, blinded_message)

    # R1 = a*G
    A = secp256k1.publickey(mint_secret_key, False)

    # e = hash(R1,R2,A,C')
    # note: Cashu impl. weirdly expects hex strings, not raw bytes
    e = sha256(
        hexlify(r1).decode()
        + hexlify(r2).decode()
        + hexlify(A).decode()
        + hexlify(blinded_signature).decode()
    ).digest()

    # s1 = e*a
    s1 = secp256k1.scalar_multiply(e, mint_secret_key)

    # s = r + s1
    s = secp256k1.scalar_add(r, s1)

    return BlindSignatureDLEQ(e=e, s=s)
