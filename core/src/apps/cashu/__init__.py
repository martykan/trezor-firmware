if not __debug__:
    from trezor import utils

    utils.halt("Disabled in production mode")

CURVE = "secp256k1"
PATTERN = "m/44'/129372'/*"
SLIP44_ID = 129372
