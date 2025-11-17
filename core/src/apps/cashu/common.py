from typing import TYPE_CHECKING
from apps.common.paths import HARDENED
from . import SLIP44_ID

from trezor.enums.CurrencyUnitType import (
    CURRENCY_UNIT_TYPE_SAT,
    CURRENCY_UNIT_TYPE_MSAT,
    CURRENCY_UNIT_TYPE_AUTH,
    CURRENCY_UNIT_TYPE_EUR,
    CURRENCY_UNIT_TYPE_USD,
)
from trezor.messages import CurrencyUnit

if TYPE_CHECKING:
    from trezor.crypto import bip32
    from trezor.messages import CurrencyUnit, KeySet
    from apps.common.keychain import Keychain


ROOT_NODE = [SLIP44_ID | HARDENED]

# From Remote signer spec (NUT WIP at the time of writing)
# https://github.com/cashubtc/nuts/pull/250
PATH_CURRENCY_MAP = {
    CURRENCY_UNIT_TYPE_SAT: 866057899,
    CURRENCY_UNIT_TYPE_MSAT: 1980671987,
    CURRENCY_UNIT_TYPE_AUTH: 1039440956,
    CURRENCY_UNIT_TYPE_EUR: 975082952,
    CURRENCY_UNIT_TYPE_USD: 1443872135,
}

ENABLED_CURRENCIES = [CURRENCY_UNIT_TYPE_SAT, CURRENCY_UNIT_TYPE_USD]


def currency_unit_path(currency: CurrencyUnit) -> int:
    from trezor.crypto.hashlib import sha256

    if currency.unit in PATH_CURRENCY_MAP:
        return PATH_CURRENCY_MAP[currency.unit]
    elif currency.custom_unit is not None:
        path = sha256(currency.custom_unit).digest()[:4]
        return int.from_bytes(path, "little") % (2**31)
    else:
        raise ValueError("Unknown currency unit")


def derive_root_node(keychain: Keychain) -> bip32.HDNode:
    return keychain.derive(ROOT_NODE)


def derive_sub_node(
    keychain: Keychain, currency: CurrencyUnit, amount: int
) -> bip32.HDNode:
    subpath = [currency_unit_path(currency), 1, amount]
    return keychain.derive(ROOT_NODE + subpath)


def get_keyset(keychain: Keychain, currency: CurrencyUnit, max_order: int) -> KeySet:
    from trezor.messages import (
        Keys,
        KeysEntry,
        KeySet,
    )
    from trezor.crypto.hashlib import sha256

    values = [2**i for i in range(max_order)]
    keys = [
        KeysEntry(
            key=v,
            value=derive_sub_node(keychain, currency, v).public_key(),
        )
        for i, v in enumerate(values)
    ]
    # NUTS-02 keyset ID
    pubkeys_concat = b"".join([ke.value for ke in keys])
    keyset_id = b"\x00" + sha256(pubkeys_concat).digest()[:7]

    return KeySet(
        id=keyset_id,
        unit=currency,
        active=True,
        input_fee_ppk=0,
        version=0,
        keys=Keys(keys=keys),
    )


def get_default_keysets(keychain: Keychain) -> dict[int, KeySet]:
    from trezor.messages import CurrencyUnit

    return [
        get_keyset(
            keychain=keychain,
            currency=CurrencyUnit(unit=currency_type),
            max_order=8,
        )
        for currency_type in ENABLED_CURRENCIES
    ]
