from typing import TYPE_CHECKING
from apps.common.paths import HARDENED
from . import SLIP44_ID

from trezor.enums.CurrencyUnitType import (
    CURRENCY_UNIT_TYPE_SAT,
    CURRENCY_UNIT_TYPE_USD,
)
from trezor.messages import CurrencyUnit

if TYPE_CHECKING:
    from trezor.crypto import bip32
    from trezor.messages import CurrencyUnit, KeySet
    from apps.common.keychain import Keychain


ROOT_NODE = [44 | HARDENED, SLIP44_ID | HARDENED]
ENABLED_CURRENCIES = [CURRENCY_UNIT_TYPE_SAT, CURRENCY_UNIT_TYPE_USD]


def derive_root_node(keychain: Keychain) -> bip32.HDNode:
    return keychain.derive(ROOT_NODE)


def derive_sub_node(keychain: Keychain, idx: int, amount: int) -> bip32.HDNode:
    subpath = [idx, amount]
    return keychain.derive(ROOT_NODE + subpath)


def get_keyset(
    keychain: Keychain, idx: int, currency: CurrencyUnit, max_order: int
) -> KeySet:
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
            value=derive_sub_node(keychain, idx, v).public_key(),
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

    keysets = {}
    for idx, currency_type in enumerate(ENABLED_CURRENCIES, start=1):
        keyset = get_keyset(
            keychain=keychain,
            idx=idx,
            currency=CurrencyUnit(unit=currency_type),
            max_order=8,
        )
        keysets[idx] = keyset

    return keysets
