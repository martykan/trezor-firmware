from typing import TYPE_CHECKING

from apps.common.keychain import auto_keychain

if TYPE_CHECKING:
    from trezor.messages import (
        CashuGetKeysets,
        CashuGetKeysetsResponse,
    )

    from apps.common.keychain import Keychain


@auto_keychain(__name__)
async def get_keysets(
    msg: CashuGetKeysets, keychain: Keychain
) -> CashuGetKeysetsResponse:
    from trezor.messages import (
        CashuGetKeysetsResponse,
        SignatoryKeysets,
    )
    from .common import derive_root_node, get_default_keysets

    node = derive_root_node(keychain)
    pk = node.public_key()

    return CashuGetKeysetsResponse(
        keysets=SignatoryKeysets(
            pubkey=pk,
            keysets=get_default_keysets(keychain),
        )
    )
