from typing import TYPE_CHECKING

from apps.common.keychain import auto_keychain

if TYPE_CHECKING:
    from trezor.messages import CashuVerifyProofs, Success

    from apps.common.keychain import Keychain


@auto_keychain(__name__)
async def verify_proofs(msg: CashuVerifyProofs, keychain: Keychain) -> Success:
    from trezor.messages import Success
    from .common import get_default_keysets, derive_sub_node
    from .crypto import verify_message

    keysets = get_default_keysets(keychain)

    for proof in msg.proofs.proof:
        try:
            keyset_idx = next(
                idx for idx, ks in keysets.items() if ks.id == proof.keyset_id
            )
        except StopIteration:
            raise ValueError("No matching keyset found")

        node = derive_sub_node(keychain, keyset_idx, proof.amount)
        is_valid = verify_message(
            node.private_key(),
            proof.c,
            proof.secret,
        )

        if not is_valid:
            raise ValueError("Invalid proof detected")

    return Success()
