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

    keysets = (
        get_default_keysets(keychain)
        if msg.keysets is None or len(msg.keysets) == 0
        else msg.keysets
    )
    for proof in msg.proofs.proof:
        try:
            keyset = next(ks for ks in keysets if ks.id == proof.keyset_id)
        except StopIteration:
            raise ValueError("No matching keyset found")

        node = derive_sub_node(keychain, keyset.unit, proof.amount)
        try:
            ks_public_key = next(
                (ke.value for ke in keyset.keys.keys if ke.key == proof.amount)
            )
        except StopIteration:
            raise ValueError("Amount mismatch verify")
        if ks_public_key != node.public_key():
            raise ValueError("Key mismatch verify")

        is_valid = verify_message(
            node.private_key(),
            proof.c,
            proof.secret,
        )

        if not is_valid:
            raise ValueError("Invalid proof detected")

    return Success()
