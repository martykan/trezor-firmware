from typing import TYPE_CHECKING

from apps.common.keychain import auto_keychain

if TYPE_CHECKING:
    from trezor.messages import CashuBlindSign, CashuBlindSignResponse

    from apps.common.keychain import Keychain


@auto_keychain(__name__)
async def blind_sign(msg: CashuBlindSign, keychain: Keychain) -> CashuBlindSignResponse:
    from trezor.messages import (
        CashuBlindSignResponse,
        BlindedMessage,
        BlindSignature,
    )
    from .common import get_default_keysets, derive_sub_node
    from .crypto import sign_message, calculate_dleq

    keysets = (
        get_default_keysets(keychain)
        if msg.keysets is None or len(msg.keysets) == 0
        else msg.keysets
    )

    def blind_sign_message(msg: BlindedMessage) -> BlindSignature:
        try:
            keyset = next(ks for ks in keysets if ks.id == msg.keyset_id)
        except StopIteration:
            raise ValueError("No matching keyset found")

        node = derive_sub_node(keychain, keyset.unit, msg.amount)
        try:
            ks_public_key = next(
                (ke.value for ke in keyset.keys.keys if ke.key == msg.amount)
            )
        except StopIteration:
            raise ValueError("Amount mismatch")
        if ks_public_key != node.public_key():
            raise ValueError("Key mismatch")
        double_blinded = sign_message(node.private_key(), msg.blinded_secret)

        return BlindSignature(
            amount=msg.amount,
            keyset_id=msg.keyset_id,
            blinded_secret=double_blinded,
            dleq=calculate_dleq(
                blinded_signature=double_blinded,
                blinded_message=msg.blinded_secret,
                mint_public_key=node.public_key(),
                mint_secret_key=node.private_key(),
            ),
        )

    sigs = [blind_sign_message(blind) for blind in msg.blinded_messages]

    return CashuBlindSignResponse(sigs=sigs)
