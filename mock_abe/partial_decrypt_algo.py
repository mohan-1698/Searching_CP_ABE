from __future__ import annotations

from .core import pairing_exp


def partial_decrypt(ciphertext: dict, secret_key: dict) -> dict:
    """Partial decryption.

    P = e(C0, K_trans)
    In exponent space: P = C0 * K_trans mod MOD
    """

    p_exp = pairing_exp(ciphertext["C0"], secret_key["K_trans"])
    return {"P": p_exp}
