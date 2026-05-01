from __future__ import annotations

from .core import pairing_exp


def partial_decrypt(ciphertext: dict, secret_key: dict) -> dict:
    """Partial decryption.

    P = e(C0, K_trans)
    In exponent space: P = C0 * K_trans mod MOD
    """

    c0_exp = ciphertext.get("C0_exp", ciphertext["C0"])
    k_trans_exp = secret_key.get("K_trans_exp", secret_key["K_trans"])
    p_exp = pairing_exp(c0_exp, k_trans_exp)
    return {"P": p_exp}
