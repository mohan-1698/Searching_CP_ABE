from __future__ import annotations

from .core import MOD, derive_key_bytes, gt_from_exp, lagrange_reconstruct_zero, xor_bytes


def final_decrypt(ciphertext: dict, secret_key: dict, partial: dict) -> dict:
    """Final decryption.

    Reconstruct s from the LSSS shares.
    Since s = r, D = e(g,g)^(k r).
    Then Z' = P / D = e(g,g)^(gamma r).
    """

    threshold = ciphertext["threshold"]
    selected_shares = ciphertext["shares"][:threshold]
    reconstructed_s = lagrange_reconstruct_zero(selected_shares)
    d_exp = (secret_key["k"] * reconstructed_s) % MOD
    z_exp = (partial["P"] - d_exp) % MOD
    z_public = gt_from_exp(z_exp)
    recovered_key = derive_key_bytes("H3", ciphertext["C0"], z_public, length=32)
    tag_check = derive_key_bytes("H4", recovered_key, ciphertext["ciphertext"], length=32)
    tag_ok = tag_check == ciphertext["tau"]
    plaintext = xor_bytes(ciphertext["ciphertext"], recovered_key) if tag_ok else b""
    return {"reconstructed_s": reconstructed_s, "D": d_exp, "Z": z_exp, "key": recovered_key, "tag_ok": tag_ok, "plaintext": plaintext}
