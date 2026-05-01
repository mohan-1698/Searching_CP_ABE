from __future__ import annotations

import random

from .core import (
    MOD,
    build_attribute_names,
    choose_threshold,
    derive_key_bytes,
    g1_from_exp,
    gt_from_exp,
    hash_to_scalar,
    polynomial_share,
    xor_bytes,
)


def encrypt(
    pp: dict,
    message: bytes,
    keywords: list[str],
    num_attributes: int,
    rng: random.Random | None = None,
) -> dict:
    """Encrypt.

    r <- Z_p
    s = r
    lambda_i = M_i * v
    C0 = g^r
    Z = e(g,g)^(gamma r)
    K_sym = H3(C0 || Z)
    tau = H4(K_sym || C_file || Z)
    """

    rng = rng or random.Random()
    threshold = choose_threshold(num_attributes)
    r = rng.randrange(1, MOD)
    s = r

    shares = polynomial_share(s, num_attributes, threshold, rng)
    lambda_values = [share_value for _, share_value in shares]

    c0_exp = r % MOD
    c0 = g1_from_exp(c0_exp)
    z_exp = (pp["gamma"] * r) % MOD
    z = gt_from_exp(z_exp)
    symmetric_key = derive_key_bytes("H3", c0, z, length=32)
    ciphertext_bytes = xor_bytes(message, symmetric_key)
    tau = derive_key_bytes("H4", symmetric_key, ciphertext_bytes, z, length=32)

    attribute_names = build_attribute_names(num_attributes)
    rows = []
    for attribute_name, lambda_i in zip(attribute_names, lambda_values):
        u_i = rng.randrange(1, MOD)
        h1 = hash_to_scalar("H1", attribute_name)
        c_i1 = (lambda_i - u_i * h1) % MOD
        c_i2_exp = u_i % MOD
        c_i2 = g1_from_exp(c_i2_exp)
        rows.append({
            "attribute": attribute_name,
            "lambda": lambda_i,
            "u": u_i,
            "C_i1": c_i1,
            "C_i2": c_i2,
            "C_i2_exp": c_i2_exp,
        })

    return {
        "r": r,
        "s": s,
        "threshold": threshold,
        "shares": shares,
        "lambda_values": lambda_values,
        "C0": c0,
        "C0_exp": c0_exp,
        "Z": z,
        "Z_exp": z_exp,
        "symmetric_key": symmetric_key,
        "ciphertext": ciphertext_bytes,
        "tau": tau,
        "rows": rows,
        "keywords": keywords,
        "keyword_sum": sum(hash_to_scalar("H2", keyword) for keyword in keywords) % MOD,
    }
