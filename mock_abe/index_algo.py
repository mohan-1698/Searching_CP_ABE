from __future__ import annotations

import random

from .core import MOD, g1_from_exp, gt_from_exp, hash_to_scalar


def build_index(keywords: list[str], rng: random.Random | None = None) -> dict:
    """Index generation.

    Phi = sum H2(kw_j)
    I1 = g^(Phi(1+beta))
    I2 = e(g,g)^beta
    """

    rng = rng or random.Random()
    phi = sum(hash_to_scalar("H2", keyword) for keyword in keywords) % MOD
    beta = rng.randrange(1, MOD)
    i1_exp = (phi * (1 + beta)) % MOD
    i2_exp = beta % MOD
    i1 = g1_from_exp(i1_exp)
    i2 = gt_from_exp(i2_exp)
    return {
        "Phi": phi,
        "beta": beta,
        "I1": i1,
        "I1_exp": i1_exp,
        "I2": i2,
        "I2_exp": i2_exp,
    }
