from __future__ import annotations

import random

from .core import MOD, hash_to_scalar


def build_index(keywords: list[str], rng: random.Random | None = None) -> dict:
    """Index generation.

    Phi = sum H2(kw_j)
    I1 = g^(Phi(1+beta))
    I2 = e(g,g)^beta
    """

    rng = rng or random.Random()
    phi = sum(hash_to_scalar("H2", keyword) for keyword in keywords) % MOD
    beta = rng.randrange(1, MOD)
    i1 = (phi * (1 + beta)) % MOD
    i2 = beta % MOD
    return {"Phi": phi, "beta": beta, "I1": i1, "I2": i2}
