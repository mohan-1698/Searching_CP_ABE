from __future__ import annotations

import random

from .core import MOD, g1_from_exp, hash_to_scalar


def build_trapdoor(query_keywords: list[str], rng: random.Random | None = None) -> dict:
    """Trapdoor generation.

    Phi' = sum H2(kw'_j)
    T1 = g^alpha
    T2 = alpha * Phi'
    """

    rng = rng or random.Random()
    phi_prime = sum(hash_to_scalar("H2", keyword) for keyword in query_keywords) % MOD
    alpha = rng.randrange(1, MOD)
    t1_exp = alpha % MOD
    t2 = (alpha * phi_prime) % MOD
    t1 = g1_from_exp(t1_exp)
    return {
        "Phi_prime": phi_prime,
        "alpha": alpha,
        "T1": t1,
        "T1_exp": t1_exp,
        "T2": t2,
    }
