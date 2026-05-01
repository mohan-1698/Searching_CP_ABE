from __future__ import annotations

import random

from .core import MOD


def setup(num_nodes: int = 3, rng: random.Random | None = None) -> dict:
    """Setup.

    gamma = sum(gamma_i) mod MOD
    PP = (MOD, gamma)
    """

    rng = rng or random.Random()
    gammas = [rng.randrange(1, MOD) for _ in range(max(1, num_nodes))]
    gamma = sum(gammas) % MOD
    return {"modulus": MOD, "gamma_parts": gammas, "gamma": gamma}
