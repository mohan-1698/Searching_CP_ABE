from __future__ import annotations

import random

from .core import MOD, hash_to_scalar


def keygen(pp: dict, attributes: list[str], rng: random.Random | None = None) -> dict:
    """KeyGen.

    k <- Z_p
    U = g^k
    K_trans = g^(gamma + k)
    """

    rng = rng or random.Random()
    k = rng.randrange(1, MOD)
    u_exp = k
    k_trans = (pp["gamma"] + k) % MOD

    attr_keys: dict[str, dict[str, int]] = {}
    for attribute in attributes:
        t_x = rng.randrange(1, MOD)
        h1 = hash_to_scalar("H1", attribute)
        attr_keys[attribute] = {"t_x": t_x, "K_x": k, "L_x": (h1 * k + t_x) % MOD}

    return {"k": k, "U": u_exp, "K_trans": k_trans, "attribute_keys": attr_keys}
