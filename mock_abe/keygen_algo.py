from __future__ import annotations

import random

from .core import MOD, g1_from_exp, hash_to_scalar


def keygen(pp: dict, attributes: list[str], rng: random.Random | None = None) -> dict:
    """KeyGen.

    k <- Z_p
    U = g^k
    K_trans = g^(gamma + k)
    """

    rng = rng or random.Random()
    k = rng.randrange(1, MOD)
    u_exp = k
    k_trans_exp = (pp["gamma"] + k) % MOD

    attr_keys: dict[str, dict[str, int]] = {}
    for attribute in attributes:
        t_x = rng.randrange(1, MOD)
        h1 = hash_to_scalar("H1", attribute)
        l_x_exp = (h1 * k + t_x) % MOD
        attr_keys[attribute] = {
            "t_x": t_x,
            "K_x": g1_from_exp(k),
            "K_x_exp": k,
            "L_x": g1_from_exp(l_x_exp),
            "L_x_exp": l_x_exp,
        }

    return {
        "k": k,
        "U": g1_from_exp(u_exp),
        "U_exp": u_exp,
        "K_trans": g1_from_exp(k_trans_exp),
        "K_trans_exp": k_trans_exp,
        "attribute_keys": attr_keys,
    }
