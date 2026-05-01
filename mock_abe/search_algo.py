from __future__ import annotations

from .core import MOD


def search(index: dict, trapdoor: dict) -> dict:
    """Search.

    In exponent space:
        lhs = T1 * I1 - I2 * T2
        rhs = T2
    """

    t1_exp = trapdoor.get("T1_exp", trapdoor["T1"])
    i1_exp = index.get("I1_exp", index["I1"])
    i2_exp = index.get("I2_exp", index["I2"])
    lhs = (t1_exp * i1_exp - i2_exp * trapdoor["T2"]) % MOD
    rhs = trapdoor["T2"] % MOD
    return {"matched": lhs == rhs, "lhs": lhs, "rhs": rhs}
