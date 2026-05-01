from __future__ import annotations

from .core import MOD


def search(index: dict, trapdoor: dict) -> dict:
    """Search.

    In exponent space:
        lhs = T1 * I1 - I2 * T2
        rhs = T2
    """

    lhs = (trapdoor["T1"] * index["I1"] - index["I2"] * trapdoor["T2"]) % MOD
    rhs = trapdoor["T2"] % MOD
    return {"matched": lhs == rhs, "lhs": lhs, "rhs": rhs}
