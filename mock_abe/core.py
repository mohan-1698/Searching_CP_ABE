from __future__ import annotations

import hashlib
import math
import random
from dataclasses import dataclass
from typing import Sequence

MOD = 2**61 - 1
G1_GEN = 5
GT_GEN = 7


def normalize_text(value: str, target_length: int) -> bytes:
    raw = value.encode("utf-8")
    if target_length <= 0:
        return raw
    if not raw:
        raw = b"x"
    repeated = (raw * ((target_length // len(raw)) + 1))[:target_length]
    return repeated


def xor_bytes(data: bytes, key: bytes) -> bytes:
    if not key:
        raise ValueError("key must not be empty")
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def hash_to_scalar(label: str, *parts: object) -> int:
    digest = hashlib.sha256()
    digest.update(label.encode("utf-8"))
    for part in parts:
        if isinstance(part, bytes):
            digest.update(part)
        elif isinstance(part, str):
            digest.update(part.encode("utf-8"))
        elif isinstance(part, int):
            digest.update(str(part).encode("utf-8"))
        else:
            digest.update(repr(part).encode("utf-8"))
    return int.from_bytes(digest.digest(), "big") % MOD


def derive_key_bytes(label: str, *parts: object, length: int = 32) -> bytes:
    material = hashlib.sha256()
    material.update(label.encode("utf-8"))
    for part in parts:
        if isinstance(part, bytes):
            material.update(part)
        elif isinstance(part, str):
            material.update(part.encode("utf-8"))
        elif isinstance(part, int):
            material.update(str(part).encode("utf-8"))
        else:
            material.update(repr(part).encode("utf-8"))
    seed = material.digest()

    output = bytearray()
    block = seed
    while len(output) < length:
        block = hashlib.sha256(block).digest()
        output.extend(block)
    return bytes(output[:length])


def pairing_exp(a: int, b: int) -> int:
    return (a * b) % MOD


def g1_from_exp(exp: int) -> int:
    return pow(G1_GEN, exp % MOD, MOD)


def gt_from_exp(exp: int) -> int:
    return pow(GT_GEN, exp % MOD, MOD)


def polynomial_share(secret: int, n: int, threshold: int, rng: random.Random) -> list[tuple[int, int]]:
    if threshold < 1:
        raise ValueError("threshold must be at least 1")
    if threshold > n:
        raise ValueError("threshold must be <= n")

    coeffs = [secret] + [rng.randrange(1, MOD) for _ in range(threshold - 1)]

    def eval_poly(x: int) -> int:
        total = 0
        power = 1
        for coefficient in coeffs:
            total = (total + coefficient * power) % MOD
            power = (power * x) % MOD
        return total

    return [(index + 1, eval_poly(index + 1)) for index in range(n)]


def lagrange_reconstruct_zero(shares: Sequence[tuple[int, int]]) -> int:
    if not shares:
        raise ValueError("shares must not be empty")

    secret = 0
    for i, (xi, yi) in enumerate(shares):
        numerator = 1
        denominator = 1
        for j, (xj, _) in enumerate(shares):
            if i == j:
                continue
            numerator = (numerator * (-xj)) % MOD
            denominator = (denominator * (xi - xj)) % MOD
        basis = (numerator * pow(denominator, -1, MOD)) % MOD
        secret = (secret + yi * basis) % MOD
    return secret


def choose_threshold(num_attributes: int) -> int:
    if num_attributes <= 1:
        return 1
    return min(num_attributes, max(2, math.ceil(num_attributes / 2)))


def build_attribute_names(count: int) -> list[str]:
    return [f"attr{i + 1}" for i in range(count)]


def build_keyword_names(count: int) -> list[str]:
    return [f"kw{i + 1}" for i in range(count)]


@dataclass(frozen=True)
class BenchmarkSeries:
    x_values: list[int]
    raw: dict[str, list[float]]
    smooth: dict[str, list[float]]
