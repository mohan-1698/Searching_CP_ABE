#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import base64
import random
from pathlib import Path

from mock_abe.setup_algo import setup
from mock_abe.keygen_algo import keygen
from mock_abe.encrypt_algo import encrypt
from mock_abe.index_algo import build_index
from mock_abe.trapdoor_algo import build_trapdoor
from mock_abe.search_algo import search
from mock_abe.partial_decrypt_algo import partial_decrypt
from mock_abe.final_decrypt_algo import final_decrypt


def run_flow(
    input_path: Path,
    out_dir: Path,
    owner_attributes: list[str],
    policy_attributes: list[str],
    encrypt_keywords: list[str],
    query_keywords: list[str],
    seed: int,
) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    data = input_path.read_bytes()

    rng = random.Random(seed)
    pp = setup(num_nodes=max(1, min(5, len(policy_attributes))), rng=rng)

    sk = keygen(pp, owner_attributes, rng=rng)

    ct = encrypt(pp, data, encrypt_keywords, num_attributes=len(policy_attributes), rng=rng)

    # persist ciphertext and index as JSON (demo)
    def b64(x: bytes) -> str:
        return base64.b64encode(x).decode("ascii") if isinstance(x, (bytes, bytearray)) else x

    ct_json = {
        "r": ct["r"],
        "s": ct["s"],
        "threshold": ct["threshold"],
        "shares": [[int(i), int(v)] for (i, v) in ct.get("shares", [])],
        "lambda_values": [int(x) for x in ct.get("lambda_values", [])],
        "C0": int(ct.get("C0")),
        "Z": int(ct.get("Z")),
        "symmetric_key": b64(ct.get("symmetric_key")),
        "ciphertext": b64(ct.get("ciphertext")),
        "tau": b64(ct.get("tau")),
        "rows": [
            {k: (b64(v) if isinstance(v, (bytes, bytearray)) else v) for k, v in row.items()} for row in ct.get("rows", [])
        ],
        "keywords": ct.get("keywords", []),
        "keyword_sum": int(ct.get("keyword_sum", 0)),
    }

    with (out_dir / "ct.json").open("w", encoding="utf-8") as f:
        json.dump(ct_json, f, indent=2)

    index = build_index(encrypt_keywords, rng=rng)
    with (out_dir / "index.json").open("w", encoding="utf-8") as f:
        json.dump({k: int(v) for k, v in index.items()}, f, indent=2)

    # simulate querier building trapdoor and searching
    trapdoor = build_trapdoor(query_keywords, rng=rng)
    matched = search(index, trapdoor).get("matched", False)
    print("search matched:", matched)
    # if search did not match, abort (no decrypt)
    if not matched:
        print("No search match; aborting decrypt.")
        return

    # check that owner attributes satisfy the policy (simple coverage check)
    available_attrs = set(sk.get("attribute_keys", {}).keys())
    policy_attr_names = [row.get("attribute") for row in ct.get("rows", [])]
    matching = sum(1 for a in policy_attr_names if a in available_attrs)
    if matching < ct.get("threshold", 0):
        print(f"Insufficient attributes for decryption: have {matching}, need {ct.get('threshold')}")
        return

    # partial + final decrypt
    partial = partial_decrypt(ct, sk)
    final = final_decrypt(ct, sk, partial)

    if final.get("tag_ok") and final.get("plaintext") == data:
        print("Decryption successful, writing recovered file.")
        (out_dir / f"recovered_{input_path.name}").write_bytes(final["plaintext"])
    else:
        print("Decryption failed. tag_ok:", final.get("tag_ok"))


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="End-to-end mock searchable encryption demo")
    p.add_argument("input", type=Path, help="Input file to encrypt")
    p.add_argument("--out", type=Path, default=Path("end_to_end_out"))
    p.add_argument("--attributes", type=str, default="attr1,attr2", help="Comma list of owner attributes for key generation (default: attr1,attr2)")
    p.add_argument("--policy-attributes", type=str, default="", help="Optional comma list of attributes used in the ciphertext policy (defaults to --attributes)")
    p.add_argument("--encrypt-keywords", type=str, default="kw1,kw2", help="Comma list of keywords to embed in the ciphertext (default: kw1,kw2)")
    p.add_argument("--query-keywords", type=str, default="", help="Optional comma list of keywords used to build the trapdoor (defaults to --encrypt-keywords)")
    p.add_argument("--seed", type=int, default=12345)
    return p


if __name__ == "__main__":
    args = build_parser().parse_args()
    owner_attrs = [a.strip() for a in args.attributes.split(",") if a.strip()]
    policy_attrs = [a.strip() for a in args.policy_attributes.split(",") if a.strip()] if args.policy_attributes else owner_attrs
    encrypt_kws = [k.strip() for k in args.encrypt_keywords.split(",") if k.strip()]
    query_kws = [k.strip() for k in args.query_keywords.split(",") if k.strip()] if args.query_keywords else encrypt_kws

    # run_flow: owner attributes (for keygen), policy attributes (for encryption/index), encrypt keywords (ciphertext), query keywords (trapdoor)
    run_flow(args.input, args.out, owner_attrs, policy_attrs, encrypt_kws, query_kws, args.seed)
