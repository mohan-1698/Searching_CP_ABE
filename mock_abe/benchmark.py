from __future__ import annotations

import argparse
import csv
import random
import statistics
import time
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np

from .core import BenchmarkSeries, build_keyword_names, normalize_text
from .encrypt_algo import encrypt
from .final_decrypt_algo import final_decrypt
from .index_algo import build_index
from .keygen_algo import keygen
from .partial_decrypt_algo import partial_decrypt
from .search_algo import search
from .setup_algo import setup
from .trapdoor_algo import build_trapdoor


def moving_average(values: list[float], window: int = 3) -> list[float]:
    if window <= 1 or len(values) <= 2:
        return values[:]
    kernel = np.ones(window, dtype=float) / window
    smoothed = np.convolve(np.asarray(values, dtype=float), kernel, mode="same")
    return smoothed.tolist()


def fit_trend_line(x_values: list[int], y_values: list[float]) -> list[float]:
    if len(x_values) < 2:
        return y_values[:]
    x = np.asarray(x_values, dtype=float)
    y = np.asarray(y_values, dtype=float)
    coefficients = np.polyfit(x, y, 1)
    polynomial = np.poly1d(coefficients)
    fitted = polynomial(x)
    fitted = np.maximum(fitted, 0.0)
    return fitted.tolist()


def average_stage_time(repeats: int, action) -> float:
    start = time.perf_counter()
    for _ in range(repeats):
        action()
    elapsed = time.perf_counter() - start
    return elapsed


def measure_pipeline_from_inputs(
    attributes: list[str],
    keywords: list[str],
    message_text: bytes,
    base_seed: int,
    work_multiplier: int,
) -> dict:
    rng = random.Random(base_seed)
    num_attributes = len(attributes)
    num_keywords = len(keywords)

    timings: dict[str, float] = {}

    setup_result: dict = {}
    timings["setup"] = average_stage_time(
        work_multiplier,
        lambda: setup_result.update(setup(num_nodes=max(1, min(5, num_attributes)), rng=rng)),
    )
    pp = setup_result

    keygen_result: dict = {}
    timings["keygen"] = average_stage_time(work_multiplier, lambda: keygen_result.update(keygen(pp, attributes, rng=rng)))
    sk = keygen_result

    encrypt_result: dict = {}
    timings["encrypt"] = average_stage_time(
        work_multiplier,
        lambda: encrypt_result.update(encrypt(pp, message_text, keywords, num_attributes, rng=rng)),
    )
    ct = encrypt_result

    index_result: dict = {}
    timings["index"] = average_stage_time(work_multiplier, lambda: index_result.update(build_index(keywords, rng=rng)))
    index = index_result

    trapdoor_result: dict = {}
    timings["trapdoor"] = average_stage_time(work_multiplier, lambda: trapdoor_result.update(build_trapdoor(keywords, rng=rng)))
    trapdoor = trapdoor_result

    search_result: dict = {}
    timings["search"] = average_stage_time(work_multiplier, lambda: search_result.update(search(index, trapdoor)))

    partial_result: dict = {}
    timings["partial_decrypt"] = average_stage_time(work_multiplier, lambda: partial_result.update(partial_decrypt(ct, sk)))
    partial = partial_result

    final_result: dict = {}
    timings["final_decrypt"] = average_stage_time(work_multiplier, lambda: final_result.update(final_decrypt(ct, sk, partial)))
    final = final_result

    timings["total"] = sum(
        timings[name]
        for name in [
            "setup",
            "keygen",
            "encrypt",
            "index",
            "trapdoor",
            "search",
            "partial_decrypt",
            "final_decrypt",
        ]
    )

    timings["success"] = float(search_result["matched"] and final["tag_ok"] and final["plaintext"] == message_text)
    timings["ciphertext_size"] = float(len(ct["ciphertext"]))
    timings["keyword_count"] = float(num_keywords)
    timings["attribute_count"] = float(num_attributes)
    timings["message_size"] = float(len(message_text))
    return timings


def measure_pipeline(num_attributes: int, num_keywords: int, message_size: int, base_seed: int) -> dict:
    attributes = [f"attr{i + 1}" for i in range(num_attributes)]
    keywords = build_keyword_names(num_keywords)
    message_text = normalize_text("Mock searchable encryption benchmark message.", message_size)
    return measure_pipeline_from_inputs(attributes, keywords, message_text, base_seed, work_multiplier=200)


def average_dicts(records: list[dict[str, float]]) -> dict[str, float]:
    keys = records[0].keys()
    return {key: statistics.fmean(record[key] for record in records) for key in keys}


def average_runs(num_attributes: int, num_keywords: int, message_size: int, repeats: int, work_multiplier: int, seed: int) -> dict:
    records = [
        measure_pipeline_from_inputs(
            [f"attr{i + 1}" for i in range(num_attributes)],
            build_keyword_names(num_keywords),
            normalize_text("Mock searchable encryption benchmark message.", message_size),
            seed + i,
            work_multiplier,
        )
        for i in range(repeats)
    ]
    return average_dicts(records)


def cycle_average_runs(
    num_attributes: int,
    num_keywords: int,
    message_size: int,
    cycles: int,
    repeats_per_cycle: int,
    work_multiplier: int,
    seed: int,
) -> dict:
    cycle_summaries: list[dict[str, float]] = []
    for cycle_index in range(cycles):
        cycle_seed = seed + cycle_index * 10_000
        cycle_summaries.append(average_runs(num_attributes, num_keywords, message_size, repeats_per_cycle, work_multiplier, cycle_seed))
    return average_dicts(cycle_summaries)


def sweep_dimension(
    values: list[int],
    *,
    num_attributes: int,
    num_keywords: int,
    message_size: int,
    cycles: int,
    repeats_per_cycle: int,
    work_multiplier: int,
    seed: int,
    dimension: str,
) -> BenchmarkSeries:
    raw: dict[str, list[float]] = {
        "setup": [],
        "keygen": [],
        "encrypt": [],
        "index": [],
        "trapdoor": [],
        "search": [],
        "partial_decrypt": [],
        "final_decrypt": [],
        "total": [],
    }
    for index, value in enumerate(values):
        if dimension == "attributes":
            summary = cycle_average_runs(value, num_keywords, message_size, cycles, repeats_per_cycle, work_multiplier, seed + index * 1000)
        elif dimension == "keywords":
            summary = cycle_average_runs(num_attributes, value, message_size, cycles, repeats_per_cycle, work_multiplier, seed + index * 1000)
        elif dimension == "text":
            summary = cycle_average_runs(num_attributes, num_keywords, value, cycles, repeats_per_cycle, work_multiplier, seed + index * 1000)
        else:
            raise ValueError(f"unknown dimension: {dimension}")

        for key in raw:
            raw[key].append(summary[key])

    smooth = {key: moving_average(series, window=3) for key, series in raw.items()}
    return BenchmarkSeries(x_values=values, raw=raw, smooth=smooth)


def ensure_output_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def plot_line(series: BenchmarkSeries, y_keys: list[str], labels: list[str], title: str, xlabel: str, ylabel: str, output_path: Path) -> None:
    plt.figure(figsize=(10, 6))
    for key, label in zip(y_keys, labels):
        y_values = fit_trend_line(series.x_values, series.raw[key])
        plt.plot(series.x_values, y_values, marker="o", linewidth=2, label=label)
        for x_value, y_value in zip(series.x_values, y_values):
            plt.annotate(
                f"{y_value:.6f}",
                (x_value, y_value),
                textcoords="offset points",
                xytext=(0, 8),
                ha="center",
                fontsize=8,
            )
    plt.title(title)
    plt.xlabel(xlabel)
    plt.ylabel(ylabel)
    plt.grid(True, alpha=0.3)
    plt.legend()
    plt.tight_layout()
    plt.savefig(output_path, dpi=200)
    plt.close()


def plot_heatmap(x_values: list[int], y_values: list[int], grid: np.ndarray, title: str, xlabel: str, ylabel: str, output_path: Path) -> None:
    plt.figure(figsize=(10, 6))
    im = plt.imshow(grid, origin="lower", aspect="auto", cmap="viridis")
    plt.colorbar(im, label="Averaged encryption time (seconds)")
    plt.xticks(range(len(x_values)), x_values)
    plt.yticks(range(len(y_values)), y_values)
    for row_index, row_values in enumerate(grid):
        for column_index, value in enumerate(row_values):
            plt.text(
                column_index,
                row_index,
                f"{value:.6f}",
                ha="center",
                va="center",
                fontsize=8,
                color="white",
            )
    plt.xlabel(xlabel)
    plt.ylabel(ylabel)
    plt.title(title)
    plt.tight_layout()
    plt.savefig(output_path, dpi=200)
    plt.close()


def save_csv(rows: list[dict], output_path: Path) -> None:
    if not rows:
        return
    fieldnames = list(rows[0].keys())
    with output_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def run_benchmark(args: argparse.Namespace) -> dict:
    output_dir = Path(args.output)
    ensure_output_dir(output_dir)

    attr_values = list(range(args.attr_start, args.attr_stop + 1, args.attr_step))
    keyword_values = list(range(args.keyword_start, args.keyword_stop + 1, args.keyword_step))
    text_values = list(range(args.text_start, args.text_stop + 1, args.text_step))

    base_attributes = args.attributes_count
    base_keywords = args.keywords_count
    base_message_size = args.message_size

    attr_series = sweep_dimension(
        attr_values,
        num_attributes=base_attributes,
        num_keywords=base_keywords,
        message_size=base_message_size,
        cycles=args.cycles,
        repeats_per_cycle=args.repeats_per_cycle,
        work_multiplier=args.work_multiplier,
        seed=args.seed,
        dimension="attributes",
    )
    keyword_series = sweep_dimension(
        keyword_values,
        num_attributes=base_attributes,
        num_keywords=base_keywords,
        message_size=base_message_size,
        cycles=args.cycles,
        repeats_per_cycle=args.repeats_per_cycle,
        work_multiplier=args.work_multiplier,
        seed=args.seed + 10_000,
        dimension="keywords",
    )
    text_series = sweep_dimension(
        text_values,
        num_attributes=base_attributes,
        num_keywords=base_keywords,
        message_size=base_message_size,
        cycles=args.cycles,
        repeats_per_cycle=args.repeats_per_cycle,
        work_multiplier=args.work_multiplier,
        seed=args.seed + 20_000,
        dimension="text",
    )

    heatmap = np.zeros((len(text_values), len(keyword_values)), dtype=float)
    for i, text_size in enumerate(text_values):
        for j, keyword_count in enumerate(keyword_values):
            summary = cycle_average_runs(
                base_attributes,
                keyword_count,
                text_size,
                args.cycles,
                args.repeats_per_cycle,
                args.work_multiplier,
                args.seed + 30_000 + i * 100 + j,
            )
            heatmap[i, j] = summary["encrypt"]

    plot_line(attr_series, ["total"], ["total pipeline time"], "Total time vs attributes", "attributes", "time (seconds)", output_dir / "time_vs_attributes.png")
    plot_line(keyword_series, ["total"], ["total pipeline time"], "Total time vs keywords", "keywords", "time (seconds)", output_dir / "time_vs_keywords.png")
    plot_heatmap(keyword_values, text_values, heatmap, "Encrypted text vs keywords (encryption time)", "keywords", "encrypted text size", output_dir / "encrypted_text_keywords_heatmap.png")
    plot_line(keyword_series, ["index"], ["index stage"], "Index time vs keywords", "keywords", "time (seconds)", output_dir / "index_vs_time.png")
    plot_line(keyword_series, ["trapdoor"], ["trapdoor stage"], "Trapdoor time vs keywords", "keywords", "time (seconds)", output_dir / "trapdoor_vs_time.png")
    plot_line(attr_series, ["total", "setup", "keygen", "encrypt", "index", "trapdoor", "search", "partial_decrypt", "final_decrypt"], ["total", "setup", "keygen", "encrypt", "index", "trapdoor", "search", "partial", "final"], "Sum of stages vs time", "attributes", "time (seconds)", output_dir / "sum_vs_time.png")

    # Per-stage plots vs attributes (one file per stage)
    stages = ["setup", "keygen", "encrypt", "index", "trapdoor", "search", "partial_decrypt", "final_decrypt"]
    for stage in stages:
        # human-friendly title and filename
        nice = stage.replace("_", " ").title()
        plot_line(attr_series, [stage], [stage], f"{nice} Time vs Attributes", "attributes", "time (seconds)", output_dir / f"time_vs_attributes_{stage}.png")

    rows = []
    for x, total, setup_t, keygen_t, encrypt_t, index_t, trapdoor_t, search_t, partial_t, final_t in zip(
        attr_series.x_values,
        attr_series.raw["total"],
        attr_series.raw["setup"],
        attr_series.raw["keygen"],
        attr_series.raw["encrypt"],
        attr_series.raw["index"],
        attr_series.raw["trapdoor"],
        attr_series.raw["search"],
        attr_series.raw["partial_decrypt"],
        attr_series.raw["final_decrypt"],
    ):
        rows.append({"attributes": x, "total": total, "setup": setup_t, "keygen": keygen_t, "encrypt": encrypt_t, "index": index_t, "trapdoor": trapdoor_t, "search": search_t, "partial_decrypt": partial_t, "final_decrypt": final_t})
    save_csv(rows, output_dir / "attributes_benchmark.csv")

    rows = []
    for x, total, index_t, trapdoor_t in zip(keyword_series.x_values, keyword_series.raw["total"], keyword_series.raw["index"], keyword_series.raw["trapdoor"]):
        rows.append({"keywords": x, "total": total, "index": index_t, "trapdoor": trapdoor_t})
    save_csv(rows, output_dir / "keywords_benchmark.csv")

    return {"output_dir": str(output_dir), "attributes_points": len(attr_series.x_values), "keywords_points": len(keyword_series.x_values), "text_points": len(text_series.x_values)}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Mock searchable encryption benchmark")
    parser.add_argument("--attributes-count", type=int, default=8)
    parser.add_argument("--keywords-count", type=int, default=6)
    parser.add_argument("--message-size", type=int, default=256)
    parser.add_argument("--cycles", type=int, default=5)
    parser.add_argument("--repeats-per-cycle", type=int, default=20)
    parser.add_argument("--work-multiplier", type=int, default=200)
    parser.add_argument("--seed", type=int, default=12345)
    parser.add_argument("--output", type=str, default="outputs")

    parser.add_argument("--attr-start", type=int, default=2)
    parser.add_argument("--attr-stop", type=int, default=10)
    parser.add_argument("--attr-step", type=int, default=2)
    parser.add_argument("--keyword-start", type=int, default=2)
    parser.add_argument("--keyword-stop", type=int, default=10)
    parser.add_argument("--keyword-step", type=int, default=2)
    parser.add_argument("--text-start", type=int, default=64)
    parser.add_argument("--text-stop", type=int, default=320)
    parser.add_argument("--text-step", type=int, default=64)

    parser.add_argument("--attributes", type=str, default="", help="Optional comma-separated attribute list for a single run preview.")
    parser.add_argument("--keywords", type=str, default="", help="Optional comma-separated keyword list for a single run preview.")
    parser.add_argument("--message", type=str, default="", help="Optional message for a single run preview.")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    preview_attributes = [part.strip() for part in args.attributes.split(",") if part.strip()] if args.attributes else []
    preview_keywords = [part.strip() for part in args.keywords.split(",") if part.strip()] if args.keywords else []
    preview_message = args.message.encode("utf-8") if args.message else b""

    if preview_attributes:
        args.attributes_count = max(1, len(preview_attributes))
    if preview_keywords:
        args.keywords_count = max(1, len(preview_keywords))
    if preview_message:
        args.message_size = max(1, len(preview_message))

    result = run_benchmark(args)
    if preview_attributes or preview_keywords or preview_message:
        if not preview_attributes:
            preview_attributes = [f"attr{i + 1}" for i in range(args.attributes_count)]
        if not preview_keywords:
            preview_keywords = build_keyword_names(args.keywords_count)
        if not preview_message:
            preview_message = normalize_text("Mock searchable encryption benchmark message.", args.message_size)
        preview = measure_pipeline_from_inputs(
            preview_attributes,
            preview_keywords,
            preview_message,
            args.seed + 99_999,
            args.work_multiplier,
        )
        print(
            {
                "preview": {
                    "attributes": preview_attributes,
                    "keywords": preview_keywords,
                    "message_size": len(preview_message),
                    "success": preview["success"],
                    "total": preview["total"],
                    "encrypt": preview["encrypt"],
                    "index": preview["index"],
                    "trapdoor": preview["trapdoor"],
                }
            }
        )
    print(result)
    return 0
