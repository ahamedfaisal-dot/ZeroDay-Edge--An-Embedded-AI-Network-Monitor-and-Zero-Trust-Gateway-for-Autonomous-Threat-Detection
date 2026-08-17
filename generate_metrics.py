"""
generate_metrics.py — architecture + real measured performance report for
the models ml_engine.py actually loads and runs (not the unused
threat_model_v1.joblib — see metrics/TRAINING_METRICS.md for that one).

There's no held-out CIC-IDS-2017 test set in this repository, so this does
NOT produce accuracy/precision/recall — that would require re-deriving the
original train/test split, which needs dataset.csv (not present here). What
this DOES produce, honestly and without fabrication:
  - Real hyperparameters and feature importances, read directly from the
    trained model objects
  - Real inference latency, measured on whatever machine this runs on
  - Real memory footprint (RSS) around model loading, via psutil

Run this on the Pi (inside the venv) for numbers that actually reflect the
edge deployment:

    cd ~/EDGE_SERVER && .venv/bin/python generate_metrics.py

Writes metrics/MODEL_ARCHITECTURE.md and metrics/model_architecture.json.
"""

import io
import json
import statistics
import time
from contextlib import redirect_stdout
from pathlib import Path

import numpy as np
import psutil

MODEL_DIR = Path(__file__).parent / "ml_models"
METRICS_DIR = Path(__file__).parent / "metrics"
CHARTS_DIR = METRICS_DIR / "charts"
N_LATENCY_ITERS = 200

# Validated categorical/sequential palette (light surface) — kept in sync with
# the Artifact report so charts read as one system, not mismatched styles.
_INK = "#0b0b0b"
_MUTED = "#898781"
_GRID = "#e1e0d9"
_SURFACE = "#fcfcfb"
_SEQ_BLUE = ["#cde2fb", "#9ec5f4", "#6da7ec", "#3987e5", "#2a78d6", "#1c5cab", "#104281"]
_CAT_BLUE = "#2a78d6"
_CAT_ORANGE = "#eb6834"


def _svg_header(width: int, height: int) -> str:
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" '
            f'width="{width}" height="{height}" font-family="ui-monospace,Consolas,monospace">'
            f'<rect width="{width}" height="{height}" fill="{_SURFACE}"/>')


def _svg_hbar_chart(title: str, items: list, unit: str = "", width: int = 640) -> str:
    """Horizontal bar chart — items: [(label, value), ...], already sorted by caller."""
    bar_h, gap, left_pad, top_pad = 18, 8, 220, 46
    max_val = max((v for _, v in items), default=1) or 1
    chart_w = width - left_pad - 90
    height = top_pad + len(items) * (bar_h + gap) + 20

    parts = [_svg_header(width, height)]
    parts.append(f'<text x="16" y="26" font-size="13" font-weight="700" fill="{_INK}">{title}</text>')

    n = len(items)
    for i, (label, val) in enumerate(items):
        y = top_pad + i * (bar_h + gap)
        w = max((val / max_val) * chart_w, 2)
        # sequential shade: highest value = darkest, per skill's ranking convention
        shade_idx = int((1 - (val / max_val)) * (len(_SEQ_BLUE) - 3)) + 2
        color = _SEQ_BLUE[min(shade_idx, len(_SEQ_BLUE) - 1)]
        safe_label = (label[:26] + "…") if len(label) > 27 else label
        parts.append(f'<text x="{left_pad - 10}" y="{y + bar_h/2 + 4}" font-size="11" '
                      f'text-anchor="end" fill="{_MUTED}">{safe_label}</text>')
        parts.append(f'<rect x="{left_pad}" y="{y}" width="{w:.1f}" height="{bar_h}" '
                      f'rx="3" fill="{color}"/>')
        parts.append(f'<text x="{left_pad + w + 8:.1f}" y="{y + bar_h/2 + 4}" font-size="11" '
                      f'fill="{_INK}">{val:.4f}{unit}</text>')

    parts.append("</svg>")
    return "".join(parts)


def _svg_grouped_bar_chart(title: str, groups: list, series: list, width: int = 640, height: int = 300) -> str:
    """
    groups: [group_label, ...]
    series: [(series_label, color, [value_per_group, ...]), ...]
    """
    left_pad, bottom_pad, top_pad, right_pad = 50, 50, 46, 20
    plot_w = width - left_pad - right_pad
    plot_h = height - top_pad - bottom_pad
    max_val = max((v for _, _, vals in series for v in vals), default=1) or 1

    parts = [_svg_header(width, height)]
    parts.append(f'<text x="16" y="26" font-size="13" font-weight="700" fill="{_INK}">{title}</text>')

    # gridlines
    for frac in (0.0, 0.25, 0.5, 0.75, 1.0):
        y = top_pad + plot_h * (1 - frac)
        parts.append(f'<line x1="{left_pad}" y1="{y:.1f}" x2="{width - right_pad}" y2="{y:.1f}" '
                      f'stroke="{_GRID}" stroke-width="1"/>')
        parts.append(f'<text x="{left_pad - 8}" y="{y + 4:.1f}" font-size="9" text-anchor="end" '
                      f'fill="{_MUTED}">{max_val * frac:.1f}</text>')

    group_w = plot_w / max(len(groups), 1)
    n_series = len(series)
    bar_w = (group_w * 0.6) / max(n_series, 1)

    for gi, glabel in enumerate(groups):
        gx = left_pad + gi * group_w + group_w * 0.2
        for si, (slabel, color, values) in enumerate(series):
            v = values[gi]
            bh = (v / max_val) * plot_h
            x = gx + si * bar_w
            y = top_pad + plot_h - bh
            parts.append(f'<rect x="{x:.1f}" y="{y:.1f}" width="{bar_w - 3:.1f}" height="{bh:.1f}" '
                          f'rx="2" fill="{color}"/>')
        parts.append(f'<text x="{gx + (bar_w * n_series)/2:.1f}" y="{height - bottom_pad + 18}" '
                      f'font-size="10" text-anchor="middle" fill="{_MUTED}">{glabel}</text>')

    # legend
    lx = left_pad
    for slabel, color, _ in series:
        parts.append(f'<rect x="{lx}" y="{height - 20}" width="9" height="9" rx="2" fill="{color}"/>')
        parts.append(f'<text x="{lx + 13}" y="{height - 12}" font-size="10" fill="{_MUTED}">{slabel}</text>')
        lx += 13 + len(slabel) * 6 + 16

    parts.append("</svg>")
    return "".join(parts)

BENIGN_FLOW = {
    "source_ip": "192.168.1.10", "destination_ip": "8.8.8.8",
    "flow_duration": 1200000, "total_fwd_packets": 8, "total_bwd_packets": 7,
    "flow_bytes_per_sec": 4300,
}
MALICIOUS_FLOW = {
    "source_ip": "10.0.0.66", "destination_ip": "192.168.1.1",
    "flow_duration": 250000, "total_fwd_packets": 8000, "total_bwd_packets": 2,
    "flow_bytes_per_sec": 1280000,
    "SYN Flag Cnt": 8000, "ACK Flag Cnt": 2, "Fwd Pkt Len Mean": 40,
    "Init Fwd Win Byts": 29200, "Init Bwd Win Byts": -1,
}


def _process_rss_mb() -> float:
    return psutil.Process().memory_info().rss / (1024 * 1024)


def _file_size_kb(path: Path) -> float | None:
    return round(path.stat().st_size / 1024, 1) if path.exists() else None


def _tree_model_report(name: str, model) -> dict:
    params = model.get_params() if hasattr(model, "get_params") else {}
    report = {
        "type": type(model).__name__,
        "n_estimators": params.get("n_estimators"),
        "max_depth": params.get("max_depth"),
        "learning_rate": params.get("learning_rate"),
    }
    if hasattr(model, "feature_importances_"):
        import joblib
        try:
            cols = joblib.load(MODEL_DIR / "feature_columns.joblib")
        except Exception:
            cols = None
        importances = model.feature_importances_
        idx = np.argsort(importances)[::-1][:15]
        report["top_15_features"] = [
            {"name": (cols[i] if cols else f"feature_{i}"), "importance": round(float(importances[i]), 5)}
            for i in idx
        ]
    return report


def _deep_model_report(name: str, model, model_dir: Path) -> dict:
    tflite_path = model_dir / f"{name}.tflite"
    h5_path = model_dir / f"{name}.h5"

    if tflite_path.exists():
        return {
            "runtime": "tflite",
            "file_size_kb": _file_size_kb(tflite_path),
            "note": "Quantized TFLite model — internal layer parameter count isn't "
                    "introspectable the way a Keras model's is; file size is the "
                    "practical proxy for footprint.",
        }
    if h5_path.exists():
        try:
            buf = io.StringIO()
            with redirect_stdout(buf):
                model.summary()
            param_count = model.count_params()
        except Exception as e:
            return {"runtime": "keras (.h5)", "error": str(e)}
        return {
            "runtime": "keras (.h5)",
            "file_size_kb": _file_size_kb(h5_path),
            "total_params": int(param_count),
            "summary": buf.getvalue(),
        }
    return {"runtime": "not loaded"}


def _latency_benchmark(engine, flow: dict, label: str) -> dict:
    # Warm-up (first call may pay one-time lazy-init costs)
    engine.classify(flow)

    samples_ms = []
    for _ in range(N_LATENCY_ITERS):
        start = time.perf_counter()
        engine.classify(flow)
        samples_ms.append((time.perf_counter() - start) * 1000)

    samples_ms.sort()
    n = len(samples_ms)
    return {
        "label": label,
        "iterations": n,
        "mean_ms": round(statistics.mean(samples_ms), 3),
        "median_ms": round(statistics.median(samples_ms), 3),
        "p95_ms": round(samples_ms[int(n * 0.95) - 1], 3),
        "p99_ms": round(samples_ms[int(n * 0.99) - 1], 3),
        "min_ms": round(samples_ms[0], 3),
        "max_ms": round(samples_ms[-1], 3),
    }


def main():
    METRICS_DIR.mkdir(exist_ok=True)
    CHARTS_DIR.mkdir(exist_ok=True)

    rss_before = _process_rss_mb()
    from ml_engine import MLEngine
    engine = MLEngine()
    load_start = time.perf_counter()
    engine.load()
    load_time_s = time.perf_counter() - load_start
    rss_after = _process_rss_mb()

    report = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "model_load": {
            "load_time_seconds": round(load_time_s, 3),
            "rss_before_mb": round(rss_before, 1),
            "rss_after_mb": round(rss_after, 1),
            "rss_delta_mb": round(rss_after - rss_before, 1),
        },
        "models": {},
        "latency": {},
    }

    if engine.xgb is not None:
        report["models"]["xgboost"] = _tree_model_report("xgboost", engine.xgb)
        report["models"]["xgboost"]["file_size_kb"] = _file_size_kb(MODEL_DIR / "xgboost_model.joblib")
    if engine.rf is not None:
        report["models"]["random_forest"] = _tree_model_report("random_forest", engine.rf)
        report["models"]["random_forest"]["file_size_kb"] = _file_size_kb(MODEL_DIR / "rf_model.joblib")
    if engine.autoencoder is not None:
        report["models"]["autoencoder"] = _deep_model_report("autoencoder", engine.autoencoder, MODEL_DIR)
    if engine.bilstm is not None:
        report["models"]["bilstm"] = _deep_model_report("bilstm", engine.bilstm, MODEL_DIR)

    report["models"]["feature_count"] = len(engine.feature_columns) if engine.feature_columns else None

    report["latency"]["benign_flow"] = _latency_benchmark(engine, BENIGN_FLOW, "benign")
    report["latency"]["malicious_flow"] = _latency_benchmark(engine, MALICIOUS_FLOW, "malicious")

    _write_charts(report)

    (METRICS_DIR / "model_architecture.json").write_text(json.dumps(report, indent=2))

    md = _render_markdown(report)
    (METRICS_DIR / "MODEL_ARCHITECTURE.md").write_text(md)

    print(md)
    print(f"\nWritten to {METRICS_DIR / 'MODEL_ARCHITECTURE.md'} and {METRICS_DIR / 'model_architecture.json'}")


def _write_charts(r: dict):
    xgb = r["models"].get("xgboost")
    if xgb and xgb.get("top_15_features"):
        items = [(f["name"], f["importance"]) for f in xgb["top_15_features"]]
        svg = _svg_hbar_chart("XGBoost — Top 15 Features by Importance", items)
        (CHARTS_DIR / "feature_importance.svg").write_text(svg)

    lat = r["latency"]
    svg = _svg_grouped_bar_chart(
        "Inference Latency by Flow Type",
        groups=["mean", "p95", "p99"],
        series=[
            ("benign", _CAT_BLUE, [lat["benign_flow"]["mean_ms"], lat["benign_flow"]["p95_ms"], lat["benign_flow"]["p99_ms"]]),
            ("malicious", _CAT_ORANGE, [lat["malicious_flow"]["mean_ms"], lat["malicious_flow"]["p95_ms"], lat["malicious_flow"]["p99_ms"]]),
        ],
    )
    (CHARTS_DIR / "latency.svg").write_text(svg)

    ml = r["model_load"]
    svg = _svg_grouped_bar_chart(
        "Process Memory (RSS) Around Model Load",
        groups=["before", "after"],
        series=[("RSS (MB)", _CAT_BLUE, [ml["rss_before_mb"], ml["rss_after_mb"]])],
        width=360, height=260,
    )
    (CHARTS_DIR / "memory.svg").write_text(svg)


def _render_markdown(r: dict) -> str:
    lines = [
        "# Deployed Model Architecture & Measured Performance",
        "",
        f"Generated: {r['generated_at']}",
        "",
        "Real numbers measured on this machine — not estimates. See "
        "`TRAINING_METRICS.md` for the one real accuracy/precision/recall/F1 "
        "figure that exists in this project (for a related but different, "
        "unused model).",
        "",
        "## Model Loading",
        "",
        f"- Load time: **{r['model_load']['load_time_seconds']} s**",
        f"- RSS before load: {r['model_load']['rss_before_mb']} MB",
        f"- RSS after load: {r['model_load']['rss_after_mb']} MB",
        f"- **Memory added by loading all models: {r['model_load']['rss_delta_mb']} MB**",
        "",
        f"- Trained feature count: {r['models'].get('feature_count')}",
        "",
        "## Stage 1 — Tree Ensemble",
        "",
    ]

    for key, title in [("xgboost", "XGBoost"), ("random_forest", "Random Forest")]:
        m = r["models"].get(key)
        if not m:
            lines.append(f"### {title}: not loaded\n")
            continue
        lines += [
            f"### {title}",
            "",
            f"- `n_estimators`: {m.get('n_estimators')}",
            f"- `max_depth`: {m.get('max_depth')}",
            f"- `learning_rate`: {m.get('learning_rate')}",
            f"- File size: {m.get('file_size_kb')} KB",
            "",
        ]
        if m.get("top_15_features"):
            if key == "xgboost":
                lines.append("![Feature importance](charts/feature_importance.svg)\n")
            lines.append("**Top 15 features by importance:**\n")
            lines.append("| Feature | Importance |")
            lines.append("|---|---|")
            for f in m["top_15_features"]:
                lines.append(f"| {f['name']} | {f['importance']} |")
            lines.append("")

    lines += ["## Stage 2/3 — Deep Models", ""]
    for key, title in [("autoencoder", "Autoencoder (Zero-Day)"), ("bilstm", "BiLSTM (Temporal)")]:
        m = r["models"].get(key)
        if not m:
            lines.append(f"### {title}: not loaded (EDGE_LITE_MODE or missing model files)\n")
            continue
        lines += [f"### {title}", "", f"- Runtime: {m.get('runtime')}"]
        if "file_size_kb" in m:
            lines.append(f"- File size: {m['file_size_kb']} KB")
        if "total_params" in m:
            lines.append(f"- Total parameters: {m['total_params']:,}")
        if "note" in m:
            lines.append(f"- Note: {m['note']}")
        lines.append("")

    lines += ["## Inference Latency (this machine)", "", "![Latency](charts/latency.svg)", "",
              "| Flow | Iterations | Mean | Median | P95 | P99 | Min | Max |", "|---|---|---|---|---|---|---|---|"]
    for key in ("benign_flow", "malicious_flow"):
        l = r["latency"][key]
        lines.append(
            f"| {l['label']} | {l['iterations']} | {l['mean_ms']} ms | {l['median_ms']} ms | "
            f"{l['p95_ms']} ms | {l['p99_ms']} ms | {l['min_ms']} ms | {l['max_ms']} ms |"
        )
    lines += ["", "## Memory Footprint", "", "![Memory](charts/memory.svg)", ""]

    return "\n".join(lines)


if __name__ == "__main__":
    main()
