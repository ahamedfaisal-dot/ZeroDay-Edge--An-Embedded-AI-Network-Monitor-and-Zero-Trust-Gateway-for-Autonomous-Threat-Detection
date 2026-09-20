"""
plot_metrics.py — simple matplotlib charts from real metrics data.

Two data sources, both real:
  1. Training-time accuracy/precision/recall/F1 — hardcoded here because
     it's a single fixed result already extracted from
     scripts/modelTrainingScript.ipynb's saved output (see
     metrics/TRAINING_METRICS.md for the full writeup).
  2. metrics/model_architecture.json — written by generate_metrics.py when
     run on the Pi. If it's not there yet, this script just skips those
     charts instead of making anything up.

Usage:
    pip install matplotlib
    python plot_metrics.py
"""

import json
from pathlib import Path

import matplotlib.pyplot as plt

METRICS_DIR = Path(__file__).parent / "metrics"
ARCH_JSON = METRICS_DIR / "model_architecture.json"

# Real numbers from scripts/modelTrainingScript.ipynb's saved output.
TRAINING_METRICS = {"Accuracy": 0.9988, "Precision": 0.9988, "Recall": 0.9988, "F1 Score": 0.9988}


def plot_training_metrics():
    labels = list(TRAINING_METRICS.keys())
    values = list(TRAINING_METRICS.values())

    fig, ax = plt.subplots(figsize=(6, 4))
    bars = ax.bar(labels, values, color="#2a78d6")
    ax.set_ylim(0, 1.05)
    ax.set_ylabel("Score")
    ax.set_title("Training-Time Metrics (threat_model_v1, held-out test set)")
    for bar, val in zip(bars, values):
        ax.text(bar.get_x() + bar.get_width() / 2, val + 0.02, f"{val:.2%}", ha="center", fontsize=9)

    fig.tight_layout()
    out = METRICS_DIR / "training_metrics.png"
    fig.savefig(out, dpi=150)
    plt.close(fig)
    print(f"Wrote {out}")


def plot_feature_importance(report: dict):
    xgb = report.get("models", {}).get("xgboost", {})
    features = xgb.get("top_15_features")
    if not features:
        print("No feature importance data in model_architecture.json — skipping.")
        return

    names = [f["name"] for f in features][::-1]
    importances = [f["importance"] for f in features][::-1]

    fig, ax = plt.subplots(figsize=(7, 5))
    ax.barh(names, importances, color="#2a78d6")
    ax.set_xlabel("Importance")
    ax.set_title("XGBoost — Top 15 Features")

    fig.tight_layout()
    out = METRICS_DIR / "feature_importance.png"
    fig.savefig(out, dpi=150)
    plt.close(fig)
    print(f"Wrote {out}")


def plot_latency(report: dict):
    latency = report.get("latency")
    if not latency:
        print("No latency data in model_architecture.json — skipping.")
        return

    metrics = ["mean_ms", "p95_ms", "p99_ms"]
    x = range(len(metrics))
    width = 0.35

    fig, ax = plt.subplots(figsize=(6, 4))
    benign_vals = [latency["benign_flow"][m] for m in metrics]
    malicious_vals = [latency["malicious_flow"][m] for m in metrics]

    ax.bar([i - width / 2 for i in x], benign_vals, width, label="benign", color="#2a78d6")
    ax.bar([i + width / 2 for i in x], malicious_vals, width, label="malicious", color="#eb6834")
    ax.set_xticks(list(x))
    ax.set_xticklabels(["mean", "p95", "p99"])
    ax.set_ylabel("Latency (ms)")
    ax.set_title("Inference Latency by Flow Type")
    ax.legend()

    fig.tight_layout()
    out = METRICS_DIR / "latency.png"
    fig.savefig(out, dpi=150)
    plt.close(fig)
    print(f"Wrote {out}")


def plot_memory(report: dict):
    load = report.get("model_load")
    if not load:
        print("No memory data in model_architecture.json — skipping.")
        return

    fig, ax = plt.subplots(figsize=(4, 4))
    ax.bar(["before load", "after load"], [load["rss_before_mb"], load["rss_after_mb"]], color="#2a78d6")
    ax.set_ylabel("RSS (MB)")
    ax.set_title("Process Memory Around Model Load")

    fig.tight_layout()
    out = METRICS_DIR / "memory.png"
    fig.savefig(out, dpi=150)
    plt.close(fig)
    print(f"Wrote {out}")


def main():
    METRICS_DIR.mkdir(exist_ok=True)
    plot_training_metrics()

    # Generate separate metric graphs if evaluation_report.json exists
    eval_report_path = METRICS_DIR / "evaluation_report.json"
    if eval_report_path.exists():
        import sys
        scripts_dir = str(Path(__file__).parent.parent / "scripts")
        if scripts_dir not in sys.path:
            sys.path.insert(0, scripts_dir)
        try:
            from generate_metric_plots import (
                plot_accuracy,
                plot_precision,
                plot_recall,
                plot_f1_score,
                plot_specificity,
                plot_false_positive_rate,
                plot_confusion_matrix,
                plot_roc_curve,
                plot_pr_curve,
                plot_per_class_metrics,
                plot_model_comparison,
                plot_summary_dashboard,
                setup_matplotlib_style,
            )
            setup_matplotlib_style()
            ev_data = json.loads(eval_report_path.read_text(encoding="utf-8"))
            print("\nGenerating separate metric graphs from evaluation_report.json...")
            plot_accuracy(ev_data)
            plot_precision(ev_data)
            plot_recall(ev_data)
            plot_f1_score(ev_data)
            plot_specificity(ev_data)
            plot_false_positive_rate(ev_data)
            plot_confusion_matrix(ev_data)
            plot_roc_curve(ev_data)
            plot_pr_curve(ev_data)
            plot_per_class_metrics(ev_data)
            plot_feature_importance(ev_data)
            plot_model_comparison(ev_data)
            plot_summary_dashboard(ev_data)
            print("[OK] Separate metric graphs created in metrics/ and metrics/plots/")
        except Exception as e:
            print(f"Note: Could not run generate_metric_plots: {e}")

    if ARCH_JSON.exists():
        report = json.loads(ARCH_JSON.read_text())
        plot_feature_importance(report)
        plot_latency(report)
        plot_memory(report)
    else:
        print(f"\n{ARCH_JSON} not found — run generate_metrics.py first for the "
              f"deployed-model charts (feature importance / latency / memory).")


if __name__ == "__main__":
    main()

