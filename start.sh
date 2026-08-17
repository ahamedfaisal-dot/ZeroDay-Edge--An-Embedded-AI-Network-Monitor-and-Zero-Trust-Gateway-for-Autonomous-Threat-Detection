#!/usr/bin/env bash
# start.sh — Manual start for the ZeroDay-Edge Node
# Usage: bash start.sh
#        sudo bash start.sh   (required for packet capture / iptables)
#
# Env overrides (see ml_engine.py / app.py for details):
#   EDGE_LITE_MODE=1        Skip deep-learning stages + SHAP (tree-ensemble only)
#   EDGE_FLOW_INTERVAL=N    Seconds between flow-drain/classify passes (default 5)
#   EDGE_ARP_INTERVAL=N     Seconds between ARP scans (default 60)
#   EDGE_ML_THREADS=N       Thread cap for XGBoost/RF/tflite (default 2)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_PYTHON="$SCRIPT_DIR/.venv/bin/python"

# Fall back to system python if venv not yet created
if [ ! -f "$VENV_PYTHON" ]; then
    VENV_PYTHON="python3"
    echo "Warning: venv not found — using system python3"
    echo "Run 'sudo bash install.sh' for full setup"
fi

echo ""
  echo "  ZeroDay-Edge — Embedded AI Network Monitor"
echo "  Dashboard → http://$(hostname -I | awk '{print $1}'):5000"
echo ""

exec "$VENV_PYTHON" "$SCRIPT_DIR/app.py"
