#!/usr/bin/env bash
# install.sh — One-shot setup for ZeroDay-Edge Node (Raspberry Pi 4B / 4GB tuned)
# Run once as: sudo bash install.sh
#
# What this does:
#  1. Updates system & installs OS packages
#  2. Ensures swap space exists (4GB RAM is tight for ML + Chromium kiosk)
#  3. Creates Python venv + installs requirements
#  4. Copies ML models from the main backend
#  5. Sets up a systemd service (auto-start on boot) with memory/CPU limits
#  6. Configures Chromium kiosk on DISPLAY :0 (skip with LITE_KIOSK=1)
#
# Env overrides:
#   LITE_KIOSK=1   Skip installing/configuring the Chromium kiosk — run the
#                  server headless and view the dashboard from another device
#                  at http://<pi-ip>:5000. Recommended if RAM is very tight.
#   EDGE_LITE_MODE=1  Passed through to the systemd service — skips deep
#                  learning stages + SHAP, tree-ensemble classification only.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$SCRIPT_DIR/.venv"
SERVICE_NAME="cybershield-edge"
MAIN_ML_DIR="$SCRIPT_DIR/../backend/ml_models"
LITE_KIOSK="${LITE_KIOSK:-0}"
EDGE_LITE_MODE="${EDGE_LITE_MODE:-0}"

echo ""
echo "╔══════════════════════════════════════════╗"
echo "║  ZeroDay-Edge — Setup Script             ║"
echo "║  Embedded AI Network Monitor             ║"
echo "╚══════════════════════════════════════════╝"
echo ""

# ── 1. System packages ────────────────────────────────────────────────
echo "[1/6] Installing system packages…"
apt-get update -qq
apt-get install -y --no-install-recommends \
    python3 python3-pip python3-venv \
    libpcap-dev \
    libopenblas-dev \
    dphys-swapfile

if [ "$LITE_KIOSK" != "1" ]; then
    apt-get install -y --no-install-recommends \
        chromium-browser \
        x11-xserver-utils \
        unclutter
fi

echo "      ✓ System packages installed"

# ── 2. Swap space ────────────────────────────────────────────────────
# 4GB RAM is genuinely tight once ML models + Flask + Scapy + (optionally)
# Chromium kiosk are all resident. Swap is a safety net against OOM kills,
# not a performance feature — the SD card is slow, so this trades an
# occasional stall for staying up. Bump CONF_SWAPSIZE if you still see OOM
# kills in `dmesg`.
echo "[2/6] Configuring swap…"
if [ -f /etc/dphys-swapfile ]; then
    CURRENT_SWAP=$(grep -oP '^CONF_SWAPSIZE=\K\d+' /etc/dphys-swapfile 2>/dev/null || echo 0)
    if [ "${CURRENT_SWAP:-0}" -lt 1024 ]; then
        dphys-swapfile swapoff 2>/dev/null || true
        sed -i 's/^CONF_SWAPSIZE=.*/CONF_SWAPSIZE=1024/' /etc/dphys-swapfile
        grep -q '^CONF_SWAPSIZE=' /etc/dphys-swapfile || echo 'CONF_SWAPSIZE=1024' >> /etc/dphys-swapfile
        dphys-swapfile setup
        dphys-swapfile swapon
        echo "      ✓ Swap set to 1024MB"
    else
        echo "      ✓ Swap already >= 1024MB — leaving as-is"
    fi
else
    echo "      ⚠ dphys-swapfile not found — configure swap manually if you see OOM kills"
fi

# ── 3. Python virtual environment ─────────────────────────────────────
echo "[3/6] Creating Python venv at $VENV_DIR …"
python3 -m venv "$VENV_DIR"

echo "      Installing Python packages (this takes a few minutes on a Pi 4)…"

# Upgrade pip first
"$VENV_DIR/bin/pip" install --upgrade pip --quiet

# Install requirements. tflite-runtime (not full TensorFlow) is used for
# deep-learning inference — see requirements.txt / convert_to_tflite.py.
# Only fall back to `pip install tensorflow-aarch64` on-device if you
# genuinely can't run the conversion step elsewhere first.
"$VENV_DIR/bin/pip" install -r "$SCRIPT_DIR/requirements.txt" --quiet

echo "      ✓ Python packages installed"

# ── 4. ML Model files ─────────────────────────────────────────────────
echo "[4/6] Copying ML model files…"
mkdir -p "$SCRIPT_DIR/ml_models"

MODEL_FILES=(
    "xgboost_model.joblib"
    "rf_model.joblib"
    "autoencoder.tflite"
    "bilstm.tflite"
    "autoencoder.h5"
    "bilstm.h5"
    "scaler.joblib"
    "feature_columns.joblib"
)

if [ -d "$MAIN_ML_DIR" ]; then
    for f in "${MODEL_FILES[@]}"; do
        src="$MAIN_ML_DIR/$f"
        dst="$SCRIPT_DIR/ml_models/$f"
        if [ -f "$src" ]; then
            cp "$src" "$dst"
            echo "      ✓ $f"
        else
            echo "      ⚠ $f not found in $MAIN_ML_DIR — skipping"
        fi
    done
else
    echo "      ⚠ Main backend ml_models directory not found at $MAIN_ML_DIR"
    echo "        Copy model files manually to: $SCRIPT_DIR/ml_models/"
fi

if [ "$LITE_KIOSK" != "1" ] && [ "$EDGE_LITE_MODE" != "1" ]; then
    if [ ! -f "$SCRIPT_DIR/ml_models/autoencoder.tflite" ] && [ -f "$SCRIPT_DIR/ml_models/autoencoder.h5" ]; then
        echo ""
        echo "      ⚠ Running Chromium kiosk + full TensorFlow (.h5 fallback, no .tflite"
        echo "        found) is the tightest RAM combination on a 4GB Pi 4. Recommended:"
        echo "          1. Run convert_to_tflite.py on a dev machine, copy the .tflite"
        echo "             files into ml_models/, and re-run this installer, OR"
        echo "          2. Re-run with EDGE_LITE_MODE=1 to skip the deep models."
        echo ""
    fi
fi

# ── 5. Systemd service ────────────────────────────────────────────────
echo "[5/6] Creating systemd service: $SERVICE_NAME…"

cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<EOF
[Unit]
Description=ZeroDay-Edge — Embedded AI Network Monitor (Flask)
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=${SCRIPT_DIR}
ExecStart=${VENV_DIR}/bin/python ${SCRIPT_DIR}/app.py
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
Environment=PYTHONUNBUFFERED=1
Environment=EDGE_LITE_MODE=${EDGE_LITE_MODE}
# Caps this service so it can't crowd out Chromium/the OS and get itself
# OOM-killed instead of just degrading. Kiosk mode keeps Chromium resident
# on this same 4GB box the whole time (unlike a headless deploy), so the
# ML server gets a tighter slice: OS ~400-600M, Chromium ~400-700M even
# trimmed, leaving roughly this much for Flask+Scapy+models+swap headroom.
MemoryMax=1600M
MemoryHigh=1300M
CPUWeight=80

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable "$SERVICE_NAME"

echo "      ✓ Service created and enabled (EDGE_LITE_MODE=${EDGE_LITE_MODE})"
echo "        Start now:  sudo systemctl start $SERVICE_NAME"
echo "        View logs:  sudo journalctl -fu $SERVICE_NAME"

# ── 6. Chromium kiosk autostart ───────────────────────────────────────
echo "[6/6] Configuring Chromium kiosk autostart…"

if [ "$LITE_KIOSK" = "1" ]; then
    echo "      LITE_KIOSK=1 — skipping kiosk setup."
    echo "      View the dashboard from another device: http://<pi-ip>:5000"
else
    AUTOSTART_DIR="/etc/xdg/lxsession/LXDE-pi"
    mkdir -p "$AUTOSTART_DIR"

    # Disable screen blanking. Chromium flags trim its own footprint
    # (disable GPU compositing/shared-memory tricks that assume more RAM
    # than a 4GB Pi 4 has to spare while the ML server is also running).
    cat >> "$AUTOSTART_DIR/autostart" <<'EOF'

# ZeroDay-Edge kiosk
@xset s noblank
@xset s off
@xset -dpms
@unclutter -idle 0 -root
@chromium-browser --kiosk --no-sandbox --disable-infobars \
  --disable-session-crashed-bubble --disable-restore-session-state \
  --noerrdialogs --disable-gpu --disable-software-rasterizer \
  --disable-dev-shm-usage --disk-cache-size=1 \
  --app=http://localhost:5000
EOF

    echo "      ✓ Chromium kiosk configured (memory-trimmed flags)"
fi

echo ""
echo "╔══════════════════════════════════════════╗"
echo "║  Setup complete — ZeroDay-Edge           ║"
echo "║                                          ║"
echo "║  To start the edge node now:             ║"
echo "║    sudo systemctl start cybershield-edge ║"
echo "║                                          ║"
echo "║  Dashboard auto-opens on next reboot     ║"
echo "║  in Chromium kiosk mode.                 ║"
echo "║                                          ║"
echo "║  Remote access from any device:          ║"
echo "║    http://<rpi-ip>:5000                  ║"
echo "╚══════════════════════════════════════════╝"
echo ""
