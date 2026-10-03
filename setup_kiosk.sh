#!/usr/bin/env bash
# setup_kiosk.sh — one-time setup: boot straight into the ZeroDay-Edge dashboard.
#
#   bash setup_kiosk.sh
#
# After this and a reboot, with NO typing and NO password prompts:
#   1. the edge server starts by itself (systemd service, runs as root, so
#      packet capture + firewall work without sudo),
#   2. the Pi logs into the desktop automatically (autologin),
#   3. Chromium opens the dashboard full-screen (kiosk) once the server is up.
#
# Re-run safely any time (idempotent). Undo: bash setup_kiosk.sh --remove
#
# The sudo password is taken from EDGE_SUDO_PASSWORD (default "pi"), the same
# convention as install.sh / start.sh — only used for THIS script's own sudo.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT_PATH="$SCRIPT_DIR/$(basename "${BASH_SOURCE[0]}")"

# ── Elevate (absolute path so "command not found" can't happen) ───────────
if [ "$EUID" -ne 0 ]; then
    echo "Not root — re-launching with sudo..."
    echo "${EDGE_SUDO_PASSWORD:-pi}" | exec sudo -S -E bash "$SCRIPT_PATH" "$@"
fi

# The desktop user (the one who ran sudo), not root
TARGET_USER="${SUDO_USER:-}"
if [ -z "$TARGET_USER" ] || [ "$TARGET_USER" = "root" ]; then
    TARGET_USER="$(stat -c %U "$SCRIPT_DIR")"
fi
USER_HOME="$(getent passwd "$TARGET_USER" | cut -d: -f6)"
SERVICE_NAME="cybershield-edge"
PORT="${EDGE_PORT:-5000}"
URL="http://localhost:${PORT}"
LAUNCHER="$SCRIPT_DIR/kiosk_launch.sh"
PROFILE_DIR="$USER_HOME/.config/chromium-kiosk"

# ── Remove mode ───────────────────────────────────────────────────────────
if [ "${1:-}" = "--remove" ]; then
    systemctl disable --now "$SERVICE_NAME" 2>/dev/null || true
    rm -f "/etc/systemd/system/${SERVICE_NAME}.service" "/etc/sudoers.d/zeroday-edge"
    rm -f "$USER_HOME/.config/labwc/autostart" "$USER_HOME/.config/autostart/zeroday-kiosk.desktop"
    rm -f "$USER_HOME/.config/lxsession/LXDE-pi/autostart" "$LAUNCHER"
    systemctl daemon-reload
    echo "Kiosk + service removed. (Autologin left as is: sudo raspi-config → System → Boot / Auto Login)"
    exit 0
fi

echo "ZeroDay-Edge kiosk setup"
echo "  desktop user : $TARGET_USER ($USER_HOME)"
echo "  app folder   : $SCRIPT_DIR"

# ── 1. Python (the venv you already created) ──────────────────────────────
PYBIN=""
for v in "$SCRIPT_DIR/venv/bin/python" "$SCRIPT_DIR/.venv/bin/python"; do
    [ -x "$v" ] && PYBIN="$v" && break
done
if [ -z "$PYBIN" ]; then
    echo "ERROR: no venv found in $SCRIPT_DIR (expected venv/ or .venv/)."
    echo "       Create it first:  python3 -m venv venv && ./venv/bin/pip install -r requirements.txt"
    exit 1
fi
echo "[1/6] Python: $PYBIN"

# ── 2. Packages: Chromium (+ cursor hider for X11) ────────────────────────
echo "[2/6] Checking Chromium..."
BROWSER=""
for b in chromium chromium-browser; do
    command -v "$b" >/dev/null 2>&1 && BROWSER="$b" && break
done
if [ -z "$BROWSER" ]; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq || true
    apt-get install -y -qq chromium 2>/dev/null || apt-get install -y -qq chromium-browser
    for b in chromium chromium-browser; do
        command -v "$b" >/dev/null 2>&1 && BROWSER="$b" && break
    done
fi
[ -n "$BROWSER" ] || { echo "ERROR: could not install Chromium"; exit 1; }
apt-get install -y -qq unclutter 2>/dev/null || true   # X11 cursor hiding; harmless if absent
echo "      ✓ $BROWSER"

# ── 3. systemd service: server starts on boot, as root ────────────────────
echo "[3/6] Installing service: $SERVICE_NAME"
cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<EOF
[Unit]
Description=ZeroDay-Edge — Embedded AI Network Monitor
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=${SCRIPT_DIR}
ExecStart=${PYBIN} ${SCRIPT_DIR}/app.py
Restart=always
RestartSec=5
Environment=PYTHONUNBUFFERED=1
Environment=EDGE_NO_SUDO=1
# Never auto-block the gateway / this Pi; add your admin PC here so a test
# attack from it can never cut your SSH session:
Environment=EDGE_WHITELIST=${EDGE_WHITELIST:-}

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable "$SERVICE_NAME" >/dev/null 2>&1

# Free the port if a hand-started copy is still running, then (re)start
pkill -f "$SCRIPT_DIR/app.py" 2>/dev/null || true
pkill -f "python.* app.py" 2>/dev/null || true
sleep 1
systemctl restart "$SERVICE_NAME"
echo "      ✓ enabled + started (logs: sudo journalctl -fu $SERVICE_NAME)"

# Let the desktop user control just this service without a password
cat > /etc/sudoers.d/zeroday-edge <<EOF
${TARGET_USER} ALL=(root) NOPASSWD: /usr/bin/systemctl start ${SERVICE_NAME}, /usr/bin/systemctl stop ${SERVICE_NAME}, /usr/bin/systemctl restart ${SERVICE_NAME}, /usr/bin/systemctl status ${SERVICE_NAME}, /usr/bin/journalctl -fu ${SERVICE_NAME}
EOF
chmod 440 /etc/sudoers.d/zeroday-edge
visudo -cf /etc/sudoers.d/zeroday-edge >/dev/null || { rm -f /etc/sudoers.d/zeroday-edge; echo "      (sudoers rule rejected, removed)"; }

# ── 4. Kiosk launcher ─────────────────────────────────────────────────────
echo "[4/6] Writing kiosk launcher"
cat > "$LAUNCHER" <<EOF
#!/usr/bin/env bash
# Opens the dashboard in Chromium kiosk mode. Safe to start more than once.
exec 9>/tmp/zeroday-kiosk.lock
flock -n 9 || exit 0

# Wait (up to 3 min) for the edge server to answer
for i in \$(seq 1 90); do
    curl -fs -o /dev/null "${URL}/api/stats" && break
    sleep 2
done

# Don't show "Chromium didn't shut down correctly" after a power cut
mkdir -p "${PROFILE_DIR}/Default"
sed -i 's/"exited_cleanly":false/"exited_cleanly":true/; s/"exit_type":"Crashed"/"exit_type":"Normal"/' \\
    "${PROFILE_DIR}/Default/Preferences" "${PROFILE_DIR}/Local State" 2>/dev/null || true

# --password-store=basic  : never touches the GNOME/KWallet keyring, so there is
#                           no "enter password to unlock keyring" prompt
exec ${BROWSER} \\
  --kiosk "${URL}" \\
  --user-data-dir="${PROFILE_DIR}" \\
  --password-store=basic \\
  --no-first-run --no-default-browser-check \\
  --noerrdialogs --disable-infobars \\
  --disable-session-crashed-bubble --disable-restore-session-state \\
  --disable-features=Translate,PasswordManagerOnboarding,HttpsUpgrades \\
  --disable-pinch --overscroll-history-navigation=0 \\
  --check-for-update-interval=31536000 \\
  --ozone-platform-hint=auto
EOF
chmod +x "$LAUNCHER"
chown "$TARGET_USER":"$TARGET_USER" "$LAUNCHER"
mkdir -p "$PROFILE_DIR" && chown -R "$TARGET_USER":"$TARGET_USER" "$PROFILE_DIR"

# ── 5. Autostart in the desktop session (Wayland/labwc, X11/LXDE, generic) ─
echo "[5/6] Wiring desktop autostart"
as_user() { sudo -u "$TARGET_USER" "$@"; }

# Wayland (current Raspberry Pi OS: labwc). A user autostart replaces the
# system one, so the panel/wallpaper don't start — exactly what a kiosk wants.
as_user mkdir -p "$USER_HOME/.config/labwc"
cat > "$USER_HOME/.config/labwc/autostart" <<EOF
# ZeroDay-Edge kiosk
"$LAUNCHER" &
EOF

# X11 (older Pi OS / LXDE-pi): no blanking, hidden cursor, kiosk
as_user mkdir -p "$USER_HOME/.config/lxsession/LXDE-pi"
cat > "$USER_HOME/.config/lxsession/LXDE-pi/autostart" <<EOF
@xset s noblank
@xset s off
@xset -dpms
@unclutter -idle 0.5 -root
@$LAUNCHER
EOF

# Generic XDG autostart as a belt-and-braces fallback (the launcher's lock
# makes a double start harmless)
as_user mkdir -p "$USER_HOME/.config/autostart"
cat > "$USER_HOME/.config/autostart/zeroday-kiosk.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=ZeroDay-Edge Kiosk
Exec=$LAUNCHER
X-GNOME-Autostart-enabled=true
EOF
chown -R "$TARGET_USER":"$TARGET_USER" "$USER_HOME/.config/labwc" "$USER_HOME/.config/lxsession" "$USER_HOME/.config/autostart"

# ── 6. Boot to desktop, auto-login, no screen blanking ────────────────────
echo "[6/6] Autologin + no screen blanking"
if command -v raspi-config >/dev/null 2>&1; then
    raspi-config nonint do_boot_behaviour B4 || echo "      (could not set autologin — set it in raspi-config → System → Boot)"
    raspi-config nonint do_blanking 1       || true
    echo "      ✓ desktop autologin on, blanking off"
else
    echo "      raspi-config not found — enable desktop autologin in your display manager manually"
fi

echo ""
echo "Done. Reboot to see it:   sudo reboot"
echo "  Dashboard from any PC : http://$(hostname -I | awk '{print $1}'):${PORT}"
echo "  Leave kiosk (keyboard): Alt+F4   |   undo everything: bash setup_kiosk.sh --remove"
