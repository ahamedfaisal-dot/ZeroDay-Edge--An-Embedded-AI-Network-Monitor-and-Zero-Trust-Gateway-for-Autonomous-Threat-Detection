#!/usr/bin/env bash
# kiosk_launch.sh — open the dashboard in Chromium kiosk mode on the Pi's screen.
#
# Started automatically by app.py / start.sh when you run the server from a
# terminal (SSH included). The server runs as root, but Chromium must run as
# the logged-in DESKTOP user, so this finds that user's graphical session
# (Wayland or X11) and starts Chromium inside it. No passwords involved.
#
# Needs the Pi to be on its desktop (enable once: sudo raspi-config →
# System Options → Boot / Auto Login → Desktop Autologin).
#
# Env: EDGE_KIOSK=0 disables it · EDGE_KIOSK_USER=name picks the desktop user ·
#      EDGE_PORT (default 5000). Log: /tmp/zeroday-kiosk.log

LOG=/tmp/zeroday-kiosk.log
P="[kiosk]"
# Log to the file AND to the terminal that started the server
exec > >(tee -a "$LOG") 2>&1
echo "=== $(date) kiosk_launch ==="

[ "${EDGE_KIOSK:-1}" = "0" ] && { echo "$P disabled (EDGE_KIOSK=0)"; exit 0; }

# Only one launcher at a time
exec 9>/tmp/zeroday-kiosk.lock
flock -n 9 || { echo "$P already launching"; exit 0; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PORT="${EDGE_PORT:-5000}"
URL="http://localhost:${PORT}"

# ── Desktop user ──────────────────────────────────────────────────────────
KUSER="${EDGE_KIOSK_USER:-${SUDO_USER:-}}"
if [ -z "$KUSER" ] || [ "$KUSER" = "root" ]; then
    KUSER="$(stat -c %U "$SCRIPT_DIR")"
fi
if ! id "$KUSER" >/dev/null 2>&1 || [ "$KUSER" = "root" ]; then
    echo "$P no desktop user found (set EDGE_KIOSK_USER)"; exit 1
fi
KUID="$(id -u "$KUSER")"
KHOME="$(getent passwd "$KUSER" | cut -d: -f6)"
RUNTIME="/run/user/$KUID"
# Profile + config + cache live in /tmp (RAM): a kiosk needs no persistence, it
# spares the SD card, and it keeps working even if the home folder has
# filesystem errors ("Structure needs cleaning").
PROFILE="/tmp/zeroday-chromium"

# ── Browser ───────────────────────────────────────────────────────────────
BROWSER="$(command -v chromium || command -v chromium-browser)"
if [ -z "$BROWSER" ]; then
    echo "$P Chromium not installed — run: sudo apt install -y chromium"
    exit 1
fi

# ── Already showing? ──────────────────────────────────────────────────────
if pgrep -u "$KUSER" -f "zeroday-chromium" >/dev/null 2>&1; then
    echo "$P kiosk already running"; exit 0
fi

# ── Wait for the server ───────────────────────────────────────────────────
for i in $(seq 1 90); do
    curl -fs -o /dev/null "${URL}/api/stats" && break
    sleep 1
done

# ── Find the desktop session (wait up to 60 s for autologin to finish) ────
WL=""
for i in $(seq 1 60); do
    WL="$(ls "$RUNTIME" 2>/dev/null | grep -E '^wayland-[0-9]+$' | head -1)"
    [ -n "$WL" ] && break
    [ -S /tmp/.X11-unix/X0 ] && break
    sleep 1
done

if [ -n "$WL" ]; then
    SESSION_ENV=(XDG_RUNTIME_DIR="$RUNTIME" WAYLAND_DISPLAY="$WL")
    echo "$P session: Wayland ($WL)"
elif [ -S /tmp/.X11-unix/X0 ]; then
    SESSION_ENV=(XDG_RUNTIME_DIR="$RUNTIME" DISPLAY=":0" XAUTHORITY="$KHOME/.Xauthority")
    echo "$P session: X11 (:0)"
else
    echo "$P no desktop session for $KUSER — is the Pi on its desktop? (raspi-config → Boot / Auto Login → Desktop Autologin)"
    exit 1
fi

# ── Keep the screen awake while the kiosk runs ────────────────────────────
runuser -u "$KUSER" -- env "${SESSION_ENV[@]}" xset s off -dpms s noblank 2>/dev/null || true

# ── Fresh profile each launch (so no crash-recovery bubble is possible) ───
rm -rf "$PROFILE"
mkdir -p "$PROFILE/config" "$PROFILE/cache" "$PROFILE/data"
chown -R "$KUSER":"$KUSER" "$PROFILE" || echo "$P could not prepare $PROFILE"

# ── Go ────────────────────────────────────────────────────────────────────
# --password-store=basic: never touches the keyring, so no unlock-password prompt
echo "$P launching: $BROWSER as $KUSER"
nohup runuser -u "$KUSER" -- env "${SESSION_ENV[@]}" \
    XDG_CONFIG_HOME="$PROFILE/config" XDG_CACHE_HOME="$PROFILE/cache" "$BROWSER" \
    --kiosk "$URL" \
    --user-data-dir="$PROFILE/data" --disk-cache-dir="$PROFILE/cache" \
    --password-store=basic \
    --no-first-run --no-default-browser-check \
    --noerrdialogs --disable-infobars \
    --disable-session-crashed-bubble --disable-restore-session-state \
    --disable-features=Translate,PasswordManagerOnboarding,HttpsUpgrades \
    --disable-pinch --overscroll-history-navigation=0 \
    --check-for-update-interval=31536000 \
    --ozone-platform-hint=auto \
    >/dev/null 2>&1 &
disown

# Don't claim success blindly: confirm Chromium is still alive a few seconds in
sleep 6
if pgrep -u "$KUSER" -f "zeroday-chromium" >/dev/null 2>&1; then
    echo "$P kiosk running"
else
    echo "$P Chromium exited right after start — try it by hand to see why:"
    echo "$P   XDG_RUNTIME_DIR=$RUNTIME ${SESSION_ENV[*]} $BROWSER --kiosk $URL"
fi
