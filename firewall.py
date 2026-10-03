"""
firewall.py — IP block/unblock enforcement for the ZeroDay-Edge Node.

Backends (auto-detected, first match wins):
  1. iptables  — INPUT DROP rules (idempotent: checked with -C before -A, every
                 duplicate removed on unblock)
  2. nft       — one `inet cybershield` table with a `blocked` set; add/delete
                 element is naturally idempotent, so no duplicate-rule problem
  3. none      — DB-only simulation (logged loudly)

Why this exists: on Debian/Raspberry Pi OS the user's PATH lacks /usr/sbin and
/sbin, where iptables/nft live. A root process inherited via `sudo -E` keeps
that PATH, so a plain subprocess.run(["iptables", ...]) raised
FileNotFoundError and blocking silently degraded to DB-only. We look in the
sbin dirs explicitly.

Management ports (dashboard + SSH) are always ACCEPTed ahead of any DROP so an
attack launched from the operator's PC can never sever the session.
"""

import logging
import os
import shutil
import subprocess

logger = logging.getLogger(__name__)

_SEARCH_PATH = os.pathsep.join(
    [os.environ.get("PATH", ""), "/usr/local/sbin", "/usr/sbin", "/sbin", "/usr/bin", "/bin"]
)
IPTABLES = shutil.which("iptables", path=_SEARCH_PATH)
NFT = shutil.which("nft", path=_SEARCH_PATH)

BACKEND = "iptables" if IPTABLES else ("nft" if NFT else "none")

_MGMT_PORTS = (os.environ.get("EDGE_PORT", "5000"), "22")
_TABLE = ("inet", "cybershield")


def _is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


def _run(cmd: list[str], stdin: str | None = None) -> subprocess.CompletedProcess:
    """Run a firewall command, via sudo -S when we aren't root."""
    if not _is_root() and hasattr(os, "geteuid"):
        pw = os.environ.get("EDGE_SUDO_PASSWORD", "pi")
        cmd = ["sudo", "-S"] + cmd
        stdin = pw + "\n" + (stdin or "")
    return subprocess.run(cmd, input=stdin, text=True, capture_output=True, timeout=10)


# ── iptables backend ─────────────────────────────────────────────────────

def _ipt(*args) -> subprocess.CompletedProcess:
    return _run([IPTABLES, *args])


def _ipt_setup():
    for port in _MGMT_PORTS:
        rule = ["-p", "tcp", "--dport", str(port), "-j", "ACCEPT"]
        if _ipt("-C", "INPUT", *rule).returncode != 0:
            r = _ipt("-I", "INPUT", "1", *rule)
            if r.returncode == 0:
                logger.info("firewall: ACCEPT tcp/%s installed at top of INPUT", port)
            else:
                logger.warning("firewall: safeguard tcp/%s failed: %s", port, r.stderr.strip())


def _ipt_block(ip: str) -> bool:
    if _ipt("-C", "INPUT", "-s", ip, "-j", "DROP").returncode == 0:
        return True  # already enforced — don't stack duplicates
    r = _ipt("-A", "INPUT", "-s", ip, "-j", "DROP")
    if r.returncode != 0:
        logger.warning("firewall: iptables -A %s failed: %s", ip, r.stderr.strip())
    return r.returncode == 0


def _ipt_unblock(ip: str) -> bool:
    for _ in range(50):  # -D removes one copy per call; purge them all
        if _ipt("-D", "INPUT", "-s", ip, "-j", "DROP").returncode != 0:
            break
    return _ipt("-C", "INPUT", "-s", ip, "-j", "DROP").returncode != 0


def _ipt_blocked(ip: str) -> bool:
    return _ipt("-C", "INPUT", "-s", ip, "-j", "DROP").returncode == 0


# ── nftables backend ─────────────────────────────────────────────────────

def _nft(script: str) -> subprocess.CompletedProcess:
    return _run([NFT, "-f", "-"], stdin=script)


def _nft_setup():
    ports = ", ".join(str(p) for p in _MGMT_PORTS)
    t = " ".join(_TABLE)
    script = f"""
add table {t}
add set {t} blocked {{ type ipv4_addr; }}
add chain {t} input {{ type filter hook input priority -10; policy accept; }}
flush chain {t} input
add rule {t} input tcp dport {{ {ports} }} accept
add rule {t} input ip saddr @blocked drop
"""
    r = _nft(script)
    if r.returncode == 0:
        logger.info("firewall: nft table %s ready (mgmt ports %s always accepted)", t, ports)
    else:
        logger.warning("firewall: nft setup failed: %s", r.stderr.strip())


def _nft_block(ip: str) -> bool:
    r = _nft(f"add element {' '.join(_TABLE)} blocked {{ {ip} }}")
    if r.returncode != 0:
        logger.warning("firewall: nft add %s failed: %s", ip, r.stderr.strip())
    return r.returncode == 0


def _nft_unblock(ip: str) -> bool:
    r = _nft(f"delete element {' '.join(_TABLE)} blocked {{ {ip} }}")
    # "No such file" = element already absent, which is the desired end state
    return r.returncode == 0 or "No such" in r.stderr


def _nft_blocked(ip: str) -> bool:
    r = _run([NFT, "get", "element", *_TABLE, "blocked", f"{{ {ip} }}"])
    return r.returncode == 0


# ── Public API ───────────────────────────────────────────────────────────

def setup():
    """Install management-port safeguards. Call once at startup."""
    if BACKEND == "none":
        logger.warning(
            "firewall: neither iptables nor nft found — blocking is DB-only. "
            "Install one: sudo apt install -y nftables  (or iptables)"
        )
        return
    logger.info("firewall: backend=%s", BACKEND)
    try:
        (_ipt_setup if BACKEND == "iptables" else _nft_setup)()
    except Exception as e:
        logger.error("firewall setup error: %s", e)


def block(ip: str) -> bool:
    """Enforce a drop for `ip`. True if the firewall now drops it (False in DB-only mode)."""
    if BACKEND == "none":
        return False
    try:
        return (_ipt_block if BACKEND == "iptables" else _nft_block)(ip)
    except Exception as e:
        logger.error("firewall block error: %s", e)
        return False


def unblock(ip: str) -> bool:
    """Remove every drop for `ip`. True if the firewall no longer drops it."""
    if BACKEND == "none":
        return False
    try:
        return (_ipt_unblock if BACKEND == "iptables" else _nft_unblock)(ip)
    except Exception as e:
        logger.error("firewall unblock error: %s", e)
        return False


def is_blocked(ip: str) -> bool:
    if BACKEND == "none":
        return False
    try:
        return (_ipt_blocked if BACKEND == "iptables" else _nft_blocked)(ip)
    except Exception:
        return False


def restore(ips: list[str]):
    """Re-apply DB-recorded blocks (firewall rules don't survive a reboot)."""
    for ip in ips:
        block(ip)
    if ips:
        logger.info("firewall: restored %d block(s) from DB", len(ips))
