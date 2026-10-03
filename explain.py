"""
explain.py — turns an alert + its XAI features into a plain-English incident
brief: what happened, why the AI flagged it, how severe it is, what to do.

Rule/template based on purpose: deterministic, instant, no network and no LLM
on a Pi 4 — and it can only describe evidence that is actually in the alert.
"""

_PLAYBOOK = {
    "portscan": (
        "Reconnaissance",
        "{ip} probed {n} different ports on {dst} in a few seconds — the signature of a port scan "
        "looking for open services before an attack.",
        "Block the source; check which ports on the target are exposed and close any that aren't needed.",
    ),
    "ddos": (
        "Denial of Service",
        "{ip} sent an abnormal flood of packets at {dst} — enough to exhaust the target's bandwidth "
        "or connection table.",
        "Keep the source blocked; if the target is a critical device, check it still responds and consider rate limiting.",
    ),
    "brute": (
        "Credential attack",
        "{ip} made repeated fresh connection attempts to the same service on {dst} — consistent with "
        "password guessing against a login service.",
        "Block the source; enforce key-based SSH / strong passwords on the targeted service and review its logs.",
    ),
    "behavioral": (
        "Behavioural anomaly (zero-day / compromised device)",
        "{ip} suddenly behaves very differently from its own learned normal — matching no known "
        "attack signature, which is how compromised IoT devices and data exfiltration often look.",
        "Verify the device with its owner; if unexpected, isolate it (Block) and inspect it for malware.",
    ),
    "evil": (
        "Rogue access point",
        "A second access point is advertising the network name '{dst}' — the classic Evil Twin setup "
        "used to intercept traffic from devices that auto-connect.",
        "Do not connect to it; locate the rogue AP and verify the legitimate AP's BSSID.",
    ),
    "beacon": (
        "WiFi beacon flood",
        "An unusually large number of fake WiFi networks is being broadcast nearby — used to disrupt "
        "or confuse WiFi clients.",
        "Identify the broadcasting device; temporarily move critical devices to a wired link.",
    ),
    "malicious": (
        "Malicious traffic",
        "The traffic from {ip} to {dst} matches patterns the trained models associate with attacks.",
        "Review the top contributing features below; block the source if it is not a known device.",
    ),
}


def _kind(threat_class: str) -> str:
    t = (threat_class or "").lower().replace(" ", "")
    if "beacon" in t:
        return "beacon"
    if "evil" in t or "rogue" in t:
        return "evil"
    if "behavior" in t:
        return "behavioral"
    if "portscan" in t and "ddos" not in t:
        return "portscan"
    if "ddos" in t or "flood" in t:
        return "ddos"
    if "brute" in t:
        return "brute"
    return "malicious"


def _severity(confidence: float, kind: str) -> str:
    c = float(confidence or 0)
    if kind in ("behavioral", "beacon") and c < 0.9:
        return "MEDIUM"
    if c >= 0.9:
        return "CRITICAL"
    if c >= 0.75:
        return "HIGH"
    if c >= 0.5:
        return "MEDIUM"
    return "LOW"


def explain_alert(alert: dict) -> dict:
    kind = _kind(alert.get("threat_class", ""))
    category, what, action = _PLAYBOOK[kind]
    feats = alert.get("xai_features") or []

    n_ports = next((f["raw_value"] for f in feats if f.get("name") == "distinct_ports_scanned"), "many")
    what = what.format(ip=alert.get("source_ip", "?"), dst=alert.get("dest_ip", "?"), n=n_ports)

    why = []
    for f in feats[:3]:
        name = str(f.get("name", "")).replace("_", " ")
        why.append(f"{name} = {f.get('raw_value')}")
    why_txt = ("Key evidence: " + "; ".join(why) + ".") if why else "No per-feature evidence was stored for this alert."

    conf = float(alert.get("confidence") or 0)
    sev = _severity(conf, kind)
    blocked = bool(alert.get("is_blocked"))
    status = ("The source is currently BLOCKED." if blocked
              else "The source is NOT blocked — this was flagged as advisory/under the auto-block bar.")

    return {
        "category": category,
        "severity": sev,
        "summary": what,
        "evidence": why_txt,
        "detector": alert.get("detected_by"),
        "confidence_pct": round(conf * 100),
        "status": status,
        "recommendation": action,
    }
