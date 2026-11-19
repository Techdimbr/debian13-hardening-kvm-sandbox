#!/usr/bin/env bash
# =============================================================================
# Techdim Kether_1 — 43-Control CIS Debian 13 & BeyondCorp Zero Trust Auditor
# Read-only auditor evaluating all 43 Kether_1 controls across the 6 layers.
# Emits strictly typed JSON (cis_43_audit.json), Markdown table (cis_43_audit.md),
# and cryptographic manifest (SHA256SUMS.txt).
#
# Usage:
#   ./scripts/audit_cis_43_controls.sh [OUT_DIR]
#
# Author: Eng. Deivis Irio Mayer (Kether1) — ORCID: 0009-0003-3273-7883
# License: MIT
# =============================================================================
set -euo pipefail

OUT_DIR="${1:-./benchmarks/cis43_$(date -u +%Y%m%dT%H%M%SZ)}"
command -v python3 >/dev/null 2>&1 || { echo "ERROR: python3 is required." >&2; exit 1; }
mkdir -p "$OUT_DIR"

python3 - "$OUT_DIR" <<'PYEOF'
import datetime
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

out_dir = Path(sys.argv[1])
euid = os.geteuid()
is_root = euid == 0


def read_file(path):
    p = Path(path)
    if not p.exists():
        return ("unavailable", None)
    try:
        return ("ok", p.read_text(encoding="utf-8", errors="replace").strip())
    except PermissionError:
        return ("permission_denied", None)
    except OSError:
        return ("error", None)


def sysctl_eq(key, expected):
    st, val = read_file(Path("/proc/sys") / key.replace(".", "/"))
    if st != "ok":
        return (st, f"{key}={st}")
    first = val.split()[0] if val else ""
    return ("pass" if first == str(expected) else "fail", f"{key}={first} (expected {expected})")


def sysctl_ge(key, minimum):
    st, val = read_file(Path("/proc/sys") / key.replace(".", "/"))
    if st != "ok":
        return (st, f"{key}={st}")
    try:
        iv = int(val.split()[0])
        return ("pass" if iv >= minimum else "fail", f"{key}={iv} (expected >={minimum})")
    except ValueError:
        return ("fail", f"{key}={val}")


def run(cmd):
    if not shutil.which(cmd[0]):
        return ("not_installed", "", f"{cmd[0]} missing")
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
    if p.returncode == 0:
        return ("ok", p.stdout, p.stderr)
    low = (p.stderr or "").lower()
    if not is_root and any(t in low for t in ("permission denied", "must be root", "operation not permitted")):
        return ("permission_denied", p.stdout, p.stderr)
    return ("error", p.stdout, p.stderr)


def svc_active(unit):
    st, out, err = run(["systemctl", "is-active", unit])
    if "system has not been booted with systemd" in (err or "").lower():
        return ("not_applicable", f"{unit}: no systemd")
    if st == "not_installed":
        return ("not_applicable", "systemctl not installed")
    val = (out or err).strip().splitlines()[0] if (out or err).strip() else "unknown"
    return ("pass" if val == "active" else "fail", f"{unit}={val}")


def svc_inactive(unit):
    st, out, err = run(["systemctl", "is-active", unit])
    if "system has not been booted with systemd" in (err or "").lower():
        return ("not_applicable", f"{unit}: no systemd")
    if st == "not_installed":
        return ("not_applicable", "systemctl not installed")
    val = (out or err).strip().splitlines()[0] if (out or err).strip() else "unknown"
    return ("pass" if val != "active" else "fail", f"{unit}={val}")


def ssh_param(regex, desc):
    files = [Path("/etc/ssh/sshd_config")] + sorted(Path("/etc/ssh/sshd_config.d").glob("*.conf")) if Path("/etc/ssh/sshd_config.d").exists() else [Path("/etc/ssh/sshd_config")]
    found = False
    denied = False
    for f in files:
        if not f.exists():
            continue
        st, txt = read_file(f)
        if st == "permission_denied":
            denied = True
            continue
        if st == "ok" and re.search(regex, txt, flags=re.MULTILINE | re.IGNORECASE):
            found = True
            break
    if found:
        return ("pass", desc)
    if denied:
        return ("permission_denied", f"cannot read sshd_config as euid={euid}")
    return ("fail", f"{desc} not matched")


def check_nft_policy(hook):
    st, out, _ = run(["nft", "list", "ruleset"])
    if st != "ok":
        return ("permission_denied" if st == "permission_denied" else "fail", f"nft={st}")
    ok = bool(re.search(rf"hook\s+{hook}\b[^;]*;\s*policy\s+drop\s*;", out))
    return ("pass" if ok else "fail", f"nft {hook} policy drop={'yes' if ok else 'no'}")


def check_luks():
    st, out, _ = run(["lsblk", "-J", "-o", "TYPE,FSTYPE"])
    if st != "ok":
        return ("fail", f"lsblk={st}")
    ok = '"crypt"' in out.lower() or "luks" in out.lower()
    return ("pass" if ok else "fail", "LUKS/crypt volume detected" if ok else "no LUKS volume")


def check_lvm():
    st, out, _ = run(["lsblk", "-J", "-o", "TYPE,FSTYPE"])
    if st != "ok":
        return ("fail", f"lsblk={st}")
    ok = '"lvm"' in out.lower()
    return ("pass" if ok else "fail", "LVM detected" if ok else "no LVM volume")


def check_lockdown():
    st, val = read_file("/sys/kernel/security/lockdown")
    if st != "ok":
        return (st, f"lockdown={st}")
    ok = "[integrity]" in val or "[confidentiality]" in val
    return ("pass" if ok else "fail", f"lockdown={val}")


def check_core_pattern():
    st, val = read_file("/proc/sys/kernel/core_pattern")
    if st != "ok":
        return (st, f"core_pattern={st}")
    ok = val.strip() == "|/bin/false"
    return ("pass" if ok else "fail", f"core_pattern={val}")


def check_apparmor_enforcing():
    st, out, _ = run(["aa-status", "--json"])
    if st != "ok":
        return ("permission_denied" if st == "permission_denied" else "fail", f"aa-status={st}")
    data = json.loads(out)
    n = sum(1 for v in data.get("profiles", {}).values() if v == "enforce")
    return ("pass" if n > 0 else "fail", f"apparmor_enforce={n}")


def check_auditd_backlog():
    st, out, _ = run(["auditctl", "-s"])
    if st != "ok":
        return ("permission_denied" if st == "permission_denied" else "fail", f"auditctl={st}")
    m = re.search(r"backlog_limit\s+(\d+)", out)
    v = int(m.group(1)) if m else 0
    return ("pass" if v >= 8192 else "fail", f"backlog_limit={v} (expected >=8192)")


def check_auditd_lost():
    st, out, _ = run(["auditctl", "-s"])
    if st != "ok":
        return ("permission_denied" if st == "permission_denied" else "fail", f"auditctl={st}")
    m = re.search(r"\blost\s+(\d+)", out)
    v = int(m.group(1)) if m else -1
    return ("pass" if v == 0 else "fail", f"lost={v} (expected 0)")


def check_auditd_immutable():
    st, out, _ = run(["auditctl", "-s"])
    if st != "ok":
        return ("permission_denied" if st == "permission_denied" else "fail", f"auditctl={st}")
    m = re.search(r"\benabled\s+(\d+)", out)
    v = int(m.group(1)) if m else 0
    return ("pass" if v == 2 else "fail", f"audit_enabled={v} (2=immutable)")


def check_dot():
    st, out, _ = run(["resolvectl", "status"])
    if st != "ok":
        return ("fail", f"resolvectl={st}")
    ok = bool(re.search(r"DNSOverTLS\s*setting:\s*(yes|opportunistic)", out, re.IGNORECASE))
    return ("pass" if ok else "fail", "DNSOverTLS enabled" if ok else "DNSOverTLS disabled")


def check_dnssec():
    st, out, _ = run(["resolvectl", "status"])
    if st != "ok":
        return ("fail", f"resolvectl={st}")
    ok = bool(re.search(r"DNSSEC\s*setting:\s*(yes|allow-downgrade)", out, re.IGNORECASE))
    return ("pass" if ok else "fail", "DNSSEC enabled" if ok else "DNSSEC disabled")


def check_file_exists(path, label):
    return ("pass" if Path(path).exists() else "fail", f"{label}: {'present' if Path(path).exists() else 'absent'}")


def check_cmd_exists(exe):
    return ("pass" if shutil.which(exe) else "fail", f"{exe}: {'installed' if shutil.which(exe) else 'missing'}")


def check_secure_boot():
    st, out, _ = run(["mokutil", "--sb-state"])
    if st != "ok":
        return ("not_applicable" if not Path("/sys/firmware/efi").exists() else "fail", f"mokutil={st}")
    ok = "secureboot enabled" in out.lower()
    return ("pass" if ok else "fail", out.strip())


def check_shadow_perms():
    p = Path("/etc/shadow")
    if not p.exists():
        return ("fail", "/etc/shadow missing")
    mode = p.stat().st_mode & 0o777
    return ("pass" if mode <= 0o640 else "fail", f"/etc/shadow mode={oct(mode)}")


def check_sudoers_dropin():
    return ("pass" if Path("/etc/sudoers.d").is_dir() else "fail", "/etc/sudoers.d directory")


def check_journald_dropin():
    st, txt = read_file("/etc/systemd/journald.conf.d/99-kether.conf")
    ok = st == "ok" and "SystemMaxUse=" in txt
    return ("pass" if ok else "fail", "journald SystemMaxUse configured" if ok else "99-kether.conf missing")


def check_unattended_upgrades():
    return check_file_exists("/etc/apt/apt.conf.d/20auto-upgrades", "APT 20auto-upgrades")


def check_cpu_virt():
    st, txt = read_file("/proc/cpuinfo")
    if st != "ok":
        return (st, "cpuinfo unreadable")
    ok = bool(re.search(r"\b(vmx|svm)\b", txt))
    return ("pass" if ok else "fail", "vmx/svm supported" if ok else "no vmx/svm flag")


# Exact catalog of 43 Kether_1 CIS Debian 13 + BeyondCorp Zero Trust controls
CONTROLS = [
    # Layer 1 — Storage & Firmware (6 controls)
    ("K1-01", "L1_Storage_Firmware", "CIS-1.1 / BeyondCorp", "LUKS2 full-disk/volume encryption active", check_luks),
    ("K1-02", "L1_Storage_Firmware", "CIS-1.1", "LVM logical volume segmentation present", check_lvm),
    ("K1-03", "L1_Storage_Firmware", "BeyondCorp", "UEFI Secure Boot enabled", check_secure_boot),
    ("K1-04", "L1_Storage_Firmware", "BeyondCorp", "TPM 2.0 hardware root-of-trust present", lambda: check_file_exists("/dev/tpmrm0", "/dev/tpmrm0")),
    ("K1-05", "L1_Storage_Firmware", "CIS-6.1.3", "/etc/shadow permissions <= 0640", check_shadow_perms),
    ("K1-06", "L1_Storage_Firmware", "CIS-1.9", "Automatic security updates configured (unattended-upgrades)", check_unattended_upgrades),

    # Layer 2 — Kernel & Sysctl Hardening (15 controls)
    ("K1-07", "L2_Kernel_Sysctl", "BeyondCorp", "Kernel lockdown=integrity or confidentiality", check_lockdown),
    ("K1-08", "L2_Kernel_Sysctl", "CIS-1.5.2", "ASLR enabled (kernel.randomize_va_space=2)", lambda: sysctl_eq("kernel.randomize_va_space", 2)),
    ("K1-09", "L2_Kernel_Sysctl", "CIS-1.5", "Kernel pointer hiding (kernel.kptr_restrict=2)", lambda: sysctl_eq("kernel.kptr_restrict", 2)),
    ("K1-10", "L2_Kernel_Sysctl", "CIS-1.5", "Restrict dmesg access (kernel.dmesg_restrict=1)", lambda: sysctl_eq("kernel.dmesg_restrict", 1)),
    ("K1-11", "L2_Kernel_Sysctl", "CIS-1.5", "Disable unprivileged BPF (kernel.unprivileged_bpf_disabled=1)", lambda: sysctl_ge("kernel.unprivileged_bpf_disabled", 1)),
    ("K1-12", "L2_Kernel_Sysctl", "CIS-1.5", "Harden BPF JIT (net.core.bpf_jit_harden=2)", lambda: sysctl_eq("net.core.bpf_jit_harden", 2)),
    ("K1-13", "L2_Kernel_Sysctl", "CIS-1.5", "Restrict perf events (kernel.perf_event_paranoid>=2)", lambda: sysctl_ge("kernel.perf_event_paranoid", 2)),
    ("K1-14", "L2_Kernel_Sysctl", "CIS-1.5", "Yama ptrace restriction (kernel.yama.ptrace_scope>=1)", lambda: sysctl_ge("kernel.yama.ptrace_scope", 1)),
    ("K1-15", "L2_Kernel_Sysctl", "CIS-1.5.1", "Disable SUID core dumps (fs.suid_dumpable=0)", lambda: sysctl_eq("fs.suid_dumpable", 0)),
    ("K1-16", "L2_Kernel_Sysctl", "CIS-1.5.1", "Null core_pattern (|/bin/false)", check_core_pattern),
    ("K1-17", "L2_Kernel_Sysctl", "CIS-1.5", "Protected hardlinks (fs.protected_hardlinks=1)", lambda: sysctl_eq("fs.protected_hardlinks", 1)),
    ("K1-18", "L2_Kernel_Sysctl", "CIS-1.5", "Protected symlinks (fs.protected_symlinks=1)", lambda: sysctl_eq("fs.protected_symlinks", 1)),
    ("K1-19", "L2_Kernel_Sysctl", "CIS-3.3.7", "Reverse path filtering (net.ipv4.conf.all.rp_filter=1)", lambda: sysctl_eq("net.ipv4.conf.all.rp_filter", 1)),
    ("K1-20", "L2_Kernel_Sysctl", "CIS-3.3.8", "TCP SYN cookies enabled (net.ipv4.tcp_syncookies=1)", lambda: sysctl_eq("net.ipv4.tcp_syncookies", 1)),
    ("K1-21", "L2_Kernel_Sysctl", "CIS-3.3.2", "Disable ICMP redirects (net.ipv4.conf.all.accept_redirects=0)", lambda: sysctl_eq("net.ipv4.conf.all.accept_redirects", 0)),

    # Layer 3 — MAC Confinement & AI Sandbox Userns (4 controls)
    ("K1-22", "L3_MAC_AppArmor", "CIS-1.6.1.1", "AppArmor systemd service active", lambda: svc_active("apparmor")),
    ("K1-23", "L3_MAC_AppArmor", "CIS-1.6.1.4", "AppArmor enforcing profiles active (>0)", check_apparmor_enforcing),
    ("K1-24", "L3_MAC_AppArmor", "Kether_1", "Unprivileged userns available for AppArmor-mediated sandboxes", lambda: sysctl_eq("kernel.unprivileged_userns_clone", 1)),
    ("K1-25", "L3_MAC_AppArmor", "Kether_1", "Kether AI agent selective userns AppArmor profile installed", lambda: check_file_exists("/etc/apparmor.d/kether-ai-agent-userns", "kether-ai-agent-userns")),

    # Layer 4 — Network, Firewall & SSH Zero Trust (9 controls)
    ("K1-26", "L4_Network_ZeroTrust", "CIS-3.5.2.8", "nftables input chain default-deny (policy drop)", lambda: check_nft_policy("input")),
    ("K1-27", "L4_Network_ZeroTrust", "CIS-3.5.2.8", "nftables forward chain default-deny (policy drop)", lambda: check_nft_policy("forward")),
    ("K1-28", "L4_Network_ZeroTrust", "BeyondCorp", "DNS-over-TLS active via systemd-resolved", check_dot),
    ("K1-29", "L4_Network_ZeroTrust", "BeyondCorp", "DNSSEC validation enabled via systemd-resolved", check_dnssec),
    ("K1-30", "L4_Network_ZeroTrust", "CIS-5.2.10", "SSH PermitRootLogin disabled", lambda: ssh_param(r"^\s*PermitRootLogin\s+no\b", "PermitRootLogin no")),
    ("K1-31", "L4_Network_ZeroTrust", "CIS-5.2.12", "SSH PasswordAuthentication disabled", lambda: ssh_param(r"^\s*PasswordAuthentication\s+no\b", "PasswordAuthentication no")),
    ("K1-32", "L4_Network_ZeroTrust", "CIS-5.2.6", "SSH X11Forwarding disabled", lambda: ssh_param(r"^\s*X11Forwarding\s+no\b", "X11Forwarding no")),
    ("K1-33", "L4_Network_ZeroTrust", "CIS-2.2.3", "Avahi mDNS daemon disabled", lambda: svc_inactive("avahi-daemon")),
    ("K1-34", "L4_Network_ZeroTrust", "CIS-2.2.4", "CUPS print daemon disabled on hardened host", lambda: svc_inactive("cups")),

    # Layer 5 — Forensic Telemetry & Host Integrity (6 controls)
    ("K1-35", "L5_Telemetry_Integrity", "CIS-4.1.1.2", "auditd service active", lambda: svc_active("auditd")),
    ("K1-36", "L5_Telemetry_Integrity", "Kether_1 / CIS-4.1", "auditd backlog_limit >= 8192", check_auditd_backlog),
    ("K1-37", "L5_Telemetry_Integrity", "Kether_1", "auditd lost events == 0 (lossless telemetry)", check_auditd_lost),
    ("K1-38", "L5_Telemetry_Integrity", "CIS-4.1.3.21", "auditd immutable mode (-e 2)", check_auditd_immutable),
    ("K1-39", "L5_Telemetry_Integrity", "CIS-1.3.1", "AIDE file integrity baseline present (/var/lib/aide/aide.db)", lambda: check_file_exists("/var/lib/aide/aide.db", "AIDE db")),
    ("K1-40", "L5_Telemetry_Integrity", "BeyondCorp / CIS-4.2", "USBGuard active & journald retention drop-in present", lambda: ("pass", "USBGuard + journald ok") if (svc_active("usbguard")[0] == "pass" and check_journald_dropin()[0] == "pass") else ("fail", f"usbguard={svc_active('usbguard')[1]}; {check_journald_dropin()[1]}")),

    # Layer 6 — Ephemeral KVM/QCOW2 Sandbox Readiness (3 controls)
    ("K1-41", "L6_Ephemeral_KVM", "Kether_1", "CPU hardware virtualization extensions (vmx/svm) present", check_cpu_virt),
    ("K1-42", "L6_Ephemeral_KVM", "Kether_1", "KVM kernel device (/dev/kvm) & qemu-img available", lambda: ("pass", "/dev/kvm + qemu-img ok") if (Path("/dev/kvm").exists() and shutil.which("qemu-img")) else ("fail", f"/dev/kvm={Path('/dev/kvm').exists()}, qemu-img={bool(shutil.which('qemu-img'))}")),
    ("K1-43", "L6_Ephemeral_KVM", "Kether_1 / BeyondCorp", "libvirtd active & sudoers drop-in isolation configured", lambda: ("pass", "libvirtd + sudoers.d ok") if (svc_active("libvirtd")[0] == "pass" and check_sudoers_dropin()[0] == "pass") else ("fail", f"libvirtd={svc_active('libvirtd')[1]}; {check_sudoers_dropin()[1]}")),
]

assert len(CONTROLS) == 43, f"Expected 43 controls, got {len(CONTROLS)}"

results = []
counts = {"pass": 0, "fail": 0, "permission_denied": 0, "not_applicable": 0, "unavailable": 0, "error": 0}
for cid, layer, std, title, fn in CONTROLS:
    st, detail = fn()
    counts[st] = counts.get(st, 0) + 1
    results.append({
        "id": cid,
        "layer": layer,
        "standard": std,
        "title": title,
        "status": st,
        "detail": detail,
    })

evaluable = counts["pass"] + counts["fail"]
pass_rate_all = round((counts["pass"] / len(CONTROLS)) * 100.0, 2)
pass_rate_evaluable = round((counts["pass"] / evaluable) * 100.0, 2) if evaluable > 0 else 0.0

payload = {
    "schema_version": "1.1.0",
    "timestamp_utc": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "privilege_context": "root" if is_root else "unprivileged",
    "euid": euid,
    "total_controls": len(CONTROLS),
    "summary": {
        **counts,
        "pass_rate_total_pct": pass_rate_all,
        "pass_rate_evaluable_pct": pass_rate_evaluable,
    },
    "controls": results,
}

json_path = out_dir / "cis_43_audit.json"
json_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

md = [
    "# Kether_1 — 43-Control CIS Debian 13 & BeyondCorp Audit Report",
    "",
    f"- **Timestamp (UTC):** `{payload['timestamp_utc']}`",
    f"- **Privilege Context:** `{payload['privilege_context']}` (`euid={euid}`)",
    f"- **Pass Rate (Total 43):** `{pass_rate_all}%` (`{counts['pass']}/43`)",
    f"- **Breakdown:** `pass={counts['pass']}`, `fail={counts['fail']}`, `permission_denied={counts['permission_denied']}`, `not_applicable={counts['not_applicable']}`",
    "",
    "| ID | Layer | Standard | Control | Status | Detail |",
    "| :--- | :--- | :--- | :--- | :--- | :--- |",
]
for r in results:
    md.append(f"| `{r['id']}` | `{r['layer']}` | {r['standard']} | {r['title']} | `{r['status']}` | {r['detail']} |")

md_path = out_dir / "cis_43_audit.md"
md_path.write_text("\n".join(md) + "\n", encoding="utf-8")

sums = [f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}" for p in (json_path, md_path)]
(out_dir / "SHA256SUMS.txt").write_text("\n".join(sums) + "\n", encoding="utf-8")

print(f"43-control audit completed ({payload['privilege_context']}): {counts['pass']}/43 pass -> {json_path}")
PYEOF
