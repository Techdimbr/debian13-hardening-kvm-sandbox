#!/usr/bin/env bash
# =============================================================================
# Techdim Kether_1 — Hardened Read-Only Experimental Metrics Collector (v1.1.0)
# Covers all 6 Defense-in-Depth Layers on Debian 13 (Trixie, Kernel 6.12 LTS)
#
# Key guarantees (addressing Peer Review of Zenodo 10.5281/zenodo.24380375):
#   1. Explicit privilege_context (root vs unprivileged) — never disguises
#      permission errors (EACCES) as absent security controls.
#   2. Strict JSON serialization via Python 3 json.dumps — real integers,
#      booleans, and nulls (zero unsafe here-doc string interpolation).
#   3. Full 6-layer coverage: Storage/Firmware (LUKS2, LVM, Secure Boot, TPM),
#      Kernel (lockdown, sysctl), MAC (AppArmor enforce/complain + userns),
#      Network (nftables policy drop + DoT/DNSSEC), Telemetry (auditd backlog
#      & lost=0, journald, AIDE, USBGuard, Lynis), and Ephemeral KVM/QCOW2
#      functional overlay benchmark (--test-qcow2-overlay).
#   4. Emits metrics_report.json + metrics_summary.md + SHA256SUMS.txt.
#
# Usage:
#   ./scripts/collect_kether_metrics.sh [OPTIONS] [OUT_DIR]
#   Options:
#     --require-root         Exit non-zero if not running as EUID 0
#     --test-qcow2-overlay   Run live scratch QCOW2 backing+overlay timing test
#     --lynis-log PATH       Parse Hardening index from a Lynis report file
#     -h, --help             Show this help message
#
# Author: Eng. Deivis Irio Mayer (Kether1) — ORCID: 0009-0003-3273-7883
# License: MIT
# =============================================================================
set -euo pipefail

REQUIRE_ROOT=0
TEST_QCOW2=0
LYNIS_LOG=""
OUT_DIR=""

usage() {
  cat <<'EOF'
Usage: collect_kether_metrics.sh [OPTIONS] [OUT_DIR]

Options:
  --require-root         Abort if EUID != 0 (recommended for full host audit)
  --test-qcow2-overlay   Run functional scratch QCOW2 CoW overlay create/discard benchmark
  --lynis-log PATH       Path to Lynis report file (default: /var/log/lynis-report.dat)
  -h, --help             Display this help text
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --require-root)
      REQUIRE_ROOT=1
      shift
      ;;
    --test-qcow2-overlay)
      TEST_QCOW2=1
      shift
      ;;
    --lynis-log)
      [[ $# -ge 2 ]] || { echo "ERROR: --lynis-log requires a path" >&2; exit 2; }
      LYNIS_LOG="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    -*)
      echo "ERROR: Unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
    *)
      OUT_DIR="$1"
      shift
      ;;
  esac
done

if [[ "$REQUIRE_ROOT" -eq 1 && "$EUID" -ne 0 ]]; then
  echo "ERROR: --require-root specified, but current EUID is ${EUID}. Re-run with sudo." >&2
  exit 1
fi

if [[ -z "$OUT_DIR" ]]; then
  OUT_DIR="./benchmarks/run_$(date -u +%Y%m%dT%H%M%SZ)"
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "ERROR: python3 is required for safe, strongly-typed JSON serialization." >&2
  exit 1
fi

mkdir -p "$OUT_DIR"

python3 - "$OUT_DIR" "$TEST_QCOW2" "$LYNIS_LOG" <<'PYEOF'
import datetime
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

out_dir = Path(sys.argv[1])
test_qcow2 = sys.argv[2] == "1"
lynis_log_arg = sys.argv[3]

euid = os.geteuid()
is_root = euid == 0
effective_user = os.environ.get("USER") or str(euid)


def run_cmd(cmd, timeout=10):
    """Run command capturing stdout/stderr without hiding permission failures."""
    exe = shutil.which(cmd[0])
    if not exe:
        return {"status": "not_installed", "rc": None, "stdout": "", "stderr": f"{cmd[0]} not found"}
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
            check=False,
        )
    except Exception as exc:
        return {"status": "error", "rc": None, "stdout": "", "stderr": str(exc)}

    combined_err = (proc.stderr or "").strip()
    if proc.returncode == 0:
        return {"status": "ok", "rc": 0, "stdout": proc.stdout, "stderr": combined_err}
    low = combined_err.lower()
    if (
        not is_root
        and (
            "permission denied" in low
            or "must be root" in low
            or "operation not permitted" in low
            or "you need to be root" in low
            or "insufficient" in low
        )
    ):
        return {"status": "permission_denied", "rc": proc.returncode, "stdout": proc.stdout, "stderr": combined_err}
    return {"status": "error", "rc": proc.returncode, "stdout": proc.stdout, "stderr": combined_err}


def read_text_file(path):
    p = Path(path)
    if not p.exists():
        return {"status": "unavailable", "value": None}
    try:
        return {"status": "ok", "value": p.read_text(encoding="utf-8", errors="replace").strip()}
    except PermissionError:
        return {"status": "permission_denied", "value": None}
    except OSError as exc:
        return {"status": "error", "value": None, "detail": str(exc)}


def read_sysctl_int(key):
    proc_path = Path("/proc/sys") / key.replace(".", "/")
    res = read_text_file(proc_path)
    if res["status"] != "ok":
        return {"status": res["status"], "value": None}
    raw = res["value"].split()[0] if res["value"] else ""
    try:
        return {"status": "ok", "value": int(raw)}
    except ValueError:
        return {"status": "ok", "value": raw}


def systemctl_active(unit):
    if not shutil.which("systemctl"):
        return {"status": "not_installed", "active": None, "state": None}
    res = run_cmd(["systemctl", "is-active", unit])
    state = (res["stdout"] or res["stderr"]).strip().splitlines()
    state_str = state[0].strip() if state else "unknown"
    if "system has not been booted with systemd" in (res["stderr"] or "").lower():
        return {"status": "unavailable", "active": None, "state": "no_systemd"}
    return {"status": "ok", "active": state_str == "active", "state": state_str}


# =============================================================================
# LAYER 1 — STORAGE & FIRMWARE
# =============================================================================
def probe_layer1():
    luks_status = "unavailable"
    luks_count = None
    lvm_count = None
    lsblk_res = run_cmd(["lsblk", "-J", "-o", "NAME,TYPE,FSTYPE,MOUNTPOINT"])
    if lsblk_res["status"] == "ok":
        try:
            tree = json.loads(lsblk_res["stdout"])
            luks_c = 0
            lvm_c = 0

            def walk(nodes):
                nonlocal luks_c, lvm_c
                for n in nodes or []:
                    t = (n.get("type") or "").lower()
                    fs = (n.get("fstype") or "").lower()
                    if t == "crypt" or "luks" in fs:
                        luks_c += 1
                    if t == "lvm" or "lvm" in fs:
                        lvm_c += 1
                    walk(n.get("children"))

            walk(tree.get("blockdevices", []))
            luks_status = "ok"
            luks_count = luks_c
            lvm_count = lvm_c
        except json.JSONDecodeError:
            luks_status = "error"
    else:
        luks_status = lsblk_res["status"]

    secure_boot = {"status": "unavailable", "enabled": None}
    mok = run_cmd(["mokutil", "--sb-state"])
    if mok["status"] == "ok":
        out_low = mok["stdout"].lower()
        secure_boot = {
            "status": "ok",
            "enabled": "secureboot enabled" in out_low,
            "raw": mok["stdout"].strip(),
        }
    elif Path("/sys/firmware/efi").exists():
        secure_boot = {"status": mok["status"], "enabled": None}
    else:
        secure_boot = {"status": "unavailable", "enabled": False, "detail": "non_efi_or_container"}

    tpm_present = Path("/dev/tpmrm0").exists() or Path("/dev/tpm0").exists()
    return {
        "luks_volumes": {"status": luks_status, "count": luks_count},
        "lvm_volumes": {"status": luks_status, "count": lvm_count},
        "secure_boot": secure_boot,
        "tpm2_device_present": tpm_present,
    }


# =============================================================================
# LAYER 2 — KERNEL & SYSCTL HARDENING
# =============================================================================
def probe_layer2():
    deb = read_text_file("/etc/debian_version")
    lockdown = read_text_file("/sys/kernel/security/lockdown")
    lockdown_mode = None
    if lockdown["status"] == "ok" and lockdown["value"]:
        m = re.search(r"\[([^\]]+)\]", lockdown["value"])
        lockdown_mode = m.group(1) if m else lockdown["value"]

    sysctl_keys = [
        "kernel.randomize_va_space",
        "kernel.kptr_restrict",
        "kernel.dmesg_restrict",
        "kernel.unprivileged_userns_clone",
        "kernel.unprivileged_bpf_disabled",
        "kernel.perf_event_paranoid",
        "kernel.yama.ptrace_scope",
        "kernel.apparmor_restrict_unprivileged_userns",
        "net.core.bpf_jit_harden",
        "fs.protected_hardlinks",
        "fs.protected_symlinks",
        "fs.suid_dumpable",
        "net.ipv4.conf.all.rp_filter",
        "net.ipv4.tcp_syncookies",
    ]
    sysctls = {k: read_sysctl_int(k) for k in sysctl_keys}

    return {
        "debian_version": deb["value"] if deb["status"] == "ok" else None,
        "kernel_release": platform.release(),
        "architecture": platform.machine(),
        "kernel_lockdown": {
            "status": lockdown["status"],
            "mode": lockdown_mode,
            "raw": lockdown["value"],
        },
        "sysctl": sysctls,
    }


# =============================================================================
# LAYER 3 — MAC CONFINEMENT (APPARMOR + SELECTIVE USERNS)
# =============================================================================
def probe_layer3():
    svc = systemctl_active("apparmor")
    aa_enabled_file = read_text_file("/sys/module/apparmor/parameters/enabled")
    kernel_enabled = None
    if aa_enabled_file["status"] == "ok":
        kernel_enabled = aa_enabled_file["value"] in ("Y", "1", "true")

    aa_probe = {"status": "unavailable", "profiles_enforce": None, "profiles_complain": None, "profiles_total": None}
    aa_res = run_cmd(["aa-status", "--json"])
    if aa_res["status"] == "ok":
        try:
            data = json.loads(aa_res["stdout"])
            profiles = data.get("profiles", {})
            enforce_n = sum(1 for v in profiles.values() if v == "enforce")
            complain_n = sum(1 for v in profiles.values() if v == "complain")
            aa_probe = {
                "status": "ok",
                "profiles_enforce": enforce_n,
                "profiles_complain": complain_n,
                "profiles_total": len(profiles),
            }
        except json.JSONDecodeError:
            aa_probe["status"] = "error"
    else:
        aa_probe["status"] = aa_res["status"]
        if aa_res["stderr"]:
            aa_probe["detail"] = aa_res["stderr"]

    kether_profile_installed = Path("/etc/apparmor.d/kether-ai-agent-userns").exists()
    return {
        "service": svc,
        "kernel_module_enabled": kernel_enabled,
        "aa_status": aa_probe,
        "kether_userns_profile_installed": kether_profile_installed,
    }


# =============================================================================
# LAYER 4 — NETWORK (NFTABLES DEFAULT-DENY + DNS-OVER-TLS)
# =============================================================================
def probe_layer4():
    nft_probe = {
        "status": "unavailable",
        "table_count": None,
        "input_policy_drop": None,
        "forward_policy_drop": None,
        "output_policy_drop": None,
    }
    nft_res = run_cmd(["nft", "list", "ruleset"])
    if nft_res["status"] == "ok":
        txt = nft_res["stdout"]
        tables = re.findall(r"^\s*table\s+\S+\s+\S+", txt, flags=re.MULTILINE)
        nft_probe = {
            "status": "ok",
            "table_count": len(tables),
            "input_policy_drop": bool(re.search(r"hook\s+input\b[^;]*;\s*policy\s+drop\s*;", txt)),
            "forward_policy_drop": bool(re.search(r"hook\s+forward\b[^;]*;\s*policy\s+drop\s*;", txt)),
            "output_policy_drop": bool(re.search(r"hook\s+output\b[^;]*;\s*policy\s+drop\s*;", txt)),
        }
    else:
        nft_probe["status"] = nft_res["status"]
        if nft_res["stderr"]:
            nft_probe["detail"] = nft_res["stderr"]

    dot_probe = {"status": "unavailable", "dns_over_tls": None, "dnssec": None}
    res_cmd = run_cmd(["resolvectl", "status"])
    if res_cmd["status"] == "ok":
        out = res_cmd["stdout"]
        dot_m = re.search(r"DNSOverTLS\s*setting:\s*(\S+)", out, re.IGNORECASE)
        dnssec_m = re.search(r"DNSSEC\s*setting:\s*(\S+)", out, re.IGNORECASE)
        dot_val = dot_m.group(1).lower() if dot_m else None
        dnssec_val = dnssec_m.group(1).lower() if dnssec_m else None
        dot_probe = {
            "status": "ok",
            "dns_over_tls": dot_val in ("yes", "opportunistic") if dot_val else None,
            "dns_over_tls_mode": dot_val,
            "dnssec": dnssec_val in ("yes", "allow-downgrade") if dnssec_val else None,
            "dnssec_mode": dnssec_val,
        }
    else:
        # Check static drop-in fallback when systemd-resolved is inactive in containers
        dropin = read_text_file("/etc/systemd/resolved.conf.d/99-kether.conf")
        dot_probe["status"] = res_cmd["status"]
        dot_probe["dropin_configured"] = dropin["status"] == "ok" and "DNSOverTLS=yes" in (dropin["value"] or "")

    return {
        "nftables": nft_probe,
        "systemd_resolved": dot_probe,
    }


# =============================================================================
# LAYER 5 — TELEMETRY & INTEGRITY (AUDITD, JOURNALD, AIDE, USBGUARD, LYNIS)
# =============================================================================
def probe_layer5():
    audit_svc = systemctl_active("auditd")
    audit_probe = {
        "status": "unavailable",
        "enabled": None,
        "backlog_limit": None,
        "lost_events": None,
        "rules_loaded": None,
    }
    ac_res = run_cmd(["auditctl", "-s"])
    if ac_res["status"] == "ok":
        kv = {}
        for line in ac_res["stdout"].splitlines():
            parts = line.strip().split()
            if len(parts) >= 2:
                kv[parts[0]] = parts[1]

        def to_int(k):
            try:
                return int(kv[k])
            except (KeyError, ValueError):
                return None

        rules_res = run_cmd(["auditctl", "-l"])
        rules_n = None
        if rules_res["status"] == "ok":
            lines = [ln for ln in rules_res["stdout"].splitlines() if ln.strip() and not ln.startswith("No rules")]
            rules_n = len(lines)

        audit_probe = {
            "status": "ok",
            "enabled": to_int("enabled"),
            "backlog_limit": to_int("backlog_limit"),
            "lost_events": to_int("lost"),
            "rules_loaded": rules_n,
        }
    else:
        audit_probe["status"] = ac_res["status"]
        if ac_res["stderr"]:
            audit_probe["detail"] = ac_res["stderr"]

    aide_db_present = Path("/var/lib/aide/aide.db").exists()
    usbguard_svc = systemctl_active("usbguard")
    journald_svc = systemctl_active("systemd-journald")

    lynis_candidates = [Path(lynis_log_arg)] if lynis_log_arg else [Path("/var/log/lynis-report.dat")]
    lynis_probe = {"status": "unavailable", "hardening_index": None, "source": None}
    for cand in lynis_candidates:
        if cand.exists():
            txt = read_text_file(cand)
            if txt["status"] == "ok":
                m = re.search(r"hardening_index=(\d+)", txt["value"]) or re.search(
                    r"Hardening index\s*:\s*(\d+)", txt["value"]
                )
                if m:
                    lynis_probe = {
                        "status": "ok",
                        "hardening_index": int(m.group(1)),
                        "source": str(cand),
                    }
                    break
            else:
                lynis_probe = {"status": txt["status"], "hardening_index": None, "source": str(cand)}

    return {
        "auditd_service": audit_svc,
        "auditd_status": audit_probe,
        "journald_service": journald_svc,
        "aide_baseline_present": aide_db_present,
        "usbguard_service": usbguard_svc,
        "lynis": lynis_probe,
    }


# =============================================================================
# LAYER 6 — EPHEMERAL KVM / QCOW2 SANDBOX
# =============================================================================
def probe_layer6():
    kvm_present = Path("/dev/kvm").exists()
    kvm_rw = os.access("/dev/kvm", os.R_OK | os.W_OK) if kvm_present else False
    cpuinfo = read_text_file("/proc/cpuinfo")
    virt_flags = 0
    if cpuinfo["status"] == "ok" and cpuinfo["value"]:
        virt_flags = len(re.findall(r"\b(vmx|svm)\b", cpuinfo["value"]))

    libvirt_svc = systemctl_active("libvirtd")
    qemu_img_path = shutil.which("qemu-img")

    overlay_test = {"status": "skipped", "overlay_create_ms": None, "teardown_ms": None, "base_integrity_preserved": None}
    if test_qcow2:
        if not qemu_img_path:
            overlay_test["status"] = "not_installed"
        else:
            with tempfile.TemporaryDirectory(prefix="kether_qcow2_bench_") as tmpdir:
                base_img = Path(tmpdir) / "base.qcow2"
                overlay_img = Path(tmpdir) / "ephemeral_overlay.qcow2"
                c1 = run_cmd([qemu_img_path, "create", "-f", "qcow2", str(base_img), "16M"])
                if c1["status"] == "ok":
                    os.chmod(base_img, 0o444)
                    sha_before = hashlib.sha256(base_img.read_bytes()).hexdigest()
                    t0 = time.perf_counter()
                    c2 = run_cmd(
                        [qemu_img_path, "create", "-f", "qcow2", "-F", "qcow2", "-b", str(base_img), str(overlay_img)]
                    )
                    create_ms = round((time.perf_counter() - t0) * 1000.0, 2)
                    if c2["status"] == "ok":
                        t1 = time.perf_counter()
                        overlay_img.unlink()
                        teardown_ms = round((time.perf_counter() - t1) * 1000.0, 2)
                        sha_after = hashlib.sha256(base_img.read_bytes()).hexdigest()
                        overlay_test = {
                            "status": "ok",
                            "overlay_create_ms": create_ms,
                            "teardown_ms": teardown_ms,
                            "base_integrity_preserved": sha_before == sha_after,
                        }
                    else:
                        overlay_test["status"] = c2["status"]
                else:
                    overlay_test["status"] = c1["status"]

    return {
        "kvm_device_present": kvm_present,
        "kvm_device_accessible": kvm_rw,
        "cpu_virt_extensions_count": virt_flags,
        "libvirtd_service": libvirt_svc,
        "qemu_img_installed": qemu_img_path is not None,
        "qcow2_overlay_benchmark": overlay_test,
    }


report = {
    "schema_version": "1.1.0",
    "framework": "Techdim Debian 13 Hardening Framework & Ephemeral KVM Sandbox (Kether_1)",
    "concept_doi": "10.5281/zenodo.24380374",
    "timestamp_utc": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "execution_context": {
        "privilege_context": "root" if is_root else "unprivileged",
        "euid": euid,
        "effective_user": effective_user,
        "hostname_sha256_prefix": hashlib.sha256(platform.node().encode("utf-8")).hexdigest()[:12],
    },
    "layers": {
        "layer_1_storage_firmware": probe_layer1(),
        "layer_2_kernel_sysctl": probe_layer2(),
        "layer_3_mac_apparmor": probe_layer3(),
        "layer_4_network_nftables_dot": probe_layer4(),
        "layer_5_telemetry_integrity": probe_layer5(),
        "layer_6_ephemeral_kvm_sandbox": probe_layer6(),
    },
}

json_path = out_dir / "metrics_report.json"
json_path.write_text(json.dumps(report, indent=2, sort_keys=False) + "\n", encoding="utf-8")

# Generate paper-ready Markdown summary table
l1 = report["layers"]["layer_1_storage_firmware"]
l2 = report["layers"]["layer_2_kernel_sysctl"]
l3 = report["layers"]["layer_3_mac_apparmor"]
l4 = report["layers"]["layer_4_network_nftables_dot"]
l5 = report["layers"]["layer_5_telemetry_integrity"]
l6 = report["layers"]["layer_6_ephemeral_kvm_sandbox"]


def fmt(val, status=None):
    if status and status != "ok":
        return f"`{status}`"
    if val is None:
        return "`null`"
    return f"`{val}`"


md_lines = [
    "# Kether_1 Experimental Metrics Summary",
    "",
    f"- **Timestamp (UTC):** `{report['timestamp_utc']}`",
    f"- **Privilege Context:** `{report['execution_context']['privilege_context']}` (`euid={euid}`)",
    f"- **Debian / Kernel:** `{l2['debian_version']}` / `{l2['kernel_release']}` (`{l2['architecture']}`)",
    "",
    "| Layer | Indicator | Value / Status |",
    "| :--- | :--- | :--- |",
    f"| L1 Storage/Firmware | LUKS2 / LVM volumes | {fmt(l1['luks_volumes']['count'], l1['luks_volumes']['status'])} / {fmt(l1['lvm_volumes']['count'], l1['lvm_volumes']['status'])} |",
    f"| L1 Storage/Firmware | UEFI Secure Boot / TPM 2.0 | {fmt(l1['secure_boot']['enabled'], l1['secure_boot']['status'])} / `{l1['tpm2_device_present']}` |",
    f"| L2 Kernel | `lockdown` mode | {fmt(l2['kernel_lockdown']['mode'], l2['kernel_lockdown']['status'])} |",
    f"| L2 Kernel | `unprivileged_userns_clone` / `unprivileged_bpf_disabled` | {fmt(l2['sysctl']['kernel.unprivileged_userns_clone']['value'], l2['sysctl']['kernel.unprivileged_userns_clone']['status'])} / {fmt(l2['sysctl']['kernel.unprivileged_bpf_disabled']['value'], l2['sysctl']['kernel.unprivileged_bpf_disabled']['status'])} |",
    f"| L3 MAC AppArmor | Profiles `enforce` / `complain` | {fmt(l3['aa_status']['profiles_enforce'], l3['aa_status']['status'])} / {fmt(l3['aa_status']['profiles_complain'], l3['aa_status']['status'])} |",
    f"| L4 Network | `nftables` `input`/`forward` `policy drop` | {fmt(l4['nftables']['input_policy_drop'], l4['nftables']['status'])} / {fmt(l4['nftables']['forward_policy_drop'], l4['nftables']['status'])} |",
    f"| L4 Network | `systemd-resolved` DNS-over-TLS | {fmt(l4['systemd_resolved']['dns_over_tls'], l4['systemd_resolved']['status'])} |",
    f"| L5 Telemetry | `auditd` `backlog_limit` / `lost_events` | {fmt(l5['auditd_status']['backlog_limit'], l5['auditd_status']['status'])} / {fmt(l5['auditd_status']['lost_events'], l5['auditd_status']['status'])} |",
    f"| L5 Integrity | AIDE DB / USBGuard / Lynis Index | `{l5['aide_baseline_present']}` / {fmt(l5['usbguard_service']['active'], l5['usbguard_service']['status'])} / {fmt(l5['lynis']['hardening_index'], l5['lynis']['status'])} |",
    f"| L6 KVM Sandbox | `/dev/kvm` / QCOW2 CoW Overlay Test | `{l6['kvm_device_present']}` / {fmt(l6['qcow2_overlay_benchmark']['overlay_create_ms'], l6['qcow2_overlay_benchmark']['status'])} ms |",
    "",
]
md_path = out_dir / "metrics_summary.md"
md_path.write_text("\n".join(md_lines), encoding="utf-8")

# Cryptographic integrity manifest
checksums = []
for fpath in (json_path, md_path):
    digest = hashlib.sha256(fpath.read_bytes()).hexdigest()
    checksums.append(f"{digest}  {fpath.name}")
(out_dir / "SHA256SUMS.txt").write_text("\n".join(checksums) + "\n", encoding="utf-8")

print(f"Kether_1 metrics collected ({report['execution_context']['privilege_context']}) -> {json_path}")
PYEOF
