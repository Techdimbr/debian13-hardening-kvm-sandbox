#!/usr/bin/env bash
# Techdim Kether_1 — Read-Only Experimental Metrics Collector for Debian 13 + KVM Sandbox
# Author: Eng. Deivis Irio Mayer (Kether1) — TECHDIM INOVA SIMPLES (I.S.) - ME
# License: MIT
set -euo pipefail

OUT_DIR="${1:-./benchmarks/run_$(date -u +%Y%m%dT%H%M%SZ)}"
mkdir -p "$OUT_DIR"

DEBIAN_VER="$(cat /etc/debian_version 2>/dev/null || echo 'unknown')"
KERNEL_VER="$(uname -r)"
LOCKDOWN_STATE="$(cat /sys/kernel/security/lockdown 2>/dev/null || echo 'unavailable')"
USERNS_CLONE="$(sysctl -n kernel.unprivileged_userns_clone 2>/dev/null || echo 'n/a')"
BPF_UNPRIV="$(sysctl -n kernel.unprivileged_bpf_disabled 2>/dev/null || echo 'n/a')"
AA_ENFORCE="$(aa-status --json 2>/dev/null | python3 -c 'import sys,json; d=json.load(sys.stdin); print(sum(1 for v in d.get("profiles",{}).values() if v=="enforce"))' 2>/dev/null || echo 'n/a')"
AA_COMPLAIN="$(aa-status --json 2>/dev/null | python3 -c 'import sys,json; d=json.load(sys.stdin); print(sum(1 for v in d.get("profiles",{}).values() if v=="complain"))' 2>/dev/null || echo 'n/a')"
AUDIT_BACKLOG="$(auditctl -s 2>/dev/null | awk '/backlog_limit/{print $2}' || echo 'n/a')"
NFT_TABLES="$(nft list tables 2>/dev/null | wc -l || echo '0')"
KVM_DEV="$( [ -e /dev/kvm ] && echo 'present' || echo 'absent' )"

cat > "${OUT_DIR}/metrics_report.json" <<EOF
{
  "timestamp_utc": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "debian_version": "${DEBIAN_VER}",
  "kernel_release": "${KERNEL_VER}",
  "kernel_lockdown": "${LOCKDOWN_STATE}",
  "sysctl_unprivileged_userns_clone": "${USERNS_CLONE}",
  "sysctl_unprivileged_bpf_disabled": "${BPF_UNPRIV}",
  "apparmor_profiles_enforce": "${AA_ENFORCE}",
  "apparmor_profiles_complain": "${AA_COMPLAIN}",
  "auditd_backlog_limit": "${AUDIT_BACKLOG}",
  "nftables_table_count": "${NFT_TABLES}",
  "kvm_device": "${KVM_DEV}"
}
EOF

sha256sum "${OUT_DIR}/metrics_report.json" > "${OUT_DIR}/SHA256SUMS.txt"
echo "Experimental metrics report saved to: ${OUT_DIR}/metrics_report.json"
