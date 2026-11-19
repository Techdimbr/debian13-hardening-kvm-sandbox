#!/usr/bin/env bash
# =============================================================================
# Techdim Kether_1 — Auditd Lossless Telemetry Stress Benchmark (lost=0)
# Simulates high-frequency autonomous AI agent tool bursts (N rapid execve
# calls to /bin/true) while comparing `auditctl -s` backlog/lost counters
# before and after the burst.
#
# Usage:
#   sudo ./scripts/benchmark_auditd_stress.sh [--events 1000] [--dry-run]
#
# Author: Eng. Deivis Irio Mayer (Kether1) — ORCID: 0009-0003-3273-7883
# License: MIT
# =============================================================================
set -euo pipefail

EVENTS=1000
DRY_RUN=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --events) EVENTS="$2"; shift 2 ;;
    --dry-run) DRY_RUN=1; shift ;;
    -h|--help)
      echo "Usage: benchmark_auditd_stress.sh [--events N] [--dry-run]"
      exit 0
      ;;
    *) echo "ERROR: Unknown option: $1" >&2; exit 2 ;;
  esac
done

if [[ ! "$EVENTS" =~ ^[0-9]+$ || "$EVENTS" -lt 1 ]]; then
  echo "ERROR: --events must be a positive integer" >&2
  exit 2
fi

if [[ "$DRY_RUN" -eq 1 ]]; then
  python3 - "$EVENTS" <<'PY'
import json, sys
print(json.dumps({
    "mode": "dry_run",
    "synthetic_execve_events": int(sys.argv[1]),
    "target_assertion": "lost_delta == 0 and backlog_limit >= 8192",
}, indent=2))
PY
  exit 0
fi

if [[ "$EUID" -ne 0 ]]; then
  echo "ERROR: Root privileges required to query auditctl -s. Re-run with sudo." >&2
  exit 1
fi

command -v auditctl >/dev/null 2>&1 || { echo "ERROR: auditctl not installed." >&2; exit 1; }

read_audit_field() {
  auditctl -s | awk -v k="$1" '$1 == k { print $2; exit }'
}

BACKLOG_LIMIT="$(read_audit_field backlog_limit)"
LOST_BEFORE="$(read_audit_field lost)"
START_NS="$(date +%s%N)"

for ((i = 1; i <= EVENTS; i++)); do
  /bin/true
done

END_NS="$(date +%s%N)"
LOST_AFTER="$(read_audit_field lost)"
BACKLOG_PEAK="$(read_audit_field backlog)"

python3 - "$EVENTS" "$BACKLOG_LIMIT" "$LOST_BEFORE" "$LOST_AFTER" "$BACKLOG_PEAK" "$START_NS" "$END_NS" <<'PY'
import json, sys
events = int(sys.argv[1])
backlog_limit = int(sys.argv[2] or 0)
lost_before = int(sys.argv[3] or 0)
lost_after = int(sys.argv[4] or 0)
backlog_peak = int(sys.argv[5] or 0)
elapsed_ms = round((int(sys.argv[7]) - int(sys.argv[6])) / 1_000_000.0, 2)
lost_delta = lost_after - lost_before

print(json.dumps({
    "status": "ok",
    "synthetic_execve_events": events,
    "elapsed_ms": elapsed_ms,
    "auditd_backlog_limit": backlog_limit,
    "auditd_backlog_observed": backlog_peak,
    "lost_before": lost_before,
    "lost_after": lost_after,
    "lost_delta": lost_delta,
    "lossless_passed": (lost_delta == 0 and backlog_limit >= 8192),
}, indent=2))
PY
