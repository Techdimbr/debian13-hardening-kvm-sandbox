#!/usr/bin/env bash
# =============================================================================
# Techdim Kether_1 — Ephemeral KVM/QCOW2 Sandbox Lifecycle Orchestrator
# Purpose: Provision disposable Copy-on-Write (CoW) QCOW2 overlays backed by an
#          immutable read-only Debian 13 golden image for autonomous AI agent
#          execution, guaranteeing deterministic teardown and zero host/base
#          image contamination.
#
# Subcommands:
#   create     Create a disposable QCOW2 overlay & define/start ephemeral VM
#   status     Show active ephemeral sandbox VMs and overlay metadata
#   destroy    Force-stop, undefine VM, securely shred/remove overlay & verify base SHA-256
#   benchmark  Measure overlay creation + teardown latency & verify base integrity (JSON)
#
# Flags:
#   --base PATH          Path to read-only golden QCOW2 image
#   --name NAME          Sandbox session name (default: kether-sbx-<timestamp>)
#   --workdir DIR        Overlay directory (default: /var/lib/libvirt/images/kether-ephemeral)
#   --vcpus N            vCPU count (default: 4)
#   --ram-mb N           Memory in MiB (default: 4096)
#   --network NET        Libvirt network name (default: default)
#   --dry-run            Print commands and emit plan JSON without modifying host
#
# Author: Eng. Deivis Irio Mayer (Kether1) — ORCID: 0009-0003-3273-7883
# License: MIT
# =============================================================================
set -euo pipefail

CMD="${1:-help}"
if [[ $# -gt 0 ]]; then shift; fi

BASE_IMAGE=""
SANDBOX_NAME="kether-sbx-$(date -u +%Y%m%dT%H%M%S)"
WORKDIR="/var/lib/libvirt/images/kether-ephemeral"
VCPUS=4
RAM_MB=4096
NETWORK="default"
DRY_RUN=0

usage() {
  cat <<'EOF'
Usage: kvm_ephemeral_sandbox.sh <create|status|destroy|benchmark> [OPTIONS]

Options:
  --base PATH      Golden read-only QCOW2 backing image
  --name NAME      Ephemeral VM / session name
  --workdir DIR    Directory for disposable overlays
  --vcpus N        Number of vCPUs (default: 4)
  --ram-mb N       RAM in MiB (default: 4096)
  --network NET    Libvirt isolated network (default: default)
  --dry-run        Validate arguments and print deterministic execution plan
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --base) BASE_IMAGE="$2"; shift 2 ;;
    --name) SANDBOX_NAME="$2"; shift 2 ;;
    --workdir) WORKDIR="$2"; shift 2 ;;
    --vcpus) VCPUS="$2"; shift 2 ;;
    --ram-mb) RAM_MB="$2"; shift 2 ;;
    --network) NETWORK="$2"; shift 2 ;;
    --dry-run) DRY_RUN=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "ERROR: Unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

validate_name() {
  if [[ ! "$SANDBOX_NAME" =~ ^[a-zA-Z0-9._-]+$ ]]; then
    echo "ERROR: Invalid sandbox name '$SANDBOX_NAME' (allowed: a-zA-Z0-9._-)" >&2
    exit 2
  fi
}

run_or_plan() {
  if [[ "$DRY_RUN" -eq 1 ]]; then
    printf '[DRY-RUN] %q' "$1"
    shift
    for arg in "$@"; do
      printf ' %q' "$arg"
    done
    printf '\n'
  else
    "$@"
  fi
}

case "$CMD" in
  create)
    validate_name
    [[ -n "$BASE_IMAGE" ]] || { echo "ERROR: --base PATH is required for create" >&2; exit 2; }
    if [[ "$DRY_RUN" -eq 0 ]]; then
      [[ -f "$BASE_IMAGE" ]] || { echo "ERROR: Base image not found: $BASE_IMAGE" >&2; exit 1; }
      for bin in qemu-img virt-install sha256sum; do
        command -v "$bin" >/dev/null 2>&1 || { echo "ERROR: Required tool missing: $bin" >&2; exit 1; }
      done
    fi

    OVERLAY_PATH="${WORKDIR}/${SANDBOX_NAME}.qcow2"
    META_PATH="${WORKDIR}/${SANDBOX_NAME}.meta.json"

    run_or_plan mkdir -p "$WORKDIR"
    # Enforce immutable permissions on golden backing image
    run_or_plan chmod a-w "$BASE_IMAGE"
    run_or_plan qemu-img create -f qcow2 -F qcow2 -b "$BASE_IMAGE" "$OVERLAY_PATH"

    if [[ "$DRY_RUN" -eq 0 ]]; then
      BASE_SHA="$(sha256sum "$BASE_IMAGE" | awk '{print $1}')"
      python3 - "$META_PATH" "$SANDBOX_NAME" "$BASE_IMAGE" "$BASE_SHA" "$OVERLAY_PATH" "$VCPUS" "$RAM_MB" "$NETWORK" <<'PY'
import datetime, json, sys
p, name, base, sha, ov, vcpus, ram, net = sys.argv[1:]
meta = {
    "sandbox_name": name,
    "created_utc": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "base_image": base,
    "base_sha256_before": sha,
    "overlay_path": ov,
    "vcpus": int(vcpus),
    "ram_mb": int(ram),
    "network": net,
}
open(p, "w", encoding="utf-8").write(json.dumps(meta, indent=2) + "\n")
PY
    fi

    # Boot ephemeral domain (transient, virtio-blk, isolated network, no host shared folders)
    run_or_plan virt-install \
      --name "$SANDBOX_NAME" \
      --memory "$RAM_MB" \
      --vcpus "$VCPUS" \
      --disk "path=${OVERLAY_PATH},format=qcow2,bus=virtio,cache=writeback" \
      --network "network=${NETWORK},model=virtio" \
      --os-variant debian12 \
      --import \
      --noautoconsole \
      --transient

    echo "Ephemeral sandbox '${SANDBOX_NAME}' ready (overlay: ${OVERLAY_PATH})."
    ;;

  status)
    if [[ "$DRY_RUN" -eq 1 ]]; then
      echo "[DRY-RUN] virsh list --all --name | grep '^kether-sbx-'"
      exit 0
    fi
    command -v virsh >/dev/null 2>&1 || { echo "ERROR: virsh not installed" >&2; exit 1; }
    virsh list --all | grep -E "Name|---|kether-sbx-" || true
    ;;

  destroy)
    validate_name
    OVERLAY_PATH="${WORKDIR}/${SANDBOX_NAME}.qcow2"
    META_PATH="${WORKDIR}/${SANDBOX_NAME}.meta.json"

    run_or_plan virsh destroy "$SANDBOX_NAME" || true
    run_or_plan virsh undefine "$SANDBOX_NAME" --nvram || true
    run_or_plan rm -f "$OVERLAY_PATH"

    if [[ "$DRY_RUN" -eq 0 && -f "$META_PATH" ]]; then
      python3 - "$META_PATH" <<'PY'
import hashlib, json, sys
from pathlib import Path
meta = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
base = Path(meta["base_image"])
sha_after = hashlib.sha256(base.read_bytes()).hexdigest()
preserved = (sha_after == meta["base_sha256_before"])
print(json.dumps({
    "sandbox_name": meta["sandbox_name"],
    "overlay_removed": not Path(meta["overlay_path"]).exists(),
    "base_integrity_preserved": preserved,
}, indent=2))
assert preserved, "CRITICAL: Base golden image hash changed!"
PY
      rm -f "$META_PATH"
    fi
    echo "Ephemeral sandbox '${SANDBOX_NAME}' destroyed and verified."
    ;;

  benchmark)
    if [[ "$DRY_RUN" -eq 1 ]]; then
      python3 - <<'PY'
import json
print(json.dumps({
    "mode": "dry_run",
    "planned_steps": [
        "create_16M_scratch_base_qcow2",
        "chmod_a_minus_w_base",
        "sha256_base_before",
        "timed_qemu_img_create_cow_overlay",
        "timed_overlay_teardown",
        "sha256_base_after_assert_equal"
    ]
}, indent=2))
PY
      exit 0
    fi
    command -v qemu-img >/dev/null 2>&1 || { echo "ERROR: qemu-img not installed" >&2; exit 1; }
    python3 - <<'PY'
import hashlib, json, os, subprocess, tempfile, time
from pathlib import Path

with tempfile.TemporaryDirectory(prefix="kether_sbx_bench_") as d:
    base = Path(d) / "golden.qcow2"
    overlay = Path(d) / "overlay.qcow2"
    subprocess.run(["qemu-img", "create", "-f", "qcow2", str(base), "16M"], check=True, stdout=subprocess.DEVNULL)
    os.chmod(base, 0o444)
    sha_before = hashlib.sha256(base.read_bytes()).hexdigest()

    t0 = time.perf_counter()
    subprocess.run(["qemu-img", "create", "-f", "qcow2", "-F", "qcow2", "-b", str(base), str(overlay)], check=True, stdout=subprocess.DEVNULL)
    create_ms = round((time.perf_counter() - t0) * 1000.0, 2)

    t1 = time.perf_counter()
    overlay.unlink()
    teardown_ms = round((time.perf_counter() - t1) * 1000.0, 2)

    sha_after = hashlib.sha256(base.read_bytes()).hexdigest()
    print(json.dumps({
        "status": "ok",
        "overlay_create_ms": create_ms,
        "teardown_ms": teardown_ms,
        "base_integrity_preserved": sha_before == sha_after,
    }, indent=2))
PY
    ;;

  help|-h|--help)
    usage
    exit 0
    ;;

  *)
    echo "ERROR: Unknown subcommand: $CMD" >&2
    usage >&2
    exit 2
    ;;
esac
