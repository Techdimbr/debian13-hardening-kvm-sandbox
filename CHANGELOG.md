# Changelog

All notable changes to **Techdim Debian 13 Hardening Framework & Ephemeral KVM Sandbox (`Kether_1`)** are documented in this file.

## [1.1.0-rc1] — 2026-11-19 (Peer-Review Remediation & Full Framework Implementation)

### Added
- **Executable 6-Layer Hardening Configs (`configs/`):**
  - `configs/sysctl/99-kether-hardening.conf` (Debian 13 Kernel 6.12 LTS baseline preserving AppArmor-mediated `userns`).
  - `configs/apparmor/kether-ai-agent-userns` (AppArmor 4.x selective `userns` confinement denying host credentials).
  - `configs/nftables/kether-workstation.nft` (default-deny `input`/`forward`/`output` + KVM lateral RFC1918 drop).
  - `configs/auditd/99-kether.rules` (`-b 8192` at top, forensic watches, immutable `-e 2` finalized last).
  - `configs/systemd/resolved-dot.conf` (DNS-over-TLS + DNSSEC), `configs/systemd/journald-kether.conf`, and `configs/ssh/99-kether-sshd.conf` (OpenSSH 10 PQ-hybrid KEX).
- **Executable Orchestration & Audit Scripts (`scripts/`):**
  - `scripts/kvm_ephemeral_sandbox.sh` — Disposable QCOW2 CoW KVM sandbox orchestrator with SHA-256 base-image verification and `--dry-run`.
  - `scripts/audit_cis_43_controls.sh` — Full 43-control CIS Debian 13 + BeyondCorp auditor emitting typed JSON, Markdown, and `SHA256SUMS.txt`.
  - `scripts/benchmark_auditd_stress.sh` — Lossless `auditd` burst stress benchmark (`lost_delta == 0`).
- **Academic & Licensing Documentation:**
  - Canonical `docs/WHITEPAPER.md` with formal STRIDE Threat Model, Methodology, and comparative benchmark protocol.
  - `docs/PEER_REVIEW_RESPONSE_v1.0.1.md` documenting remediation of Zenodo `v1.0.1` peer review.
  - `LICENSE-DOCS` (CC-BY-4.0) harmonizing dual licensing with `LICENSE` (MIT).
- **Automated Test Suite (`tests/test_framework.py`)** + `shellcheck` enforcement in GitHub Actions CI.

### Changed
- **Hardened `scripts/collect_kether_metrics.sh`:** Replaced bash here-doc JSON interpolation with strongly typed Python `json.dumps()`, added explicit `privilege_context` and per-probe `status` (eliminating silent permission fallbacks), expanded coverage to all 6 layers, and added `--test-qcow2-overlay` functional benchmark.
- Updated `README.md` DOI badge to persistent **Concept DOI** (`10.5281/zenodo.24380374`) alongside version DOI (`10.5281/zenodo.24380375`).
- Replaced version-locked `docs/WHITEPAPER_v1.0.0.md` with canonical `docs/WHITEPAPER.md`.

## [1.0.1] — 2026-11-19 (First Zenodo-Archived Release — DOI `10.5281/zenodo.24380375`)
- First GitHub Release archived automatically via Zenodo webhook with Concept DOI `10.5281/zenodo.24380374` and author ORCID `0009-0003-3273-7883`.

## [1.0.0] — 2026-11-19
- Initial repository architecture, `CITATION.cff`, `.zenodo.json`, CI metadata validation workflow, Technical Note draft, and initial metrics collector.
