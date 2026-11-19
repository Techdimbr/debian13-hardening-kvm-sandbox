# Zero Trust Hardening and Ephemeral KVM Sandboxing on Debian 13 for Autonomous AI Agents (`Kether_1` Framework)

**Version:** `1.1.0-rc1` *(Revision addressing Peer Review of Zenodo Record `v1.0.1`)*  
**Author:** Deivis Irio Mayer (`Kether1`) — ORCID: [0009-0003-3273-7883](https://orcid.org/0009-0003-3273-7883) · Google Scholar: [Ik00pFwAAAAJ](https://scholar.google.com/citations?user=Ik00pFwAAAAJ&hl=pt-BR)  
**Affiliation:** TECHDIM INOVA SIMPLES (I.S.) - ME, Campinas — SP, Brazil  
**Formatted Academic PDF (Google Scholar Ready):** [`docs/paper/Kether1_Debian13_Hardening_Ephemeral_KVM_Sandbox_2026.pdf`](paper/Kether1_Debian13_Hardening_Ephemeral_KVM_Sandbox_2026.pdf) · [`citation.bib`](paper/citation.bib)  
**Repository:** https://github.com/Techdimbr/debian13-hardening-kvm-sandbox  
**Concept DOI (All Versions):** https://doi.org/10.5281/zenodo.24380374  
**Previous Version DOI (`v1.0.1`):** https://doi.org/10.5281/zenodo.24380375  
**Licensing:** Dual-licensed — **MIT License** for software, scripts, and configurations ([`LICENSE`](../LICENSE)); **CC-BY-4.0** for this Technical Note and documentation ([`LICENSE-DOCS`](../LICENSE-DOCS)).

---

## Abstract

Autonomous AI coding and systems-operations agents increasingly execute build toolchains, browsers, shell commands, and untrusted third-party artifacts directly on developer workstations and edge servers. Conventional enterprise Linux hardening baselines (CIS Level 2, kernel lockdown, global user-namespace bans, and default `auditd` buffers) frequently break modern rootless sandboxes or drop forensic telemetry during high-frequency agent bursts. This paper presents and delivers the **Kether_1 Debian 13 Hardening Framework & Ephemeral KVM Sandbox**, a reproducible six-layer defense-in-depth architecture targeting Debian 13 (*Trixie*, Kernel 6.12 LTS). We contribute: (1) deployable configuration baselines spanning `sysctl`, selective `userns` AppArmor 4.x confinement, default-deny `nftables` with lateral KVM isolation, lossless `auditd` (`-b 8192`, immutable `-e 2`), DNS-over-TLS, and post-quantum hybrid OpenSSH 10; (2) an idempotent Copy-on-Write (CoW) QCOW2 ephemeral KVM sandbox orchestrator with cryptographic base-image integrity verification; (3) a privilege-aware, strongly typed JSON metrics collector and 43-control CIS/BeyondCorp auditor; and (4) a formal experimental evaluation protocol comparing pre-hardening vs. post-hardening baselines.

**Keywords:** Debian 13, Linux Kernel Hardening, Zero Trust, BeyondCorp, CIS Benchmark Level 2, AppArmor `userns`, Ephemeral KVM Sandbox, QCOW2 Copy-on-Write, Autonomous AI Agent Security, Reproducible Research.

---

## 1. Problem Statement & Research Questions

When autonomous AI agents operate locally on hardened Linux hosts, three structural tensions arise:

1. **Sandbox Breakage (`userns` / `eBPF` vs. Kernel Hardening):** Setting `kernel.unprivileged_userns_clone=0` mitigates kernel namespace attack surface but breaks rootless containers (Podman), `bubblewrap`, and browser/agent sandboxes, pressuring operators to run agents unsandboxed or with elevated privileges.
2. **Forensic Telemetry Loss (`auditd` Backlog Overflows):** Autonomous agents spawn hundreds of short-lived processes (`execve`) per minute; default Linux `auditd` buffer limits (`-b 64` or `-b 320`) suffer silent packet drops (`lost > 0`), breaking forensic chains of custody.
3. **Host State Drift & Credential Exfiltration:** Running agents directly on the host filesystem exposes `~/.ssh`, `~/.gnupg`, cloud SDK tokens, and `.env` files to indirect prompt injection or malicious dependencies.

This work addresses three research questions:
* **RQ1:** Can a Debian 13 host enforce CIS Level 2 + Zero Trust kernel/network hardening while selectively preserving `userns` strictly for AppArmor-confined sandboxes?
* **RQ2:** Does an ephemeral KVM/QCOW2 Copy-on-Write execution layer provide deterministic post-task rollback (zero base-image mutation verified by `SHA-256`) with low provisioning overhead?
* **RQ3:** Does raising the `auditd` kernel backlog (`-b 8192`) with properly ordered immutable rules (`-e 2` at finalization) achieve lossless telemetry (`lost_delta = 0`) under synthetic agent syscall bursts?

---

## 2. Formal Threat Model (Autonomous AI Agent Host)

We model an attacker leveraging **indirect prompt injection**, **poisoned package dependencies**, or **malicious tool outputs** inside an autonomous AI agent session running under a non-root local user account.

| ID | Threat Vector (STRIDE) | Attack Objective | Kether_1 Architectural Mitigation | Concrete Artifact |
| :--- | :--- | :--- | :--- | :--- |
| **T1** | Credential Theft *(Information Disclosure)* | Read `~/.ssh`, `~/.gnupg`, `~/.config/gcloud`, `.env`, `/etc/shadow` | Explicit AppArmor `deny` rules + VM boundary (no host shared mounts) | [`configs/apparmor/kether-ai-agent-userns`](../configs/apparmor/kether-ai-agent-userns) |
| **T2** | Kernel / Privilege Escalation *(Elevation of Privilege)* | Exploit `userns`, unprivileged `eBPF`, `ptrace`, or kernel pointers | `lockdown=integrity`, `unprivileged_bpf_disabled=1`, `bpf_jit_harden=2`, `kptr_restrict=2`, selective AppArmor `userns` | [`configs/sysctl/99-kether-hardening.conf`](../configs/sysctl/99-kether-hardening.conf) |
| **T3** | Lateral Movement & C2 Exfiltration *(Tampering / Info Disclosure)* | Probe LAN subnets (`RFC1918`) or exfiltrate data via plaintext DNS | `nftables` default-deny (`input`/`forward`/`output`), `virbr0 → RFC1918` drop, strict DNS-over-TLS (`853/tcp`) | [`configs/nftables/kether-workstation.nft`](../configs/nftables/kether-workstation.nft), [`configs/systemd/resolved-dot.conf`](../configs/systemd/resolved-dot.conf) |
| **T4** | Forensic Evasion *(Repudiation)* | Flood `auditd` queue (`lost > 0`) or disable audit rules | `auditd -b 8192`, watched config paths, immutable `-e 2` finalized last, `journald` retention + `AIDE` | [`configs/auditd/99-kether.rules`](../configs/auditd/99-kether.rules), [`configs/systemd/journald-kether.conf`](../configs/systemd/journald-kether.conf) |
| **T5** | Persistent Host Contamination *(Tampering)* | Plant cron/systemd persistence or backdoor host binaries | Ephemeral KVM/QCOW2 CoW overlays backed by `chmod a-w` golden image; overlay shredded on teardown | [`scripts/kvm_ephemeral_sandbox.sh`](../scripts/kvm_ephemeral_sandbox.sh) |
| **T6** | Physical / Offline Media Compromise *(Tampering / Info Disclosure)* | Cold disk extraction or rogue USB HID injection | LUKS2/LVM full-disk encryption, UEFI Secure Boot, TPM 2.0, `USBGuard` allowlist | Audited via [`scripts/audit_cis_43_controls.sh`](../scripts/audit_cis_43_controls.sh) |

**Out of Scope:** Hardware side-channel attacks (Spectre/Meltdown microarchitectural leaks beyond upstream Debian 6.12 LTS mitigations), compromised CPU microcode/UEFI firmware pre-dating host provisioning, and authorized cloud API exfiltration over allowed HTTPS endpoints inside an agent's legitimate task scope.

---

## 3. Six-Layer Defense-in-Depth Architecture (`Kether_1`)

| Layer | Security Objective | Deployed Controls | Repository Artifacts |
| :--- | :--- | :--- | :--- |
| **L1 — Storage & Firmware** | Confidentiality at rest & boot integrity | LUKS2 + LVM, UEFI Secure Boot, TPM 2.0, `/etc/shadow <= 0640`, `unattended-upgrades` | Audited by `K1-01`..`K1-06` |
| **L2 — Kernel & Sysctl** | Runtime kernel integrity & exploit mitigation | Debian 13 (6.12 LTS), `lockdown=integrity`, ASLR=2, `kptr_restrict=2`, `unprivileged_bpf_disabled=1`, `bpf_jit_harden=2`, `yama.ptrace_scope=1`, `rp_filter=1` | [`configs/sysctl/99-kether-hardening.conf`](../configs/sysctl/99-kether-hardening.conf) |
| **L3 — MAC Confinement** | Process least-privilege + selective `userns` | AppArmor 4.x enforcing profiles + explicit `userns` profile denying host secrets | [`configs/apparmor/kether-ai-agent-userns`](../configs/apparmor/kether-ai-agent-userns) |
| **L4 — Network Zero Trust** | Default-deny filtering & encrypted transport | `nftables` `policy drop` (`input`/`forward`/`output`), `virbr0` RFC1918 lateral drop, `systemd-resolved` DoT+DNSSEC, OpenSSH 10 PQ-hybrid KEX | [`configs/nftables/kether-workstation.nft`](../configs/nftables/kether-workstation.nft), [`configs/systemd/resolved-dot.conf`](../configs/systemd/resolved-dot.conf), [`configs/ssh/99-kether-sshd.conf`](../configs/ssh/99-kether-sshd.conf) |
| **L5 — Telemetry & Integrity** | Lossless forensic trail & drift detection | `auditd` (`-b 8192`, `-f 1`, `-e 2` last), `journald` caps, `AIDE` baseline, `USBGuard`, `Lynis` | [`configs/auditd/99-kether.rules`](../configs/auditd/99-kether.rules), [`configs/systemd/journald-kether.conf`](../configs/systemd/journald-kether.conf) |
| **L6 — Ephemeral KVM Sandbox** | Hardware-enforced disposable execution | Transient KVM/QEMU domain on QCOW2 CoW overlay with immutable backing image + SHA-256 verification | [`scripts/kvm_ephemeral_sandbox.sh`](../scripts/kvm_ephemeral_sandbox.sh) |

---

## 4. Methodology & Reproducible Audit Instrumentation

To eliminate silent false negatives observed in ad-hoc shell audits (e.g., hiding `EACCES` behind `2>/dev/null` or interpolating untyped strings into JSON), the Kether_1 instrumentation enforces four strict engineering invariants:

1. **Explicit Privilege Context:** Both [`scripts/collect_kether_metrics.sh`](../scripts/collect_kether_metrics.sh) and [`scripts/audit_cis_43_controls.sh`](../scripts/audit_cis_43_controls.sh) record `execution_context.privilege_context` (`"root"` or `"unprivileged"`), `euid`, and per-probe `status` (`ok`, `permission_denied`, `not_installed`, `unavailable`). Passing `--require-root` aborts unprivileged executions cleanly.
2. **Typed JSON Serialization:** All reports are serialized exclusively via Python `json.dumps()`, guaranteeing native JSON integers, booleans, and `null` values.
3. **Cryptographic Custody:** Every run emits `SHA256SUMS.txt` over all generated JSON and Markdown artifacts.
4. **Automated CI Verification:** Every commit runs `cffconvert --validate`, `.zenodo.json` schema checks, `shellcheck`, `bash -n`, and `unittest` integration tests via [`.github/workflows/scientific-release.yml`](../.github/workflows/scientific-release.yml).

---

## 5. Experimental Evaluation Protocol (Baseline vs. Hardened Host)

### 5.1 Execution Commands (Reproducible on Debian 13)

```bash
# 1. Full 6-layer host telemetry + live QCOW2 CoW overlay benchmark
sudo ./scripts/collect_kether_metrics.sh --require-root --test-qcow2-overlay ./benchmarks/run_hardened

# 2. Full 43-control CIS Debian 13 & BeyondCorp audit
sudo ./scripts/audit_cis_43_controls.sh ./benchmarks/cis43_hardened

# 3. Auditd lossless telemetry stress test (10,000 synthetic execve calls)
sudo ./scripts/benchmark_auditd_stress.sh --events 10000

# 4. Verify cryptographic manifest integrity
(cd ./benchmarks/run_hardened && sha256sum -c SHA256SUMS.txt)
```

### 5.2 Comparative Benchmark Matrix *(Template Ready for Debian 13 Host Capture — `v1.1.0` Final)*

> **Transparency Note:** The columns marked *Pending Host Capture* will be populated exclusively with real, SHA-256-verified measurements collected on physical Debian 13 hardware before tagging the final `v1.1.0` Zenodo release (zero synthetic or fabricated numbers).

| Metric | Baseline Debian 13 (Pre-Hardening) | Hardened Kether_1 Host (Post-Hardening) | Target / Acceptance Criterion |
| :--- | :--- | :--- | :--- |
| **Lynis Hardening Index** | *Pending Host Capture* | *Pending Host Capture* | `>= 75` (target `>= 80`) |
| **43-Control CIS/BeyondCorp Pass Rate** | *Pending Host Capture* | *Pending Host Capture* | `>= 90%` (`>= 39/43`) |
| **AppArmor Enforcing Profiles** | *Pending Host Capture* | *Pending Host Capture* | `> 0` + `kether-ai-agent-userns` active |
| **Kernel Lockdown Mode** | *Pending Host Capture* | *Pending Host Capture* | `integrity` |
| **`nftables` Default-Deny (`input`/`forward`/`output`)** | *Pending Host Capture* | *Pending Host Capture* | `true / true / true` |
| **`auditd` Stress Test (`10,000` `execve` burst)** | *Pending Host Capture* | *Pending Host Capture* | `lost_delta == 0`, `backlog_limit >= 8192` |
| **QCOW2 CoW Overlay Provisioning Latency** | N/A | *Pending Host Capture* | `< 50 ms` + `base_integrity_preserved == true` |
| **KVM Sandbox Cold Boot vs. Ephemeral Overlay Boot** | *Pending Host Capture* | *Pending Host Capture* | Reproducible boot with `0` host mutations |

---

## 6. Threats to Validity & Limitations

* **Internal Validity:** Unprivileged execution masks privileged subsystem probes (`aa-status`, `auditctl`, `nft`); mitigated by mandatory `privilege_context` tagging and `--require-root` enforcement.
* **External Validity:** Kernel `lockdown=integrity` requires signed kernel modules; workstations relying on unsigned DKMS drivers (e.g., proprietary GPU modules without MOK enrollment) require signing keys enrolled via `mokutil`.
* **Operational Scope:** Default-deny `output` rules in `nftables` require explicit allowlisting if specialized development protocols beyond ports `22/80/123/443/853` are used.

---

## 7. Data, Code Availability & Licensing

* **Source Repository:** https://github.com/Techdimbr/debian13-hardening-kvm-sandbox
* **Permanent Archive (Zenodo Concept DOI):** https://doi.org/10.5281/zenodo.24380374
* **Software License:** MIT License ([`LICENSE`](../LICENSE))
* **Documentation & Whitepaper License:** Creative Commons Attribution 4.0 International — CC-BY-4.0 ([`LICENSE-DOCS`](../LICENSE-DOCS))

---

## 8. References

1. Center for Internet Security (CIS). *CIS Debian Linux Benchmark (Level 1 & Level 2)*.
2. Ward, R., & Beyer, B. (2014). *BeyondCorp: A New Approach to Enterprise Security*. USENIX ;login:, 39(6), 6–11.
3. Debian Project. *Debian 13 ("Trixie") Release Notes & Linux Kernel 6.12 LTS Security Documentation*.
4. Canonical / AppArmor Project. *AppArmor 4.x Unprivileged User Namespace Restriction (`apparmor_restrict_unprivileged_userns`)*.
5. Linux Audit Project. *Linux Audit Framework (`auditd`, `augenrules`, `auditctl`)*.
6. QEMU / KVM Project. *QCOW2 Backing Files and Copy-on-Write Overlay Disk Images*.
