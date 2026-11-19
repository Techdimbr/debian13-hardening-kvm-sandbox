# Zero Trust Hardening and Ephemeral KVM Sandboxing on Debian 13 for Autonomous AI Agents (`Kether_1` Technical Note v1.0.0)

**Author:** Eng. Deivis Irio Mayer (`Kether1`) — ORCID: [0009-0003-3273-7883](https://orcid.org/0009-0003-3273-7883)  
**Affiliation:** TECHDIM INOVA SIMPLES (I.S.) - ME, Campinas — SP, Brazil  
**Repository:** https://github.com/Techdimbr/debian13-hardening-kvm-sandbox  
**License:** MIT (Software) / CC-BY-4.0 (Technical Note)

---

## Abstract

Autonomous AI coding and operations agents require local execution privileges (ephemeral sandboxes, unprivileged user namespaces, eBPF observability, and virtualized runtime isolation) that frequently conflict with strict enterprise Linux hardening baselines. This Technical Note presents the **Kether_1 Debian 13 Hardening Framework & Ephemeral KVM Sandbox**, a reproducible architecture combining CIS Debian 13 Level 2 controls and BeyondCorp Zero Trust principles (`lockdown=integrity`, AppArmor confinement compatible with `userns`, `auditd -b 8192`, `nftables`, LUKS2/LVM full-disk encryption, and copy-on-write QCOW2 KVM sandboxes). We document the conflict-resolution design, provide an auditable read-only telemetry collector (`collect_kether_metrics.sh`), and establish a FAIR-compliant software/paper dual-DOI publication pipeline.

---

## 1. Problem Statement

Conventional Linux workstation hardening baselines assume static user workloads. When autonomous AI agents execute build toolchains, browsers, containers, or untrusted code on a hardened host, three recurring failure modes emerge:
1. **Namespace & Sandbox Breakage:** Blanket disabling of `kernel.unprivileged_userns_clone` or overly broad AppArmor restrictions breaks rootless containers and agent sandboxes.
2. **Observability Blind Spots:** Default `auditd` buffer limits drop syscall telemetry during high-frequency agent tool invocations.
3. **Persistent State Contamination:** Running autonomous workflows directly on the host filesystem risks credential exfiltration or silent drift.

---

## 2. Reference Architecture (`Kether_1` Defense-in-Depth)

| Layer | Control / Mechanism | Objective |
| :--- | :--- | :--- |
| **Storage & Firmware** | LUKS2 + LVM + Firmware Audit | Data-at-rest confidentiality & supply-chain integrity |
| **Kernel** | Debian 13 (6.12 LTS), `lockdown=integrity`, hardened `sysctl` | Prevent runtime kernel tampering while preserving signed modules |
| **MAC Confinement** | AppArmor profiles (`enforce` + selective `userns` allowance) | Process-level least privilege without breaking rootless sandboxes |
| **Network** | `nftables` default-deny egress/ingress + DoT (`systemd-resolved`) | Lateral movement containment and encrypted DNS |
| **Telemetry** | `auditd` (`-b 8192`) + `journald` retention caps + `AIDE` | Lossless forensic logging and file-integrity baseline |
| **Agent Execution** | Ephemeral KVM/QEMU with QCOW2 backing overlays | Hardware-assisted VM boundary with instant post-task reset |

---

## 3. Experimental Reproducibility Protocol (v1.0.0 → v1.1.0)

To verify compliance and collect empirical metrics on any Debian 13 host:

```bash
./scripts/collect_kether_metrics.sh ./benchmarks/run_01
```

Metrics captured in `metrics_report.json` (with `SHA256SUMS.txt`):
* Debian version and kernel release (`6.12.x`)
* Kernel lockdown mode (`/sys/kernel/security/lockdown`)
* `sysctl` values for `unprivileged_userns_clone` and `unprivileged_bpf_disabled`
* AppArmor profile counts (`enforce` vs. `complain`)
* Active `auditd` backlog limit and `nftables` table count
* KVM hardware virtualization device availability (`/dev/kvm`)

*Note: Experimental benchmark tables (KVM cold/overlay boot latency, Lynis hardening index before/after, and CIS 43-control pass rate) will be appended in release `v1.1.0`.*

---

## 4. Data & Code Availability

All scripts, metadata schemas (`CITATION.cff`, `.zenodo.json`), and CI validation workflows are openly archived on GitHub at https://github.com/Techdimbr/debian13-hardening-kvm-sandbox and preserved via Zenodo/Software Heritage.
