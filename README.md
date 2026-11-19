# Techdim Debian 13 Hardening Framework & Ephemeral KVM Sandbox (`Kether_1`)

[![DOI (All Versions)](https://zenodo.org/badge/DOI/10.5281/zenodo.24380374.svg)](https://doi.org/10.5281/zenodo.24380374)
[![License: MIT](https://img.shields.io/badge/Code%20License-MIT-blue.svg)](LICENSE)
[![Docs: CC-BY-4.0](https://img.shields.io/badge/Docs%20License-CC--BY--4.0-lightgrey.svg)](LICENSE-DOCS)
[![CFF 1.2.0](https://img.shields.io/badge/Citation-CFF%201.2.0-green.svg)](CITATION.cff)
[![ORCID](https://img.shields.io/badge/ORCID-0009--0003--3273--7883-A6CE39.svg)](https://orcid.org/0009-0003-3273-7883)

> **Arquitetura reproduzível de segurança Zero Trust (CIS Debian 13 Level 2 + BeyondCorp) e isolamento em Sandbox KVM/QCOW2 Efêmera para estações e servidores Linux que executam agentes de IA autônomos sem quebrar `userns`, `eBPF` ou telemetria forense `auditd`.**

**Autor:** Eng. Deivis Irio Mayer (`Kether1`) — [ORCID: 0009-0003-3273-7883](https://orcid.org/0009-0003-3273-7883)  
**Organização:** TECHDIM INOVA SIMPLES (I.S.) - ME — Campinas, SP, Brasil  
**Concept DOI (todas as versões):** https://doi.org/10.5281/zenodo.24380374  
**Version DOI (`v1.0.1`):** https://doi.org/10.5281/zenodo.24380375  
**Catálogo Open-Core:** [techdim.github.io](https://techdim.github.io/)

---

## Visão Geral Científica

A execução local de agentes de IA autônomos em hosts Linux endurecidos cria uma tensão arquitetural direta entre controles rígidos de segurança e primitivas modernas de sandboxing. O framework **`Kether_1`** entrega artefatos executáveis, configurações determinísticas e instrumentação auditável nas **6 camadas de defesa em profundidade**:

| Camada | Artefatos Executáveis no Repositório |
| :--- | :--- |
| **L1 — Storage & Firmware** | Auditoria LUKS2, LVM, UEFI Secure Boot, TPM 2.0, `/etc/shadow` e `unattended-upgrades` (`K1-01`..`K1-06`) |
| **L2 — Kernel & Sysctl** | [`configs/sysctl/99-kether-hardening.conf`](configs/sysctl/99-kether-hardening.conf) (`lockdown=integrity`, ASLR=2, `kptr_restrict=2`, BPF endurecido, `userns` mediado) |
| **L3 — MAC Confinement** | [`configs/apparmor/kether-ai-agent-userns`](configs/apparmor/kether-ai-agent-userns) (permissão seletiva de `userns` + `deny` explícito de `~/.ssh`, `~/.gnupg`, `/etc/shadow`, `/proc/kcore`) |
| **L4 — Network Zero Trust** | [`configs/nftables/kether-workstation.nft`](configs/nftables/kether-workstation.nft) (`policy drop` em `input`/`forward`/`output` + bloqueio lateral `virbr0 → RFC1918`), [`configs/systemd/resolved-dot.conf`](configs/systemd/resolved-dot.conf) (DoT+DNSSEC), [`configs/ssh/99-kether-sshd.conf`](configs/ssh/99-kether-sshd.conf) |
| **L5 — Telemetry & Integrity** | [`configs/auditd/99-kether.rules`](configs/auditd/99-kether.rules) (`-b 8192` no topo, `-e 2` imutável no final), [`configs/systemd/journald-kether.conf`](configs/systemd/journald-kether.conf), [`scripts/benchmark_auditd_stress.sh`](scripts/benchmark_auditd_stress.sh) |
| **L6 — Ephemeral KVM Sandbox** | [`scripts/kvm_ephemeral_sandbox.sh`](scripts/kvm_ephemeral_sandbox.sh) (overlays QCOW2 Copy-on-Write descartáveis sobre imagem golden `chmod a-w` + verificação `SHA-256`) |

---

## Estrutura do Repositório

```text
.
├── .github/workflows/
│   └── scientific-release.yml      # CI: cffconvert, .zenodo.json, shellcheck, unittest e API Zenodo
├── configs/
│   ├── apparmor/kether-ai-agent-userns
│   ├── auditd/99-kether.rules
│   ├── nftables/kether-workstation.nft
│   ├── ssh/99-kether-sshd.conf
│   ├── sysctl/99-kether-hardening.conf
│   └── systemd/{resolved-dot.conf,journald-kether.conf}
├── docs/
│   ├── WHITEPAPER.md               # Nota Técnica / Artigo (Threat Model, Metodologia, Benchmarks)
│   └── PEER_REVIEW_RESPONSE_v1.0.1.md # Resposta formal à revisão por pares do Zenodo v1.0.1
├── scripts/
│   ├── collect_kether_metrics.sh   # Coletor endurecido das 6 camadas (JSON tipado + privilege_context)
│   ├── audit_cis_43_controls.sh    # Auditor dos 43 controles CIS Debian 13 + BeyondCorp
│   ├── kvm_ephemeral_sandbox.sh    # Orquestrador KVM/QCOW2 efêmero (--dry-run, create, destroy, benchmark)
│   └── benchmark_auditd_stress.sh  # Teste de estresse auditd verificando lost_delta == 0
├── tests/
│   └── test_framework.py           # Suíte automatizada de testes estruturais e funcionais
├── .zenodo.json
├── CHANGELOG.md
├── CITATION.cff
├── LICENSE                         # MIT (código, scripts e configurações)
└── LICENSE-DOCS                    # CC-BY-4.0 (Whitepaper e documentação)
```

---

## Reprodutibilidade Rápida (Debian 13)

```bash
# 1. Coleta das 6 camadas + teste funcional de overlay QCOW2 (JSON tipado + Markdown + SHA-256)
sudo ./scripts/collect_kether_metrics.sh --require-root --test-qcow2-overlay ./benchmarks/run_local

# 2. Auditoria dos 43 controles CIS Debian 13 + BeyondCorp Zero Trust
sudo ./scripts/audit_cis_43_controls.sh ./benchmarks/cis43_local

# 3. Teste de estresse auditd (valida lost_delta == 0 e backlog_limit >= 8192)
sudo ./scripts/benchmark_auditd_stress.sh --events 10000

# 4. Dry-run determinístico do ciclo de vida da Sandbox KVM Efêmera
./scripts/kvm_ephemeral_sandbox.sh create --base /var/lib/libvirt/images/debian13-golden.qcow2 --dry-run

# 5. Executar a suíte de testes local (sem privilégios de root)
python3 -m unittest discover -s tests -v
```

---

## Licenciamento e Citação

* **Código, scripts e configurações:** [MIT License](LICENSE) (`SPDX: MIT`).
* **Nota Técnica (`docs/WHITEPAPER.md`) e documentação:** [CC-BY-4.0](LICENSE-DOCS).
* **Como citar:** Utilize o botão **"Cite this repository"** do GitHub ([`CITATION.cff`](CITATION.cff)) ou cite o Concept DOI persistente `https://doi.org/10.5281/zenodo.24380374`.
