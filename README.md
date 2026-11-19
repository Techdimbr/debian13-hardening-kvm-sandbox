# Techdim Debian 13 Hardening Framework & Ephemeral KVM Sandbox (`Kether_1`)

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.24380375.svg)](https://doi.org/10.5281/zenodo.24380375)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![CFF 1.2.0](https://img.shields.io/badge/Citation-CFF%201.2.0-green.svg)](CITATION.cff)
[![ORCID](https://img.shields.io/badge/ORCID-0009--0003--3273--7883-A6CE39.svg)](https://orcid.org/0009-0003-3273-7883)

> **Arquitetura reproduzível de segurança Zero Trust (CIS Debian 13 + BeyondCorp) para estações e servidores Linux que executam agentes de IA autônomos sem quebrar `userns`, `eBPF` ou isolamento efêmero KVM/QCOW2.**

**Autor:** Eng. Deivis Irio Mayer (`Kether1`) — [ORCID: 0009-0003-3273-7883](https://orcid.org/0009-0003-3273-7883)  
**Organização:** TECHDIM INOVA SIMPLES (I.S.) - ME — Campinas, SP, Brasil  
**Catálogo Open-Core:** [techdim.github.io](https://techdim.github.io/)

---

## Visão Geral Científica

A execução local de agentes de IA autônomos e ferramentas de desenvolvimento em estações Linux impõe uma tensão arquitetural direta: controles clássicos de hardening (como `lockdown=integrity`, restrições globais de `unprivileged_userns_clone`, bloqueio indiscriminado de BPF e perfis AppArmor legados) frequentemente quebram sandboxes modernas, contêineres *rootless* e hipervisores efêmeros.

Este repositório fornece:
1. **Arquitetura de Hardening Debian 13 ("Trixie", Kernel 6.12 LTS):** alinhada ao CIS Benchmark Level 2 e princípios Zero Trust (`sysctl`, `AppArmor`, `nftables`, `auditd -b 8192`, LUKS2/LVM, `USBGuard`, `AIDE`).
2. **Isolamento por Sandbox KVM Efêmera (QCOW2 copy-on-write):** execução descartável de workloads de agentes com rollback instantâneo.
3. **Coletor Reproduzível de Métricas Experimentais ([`scripts/collect_kether_metrics.sh`](scripts/collect_kether_metrics.sh)):** coleta somente leitura de evidências do host com manifesto criptográfico `SHA-256` para reprodutibilidade científica.
4. **Pipeline Científico Automatizado ([`.github/workflows/scientific-release.yml`](.github/workflows/scientific-release.yml)):** validação contínua de `CITATION.cff`, `.zenodo.json` e scripts Bash + integração pronta para Zenodo (Sandbox e Produção) e ORCID via DataCite.

---

## Estrutura do Repositório

```text
.
├── .github/workflows/
│   └── scientific-release.yml   # CI: validação CFF 1.2.0, .zenodo.json, Bash e upload Zenodo API
├── docs/
│   └── WHITEPAPER_v1.0.0.md     # Nota Técnica / Whitepaper científico pronto para PDF + DOI cruzado
├── scripts/
│   └── collect_kether_metrics.sh # Coletor auditável de métricas Debian 13 + KVM + SHA-256
├── .zenodo.json                 # Metadados oficiais para indexação automática no Zenodo
├── CITATION.cff                 # Metadados de citação padrão CFF 1.2.0 (botão "Cite this repository")
├── LICENSE                      # Licença MIT (SPDX: MIT)
└── README.md
```

---

## Reprodutibilidade Rápida (Debian 13)

Para gerar um relatório experimental verificável em um host Debian 13 (somente leitura, sem alterar configurações do sistema):

```bash
chmod +x scripts/collect_kether_metrics.sh
./scripts/collect_kether_metrics.sh ./benchmarks/run_local
```

Saída gerada:
* `metrics_report.json` — versão Debian/kernel, estado de `lockdown`, `userns`, `bpf`, contagem de perfis AppArmor (`enforce`/`complain`), backlog `auditd`, tabelas `nftables` e presença KVM.
* `SHA256SUMS.txt` — hash criptográfico de integridade da coleta.

---

## Publicação Científica & Citação (Zenodo + ORCID)

1. Adicione seu **ORCID iD** em [`CITATION.cff`](CITATION.cff) (`orcid: "https://orcid.org/0000-000X-XXXX-XXXX"`) e em [`.zenodo.json`](.zenodo.json) (`"orcid": "0000-000X-XXXX-XXXX"`).
2. Ative este repositório em [zenodo.org/account/settings/github/](https://zenodo.org/account/settings/github/).
3. Crie a GitHub Release `v1.0.0` para emissão automática do **Version DOI**, **Concept DOI**, arquivamento no **Software Heritage** e atualização automática no **ORCID** (via DataCite Auto-Update).

### Como Citar

Utilize o botão **"Cite this repository"** na barra lateral do GitHub ou o arquivo [`CITATION.cff`](CITATION.cff).
