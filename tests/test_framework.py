"""Automated verification suite for the Kether_1 Debian 13 Hardening Framework.

Validates:
  1. Hardened metrics collector (typed JSON, explicit privilege_context, SHA-256).
  2. 43-control CIS/BeyondCorp auditor (exact 43 controls across 6 layers).
  3. Ephemeral KVM/QCOW2 sandbox orchestrator (--dry-run lifecycle checks).
  4. Auditd stress benchmark (--dry-run JSON output).
  5. Deployable 6-layer hardening configs (sysctl, AppArmor userns, nftables
     policy drop, auditd -b 8192 before -e 2 finalization, DoT, journald, SSH).
  6. Scientific metadata harmonization (CITATION.cff, .zenodo.json, dual licenses).
"""

import hashlib
import json
import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


class TestKetherHardeningFramework(unittest.TestCase):
    def test_metrics_collector_typed_json_and_sha256(self):
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "run_test"
            proc = subprocess.run(
                [str(ROOT / "scripts/collect_kether_metrics.sh"), str(out_dir)],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, msg=proc.stderr)

            report_path = out_dir / "metrics_report.json"
            summary_path = out_dir / "metrics_summary.md"
            sums_path = out_dir / "SHA256SUMS.txt"

            self.assertTrue(report_path.is_file())
            self.assertTrue(summary_path.is_file())
            self.assertTrue(sums_path.is_file())

            data = json.loads(report_path.read_text(encoding="utf-8"))
            self.assertEqual(data["schema_version"], "1.1.0")
            self.assertEqual(data["concept_doi"], "10.5281/zenodo.24380374")

            ctx = data["execution_context"]
            self.assertIn(ctx["privilege_context"], ("root", "unprivileged"))
            self.assertIsInstance(ctx["euid"], int)
            self.assertEqual(ctx["euid"], os.geteuid())

            layers = data["layers"]
            expected_layers = {
                "layer_1_storage_firmware",
                "layer_2_kernel_sysctl",
                "layer_3_mac_apparmor",
                "layer_4_network_nftables_dot",
                "layer_5_telemetry_integrity",
                "layer_6_ephemeral_kvm_sandbox",
            }
            self.assertEqual(set(layers.keys()), expected_layers)

            # Verify strict native typing (never stringified ints or bools)
            l3_aa = layers["layer_3_mac_apparmor"]["aa_status"]
            for key in ("profiles_enforce", "profiles_complain", "profiles_total"):
                self.assertTrue(l3_aa[key] is None or isinstance(l3_aa[key], int), f"{key} must be int or None")

            l4_nft = layers["layer_4_network_nftables_dot"]["nftables"]
            self.assertTrue(l4_nft["table_count"] is None or isinstance(l4_nft["table_count"], int))
            self.assertTrue(l4_nft["input_policy_drop"] is None or isinstance(l4_nft["input_policy_drop"], bool))

            l5_aud = layers["layer_5_telemetry_integrity"]["auditd_status"]
            for key in ("backlog_limit", "lost_events", "rules_loaded"):
                self.assertTrue(l5_aud[key] is None or isinstance(l5_aud[key], int), f"{key} must be int or None")

            l6 = layers["layer_6_ephemeral_kvm_sandbox"]
            self.assertIsInstance(l6["kvm_device_present"], bool)
            self.assertIsInstance(l6["cpu_virt_extensions_count"], int)

            # Verify cryptographic SHA-256 manifest matches exact file contents
            for line in sums_path.read_text(encoding="utf-8").strip().splitlines():
                expected_hash, fname = line.split()
                actual_hash = hashlib.sha256((out_dir / fname).read_bytes()).hexdigest()
                self.assertEqual(actual_hash, expected_hash)

    def test_metrics_collector_require_root_guard(self):
        if os.geteuid() == 0:
            self.skipTest("Running as root; unprivileged --require-root guard not triggered.")
        with tempfile.TemporaryDirectory() as tmp:
            proc = subprocess.run(
                [str(ROOT / "scripts/collect_kether_metrics.sh"), "--require-root", tmp],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("--require-root", proc.stderr)

    def test_cis_43_controls_auditor(self):
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "cis43"
            proc = subprocess.run(
                [str(ROOT / "scripts/audit_cis_43_controls.sh"), str(out_dir)],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, msg=proc.stderr)
            audit = json.loads((out_dir / "cis_43_audit.json").read_text(encoding="utf-8"))
            self.assertEqual(audit["total_controls"], 43)
            self.assertEqual(len(audit["controls"]), 43)
            ids = [c["id"] for c in audit["controls"]]
            self.assertEqual(len(set(ids)), 43, "Control IDs must be unique")
            layers = {c["layer"] for c in audit["controls"]}
            self.assertEqual(len(layers), 6, "All 6 layers must be represented")

    def test_kvm_ephemeral_sandbox_dry_run(self):
        script = str(ROOT / "scripts/kvm_ephemeral_sandbox.sh")
        c_proc = subprocess.run(
            [script, "create", "--base", "/tmp/debian13-golden.qcow2", "--name", "kether-sbx-ci", "--dry-run"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(c_proc.returncode, 0, msg=c_proc.stderr)
        self.assertIn("qemu-img create -f qcow2 -F qcow2 -b", c_proc.stdout)
        self.assertIn("chmod a-w", c_proc.stdout)
        self.assertIn("--transient", c_proc.stdout)

        b_proc = subprocess.run([script, "benchmark", "--dry-run"], capture_output=True, text=True, check=False)
        self.assertEqual(b_proc.returncode, 0, msg=b_proc.stderr)
        bench = json.loads(b_proc.stdout)
        self.assertEqual(bench["mode"], "dry_run")

    def test_auditd_stress_benchmark_dry_run(self):
        proc = subprocess.run(
            [str(ROOT / "scripts/benchmark_auditd_stress.sh"), "--events", "500", "--dry-run"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, msg=proc.stderr)
        res = json.loads(proc.stdout)
        self.assertEqual(res["synthetic_execve_events"], 500)

    def test_hardening_configs_structural_invariants(self):
        # 1. sysctl baseline
        sysctl_txt = (ROOT / "configs/sysctl/99-kether-hardening.conf").read_text(encoding="utf-8")
        for expected in (
            "kernel.randomize_va_space = 2",
            "kernel.kptr_restrict = 2",
            "kernel.unprivileged_bpf_disabled = 1",
            "net.core.bpf_jit_harden = 2",
            "kernel.unprivileged_userns_clone = 1",
        ):
            self.assertIn(expected, sysctl_txt)

        # 2. AppArmor selective userns profile
        aa_txt = (ROOT / "configs/apparmor/kether-ai-agent-userns").read_text(encoding="utf-8")
        self.assertIn("userns,", aa_txt)
        self.assertIn("deny @{HOME}/.ssh/** rwx,", aa_txt)
        self.assertIn("deny /etc/shadow rwx,", aa_txt)

        # 3. nftables default-deny on input, forward, output + KVM RFC1918 lateral drop
        nft_txt = (ROOT / "configs/nftables/kether-workstation.nft").read_text(encoding="utf-8")
        self.assertRegex(nft_txt, r"hook\s+input\b[^;]*;\s*policy\s+drop\s*;")
        self.assertRegex(nft_txt, r"hook\s+forward\b[^;]*;\s*policy\s+drop\s*;")
        self.assertRegex(nft_txt, r"hook\s+output\b[^;]*;\s*policy\s+drop\s*;")
        self.assertIn("192.168.0.0/16", nft_txt)

        # 4. auditd: -b 8192 MUST precede rules, and -e 2 MUST be the final non-comment directive
        audit_lines = [
            ln.strip()
            for ln in (ROOT / "configs/auditd/99-kether.rules").read_text(encoding="utf-8").splitlines()
            if ln.strip() and not ln.strip().startswith("#")
        ]
        self.assertIn("-b 8192", audit_lines[:3], "-b 8192 must be declared at the top of 99-kether.rules")
        self.assertEqual(audit_lines[-1], "-e 2", "-e 2 immutable lock MUST be the final rule")

        # 5. DNS-over-TLS + Journald + OpenSSH
        resolved_txt = (ROOT / "configs/systemd/resolved-dot.conf").read_text(encoding="utf-8")
        self.assertIn("DNSOverTLS=yes", resolved_txt)
        self.assertIn("DNSSEC=yes", resolved_txt)
        sshd_txt = (ROOT / "configs/ssh/99-kether-sshd.conf").read_text(encoding="utf-8")
        self.assertIn("PermitRootLogin no", sshd_txt)
        self.assertIn("PasswordAuthentication no", sshd_txt)

    def test_scientific_metadata_and_licensing_harmonization(self):
        self.assertTrue((ROOT / "LICENSE").is_file())
        self.assertTrue((ROOT / "LICENSE-DOCS").is_file())
        self.assertTrue((ROOT / "docs/WHITEPAPER.md").is_file())
        self.assertFalse((ROOT / "docs/WHITEPAPER_v1.0.0.md").exists(), "Version-locked filename should be removed")

        z = json.loads((ROOT / ".zenodo.json").read_text(encoding="utf-8"))
        self.assertEqual(z["upload_type"], "software")
        self.assertEqual(z["creators"][0]["orcid"], "0009-0003-3273-7883")

        cff = (ROOT / "CITATION.cff").read_text(encoding="utf-8")
        self.assertIn("https://orcid.org/0009-0003-3273-7883", cff)
        self.assertIn("10.5281/zenodo.24380374", cff)
        self.assertNotRegex(cff, r"^\s+name:\s+", "Person entry in CFF 1.2.0 must not mix 'name:' with family-names")

    def test_google_scholar_pdf_and_metadata_compliance(self):
        pdf_path = ROOT / "docs/paper/Kether1_Debian13_Hardening_Ephemeral_KVM_Sandbox_2026.pdf"
        self.assertTrue(pdf_path.is_file(), "Compiled academic PDF must exist")
        pdf_bytes = pdf_path.read_bytes()
        self.assertTrue(pdf_bytes.startswith(b"%PDF-"), "PDF header invalid")
        self.assertLess(len(pdf_bytes), 5 * 1024 * 1024, "PDF must stay under Google Scholar 5 MB limit")

        html = (ROOT / "docs/paper/index.html").read_text(encoding="utf-8")
        for required_tag in (
            'name="citation_title"',
            'name="citation_author" content="Mayer, Deivis Irio"',
            'name="citation_publication_date" content="2026/11/19"',
            'name="citation_technical_report_institution"',
            'name="citation_doi" content="10.5281/zenodo.24380374"',
            'name="citation_pdf_url" content="https://techdimbr.github.io/debian13-hardening-kvm-sandbox/paper/Kether1_Debian13_Hardening_Ephemeral_KVM_Sandbox_2026.pdf"',
            'name="DC.title"',
            '"@type": "ScholarlyArticle"',
            "Ik00pFwAAAAJ",
        ):
            self.assertIn(required_tag, html, f"Missing required Google Scholar tag: {required_tag}")

        bib = (ROOT / "docs/paper/citation.bib").read_text(encoding="utf-8")
        self.assertIn("10.5281/zenodo.24380374", bib)
        self.assertIn("Mayer, Deivis Irio", bib)

        robots = (ROOT / "docs/robots.txt").read_text(encoding="utf-8")
        self.assertIn("Allow: /", robots)
        self.assertNotIn("Disallow: /paper", robots)


if __name__ == "__main__":
    unittest.main()
