import copy
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from trustai.chain import EvidenceChain
from trustai.contracts import load_contract, register_contract
from trustai.gate import append_eval_and_gate
from trustai.proofpack import compile_proof_pack
from trustai.runtime import append_runtime_attestation, load_action
from trustai.shadow import (
    append_shadow_replay,
    append_soak_report,
    load_shadow_replay,
    load_soak_window,
    shadow_replay_to_eval_results,
)
from trustai.go_verifier_build import (
    GO_VERIFIER_BUILD_ENTRY_TYPE,
    GO_VERIFIER_BUILD_SCHEMA,
    GO_VERIFIER_BINARY_SIGNATURE_SCHEMA,
    append_go_verifier_build_attestation,
    build_go_verifier_build_attestation,
    build_go_verifier_binary_signature_artifact,
    verify_go_verifier_build_attestation,
    write_go_verifier_build_attestation,
    write_go_verifier_binary_signature_artifact,
)
from trustai.standards import build_standards_submission, write_standards_markdown, write_standards_submission
from trustai.verifier_conformance import build_verifier_conformance_report, write_verifier_conformance_report
from trustai.verifier_release import build_verifier_release_manifest, write_verifier_release_manifest


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "examples" / "aitrade" / "verification-contract.yaml"
ACTION = ROOT / "examples" / "aitrade" / "runtime-action.json"
SHADOW = ROOT / "examples" / "aitrade" / "shadow-replay.json"
SOAK = ROOT / "examples" / "aitrade" / "soak-window.json"


def _sha256_ref(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


class GoVerifierBuildTests(unittest.TestCase):
    def _proof_pack(self, tmp: Path):
        chain = EvidenceChain.load(tmp / "chain.json", tenant_id="go-verifier-build-test")
        contract = load_contract(CONTRACT)
        register_contract(chain, contract)
        append_runtime_attestation(chain, contract, load_action(ACTION))
        shadow = load_shadow_replay(SHADOW)
        append_shadow_replay(chain, contract, shadow)
        append_soak_report(chain, contract, load_soak_window(SOAK))
        eval_entry, gate_entry, decision = append_eval_and_gate(
            chain,
            contract,
            shadow_replay_to_eval_results(contract, shadow),
        )
        return compile_proof_pack(chain, contract, eval_entry, gate_entry, decision, out_path=tmp / "pack.json")

    def _inputs(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            pack = self._proof_pack(Path(tmp_dir))
            conformance = build_verifier_conformance_report(pack)
        standards = build_standards_submission(ROOT)
        release = build_verifier_release_manifest(
            ROOT,
            conformance_report=conformance,
            standards_package=standards,
        )
        return conformance, standards, release

    def _attestation(self, release, conformance, standards, **overrides):
        values = {
            "verifier_release": release,
            "root": ROOT,
            "conformance_report": conformance,
            "standards_package": standards,
            "mode": "source-plan",
            "builder_ref": "builder:trustai/go-verifier/local",
            "toolchain_ref": "go:download-required",
            "toolchain_version": "not-installed-local-reference",
            "goos": "linux",
            "goarch": "amd64",
            "cgo_enabled": False,
            "trimpath": True,
            "ldflags": "-s -w",
            "build_started_at": "2026-07-16T00:00:00Z",
            "build_finished_at": "2026-07-16T00:01:00Z",
            "attested_at": "2026-07-16T00:02:00Z",
        }
        values.update(overrides)
        return build_go_verifier_build_attestation(**values)

    def _write_binary_signature(self, release, conformance, standards, binary_path, build_log_path, sbom_path, provenance_path, signature_path):
        artifact = build_go_verifier_binary_signature_artifact(
            release,
            root=ROOT,
            conformance_report=conformance,
            standards_package=standards,
            binary_path=binary_path,
            build_log_ref=build_log_path,
            sbom_ref=sbom_path,
            provenance_ref=provenance_path,
            generated_at="2026-07-16T00:01:30Z",
        )
        write_go_verifier_binary_signature_artifact(signature_path, artifact)
        return artifact

    def test_go_verifier_build_attestation_verifies_and_appends_source_plan(self):
        conformance, standards, release = self._inputs()
        attestation = self._attestation(release, conformance, standards)

        result = verify_go_verifier_build_attestation(
            attestation,
            release,
            root=ROOT,
            conformance_report=conformance,
            standards_package=standards,
        )
        with tempfile.TemporaryDirectory() as tmp_dir:
            chain = EvidenceChain.load(Path(tmp_dir) / "chain.json", tenant_id="go-verifier-build-local")
            entry = append_go_verifier_build_attestation(
                chain,
                attestation,
                release,
                root=ROOT,
                conformance_report=conformance,
                standards_package=standards,
            )

        self.assertTrue(result.ok, result.errors)
        self.assertEqual(GO_VERIFIER_BUILD_SCHEMA, attestation["schema"])
        self.assertEqual("source-plan", attestation["build"]["mode"])
        self.assertEqual("not-built", attestation["binary"]["status"])
        self.assertEqual(release["release_id"], attestation["source"]["release_id"])
        self.assertIn("verifier/go/trustai-verify/main.go", {item["path"] for item in attestation["go_sources"]})
        self.assertEqual(GO_VERIFIER_BUILD_ENTRY_TYPE, entry["entry_type"])
        self.assertEqual(attestation["build_id"], entry["payload"]["build_id"])

    def test_go_verifier_build_attestation_verifies_and_appends_binary_attested(self):
        conformance, standards, release = self._inputs()
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            binary_path = tmp / "trustai-verify-linux-amd64"
            build_log_path = tmp / "trustai-verify-linux-amd64.build.log"
            sbom_path = tmp / "trustai-verify-linux-amd64.sbom.json"
            provenance_path = tmp / "trustai-verify-linux-amd64.provenance.json"
            signature_path = tmp / "trustai-verify-linux-amd64.sig"
            binary_path.write_bytes(b"trustai verifier static binary fixture\n")
            build_log_path.write_text("CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags \"-s -w\"\n", encoding="utf-8")
            sbom_path.write_text(json.dumps({"schema": "trustai.go-verifier-ci-sbom/0.1", "artifact": binary_path.name}, sort_keys=True), encoding="utf-8")
            provenance_path.write_text(json.dumps({"schema": "trustai.go-verifier-ci-provenance/0.1", "artifact": binary_path.name}, sort_keys=True), encoding="utf-8")
            signature_artifact = self._write_binary_signature(release, conformance, standards, binary_path, build_log_path, sbom_path, provenance_path, signature_path)

            attestation = self._attestation(
                release,
                conformance,
                standards,
                binary_path=binary_path,
                mode="binary-attested",
                toolchain_ref="go:github-actions/setup-go",
                toolchain_version="1.23.0",
                build_command='CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o dist/trustai-verify-linux-amd64 ./verifier/go/trustai-verify',
                build_log_ref=str(build_log_path),
                build_log_hash=_sha256_ref(build_log_path),
                sbom_ref=str(sbom_path),
                sbom_hash=_sha256_ref(sbom_path),
                provenance_ref=str(provenance_path),
                provenance_hash=_sha256_ref(provenance_path),
                signature_ref=str(signature_path),
                signature_hash=_sha256_ref(signature_path),
            )

            result = verify_go_verifier_build_attestation(
                attestation,
                release,
                root=ROOT,
                conformance_report=conformance,
                standards_package=standards,
                binary_path=binary_path,
            )
            chain = EvidenceChain.load(tmp / "chain.json", tenant_id="go-verifier-build-local")
            entry = append_go_verifier_build_attestation(
                chain,
                attestation,
                release,
                root=ROOT,
                conformance_report=conformance,
                standards_package=standards,
                binary_path=binary_path,
            )

        control_status = {control["id"]: control["status"] for control in attestation["controls"]}
        self.assertTrue(result.ok, result.errors)
        self.assertEqual("binary-attested", attestation["build"]["mode"])
        self.assertEqual("available", attestation["binary"]["status"])
        self.assertEqual(hashlib.sha256(b"trustai verifier static binary fixture\n").hexdigest(), attestation["binary"]["sha256"])
        self.assertEqual("attested", control_status["go-verifier-binary-hash"])
        self.assertEqual("attested", control_status["go-verifier-supply-chain-provenance"])
        self.assertTrue(attestation["binary_signature"]["verified"])
        self.assertEqual(GO_VERIFIER_BINARY_SIGNATURE_SCHEMA, signature_artifact["schema"])
        self.assertEqual(GO_VERIFIER_BUILD_ENTRY_TYPE, entry["entry_type"])
        self.assertEqual("available", entry["payload"]["binary"]["status"])

    def test_go_verifier_build_detects_release_source_mismatch(self):
        conformance, standards, release = self._inputs()
        attestation = self._attestation(release, conformance, standards)
        tampered = copy.deepcopy(release)
        tampered["source_files"][-1]["sha256"] = "0" * 64

        result = verify_go_verifier_build_attestation(
            attestation,
            tampered,
            root=ROOT,
            conformance_report=conformance,
            standards_package=standards,
        )

        self.assertFalse(result.ok)
        self.assertTrue(any("verifier release source" in error for error in result.errors))
        self.assertTrue(any("go_sources do not match" in error or "go_source_hash" in error for error in result.errors))

    def test_go_verifier_build_detects_binary_tamper(self):
        conformance, standards, release = self._inputs()
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            binary_path = tmp / "trustai-verify-linux-amd64"
            build_log_path = tmp / "build.log"
            sbom_path = tmp / "sbom.json"
            provenance_path = tmp / "provenance.json"
            signature_path = tmp / "signature.sig"
            binary_path.write_bytes(b"trustai verifier binary before tamper\n")
            build_log_path.write_text("build ok\n", encoding="utf-8")
            sbom_path.write_text("sbom\n", encoding="utf-8")
            provenance_path.write_text("provenance\n", encoding="utf-8")
            self._write_binary_signature(release, conformance, standards, binary_path, build_log_path, sbom_path, provenance_path, signature_path)
            attestation = self._attestation(
                release,
                conformance,
                standards,
                binary_path=binary_path,
                mode="binary-attested",
                build_log_ref=str(build_log_path),
                build_log_hash=_sha256_ref(build_log_path),
                sbom_ref=str(sbom_path),
                sbom_hash=_sha256_ref(sbom_path),
                provenance_ref=str(provenance_path),
                provenance_hash=_sha256_ref(provenance_path),
                signature_ref=str(signature_path),
                signature_hash=_sha256_ref(signature_path),
            )
            binary_path.write_bytes(b"trustai verifier binary after tamper\n")

            result = verify_go_verifier_build_attestation(
                attestation,
                release,
                root=ROOT,
                conformance_report=conformance,
                standards_package=standards,
                binary_path=binary_path,
            )

        self.assertFalse(result.ok)
        self.assertIn("Go verifier build binary.sha256 does not match supplied binary", result.errors)

    def test_go_verifier_build_detects_sidecar_tamper(self):
        conformance, standards, release = self._inputs()
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            binary_path = tmp / "trustai-verify-linux-amd64"
            build_log_path = tmp / "build.log"
            sbom_path = tmp / "sbom.json"
            provenance_path = tmp / "provenance.json"
            signature_path = tmp / "signature.sig"
            binary_path.write_bytes(b"trustai verifier binary\n")
            build_log_path.write_text("build ok\n", encoding="utf-8")
            sbom_path.write_text("sbom before tamper\n", encoding="utf-8")
            provenance_path.write_text("provenance\n", encoding="utf-8")
            self._write_binary_signature(release, conformance, standards, binary_path, build_log_path, sbom_path, provenance_path, signature_path)
            attestation = self._attestation(
                release,
                conformance,
                standards,
                binary_path=binary_path,
                mode="binary-attested",
                build_log_ref=str(build_log_path),
                build_log_hash=_sha256_ref(build_log_path),
                sbom_ref=str(sbom_path),
                sbom_hash=_sha256_ref(sbom_path),
                provenance_ref=str(provenance_path),
                provenance_hash=_sha256_ref(provenance_path),
                signature_ref=str(signature_path),
                signature_hash=_sha256_ref(signature_path),
            )
            sbom_path.write_text("sbom after tamper\n", encoding="utf-8")

            result = verify_go_verifier_build_attestation(
                attestation,
                release,
                root=ROOT,
                conformance_report=conformance,
                standards_package=standards,
                binary_path=binary_path,
            )

        self.assertFalse(result.ok)
        self.assertIn("Go verifier build provenance.sbom_hash does not match local source " + str(sbom_path), result.errors)

    def test_go_verifier_build_rejects_unstructured_binary_signature(self):
        conformance, standards, release = self._inputs()
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            binary_path = tmp / "trustai-verify-linux-amd64"
            build_log_path = tmp / "build.log"
            sbom_path = tmp / "sbom.json"
            provenance_path = tmp / "provenance.json"
            signature_path = tmp / "signature.sig"
            binary_path.write_bytes(b"trustai verifier binary\n")
            build_log_path.write_text("build ok\n", encoding="utf-8")
            sbom_path.write_text("sbom\n", encoding="utf-8")
            provenance_path.write_text("provenance\n", encoding="utf-8")
            signature_path.write_text("unstructured signature\n", encoding="utf-8")
            attestation = self._attestation(
                release,
                conformance,
                standards,
                binary_path=binary_path,
                mode="binary-attested",
                build_log_ref=str(build_log_path),
                build_log_hash=_sha256_ref(build_log_path),
                sbom_ref=str(sbom_path),
                sbom_hash=_sha256_ref(sbom_path),
                provenance_ref=str(provenance_path),
                provenance_hash=_sha256_ref(provenance_path),
                signature_ref=str(signature_path),
                signature_hash=_sha256_ref(signature_path),
            )

            result = verify_go_verifier_build_attestation(
                attestation,
                release,
                root=ROOT,
                conformance_report=conformance,
                standards_package=standards,
                binary_path=binary_path,
            )

        self.assertFalse(result.ok)
        self.assertFalse(attestation["binary_signature"]["verified"])
        self.assertTrue(any("Go verifier binary signature" in error for error in result.errors))

    def test_go_verifier_build_rejects_cgo_enabled(self):
        conformance, standards, release = self._inputs()
        attestation = self._attestation(release, conformance, standards, cgo_enabled=True)

        result = verify_go_verifier_build_attestation(
            attestation,
            release,
            root=ROOT,
            conformance_report=conformance,
            standards_package=standards,
        )

        self.assertFalse(result.ok)
        self.assertIn("Go verifier build must set cgo_enabled=false for static verifier releases", result.errors)

    def test_go_verifier_build_requires_binary_for_binary_attested_mode(self):
        conformance, standards, release = self._inputs()

        with self.assertRaisesRegex(ValueError, "binary_path is required"):
            self._attestation(release, conformance, standards, mode="binary-attested")

    def test_cli_go_verifier_build_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            conformance, standards, release = self._inputs()
            conformance_path = tmp / "verifier-conformance.json"
            standards_path = tmp / "standards-submission.json"
            standards_md_path = tmp / "standards-submission.md"
            release_path = tmp / "verifier-release.json"
            attestation_path = tmp / "go-verifier-build.json"
            entry_path = tmp / "go-verifier-build-entry.json"
            state_path = tmp / "go-verifier-build-chain.json"
            write_verifier_conformance_report(conformance_path, conformance)
            write_standards_submission(standards_path, standards)
            write_standards_markdown(standards_md_path, standards)
            write_verifier_release_manifest(release_path, release)

            env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
            source_args = [
                str(release_path),
                "--conformance-report", str(conformance_path),
                "--standards-package", str(standards_path),
                "--root", str(ROOT),
            ]
            build_args = [
                "--mode", "source-plan",
                "--builder-ref", "builder:trustai/go-verifier/local",
                "--toolchain-ref", "go:download-required",
                "--toolchain-version", "not-installed-local-reference",
                "--goos", "linux",
                "--goarch", "amd64",
                "--build-started-at", "2026-07-16T00:00:00Z",
                "--build-finished-at", "2026-07-16T00:01:00Z",
                "--attested-at", "2026-07-16T00:02:00Z",
            ]
            subprocess.run(
                [sys.executable, "-m", "trustai", "go-verifier-build-attestation", *source_args, *build_args, "--out", str(attestation_path)],
                cwd=ROOT,
                env=env,
                check=True,
            )
            subprocess.run(
                [sys.executable, "-m", "trustai", "go-verifier-build-verify", str(attestation_path), *source_args],
                cwd=ROOT,
                env=env,
                check=True,
            )
            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "go-verifier-build-append",
                    str(attestation_path),
                    *source_args,
                    "--state", str(state_path),
                    "--tenant", "go-verifier-build-local",
                    "--out", str(entry_path),
                ],
                cwd=ROOT,
                env=env,
                check=True,
            )

            self.assertTrue(attestation_path.exists())
            self.assertTrue(entry_path.exists())

    def test_cli_go_verifier_build_binary_attested_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            conformance, standards, release = self._inputs()
            conformance_path = tmp / "verifier-conformance.json"
            standards_path = tmp / "standards-submission.json"
            release_path = tmp / "verifier-release.json"
            binary_path = tmp / "trustai-verify-linux-amd64"
            build_log_path = tmp / "trustai-verify-linux-amd64.build.log"
            sbom_path = tmp / "trustai-verify-linux-amd64.sbom.json"
            provenance_path = tmp / "trustai-verify-linux-amd64.provenance.json"
            signature_path = tmp / "trustai-verify-linux-amd64.sig"
            attestation_path = tmp / "go-verifier-build.json"
            entry_path = tmp / "go-verifier-build-entry.json"
            state_path = tmp / "go-verifier-build-chain.json"
            write_verifier_conformance_report(conformance_path, conformance)
            write_standards_submission(standards_path, standards)
            write_verifier_release_manifest(release_path, release)
            binary_path.write_bytes(b"trustai verifier static binary fixture for cli\n")
            build_log_path.write_text("CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath\n", encoding="utf-8")
            sbom_path.write_text("sbom fixture\n", encoding="utf-8")
            provenance_path.write_text("provenance fixture\n", encoding="utf-8")

            env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
            source_args = [
                str(release_path),
                "--conformance-report", str(conformance_path),
                "--standards-package", str(standards_path),
                "--root", str(ROOT),
                "--binary", str(binary_path),
            ]
            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "trustai",
                    "go-verifier-binary-signature",
                    *source_args,
                    "--build-log-ref", str(build_log_path),
                    "--sbom-ref", str(sbom_path),
                    "--provenance-ref", str(provenance_path),
                    "--out", str(signature_path),
                ],
                cwd=ROOT,
                env=env,
                check=True,
            )
            build_args = [
                "--mode", "binary-attested",
                "--builder-ref", "builder:github-actions/go-verifier",
                "--toolchain-ref", "go:github-actions/setup-go",
                "--toolchain-version", "1.23.0",
                "--goos", "linux",
                "--goarch", "amd64",
                "--build-command", 'CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o dist/trustai-verify-linux-amd64 ./verifier/go/trustai-verify',
                "--build-log-ref", str(build_log_path),
                "--build-log-hash", _sha256_ref(build_log_path),
                "--sbom-ref", str(sbom_path),
                "--sbom-hash", _sha256_ref(sbom_path),
                "--provenance-ref", str(provenance_path),
                "--provenance-hash", _sha256_ref(provenance_path),
                "--signature-ref", str(signature_path),
                "--signature-hash", _sha256_ref(signature_path),
                "--build-started-at", "2026-07-16T00:00:00Z",
                "--build-finished-at", "2026-07-16T00:01:00Z",
                "--attested-at", "2026-07-16T00:02:00Z",
            ]
            subprocess.run(
                [sys.executable, "-m", "trustai", "go-verifier-build-attestation", *source_args, *build_args, "--out", str(attestation_path)],
                cwd=ROOT,
                env=env,
                check=True,
            )
            subprocess.run(
                [sys.executable, "-m", "trustai", "go-verifier-build-verify", str(attestation_path), *source_args],
                cwd=ROOT,
                env=env,
                check=True,
            )
            subprocess.run(
                [sys.executable, "-m", "trustai", "go-verifier-build-append", str(attestation_path), *source_args, "--state", str(state_path), "--tenant", "go-verifier-build-local", "--out", str(entry_path)],
                cwd=ROOT,
                env=env,
                check=True,
            )

            attestation = json.loads(attestation_path.read_text(encoding="utf-8"))
            self.assertEqual("binary-attested", attestation["build"]["mode"])
            self.assertEqual("available", attestation["binary"]["status"])
            self.assertTrue(entry_path.exists())


if __name__ == "__main__":
    unittest.main()
