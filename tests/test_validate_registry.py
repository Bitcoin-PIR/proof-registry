import hashlib
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from tools.validate_registry import check_append_only, validate_registry


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
PRODUCER_COMMIT = "a" * 40
VERIFIER_COMMIT = "b" * 40


def encoded_json(value):
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def digest(value):
    return hashlib.sha256(value).hexdigest()


class RegistryFixture:
    def __init__(self, root):
        self.root = root
        for section in ("bundles", "verifications", "deployments", "revocations"):
            directory = root / section
            directory.mkdir(parents=True)
            (directory / "README.md").write_text("fixture\n", encoding="utf-8")
        shutil.copytree(REPOSITORY_ROOT / "schemas", root / "schemas")

    def add_bundle(
        self,
        include_status=False,
        corrupt_artifact=False,
        malformed_profiles=False,
        trust_variant=None,
        declared_path="artifacts/proof.bin",
    ):
        artifact = b"compact proof evidence\n"
        manifest = {
            "artifacts": [
                {
                    "mediaType": "application/octet-stream",
                    "path": declared_path,
                    "role": "proof",
                    "sha256": digest(artifact),
                    "size": len(artifact),
                }
            ],
            "bundleId": "test.bundle/mainnet-100",
            "claims": {"rootSha256": "c" * 64},
            "createdAt": "2026-07-20T00:00:00Z",
            "dependencies": [],
            "mediaType": "application/vnd.bitcoinpir.proof-bundle.v1+json",
            "producers": [
                {
                    "commit": PRODUCER_COMMIT,
                    "repository": "https://github.com/Bitcoin-PIR/attested-builder",
                    "sourcePath": "crates/builder",
                }
            ],
            "schemaVersion": 1,
            "subject": {
                "identifiers": {"height": 100},
                "kind": "database-proof",
                "network": "bitcoin-mainnet",
            },
            "verificationProfiles": ["database-proof/full-v1"],
        }
        if malformed_profiles:
            manifest["verificationProfiles"] = [{"unexpected": True}, "database-proof/full-v1"]
        if include_status:
            manifest["claims"]["status"] = "pass"
        if trust_variant == "verification-claim":
            manifest["claims"]["verification"] = {"claim": "passed"}
        elif trust_variant == "proof-passed":
            manifest["claims"]["proofPassed"] = True
        elif trust_variant == "outcome-value":
            manifest["claims"]["claim"] = "passed"
        elif trust_variant == "validity-alias":
            manifest["claims"]["proofValid"] = True
        elif trust_variant == "failure-value":
            manifest["claims"]["claim"] = "failed"
        raw = encoded_json(manifest)
        manifest_digest = digest(raw)
        bundle_dir = self.root / "bundles" / "sha256" / manifest_digest[:2] / manifest_digest
        artifact_dir = bundle_dir / "artifacts"
        artifact_dir.mkdir(parents=True)
        (bundle_dir / "manifest.json").write_bytes(raw)
        (artifact_dir / "proof.bin").write_bytes(
            b"tampered\n" if corrupt_artifact else artifact
        )
        return manifest_digest

    def add_verification(self, bundle_digest, failing=False, recorded_pass=True):
        check_outcome = "fail" if failing else "pass"
        exit_code = 1 if failing else 0
        record = {
            "bundleManifestSha256": bundle_digest,
            "checks": [
                {
                    "evidenceSha256": "d" * 64,
                    "exitCode": exit_code,
                    "id": "proof/cryptographic-verification",
                    "outcome": check_outcome,
                    "required": True,
                }
            ],
            "createdAt": "2026-07-20T00:01:00Z",
            "mediaType": "application/vnd.bitcoinpir.verification-record.v1+json",
            "overallOutcome": "pass" if recorded_pass else "fail",
            "schemaVersion": 1,
            "verificationProfile": "database-proof/full-v1",
            "verifier": {
                "commit": VERIFIER_COMMIT,
                "repository": "https://github.com/Bitcoin-PIR/BitcoinPIR",
                "tool": "proof-verifier",
                "toolSha256": "e" * 64,
            },
        }
        raw = encoded_json(record)
        record_digest = digest(raw)
        record_dir = (
            self.root
            / "verifications"
            / "sha256"
            / bundle_digest
            / VERIFIER_COMMIT
        )
        record_dir.mkdir(parents=True)
        (record_dir / (record_digest + ".json")).write_bytes(raw)
        return record_digest

    def add_deployment(self, bundle_digest, verification_digest):
        record = {
            "bundleManifestSha256": bundle_digest,
            "consumer": {
                "commit": "f" * 40,
                "repository": "https://github.com/Bitcoin-PIR/BitcoinPIR",
            },
            "createdAt": "2026-07-20T00:02:00Z",
            "deployment": {"identifier": "test-node", "kind": "unified-server"},
            "environment": "testnet-lab",
            "mediaType": "application/vnd.bitcoinpir.deployment-record.v1+json",
            "runtimePins": [{"name": "binary", "sha256": "1" * 64}],
            "schemaVersion": 1,
            "verificationRecordSha256": verification_digest,
        }
        raw = encoded_json(record)
        record_digest = digest(raw)
        record_dir = self.root / "deployments" / "testnet-lab" / "sha256"
        record_dir.mkdir(parents=True)
        (record_dir / (record_digest + ".json")).write_bytes(raw)

    def add_revocation(self, bundle_digest):
        record = {
            "bundleManifestSha256": bundle_digest,
            "createdAt": "2026-07-20T00:03:00Z",
            "evidenceSha256": ["2" * 64],
            "issuedBy": {
                "identity": "test-maintainer",
                "repository": "https://github.com/Bitcoin-PIR/proof-registry",
            },
            "mediaType": "application/vnd.bitcoinpir.revocation-record.v1+json",
            "reason": "Test-only revocation record.",
            "reasonCode": "other",
            "schemaVersion": 1,
        }
        raw = encoded_json(record)
        record_digest = digest(raw)
        record_dir = self.root / "revocations" / "sha256" / bundle_digest
        record_dir.mkdir(parents=True)
        (record_dir / (record_digest + ".json")).write_bytes(raw)


class RegistryValidationTests(unittest.TestCase):
    def fixture(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        return root, RegistryFixture(root)

    def test_empty_skeleton_is_valid(self):
        root, _ = self.fixture()
        errors, stats = validate_registry(root)
        self.assertEqual(errors, [])
        self.assertEqual(
            stats,
            {"bundles": 0, "verifications": 0, "deployments": 0, "revocations": 0},
        )

    def test_complete_cross_linked_registry_is_valid(self):
        root, fixture = self.fixture()
        bundle = fixture.add_bundle()
        verification = fixture.add_verification(bundle)
        fixture.add_deployment(bundle, verification)
        fixture.add_revocation(bundle)
        errors, stats = validate_registry(root)
        self.assertEqual(errors, [])
        self.assertEqual(
            stats,
            {"bundles": 1, "verifications": 1, "deployments": 1, "revocations": 1},
        )

    def test_bundle_cannot_self_report_pass_status(self):
        root, fixture = self.fixture()
        fixture.add_bundle(include_status=True)
        errors, _ = validate_registry(root)
        self.assertTrue(any("trust/result-like key 'status' is forbidden" in error for error in errors))

    def test_bundle_cannot_disguise_self_reported_outcome(self):
        for variant in (
            "verification-claim",
            "proof-passed",
            "outcome-value",
            "validity-alias",
            "failure-value",
        ):
            with self.subTest(variant=variant):
                root, fixture = self.fixture()
                fixture.add_bundle(trust_variant=variant)
                errors, _ = validate_registry(root)
                self.assertTrue(
                    any(
                        "bundle trust/result-like key" in error
                        or "bundle outcome-like value" in error
                        for error in errors
                    )
                )

    def test_artifact_hash_mismatch_is_rejected(self):
        root, fixture = self.fixture()
        fixture.add_bundle(corrupt_artifact=True)
        errors, _ = validate_registry(root)
        self.assertTrue(any("artifact SHA-256 mismatch" in error for error in errors))
        self.assertTrue(any("artifact size mismatch" in error for error in errors))

    def test_malformed_types_are_reported_without_crashing(self):
        root, fixture = self.fixture()
        fixture.add_bundle(malformed_profiles=True)
        errors, _ = validate_registry(root)
        self.assertTrue(any("expected lowercase identifier" in error for error in errors))

    def test_artifact_path_traversal_is_rejected(self):
        root, fixture = self.fixture()
        fixture.add_bundle(declared_path="artifacts/../outside.bin")
        errors, _ = validate_registry(root)
        self.assertTrue(any("traversal-free" in error for error in errors))

    def test_artifact_symlink_is_rejected(self):
        root, fixture = self.fixture()
        bundle = fixture.add_bundle()
        artifact = (
            root
            / "bundles"
            / "sha256"
            / bundle[:2]
            / bundle
            / "artifacts"
            / "proof.bin"
        )
        artifact.unlink()
        target = root / "outside-proof.bin"
        target.write_bytes(b"compact proof evidence\n")
        artifact.symlink_to(target)
        errors, _ = validate_registry(root)
        self.assertTrue(any("symlinks are forbidden" in error for error in errors))

    def test_recorded_pass_is_rejected_when_required_check_fails(self):
        root, fixture = self.fixture()
        bundle = fixture.add_bundle()
        fixture.add_verification(bundle, failing=True, recorded_pass=True)
        errors, _ = validate_registry(root)
        self.assertTrue(any("overallOutcome must be 'fail'" in error for error in errors))

    def test_deployment_must_reference_existing_verification(self):
        root, fixture = self.fixture()
        bundle = fixture.add_bundle()
        fixture.add_deployment(bundle, "9" * 64)
        errors, _ = validate_registry(root)
        self.assertTrue(any("verification record does not exist" in error for error in errors))


class AppendOnlyTests(unittest.TestCase):
    def git(self, root, *args):
        subprocess.run(
            ["git"] + list(args),
            cwd=str(root),
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    def repository(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        self.git(root, "init", "-q")
        self.git(root, "config", "user.name", "Registry Test")
        self.git(root, "config", "user.email", "registry-test@example.invalid")
        return root

    def test_addition_to_immutable_path_is_allowed(self):
        root = self.repository()
        (root / "README.md").write_text("base\n", encoding="utf-8")
        self.git(root, "add", "README.md")
        self.git(root, "commit", "-qm", "base")
        base = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=str(root), text=True).strip()
        digest_value = "a" * 64
        artifact = root / "bundles" / "sha256" / "aa" / digest_value / "artifacts" / "proof"
        artifact.parent.mkdir(parents=True)
        artifact.write_text("new\n", encoding="utf-8")
        self.git(root, "add", ".")
        self.git(root, "commit", "-qm", "add bundle")
        self.assertEqual(check_append_only(root, base, "merge-base"), [])

    def test_modification_to_immutable_path_is_rejected(self):
        root = self.repository()
        digest_value = "a" * 64
        artifact = root / "bundles" / "sha256" / "aa" / digest_value / "artifacts" / "proof"
        artifact.parent.mkdir(parents=True)
        artifact.write_text("original\n", encoding="utf-8")
        self.git(root, "add", ".")
        self.git(root, "commit", "-qm", "base")
        base = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=str(root), text=True).strip()
        artifact.write_text("changed\n", encoding="utf-8")
        self.git(root, "add", ".")
        self.git(root, "commit", "-qm", "mutate bundle")
        errors = check_append_only(root, base, "merge-base")
        self.assertTrue(any("M change is forbidden" in error for error in errors))

    def test_exact_push_comparison_catches_divergent_history_deletion(self):
        root = self.repository()
        (root / "README.md").write_text("common\n", encoding="utf-8")
        self.git(root, "add", ".")
        self.git(root, "commit", "-qm", "common")
        common = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=str(root), text=True
        ).strip()

        digest_value = "a" * 64
        artifact = root / "bundles" / "sha256" / "aa" / digest_value / "artifacts" / "proof"
        artifact.parent.mkdir(parents=True)
        artifact.write_text("old-main-data\n", encoding="utf-8")
        self.git(root, "add", ".")
        self.git(root, "commit", "-qm", "old main registry data")
        before = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=str(root), text=True
        ).strip()

        self.git(root, "checkout", "-q", "-b", "divergent", common)
        (root / "README.md").write_text("divergent\n", encoding="utf-8")
        self.git(root, "add", ".")
        self.git(root, "commit", "-qm", "divergent replacement")

        # A merge-base diff sees only the unrelated README addition and misses
        # the old-main-only immutable file. Exact event.before comparison must
        # detect that the pushed tree deleted it.
        self.assertEqual(check_append_only(root, before, "merge-base"), [])
        errors = check_append_only(root, before, "exact")
        self.assertTrue(any("D change is forbidden" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
