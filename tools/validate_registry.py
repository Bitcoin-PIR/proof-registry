#!/usr/bin/env python3
"""Validate the Bitcoin-PIR append-only proof registry.

This validator intentionally uses only the Python standard library so registry
integrity checks do not depend on an unpinned package installation. The JSON
Schema files are the portable contract; this program additionally enforces
filesystem, content-addressing, cross-record, and append-only invariants that
JSON Schema cannot express.
"""

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple


HEX64 = re.compile(r"^[0-9a-f]{64}$")
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX2 = re.compile(r"^[0-9a-f]{2}$")
SLUG = re.compile(r"^[a-z0-9][a-z0-9._-]*$")
ID = re.compile(r"^[a-z0-9][a-z0-9._/-]*$")
GITHUB_REPO = re.compile(
    r"^https://github\.com/Bitcoin-PIR/[A-Za-z0-9._-]+$"
)
UTC_TIMESTAMP = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?Z$"
)

BUNDLE_MEDIA_TYPE = "application/vnd.bitcoinpir.proof-bundle.v1+json"
VERIFICATION_MEDIA_TYPE = (
    "application/vnd.bitcoinpir.verification-record.v1+json"
)
DEPLOYMENT_MEDIA_TYPE = "application/vnd.bitcoinpir.deployment-record.v1+json"
REVOCATION_MEDIA_TYPE = "application/vnd.bitcoinpir.revocation-record.v1+json"

SCHEMA_FILES = {
    "bundle-manifest.schema.json",
    "deployment-record.schema.json",
    "revocation-record.schema.json",
    "verification-record.schema.json",
}

# These names and values are forbidden in producer-controlled claim and subject
# identifier payloads. A bundle may make typed claims, but must not smuggle in
# an apparently authoritative verification/trust outcome.
FORBIDDEN_BUNDLE_TRUST_KEYS = {
    "istrusted",
    "isverified",
    "overalloutcome",
    "pass",
    "passed",
    "result",
    "status",
    "trust",
    "trusted",
    "verificationstatus",
    "verified",
    "verdict",
    "outcome",
}
FORBIDDEN_BUNDLE_TRUST_KEY_FRAGMENTS = {
    "accept",
    "approv",
    "error",
    "fail",
    "outcome",
    "pass",
    "reject",
    "status",
    "success",
    "trust",
    "valid",
    "verdict",
    "verif",
}
FORBIDDEN_BUNDLE_OUTCOME_VALUES = {
    "accepted",
    "approved",
    "error",
    "fail",
    "failed",
    "invalid",
    "ok",
    "pass",
    "passed",
    "success",
    "successful",
    "rejected",
    "trusted",
    "untrusted",
    "unverified",
    "valid",
    "verified",
}


class DuplicateKeyError(ValueError):
    pass


def _reject_duplicate_keys(pairs: Sequence[Tuple[str, Any]]) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateKeyError("duplicate JSON key: {!r}".format(key))
        result[key] = value
    return result


def _reject_nonfinite_number(value: str) -> None:
    raise ValueError("non-finite JSON number: {}".format(value))


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_json(path: Path, errors: List[str]) -> Optional[Tuple[Any, bytes]]:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        errors.append("{}: cannot read: {}".format(path, exc))
        return None
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        errors.append("{}: must be UTF-8: {}".format(path, exc))
        return None
    try:
        data = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_nonfinite_number,
        )
    except (json.JSONDecodeError, DuplicateKeyError, ValueError) as exc:
        errors.append("{}: invalid JSON: {}".format(path, exc))
        return None
    return data, raw


def is_exact_int(value: Any) -> bool:
    return type(value) is int


def check_sha(value: Any, context: str, errors: List[str]) -> bool:
    if not isinstance(value, str) or not HEX64.fullmatch(value):
        errors.append("{}: expected lowercase 64-character SHA-256".format(context))
        return False
    return True


def check_commit(value: Any, context: str, errors: List[str]) -> bool:
    if not isinstance(value, str) or not HEX40.fullmatch(value):
        errors.append("{}: expected lowercase full 40-character Git commit".format(context))
        return False
    return True


def check_slug(value: Any, context: str, errors: List[str]) -> bool:
    if not isinstance(value, str) or not SLUG.fullmatch(value):
        errors.append("{}: expected lowercase slug".format(context))
        return False
    return True


def check_id(value: Any, context: str, errors: List[str]) -> bool:
    if not isinstance(value, str) or not ID.fullmatch(value):
        errors.append("{}: expected lowercase identifier".format(context))
        return False
    return True


def check_timestamp(value: Any, context: str, errors: List[str]) -> bool:
    if not isinstance(value, str) or not UTC_TIMESTAMP.fullmatch(value):
        errors.append("{}: expected RFC 3339 UTC timestamp ending in Z".format(context))
        return False
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        errors.append("{}: invalid RFC 3339 timestamp".format(context))
        return False
    if parsed.utcoffset() is None or parsed.utcoffset().total_seconds() != 0:
        errors.append("{}: timestamp must be UTC".format(context))
        return False
    return True


def check_repo(value: Any, context: str, errors: List[str]) -> bool:
    if not isinstance(value, str) or not GITHUB_REPO.fullmatch(value):
        errors.append(
            "{}: expected canonical https://github.com/Bitcoin-PIR/<repo> URL".format(
                context
            )
        )
        return False
    return True


def check_keys(
    value: Any,
    required: Set[str],
    optional: Set[str],
    context: str,
    errors: List[str],
) -> bool:
    if not isinstance(value, dict):
        errors.append("{}: expected JSON object".format(context))
        return False
    keys = set(value)
    missing = sorted(required - keys)
    extra = sorted(keys - required - optional)
    if missing:
        errors.append("{}: missing keys: {}".format(context, ", ".join(missing)))
    if extra:
        errors.append("{}: unexpected keys: {}".format(context, ", ".join(extra)))
    return not missing and not extra


def check_list(value: Any, context: str, errors: List[str]) -> bool:
    if not isinstance(value, list):
        errors.append("{}: expected JSON array".format(context))
        return False
    return True


def check_unique_sorted_strings(
    values: Sequence[Any], context: str, errors: List[str]
) -> None:
    if not all(isinstance(value, str) for value in values):
        return
    if len(values) != len(set(values)):
        errors.append("{}: duplicates are forbidden".format(context))
    if list(values) != sorted(values):
        errors.append("{}: entries must be sorted".format(context))


def normalized_relative_path(
    value: Any, context: str, errors: List[str], required_prefix: Optional[str] = None
) -> bool:
    if not isinstance(value, str) or not value:
        errors.append("{}: expected non-empty relative path".format(context))
        return False
    if "\\" in value:
        errors.append("{}: backslashes are forbidden".format(context))
        return False
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in ("", ".", "..") for part in path.parts):
        errors.append("{}: path must be normalized, relative, and traversal-free".format(context))
        return False
    if path.as_posix() != value:
        errors.append("{}: path is not normalized".format(context))
        return False
    if required_prefix is not None:
        if not path.parts or path.parts[0] != required_prefix or len(path.parts) < 2:
            errors.append(
                "{}: path must be strictly below {}/".format(context, required_prefix)
            )
            return False
    return True


def normalized_key(key: str) -> str:
    return re.sub(r"[^a-z]", "", key.casefold())


def find_forbidden_bundle_assertions(
    value: Any, context: str, errors: List[str]
) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            normalized = normalized_key(key)
            if normalized in FORBIDDEN_BUNDLE_TRUST_KEYS or any(
                fragment in normalized
                for fragment in FORBIDDEN_BUNDLE_TRUST_KEY_FRAGMENTS
            ):
                errors.append(
                    "{}: bundle trust/result-like key {!r} is forbidden; use a separate "
                    "verification record".format(context, key)
                )
            find_forbidden_bundle_assertions(child, context + "." + key, errors)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            find_forbidden_bundle_assertions(
                child, "{}[{}]".format(context, index), errors
            )
    elif isinstance(value, str) and value.strip().casefold() in FORBIDDEN_BUNDLE_OUTCOME_VALUES:
        errors.append(
            "{}: bundle outcome-like value {!r} is forbidden; use a separate "
            "verification record".format(context, value)
        )


def check_no_symlinks(root: Path, errors: List[str]) -> None:
    for relative_root in ("bundles", "verifications", "deployments", "revocations", "schemas"):
        base = root / relative_root
        if not base.exists():
            errors.append("{}: required directory is missing".format(base))
            continue
        if base.is_symlink():
            errors.append("{}: symlinks are forbidden".format(base))
            continue
        for directory, dirnames, filenames in os.walk(str(base), followlinks=False):
            current = Path(directory)
            for name in list(dirnames) + list(filenames):
                candidate = current / name
                if candidate.is_symlink():
                    errors.append("{}: symlinks are forbidden".format(candidate))


def validate_schema_files(root: Path, errors: List[str]) -> None:
    schema_dir = root / "schemas"
    actual = {path.name for path in schema_dir.glob("*.json") if path.is_file()}
    missing = sorted(SCHEMA_FILES - actual)
    extra = sorted(actual - SCHEMA_FILES)
    if missing:
        errors.append("schemas: missing schema files: {}".format(", ".join(missing)))
    if extra:
        errors.append("schemas: unexpected JSON files: {}".format(", ".join(extra)))
    for name in sorted(actual):
        loaded = load_json(schema_dir / name, errors)
        if loaded is None:
            continue
        data, _ = loaded
        if not isinstance(data, dict):
            errors.append("schemas/{}: schema must be a JSON object".format(name))
        elif data.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
            errors.append("schemas/{}: expected JSON Schema draft 2020-12".format(name))


def validate_controlled_layout(root: Path, errors: List[str]) -> None:
    bundle_file = re.compile(
        r"^bundles/sha256/[0-9a-f]{2}/[0-9a-f]{64}/(?:manifest\.json|artifacts/[A-Za-z0-9._/-]+)$"
    )
    verification_file = re.compile(
        r"^verifications/sha256/[0-9a-f]{64}/[0-9a-f]{40}/[0-9a-f]{64}\.json$"
    )
    deployment_file = re.compile(
        r"^deployments/[a-z0-9][a-z0-9._-]*/sha256/[0-9a-f]{64}\.json$"
    )
    revocation_file = re.compile(
        r"^revocations/sha256/[0-9a-f]{64}/[0-9a-f]{64}\.json$"
    )
    matchers = {
        "bundles": bundle_file,
        "verifications": verification_file,
        "deployments": deployment_file,
        "revocations": revocation_file,
    }
    for section, matcher in matchers.items():
        base = root / section
        if not base.exists() or base.is_symlink():
            continue
        for path in base.rglob("*"):
            if not path.is_file() or path.is_symlink():
                continue
            relative = path.relative_to(root).as_posix()
            if relative == section + "/README.md":
                continue
            if not matcher.fullmatch(relative):
                errors.append("{}: file is outside the defined registry layout".format(relative))


def bundle_path(root: Path, digest: str) -> Path:
    return root / "bundles" / "sha256" / digest[:2] / digest / "manifest.json"


def validate_bundle(
    root: Path, manifest_path: Path, errors: List[str]
) -> Optional[Dict[str, Any]]:
    relative = manifest_path.relative_to(root).as_posix()
    match = re.fullmatch(
        r"bundles/sha256/([0-9a-f]{2})/([0-9a-f]{64})/manifest\.json",
        relative,
    )
    if match is None:
        return None
    shard, path_digest = match.groups()
    if shard != path_digest[:2]:
        errors.append("{}: shard does not match manifest digest".format(relative))

    loaded = load_json(manifest_path, errors)
    if loaded is None:
        return None
    data, raw = loaded
    raw_digest = sha256_bytes(raw)
    if raw_digest != path_digest:
        errors.append(
            "{}: path digest {} does not match raw manifest SHA-256 {}".format(
                relative, path_digest, raw_digest
            )
        )
    required = {
        "schemaVersion",
        "mediaType",
        "bundleId",
        "createdAt",
        "subject",
        "producers",
        "claims",
        "artifacts",
        "dependencies",
        "verificationProfiles",
    }
    if not check_keys(data, required, set(), relative, errors):
        if not isinstance(data, dict):
            return None
    assert isinstance(data, dict)
    if data.get("schemaVersion") != 1:
        errors.append("{}: schemaVersion must be 1".format(relative))
    if data.get("mediaType") != BUNDLE_MEDIA_TYPE:
        errors.append("{}: invalid mediaType".format(relative))
    check_id(data.get("bundleId"), relative + ".bundleId", errors)
    check_timestamp(data.get("createdAt"), relative + ".createdAt", errors)

    subject = data.get("subject")
    if check_keys(subject, {"kind", "network", "identifiers"}, set(), relative + ".subject", errors):
        check_slug(subject.get("kind"), relative + ".subject.kind", errors)
        if not isinstance(subject.get("network"), str) or not subject.get("network"):
            errors.append("{}.subject.network: expected non-empty string".format(relative))
        identifiers = subject.get("identifiers")
        if not isinstance(identifiers, dict) or not identifiers:
            errors.append("{}.subject.identifiers: expected non-empty object".format(relative))

    producers = data.get("producers")
    if check_list(producers, relative + ".producers", errors):
        if not producers:
            errors.append("{}.producers: at least one producer is required".format(relative))
        producer_order: List[Tuple[str, str]] = []
        for index, producer in enumerate(producers):
            context = "{}.producers[{}]".format(relative, index)
            if check_keys(producer, {"repository", "commit"}, {"sourcePath"}, context, errors):
                check_repo(producer.get("repository"), context + ".repository", errors)
                check_commit(producer.get("commit"), context + ".commit", errors)
                if "sourcePath" in producer:
                    normalized_relative_path(producer["sourcePath"], context + ".sourcePath", errors)
                repository = producer.get("repository")
                commit = producer.get("commit")
                if isinstance(repository, str) and isinstance(commit, str):
                    producer_order.append((repository, commit))
        if len(producer_order) != len(set(producer_order)):
            errors.append("{}.producers: duplicate entries are forbidden".format(relative))
        if producer_order != sorted(producer_order):
            errors.append("{}.producers: entries must be sorted by repository and commit".format(relative))

    claims = data.get("claims")
    if not isinstance(claims, dict) or not claims:
        errors.append("{}.claims: expected non-empty object".format(relative))
    else:
        find_forbidden_bundle_assertions(claims, relative + ".claims", errors)

    if isinstance(subject, dict) and isinstance(subject.get("identifiers"), dict):
        find_forbidden_bundle_assertions(
            subject["identifiers"], relative + ".subject.identifiers", errors
        )

    declared_paths: List[str] = []
    artifacts = data.get("artifacts")
    if check_list(artifacts, relative + ".artifacts", errors):
        for index, artifact in enumerate(artifacts):
            context = "{}.artifacts[{}]".format(relative, index)
            required_artifact = {"path", "sha256", "size", "mediaType", "role"}
            if not check_keys(artifact, required_artifact, set(), context, errors):
                continue
            artifact_path = artifact.get("path")
            path_ok = normalized_relative_path(
                artifact_path, context + ".path", errors, required_prefix="artifacts"
            )
            check_sha(artifact.get("sha256"), context + ".sha256", errors)
            size = artifact.get("size")
            if not is_exact_int(size) or size < 0:
                errors.append("{}.size: expected nonnegative integer".format(context))
            if not isinstance(artifact.get("mediaType"), str) or not artifact.get("mediaType"):
                errors.append("{}.mediaType: expected non-empty string".format(context))
            check_slug(artifact.get("role"), context + ".role", errors)
            if not path_ok:
                continue
            declared_paths.append(artifact_path)
            target = manifest_path.parent / artifact_path
            if not target.is_file() or target.is_symlink():
                errors.append("{}: declared artifact is missing or not a regular file".format(target))
                continue
            artifact_raw = target.read_bytes()
            if artifact.get("sha256") != sha256_bytes(artifact_raw):
                errors.append("{}: artifact SHA-256 mismatch".format(target))
            if artifact.get("size") != len(artifact_raw):
                errors.append("{}: artifact size mismatch".format(target))
        if len(declared_paths) != len(set(declared_paths)):
            errors.append("{}.artifacts: duplicate paths are forbidden".format(relative))
        if declared_paths != sorted(declared_paths):
            errors.append("{}.artifacts: entries must be sorted by path".format(relative))

    actual_artifacts: Set[str] = set()
    artifact_root = manifest_path.parent / "artifacts"
    if artifact_root.exists():
        if not artifact_root.is_dir() or artifact_root.is_symlink():
            errors.append("{}: artifacts must be a real directory".format(artifact_root))
        else:
            for path in artifact_root.rglob("*"):
                if path.is_file() and not path.is_symlink():
                    actual_artifacts.add(path.relative_to(manifest_path.parent).as_posix())
    undeclared = sorted(actual_artifacts - set(declared_paths))
    missing = sorted(set(declared_paths) - actual_artifacts)
    if undeclared:
        errors.append("{}: undeclared artifacts: {}".format(relative, ", ".join(undeclared)))
    if missing:
        errors.append("{}: missing declared artifacts: {}".format(relative, ", ".join(missing)))

    dependencies = data.get("dependencies")
    dependency_order: List[Tuple[str, str]] = []
    if check_list(dependencies, relative + ".dependencies", errors):
        for index, dependency in enumerate(dependencies):
            context = "{}.dependencies[{}]".format(relative, index)
            if check_keys(dependency, {"role", "manifestSha256"}, set(), context, errors):
                check_slug(dependency.get("role"), context + ".role", errors)
                digest = dependency.get("manifestSha256")
                if check_sha(digest, context + ".manifestSha256", errors):
                    if digest == path_digest:
                        errors.append("{}: bundle cannot depend on itself".format(context))
                    elif not bundle_path(root, digest).is_file():
                        errors.append("{}: referenced bundle does not exist".format(context))
                role = dependency.get("role")
                if isinstance(role, str) and isinstance(digest, str):
                    dependency_order.append((role, digest))
        if len(dependency_order) != len(set(dependency_order)):
            errors.append("{}.dependencies: duplicate dependencies are forbidden".format(relative))
        if dependency_order != sorted(dependency_order):
            errors.append("{}.dependencies: entries must be sorted".format(relative))

    profiles = data.get("verificationProfiles")
    if check_list(profiles, relative + ".verificationProfiles", errors):
        if not profiles:
            errors.append("{}.verificationProfiles: at least one profile is required".format(relative))
        for index, profile in enumerate(profiles):
            check_id(profile, "{}.verificationProfiles[{}]".format(relative, index), errors)
        check_unique_sorted_strings(
            profiles, relative + ".verificationProfiles", errors
        )

    return data


def validate_verification_record(
    root: Path,
    path: Path,
    bundles: Dict[str, Dict[str, Any]],
    errors: List[str],
) -> Optional[Tuple[str, str]]:
    relative = path.relative_to(root).as_posix()
    match = re.fullmatch(
        r"verifications/sha256/([0-9a-f]{64})/([0-9a-f]{40})/([0-9a-f]{64})\.json",
        relative,
    )
    if match is None:
        return None
    bundle_digest, verifier_commit, record_digest = match.groups()
    loaded = load_json(path, errors)
    if loaded is None:
        return None
    data, raw = loaded
    if sha256_bytes(raw) != record_digest:
        errors.append("{}: filename does not match raw record SHA-256".format(relative))
    required = {
        "schemaVersion",
        "mediaType",
        "createdAt",
        "bundleManifestSha256",
        "verificationProfile",
        "verifier",
        "checks",
        "overallOutcome",
    }
    if not check_keys(data, required, set(), relative, errors):
        if not isinstance(data, dict):
            return None
    assert isinstance(data, dict)
    if data.get("schemaVersion") != 1:
        errors.append("{}: schemaVersion must be 1".format(relative))
    if data.get("mediaType") != VERIFICATION_MEDIA_TYPE:
        errors.append("{}: invalid mediaType".format(relative))
    check_timestamp(data.get("createdAt"), relative + ".createdAt", errors)
    if data.get("bundleManifestSha256") != bundle_digest:
        errors.append("{}: bundle digest does not match path".format(relative))
    if bundle_digest not in bundles:
        errors.append("{}: referenced bundle does not exist".format(relative))
    profile = data.get("verificationProfile")
    check_id(profile, relative + ".verificationProfile", errors)
    if bundle_digest in bundles:
        allowed_profiles = bundles[bundle_digest].get("verificationProfiles", [])
        if profile not in allowed_profiles:
            errors.append("{}: profile is not declared by the bundle".format(relative))

    verifier = data.get("verifier")
    verifier_required = {"repository", "commit", "tool", "toolSha256"}
    if check_keys(verifier, verifier_required, set(), relative + ".verifier", errors):
        check_repo(verifier.get("repository"), relative + ".verifier.repository", errors)
        check_commit(verifier.get("commit"), relative + ".verifier.commit", errors)
        if verifier.get("commit") != verifier_commit:
            errors.append("{}: verifier commit does not match path".format(relative))
        if not isinstance(verifier.get("tool"), str) or not verifier.get("tool"):
            errors.append("{}.verifier.tool: expected non-empty string".format(relative))
        check_sha(verifier.get("toolSha256"), relative + ".verifier.toolSha256", errors)

    checks = data.get("checks")
    check_ids: List[str] = []
    all_required_pass = True
    required_count = 0
    if check_list(checks, relative + ".checks", errors):
        if not checks:
            errors.append("{}.checks: at least one check is required".format(relative))
        for index, check in enumerate(checks):
            context = "{}.checks[{}]".format(relative, index)
            required_check = {"id", "required", "outcome", "exitCode"}
            if not check_keys(check, required_check, {"evidenceSha256"}, context, errors):
                all_required_pass = False
                continue
            check_identifier = check.get("id")
            check_id(check_identifier, context + ".id", errors)
            if isinstance(check_identifier, str):
                check_ids.append(check_identifier)
            if type(check.get("required")) is not bool:
                errors.append("{}.required: expected boolean".format(context))
            outcome = check.get("outcome")
            if outcome not in {"pass", "fail", "error", "skipped"}:
                errors.append("{}.outcome: invalid outcome".format(context))
            exit_code = check.get("exitCode")
            if not is_exact_int(exit_code) or exit_code < 0:
                errors.append("{}.exitCode: expected nonnegative integer".format(context))
            if outcome == "pass" and exit_code != 0:
                errors.append("{}: passing check must have exitCode 0".format(context))
            if "evidenceSha256" in check:
                check_sha(check["evidenceSha256"], context + ".evidenceSha256", errors)
            if check.get("required") is True:
                required_count += 1
                if outcome != "pass" or exit_code != 0:
                    all_required_pass = False
        if required_count == 0:
            errors.append("{}.checks: at least one required check is mandatory".format(relative))
            all_required_pass = False
        check_unique_sorted_strings(check_ids, relative + ".checks", errors)
    else:
        all_required_pass = False

    expected_outcome = "pass" if all_required_pass else "fail"
    if data.get("overallOutcome") != expected_outcome:
        errors.append(
            "{}: overallOutcome must be {!r}, derived from required checks".format(
                relative, expected_outcome
            )
        )
    return record_digest, bundle_digest


def validate_deployment_record(
    root: Path,
    path: Path,
    bundles: Dict[str, Dict[str, Any]],
    verification_records: Dict[str, str],
    errors: List[str],
) -> None:
    relative = path.relative_to(root).as_posix()
    match = re.fullmatch(
        r"deployments/([a-z0-9][a-z0-9._-]*)/sha256/([0-9a-f]{64})\.json",
        relative,
    )
    if match is None:
        return
    environment, record_digest = match.groups()
    loaded = load_json(path, errors)
    if loaded is None:
        return
    data, raw = loaded
    if sha256_bytes(raw) != record_digest:
        errors.append("{}: filename does not match raw record SHA-256".format(relative))
    required = {
        "schemaVersion",
        "mediaType",
        "createdAt",
        "environment",
        "deployment",
        "bundleManifestSha256",
        "verificationRecordSha256",
        "consumer",
        "runtimePins",
    }
    if not check_keys(data, required, set(), relative, errors):
        if not isinstance(data, dict):
            return
    assert isinstance(data, dict)
    if data.get("schemaVersion") != 1:
        errors.append("{}: schemaVersion must be 1".format(relative))
    if data.get("mediaType") != DEPLOYMENT_MEDIA_TYPE:
        errors.append("{}: invalid mediaType".format(relative))
    check_timestamp(data.get("createdAt"), relative + ".createdAt", errors)
    if data.get("environment") != environment:
        errors.append("{}: environment does not match path".format(relative))

    deployment = data.get("deployment")
    if check_keys(deployment, {"kind", "identifier"}, set(), relative + ".deployment", errors):
        check_slug(deployment.get("kind"), relative + ".deployment.kind", errors)
        if not isinstance(deployment.get("identifier"), str) or not deployment.get("identifier"):
            errors.append("{}.deployment.identifier: expected non-empty string".format(relative))

    bundle_digest = data.get("bundleManifestSha256")
    if check_sha(bundle_digest, relative + ".bundleManifestSha256", errors):
        if bundle_digest not in bundles:
            errors.append("{}: referenced bundle does not exist".format(relative))
    verification_digest = data.get("verificationRecordSha256")
    if check_sha(verification_digest, relative + ".verificationRecordSha256", errors):
        verified_bundle = verification_records.get(verification_digest)
        if verified_bundle is None:
            errors.append("{}: referenced verification record does not exist".format(relative))
        elif verified_bundle != bundle_digest:
            errors.append("{}: verification record belongs to a different bundle".format(relative))

    consumer = data.get("consumer")
    if check_keys(consumer, {"repository", "commit"}, set(), relative + ".consumer", errors):
        check_repo(consumer.get("repository"), relative + ".consumer.repository", errors)
        check_commit(consumer.get("commit"), relative + ".consumer.commit", errors)

    pins = data.get("runtimePins")
    pin_names: List[str] = []
    if check_list(pins, relative + ".runtimePins", errors):
        if not pins:
            errors.append("{}.runtimePins: at least one runtime pin is required".format(relative))
        for index, pin in enumerate(pins):
            context = "{}.runtimePins[{}]".format(relative, index)
            if check_keys(pin, {"name", "sha256"}, set(), context, errors):
                check_slug(pin.get("name"), context + ".name", errors)
                check_sha(pin.get("sha256"), context + ".sha256", errors)
                pin_name = pin.get("name")
                if isinstance(pin_name, str):
                    pin_names.append(pin_name)
        check_unique_sorted_strings(pin_names, relative + ".runtimePins", errors)


def validate_revocation_record(
    root: Path,
    path: Path,
    bundles: Dict[str, Dict[str, Any]],
    errors: List[str],
) -> None:
    relative = path.relative_to(root).as_posix()
    match = re.fullmatch(
        r"revocations/sha256/([0-9a-f]{64})/([0-9a-f]{64})\.json", relative
    )
    if match is None:
        return
    bundle_digest, record_digest = match.groups()
    loaded = load_json(path, errors)
    if loaded is None:
        return
    data, raw = loaded
    if sha256_bytes(raw) != record_digest:
        errors.append("{}: filename does not match raw record SHA-256".format(relative))
    required = {
        "schemaVersion",
        "mediaType",
        "createdAt",
        "bundleManifestSha256",
        "reasonCode",
        "reason",
        "issuedBy",
        "evidenceSha256",
    }
    if not check_keys(data, required, set(), relative, errors):
        if not isinstance(data, dict):
            return
    assert isinstance(data, dict)
    if data.get("schemaVersion") != 1:
        errors.append("{}: schemaVersion must be 1".format(relative))
    if data.get("mediaType") != REVOCATION_MEDIA_TYPE:
        errors.append("{}: invalid mediaType".format(relative))
    check_timestamp(data.get("createdAt"), relative + ".createdAt", errors)
    if data.get("bundleManifestSha256") != bundle_digest:
        errors.append("{}: bundle digest does not match path".format(relative))
    if bundle_digest not in bundles:
        errors.append("{}: referenced bundle does not exist".format(relative))
    if data.get("reasonCode") not in {"compromised", "invalid", "obsolete", "superseded", "other"}:
        errors.append("{}: invalid reasonCode".format(relative))
    if not isinstance(data.get("reason"), str) or not data.get("reason", "").strip():
        errors.append("{}.reason: expected non-empty string".format(relative))
    issuer = data.get("issuedBy")
    if check_keys(issuer, {"identity", "repository"}, set(), relative + ".issuedBy", errors):
        if not isinstance(issuer.get("identity"), str) or not issuer.get("identity"):
            errors.append("{}.issuedBy.identity: expected non-empty string".format(relative))
        if issuer.get("repository") != "https://github.com/Bitcoin-PIR/proof-registry":
            errors.append("{}.issuedBy.repository: invalid registry URL".format(relative))
    evidence = data.get("evidenceSha256")
    if check_list(evidence, relative + ".evidenceSha256", errors):
        for index, digest in enumerate(evidence):
            check_sha(digest, "{}.evidenceSha256[{}]".format(relative, index), errors)
        check_unique_sorted_strings(evidence, relative + ".evidenceSha256", errors)


def validate_registry(root: Path) -> Tuple[List[str], Dict[str, int]]:
    root = root.resolve()
    errors: List[str] = []
    check_no_symlinks(root, errors)
    validate_schema_files(root, errors)
    validate_controlled_layout(root, errors)

    bundles: Dict[str, Dict[str, Any]] = {}
    bundle_root = root / "bundles" / "sha256"
    if bundle_root.exists():
        for manifest in sorted(bundle_root.glob("*/*/manifest.json")):
            data = validate_bundle(root, manifest, errors)
            digest = manifest.parent.name
            if data is not None and HEX64.fullmatch(digest):
                bundles[digest] = data
        for candidate in sorted(bundle_root.glob("*/*")):
            if candidate.is_dir() and not candidate.is_symlink() and not (candidate / "manifest.json").is_file():
                errors.append("{}: bundle directory is missing manifest.json".format(candidate))

    verification_records: Dict[str, str] = {}
    verification_root = root / "verifications" / "sha256"
    verification_count = 0
    if verification_root.exists():
        for record in sorted(verification_root.glob("*/*/*.json")):
            result = validate_verification_record(root, record, bundles, errors)
            if result is not None:
                digest, bundle_digest = result
                verification_count += 1
                existing = verification_records.get(digest)
                if existing is not None and existing != bundle_digest:
                    errors.append("{}: verification digest collision across bundles".format(record))
                verification_records[digest] = bundle_digest

    deployment_count = 0
    deployment_root = root / "deployments"
    if deployment_root.exists():
        for record in sorted(deployment_root.glob("*/sha256/*.json")):
            validate_deployment_record(
                root, record, bundles, verification_records, errors
            )
            deployment_count += 1

    revocation_count = 0
    revocation_root = root / "revocations" / "sha256"
    if revocation_root.exists():
        for record in sorted(revocation_root.glob("*/*.json")):
            validate_revocation_record(root, record, bundles, errors)
            revocation_count += 1

    stats = {
        "bundles": len(bundles),
        "verifications": verification_count,
        "deployments": deployment_count,
        "revocations": revocation_count,
    }
    return errors, stats


def immutable_registry_path(path: str) -> bool:
    patterns = (
        r"^bundles/sha256/[0-9a-f]{2}/[0-9a-f]{64}/.*$",
        r"^verifications/sha256/[0-9a-f]{64}/[0-9a-f]{40}/[0-9a-f]{64}\.json$",
        r"^deployments/[a-z0-9][a-z0-9._-]*/sha256/[0-9a-f]{64}\.json$",
        r"^revocations/sha256/[0-9a-f]{64}/[0-9a-f]{64}\.json$",
    )
    return any(re.fullmatch(pattern, path) for pattern in patterns)


def parse_name_status_z(output: bytes) -> Iterable[Tuple[str, List[str]]]:
    tokens = output.split(b"\0")
    if tokens and tokens[-1] == b"":
        tokens.pop()
    index = 0
    while index < len(tokens):
        status = tokens[index].decode("utf-8", "strict")
        index += 1
        path_count = 2 if status[:1] in {"R", "C"} else 1
        if index + path_count > len(tokens):
            raise ValueError("truncated git --name-status output")
        paths = [tokens[index + offset].decode("utf-8", "strict") for offset in range(path_count)]
        index += path_count
        yield status, paths


def check_append_only(
    root: Path, base_ref: str, comparison: str = "exact"
) -> List[str]:
    errors: List[str] = []
    if comparison not in {"exact", "merge-base"}:
        return ["append-only: invalid comparison mode {!r}".format(comparison)]
    try:
        subprocess.run(
            ["git", "cat-file", "-e", base_ref + "^{commit}"],
            cwd=str(root),
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except subprocess.CalledProcessError as exc:
        message = exc.stderr.decode("utf-8", "replace").strip()
        return ["append-only: base ref {!r} is unavailable: {}".format(base_ref, message)]

    try:
        comparison_range = (
            base_ref + "...HEAD" if comparison == "merge-base" else base_ref
        )
        command = [
            "git",
            "diff",
            "--name-status",
            "-z",
            "--find-renames",
            comparison_range,
        ]
        if comparison == "exact":
            command.append("HEAD")
        command.extend(
            [
                "--",
                "bundles",
                "verifications",
                "deployments",
                "revocations",
            ]
        )
        completed = subprocess.run(
            command,
            cwd=str(root),
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        changes = list(parse_name_status_z(completed.stdout))
    except (subprocess.CalledProcessError, UnicodeDecodeError, ValueError) as exc:
        errors.append("append-only: cannot inspect Git diff: {}".format(exc))
        return errors

    for status, paths in changes:
        immutable_paths = [path for path in paths if immutable_registry_path(path)]
        if immutable_paths and status != "A":
            errors.append(
                "append-only: {} change is forbidden for {}".format(
                    status, ", ".join(immutable_paths)
                )
            )
    return errors


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=".", help="registry root (default: .)")
    parser.add_argument(
        "--base-ref",
        help="also reject non-additive changes to immutable paths since this Git ref",
    )
    parser.add_argument(
        "--comparison",
        choices=("exact", "merge-base"),
        default="exact",
        help="append-only Git comparison mode (default: exact)",
    )
    args = parser.parse_args(argv)
    root = Path(args.root)
    errors, stats = validate_registry(root)
    if args.base_ref:
        errors.extend(
            check_append_only(root.resolve(), args.base_ref, args.comparison)
        )
    if errors:
        for error in errors:
            print("ERROR: " + error, file=sys.stderr)
        print("registry validation failed with {} error(s)".format(len(errors)), file=sys.stderr)
        return 1
    print(
        "registry valid: {bundles} bundle(s), {verifications} verification(s), "
        "{deployments} deployment(s), {revocations} revocation(s)".format(**stats)
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
