# Bitcoin-PIR Proof Registry

This repository is an append-only, content-addressed registry for compact
Bitcoin-PIR proof artifacts and the records that connect them to independent
verification and deployments.

It is deliberately **not** a source of truth for a `pass` flag. A proof bundle
describes producer claims, provenance, and hashed artifacts. It cannot declare
itself trusted, verified, or passing. Consumers must pin an exact registry Git
commit and bundle manifest SHA-256, then run the required verifier profile
before using the result.

## Trust model

The registry preserves four different kinds of information without conflating
them:

1. `bundles/` contains immutable producer artifacts and claims.
2. `verifications/` contains immutable records of a particular verifier run.
3. `deployments/` records which exact bundle and verification record a
   deployment observed.
4. `revocations/` adds warnings or revocations without deleting history.

A verification record is auditable evidence, not authorization. Its recorded
outcome must be consistent with its checks, but a consumer must still decide
which verifier repository, commit, profile, operator, and revocation policy it
trusts. GitHub UI badges, a bundle's contents, and `server-info` are never trust
roots.

Within a bundle's `claims` and subject identifiers, the validator rejects
trust/result-like key families (`verification`, `trust`, `pass`, `status`,
`outcome`, `verdict`, `valid`, and similar forms) and outcome-like values such
as `passed`, `verified`, `trusted`, or `failed`. Cryptographic result roots are
allowed under a specific non-outcome name such as `resultRoot`; verification
material itself should be a hashed artifact, not a claimed conclusion.

## Directory layout

```text
bundles/sha256/<first-2>/<manifest-sha256>/
  manifest.json
  artifacts/...

verifications/sha256/<manifest-sha256>/<verifier-commit>/<record-sha256>.json
deployments/<environment>/sha256/<record-sha256>.json
revocations/sha256/<manifest-sha256>/<record-sha256>.json
schemas/*.schema.json
tools/validate_registry.py
```

Every digest is lowercase hexadecimal. `<manifest-sha256>` is the SHA-256 of
the exact `manifest.json` bytes. A record filename is the SHA-256 of the exact
JSON record bytes. Bundle artifact paths are relative, normalized POSIX paths
strictly below `artifacts/`; absolute paths, traversal, symlinks, undeclared
files, duplicate paths, and hash or size mismatches are rejected.

Only compact proof evidence belongs in Git. Large artifacts require a future
schema extension defining content-addressed external storage; ad-hoc URLs are
not accepted by version 1.

## Adding data

1. Produce the artifacts from a clean source checkout and record the full
   40-character producer commit.
2. Create a version 1 manifest conforming to
   `schemas/bundle-manifest.schema.json` and hash every artifact.
3. Place the complete bundle at the path derived from the raw manifest hash.
4. Run `python3 tools/validate_registry.py --root .`.
5. Run the relevant independent verifier. Store its content-addressed record
   separately under `verifications/`; do not edit the bundle.
6. Let CI compare the pull request to its base and enforce append-only history.

Corrections create a new bundle or record. Existing content-addressed paths are
never changed, moved, or deleted. A compromised or obsolete bundle remains in
history and receives an additive revocation record.

## Local validation

```sh
python3 -m unittest discover -s tests -v
python3 tools/validate_registry.py --root .
python3 tools/validate_registry.py --root . --base-ref origin/main --comparison merge-base
```

The last command checks a topic branch against its merge base. Main-branch push
CI instead uses an exact comparison from `github.event.before` to the new HEAD,
so a divergent or forced update cannot hide deletion of prior registry data.

## Consumer lock

A downstream lock should contain, at minimum:

- the full registry Git commit;
- the raw bundle manifest SHA-256;
- the required verification profile;
- the accepted verifier repository and full commit;
- any required attestation, measurement, binary pin, operator identity, and
  revocation-policy digests.

Pinning only a branch, height, filename, server URL, or recorded `pass` result
is insufficient.

## License

Licensed under either Apache License, Version 2.0 or the MIT License, at your
option.
