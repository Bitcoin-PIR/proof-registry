# Verification records

Verification record paths are:

```text
sha256/<bundle-manifest-sha256>/<verifier-commit>/<record-sha256>.json
```

The filename hashes the exact record bytes. The full verifier source commit and
verification profile are mandatory. Required checks determine the recorded
overall outcome; a recorded pass with a missing, skipped, nonzero, or failed
required check is invalid.

These records are historical evidence only. Consumers must independently pin
and execute an acceptable verifier/profile rather than trusting the outcome in
this repository.
