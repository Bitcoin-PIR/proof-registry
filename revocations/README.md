# Revocations

Revocation record paths are:

```text
sha256/<bundle-manifest-sha256>/<record-sha256>.json
```

Revocations are additive statements. They never delete or rewrite a bundle or
verification record. Consumers must define which registry history and issuers
their revocation policy accepts; the record does not authenticate itself.
