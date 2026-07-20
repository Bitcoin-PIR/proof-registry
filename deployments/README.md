# Deployment records

Deployment record paths are:

```text
<environment>/sha256/<record-sha256>.json
```

Records bind an observed deployment to an immutable bundle, verification
record, consumer source commit, and runtime pins. They describe an event; they
do not define a mutable `latest` or `active` deployment.

Deployment records are append-only. A later deployment creates a new record.
