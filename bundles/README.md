# Bundles

Bundle paths are:

```text
sha256/<first-2>/<manifest-sha256>/manifest.json
sha256/<first-2>/<manifest-sha256>/artifacts/...
```

The directory digest is the SHA-256 of the exact manifest bytes and the shard
is its first two characters. Every artifact must be declared by relative path,
size, media type, role, and SHA-256. No bundle may report its own verification
status; verification belongs in `../verifications/`.

Once merged, a bundle is immutable. Publish a new bundle for any correction.
