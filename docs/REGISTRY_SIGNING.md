# Registry Signing Model

## Why this exists

`wsh` can pull registry metadata (`registry.toml`) and manifests over the network.  
Without signature verification, an attacker on the network path (or a compromised upstream) could serve a fake registry index and redirect clients to malicious manifest content.

Registry signing protects the trust anchor for that metadata.

## What is signed

- `registry.toml` is signed with an Ed25519 private key.
- The detached signature is stored as `registry.toml.sig`.

Client behavior:

1. Download `registry.toml`
2. Download `registry.toml.sig`
3. Verify signature using a pinned trusted public key
4. Only then trust manifest hash metadata in the index

## What should be committed to GitHub

Commit/push:

- `registry.toml`
- `registry.toml.sig`
- Public key material (or pin the public key in client code)

Do **not** commit:

- The private signing key

Public keys are safe to publish. They only verify signatures; they cannot create them.

## Where the private key should live

The registry private key should be team-managed and stored securely, for example:

- CI secrets manager (GitHub Actions Secrets, Vault, cloud secret manager)
- Offline signing machine
- HSM/KMS-backed workflow

It should not live in this repo.

## Shared publisher key vs per-user keys

Registry signing should use a shared publisher trust model:

- One team-owned keypair (or a controlled keyset) signs registry metadata.
- All clients trust that key (or keyset).
- Individual developers do not each use their own personal registry key by default.

Important distinction:

- `warrant-core` per-user keys are for local warrant lock/sign flows.
- Registry signing keys are for publishing central registry metadata.

These are separate trust domains.

## Rotation and incident note

If a private key is ever exposed (including appearing in logs), treat it as compromised:

1. Generate a new registry signing keypair
2. Re-sign `registry.toml`
3. Update `registry.toml.sig`
4. Update pinned trusted public key in clients
5. Publish and communicate the rotation

## Suggested operational flow

1. Update `registry.toml`
2. Run signing step using secured private key
3. Commit changed `registry.toml` and `registry.toml.sig`
4. CI/test verifies signature validity before release
5. Clients verify signature before trusting registry metadata

## Practical: How to publish a registry update

Use this when you are changing manifests or bundles in the `registry` repo.

### 1. Edit manifest or bundle files

Examples:

- `warrant-sh/git/manifest.toml`
- `bundles/python.toml`

### 2. Recompute hashes in `registry.toml` for changed manifests

For each changed manifest file:

```bash
shasum -a 256 warrant-sh/git/manifest.toml
```

Take the hex output and set:

```toml
hash = "sha256:<hex>"
```

in the matching `[[manifests]]` entry in `registry.toml`.

### 3. Update metadata timestamp

In `registry.toml`, update:

```toml
[registry]
updated = "<current RFC3339 UTC timestamp>"
```

### 4. Sign `registry.toml` with the team private key

Generate detached signature bytes over the exact file contents, then base64-encode and write to `registry.toml.sig`.

Important:

- Sign exactly the bytes of `registry.toml` as committed.
- `registry.toml.sig` should contain only the base64 signature (single line is simplest).

### 5. Verify locally before commit

Checks:

1. Signature verification succeeds using the trusted public key
2. Every changed manifest hash in `registry.toml` matches file contents

### 6. Commit and push

Commit:

- `registry.toml`
- `registry.toml.sig`
- changed manifest/bundle files

Do not commit private key material.

### 7. After merge

Clients pulling from registry will:

1. fetch `registry.toml`
2. fetch `registry.toml.sig`
3. verify with pinned trusted public key
4. accept metadata only if verification passes

## Practical: key rotation procedure

Use this when the signing private key may be exposed.

1. Generate new keypair (secure environment).
2. Update trusted public key:
   `registry/signing/registry-index-public-key.b64`
   and pinned key in `warrant-shell/src/registry.rs` (or rollout via `WSH_REGISTRY_PUBLIC_KEY` policy).
3. Re-sign current `registry.toml` with new private key.
4. Commit updated public key and `registry.toml.sig`.
5. Release/roll out clients that trust the new public key.
6. Revoke old private key operationally.
