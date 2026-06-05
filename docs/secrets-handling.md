# Secrets Handling Guide

Audience: operators running bpfcompat in production. This document
captures the rules of the road for the secrets the system depends on —
where they live, how to rotate them, what NOT to do.

## Inventory of secrets

| Secret                            | Where it lives                                                          | Rotation cadence       |
| ---                               | ---                                                                     | ---                    |
| API key (`BPFCOMPAT_API_WRITE_KEY`) | Env var on the API process                                              | 90 days, on-demand     |
| Token grants                      | `<workdir>/cloud-registry/auth/tokens.json` (mode 0600)                 | Per-tenant; bound by `ExpiresAt` |
| JWT signing material              | External (operator's IdP / JWKS)                                        | Per IdP policy         |
| TLS server cert + key             | Filesystem paths in `TLSCertPath` / `TLSKeyPath`                        | 90 days                |
| mTLS CA bundle                    | `BPFCOMPAT_API_CLIENT_CA_PATH`                                          | Per CA policy          |
| mTLS identity map                 | `BPFCOMPAT_API_MTLS_IDENTITY_MAP_PATH`                                  | On cert/tenant change  |
| Artifact registry signing key     | `<workdir>/keys/artifact-registry-signing-key.ed25519` (mode 0600)      | 1 year, on key compromise |
| Runtime-execute approval token    | `BPFCOMPAT_API_RUNTIME_EXECUTE_APPROVAL_TOKEN`                          | 90 days                |
| Audit-export signing key          | Operator-managed; passed to `admin audit-export --sign-key`             | 1 year                 |

## Hard rules

1. **`tokens.json` is never committed.** It is in `.gitignore`. If a token
   value lands in a repo (commit, gist, screenshot), revoke it
   immediately with `bpfcompat admin revoke-token` and rotate.
2. **Always hash new grants.** Use the `HashTokenGrant` helper for any
   new token. Plaintext `Token` is supported for legacy compatibility
   only; new entries should populate `TokenHash` + `TokenHashSalt`.
3. **Set `ExpiresAt` on every new grant.** Default "never expires" exists
   only for backward compatibility with old `tokens.json`. CI for prod
   should reject grants without a bounded expiry.
4. **Signing keys never round-trip through chat/email.** Use your secret
   manager (Vault, AWS Secrets Manager, etc.). The audit-export signing
   key path is read at command time, so you can mount it just-in-time.
5. **mTLS CA membership is not API authorization.** A verified client cert
   must also match `BPFCOMPAT_API_MTLS_IDENTITY_MAP_PATH`, which maps cert
   selectors to subject, tenant, project, scopes, and roles. Treat issued
   client certs like long-lived credentials and revoke through your CA.
6. **TLS material at rest is mode 0600.** Same for `tokens.json` and the
   artifact signing private key. The server doesn't enforce this, but
   `bpfcompat admin list-tokens` will refuse to read an obviously
   over-permissioned file in a future release.

## Rotation playbooks

### Rotate an API key

```bash
# 1. Generate new key (your secret manager / openssl rand).
NEWKEY=$(openssl rand -hex 32)

# 2. Update env and restart in rolling fashion (k8s rollout, systemd reload).
#    The API key check is constant-time; old key continues to work until
#    every replica has the new env.

# 3. Burn the old key by removing it from your secret manager.
```

### Rotate a tenant token

```bash
# 1. Add new grant to tokens.json (use HashTokenGrant).
# 2. Communicate new credential out-of-band.
# 3. Wait for caller to switch.
# 4. Revoke old:
bpfcompat admin revoke-token \
  --subject svc-payments \
  --tenant acme \
  --dry-run    # confirm the diff
bpfcompat admin revoke-token \
  --subject svc-payments \
  --tenant acme
```

### Rotate TLS cert / key

```bash
# 1. Issue new cert (cert-manager, Vault PKI, your CA).
# 2. Write to TLSCertPath / TLSKeyPath atomically (write + rename).
# 3. Send SIGHUP — NOT YET IMPLEMENTED. Today: restart the process.
#    (Reload-on-SIGHUP is on the post-P4 roadmap; see issue tracker.)
```

### Rotate audit-export signing key

```bash
# 1. Generate new Ed25519 keypair (openssl genpkey or your KMS).
# 2. Distribute the new public key to verifiers (auditors, log shipper).
# 3. Cut over at the next export window.
# 4. Old verifications still work — past exports remain valid against
#    the pubkey embedded in their envelope.
```

## Audit-export hygiene

- Always pair `--sign-key` with `--sig-out`. Unsigned exports have no
  provenance.
- Verify exports nightly with `bpfcompat admin audit-verify` and a
  **pinned** `--pubkey`. Pinning is required by default; the
  `--trust-envelope-key` escape hatch is for dev/demo only.
- Keep verified exports immutable (object storage with object-lock).
- The signature envelope contains the sha256 of the payload — a verifier
  catches truncation/corruption even without re-running the signer.

## What to do on suspected compromise

1. Revoke the affected token / cert immediately.
2. Force JWKS refresh if a JWT key is suspected: bump the JWKS endpoint
   and let the in-process cache miss; the cooldown defaults to 30s.
3. Run `bpfcompat admin verify-chain` to confirm registry integrity.
4. Run `bpfcompat admin audit-export --sign-key ...` for the affected
   window; ship to forensics.
5. File against the disclosure address in `SECURITY.md`.
