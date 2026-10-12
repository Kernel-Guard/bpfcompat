# Verified Compatibility Preview

The preview turns a bpfcompat report into a narrow, reviewable compatibility
claim. It is the first step toward a certification-like program, but it is not
an independent certification or an endorsement by the project whose loader is
tested.

The first profile is
[`falco-modern-bpf-v0.1`](../conformance/falco-modern-bpf-v0.1/spec.md). It tests
the exact `scap-open` bytes through Falco's real `modern_bpf` loader path on five
required x86-64 distribution kernels, including enterprise backport kernels.

## Trust model

The evidence separates four things that must not be conflated:

1. The `scap-open` SHA-256 identifies the exact subject.
2. The bpfcompat report records the command contract, actual guest kernels,
   boot-image SHA-256 values, and per-target results.
3. The versioned profile and matrix define what must pass.
4. A GitHub OIDC/Sigstore attestation identifies the repository workflow that
   issued the result.

Trusting an attestation is a policy decision. Consumers should verify its
subject digest, predicate type, signer repository, and workflow identity, then
enforce their own freshness requirement. The profile permits a 90-day snapshot;
the program may call the result continuous only while its latest successful
scheduled run is at most 14 days old.

## Outcomes

| Decision | Meaning | Signed Test Result | Signed verification result |
|---|---|---:|---:|
| `conformant` | Every required assertion passed | yes (`PASSED`) | yes |
| `nonconformant` | The prescribed loader command ran and failed on a required kernel | yes (`FAILED`) | no |
| `inconclusive` | Infrastructure, identity, freshness, or evidence was insufficient | yes (`WARNED`) | no |

This distinction prevents a KVM, network, image, or runner outage from being
misrepresented as a Falco compatibility defect. If one target has a known
loader failure while another has an infrastructure error, the known product
failure is still `nonconformant`.

## Evaluate a report locally

Run the prescribed command mode against the canonical matrix:

```bash
./bin/bpfcompat test \
  --command '$BPFCOMPAT_BIN --modern_bpf --num_events 10' \
  --command-binary ./scap-open \
  --matrix conformance/falco-modern-bpf-v0.1/matrix.yaml \
  --out reports/falco.json
```

Then evaluate the immutable report against the versioned policy:

```bash
./bin/bpfcompat conformance evaluate \
  --profile conformance/falco-modern-bpf-v0.1/profile.yaml \
  --report reports/falco.json \
  --out-dir reports/falco-conformance \
  --verifier-id https://github.com/Kernel-Guard/bpfcompat/tree/main/conformance/falco-modern-bpf-v0.1
```

Exit code `0` means conformant, `2` means nonconformant, and `1` means
inconclusive or a tool/input error. Inspect `decision.json` to distinguish an
inconclusive decision from a tool error.

The evaluator writes:

- `decision.json`, the detailed decision and assertion evidence;
- `test-result.intoto.json`, an unsigned in-toto Test Result v0.1 statement;
- `verification-result.intoto.json`, an unsigned in-toto Simple Verification
  Result v0.2 statement, only for `conformant` decisions.

The weekly [`external-consumer-canary`](../.github/workflows/external-consumer-canary.yml)
extracts the standard predicates, binds them to the same `scap-open` path, and
signs them with
[GitHub Artifact Attestations](https://github.com/actions/attest). It uploads the
subject binary, report, decision, unsigned statements, and signed Sigstore
bundles together for audit.

## Verify a published result

After downloading the `scap-open` subject from the same workflow run, verify
both the signer and predicate type:

```bash
gh attestation verify ./scap-open \
  --repo Kernel-Guard/bpfcompat \
  --predicate-type https://in-toto.io/attestation/test-result/v0.1

gh attestation verify ./scap-open \
  --repo Kernel-Guard/bpfcompat \
  --predicate-type https://in-toto.io/attestation/svr/v0.2
```

The second command is expected to succeed only for a conformant result. A
serious consumer should additionally pin the signer workflow and enforce the
maximum acceptable attestation age. Verification proves who issued the
statement and which bytes it covers; it does not broaden the profile's claim.

## Promotion criteria

The word `certified` remains out of scope until the program has all of the
following:

- a documented appeals, revocation, and incident process;
- public verifier implementation and profile change control;
- multiple successful recurring cycles with measured infrastructure
  reliability;
- independent governance or a clearly disclosed first-party self-verification
  model;
- a public registry that derives current/expired/revoked state from signed
  evidence; and
- at least one additional adopter profile proving the design is not
  Falco-specific.

Until then, the accurate claim is that bpfcompat issued a signed, scoped
compatibility verification for exact artifact bytes under a preview policy.
