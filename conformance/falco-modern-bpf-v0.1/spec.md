# Falco modern_bpf compatibility profile v0.1

Status: **Verified Compatibility Preview**

This profile evaluates the kernel-compatibility behavior of the exact
`scap-open` binary built from `falcosecurity/libs`. It uses Falco's real
userspace loader path with the modern eBPF probe skeleton embedded.

It is an independent compatibility test of publicly available software. It is
not affiliated with, sponsored by, or endorsed by the Falco project or CNCF.

## Normative claim

A `conformant` decision means:

> The exact `scap-open` loader binary identified by SHA-256 completed Falco's
> `modern_bpf` initialization and bounded event-capture contract on every
> required kernel in `matrix.yaml`.

The tested command MUST be:

```bash
$BPFCOMPAT_BIN --modern_bpf --num_events 10
```

and the expected exit code MUST be zero. `scap-open` exits successfully only
after `scap_open()` has exercised libpman's load path, attached the selected
programs, and captured the requested bounded event count.

## Subject

The subject is the loader binary, not the Falco organization, repository name,
branch, mutable tag, or every product built from the repository. The subject
MUST be named `scap-open` and MUST have a valid SHA-256 in the report's
`command.binary` identity.

Source repository and commit metadata MAY accompany a submission, but source
metadata alone does not replace the binary digest. A future build-provenance
profile can establish the source-to-binary relationship separately.

## Required matrix

Every profile in `matrix.yaml` is mandatory. The report MAY contain additional
informational targets, but they do not expand the credential's scope.
The expected distro, release, kernel family, and architecture for every matrix
ID are separately declared in `profile.yaml`; matching a profile ID string alone
is not sufficient evidence.

Each required target MUST:

- appear exactly once and remain marked `required`;
- record requested distro, version, kernel family, and architecture;
- record the actual host kernel release and architecture;
- record the SHA-256 of the base image bytes used to boot the guest; and
- contain a passing required `command` functional result.

The report MUST use a schema allowed by `profile.yaml` and MUST be evaluated
before its 90-day snapshot window expires.

## Outcomes

- `conformant`: all assertions pass.
- `nonconformant`: the prescribed loader command executes and fails on at least
  one required target.
- `inconclusive`: the report is stale, incomplete, uses the wrong contract,
  omits a required target or identity, or contains an infrastructure error.

A known product failure is sufficient to establish `nonconformant` even when a
different target is inconclusive. Infrastructure failure by itself MUST NOT be
reported as Falco incompatibility.

## Evidence and attestations

Every evaluation writes:

1. `decision.json`, binding the subject, report, profile, matrix, assertion
   results, evaluated targets, verifier, creation time, and validity window;
2. `test-result.intoto.json`, using the
   [in-toto Test Result v0.1](https://github.com/in-toto/attestation/blob/main/spec/predicates/test-result.md)
   predicate.

Only a conformant evaluation additionally writes
`verification-result.intoto.json`, using the
[in-toto Simple Verification Result v0.2](https://github.com/in-toto/attestation/blob/main/spec/predicates/svr.md)
predicate. Signing and transparency logging happen after evaluation so the
unsigned statement remains independently inspectable.

## Validity

A snapshot decision expires 90 days after the underlying compatibility run.
The report MUST still be within that window when evaluated. A registry MAY show
`continuous` only while the latest successful scheduled run is no more than 14
days old.

Any change to the subject digest, required matrix, command contract, profile, or
assertion semantics requires a new evaluation. A materially changed contract
requires a new profile version.

## Explicit exclusions

This profile does not establish:

- complete Falco daemon startup or configuration correctness;
- Falco rules-engine or plugin behavior;
- correctness of every event field;
- support for kernels or configurations outside the recorded matrix; or
- endorsement by Falco, CNCF, or the eBPF Foundation.
