# Research Corpus Metadata

The research corpus should use machine-readable manifests. This document defines
the minimum fields before concrete manifests are frozen.

## Artifact record

Required fields:

```yaml
id: stable-human-readable-id
class: artifact_only | project_loader | framework_coupled | controlled_probe
project: upstream project name
source_url: immutable or reviewable upstream source
source_revision: tag, commit, or release
license: SPDX identifier or documented license
artifact_identity:
  sha256: null
  oci_reference: null
  oci_resolved_digest: null
loader:
  mode: generic | project
  source_revision: null
  binary_sha256: null
notes: null
```

At least one immutable artifact or loader identity must be populated for an
executed record.

## Environment record

A logical profile and an exact executed environment are distinct identities.

Required fields:

```yaml
logical_profile_id: ubuntu-22.04-5.15
exact_environment_id: sha256:<canonical-environment-manifest>
distribution: ubuntu
distribution_release: "22.04"
architecture: x86_64
requested_kernel_family: "5.15"
observed_kernel_release: "5.15.0-191-generic"
image_source: vendor image URL or source description
image_identity: sha256:<image-or-snapshot-digest> | null
btf_available: true
profile_revision: <immutable profile revision or digest>
stand_in_for: null
notes: null
```

`logical_profile_id` groups comparable environments across time.
`exact_environment_id` identifies one immutable execution environment and is
the SHA-256 of the canonical environment manifest. The canonical manifest must
include the exact observed kernel release and any available immutable image,
snapshot, OCI, or profile identities.

A new `exact_environment_id` is required whenever any execution-defining state
changes, including the observed kernel release, architecture, distribution
release, profile revision, or an available image/OCI identity.

`observed_kernel_release` belongs to execution evidence. Never infer it from
the logical profile name.

If the source image has no independently immutable identifier,
`image_identity` may remain null, but the exact environment manifest and its
digest must still preserve the observed environment metadata used for the run.
This limitation must be retained in the dataset rather than hidden.

## Validation contract record

The validation contract is independent from the artifact identity. Reusing the
same artifact with a different command, arguments, or success criteria creates a
different contract.

Required fields:

```yaml
id: sha256:<canonical-validation-contract>
mode: load | load_attach | command
command: bpfcompat-validator
arguments:
  - --example-flag
success_criteria:
  expected_exit_codes:
    - 0
  require_load: true
  require_attach: true
  additional_conditions: []
notes: null
```

`id` is the SHA-256 of the canonical validation-contract record. The record
must contain the complete invocation and success criteria needed to determine a
verdict. For project-loader mode, this includes the exact command, arguments,
and expected exit code(s). For built-in validation, it includes the validation
mode and all enabled success conditions.

## Execution record

A normalized analysis row should retain:

```yaml
dataset_version: "v1"
run_id: stable-run-id
timestamp_utc: "2026-09-18T00:00:00Z"
bpfcompat_version: "0.4.0"
bpfcompat_commit: <immutable git commit SHA or sha256:binary/package-digest>
artifact_id: stable-human-readable-id
environment_id: sha256:<canonical-environment-manifest>
observed_kernel_release: "5.15.0-191-generic"
architecture: x86_64
validation_contract_id: sha256:<canonical-validation-contract>
validation_mode: load | load_attach | command
verdict: compatible | incompatible | inconclusive
classification_code: <normalized-code> | unknown | null
inconclusive_reason: <allowed-reason> | null
raw_report_sha256: sha256:<raw-report>
evidence_path: relative/path/to/raw/evidence
```

### Execution identity requirements

- `bpfcompat_version` is required descriptive metadata.
- `bpfcompat_commit` is required and must be an immutable implementation
  identity. Prefer the resolved Git commit SHA. If a source commit cannot be
  recovered for a packaged binary, store an equivalent immutable binary or
  package digest using a `sha256:`-prefixed value.
- `environment_id` is required and must reference the exact environment
  identity, not the logical profile identity.
- `validation_contract_id` is required and must reference the canonical
  validation contract used by this execution.

### Verdict and reason requirements

`inconclusive_reason` is required when `verdict: inconclusive` and must be
null for `compatible` and `incompatible` results.

Allowed inconclusive reasons:

- `infrastructure_error`
- `timeout`
- `missing_profile`
- `artifact_unavailable`
- `environment_unavailable`
- `unsupported_execution_path`
- `evidence_unavailable`
- `cancelled`
- `unknown`

`classification_code` describes the compatibility mechanism when such a
classification applies. Concrete incompatible results with an ambiguous
mechanism must use `unknown`; they must not use null to hide uncertainty.
`null` is reserved for records where compatibility classification does not
apply, such as successful compatible results or inconclusive attempts without a
compatibility failure to classify.

### Raw evidence requirements

Executed records must contain both:

- `raw_report_sha256`: SHA-256 of the exact machine-readable BPFCompat report;
- `evidence_path`: stable path or archive reference to the captured evidence.

An execution must not publish a `compatible` or `incompatible` verdict when
either field is missing. A normalized record without both evidence references
must be `inconclusive` with
`inconclusive_reason: evidence_unavailable`.

Additional raw fields may be retained. Normalization must never discard the
information needed to distinguish compatibility failure from infrastructure or
evidence failure.

## Dataset versioning

A published corpus release should be immutable. Corrections or additions create
a new version and a changelog entry explaining:

- what changed;
- why it changed;
- which results or conclusions are affected.
