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
  invocation: null
  expected_exit_code: null
notes: null
```

At least one immutable artifact or loader identity must be populated for an
executed record.

## Environment record

Required fields:

```yaml
id: logical-profile-id
distribution: ubuntu
distribution_release: "22.04"
architecture: x86_64
requested_kernel_family: "5.15"
observed_kernel_release: null
image_source: null
image_identity: null
btf_available: null
profile_revision: null
stand_in_for: null
notes: null
```

`observed_kernel_release` belongs to execution evidence when the exact value is
only known after boot. Never infer it from the profile name.

## Execution record

A normalized analysis row should retain:

```yaml
dataset_version: null
run_id: null
timestamp_utc: null
bpfcompat_version: null
bpfcompat_commit: null
artifact_id: null
environment_id: null
observed_kernel_release: null
architecture: null
validation_mode: null
verdict: compatible | incompatible | inconclusive
classification_code: null
inconclusive_reason: null
raw_report_sha256: null
evidence_path: null
```

Additional raw fields may be retained. Normalization must never discard the
information needed to distinguish compatibility failure from infrastructure or
evidence failure.

## Dataset versioning

A published corpus release should be immutable. Corrections or additions create
a new version and a changelog entry explaining:

- what changed;
- why it changed;
- which results or conclusions are affected.
