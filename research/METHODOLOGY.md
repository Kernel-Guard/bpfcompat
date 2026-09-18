# Proposed Research Methodology

This document is the prospective protocol for a future BPFCompat compatibility
study. It should be versioned before a confirmatory dataset is collected.

## Unit of observation

The primary unit is an execution tuple:

```text
artifact_or_loader × exact_kernel_environment × architecture × validation_contract
```

A logical profile (for example, a distro/kernel family) and the exact observed
kernel release are both retained. They must not be conflated.

## Corpus construction

### Artifacts

Prefer real, publicly redistributable eBPF artifacts from maintained projects.
Controlled feature probes are included only to isolate mechanisms and must be
labeled separately.

Each corpus entry is assigned one of:

- `artifact_only`: a compiled object validated through BPFCompat's validator;
- `project_loader`: the project's real loader is executed in command mode;
- `framework_coupled`: meaningful execution requires project/runtime context;
- `controlled_probe`: intentionally minimal probe for a specific mechanism.

Selection criteria and exclusions must be recorded before confirmatory runs.

### Kernel environments

Include multiple distro families and architectures where execution is
reproducible. Prefer real vendor images. Rebuilds or stand-ins must be labeled
as such and must not be described as the proprietary distribution itself.

Record at least:

- distribution and release;
- architecture;
- requested kernel family;
- exact observed `uname -r`;
- BTF availability;
- image/source identity when available;
- BPFCompat profile revision;
- relevant execution mode.

## Outcome model

Primary execution outcomes:

- `compatible`
- `incompatible`
- `inconclusive`

Operational states such as infrastructure error, timeout, missing profile
result, or unavailable artifact are retained as reasons for
`inconclusive`; they must not be converted into compatibility failures.

For longitudinal comparisons, use BPFCompat's baseline/candidate comparison
semantics and retain stable, regression, improvement, existing-limitation, and
incomplete states.

## RQ1 analysis — version predictiveness

Construct simple version-derived expectations for features with documented
upstream introduction points, then compare them with observed vendor-kernel
behavior. Report disagreement rates and concrete backport/rebase cases.

Do not generalize from a single feature probe to overall kernel compatibility.

## RQ2 analysis — failure taxonomy

Count failures by normalized mechanism only where the evidence supports that
classification. Preserve an `unknown` category rather than forcing ambiguous
failures into a known class.

Report both absolute counts and rates with denominators. Separate controlled
probes from real project artifacts.

## RQ3 analysis — loader effect

For artifact/loader pairs that represent the same project and comparable test
contract, compare generic artifact validation with project-loader validation.

Report disagreements; do not assume either path is universally authoritative.
For a project's deployability question, its supported loader path is the
stronger operational evidence.

## RQ4 analysis — vendor and patch-level variation

Group observations by logical distro/kernel family while retaining exact kernel
release. Analyze changes across vendor families and, where available, patch
releases within a family.

A newer version must not be treated as monotonically "more compatible" without
observed evidence.

## Repetition and determinism

At least a sample of positive, negative, and inconclusive cases should be
rerun to estimate execution stability. Repeated outcomes should preserve the
same artifact identity and execution contract.

Environmental drift (updated vendor image, kernel package, OCI tag resolution)
must create a new exact-environment or artifact identity rather than silently
overwriting prior evidence.

## Reporting

Every table/figure used for a research claim should be generated from a
machine-readable dataset derived from raw reports. Analysis code and inputs must
be versioned with the dataset release.

Report:

- corpus size and construction rules;
- exact number of execution tuples attempted;
- compatible / incompatible / inconclusive counts;
- failure taxonomy counts with denominators;
- per-distro and per-architecture coverage;
- missing/unavailable cases;
- deviations from this protocol.

## Threats to validity

At minimum discuss:

- selection bias in the artifact corpus;
- public cloud images versus customer-modified kernels;
- proprietary distro images that cannot be redistributed;
- loader setup fidelity;
- incomplete ARM64 parity;
- distro image drift over time;
- feature probes overrepresenting isolated mechanisms;
- correlated artifacts from the same framework or project;
- limits of inferring production support from successful load/attach.

## Reproducibility boundary

The intended research artifact includes metadata and scripts needed to recreate
analysis from captured evidence. Full re-execution of all VM experiments may
require KVM, network access, vendor images, registry access, and substantial
compute; these prerequisites must be stated explicitly rather than hidden.
