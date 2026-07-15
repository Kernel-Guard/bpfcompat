# Adopters and Public Evaluations

bpfcompat is pre-1.0. This file separates confirmed use from project-maintained
compatibility studies so that a test result is never misrepresented as an
upstream project's adoption or endorsement.

## Confirmed adopters

No organization has yet requested a public listing as a production or CI
adopter.

If you use bpfcompat, please open the
[adopter issue form](https://github.com/Kernel-Guard/bpfcompat/issues/new?template=adopter.yml)
or submit a pull request. Private confirmations can be sent to
`contact@kernelguard.net`; the project will not publish a name or logo without
permission.

## Public evaluations and integration discussions

The following entries are public technical work, not claims of adoption or
endorsement:

| Project | Public evidence | Status |
|---|---|---|
| Falco | [Compatibility case study](docs/case-study-falco-modern-bpf.md) and [falcosecurity/libs#3024](https://github.com/falcosecurity/libs/pull/3024) | Proposed scheduled validation using Falco's loader path; upstream pull request under review |
| KubeArmor | [KubeArmor#2683](https://github.com/kubearmor/KubeArmor/issues/2683) | Public discussion of bpfcompat and VM-test scope; no adoption claim |
| Inspektor Gadget | [OCI gadget case study](docs/case-study-inspektor-gadget.md) | bpfcompat-maintained validation of published gadgets; no adoption claim |

## What an adopter entry should contain

- organization or project name and public URL;
- how bpfcompat is used: CLI, GitHub Action, command mode, or library;
- the kernel, distribution, architecture, or artifact scope;
- whether use is production, release gating, scheduled CI, or evaluation;
- a public issue, workflow, report, or short confirmation when available; and
- explicit permission to publish the name and, separately, any logo.

Listings are informational. They do not imply commercial endorsement, support,
or a guarantee that future releases remain compatible. An adopter can request
an update or removal at any time.
