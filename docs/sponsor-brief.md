# bpfcompat Sponsor Brief

## The problem

CO-RE makes eBPF artifacts portable in principle, but it does not prove that a
compiled object or a project's real loader will work across the kernels its
users run. Vendor backports, missing BTF, map and attach support, kernel config,
architecture, and loader behavior still cause release-time and customer-time
failures.

bpfcompat turns that uncertainty into a reproducible CI result by booting real
distribution kernels, executing real load and attach paths, and publishing
structured evidence.

## What exists today

- QEMU/KVM validation against real vendor cloud images and kernels;
- x86_64 and ARM64 profiles across Ubuntu, Debian, enterprise Linux, Oracle
  UEK, Amazon Linux, SUSE, upstream kernels, and CoreOS-family systems;
- command mode for testing a project's own loader binary and exit code;
- an embeddable Go pre-load validation library;
- JSON, Markdown, GitHub Action, and public matrix reports;
- public Falco, Inspektor Gadget, enterprise-kernel, and RHCOS/OpenShift
  compatibility studies; and
- Apache-2.0 licensing, CodeQL, OpenSSF Scorecard, signed releases, SBOMs, and
  SLSA build provenance.

The supported product boundary is the CLI and GitHub Action in CI. The web/API
and runtime decisioning tracks remain experimental.

## Who benefits

- eBPF security, observability, networking, and profiling projects;
- Linux distribution and cloud platform engineering teams;
- vendors supporting customer fleets with mixed kernel and architecture
  baselines; and
- foundations and research groups improving eBPF safety and portability.

## What sponsorship enables

The immediate priorities are:

1. repeatable native ARM64 KVM validation;
2. continuous vendor-kernel image and evidence freshness;
3. upstream integrations that execute each project's real loader;
4. stable CLI, Action, report-schema, and library contracts; and
5. sustainable release, security, documentation, and vulnerability-response
   work.

Success is measured through reproducible public outputs: current kernel
profiles, versioned reports, signed releases, merged upstream integrations,
confirmed adopters, and documented regressions caught before release.

## Three useful forms of support

### 1. Financial support

Recurring sponsorship sustains matrix maintenance. Annual or grant funding can
support a larger public work package such as native ARM64 coverage, a new vendor
family, or an independent security review.

### 2. Compute and storage

Native ARM64 KVM hosts, CI capacity, artifact storage, mirrors, and bandwidth
directly increase the coverage the project can validate regularly.

### 3. Authorized images and engineering access

Vendor subscriptions, test images, and a technical contact make it possible to
validate the exact kernels customers run rather than a public approximation.

## Independence guarantee

A sponsor funds coverage, not the answer. Sponsors cannot buy a passing result,
suppress a finding, bypass public review, or obtain governance rights through
payment. Material sponsored work is disclosed and uses the same evidence rules
as all other compatibility claims.

## Start a conversation

See [FUNDING.md](../FUNDING.md) for sponsorship paths and the full independence
policy, or contact `contact@kernelguard.net` with:

- the kernels, distributions, architectures, or project loaders that matter;
- the desired public outcome;
- whether support is financial, infrastructure, or engineering access; and
- any timing, recognition, or procurement requirements.
