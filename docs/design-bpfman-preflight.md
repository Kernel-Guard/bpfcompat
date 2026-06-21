# Design sketch: bpfman pre-flight integration

> Status: **design only / Phase 2.** Not built. Pursue after a first external
> adopter; captured here so the direction isn't lost.

## Principle

bpfcompat decides **whether/which** an eBPF program will load; bpfman does the
privileged **execute**. bpfcompat never loads BPF in the cluster — it only reads
node metadata and runs its own disposable VMs on the customer's CI/runner. This
keeps bpfcompat on its defensible wedge (pre-deployment compatibility evidence)
with **no new kernel-exploit surface** — unlike building a rival loader or a
multi-tenant BPF-running SaaS.

## The gap it fills

[bpfman](https://bpfman.io/) (CNCF; shipped by Red Hat as the OpenShift "eBPF
Manager Operator") deploys an eBPF program from an OCI bytecode image to nodes via
a `nodeSelector`. But a node's `status.nodeInfo.kernelVersion` is the *exact
backported* kernel (e.g. `4.18.0-553.el8_10`), and backported enterprise kernels
do not reveal feature support from the version. So bpfman can roll a program to
nodes where it silently fails to load. bpfcompat answers, before the rollout:
"loads on these node kernels, fails on those, here's the classified reason."

## Data flow

```
bpfman program CR ──▶ OCI bytecode image + program/attach type ──┐
K8s Node objects  ──▶ fleet matrix {distro, kernelVersion, arch} ─┼─▶ bpfcompat run
                          └─ map each node kernel → profile ──────┘   (VMs on CI /
                                                                       self-hosted)
                                                                          │
                              classified pass/fail matrix per node kernel │
                          ┌── PASS on required kernels ─▶ allow rollout ───┘
                          └── FAIL ─▶ gate / annotate (which nodes, why)
                                          bpfman (privileged) still does the load
```

Inputs and their sources:
1. **Artifact** — the program CR already references bytecode as an OCI image;
   bpfcompat pulls the same image (registry-artifact support already exists).
2. **Target kernels** — read-only K8s API: `Node.status.nodeInfo` →
   `kernelVersion`, `osImage`, `architecture` (the "fleet-aware matrix").
3. **Profiles** — map each distinct node kernel to a curated bpfcompat profile.
   This is where the enterprise catalog pays off — real clusters run
   RHEL/Amazon/Oracle nodes, now proven (`docs/case-study-enterprise-kernels.md`).

## Two shapes

**Shape A — CI / GitOps pre-flight (MVP, build first).** In the pipeline that
publishes the bytecode image + bpfman CR, run the bpfcompat GitHub Action against
the fleet matrix; block/annotate the PR if the program won't load on required node
kernels. Zero cluster privilege, no new infra.

**Shape B — admission / controller pre-flight (later).** A validating admission
webhook intercepts a bpfman program CR before apply. Because VM validation takes
minutes, it **cannot** run inside admission — a controller/CronJob precomputes a
compatibility cache (image × fleet-kernel → verdict) asynchronously; the webhook
just looks it up and denies/warns. That cache + controller is the part that starts
to look like a real product surface.

## What to build (later, if pursued)
- `bpfcompat fleet-matrix --from-kube` — read Node objects → emit a matrix YAML,
  mapping `(distro, kernelVersion, arch)` to a profile; flag kernels with no
  curated profile as **"uncovered"** (honest; a catalog-growth signal).
- `adapters/bpfman/` — given a bpfman program CR, extract OCI image +
  program/attach type → bpfcompat artifact + manifest.
- Documented "gate your bpfman CRs in CI" recipe (Shape A).
- (Shape B) the evidence-cache controller + admission webhook.

## Trust & security posture
- bpfcompat never loads BPF in-cluster or on shared infra; only reads Node
  metadata + runs disposable VMs on the customer's CI/runner. bpfman keeps the
  privileged load. No untrusted-multi-tenant execution, no new exploit surface.
- Read-only K8s RBAC (get/list Nodes + program CRs).

## Why this shape is right
- **Complements** bpfman (CNCF/Red Hat) instead of competing → a credible OSS
  integration target (joins Falco/Tracee/Aya on the adoption list).
- **Leverages the enterprise catalog moat** exactly where CO-RE/bpfman give the
  least guarantee — backported RHEL/Amazon fleets.
- Keeps bpfcompat on its defensible pre-deployment wedge.

## Caveats
- Phase 2; pursue only after OSS adoption signal.
- Shape B's value depends on the async evidence cache (admission can't boot VMs).
- Coverage is bounded by the curated catalog — "uncovered" must be reported, not
  hidden (and it drives the paid-catalog loop).
