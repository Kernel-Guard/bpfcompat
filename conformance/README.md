# bpfcompat Verified Compatibility Preview

This directory contains versioned, machine-evaluable compatibility profiles.
It is a preview conformance program, not an independent certification program.

A conformance decision is scoped to:

- one immutable subject digest;
- one versioned profile and matrix;
- one bpfcompat report and its exact test invocation;
- the required kernels actually exercised by that report; and
- the time and verifier identity recorded in the decision.

The evaluator has three outcomes:

- `conformant`: every required assertion passed;
- `nonconformant`: the tested product behavior failed at least one required
  assertion; and
- `inconclusive`: the test contract, evidence, or infrastructure was incomplete.

Only `conformant` decisions produce an in-toto Simple Verification Result.
Every valid evaluation produces a decision and an in-toto Test Result, including
failed and inconclusive evaluations.

The first profile is [Falco modern_bpf v0.1](falco-modern-bpf-v0.1/spec.md).
