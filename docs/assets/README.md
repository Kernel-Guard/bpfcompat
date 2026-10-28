# Listing assets

Prepared submissions for third-party directories. Kept here so a submission is
a copy-paste, not a rewrite.

## `upstream-ci.svg`

A compact, theme-aware README strip linking to the public upstream CI evidence.
The project names are plain text, not third-party logos. It records scheduled
CI integration, consistent with [ADOPTERS.md](../../ADOPTERS.md).

Sources: [Falco's merged integration](https://github.com/falcosecurity/libs/pull/3024)
and [workflow](https://github.com/falcosecurity/libs/blob/master/.github/workflows/bpfcompat-compatibility.yml);
[Inspektor Gadget's merged integration](https://github.com/inspektor-gadget/inspektor-gadget/pull/5708)
and [workflow](https://github.com/inspektor-gadget/inspektor-gadget/blob/main/.github/workflows/gadget-kernel-compatibility.yml).

## `bpfcompat-logo.svg`

Mark-only (no text). Directory guidelines — CNCF landscape and ebpf.io both —
reject font-rendered `<text>`, because it does not render identically on a
machine without the font; the usual fix is converting text to outlines, so a
mark with no text sidesteps it entirely. No embedded raster either.

## `ebpf-io-entry.json`

An entry for [ebpf.io](https://ebpf.io)'s project landscape, matching the shape
in `src/data/pages/applications/emerging.json` of
[`ebpf-io/ebpf.io-website`](https://github.com/ebpf-io/ebpf.io-website).

Submitting also requires adding the logo to their asset pipeline and wiring
`logoName` to it, so the PR touches more than the JSON. Ask in `#ebpf-website`
on Cilium Slack first — their CONTRIBUTING covers blog posts only and says
nothing about landscape entries, so the process is worth confirming rather than
guessing.

`githubStars` is a snapshot and needs refreshing at submission time.

## Timing (read before submitting)

Star count is low relative to the projects already listed. The stronger
credential is not stars but that **falcosecurity/libs runs this weekly in CI** —
lead with that. If a listing is declined, it is a timing problem, not a
rejection of the work; re-submit once there are two or three named consumers.
