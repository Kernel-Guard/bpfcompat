# Funding bpfcompat

bpfcompat is an independent, Apache-2.0 compatibility project for testing
compiled eBPF artifacts against real Linux kernels. Funding helps keep the
kernel matrix current, expand architecture coverage, and maintain trustworthy,
reproducible evidence for the eBPF ecosystem.

## Ways to support the project

### GitHub Sponsors

Individuals and organizations can provide recurring or one-time support through
[GitHub Sponsors](https://github.com/sponsors/ErenAri).

### Infrastructure sponsorship

The project also accepts useful in-kind support, especially:

- native ARM64 machines with KVM access;
- CI compute and artifact storage;
- licensed or otherwise authorized access to vendor kernel images;
- mirrors or bandwidth for reproducible image acquisition; and
- independent security review, documentation, or testing services.

Infrastructure offers should be sent to `contact@kernelguard.net`. Please
describe the resource, duration, usage limits, and whether public recognition is
required.

### Organization sponsorships and funded work

Organizations that depend on broad Linux compatibility can fund ongoing
maintenance or a public, scoped work package. Example starting points are:

| Path | Suggested level | Typical outcome |
|---|---:|---|
| Infrastructure | $500/month | Public matrix compute, storage, and images |
| Ecosystem | $1,500/month | Upstream integration or public study |
| Sustaining | $25,000/year | Public maintenance or coverage scope |
| Strategic | $50,000+ | Architecture, distro, research, or security scope |

These are starting points, not automatic service tiers. Scope, recognition, and
deliverables must be agreed in writing before work begins. Commercial support,
private integrations, and response-time commitments require a separate
agreement and are not implied by open-source sponsorship.

For a one-page overview suitable for an engineering lead, OSPO, or grant
reviewer, see the [sponsor brief](docs/sponsor-brief.md).

## Current funding priorities

1. **Native ARM64 validation:** move the ARM64 lane from cross-architecture
   emulation to repeatable native KVM execution.
2. **Vendor-kernel freshness:** keep enterprise and cloud distribution images,
   provenance, and evidence current as kernels change.
3. **Adopter integrations:** validate real project loaders rather than only
   generic object loading, then publish reproducible case studies.
4. **Release and security sustainability:** maintain signed releases, SBOMs,
   provenance, dependency review, threat-model updates, and vulnerability
   response.
5. **Stable interfaces:** harden the CLI, GitHub Action, report schema, and
   embeddable library on the path to 1.0.

## Independence and conflicts of interest

Funding expands coverage; it does not purchase a favorable result.

- Sponsors cannot change, suppress, or pre-approve compatibility verdicts.
- The same validation methodology and evidence requirements apply to sponsors
  and non-sponsors.
- Material sponsored work is identified in its pull request, report, or release
  notes.
- A sponsor receives no governance, release, or security-disclosure privilege
  unless separately earned through the public maintainer process.
- The maintainers may decline funding that conflicts with the project's
  security, technical independence, license, or community interests.

Maintainers with a material financial conflict must disclose it and, when
another qualified maintainer exists, recuse themselves from the affected
decision. See [GOVERNANCE.md](GOVERNANCE.md).

## Recognition and reporting

Confirmed financial and infrastructure supporters are recorded in
[SPONSORS.md](SPONSORS.md). Recognition is an acknowledgement, not an
endorsement of a sponsor or its products.

When the project receives material funding, maintainers will publish a short
periodic summary of the work it enabled. Private financial, security, or
contractual information will not be published.
