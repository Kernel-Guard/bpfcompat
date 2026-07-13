# Governance

## Project model

bpfcompat is an Apache-2.0 open-source project hosted in the `Kernel-Guard`
GitHub organization. During the pre-1.0 phase it uses maintainer-led governance:
maintainers are accountable for technical quality, security, releases, and the
long-term interests of the project, while substantive decisions remain visible
and open to community input.

The current maintainers and their scope are listed in
[MAINTAINERS.md](MAINTAINERS.md).

## Roles

### Contributors

Anyone who participates through issues, documentation, code, testing, design
feedback, or compatibility evidence is a contributor. Contributors must follow
the [Code of Conduct](CODE_OF_CONDUCT.md) and the process in
[CONTRIBUTING.md](CONTRIBUTING.md).

### Maintainers

Maintainers review and merge changes, triage issues, protect the compatibility
methodology, manage releases, and respond to security reports. Repository or
release access is granted only to the minimum scope needed for those duties.

### Project lead

The project lead coordinates releases and resolves decisions that cannot reach
consensus. While there is only one active maintainer, the project lead is the
final decision maker. This is an explicit pre-1.0 limitation, not a claim of
vendor-neutral governance.

## Decision making

Routine changes follow normal pull-request review. Substantive decisions should
be proposed in a public issue or pull request and include:

- the problem and affected users;
- security and compatibility consequences;
- alternatives considered;
- migration or rollback implications; and
- any relevant financial or organizational conflict.

The preferred decision process is lazy consensus: maintainers seek agreement
and proceed when material objections have been addressed. When practical, major
changes remain open for comment for at least 72 hours. A maintainer may act
faster for security incidents, broken releases, data-loss risks, or CI outages,
and must document the reason afterward when disclosure is safe.

If consensus cannot be reached, the project lead records a decision and its
rationale. Decisions can be revisited when new technical evidence appears.

## Releases and compatibility claims

- A maintainer approves releases after required CI and release checks pass.
- Compatibility claims must be backed by reproducible evidence from the kernel
  or loader being described.
- A case study must distinguish project-maintained reproduction from an
  upstream project's official adoption or endorsement.
- Breaking changes before 1.0 must be documented in the changelog and include a
  practical migration path when possible.

## Becoming a maintainer

Maintainers are selected for sustained, trustworthy work rather than employer,
sponsorship, or a fixed contribution count. Evidence normally includes several
of the following:

- repeated, high-quality contributions over time;
- careful review of other contributors' work;
- sound security and compatibility judgment;
- reliable issue triage or release work;
- constructive participation under the Code of Conduct; and
- willingness to accept ongoing maintenance responsibility.

An existing maintainer nominates the candidate in a public issue or pull
request. Active maintainers approve the nomination by consensus. The decision
and granted access scope are recorded in [MAINTAINERS.md](MAINTAINERS.md).

A maintainer who steps away can request emeritus status. Access may be reduced
after prolonged inactivity or removed immediately for account compromise,
serious security risk, or repeated Code of Conduct violations. Except in urgent
security cases, removal requires a documented maintainer decision and an
opportunity for the affected maintainer to respond.

## Sponsorship and conflicts

Sponsorship does not grant commit access, roadmap control, a favorable verdict,
or advance access to security reports. Maintainers must disclose material
interests that could reasonably affect a decision. When another qualified
maintainer exists, the conflicted maintainer should recuse themselves.

The full funding and independence policy is in [FUNDING.md](FUNDING.md).

## Security and conduct matters

Vulnerabilities follow [SECURITY.md](SECURITY.md), including private handling
when public discussion would create risk. Community conduct reports follow
[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). Sensitive details may remain private,
but maintainers should publish a non-sensitive outcome when appropriate.

## Changing this document

Governance changes use a public pull request. Unless the change fixes an urgent
security or legal problem, it should remain open for comment for at least seven
days. The changelog must record accepted governance changes.
