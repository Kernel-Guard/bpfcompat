# Public Release Checklist

Use this checklist before making a repository public or creating a public
mirror.

## Safe Publication Path

Do **not** change the visibility of a private repository if old commits contain
private strategy docs, generated evidence, cloud resource metadata, emails, or
tokens. Deleting those files in a later commit does not remove them from git
history.

Recommended path:

1. Keep the current private repository private.
2. Clean the working tree.
3. Create a fresh public repository from the cleaned tree with a new initial
   commit, or rewrite history with a dedicated tool such as `git filter-repo`
   and then force-push only after review.
4. Rotate any credential that ever appeared in the old repository history.

For a fresh public repo:

```bash
git archive --format=tar HEAD | tar -x -C /tmp/bpfcompat-public
cd /tmp/bpfcompat-public
git init
git add .
git commit -m "Initial public release"
```

Review the new repository before pushing it.

## File Hygiene

Required:

- No tracked `.bpfcompat/`, `evidence/`, generated `.bpf.o` files, or real
  generated files under `reports/` / `vm/cache/`. `.gitkeep` placeholders are
  fine.
- No private planning, sponsorship, outreach, or old product-planning
  documents.
- No live cloud subscription IDs, resource IDs, storage account names, tenant
  IDs, private emails beyond the intended security contact, or access tokens.
- No generated proof bundles committed by default.
- No broken Makefile targets pointing at removed scripts.

Useful checks:

```bash
git status --short
git ls-files evidence .bpfcompat
git ls-files reports vm/cache | grep -v '/.gitkeep$'
rg -n "(BEGIN .*PRIVATE KEY|AKIA|AZURE_CLIENT_SECRET|8008b8ad|cloudapp.azure.com)" . --glob '!docs/public-release-checklist.md'
rg -n "(sponsorship|private-deployment|old product-planning)" README.md docs scripts Makefile --glob '!docs/public-release-checklist.md'
```

The second search is not a secret scan; it is a language/hygiene check so the
public repo reads like an engineering project.

## Project Metadata

Required:

- `LICENSE`
- `SECURITY.md`
- `CONTRIBUTING.md`
- `.github/workflows/ci.yml`
- `.github/workflows/release-artifacts.yml`
- `docs/openapi.yaml`
- `docs/env-reference.md`

Recommended:

- Branch protection on `main`.
- GitHub Security Advisories enabled.
- Dependabot or dependency-review workflow enabled.
- Release tags signed by a trusted maintainer key.

## Verification

Run before publishing:

```bash
make test
go vet ./...
golangci-lint run --timeout=5m
govulncheck ./...
git diff --check
```

Optional heavier checks:

```bash
make acceptance-dev-one
make acceptance-suite-dev-one
make acceptance-firecracker-dev-one
make acceptance-upstream-kernel
```

## Public Positioning

Use this wording:

- "open-source eBPF compatibility evidence and CI gate"
- "VM-backed validation across Linux kernel profiles"
- "runtime artifact decisioning proof"

Avoid these claims unless the separate production gates pass:

- "production runtime loader"
- "production multi-tenant SaaS"
- "fully managed artifact registry"
