# Contributing

Thanks for your interest in bpfcompat. This document is the short,
opinionated version of how to work with the codebase.

By participating, you agree to follow the
[Code of Conduct](CODE_OF_CONDUCT.md). Project roles and decision-making are
described in [GOVERNANCE.md](GOVERNANCE.md).

## Ground rules

1. **Treat other contributors professionally.** Follow the Code of Conduct in
   project spaces and when representing the project elsewhere.
2. **Security disclosures go through `SECURITY.md`, not public issues.** If
   you've found a vulnerability, please email the address listed there and
   wait for a coordinated disclosure window before publishing.
3. **Tests are mandatory** for behavior changes. The CI gate runs
   `go test -race`, `go vet`, `golangci-lint`, and `govulncheck`. Bench/fuzz
   additions are welcome but not required for every PR.
4. **No `panic()` in production code.** The only acceptable
   process-terminating call is `os.Exit` from `cmd/bpfcompat/main.go`.
5. **Don't loosen the JSON body cap or DisallowUnknownFields.** They're load
   bearing for the API version contract (see `docs/openapi.yaml` and the
   `/api/v1/` move). Changes that need a richer wire shape should ride a
   `v2` route, not relax the v1 one.

## Local development

```bash
make build              # produces bin/bpfcompat with version ldflags
make validator-static   # builds the C validator (needs libbpf-dev + clang)
make test               # go test ./...
make openapi-sync       # copies docs/openapi.yaml into the embed location
```

Run the API server locally:

```bash
BPFCOMPAT_API_WRITE_KEY=dev-key \
BPFCOMPAT_API_ENABLE_METRICS=true \
BPFCOMPAT_LOG_LEVEL=debug \
BPFCOMPAT_LOG_FORMAT=text \
./bin/bpfcompat serve --addr 127.0.0.1:8080
```

For VM-backed validation you'll need `qemu-system-x86_64`, `qemu-img`,
`ssh`, `scp`, `jq`, `pkg-config`, `libbpf-dev`, and `/dev/kvm`. `make doctor`
checks for them.

## Workflow

1. Open an issue (or comment on an existing one) describing the change
   before you start a non-trivial PR. Security-adjacent changes especially
   benefit from an early design conversation.
2. Branch from `main`. Keep PRs focused — one logical change per PR.
3. Run `golangci-lint run --new-from-rev=origin/main` locally before pushing.
   Pre-existing lint debt is tracked separately; new code should be clean.
4. Update `CHANGELOG.md` under the `[Unreleased]` heading with a one-line
   summary of your change. Categorize as Added / Changed / Fixed / Security.
5. If you touch `docs/openapi.yaml`, run `make openapi-sync` and commit the
   updated `internal/api/openapi_spec.yaml`. CI fails on drift.

## Code style

- `gofmt` + `goimports` enforced via `golangci-lint`.
- Public types and exported functions need at least a one-line doc comment.
- Comments explain **why**, not what. Don't repeat the code in English.
  Surrounding context (related security finding, historical bug, related
  design decision) is what we want to capture.
- Tests live next to the code (`foo.go` ↔ `foo_test.go`). Integration
  tests that span packages can live under `internal/<pkg>/integration`.
- Errors: wrap with `%w` and surface domain sentinels (`registry.ErrNotFound`,
  `cloudregistry.ErrUnauthorized`) so handlers can map to status codes
  without string matching.

## Commit messages

Imperative mood, capitalized first line under ~70 characters, optional body
wrapped at 80. Reference the issue number when relevant. Example:

```
api: refuse new validate submissions during shutdown drain (#42)

Bind the global shutting flag at the top of handleValidateStart so callers
get a clean 503 instead of starting a job we're about to cancel mid-flight.
Goroutines launched before the flag flipped continue to a normal terminal
state and drain via inflight.WaitGroup.
```

## Adding a new HTTP route

1. Register via `registerAPIRoute(mux, "/your/route", handler)` so both
   `/api/v1/your/route` and the legacy `/api/your/route` get the same
   handler.
2. Pick the right auth gate:
   - State change → `requireWriteAuthorizationForAction(w, r, "your_action")`
   - Read-only → `requireReadAuthorizationForAction(w, r, "your_action")`
3. Use `decodeJSONBody(w, r, &req)` for JSON bodies — never `json.NewDecoder`
   directly (the helper enforces size/unknown-field/smuggling rules).
4. Record the route in `docs/openapi.yaml` and re-run `make openapi-sync`.
5. Add a tests file that exercises the auth gate, the happy path, and at
   least one error path.
6. If the handler triggers a runtime side effect (fetch, execute, registry
   change), bump the corresponding metric counter via the helpers in
   `internal/api/metrics.go`.

## Adding a new env knob

1. Define the constant in the package that consumes it (don't centralize —
   the consumer documents the semantics).
2. Surface the default + description in the env reference (`docs/env-reference.md`)
   and via `bpfcompat env`.
3. Document any operational risk (e.g. `BPFCOMPAT_FETCH_ALLOW_INTERNAL_HOSTS`
   carries an SSRF unlock) in `SECURITY.md` under the hardening guidance
   section.

## License

By submitting a contribution you agree to license it under the terms in
[`LICENSE`](LICENSE) (Apache-2.0). See the appendix in that file for the
required boilerplate header on new source files.
