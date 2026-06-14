# syntax=docker/dockerfile:1.7
#
# Multi-stage build for bpfcompat. The final image carries the Go binary
# only — qemu/kvm/libbpf are dependencies of the validate flow that runs
# the C validator inside guest VMs, so they belong on the host that
# instantiates this container with /dev/kvm passed through, not in the
# image itself. If you want to embed the C validator and run host-side
# validation from the container, see the "with-validator" target.
#
# Build:
#   docker build -t bpfcompat:dev .
#   docker build --target with-validator -t bpfcompat:dev-validator .
#
# Run:
#   docker run --rm -p 8080:8080 \
#     -v $(pwd)/.bpfcompat:/data/.bpfcompat \
#     bpfcompat:dev serve --addr :8080 --workdir /data/.bpfcompat
#
# Security notes:
#   - Final stage is distroless/static so there's no shell, no package
#     manager, and no resolver to attack. CVE surface drops to "Go runtime
#     and our own code".
#   - We run as the unprivileged 'nonroot' uid (65532) baked into the
#     distroless image. The API server doesn't need root.
#   - Build is reproducible: -trimpath strips host paths and -buildid=""
#     drops the build-id, so two builds of the same commit hash produce
#     byte-identical binaries.

ARG GO_VERSION=1.25

#######################################
# 1. Builder
#######################################
FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-bookworm@sha256:bbb255b0e131db500cf0520adc97441d2260cf629c7fa7e39e025ddf53995a24 AS builder

WORKDIR /src

# Copy module manifests first so layer caching skips the download when only
# source files change. vendor/ is mounted via COPY in the bulk step below;
# we don't run `go mod download` separately because we always use the
# vendored set inside the container.
COPY go.mod go.sum ./
COPY vendor/ ./vendor/

# Copy the rest of the source. .dockerignore filters out caches, evidence,
# and on-host artifacts so a bloated workspace doesn't poison the image.
COPY . .

ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown

ENV CGO_ENABLED=0 \
    GOOS=${TARGETOS} \
    GOARCH=${TARGETARCH}

RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    go build -mod=vendor -trimpath \
      -ldflags "-s -w -buildid= \
        -X github.com/kernel-guard/bpfcompat/internal/version.Version=${VERSION} \
        -X github.com/kernel-guard/bpfcompat/internal/version.Commit=${COMMIT} \
        -X github.com/kernel-guard/bpfcompat/internal/version.BuildDate=${BUILD_DATE}" \
      -o /out/bpfcompat ./cmd/bpfcompat

#######################################
# 2. Final image (default): Go binary only
#######################################
FROM gcr.io/distroless/static-debian12:nonroot@sha256:d093aa3e30dbadd3efe1310db061a14da60299baff8450a17fe0ccc514a16639 AS final

# /data is the conventional mount point for the workdir. Override via
#   docker run -v /host/path:/data/.bpfcompat ...
# or via --workdir on the CLI.
WORKDIR /data

COPY --from=builder /out/bpfcompat /usr/local/bin/bpfcompat

# distroless images carry an unprivileged 'nonroot' user (uid 65532) already.
USER nonroot:nonroot

EXPOSE 8080

# Entry point is the binary; subcommand is passed via CMD so the typical
# operator override is just `docker run bpfcompat:dev <subcommand>`.
ENTRYPOINT ["/usr/local/bin/bpfcompat"]
CMD ["serve", "--addr", ":8080", "--workdir", "/data/.bpfcompat"]

#######################################
# 3. Optional final stage with the C validator bundled
#######################################
# This target shouldn't be the default because building the validator pulls
# in libbpf/clang/llvm and bloats the image. Build explicitly when you need
# host-side runtime execute from inside the container:
#   docker build --target with-validator -t bpfcompat:dev-validator .
FROM debian:bookworm-slim@sha256:96e378d7e6531ac9a15ad505478fcc2e69f371b10f5cdf87857c4b8188404716 AS validator-builder

RUN apt-get update -y && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      build-essential \
      clang \
      llvm \
      libbpf-dev \
      libelf-dev \
      zlib1g-dev \
      pkg-config \
      make && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY validator/c-libbpf ./validator/c-libbpf
COPY Makefile ./Makefile
RUN make -C validator/c-libbpf clean all LIBBPF_LINK_MODE=static

FROM gcr.io/distroless/cc-debian12:nonroot@sha256:b0ae8e989418b458e0f25489bc3be523718938a2b70864cc0f6a00af1ddbd985 AS with-validator
WORKDIR /data
COPY --from=builder /out/bpfcompat /usr/local/bin/bpfcompat
COPY --from=validator-builder /src/validator/c-libbpf/bin/bpfcompat-validator \
     /usr/libexec/bpfcompat/bpfcompat-validator
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/bpfcompat"]
CMD ["serve", "--addr", ":8080", "--workdir", "/data/.bpfcompat"]
