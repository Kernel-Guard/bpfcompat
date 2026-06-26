GO ?= go
CLANG ?= clang

# Build identity injected into internal/version at link time. Each is
# overridable from the command line (e.g. `make build VERSION=v1.0.0`) so a
# release pipeline can stamp a tagged release without touching the source.
VERSION    ?= $(shell git describe --tags --dirty --always 2>/dev/null || echo 0.1.0-dev)
COMMIT     ?= $(shell git rev-parse --short=12 HEAD 2>/dev/null || echo unknown)
BUILD_DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
VERSION_PKG := github.com/kernel-guard/bpfcompat/internal/version
LDFLAGS    ?= -X $(VERSION_PKG).Version=$(VERSION) \
              -X $(VERSION_PKG).Commit=$(COMMIT) \
              -X $(VERSION_PKG).BuildDate=$(BUILD_DATE)
GO_BUILD_FLAGS ?= -trimpath -ldflags '$(LDFLAGS)'

.PHONY: all deps vendor doctor doctor-virtme doctor-firecracker doctor-arm64-kvm firecracker-install firecracker-kernel-install firecracker-runnable firecracker-preflight arm64-kvm-preflight build test test-vendor tidy validator validator-dynamic validator-static pkg-embed-validator lib-hostload examples examples-arm64 oss-examples oss-evidence compatibility-site clean vm-ubuntu-22 vm-ubuntu-22-arm64 vm-image-fcos vm-images vm-images-tier1 vm-images-extended vm-images-expanded-2026 vm-images-expanded-2026-dry-run vm-images-latest-kernel matrix-runnable matrix-runnable-strict matrix-runnable-keep-manual latest-kernel-runnable upstream-kernel-runnable manual-image-check manual-image-check-strict profile-catalog-audit matrix-readiness runtime-selector-proof runtime-delivery-proof production-runtime-drill beta-tech-check tech-stability production-tech-check acceptance-dev-one acceptance-functional-dev-one acceptance-suite-dev-one acceptance-arm64-smoke acceptance-latest-kernel acceptance-upstream-kernel acceptance-firecracker-dev-one acceptance acceptance-expanded-runnable acceptance-evidence serve azure-provision-vm azure-bootstrap-vm azure-provision-foundation azure-production-boundary-proof azure-configure-tls azure-rotate-registry-secret

all: build validator

deps:
	$(GO) mod download

vendor:
	$(GO) mod vendor

doctor:
	@command -v $(GO) >/dev/null || (echo "missing go" && exit 1)
	@command -v $(CLANG) >/dev/null || (echo "missing clang" && exit 1)
	@command -v qemu-system-x86_64 >/dev/null || (echo "missing qemu-system-x86_64" && exit 1)
	@command -v qemu-system-aarch64 >/dev/null || echo "warning: qemu-system-aarch64 not found (ARM64 profiles require an ARM64-capable runner)"
	@command -v qemu-img >/dev/null || (echo "missing qemu-img" && exit 1)
	@command -v ssh >/dev/null || (echo "missing ssh" && exit 1)
	@command -v scp >/dev/null || (echo "missing scp" && exit 1)
	@command -v jq >/dev/null || (echo "missing jq" && exit 1)
	@command -v cloud-localds >/dev/null || echo "warning: cloud-localds not found (RHEL 8 profile will use vvfat seed fallback)"
	@command -v pkg-config >/dev/null || (echo "missing pkg-config" && exit 1)
	@pkg-config --exists libbpf || (echo "missing libbpf-dev/pkg-config metadata" && exit 1)
	@pkg-config --exists libelf || (echo "missing libelf-dev/pkg-config metadata" && exit 1)
	@pkg-config --exists zlib || (echo "missing zlib-dev/pkg-config metadata" && exit 1)
	@test -e /dev/kvm || (echo "missing /dev/kvm" && exit 1)

doctor-virtme: doctor
	@command -v curl >/dev/null || (echo "missing curl" && exit 1)
	@command -v vng >/dev/null || (echo "missing virtme-ng executable: vng" && exit 1)

doctor-firecracker:
	bash scripts/firecracker-preflight.sh

doctor-arm64-kvm:
	bash scripts/arm64-kvm-preflight.sh

firecracker-install:
	bash scripts/install-firecracker.sh

firecracker-kernel-install:
	bash scripts/install-firecracker-kernel.sh

firecracker-runnable:
	bash scripts/generate-firecracker-matrix.sh

firecracker-preflight: doctor-firecracker

arm64-kvm-preflight: doctor-arm64-kvm

build:
	mkdir -p bin
	$(GO) build $(GO_BUILD_FLAGS) -o bin/bpfcompat ./cmd/bpfcompat

test:
	$(GO) test ./...

test-vendor:
	$(GO) test -mod=vendor ./...

tidy:
	$(GO) mod tidy

# openapi-sync copies the canonical OpenAPI doc (docs/openapi.yaml) into the
# internal/api package so go:embed picks up the change at build time. CI runs
# this and fails if the two have drifted, so a spec edit can't ship without
# the embedded copy being updated.
openapi-sync:
	cp docs/openapi.yaml internal/api/openapi_spec.yaml

openapi-check: openapi-sync
	@if ! git diff --quiet -- internal/api/openapi_spec.yaml; then \
	  echo "internal/api/openapi_spec.yaml drifted from docs/openapi.yaml — run \`make openapi-sync\` and commit." >&2; \
	  exit 1; \
	fi

# env-docs regenerates docs/env-reference.md from the in-code catalog
# (internal/envref). CI runs env-docs-check and fails if the on-disk file
# drifts from the catalog, so a missed env entry can't ship without the
# doc update.
env-docs: build
	./bin/bpfcompat env --markdown > docs/env-reference.md

env-docs-check: env-docs
	@if ! git diff --quiet -- docs/env-reference.md; then \
	  echo "docs/env-reference.md drifted from internal/envref — run \`make env-docs\` and commit." >&2; \
	  exit 1; \
	fi

validator:
	$(MAKE) -C validator/c-libbpf clean all LIBBPF_LINK_MODE=dynamic

validator-dynamic:
	$(MAKE) -C validator/c-libbpf clean all LIBBPF_LINK_MODE=dynamic

validator-static:
	$(MAKE) -C validator/c-libbpf clean all LIBBPF_LINK_MODE=static

# pkg-embed-validator builds the static validator and stages it under
# pkg/bpfcompat/validators/ so the embeddable library (`-tags hostload`) can
# go:embed it. Defaults to the host arch; cross-stage with e.g.
# `make pkg-embed-validator CC=aarch64-linux-gnu-gcc LIB_EMBED_ARCH=arm64`.
LIB_EMBED_ARCH ?= $(shell uname -m | sed -e 's/x86_64/amd64/' -e 's/aarch64/arm64/')
LIB_VALIDATOR_DIR := pkg/bpfcompat/validators

pkg-embed-validator: validator-static
	@mkdir -p $(LIB_VALIDATOR_DIR)
	cp validator/c-libbpf/bin/bpfcompat-validator \
	  $(LIB_VALIDATOR_DIR)/bpfcompat-validator-$(LIB_EMBED_ARCH)
	@echo "staged static validator for $(LIB_EMBED_ARCH) -> $(LIB_VALIDATOR_DIR)/bpfcompat-validator-$(LIB_EMBED_ARCH)"

# lib-hostload builds the embeddable library with host-kernel loading enabled,
# staging the embedded validator first.
lib-hostload: pkg-embed-validator
	$(GO) build -tags hostload ./pkg/bpfcompat/...

BPF_TARGET_ARCH ?= x86
BPF_ARCH_INCLUDE ?= /usr/include/x86_64-linux-gnu

examples:
	$(CLANG) -O2 -g -target bpf -D__TARGET_ARCH_$(BPF_TARGET_ARCH) -I$(BPF_ARCH_INCLUDE) \
	  -c examples/simple-pass/simple_pass.bpf.c \
	  -o examples/simple-pass/simple_pass.bpf.o
	$(CLANG) -O2 -g -target bpf -D__TARGET_ARCH_$(BPF_TARGET_ARCH) -I$(BPF_ARCH_INCLUDE) \
	  -c examples/attach-warn/attach_warn.bpf.c \
	  -o examples/attach-warn/attach_warn.bpf.o
	$(CLANG) -O2 -g -target bpf -D__TARGET_ARCH_$(BPF_TARGET_ARCH) -I$(BPF_ARCH_INCLUDE) \
	  -c examples/ringbuf-modern/ringbuf_modern.bpf.c \
	  -o examples/ringbuf-modern/ringbuf_modern.bpf.o
	$(CLANG) -O2 -g -target bpf -D__TARGET_ARCH_$(BPF_TARGET_ARCH) -I$(BPF_ARCH_INCLUDE) \
	  -c examples/perfbuf-fallback/perfbuf_fallback.bpf.c \
	  -o examples/perfbuf-fallback/perfbuf_fallback.bpf.o
	$(CLANG) -O2 -g -target bpf -D__TARGET_ARCH_$(BPF_TARGET_ARCH) -I$(BPF_ARCH_INCLUDE) \
	  -c examples/functional-execve/functional_execve.bpf.c \
	  -o examples/functional-execve/functional_execve.bpf.o
	$(CLANG) -O2 -g -target bpf -D__TARGET_ARCH_$(BPF_TARGET_ARCH) -I$(BPF_ARCH_INCLUDE) \
	  -c examples/core-relocation-fail/core_relocation_fail.bpf.c \
	  -o examples/core-relocation-fail/core_relocation_fail.bpf.o
	$(CLANG) -O2 -g -target bpf -D__TARGET_ARCH_$(BPF_TARGET_ARCH) -I$(BPF_ARCH_INCLUDE) \
	  -c examples/unsupported-attach/unsupported_attach.bpf.c \
	  -o examples/unsupported-attach/unsupported_attach.bpf.o

examples-arm64:
	$(MAKE) examples BPF_TARGET_ARCH=arm64 BPF_ARCH_INCLUDE=/usr/include/aarch64-linux-gnu

oss-examples:
	bash scripts/build-oss-examples.sh

compatibility-site:
	bash scripts/publish-compatibility-site.sh reports public/compatibility

vm-ubuntu-22:
	bash vm/scripts/fetch-cloud-image.sh \
	  "https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-amd64.img" \
	  "vm/cache/ubuntu-22.04.qcow2"

# Fetch + decompress the current Fedora CoreOS stable qemu image for the
# fedora-coreos-stable-7.0 profile (CoreOS boots via Ignition; see ignition.go).
vm-image-fcos:
	bash vm/scripts/fetch-fcos-image.sh vm/cache/fedora-coreos-stable.qcow2

vm-ubuntu-22-arm64:
	bash vm/scripts/fetch-cloud-image.sh \
	  "https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-arm64.img" \
	  "vm/cache/ubuntu-22.04-arm64.qcow2"

vm-images:
	bash vm/scripts/fetch-cloud-image.sh \
	  "https://cloud-images.ubuntu.com/bionic/current/bionic-server-cloudimg-amd64.img" \
	  "vm/cache/ubuntu-18.04.qcow2"
	bash vm/scripts/fetch-cloud-image.sh \
	  "https://cloud-images.ubuntu.com/focal/current/focal-server-cloudimg-amd64.img" \
	  "vm/cache/ubuntu-20.04.qcow2"
	bash vm/scripts/fetch-cloud-image.sh \
	  "https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-amd64.img" \
	  "vm/cache/ubuntu-22.04.qcow2"
	bash vm/scripts/fetch-cloud-image.sh \
	  "https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-genericcloud-amd64.qcow2" \
	  "vm/cache/debian-12.qcow2"
	bash vm/scripts/fetch-cloud-image.sh \
	  "https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img" \
	  "vm/cache/ubuntu-24.04.qcow2"
	bash vm/scripts/fetch-cloud-image.sh \
	  "https://cloud-images.ubuntu.com/minimal/daily/jammy/current/jammy-minimal-cloudimg-amd64.img" \
	  "vm/cache/ubuntu-22.04-minimal.qcow2"
	bash vm/scripts/fetch-cloud-image.sh \
	  "https://cloud.debian.org/images/cloud/bullseye/latest/debian-11-genericcloud-amd64.qcow2" \
	  "vm/cache/debian-11.qcow2"
	bash vm/scripts/fetch-cloud-image.sh \
	  "https://cloud.debian.org/images/cloud/trixie/latest/debian-13-genericcloud-amd64.qcow2" \
	  "vm/cache/debian-13.qcow2"

vm-images-extended: vm-images
	bash vm/scripts/fetch-cloud-image.sh \
	  "https://cloud-images.ubuntu.com/minimal/daily/noble/current/noble-minimal-cloudimg-amd64.img" \
	  "vm/cache/ubuntu-24.04-minimal.qcow2"
	bash vm/scripts/fetch-cloud-image.sh \
	  "https://repo.almalinux.org/almalinux/9/cloud/x86_64/images/AlmaLinux-9-GenericCloud-latest.x86_64.qcow2" \
	  "vm/cache/almalinux-9.qcow2"
	bash vm/scripts/fetch-cloud-image.sh \
	  "https://repo.almalinux.org/almalinux/10/cloud/x86_64/images/AlmaLinux-10-GenericCloud-latest.x86_64.qcow2" \
	  "vm/cache/almalinux-10.qcow2"
	bash vm/scripts/fetch-cloud-image.sh \
	  "https://dl.rockylinux.org/pub/rocky/9/images/x86_64/Rocky-9-GenericCloud-Base.latest.x86_64.qcow2" \
	  "vm/cache/rocky-9.qcow2"
	bash vm/scripts/fetch-cloud-image.sh \
	  "https://dl.rockylinux.org/pub/rocky/10/images/x86_64/Rocky-10-GenericCloud-Base.latest.x86_64.qcow2" \
	  "vm/cache/rocky-10.qcow2"
	bash vm/scripts/fetch-cloud-image.sh \
	  "https://cloud.centos.org/centos/9-stream/x86_64/images/CentOS-Stream-GenericCloud-x86_64-9-latest.x86_64.qcow2" \
	  "vm/cache/centos-stream-9.qcow2"
	bash vm/scripts/fetch-cloud-image.sh \
	  "https://cloud.centos.org/centos/10-stream/x86_64/images/CentOS-Stream-GenericCloud-x86_64-10-latest.x86_64.qcow2" \
	  "vm/cache/centos-stream-10.qcow2"

vm-images-tier1:
	bash vm/scripts/fetch-cloud-image.sh \
	  "https://cdn.amazonlinux.com/al2023/os-images/2023.11.20260514.0/kvm/al2023-kvm-2023.11.20260514.0-kernel-6.1-x86_64.xfs.gpt.qcow2" \
	  "vm/cache/amazon-linux-2023-6.1.qcow2"
	bash vm/scripts/fetch-cloud-image.sh \
	  "https://cdn.amazonlinux.com/os-images/2.0.20260109.1/kvm/amzn2-kvm-2.0.20260109.1-x86_64.xfs.gpt.qcow2" \
	  "vm/cache/amazon-linux-2-5.10.qcow2"
	bash vm/scripts/fetch-cloud-image.sh \
	  "https://yum.oracle.com/templates/OracleLinux/OL9/u7/x86_64/OL9U7_x86_64-kvm-b269.qcow2" \
	  "vm/cache/oracle-linux-9-uek7-5.15.qcow2"
	bash vm/scripts/fetch-cloud-image.sh \
	  "https://yum.oracle.com/templates/OracleLinux/OL10/u1/x86_64/OL10U1_x86_64-kvm-b270.qcow2" \
	  "vm/cache/oracle-linux-10-uek8-6.12.qcow2"
	bash vm/scripts/fetch-cloud-image.sh \
	  "https://download.opensuse.org/distribution/leap/15.6/appliances/openSUSE-Leap-15.6-Minimal-VM.x86_64-Cloud.qcow2" \
	  "vm/cache/opensuse-leap-15.6-6.4.qcow2"
	@echo "Note: RHEL 8 and SLES 15.6 profiles require licensed/manual image import into vm/cache/."

vm-images-expanded-2026: build
	BPFCOMPAT_MATRIX=matrices/expanded-2026.yaml bash scripts/fetch-matrix-images.sh

vm-images-expanded-2026-dry-run: build
	BPFCOMPAT_MATRIX=matrices/expanded-2026.yaml bash scripts/fetch-matrix-images.sh --dry-run

vm-images-latest-kernel: build
	BPFCOMPAT_MATRIX=matrices/latest-kernel-sweep.yaml bash scripts/fetch-matrix-images.sh

matrix-runnable:
	BPFCOMPAT_MATRIX=matrices/expanded-2026.yaml \
	BPFCOMPAT_OUT_MATRIX=matrices/expanded-2026-runnable.yaml \
	bash scripts/generate-runnable-matrix.sh

matrix-runnable-keep-manual:
	BPFCOMPAT_MATRIX=matrices/expanded-2026.yaml \
	BPFCOMPAT_OUT_MATRIX=matrices/expanded-2026-runnable-keep-manual.yaml \
	BPFCOMPAT_INCLUDE_MISSING_MANUAL=1 \
	bash scripts/generate-runnable-matrix.sh

matrix-runnable-strict:
	BPFCOMPAT_MATRIX=matrices/expanded-2026.yaml \
	BPFCOMPAT_OUT_MATRIX=matrices/expanded-2026-runnable.yaml \
	BPFCOMPAT_FAIL_ON_REQUIRED_EXCLUDED=1 \
	bash scripts/generate-runnable-matrix.sh

latest-kernel-runnable:
	BPFCOMPAT_MATRIX=matrices/latest-kernel-sweep.yaml \
	BPFCOMPAT_OUT_MATRIX=matrices/latest-kernel-runnable.yaml \
	bash scripts/generate-runnable-matrix.sh

upstream-kernel-runnable:
	bash scripts/generate-upstream-kernel-matrix.sh

manual-image-check:
	BPFCOMPAT_MATRIX=matrices/expanded-2026.yaml \
	bash scripts/manual-image-check.sh

manual-image-check-strict:
	BPFCOMPAT_MATRIX=matrices/expanded-2026.yaml \
	BPFCOMPAT_FAIL_ON_MISSING_REQUIRED=1 \
	bash scripts/manual-image-check.sh

import-required-images:
	RHEL8_IMG="$(RHEL8_IMG)" \
	SLES156_IMG="$(SLES156_IMG)" \
	bash scripts/import-required-images.sh

profile-catalog-audit: build
	bash scripts/profile-catalog-audit.sh

matrix-readiness: build
	bash scripts/matrix-readiness.sh

runtime-selector-proof: build
	bash scripts/runtime-selector-proof.sh

runtime-delivery-proof: build
	bash scripts/runtime-delivery-proof.sh

production-runtime-drill: build
	bash scripts/production-runtime-drill.sh

beta-tech-check: build
	bash scripts/beta-tech-check.sh

tech-stability:
	bash scripts/tech-stability-report.sh

production-tech-check: build
	bash scripts/production-tech-check.sh

acceptance-dev-one: build validator-static examples
	./bin/bpfcompat test \
	  --artifact examples/simple-pass/simple_pass.bpf.o \
	  --manifest examples/simple-pass/manifest-dev-one.yaml \
	  --matrix matrices/dev-one.yaml \
	  --out reports/dev-one.json \
	  --markdown reports/dev-one.md \
	  --timeout 8m

acceptance-functional-dev-one: build validator-static examples
	./bin/bpfcompat test \
	  --artifact examples/functional-execve/functional_execve.bpf.o \
	  --manifest examples/functional-execve/manifest-dev-one.yaml \
	  --matrix matrices/dev-one.yaml \
	  --out reports/functional-execve-dev-one.json \
	  --markdown reports/functional-execve-dev-one.md \
	  --timeout 8m \
	  --concurrency 1

acceptance-suite-dev-one: build validator-static examples
	./bin/bpfcompat suite \
	  --suite suites/dev-functional.yaml \
	  --out reports/suites/dev-functional/suite.json \
	  --markdown reports/suites/dev-functional/suite.md

acceptance-arm64-smoke: build validator-static examples-arm64 vm-ubuntu-22-arm64
	./bin/bpfcompat test \
	  --artifact examples/functional-execve/functional_execve.bpf.o \
	  --manifest examples/functional-execve/manifest-arm64-smoke.yaml \
	  --matrix matrices/arm64-smoke.yaml \
	  --out reports/functional-execve-arm64-smoke.json \
	  --markdown reports/functional-execve-arm64-smoke.md \
	  --timeout 8m \
	  --concurrency 1

acceptance-latest-kernel: build validator-static examples vm-images-latest-kernel latest-kernel-runnable
	./bin/bpfcompat test \
	  --artifact examples/functional-execve/functional_execve.bpf.o \
	  --manifest examples/functional-execve/manifest-latest-kernel.yaml \
	  --matrix matrices/latest-kernel-runnable.yaml \
	  --out reports/functional-execve-latest-kernel.json \
	  --markdown reports/functional-execve-latest-kernel.md \
	  --timeout 12m \
	  --concurrency 2

acceptance-upstream-kernel: doctor-virtme build validator-static examples upstream-kernel-runnable
	./bin/bpfcompat test \
	  --runner virtme-ng \
	  --artifact examples/functional-execve/functional_execve.bpf.o \
	  --manifest examples/functional-execve/manifest-upstream-kernel.yaml \
	  --matrix matrices/upstream-kernel-runnable.yaml \
	  --out reports/functional-execve-upstream-kernel.json \
	  --markdown reports/functional-execve-upstream-kernel.md \
	  --timeout 20m \
	  --concurrency 1

acceptance-firecracker-dev-one: firecracker-install firecracker-kernel-install build validator-static examples firecracker-runnable
	./bin/bpfcompat test \
	  --runner firecracker \
	  --artifact examples/simple-pass/simple_pass.bpf.o \
	  --manifest examples/simple-pass/manifest-firecracker.yaml \
	  --matrix matrices/firecracker-dev-one.yaml \
	  --out reports/simple-pass-firecracker-dev-one.json \
	  --markdown reports/simple-pass-firecracker-dev-one.md \
	  --timeout 5m \
	  --concurrency 1

acceptance: build validator-static examples
	bash scripts/acceptance.sh

acceptance-expanded-runnable: build validator-static examples matrix-runnable
	./bin/bpfcompat test \
	  --artifact examples/simple-pass/simple_pass.bpf.o \
	  --manifest examples/simple-pass/manifest.yaml \
	  --matrix matrices/expanded-2026-runnable.yaml \
	  --out reports/simple-pass-expanded-runnable.json \
	  --markdown reports/simple-pass-expanded-runnable.md \
	  --concurrency 4 \
	  --timeout 15m

acceptance-evidence:
	bash scripts/generate-evidence-report.sh

oss-evidence: build validator-static
	bash scripts/run-oss-evidence.sh

serve: build validator-static
	@echo "Web UI: http://127.0.0.1:8080"
	BPFCOMPAT_API_ALLOW_ANONYMOUS_VALIDATE="$${BPFCOMPAT_API_ALLOW_ANONYMOUS_VALIDATE:-true}" \
	BPFCOMPAT_API_ALLOW_ANONYMOUS_READ="$${BPFCOMPAT_API_ALLOW_ANONYMOUS_READ:-true}" \
	BPFCOMPAT_API_ALLOW_ANONYMOUS_RUNTIME_DELIVERY="$${BPFCOMPAT_API_ALLOW_ANONYMOUS_RUNTIME_DELIVERY:-true}" \
	./bin/bpfcompat serve --addr :8080 --workdir .bpfcompat --matrix matrices/mvp.yaml --concurrency 2 --timeout 8m

azure-provision-vm:
	bash scripts/azure-provision-vm.sh

azure-bootstrap-vm:
	bash scripts/azure-bootstrap-vm.sh

azure-provision-foundation:
	bash scripts/azure-provision-foundation.sh

azure-production-boundary-proof:
	bash scripts/azure-production-boundary-proof.sh

azure-configure-tls:
	bash scripts/azure-configure-tls.sh

azure-rotate-registry-secret:
	bash scripts/azure-rotate-registry-secret.sh

hetzner-bootstrap-vm:
	bash scripts/hetzner-bootstrap-vm.sh

hetzner-configure-tls:
	bash scripts/hetzner-configure-tls.sh

clean:
	rm -rf bin
	rm -rf .bpfcompat
	$(MAKE) -C validator/c-libbpf clean
