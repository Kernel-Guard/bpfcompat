CC ?= cc
CFLAGS ?= -O2 -Wall -Wextra -std=c11
LIBBPF_CFLAGS := $(shell pkg-config --cflags libbpf)
LIBBPF_LINK_MODE ?= dynamic

ifeq ($(LIBBPF_LINK_MODE),dynamic)
LIBBPF_LIBS := $(shell pkg-config --libs libbpf libelf zlib) -lzstd
else
LIBBPF_LIBS := -static -Wl,-Bstatic -lbpf -lelf -lzstd -lz -pthread
endif

OUT_DIR := bin
SRC := src/main.c
BIN := $(OUT_DIR)/bpfcompat-validator

.PHONY: all clean

all: $(BIN)

$(BIN): $(SRC)
	mkdir -p $(OUT_DIR)
	$(CC) $(CFLAGS) $(LIBBPF_CFLAGS) $(SRC) -o $(BIN) $(LIBBPF_LIBS)

# Host-safe regression test for the per-program record and link tables
# (records past the 64th program, the 1024-record bound, links kept until
# after the functional tests). The validator is rebuilt against fake
# kernel-facing libbpf entry points (tests/runtime_fake_load.c); nothing is
# loaded into the kernel and no root is needed.
# VALIDATOR_SANITIZE=1 builds it with ASan/UBSan.
# Collected by `make test-host` (run in CI); each host test adds itself.
.PHONY: test-host
test-host: test-program-records

.PHONY: test-program-records
test-program-records:
	bash tests/program_records_test.sh

clean:
	rm -rf $(OUT_DIR)
