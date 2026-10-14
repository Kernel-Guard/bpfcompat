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

.PHONY: all clean test

all: $(BIN)

$(BIN): $(SRC)
	mkdir -p $(OUT_DIR)
	$(CC) $(CFLAGS) $(LIBBPF_CFLAGS) $(SRC) -o $(BIN) $(LIBBPF_LIBS)

# Host-safe regression tests: link the validator against fake kernel-facing
# libbpf entry points (tests/fake_load.c); nothing is loaded into the kernel.
test:
	bash tests/trial_probe_maps_test.sh

clean:
	rm -rf $(OUT_DIR)
