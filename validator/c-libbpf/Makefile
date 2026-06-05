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

clean:
	rm -rf $(OUT_DIR)
