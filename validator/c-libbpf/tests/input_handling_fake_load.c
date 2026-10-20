// SPDX-License-Identifier: Apache-2.0
/* Test-only link shim for input_handling_test.sh: linked with
 * -Wl,--wrap=... so every kernel-facing libbpf entry point the validator
 * calls resolves here and never reaches bpf(2). Nothing is loaded into the
 * host kernel.
 *
 * The whole-object load always "succeeds" so the tests observe the
 * validator's own input handling (JSON escaping, map fixups, functional-plan
 * parsing) on the pass path; capability probes and attach fail with -EPERM. */
#include <errno.h>
#include <stddef.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

int __wrap_bpf_object__load(struct bpf_object *obj) {
    (void)obj;
    return 0;
}

int __wrap_bpf_map_create(enum bpf_map_type t, const char *n, __u32 k, __u32 v, __u32 m,
                          const struct bpf_map_create_opts *o) {
    (void)t; (void)n; (void)k; (void)v; (void)m; (void)o;
    return -EPERM;
}

int __wrap_bpf_prog_load(enum bpf_prog_type t, const char *n, const char *l,
                         const struct bpf_insn *i, size_t c, struct bpf_prog_load_opts *o) {
    (void)t; (void)n; (void)l; (void)i; (void)c; (void)o;
    return -EPERM;
}

int __wrap_libbpf_probe_bpf_helper(enum bpf_prog_type t, enum bpf_func_id h, const void *o) {
    (void)t; (void)h; (void)o;
    return -EPERM;
}

struct bpf_link *__wrap_bpf_program__attach(const struct bpf_program *p) {
    (void)p;
    errno = EPERM;
    return NULL;
}
