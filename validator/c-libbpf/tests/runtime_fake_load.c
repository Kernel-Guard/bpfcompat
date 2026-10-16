// SPDX-License-Identifier: Apache-2.0
/* Test-only link shim for runtime_limits_test.sh: linked with -Wl,--wrap=...
 * so every kernel-facing libbpf entry point the validator calls resolves here
 * and never reaches bpf(2). Nothing is loaded into the host kernel.
 *
 * - bpf_object__load always succeeds (whole-object load and per-program
 *   trial loads);
 * - capability probes (map create, prog load, helper probe) fail with -EPERM;
 * - bpf_program__attach hands out a heap token as the "link" and
 *   bpf_link__destroy frees it. When FAKE_LINK_LOG names a file, each attach
 *   and destroy appends one line ("attach" / "destroy") so a functional test
 *   command can count how many links were destroyed while it runs. */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

static void link_log(const char *what) {
    const char *path = getenv("FAKE_LINK_LOG");
    if (!path || !path[0]) {
        return;
    }
    FILE *f = fopen(path, "a");
    if (!f) {
        return;
    }
    fprintf(f, "%s\n", what);
    fclose(f);
}

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
    struct bpf_link *link = calloc(1, 64);
    if (!link) {
        errno = ENOMEM;
        return NULL;
    }
    link_log("attach");
    return link;
}

int __wrap_bpf_link__destroy(struct bpf_link *link) {
    if (!link) {
        return 0;
    }
    link_log("destroy");
    free(link);
    return 0;
}
