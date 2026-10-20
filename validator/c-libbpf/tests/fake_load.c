// SPDX-License-Identifier: Apache-2.0
/* Test-only link shim for trial_probe_maps_test.sh: linked with
 * -Wl,--wrap=... so the validator's calls into the kernel-facing libbpf
 * entry points never reach bpf(2). Nothing is loaded into the host kernel.
 *
 * The fake bpf_object__load models the two facts the regression depends on:
 *  - a hash map that still has max_entries == 0 fails to create, reported
 *    through the CURRENTLY installed libbpf print callback with the same
 *    text real libbpf emits;
 *  - otherwise an object with exactly one autoloaded program (a trial load)
 *    succeeds, and an object with more than one (the whole-object load)
 *    fails with a verifier-style rejection, standing in for the real cause
 *    the classifier must see;
 *  - a trial load of probe_rejected alone fails with a marker line, so a
 *    genuinely failing variant probe is exercised too. */
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

static void emit(const char *fmt, ...) {
    libbpf_print_fn_t cur = libbpf_set_print(NULL);
    libbpf_set_print(cur);
    if (!cur) {
        return;
    }
    va_list ap;
    va_start(ap, fmt);
    cur(LIBBPF_WARN, fmt, ap);
    va_end(ap);
}

int __wrap_bpf_object__load(struct bpf_object *obj) {
    struct bpf_map *map;
    bpf_object__for_each_map(map, obj) {
        if (bpf_map__type(map) == BPF_MAP_TYPE_HASH && bpf_map__max_entries(map) == 0) {
            emit("libbpf: map '%s': failed to create: Invalid argument(-22)\n",
                 bpf_map__name(map));
            return -EINVAL;
        }
    }
    int autoload = 0;
    const char *last = "";
    struct bpf_program *p;
    bpf_object__for_each_program(p, obj) {
        if (bpf_program__autoload(p)) {
            autoload++;
            last = bpf_program__name(p);
        }
    }
    if (autoload == 1 && strcmp(last, "probe_rejected") == 0) {
        emit("libbpf: prog '%s': TRIAL-PROBE-ONLY rejection marker\n", last);
        return -EINVAL;
    }
    if (autoload <= 1) {
        return 0;
    }
    emit("libbpf: prog '%s': BPF program load failed: Permission denied\n", last);
    emit("libbpf: prog '%s': -- BEGIN PROG LOAD LOG --\nR1 invalid mem access 'scalar'\n"
         "-- END PROG LOAD LOG --\n",
         last);
    return -EACCES;
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
