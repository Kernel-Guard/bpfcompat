#define _POSIX_C_SOURCE 200809L

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <fcntl.h>
#include <gelf.h>
#include <libelf.h>
#include <linux/bpf.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

#define LIBBPF_LOG_CAPACITY (256 * 1024)
#define MAX_ITEMS 64
#define MAX_MAP_FIXUPS 32

/* A pre-load adjustment for a map whose final shape the artifact's own
 * loader decides at runtime (max_entries=0 in the object, sized by
 * userspace). Declared in the manifest and applied between open and load so
 * such artifacts can be validated the same way their real loader runs them. */
struct map_fixup {
    char name[68];
    char max_entries[16]; /* decimal or "cpus"; empty = unset */
    unsigned int inner_ringbuf_bytes; /* 0 = unset */
    /* Generic inner-map prototype for HASH_OF_MAPS / ARRAY_OF_MAPS whose inner
     * shape the artifact's loader sets at runtime (e.g. KubeArmor's
     * kubearmor_visibility, an inner per-namespace hash). 0 type = unset. */
    unsigned int inner_map_type; /* BPF_MAP_TYPE_*; 0 = unset */
    unsigned int inner_key_size;
    unsigned int inner_value_size;
    unsigned int inner_max_entries;
    char status[32]; /* applied | map_not_found | error (main load only) */
    int err;
    unsigned int applied_entries;
};

/* Resolve the inner-map type names accepted in manifests to numeric
 * BPF_MAP_TYPE_* values. Returns 0 for an unknown name. */
static unsigned int inner_map_type_from_name(const char *name) {
    if (strcmp(name, "hash") == 0) return BPF_MAP_TYPE_HASH;
    if (strcmp(name, "array") == 0) return BPF_MAP_TYPE_ARRAY;
    if (strcmp(name, "lru_hash") == 0) return BPF_MAP_TYPE_LRU_HASH;
    if (strcmp(name, "percpu_hash") == 0) return BPF_MAP_TYPE_PERCPU_HASH;
    if (strcmp(name, "percpu_array") == 0) return BPF_MAP_TYPE_PERCPU_ARRAY;
    if (strcmp(name, "lru_percpu_hash") == 0) return BPF_MAP_TYPE_LRU_PERCPU_HASH;
    return 0;
}

#define MAX_VARIANT_GROUPS 16
#define MAX_VARIANTS_PER_GROUP 6

/* A group of alternative programs for the same event where the artifact's
 * loader probes kernel helper support and autoloads only the first
 * satisfying variant (Falco's exit_event_progs_table pattern). Programs in
 * the object that lose the selection are EXPECTED to fail verification on
 * kernels missing their required helper, so loading them is a loader-
 * contract violation, not a compatibility result. */
struct prog_variant_group {
    char group[68];
    int count;
    char names[MAX_VARIANTS_PER_GROUP][128];
    unsigned int helper_ids[MAX_VARIANTS_PER_GROUP]; /* 0 = unconditional */
    bool trial_probe[MAX_VARIANTS_PER_GROUP]; /* gate via isolated trial load */
    int chosen; /* index of selected variant after apply; -1 = none */
};

struct options {
    const char *artifact;
    const char *manifest;
    const char *functional_plan;
    const char *out;
    const char *log_dir;
    const char *attach_mode;
    bool probe_features;
    struct map_fixup map_fixups[MAX_MAP_FIXUPS];
    int map_fixup_count;
    struct prog_variant_group variant_groups[MAX_VARIANT_GROUPS];
    int variant_group_count;
    /* Programs statically referenced from prog-array map slots; they must
     * stay autoloaded during trial probes or slot init fails with EBADF. */
    char probe_companions[MAX_ITEMS][128];
    int probe_companion_count;
};

struct discovered_program {
    char name[128];
    char section[256];
    char attach_status[16];
    char attach_error[256];
    char load_status[16]; /* per-program isolated load: "pass" | "fail" | "skipped" */
    int load_errno;
    char load_log[4096]; /* tail of the verifier message when an isolated load fails */
};

struct probe_status {
    char status[32];
    int error_code;
    char error[256];
};

struct functional_test {
    char name[128];
    char command[1024];
    bool required;
    int timeout_seconds;
    int expect_exit_code;
    char expect_stdout_contains[256];
    char expect_stderr_contains[256];
    char status[16];
    int exit_code;
    bool timed_out;
    char stdout_tail[2048];
    char stderr_tail[2048];
    char error[256];
};

struct validator_result {
    struct options opts;
    struct utsname host;
    char timestamp[64];
    bool kernel_btf_available;
    long long kernel_btf_size;
    bool artifact_has_btf;
    bool artifact_has_btf_ext;
    bool bpftool_available;
    bool bpftool_probe_ok;
    char bpftool_probe_output_path[256];
    struct probe_status map_probe_ringbuf;
    struct probe_status map_probe_perf_event_array;
    struct probe_status map_probe_array;
    struct probe_status map_probe_hash;
    struct probe_status prog_probe_tracepoint;
    struct probe_status prog_probe_kprobe;
    struct probe_status prog_probe_tracing;
    struct probe_status prog_probe_xdp;
    bool tracefs_available;
    bool kprobe_events_available;
    bool tracepoint_events_available;
    int map_count;
    int program_count;
    struct discovered_program programs[MAX_ITEMS];
    int functional_test_count;
    struct functional_test functional_tests[MAX_ITEMS];
    char functional_status[16];
    bool load_ok;
    int load_errno;
    char load_error[256];
    char attach_status[16];
    int attach_attempted;
    int attach_passed;
    int attach_failed;
    char libbpf_log[LIBBPF_LOG_CAPACITY];
    size_t libbpf_log_len;
    struct bpf_link *links[MAX_ITEMS];
    int link_count;
};

static struct validator_result *g_result;
static void set_memlock_rlimit(void);

static void usage(const char *prog) {
    fprintf(stderr,
            "Usage: %s --artifact <path> --out <result.json> [--manifest <path>] "
            "[--functional-plan <path>] [--log-dir <dir>] [--attach-mode <mode>] "
            "[--probe-features <bool>] [--set-map-max-entries <map>=<n|cpus>]... "
            "[--set-map-inner-ringbuf <map>=<bytes>]... "
            "[--set-map-inner-map <map>=<type>:<key>:<value>:<entries>]... "
            "[--prog-variants <group>=<prog>:<helper_id|trial>,...]... "
            "[--probe-companions <prog>,<prog>,...]\n",
            prog);
}

static int parse_bool(const char *value, bool *out) {
    if (!value || !out) {
        return -1;
    }
    if (strcmp(value, "1") == 0 || strcmp(value, "true") == 0 ||
        strcmp(value, "yes") == 0 || strcmp(value, "on") == 0) {
        *out = true;
        return 0;
    }
    if (strcmp(value, "0") == 0 || strcmp(value, "false") == 0 ||
        strcmp(value, "no") == 0 || strcmp(value, "off") == 0) {
        *out = false;
        return 0;
    }
    return -1;
}

enum attach_mode {
    ATTACH_MODE_DISABLED = 0,
    ATTACH_MODE_BEST_EFFORT = 1,
    ATTACH_MODE_REQUIRED = 2,
};

static bool str_eq(const char *a, const char *b) {
    if (!a || !b) {
        return false;
    }
    return strcmp(a, b) == 0;
}

static enum attach_mode parse_attach_mode(const char *mode) {
    if (!mode || str_eq(mode, "best-effort")) {
        return ATTACH_MODE_BEST_EFFORT;
    }
    if (str_eq(mode, "disabled") || str_eq(mode, "off") || str_eq(mode, "none")) {
        return ATTACH_MODE_DISABLED;
    }
    if (str_eq(mode, "required") || str_eq(mode, "strict")) {
        return ATTACH_MODE_REQUIRED;
    }
    return ATTACH_MODE_BEST_EFFORT;
}

static bool starts_with(const char *s, const char *prefix) {
    if (!s || !prefix) {
        return false;
    }
    size_t n = strlen(prefix);
    return strncmp(s, prefix, n) == 0;
}

static bool is_auto_attach_candidate(const char *section) {
    return starts_with(section, "tracepoint/") ||
           starts_with(section, "raw_tracepoint/") ||
           starts_with(section, "raw_tp/") ||
           starts_with(section, "kprobe/") ||
           starts_with(section, "kretprobe/") ||
           starts_with(section, "ksyscall/") ||
           starts_with(section, "kretsyscall/") ||
           starts_with(section, "fentry/") ||
           starts_with(section, "fexit/") ||
           starts_with(section, "fmod_ret/") ||
           starts_with(section, "tp_btf/") ||
           starts_with(section, "uprobe/") ||
           starts_with(section, "uretprobe/") ||
           starts_with(section, "usdt/");
}

/* Parse "<map>=<value>" for --set-map-max-entries / --set-map-inner-ringbuf.
 * Fixups for the same map name merge into one entry so both settings can
 * target one array-of-maps. */
static int add_map_fixup(struct options *opts, const char *spec, bool inner_ringbuf) {
    const char *eq = spec ? strchr(spec, '=') : NULL;
    if (!eq || eq == spec || !eq[1]) {
        fprintf(stderr, "invalid map fixup spec (want <map>=<value>): %s\n", spec ? spec : "");
        return -1;
    }
    size_t name_len = (size_t)(eq - spec);
    if (name_len >= sizeof(((struct map_fixup *)0)->name)) {
        fprintf(stderr, "map fixup name too long: %s\n", spec);
        return -1;
    }
    const char *value = eq + 1;

    struct map_fixup *fx = NULL;
    for (int i = 0; i < opts->map_fixup_count; i++) {
        if (strncmp(opts->map_fixups[i].name, spec, name_len) == 0 &&
            opts->map_fixups[i].name[name_len] == '\0') {
            fx = &opts->map_fixups[i];
            break;
        }
    }
    if (!fx) {
        if (opts->map_fixup_count >= MAX_MAP_FIXUPS) {
            fprintf(stderr, "too many map fixups: max %d\n", MAX_MAP_FIXUPS);
            return -1;
        }
        fx = &opts->map_fixups[opts->map_fixup_count++];
        memset(fx, 0, sizeof(*fx));
        memcpy(fx->name, spec, name_len);
        fx->name[name_len] = '\0';
    }

    if (inner_ringbuf) {
        char *end = NULL;
        unsigned long bytes = strtoul(value, &end, 10);
        if (!end || *end != '\0' || bytes == 0 || bytes > 0xffffffffUL) {
            fprintf(stderr, "invalid inner ringbuf size: %s\n", spec);
            return -1;
        }
        fx->inner_ringbuf_bytes = (unsigned int)bytes;
        return 0;
    }

    if (strcmp(value, "cpus") != 0) {
        char *end = NULL;
        unsigned long entries = strtoul(value, &end, 10);
        if (!end || *end != '\0' || entries == 0 || entries > 0xffffffffUL) {
            fprintf(stderr, "invalid map max entries (want positive integer or \"cpus\"): %s\n", spec);
            return -1;
        }
    }
    snprintf(fx->max_entries, sizeof(fx->max_entries), "%s", value);
    return 0;
}

/* Parse "<map>=<type>:<key_size>:<value_size>:<max_entries>" for
 * --set-map-inner-map, installing a generic inner-map prototype on a
 * map-in-map (e.g. kubearmor_visibility=hash:4:4:64). */
static int add_inner_map_fixup(struct options *opts, const char *spec) {
    const char *eq = spec ? strchr(spec, '=') : NULL;
    if (!eq || eq == spec || !eq[1]) {
        fprintf(stderr, "invalid inner-map spec (want <map>=<type>:<key>:<value>:<entries>): %s\n", spec ? spec : "");
        return -1;
    }
    size_t name_len = (size_t)(eq - spec);
    if (name_len >= sizeof(((struct map_fixup *)0)->name)) {
        fprintf(stderr, "map fixup name too long: %s\n", spec);
        return -1;
    }

    char type_name[32];
    unsigned int key_size = 0, value_size = 0, max_entries = 0;
    if (sscanf(eq + 1, "%31[^:]:%u:%u:%u", type_name, &key_size, &value_size, &max_entries) != 4) {
        fprintf(stderr, "invalid inner-map spec (want <type>:<key>:<value>:<entries>): %s\n", spec);
        return -1;
    }
    unsigned int type = inner_map_type_from_name(type_name);
    if (type == 0) {
        fprintf(stderr, "unknown inner-map type '%s' (want hash|array|lru_hash|percpu_hash|percpu_array|lru_percpu_hash): %s\n", type_name, spec);
        return -1;
    }
    if (value_size == 0 || max_entries == 0) {
        fprintf(stderr, "inner-map value_size and max_entries must be positive: %s\n", spec);
        return -1;
    }

    struct map_fixup *fx = NULL;
    for (int i = 0; i < opts->map_fixup_count; i++) {
        if (strncmp(opts->map_fixups[i].name, spec, name_len) == 0 &&
            opts->map_fixups[i].name[name_len] == '\0') {
            fx = &opts->map_fixups[i];
            break;
        }
    }
    if (!fx) {
        if (opts->map_fixup_count >= MAX_MAP_FIXUPS) {
            fprintf(stderr, "too many map fixups: max %d\n", MAX_MAP_FIXUPS);
            return -1;
        }
        fx = &opts->map_fixups[opts->map_fixup_count++];
        memset(fx, 0, sizeof(*fx));
        memcpy(fx->name, spec, name_len);
        fx->name[name_len] = '\0';
    }

    fx->inner_map_type = type;
    fx->inner_key_size = key_size;
    fx->inner_value_size = value_size;
    fx->inner_max_entries = max_entries;
    return 0;
}

/* Parse "<group>=<prog>:<helper_id>,<prog>:<helper_id>,..." for
 * --prog-variants. helper_id 0 means the variant has no helper requirement
 * (the unconditional fallback). Variant order is selection priority. */
static int add_prog_variant_group(struct options *opts, const char *spec) {
    const char *eq = spec ? strchr(spec, '=') : NULL;
    if (!eq || eq == spec || !eq[1]) {
        fprintf(stderr, "invalid prog variants spec (want <group>=<prog>:<id>,...): %s\n",
                spec ? spec : "");
        return -1;
    }
    if (opts->variant_group_count >= MAX_VARIANT_GROUPS) {
        fprintf(stderr, "too many prog variant groups: max %d\n", MAX_VARIANT_GROUPS);
        return -1;
    }
    struct prog_variant_group *grp = &opts->variant_groups[opts->variant_group_count];
    memset(grp, 0, sizeof(*grp));
    grp->chosen = -1;

    size_t group_len = (size_t)(eq - spec);
    if (group_len >= sizeof(grp->group)) {
        fprintf(stderr, "prog variant group name too long: %s\n", spec);
        return -1;
    }
    memcpy(grp->group, spec, group_len);
    grp->group[group_len] = '\0';

    const char *cursor = eq + 1;
    while (*cursor) {
        if (grp->count >= MAX_VARIANTS_PER_GROUP) {
            fprintf(stderr, "too many variants in group %s: max %d\n", grp->group,
                    MAX_VARIANTS_PER_GROUP);
            return -1;
        }
        const char *comma = strchr(cursor, ',');
        size_t entry_len = comma ? (size_t)(comma - cursor) : strlen(cursor);
        const char *colon = memchr(cursor, ':', entry_len);
        size_t name_len = colon ? (size_t)(colon - cursor) : entry_len;
        if (name_len == 0 || name_len >= sizeof(grp->names[0])) {
            fprintf(stderr, "invalid variant program name in group %s\n", grp->group);
            return -1;
        }
        memcpy(grp->names[grp->count], cursor, name_len);
        grp->names[grp->count][name_len] = '\0';
        unsigned long helper_id = 0;
        bool trial = false;
        if (colon && colon + 1 < cursor + entry_len) {
            size_t value_len = (size_t)((cursor + entry_len) - (colon + 1));
            if (value_len == 5 && strncmp(colon + 1, "trial", 5) == 0) {
                trial = true;
            } else {
                char *end = NULL;
                helper_id = strtoul(colon + 1, &end, 10);
                if (!end || end != cursor + entry_len || helper_id > 0xffffffffUL) {
                    fprintf(stderr, "invalid helper id for variant %s in group %s\n",
                            grp->names[grp->count], grp->group);
                    return -1;
                }
            }
        }
        grp->helper_ids[grp->count] = (unsigned int)helper_id;
        grp->trial_probe[grp->count] = trial;
        grp->count++;
        if (!comma) {
            break;
        }
        cursor = comma + 1;
    }
    if (grp->count == 0) {
        fprintf(stderr, "prog variant group %s has no variants\n", grp->group);
        return -1;
    }
    opts->variant_group_count++;
    return 0;
}

static int parse_args(int argc, char **argv, struct options *opts) {
    memset(opts, 0, sizeof(*opts));
    opts->probe_features = true;
    opts->attach_mode = "best-effort";

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--artifact") == 0 && i + 1 < argc) {
            opts->artifact = argv[++i];
            continue;
        }
        if (strcmp(argv[i], "--manifest") == 0 && i + 1 < argc) {
            opts->manifest = argv[++i];
            continue;
        }
        if (strcmp(argv[i], "--functional-plan") == 0 && i + 1 < argc) {
            opts->functional_plan = argv[++i];
            continue;
        }
        if (strcmp(argv[i], "--out") == 0 && i + 1 < argc) {
            opts->out = argv[++i];
            continue;
        }
        if (strcmp(argv[i], "--log-dir") == 0 && i + 1 < argc) {
            opts->log_dir = argv[++i];
            continue;
        }
        if (strcmp(argv[i], "--attach-mode") == 0 && i + 1 < argc) {
            opts->attach_mode = argv[++i];
            continue;
        }
        if (strcmp(argv[i], "--probe-features") == 0 && i + 1 < argc) {
            if (parse_bool(argv[++i], &opts->probe_features) != 0) {
                fprintf(stderr, "invalid bool for --probe-features\n");
                return -1;
            }
            continue;
        }
        if (strcmp(argv[i], "--set-map-max-entries") == 0 && i + 1 < argc) {
            if (add_map_fixup(opts, argv[++i], false) != 0) {
                return -1;
            }
            continue;
        }
        if (strcmp(argv[i], "--set-map-inner-ringbuf") == 0 && i + 1 < argc) {
            if (add_map_fixup(opts, argv[++i], true) != 0) {
                return -1;
            }
            continue;
        }
        if (strcmp(argv[i], "--set-map-inner-map") == 0 && i + 1 < argc) {
            if (add_inner_map_fixup(opts, argv[++i]) != 0) {
                return -1;
            }
            continue;
        }
        if (strcmp(argv[i], "--prog-variants") == 0 && i + 1 < argc) {
            if (add_prog_variant_group(opts, argv[++i]) != 0) {
                return -1;
            }
            continue;
        }
        if (strcmp(argv[i], "--probe-companions") == 0 && i + 1 < argc) {
            const char *cursor = argv[++i];
            while (*cursor) {
                const char *comma = strchr(cursor, ',');
                size_t len = comma ? (size_t)(comma - cursor) : strlen(cursor);
                if (len == 0 || len >= sizeof(opts->probe_companions[0]) ||
                    opts->probe_companion_count >= MAX_ITEMS) {
                    fprintf(stderr, "invalid --probe-companions list\n");
                    return -1;
                }
                memcpy(opts->probe_companions[opts->probe_companion_count], cursor, len);
                opts->probe_companions[opts->probe_companion_count][len] = '\0';
                opts->probe_companion_count++;
                if (!comma) {
                    break;
                }
                cursor = comma + 1;
            }
            continue;
        }
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            return 1;
        }

        fprintf(stderr, "unknown or incomplete argument: %s\n", argv[i]);
        return -1;
    }

    if (!opts->artifact) {
        fprintf(stderr, "--artifact is required\n");
        return -1;
    }
    if (!opts->out) {
        fprintf(stderr, "--out is required\n");
        return -1;
    }
    return 0;
}

static void append_libbpf_log(const char *msg) {
    if (!g_result || !msg) {
        return;
    }
    size_t remaining = LIBBPF_LOG_CAPACITY - g_result->libbpf_log_len;
    if (remaining <= 1) {
        return;
    }

    size_t msg_len = strlen(msg);
    if (msg_len >= remaining) {
        msg_len = remaining - 1;
    }

    memcpy(g_result->libbpf_log + g_result->libbpf_log_len, msg, msg_len);
    g_result->libbpf_log_len += msg_len;
    g_result->libbpf_log[g_result->libbpf_log_len] = '\0';
}

/* libbpf emits a failed program's entire verifier log as ONE print call, so
 * the per-call format buffer must be large enough to hold it or the verdict
 * at the end of the log is silently cut. Static is safe: the validator is
 * single-threaded by design. */
static char g_print_buf[LIBBPF_LOG_CAPACITY];

static int libbpf_log_callback(enum libbpf_print_level level, const char *fmt, va_list args) {
    /* Skip DEBUG (per-insn CO-RE relocation spam): large objects emit far
     * more than the capture buffer holds, and append stops at capacity — so
     * keeping DEBUG would crowd out the WARN-level failure verdict. */
    if (level == LIBBPF_DEBUG) {
        return 0;
    }
    int n = vsnprintf(g_print_buf, sizeof(g_print_buf), fmt, args);
    if (n > 0) {
        append_libbpf_log(g_print_buf);
    }
    return n;
}

static void escape_json_string(FILE *f, const char *value) {
    if (!value) {
        return;
    }
    for (const unsigned char *p = (const unsigned char *)value; *p; p++) {
        switch (*p) {
        case '"':
            fputs("\\\"", f);
            break;
        case '\\':
            fputs("\\\\", f);
            break;
        case '\n':
            fputs("\\n", f);
            break;
        case '\r':
            fputs("\\r", f);
            break;
        case '\t':
            fputs("\\t", f);
            break;
        default:
            if (*p < 0x20) {
                fprintf(f, "\\u%04x", *p);
            } else {
                fputc(*p, f);
            }
            break;
        }
    }
}

static void set_errno_message(int err, char *buf, size_t buf_len) {
    if (!buf || buf_len == 0) {
        return;
    }
    if (err == 0) {
        buf[0] = '\0';
        return;
    }

    char tmp[128];
    if (libbpf_strerror(err, tmp, sizeof(tmp)) == 0) {
        snprintf(buf, buf_len, "%s", tmp);
        return;
    }
    snprintf(buf, buf_len, "%s", strerror(abs(err)));
}

static void init_probe_status(struct probe_status *status) {
    if (!status) {
        return;
    }
    snprintf(status->status, sizeof(status->status), "unknown");
    status->error_code = 0;
    status->error[0] = '\0';
}

static void set_probe_status(struct probe_status *status, const char *state, int err) {
    if (!status) {
        return;
    }
    snprintf(status->status, sizeof(status->status), "%s", state ? state : "unknown");
    status->error_code = err;
    set_errno_message(err, status->error, sizeof(status->error));
}

static bool path_exists(const char *path) {
    if (!path) {
        return false;
    }
    struct stat st;
    return stat(path, &st) == 0;
}

static int normalize_probe_err(int rc) {
    if (rc < 0) {
        if (rc == -1 && errno != 0) {
            return -errno;
        }
        return rc;
    }
    if (rc == 0) {
        return 0;
    }
    return -EINVAL;
}

static const char *status_from_probe_error(int err) {
    if (err == 0) {
        return "supported";
    }
    if (err == -EPERM || err == -EACCES) {
        return "permission_denied";
    }
    if (err == -EINVAL || err == -ENOENT) {
        return "inconclusive";
    }
    if (err == -EOPNOTSUPP || err == -ENOTSUP || err == -ENOSYS) {
        return "unsupported";
    }
    return "probe_error";
}

static void probe_map_support(struct probe_status *out,
                              enum bpf_map_type map_type,
                              const char *map_name,
                              __u32 key_size,
                              __u32 value_size,
                              __u32 max_entries) {
    struct bpf_map_create_opts opts = {
        .sz = sizeof(opts),
    };

    int fd = bpf_map_create(map_type, map_name, key_size, value_size, max_entries, &opts);
    int err = normalize_probe_err(fd);
    const char *status = status_from_probe_error(err);
    set_probe_status(out, status, err);
    if (fd >= 0) {
        (void)close(fd);
    }
}

static void probe_prog_support(struct probe_status *out, enum bpf_prog_type prog_type) {
    static const struct bpf_insn minimal_prog[] = {
        {
            .code = BPF_ALU64 | BPF_MOV | BPF_K,
            .dst_reg = BPF_REG_0,
            .src_reg = 0,
            .off = 0,
            .imm = 0,
        },
        {
            .code = BPF_JMP | BPF_EXIT,
            .dst_reg = 0,
            .src_reg = 0,
            .off = 0,
            .imm = 0,
        },
    };

    struct bpf_prog_load_opts opts = {
        .sz = sizeof(opts),
    };

    int fd = bpf_prog_load(prog_type,
                           "bpfcompat_probe",
                           "GPL",
                           minimal_prog,
                           sizeof(minimal_prog) / sizeof(minimal_prog[0]),
                           &opts);
    int err = normalize_probe_err(fd);
    const char *status = status_from_probe_error(err);
    set_probe_status(out, status, err);
    if (fd >= 0) {
        (void)close(fd);
    }
}

static void probe_tracing_prog_support(struct probe_status *out) {
    static const struct bpf_insn minimal_prog[] = {
        {
            .code = BPF_ALU64 | BPF_MOV | BPF_K,
            .dst_reg = BPF_REG_0,
            .src_reg = 0,
            .off = 0,
            .imm = 0,
        },
        {
            .code = BPF_JMP | BPF_EXIT,
            .dst_reg = 0,
            .src_reg = 0,
            .off = 0,
            .imm = 0,
        },
    };

    struct bpf_prog_load_opts opts = {
        .sz = sizeof(opts),
        .expected_attach_type = BPF_TRACE_RAW_TP,
    };

    int fd = bpf_prog_load(BPF_PROG_TYPE_TRACING,
                           "bpfcompat_probe_tracing",
                           "GPL",
                           minimal_prog,
                           sizeof(minimal_prog) / sizeof(minimal_prog[0]),
                           &opts);
    int err = normalize_probe_err(fd);

    if (err == -EINVAL || err == -ENOENT) {
        set_probe_status(out, "inconclusive", err);
    } else {
        set_probe_status(out, status_from_probe_error(err), err);
    }
    if (fd >= 0) {
        (void)close(fd);
    }
}

static void detect_attach_prereqs(struct validator_result *res) {
    bool canonical_tracefs = path_exists("/sys/kernel/tracing");
    bool compat_tracefs = path_exists("/sys/kernel/debug/tracing");

    res->tracefs_available = canonical_tracefs || compat_tracefs;
    res->kprobe_events_available =
        path_exists("/sys/kernel/tracing/kprobe_events") ||
        path_exists("/sys/kernel/debug/tracing/kprobe_events");
    res->tracepoint_events_available =
        path_exists("/sys/kernel/tracing/events") ||
        path_exists("/sys/kernel/debug/tracing/events");
}

static void run_custom_capability_probes(struct validator_result *res) {
    init_probe_status(&res->map_probe_ringbuf);
    init_probe_status(&res->map_probe_perf_event_array);
    init_probe_status(&res->map_probe_array);
    init_probe_status(&res->map_probe_hash);
    init_probe_status(&res->prog_probe_tracepoint);
    init_probe_status(&res->prog_probe_kprobe);
    init_probe_status(&res->prog_probe_tracing);
    init_probe_status(&res->prog_probe_xdp);
    detect_attach_prereqs(res);

    if (!res->opts.probe_features) {
        return;
    }

    set_memlock_rlimit();

    probe_map_support(&res->map_probe_ringbuf, BPF_MAP_TYPE_RINGBUF, "probe_ringbuf", 0, 0, 4096);
    probe_map_support(&res->map_probe_perf_event_array,
                      BPF_MAP_TYPE_PERF_EVENT_ARRAY,
                      "probe_perf_event",
                      sizeof(__u32),
                      sizeof(__u32),
                      1);
    probe_map_support(&res->map_probe_array,
                      BPF_MAP_TYPE_ARRAY,
                      "probe_array",
                      sizeof(__u32),
                      sizeof(__u64),
                      1);
    probe_map_support(&res->map_probe_hash,
                      BPF_MAP_TYPE_HASH,
                      "probe_hash",
                      sizeof(__u32),
                      sizeof(__u64),
                      1);

    probe_prog_support(&res->prog_probe_tracepoint, BPF_PROG_TYPE_TRACEPOINT);
    probe_prog_support(&res->prog_probe_kprobe, BPF_PROG_TYPE_KPROBE);
    probe_tracing_prog_support(&res->prog_probe_tracing);
    probe_prog_support(&res->prog_probe_xdp, BPF_PROG_TYPE_XDP);
}

static void capture_metadata(struct validator_result *res) {
    if (uname(&res->host) != 0) {
        memset(&res->host, 0, sizeof(res->host));
    }

    time_t now = time(NULL);
    struct tm tm_buf;
    gmtime_r(&now, &tm_buf);
    if (strftime(res->timestamp, sizeof(res->timestamp), "%Y-%m-%dT%H:%M:%SZ", &tm_buf) == 0) {
        snprintf(res->timestamp, sizeof(res->timestamp), "unknown");
    }
}

static void detect_kernel_btf(struct validator_result *res) {
    struct stat st;
    if (stat("/sys/kernel/btf/vmlinux", &st) == 0) {
        res->kernel_btf_available = true;
        res->kernel_btf_size = (long long)st.st_size;
        return;
    }

    res->kernel_btf_available = false;
    res->kernel_btf_size = 0;
}

static void detect_artifact_btf_sections(struct validator_result *res) {
    if (elf_version(EV_CURRENT) == EV_NONE) {
        return;
    }

    int fd = open(res->opts.artifact, O_RDONLY);
    if (fd < 0) {
        return;
    }

    Elf *elf = elf_begin(fd, ELF_C_READ, NULL);
    if (!elf) {
        close(fd);
        return;
    }

    if (elf_kind(elf) != ELF_K_ELF) {
        elf_end(elf);
        close(fd);
        return;
    }

    size_t shstrndx = 0;
    if (elf_getshdrstrndx(elf, &shstrndx) != 0) {
        elf_end(elf);
        close(fd);
        return;
    }

    Elf_Scn *scn = NULL;
    while ((scn = elf_nextscn(elf, scn)) != NULL) {
        GElf_Shdr shdr_mem;
        GElf_Shdr *shdr = gelf_getshdr(scn, &shdr_mem);
        if (!shdr) {
            continue;
        }

        const char *section_name = elf_strptr(elf, shstrndx, shdr->sh_name);
        if (!section_name) {
            continue;
        }

        if (strcmp(section_name, ".BTF") == 0) {
            res->artifact_has_btf = true;
            continue;
        }
        if (strcmp(section_name, ".BTF.ext") == 0) {
            res->artifact_has_btf_ext = true;
            continue;
        }
    }

    elf_end(elf);
    close(fd);
}

static void run_bpftool_feature_probe(struct validator_result *res) {
    if (!res->opts.probe_features) {
        return;
    }
    if (!res->opts.log_dir) {
        return;
    }

    int command_exists = system("command -v bpftool >/dev/null 2>&1");
    if (command_exists != 0) {
        res->bpftool_available = false;
        return;
    }
    res->bpftool_available = true;

    snprintf(res->bpftool_probe_output_path,
             sizeof(res->bpftool_probe_output_path),
             "%s/bpftool-feature-kernel.json",
             res->opts.log_dir);

    char cmd[1400];
    snprintf(cmd,
             sizeof(cmd),
             "bpftool feature probe -j kernel > %s 2>/dev/null",
             res->bpftool_probe_output_path);
    int probe_rc = system(cmd);
    res->bpftool_probe_ok = (probe_rc == 0);
}

static void collect_btf_and_capability_metadata(struct validator_result *res) {
    detect_kernel_btf(res);
    detect_artifact_btf_sections(res);
    run_bpftool_feature_probe(res);
    run_custom_capability_probes(res);
}

static void write_libbpf_log_file(const struct validator_result *res) {
    if (!res->opts.log_dir || res->libbpf_log_len == 0) {
        return;
    }

    char path[1024];
    snprintf(path, sizeof(path), "%s/libbpf.log", res->opts.log_dir);
    FILE *f = fopen(path, "w");
    if (!f) {
        return;
    }
    fwrite(res->libbpf_log, 1, res->libbpf_log_len, f);
    fclose(f);
}

static void trim_line_end(char *line) {
    if (!line) {
        return;
    }
    size_t len = strlen(line);
    while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) {
        line[len - 1] = '\0';
        len--;
    }
}

static void init_functional_test(struct functional_test *test) {
    if (!test) {
        return;
    }
    memset(test, 0, sizeof(*test));
    test->required = true;
    test->timeout_seconds = 10;
    test->expect_exit_code = 0;
    snprintf(test->status, sizeof(test->status), "skipped");
}

static void set_functional_field(struct functional_test *test, const char *key, const char *value) {
    if (!test || !key || !value) {
        return;
    }
    if (strcmp(key, "name") == 0) {
        snprintf(test->name, sizeof(test->name), "%s", value);
    } else if (strcmp(key, "command") == 0) {
        snprintf(test->command, sizeof(test->command), "%s", value);
    } else if (strcmp(key, "required") == 0) {
        bool parsed = true;
        if (parse_bool(value, &parsed) == 0) {
            test->required = parsed;
        }
    } else if (strcmp(key, "timeout_seconds") == 0) {
        int seconds = atoi(value);
        if (seconds > 0 && seconds <= 300) {
            test->timeout_seconds = seconds;
        }
    } else if (strcmp(key, "expect_exit_code") == 0) {
        int code = atoi(value);
        if (code >= 0 && code <= 255) {
            test->expect_exit_code = code;
        }
    } else if (strcmp(key, "expect_stdout_contains") == 0) {
        snprintf(test->expect_stdout_contains, sizeof(test->expect_stdout_contains), "%s", value);
    } else if (strcmp(key, "expect_stderr_contains") == 0) {
        snprintf(test->expect_stderr_contains, sizeof(test->expect_stderr_contains), "%s", value);
    }
}

static void load_functional_plan(struct validator_result *res) {
    snprintf(res->functional_status, sizeof(res->functional_status), "skipped");
    if (!res->opts.functional_plan || !res->opts.functional_plan[0]) {
        return;
    }

    FILE *f = fopen(res->opts.functional_plan, "r");
    if (!f) {
        snprintf(res->functional_status, sizeof(res->functional_status), "fail");
        if (res->functional_test_count < MAX_ITEMS) {
            struct functional_test *test = &res->functional_tests[res->functional_test_count++];
            init_functional_test(test);
            snprintf(test->name, sizeof(test->name), "functional-plan");
            snprintf(test->status, sizeof(test->status), "fail");
            snprintf(test->error, sizeof(test->error), "open functional plan failed: %s", strerror(errno));
        }
        return;
    }

    char line[2048];
    bool in_test = false;
    struct functional_test current;
    init_functional_test(&current);

    if (!fgets(line, sizeof(line), f)) {
        fclose(f);
        return;
    }
    trim_line_end(line);
    if (strcmp(line, "functional_plan.v0.1") != 0) {
        fclose(f);
        snprintf(res->functional_status, sizeof(res->functional_status), "fail");
        if (res->functional_test_count < MAX_ITEMS) {
            struct functional_test *test = &res->functional_tests[res->functional_test_count++];
            init_functional_test(test);
            snprintf(test->name, sizeof(test->name), "functional-plan");
            snprintf(test->status, sizeof(test->status), "fail");
            snprintf(test->error, sizeof(test->error), "unsupported functional plan version");
        }
        return;
    }

    while (fgets(line, sizeof(line), f)) {
        trim_line_end(line);
        if (strcmp(line, "BEGIN") == 0) {
            init_functional_test(&current);
            in_test = true;
            continue;
        }
        if (strcmp(line, "END") == 0) {
            if (in_test && res->functional_test_count < MAX_ITEMS) {
                if (!current.name[0]) {
                    snprintf(current.name, sizeof(current.name), "functional-%d", res->functional_test_count + 1);
                }
                res->functional_tests[res->functional_test_count++] = current;
            }
            in_test = false;
            continue;
        }
        if (!in_test) {
            continue;
        }
        char *eq = strchr(line, '=');
        if (!eq) {
            continue;
        }
        *eq = '\0';
        set_functional_field(&current, line, eq + 1);
    }
    fclose(f);
}

static void append_tail(char *dst, size_t dst_size, const char *src, size_t src_len) {
    if (!dst || dst_size == 0 || !src || src_len == 0) {
        return;
    }
    if (src_len >= dst_size) {
        memcpy(dst, src + (src_len - dst_size + 1), dst_size - 1);
        dst[dst_size - 1] = '\0';
        return;
    }
    size_t current = strlen(dst);
    if (current + src_len >= dst_size) {
        size_t drop = current + src_len - dst_size + 1;
        if (drop >= current) {
            dst[0] = '\0';
            current = 0;
        } else {
            memmove(dst, dst + drop, current - drop + 1);
            current -= drop;
        }
    }
    memcpy(dst + current, src, src_len);
    dst[current + src_len] = '\0';
}

static void set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags >= 0) {
        (void)fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    }
}

static void read_available_tail(int fd, char *dst, size_t dst_size, bool *open_flag) {
    char buf[512];
    for (;;) {
        ssize_t n = read(fd, buf, sizeof(buf));
        if (n > 0) {
            size_t copy = (size_t)n;
            if (copy > sizeof(buf)) {
                copy = sizeof(buf);
            }
            append_tail(dst, dst_size, buf, copy);
            continue;
        }
        if (n == 0) {
            *open_flag = false;
            (void)close(fd);
            return;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
            return;
        }
        *open_flag = false;
        (void)close(fd);
        return;
    }
}

static void run_functional_command(struct functional_test *test) {
    if (!test || !test->command[0]) {
        if (test) {
            snprintf(test->status, sizeof(test->status), "fail");
            snprintf(test->error, sizeof(test->error), "functional command is empty");
        }
        return;
    }

    int stdout_pipe[2] = {-1, -1};
    int stderr_pipe[2] = {-1, -1};
    if (pipe(stdout_pipe) != 0 || pipe(stderr_pipe) != 0) {
        snprintf(test->status, sizeof(test->status), "fail");
        snprintf(test->error, sizeof(test->error), "pipe failed: %s", strerror(errno));
        if (stdout_pipe[0] >= 0) {
            close(stdout_pipe[0]);
        }
        if (stdout_pipe[1] >= 0) {
            close(stdout_pipe[1]);
        }
        if (stderr_pipe[0] >= 0) {
            close(stderr_pipe[0]);
        }
        if (stderr_pipe[1] >= 0) {
            close(stderr_pipe[1]);
        }
        return;
    }

    pid_t pid = fork();
    if (pid < 0) {
        snprintf(test->status, sizeof(test->status), "fail");
        snprintf(test->error, sizeof(test->error), "fork failed: %s", strerror(errno));
        close(stdout_pipe[0]);
        close(stdout_pipe[1]);
        close(stderr_pipe[0]);
        close(stderr_pipe[1]);
        return;
    }

    if (pid == 0) {
        close(stdout_pipe[0]);
        close(stderr_pipe[0]);
        dup2(stdout_pipe[1], STDOUT_FILENO);
        dup2(stderr_pipe[1], STDERR_FILENO);
        close(stdout_pipe[1]);
        close(stderr_pipe[1]);
        execl("/bin/sh", "sh", "-c", test->command, (char *)NULL);
        _exit(127);
    }

    close(stdout_pipe[1]);
    close(stderr_pipe[1]);
    set_nonblocking(stdout_pipe[0]);
    set_nonblocking(stderr_pipe[0]);

    bool stdout_open = true;
    bool stderr_open = true;
    bool child_done = false;
    int child_status = 0;
    time_t started = time(NULL);

    while (stdout_open || stderr_open || !child_done) {
        if (!child_done) {
            pid_t w = waitpid(pid, &child_status, WNOHANG);
            if (w == pid) {
                child_done = true;
            }
        }

        if (!child_done && test->timeout_seconds > 0 &&
            time(NULL) - started >= test->timeout_seconds) {
            test->timed_out = true;
            kill(pid, SIGKILL);
            (void)waitpid(pid, &child_status, 0);
            child_done = true;
        }

        fd_set rfds;
        FD_ZERO(&rfds);
        int max_fd = -1;
        if (stdout_open) {
            FD_SET(stdout_pipe[0], &rfds);
            if (stdout_pipe[0] > max_fd) {
                max_fd = stdout_pipe[0];
            }
        }
        if (stderr_open) {
            FD_SET(stderr_pipe[0], &rfds);
            if (stderr_pipe[0] > max_fd) {
                max_fd = stderr_pipe[0];
            }
        }

        if (max_fd >= 0) {
            struct timeval tv = {
                .tv_sec = 0,
                .tv_usec = 100000,
            };
            int ready = select(max_fd + 1, &rfds, NULL, NULL, &tv);
            if (ready > 0) {
                if (stdout_open && FD_ISSET(stdout_pipe[0], &rfds)) {
                    read_available_tail(stdout_pipe[0], test->stdout_tail, sizeof(test->stdout_tail), &stdout_open);
                }
                if (stderr_open && FD_ISSET(stderr_pipe[0], &rfds)) {
                    read_available_tail(stderr_pipe[0], test->stderr_tail, sizeof(test->stderr_tail), &stderr_open);
                }
            }
        } else if (!child_done) {
            struct timespec ts = {
                .tv_sec = 0,
                .tv_nsec = 100000000,
            };
            (void)nanosleep(&ts, NULL);
        }
    }

    if (stdout_open) {
        close(stdout_pipe[0]);
    }
    if (stderr_open) {
        close(stderr_pipe[0]);
    }

    if (test->timed_out) {
        test->exit_code = 124;
        snprintf(test->status, sizeof(test->status), "fail");
        snprintf(test->error, sizeof(test->error), "functional command timed out after %d seconds", test->timeout_seconds);
        return;
    }
    if (WIFEXITED(child_status)) {
        test->exit_code = WEXITSTATUS(child_status);
    } else if (WIFSIGNALED(child_status)) {
        test->exit_code = 128 + WTERMSIG(child_status);
    } else {
        test->exit_code = 125;
    }

    if (test->exit_code != test->expect_exit_code) {
        snprintf(test->status, sizeof(test->status), "fail");
        snprintf(test->error, sizeof(test->error), "expected exit code %d, got %d", test->expect_exit_code, test->exit_code);
        return;
    }
    if (test->expect_stdout_contains[0] &&
        !strstr(test->stdout_tail, test->expect_stdout_contains)) {
        snprintf(test->status, sizeof(test->status), "fail");
        snprintf(test->error, sizeof(test->error), "stdout did not contain expected text");
        return;
    }
    if (test->expect_stderr_contains[0] &&
        !strstr(test->stderr_tail, test->expect_stderr_contains)) {
        snprintf(test->status, sizeof(test->status), "fail");
        snprintf(test->error, sizeof(test->error), "stderr did not contain expected text");
        return;
    }

    snprintf(test->status, sizeof(test->status), "pass");
    test->error[0] = '\0';
}

static void run_functional_tests(struct validator_result *res) {
    if (res->functional_test_count == 0) {
        snprintf(res->functional_status, sizeof(res->functional_status), "skipped");
        return;
    }

    if (!res->load_ok || str_eq(res->attach_status, "fail") || str_eq(res->attach_status, "skipped")) {
        snprintf(res->functional_status, sizeof(res->functional_status), "fail");
        for (int i = 0; i < res->functional_test_count; i++) {
            snprintf(res->functional_tests[i].status, sizeof(res->functional_tests[i].status), "fail");
            snprintf(res->functional_tests[i].error,
                     sizeof(res->functional_tests[i].error),
                     "load/attach did not pass; functional test was not executed");
        }
        return;
    }

    bool required_failed = false;
    bool optional_failed = false;
    for (int i = 0; i < res->functional_test_count; i++) {
        run_functional_command(&res->functional_tests[i]);
        if (!str_eq(res->functional_tests[i].status, "pass")) {
            if (res->functional_tests[i].required) {
                required_failed = true;
            } else {
                optional_failed = true;
            }
        }
    }

    if (required_failed) {
        snprintf(res->functional_status, sizeof(res->functional_status), "fail");
    } else if (optional_failed) {
        snprintf(res->functional_status, sizeof(res->functional_status), "warn");
    } else {
        snprintf(res->functional_status, sizeof(res->functional_status), "pass");
    }
}

static void set_memlock_rlimit(void) {
    struct rlimit rlim = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };
    (void)setrlimit(RLIMIT_MEMLOCK, &rlim);
}

static void discover_programs_and_maps(struct validator_result *res, struct bpf_object *obj) {
    struct bpf_program *prog;
    struct bpf_map *map;

    bpf_object__for_each_program(prog, obj) {
        if (res->program_count < MAX_ITEMS) {
            const char *name = bpf_program__name(prog);
            const char *section = bpf_program__section_name(prog);
            snprintf(res->programs[res->program_count].name,
                     sizeof(res->programs[res->program_count].name),
                     "%s",
                     name ? name : "");
            snprintf(res->programs[res->program_count].section,
                     sizeof(res->programs[res->program_count].section),
                     "%s",
                     section ? section : "");
            snprintf(res->programs[res->program_count].attach_status,
                     sizeof(res->programs[res->program_count].attach_status),
                     "skipped");
            res->programs[res->program_count].attach_error[0] = '\0';
            snprintf(res->programs[res->program_count].load_status,
                     sizeof(res->programs[res->program_count].load_status),
                     "skipped");
            res->programs[res->program_count].load_errno = 0;
            res->programs[res->program_count].load_log[0] = '\0';
        }
        res->program_count++;
    }

    bpf_object__for_each_map(map, obj) {
        res->map_count++;
    }
}

static void finalize_attach_status(struct validator_result *res, enum attach_mode mode) {
    if (!res->load_ok) {
        snprintf(res->attach_status, sizeof(res->attach_status), "skipped");
        return;
    }

    if (mode == ATTACH_MODE_DISABLED) {
        snprintf(res->attach_status, sizeof(res->attach_status), "skipped");
        return;
    }

    if (res->attach_attempted == 0) {
        snprintf(res->attach_status, sizeof(res->attach_status), "skipped");
        return;
    }

    if (res->attach_failed == 0) {
        snprintf(res->attach_status, sizeof(res->attach_status), "pass");
        return;
    }

    if (mode == ATTACH_MODE_REQUIRED) {
        snprintf(res->attach_status, sizeof(res->attach_status), "fail");
        return;
    }

    snprintf(res->attach_status, sizeof(res->attach_status), "warn");
}

static void run_attach_attempts(struct validator_result *res, struct bpf_object *obj) {
    enum attach_mode mode = parse_attach_mode(res->opts.attach_mode);
    if (mode == ATTACH_MODE_DISABLED || !res->load_ok) {
        finalize_attach_status(res, mode);
        return;
    }

    struct bpf_program *prog;
    int program_index = 0;
    bpf_object__for_each_program(prog, obj) {
        bool track = program_index < MAX_ITEMS;
        const char *section = bpf_program__section_name(prog);

        if (!is_auto_attach_candidate(section)) {
            if (track) {
                snprintf(res->programs[program_index].attach_status,
                         sizeof(res->programs[program_index].attach_status),
                         "skipped");
                snprintf(res->programs[program_index].attach_error,
                         sizeof(res->programs[program_index].attach_error),
                         "section is not an auto-attach candidate");
            }
            program_index++;
            continue;
        }

        res->attach_attempted++;
        struct bpf_link *link = bpf_program__attach(prog);
        if (!link) {
            int err = errno ? -errno : -EINVAL;
            res->attach_failed++;
            if (track) {
                snprintf(res->programs[program_index].attach_status,
                         sizeof(res->programs[program_index].attach_status),
                         "fail");
                set_errno_message(err,
                                  res->programs[program_index].attach_error,
                                  sizeof(res->programs[program_index].attach_error));
            }
        } else {
            res->attach_passed++;
            if (track) {
                snprintf(res->programs[program_index].attach_status,
                         sizeof(res->programs[program_index].attach_status),
                         "pass");
            }
            if (res->link_count < MAX_ITEMS) {
                res->links[res->link_count++] = link;
            } else {
                (void)bpf_link__destroy(link);
            }
        }

        program_index++;
    }

    finalize_attach_status(res, mode);
}

static void destroy_links(struct validator_result *res) {
    for (int i = 0; i < res->link_count; i++) {
        if (res->links[i]) {
            (void)bpf_link__destroy(res->links[i]);
            res->links[i] = NULL;
        }
    }
    res->link_count = 0;
}

/* Trial-load a single program in isolation: re-open the object, enable autoload
 * for only the program at the given index in ELF order, and report whether it
 * loads on this kernel. This identifies an individual unsupported program
 * (newer-kernel helper, or an LSM hook absent on this kernel) that would
 * otherwise be masked by the atomic whole-object load — mirroring how a real
 * agent gates optional programs by capability. Indexing by position (not name)
 * is robust to artifacts that contain two programs with the same function name.
 * Returns 0 on success or a negative errno. */
/* Inner-map prototype fds created by apply_map_fixups. They must stay open
 * until the owning bpf_object load completes; the validator is
 * single-threaded and loads are sequential, so one shared pool whose entries
 * are closed right after each object closes is sufficient. */
static int g_inner_map_fds[MAX_MAP_FIXUPS];
static int g_inner_map_fd_count;

static void close_inner_map_fds(void) {
    for (int i = 0; i < g_inner_map_fd_count; i++) {
        close(g_inner_map_fds[i]);
    }
    g_inner_map_fd_count = 0;
}

static void record_fixup(struct map_fixup *fx, bool record, const char *status, int err,
                         unsigned int entries) {
    if (!record) {
        return;
    }
    snprintf(fx->status, sizeof(fx->status), "%s", status);
    fx->err = err;
    fx->applied_entries = entries;
}

/* Apply manifest-declared map fixups between open and load, mirroring what
 * the artifact's own loader does for runtime-sized maps. `record` writes
 * per-fixup status back into opts for the result JSON; trial loads pass
 * false so they don't overwrite the whole-object outcome. */
static void apply_map_fixups(struct options *opts, struct bpf_object *obj, bool record) {
    for (int i = 0; i < opts->map_fixup_count; i++) {
        struct map_fixup *fx = &opts->map_fixups[i];
        struct bpf_map *map = bpf_object__find_map_by_name(obj, fx->name);
        if (!map) {
            record_fixup(fx, record, "map_not_found", 0, 0);
            continue;
        }

        unsigned int entries = 0;
        if (fx->max_entries[0]) {
            if (strcmp(fx->max_entries, "cpus") == 0) {
                int cpus = libbpf_num_possible_cpus();
                entries = cpus > 0 ? (unsigned int)cpus : 1;
            } else {
                entries = (unsigned int)strtoul(fx->max_entries, NULL, 10);
            }
            int err = bpf_map__set_max_entries(map, entries);
            if (err) {
                record_fixup(fx, record, "error", err, entries);
                continue;
            }
        }

        if (fx->inner_ringbuf_bytes > 0) {
            int inner_fd = bpf_map_create(BPF_MAP_TYPE_RINGBUF, NULL, 0, 0,
                                          fx->inner_ringbuf_bytes, NULL);
            if (inner_fd < 0) {
                record_fixup(fx, record, "error", inner_fd, entries);
                continue;
            }
            int err = bpf_map__set_inner_map_fd(map, inner_fd);
            if (err) {
                close(inner_fd);
                record_fixup(fx, record, "error", err, entries);
                continue;
            }
            if (g_inner_map_fd_count < MAX_MAP_FIXUPS) {
                g_inner_map_fds[g_inner_map_fd_count++] = inner_fd;
            }
        }

        if (fx->inner_map_type > 0) {
            int inner_fd = bpf_map_create((enum bpf_map_type)fx->inner_map_type, NULL,
                                          fx->inner_key_size, fx->inner_value_size,
                                          fx->inner_max_entries, NULL);
            if (inner_fd < 0) {
                record_fixup(fx, record, "error", inner_fd, entries);
                continue;
            }
            int err = bpf_map__set_inner_map_fd(map, inner_fd);
            if (err) {
                close(inner_fd);
                record_fixup(fx, record, "error", err, entries);
                continue;
            }
            if (g_inner_map_fd_count < MAX_MAP_FIXUPS) {
                g_inner_map_fds[g_inner_map_fd_count++] = inner_fd;
            }
        }

        record_fixup(fx, record, "applied", 0, entries);
    }
}

/* Auto-sizing of runtime-sized maps. Many real loaders (Inspektor Gadget,
 * KubeArmor, Falco's libpman) compile maps with max_entries=0 and set the
 * real size at load time from a userspace parameter. A generic load can't,
 * so map creation fails with EINVAL on every kernel — a loader contract, not
 * a compatibility result. We give such maps a default size so the object
 * loads, matching what the real loader does. Manifest fixups run first and
 * win; only maps still at 0 are touched. */
#define AUTOSIZE_DEFAULT_MAX_ENTRIES 4096u
#define MAX_AUTOSIZED_MAPS 64

struct autosized_map {
    char name[68];
    unsigned int map_type;
    unsigned int max_entries;
};
static struct autosized_map g_autosized[MAX_AUTOSIZED_MAPS];
static int g_autosized_count;

/* Only types where max_entries==0 is invalid AND a positive size is what the
 * real loader supplies. Deliberately excludes types where 0 is meaningful:
 * PERF_EVENT_ARRAY (kernel uses nr_cpus), RINGBUF/USER_RINGBUF (byte size),
 * and the *_STORAGE local-storage maps (which REQUIRE max_entries==0). */
static bool map_type_needs_size(unsigned int t) {
    switch (t) {
    case BPF_MAP_TYPE_HASH:
    case BPF_MAP_TYPE_ARRAY:
    case BPF_MAP_TYPE_PROG_ARRAY:
    case BPF_MAP_TYPE_PERCPU_HASH:
    case BPF_MAP_TYPE_PERCPU_ARRAY:
    case BPF_MAP_TYPE_STACK_TRACE:
    case BPF_MAP_TYPE_LRU_HASH:
    case BPF_MAP_TYPE_LRU_PERCPU_HASH:
    case BPF_MAP_TYPE_LPM_TRIE:
        return true;
    default:
        return false;
    }
}

static void auto_size_maps(struct bpf_object *obj) {
    struct bpf_map *map;
    bpf_object__for_each_map(map, obj) {
        if (bpf_map__max_entries(map) != 0) {
            continue;
        }
        unsigned int t = (unsigned int)bpf_map__type(map);
        if (!map_type_needs_size(t)) {
            continue;
        }
        if (bpf_map__set_max_entries(map, AUTOSIZE_DEFAULT_MAX_ENTRIES) != 0) {
            continue;
        }
        if (g_autosized_count < MAX_AUTOSIZED_MAPS) {
            struct autosized_map *a = &g_autosized[g_autosized_count++];
            snprintf(a->name, sizeof(a->name), "%s", bpf_map__name(map));
            a->map_type = t;
            a->max_entries = AUTOSIZE_DEFAULT_MAX_ENTRIES;
        }
    }
}

/* Programs whose ELF section name libbpf can't map to a program type get
 * auto-typed the way the real loader would. The motivating case: Inspektor
 * Gadget's socket-filter programs live in sections like "socket1", which
 * libbpf doesn't recognize (it matches "socket" exactly or "socket/..."), so
 * the load fails with "missing BPF prog type". Only programs libbpf left as
 * UNSPEC are touched, and only for section families that unambiguously imply
 * a type — today socket-filter. Other families (kprobe/, tracepoint/, ...)
 * already use libbpf's "<type>/..." convention and resolve on their own. */
#define MAX_AUTOTYPED_PROGS 64

struct autotyped_prog {
    char name[128];
    char section[128];
    unsigned int prog_type;
};
static struct autotyped_prog g_autotyped[MAX_AUTOTYPED_PROGS];
static int g_autotyped_count;

static void auto_type_programs(struct bpf_object *obj) {
    struct bpf_program *prog;
    bpf_object__for_each_program(prog, obj) {
        if (bpf_program__type(prog) != BPF_PROG_TYPE_UNSPEC) {
            continue;
        }
        const char *section = bpf_program__section_name(prog);
        if (!section) {
            continue;
        }
        unsigned int t = 0;
        if (strncmp(section, "socket", 6) == 0) {
            t = BPF_PROG_TYPE_SOCKET_FILTER;
        }
        if (t == 0) {
            continue;
        }
        if (bpf_program__set_type(prog, (enum bpf_prog_type)t) != 0) {
            continue;
        }
        if (g_autotyped_count < MAX_AUTOTYPED_PROGS) {
            struct autotyped_prog *a = &g_autotyped[g_autotyped_count++];
            snprintf(a->name, sizeof(a->name), "%s", bpf_program__name(prog));
            snprintf(a->section, sizeof(a->section), "%s", section);
            a->prog_type = t;
        }
    }
}

/* Select one variant per group the way the artifact's loader does: walk in
 * priority order, probe required helpers against this kernel, autoload the
 * first satisfying variant and disable the rest. Probing uses
 * BPF_PROG_TYPE_RAW_TRACEPOINT to match Falco's libpman; helper support is
 * not program-type-specific for the helpers this gates. */
/* Probe a variant the way Falco's iter_support_probing does: open a fresh
 * object, apply map fixups, disable every program except the probed one and
 * the declared prog-array companions, and attempt a real load. */
static bool trial_probe_variant(struct options *opts, const char *prog_name) {
    struct bpf_object *o = bpf_object__open_file(opts->artifact, NULL);
    if (!o) {
        return false;
    }
    apply_map_fixups(opts, o, false);

    struct bpf_program *p;
    bpf_object__for_each_program(p, o) {
        bpf_program__set_autoload(p, false);
    }
    for (int i = 0; i < opts->probe_companion_count; i++) {
        struct bpf_program *companion =
            bpf_object__find_program_by_name(o, opts->probe_companions[i]);
        if (companion) {
            bpf_program__set_autoload(companion, true);
        }
    }
    struct bpf_program *target = bpf_object__find_program_by_name(o, prog_name);
    if (!target) {
        bpf_object__close(o);
        close_inner_map_fds();
        return false;
    }
    bpf_program__set_autoload(target, true);

    int err = bpf_object__load(o);
    bpf_object__close(o);
    close_inner_map_fds();
    return err == 0;
}

static void apply_prog_variants(struct options *opts, struct bpf_object *obj) {
    for (int g = 0; g < opts->variant_group_count; g++) {
        struct prog_variant_group *grp = &opts->variant_groups[g];
        grp->chosen = -1;
        for (int v = 0; v < grp->count; v++) {
            struct bpf_program *prog = bpf_object__find_program_by_name(obj, grp->names[v]);
            if (!prog) {
                continue;
            }
            bool satisfied = grp->chosen == -1;
            if (satisfied && grp->helper_ids[v] > 0) {
                satisfied = libbpf_probe_bpf_helper(BPF_PROG_TYPE_RAW_TRACEPOINT,
                                                    (enum bpf_func_id)grp->helper_ids[v],
                                                    NULL) == 1;
            }
            if (satisfied && grp->trial_probe[v]) {
                satisfied = trial_probe_variant(opts, grp->names[v]);
            }
            if (satisfied) {
                grp->chosen = v;
                bpf_program__set_autoload(prog, true);
            } else {
                bpf_program__set_autoload(prog, false);
            }
        }
    }
}

static int trial_load_one_program(struct options *opts, int target_index) {
    struct bpf_object *o = bpf_object__open_file(opts->artifact, NULL);
    if (!o) {
        return errno ? -errno : -EINVAL;
    }
    apply_map_fixups(opts, o, false);
    struct bpf_program *p;
    int idx = 0;
    bpf_object__for_each_program(p, o) {
        bool is_target = (idx == target_index);
        bpf_program__set_autoload(p, is_target);
        if (is_target) {
            /* Force a verifier log for the target so the failure reason is
             * captured even when libbpf would otherwise emit only a summary. */
            bpf_program__set_log_level(p, 1);
        }
        idx++;
    }
    int err = bpf_object__load(o);
    bpf_object__close(o);
    close_inner_map_fds();
    return err;
}

/* Per-trial verifier-log capture. The validator is single-threaded by design,
 * so file-local globals are safe; parallelizing program probes would require
 * removing this shared state. Only one program autoloads per trial, so the
 * captured log is small and the verifier verdict (at the end) is not truncated. */
static char g_trial_log[65536];
static size_t g_trial_log_len;
static int trial_log_callback(enum libbpf_print_level level, const char *fmt, va_list args) {
    /* Skip DEBUG (CO-RE relocation spam) so the failure verdict — emitted at
     * WARN when a program fails to load — is not crowded out of the buffer. */
    if (level == LIBBPF_DEBUG) {
        return 0;
    }
    int n = vsnprintf(g_print_buf, sizeof(g_print_buf), fmt, args);
    if (n <= 0) {
        return n;
    }
    /* vsnprintf returns the would-be-written length, which can exceed the
     * buffer on truncation. Clamp before memcpy so we never read past it. */
    size_t copy = (size_t)n;
    if (copy >= sizeof(g_print_buf)) {
        copy = sizeof(g_print_buf) - 1;
    }
    /* Keep the tail: the verifier verdict is at the end of the log. */
    append_tail(g_trial_log, sizeof(g_trial_log), g_print_buf, copy);
    g_trial_log_len = strlen(g_trial_log);
    return n;
}

/* Record per-program isolated load results. Purely additive: the whole-object
 * load and its status are left unchanged. For a failed isolated load we also
 * capture the tail of that program's verifier message. Gated under
 * --probe-features because each trial issues a real bpf() load syscall —
 * operators who explicitly disabled feature probing don't want N more. */
static void probe_per_program_loads(struct validator_result *res) {
    if (!res->opts.probe_features) {
        return;
    }
    int max_items = res->program_count < MAX_ITEMS ? res->program_count : MAX_ITEMS;
    for (int i = 0; i < max_items; i++) {
        g_trial_log_len = 0;
        g_trial_log[0] = '\0';
        libbpf_set_print(trial_log_callback);
        int e = trial_load_one_program(&res->opts, i);
        libbpf_set_print(NULL);
        res->programs[i].load_errno = e;
        const char *status = e == 0 ? "pass" : "fail";
        /* Objects that statically initialize prog-array slots (tail-call
         * dispatch tables) cannot be loaded one-program-at-a-time: libbpf
         * fails slot initialization with EBADF because the referenced
         * programs are not autoloaded. That is a limitation of isolated
         * loading, not per-program kernel evidence — report it as skipped. */
        if (e == -EBADF && strstr(g_trial_log, "failed to initialize slot") != NULL) {
            status = "skipped";
        }
        snprintf(res->programs[i].load_status, sizeof(res->programs[i].load_status),
                 "%s", status);
        if (e != 0 && strcmp(status, "fail") == 0 && g_trial_log_len > 0) {
            /* keep the tail — the verifier verdict is at the end */
            size_t keep = sizeof(res->programs[i].load_log) - 1;
            const char *start =
                g_trial_log_len > keep ? g_trial_log + (g_trial_log_len - keep) : g_trial_log;
            snprintf(res->programs[i].load_log, sizeof(res->programs[i].load_log), "%s", start);
        }
    }
    libbpf_set_print(libbpf_log_callback);
}

static void run_libbpf_load(struct validator_result *res) {
    struct bpf_object *obj = NULL;

    libbpf_set_print(libbpf_log_callback);
    set_memlock_rlimit();
    snprintf(res->attach_status, sizeof(res->attach_status), "skipped");

    obj = bpf_object__open_file(res->opts.artifact, NULL);
    if (!obj) {
        int err = errno ? -errno : -EINVAL;
        res->load_ok = false;
        res->load_errno = err;
        set_errno_message(err, res->load_error, sizeof(res->load_error));
        finalize_attach_status(res, parse_attach_mode(res->opts.attach_mode));
        return;
    }

    discover_programs_and_maps(res, obj);

    probe_per_program_loads(res);

    /* Variant selection first: its trial probes open their own objects and
     * close their own inner-map fds, which must not race the main object's
     * fixup fds — those are created after this and stay open through load. */
    apply_prog_variants(&res->opts, obj);
    apply_map_fixups(&res->opts, obj, true);
    auto_size_maps(obj);
    auto_type_programs(obj);

    int err = bpf_object__load(obj);
    if (err) {
        res->load_ok = false;
        res->load_errno = err;
        set_errno_message(err, res->load_error, sizeof(res->load_error));
    } else {
        res->load_ok = true;
        res->load_errno = 0;
        res->load_error[0] = '\0';
    }

    run_attach_attempts(res, obj);
    run_functional_tests(res);
    destroy_links(res);

    bpf_object__close(obj);
    close_inner_map_fds();
}

static const char *overall_status(const struct validator_result *res) {
    if (!res->load_ok) {
        return "fail";
    }
    if (str_eq(res->attach_status, "fail")) {
        return "fail";
    }
    if (str_eq(res->functional_status, "fail")) {
        return "fail";
    }
    return "pass";
}

static void write_probe_status_json(FILE *f, const struct probe_status *status) {
    if (!f || !status) {
        return;
    }
    fprintf(f, "{\"status\":\"");
    escape_json_string(f, status->status);
    fprintf(f, "\",\"error_code\":%d,\"error\":\"", status->error_code);
    escape_json_string(f, status->error);
    fprintf(f, "\"}");
}

static int write_result_json(const struct validator_result *res) {
    FILE *f = fopen(res->opts.out, "w");
    if (!f) {
        fprintf(stderr, "open output file failed: %s\n", strerror(errno));
        return 1;
    }

    fprintf(f, "{\n");
    fprintf(f, "  \"schema_version\": \"validator.v0.4\",\n");
    fprintf(f, "  \"timestamp\": \"");
    escape_json_string(f, res->timestamp);
    fprintf(f, "\",\n");
    fprintf(f, "  \"status\": \"%s\",\n", overall_status(res));
    fprintf(f, "  \"host\": {\n");
    fprintf(f, "    \"sysname\": \"");
    escape_json_string(f, res->host.sysname);
    fprintf(f, "\",\n");
    fprintf(f, "    \"nodename\": \"");
    escape_json_string(f, res->host.nodename);
    fprintf(f, "\",\n");
    fprintf(f, "    \"release\": \"");
    escape_json_string(f, res->host.release);
    fprintf(f, "\",\n");
    fprintf(f, "    \"version\": \"");
    escape_json_string(f, res->host.version);
    fprintf(f, "\",\n");
    fprintf(f, "    \"machine\": \"");
    escape_json_string(f, res->host.machine);
    fprintf(f, "\"\n");
    fprintf(f, "  },\n");
    fprintf(f, "  \"input\": {\n");
    fprintf(f, "    \"artifact\": \"");
    escape_json_string(f, res->opts.artifact ? res->opts.artifact : "");
    fprintf(f, "\",\n");
    fprintf(f, "    \"manifest\": \"");
    escape_json_string(f, res->opts.manifest ? res->opts.manifest : "");
    fprintf(f, "\",\n");
    fprintf(f, "    \"functional_plan\": \"");
    escape_json_string(f, res->opts.functional_plan ? res->opts.functional_plan : "");
    fprintf(f, "\",\n");
    fprintf(f, "    \"attach_mode\": \"");
    escape_json_string(f, res->opts.attach_mode ? res->opts.attach_mode : "");
    fprintf(f, "\",\n");
    fprintf(f, "    \"probe_features\": %s\n", res->opts.probe_features ? "true" : "false");
    fprintf(f, "  },\n");
    fprintf(f, "  \"map_fixups\": [");
    for (int i = 0; i < res->opts.map_fixup_count; i++) {
        const struct map_fixup *fx = &res->opts.map_fixups[i];
        fprintf(f, "%s{\"name\":\"", i == 0 ? "" : ",");
        escape_json_string(f, fx->name);
        fprintf(f, "\",\"max_entries\":\"");
        escape_json_string(f, fx->max_entries);
        fprintf(f, "\",\"inner_ringbuf_bytes\":%u", fx->inner_ringbuf_bytes);
        fprintf(f, ",\"inner_map_type\":%u,\"inner_key_size\":%u,\"inner_value_size\":%u,\"inner_max_entries\":%u",
                fx->inner_map_type, fx->inner_key_size, fx->inner_value_size, fx->inner_max_entries);
        fprintf(f, ",\"status\":\"");
        escape_json_string(f, fx->status);
        fprintf(f, "\",\"errno\":%d,\"applied_entries\":%u}", fx->err, fx->applied_entries);
    }
    fprintf(f, "],\n");
    fprintf(f, "  \"auto_sized_maps\": [");
    for (int i = 0; i < g_autosized_count; i++) {
        fprintf(f, "%s{\"name\":\"", i == 0 ? "" : ",");
        escape_json_string(f, g_autosized[i].name);
        fprintf(f, "\",\"map_type\":%u,\"max_entries\":%u}", g_autosized[i].map_type, g_autosized[i].max_entries);
    }
    fprintf(f, "],\n");
    fprintf(f, "  \"auto_typed_programs\": [");
    for (int i = 0; i < g_autotyped_count; i++) {
        fprintf(f, "%s{\"name\":\"", i == 0 ? "" : ",");
        escape_json_string(f, g_autotyped[i].name);
        fprintf(f, "\",\"section\":\"");
        escape_json_string(f, g_autotyped[i].section);
        fprintf(f, "\",\"prog_type\":%u}", g_autotyped[i].prog_type);
    }
    fprintf(f, "],\n");
    fprintf(f, "  \"program_variants\": [");
    for (int g = 0; g < res->opts.variant_group_count; g++) {
        const struct prog_variant_group *grp = &res->opts.variant_groups[g];
        fprintf(f, "%s{\"group\":\"", g == 0 ? "" : ",");
        escape_json_string(f, grp->group);
        fprintf(f, "\",\"chosen\":\"");
        if (grp->chosen >= 0) {
            escape_json_string(f, grp->names[grp->chosen]);
        }
        fprintf(f, "\",\"disabled\":[");
        bool first = true;
        for (int v = 0; v < grp->count; v++) {
            if (v == grp->chosen) {
                continue;
            }
            fprintf(f, "%s\"", first ? "" : ",");
            escape_json_string(f, grp->names[v]);
            fprintf(f, "\"");
            first = false;
        }
        fprintf(f, "]}");
    }
    fprintf(f, "],\n");
    fprintf(f, "  \"btf\": {\n");
    fprintf(f, "    \"kernel_btf_available\": %s,\n", res->kernel_btf_available ? "true" : "false");
    fprintf(f, "    \"kernel_btf_path\": \"/sys/kernel/btf/vmlinux\",\n");
    fprintf(f, "    \"kernel_btf_size\": %lld,\n", res->kernel_btf_size);
    fprintf(f, "    \"artifact_has_btf\": %s,\n", res->artifact_has_btf ? "true" : "false");
    fprintf(f, "    \"artifact_has_btf_ext\": %s\n", res->artifact_has_btf_ext ? "true" : "false");
    fprintf(f, "  },\n");
    fprintf(f, "  \"capabilities\": {\n");
    fprintf(f, "    \"bpftool_available\": %s,\n", res->bpftool_available ? "true" : "false");
    fprintf(f, "    \"bpftool_probe_ok\": %s,\n", res->bpftool_probe_ok ? "true" : "false");
    fprintf(f, "    \"bpftool_probe_output_path\": \"");
    escape_json_string(f, res->bpftool_probe_output_path);
    fprintf(f, "\",\n");
    fprintf(f, "    \"map_types\": {\n");
    fprintf(f, "      \"ringbuf\": ");
    write_probe_status_json(f, &res->map_probe_ringbuf);
    fprintf(f, ",\n");
    fprintf(f, "      \"perf_event_array\": ");
    write_probe_status_json(f, &res->map_probe_perf_event_array);
    fprintf(f, ",\n");
    fprintf(f, "      \"array\": ");
    write_probe_status_json(f, &res->map_probe_array);
    fprintf(f, ",\n");
    fprintf(f, "      \"hash\": ");
    write_probe_status_json(f, &res->map_probe_hash);
    fprintf(f, "\n");
    fprintf(f, "    },\n");
    fprintf(f, "    \"program_types\": {\n");
    fprintf(f, "      \"tracepoint\": ");
    write_probe_status_json(f, &res->prog_probe_tracepoint);
    fprintf(f, ",\n");
    fprintf(f, "      \"kprobe\": ");
    write_probe_status_json(f, &res->prog_probe_kprobe);
    fprintf(f, ",\n");
    fprintf(f, "      \"tracing\": ");
    write_probe_status_json(f, &res->prog_probe_tracing);
    fprintf(f, ",\n");
    fprintf(f, "      \"xdp\": ");
    write_probe_status_json(f, &res->prog_probe_xdp);
    fprintf(f, "\n");
    fprintf(f, "    },\n");
    fprintf(f, "    \"attach_prereqs\": {\n");
    fprintf(f, "      \"tracefs\": \"%s\",\n", res->tracefs_available ? "present" : "missing");
    fprintf(f,
            "      \"kprobe_events\": \"%s\",\n",
            res->kprobe_events_available ? "present" : "missing");
    fprintf(f,
            "      \"tracepoint_events\": \"%s\"\n",
            res->tracepoint_events_available ? "present" : "missing");
    fprintf(f, "    }\n");
    fprintf(f, "  },\n");
    fprintf(f, "  \"discovery\": {\n");
    fprintf(f, "    \"program_count\": %d,\n", res->program_count);
    fprintf(f, "    \"map_count\": %d,\n", res->map_count);
    fprintf(f, "    \"programs\": [\n");
    int max_items = res->program_count < MAX_ITEMS ? res->program_count : MAX_ITEMS;
    for (int i = 0; i < max_items; i++) {
        fprintf(f, "      {\"name\":\"");
        escape_json_string(f, res->programs[i].name);
        fprintf(f, "\",\"section\":\"");
        escape_json_string(f, res->programs[i].section);
        fprintf(f, "\",\"attach_status\":\"");
        escape_json_string(f, res->programs[i].attach_status);
        fprintf(f, "\",\"attach_error\":\"");
        escape_json_string(f, res->programs[i].attach_error);
        fprintf(f, "\",\"load_status\":\"");
        escape_json_string(f, res->programs[i].load_status);
        fprintf(f, "\",\"load_errno\":%d,\"load_log\":\"", res->programs[i].load_errno);
        escape_json_string(f, res->programs[i].load_log);
        fprintf(f, "\"}%s\n", (i + 1 == max_items) ? "" : ",");
    }
    fprintf(f, "    ]\n");
    fprintf(f, "  },\n");
    fprintf(f, "  \"load\": {\n");
    fprintf(f, "    \"status\": \"%s\",\n", res->load_ok ? "pass" : "fail");
    fprintf(f, "    \"error_code\": %d,\n", res->load_errno);
    fprintf(f, "    \"error\": \"");
    escape_json_string(f, res->load_error);
    fprintf(f, "\"\n");
    fprintf(f, "  },\n");
    fprintf(f, "  \"attach\": {\n");
    fprintf(f, "    \"mode\": \"");
    escape_json_string(f, res->opts.attach_mode ? res->opts.attach_mode : "best-effort");
    fprintf(f, "\",\n");
    fprintf(f, "    \"status\": \"");
    escape_json_string(f, res->attach_status);
    fprintf(f, "\",\n");
    fprintf(f, "    \"attempted\": %d,\n", res->attach_attempted);
    fprintf(f, "    \"passed\": %d,\n", res->attach_passed);
    fprintf(f, "    \"failed\": %d\n", res->attach_failed);
    fprintf(f, "  },\n");
    fprintf(f, "  \"functional\": {\n");
    fprintf(f, "    \"status\": \"");
    escape_json_string(f, res->functional_status);
    fprintf(f, "\",\n");
    fprintf(f, "    \"tests\": [\n");
    for (int i = 0; i < res->functional_test_count; i++) {
        const struct functional_test *test = &res->functional_tests[i];
        fprintf(f, "      {\"name\":\"");
        escape_json_string(f, test->name);
        fprintf(f, "\",\"required\":%s,\"status\":\"", test->required ? "true" : "false");
        escape_json_string(f, test->status);
        fprintf(f, "\",\"command\":\"");
        escape_json_string(f, test->command);
        fprintf(f, "\",\"timeout_seconds\":%d,\"expected_exit_code\":%d,\"exit_code\":%d,\"timed_out\":%s,\"stdout_tail\":\"",
                test->timeout_seconds,
                test->expect_exit_code,
                test->exit_code,
                test->timed_out ? "true" : "false");
        escape_json_string(f, test->stdout_tail);
        fprintf(f, "\",\"stderr_tail\":\"");
        escape_json_string(f, test->stderr_tail);
        fprintf(f, "\",\"error\":\"");
        escape_json_string(f, test->error);
        fprintf(f, "\"}%s\n", (i + 1 == res->functional_test_count) ? "" : ",");
    }
    fprintf(f, "    ]\n");
    fprintf(f, "  },\n");
    fprintf(f, "  \"logs\": {\n");
    fprintf(f, "    \"libbpf\": \"");
    escape_json_string(f, res->libbpf_log);
    fprintf(f, "\"\n");
    fprintf(f, "  }\n");
    fprintf(f, "}\n");

    fclose(f);
    return 0;
}

int main(int argc, char **argv) {
    struct validator_result res;
    memset(&res, 0, sizeof(res));
    g_result = &res;

    int parse_rc = parse_args(argc, argv, &res.opts);
    if (parse_rc == 1) {
        return 0;
    }
    if (parse_rc != 0) {
        usage(argv[0]);
        return 1;
    }

    capture_metadata(&res);
    collect_btf_and_capability_metadata(&res);
    load_functional_plan(&res);
    run_libbpf_load(&res);
    write_libbpf_log_file(&res);
    if (write_result_json(&res) != 0) {
        return 1;
    }

    return str_eq(overall_status(&res), "pass") ? 0 : 2;
}
