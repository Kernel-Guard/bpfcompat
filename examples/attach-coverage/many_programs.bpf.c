// Attach-record fixture: more programs than the validator used to record.
//
// Default build: 80 tracepoint programs (tpm00 .. tpm79), 40 each on
// sys_enter_getpid and sys_enter_getppid, all auto-attachable. The validator
// once wrote per-program records for the first 64 programs only; this object
// has to come back with 80 records and attach_records_truncated false.
//
// -DMANY_PROGRAMS_OVER_BOUND: 1100 programs (tpl100 .. tpl1199), above the
// validator's record bound (MAX_PROGRAM_RECORDS, 1024), to show the bound is
// explicit: records stop at the bound, the result says so, and the counts
// still cover the whole object.
//
// -DMANY_PROGRAMS_ONE_TRACEPOINT: the default 80 programs all on
// sys_enter_getpid. The kernel allows at most 64 BPF programs on one
// tracepoint (BPF_TRACE_MAX_PROGS), so 16 fail to attach -- all of them past
// the 64th program, where the old records could not name them.
//
// -DMANY_PROGRAMS_LAST_CTX_BEYOND: the default 80 programs, except that the
// last one (tpm79) reads its context at offset 512 instead of 8. It still
// loads, but the kernel refuses to attach it (EACCES: the read is beyond the
// sys_enter_getppid record; see ctx_beyond_record.bpf.c). Paired with the
// default build this is an attached -> failed regression at program 80, past
// the old 64-record cap.
//
// No tracepoint carries more than 50 programs in the other builds.
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define TP(name, tp)                                           \
	SEC("tracepoint/syscalls/sys_enter_" #tp)                  \
	int name(void *ctx)                                        \
	{                                                          \
		(void)ctx;                                             \
		return 0;                                              \
	}

#ifdef MANY_PROGRAMS_LAST_CTX_BEYOND
#define LAST_CTX_OFF 512
#else
#define LAST_CTX_OFF 8
#endif

#define TPCTX(name, tp, off)                                   \
	SEC("tracepoint/syscalls/sys_enter_" #tp)                  \
	int name(void *ctx)                                        \
	{                                                          \
		(void)*(volatile __u32 *)((char *)ctx + (off));        \
		return 0;                                              \
	}

#define TP10(p, tp) TP(p##0, tp) TP(p##1, tp) TP(p##2, tp) TP(p##3, tp) TP(p##4, tp) \
	TP(p##5, tp) TP(p##6, tp) TP(p##7, tp) TP(p##8, tp) TP(p##9, tp)
/* 100 programs, 50 on each of two tracepoints. */
#define TP100(p, a, b) TP10(p##0, a) TP10(p##1, a) TP10(p##2, a) TP10(p##3, a) TP10(p##4, a) \
	TP10(p##5, b) TP10(p##6, b) TP10(p##7, b) TP10(p##8, b) TP10(p##9, b)

#if defined(MANY_PROGRAMS_OVER_BOUND)
TP100(tpl1, getpid, getppid)
TP100(tpl2, getuid, geteuid)
TP100(tpl3, getgid, getegid)
TP100(tpl4, gettid, getpgrp)
TP100(tpl5, sched_yield, umask)
TP100(tpl6, sync, pause)
TP100(tpl7, alarm, times)
TP100(tpl8, getcwd, dup)
TP100(tpl9, dup2, close)
TP100(tpl10, read, write)
TP100(tpl11, openat, getrusage)
#elif defined(MANY_PROGRAMS_ONE_TRACEPOINT)
TP10(tpm0, getpid) TP10(tpm1, getpid) TP10(tpm2, getpid) TP10(tpm3, getpid)
TP10(tpm4, getpid) TP10(tpm5, getpid) TP10(tpm6, getpid) TP10(tpm7, getpid)
#else
TP10(tpm0, getpid) TP10(tpm1, getpid) TP10(tpm2, getpid) TP10(tpm3, getpid)
TP10(tpm4, getppid) TP10(tpm5, getppid) TP10(tpm6, getppid)
TP(tpm70, getppid) TP(tpm71, getppid) TP(tpm72, getppid) TP(tpm73, getppid)
TP(tpm74, getppid) TP(tpm75, getppid) TP(tpm76, getppid) TP(tpm77, getppid)
TP(tpm78, getppid) TPCTX(tpm79, getppid, LAST_CTX_OFF)
#endif

char LICENSE[] SEC("license") = "GPL";
