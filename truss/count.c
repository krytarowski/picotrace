/*	$NetBSD$	*/

/*-
 * Copyright (c) 2019 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Kamil Rytarowski.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */


#include <sys/syscall.h>

#include <assert.h>
#include <elf.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <threads.h>
#include <unistd.h>

#include <util.h>

#include "children.h"
#include "misc.h"
#include "syscalls.h"
#include "trace.h"
#include "xutils.h"

#include "truss.h"

static void setup_ops(void);

static void print_summary(void);
static void resolve_child_name(pid_t, char *, size_t);
static void detach_child(pid_t pid);
static void signal_handler(int dummy);
static void siginfo_child(pid_t pid);
static void siginfo_handler(int dummy);

static int mode;
static FILE *output;				/* -o */

#define PRINT(fmt, ...)							\
	do {								\
		fprintf(output, fmt, ## __VA_ARGS__);			\
	} while(0)

struct timespec start_ts;

struct syscall_stats {
	struct timespec ts;
	uint64_t ncalls;
	uint64_t nerrors;
	uint64_t missed_sce;
	uint64_t missed_scx;
};

static struct syscall_stats *stats;

static mtx_t mtx;		/* Protects pid_tree */

/* Process related variables */
struct pid_context {
	char name[NAME_MAX];
	struct timespec startup_ts;
	void *lwp_tree;	/* No need to protect as NetBSD stops all LWPs */
};

static void *pid_tree;
static thread_local struct pid_context *pid_ctx;

/* Thread related variables */
struct lwp_context {
	struct timespec sce_ts;
	struct timespec scx_ts;
	int current_syscall;
};

static struct timespec now_ts; /* used by the SIGINFO signal handler */

void
count_main(FILE *out, int m)
{

	output = out;
	mode = m;

	setup_ops();

	xmtx_init(&mtx, mtx_plain);
	pid_tree = children_tree_init();

	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);
	signal(SIGHUP, signal_handler);

	signal(SIGINFO, siginfo_handler);

	xtimespec_get(&start_ts, TIME_UTC);

	stats = ecalloc(SYS_NSYSENT, sizeof(struct syscall_stats));
}

static void
count_end(void)
{

	print_summary();
}

static void
count_startup(pid_t pid)
{
	struct timespec ts;
#ifdef PT_LWPNEXT
	struct ptrace_lwpstatus pl;
	int op = PT_LWPNEXT;
#else
	struct ptrace_lwpinfo pl;
	int op = PT_LWPNEXT;
#endif

	ptrace_event_t pe;
	struct lwp_context *lwp_ctx;

	pid_ctx = emalloc(sizeof(*pid_ctx));

	resolve_child_name(pid, pid_ctx->name, sizeof(pid_ctx->name));
	pid_ctx->lwp_tree = children_tree_init();

	pl.pl_lwpid = 0;
	while (ptrace(op, pid, (void *)&pl, sizeof(pl)) != -1
		&& pl.pl_lwpid != 0) {
		lwp_ctx = emalloc(sizeof(*lwp_ctx));
		lwp_ctx->current_syscall = -1;
		children_tree_insert(pid_ctx->lwp_tree, pl.pl_lwpid, lwp_ctx);
	}

	xtimespec_get(&pid_ctx->startup_ts, TIME_UTC);

	mtx_lock(&mtx);
	children_tree_insert(pid_tree, pid, pid_ctx);
	mtx_unlock(&mtx);

	if (mode & MODE_INHERIT) {
		pe.pe_set_event |= PTRACE_FORK;
		pe.pe_set_event |= PTRACE_VFORK;
		pe.pe_set_event |= PTRACE_VFORK_DONE;
		pe.pe_set_event |= PTRACE_POSIX_SPAWN;
	}

	pe.pe_set_event |= PTRACE_LWP_CREATE;
	pe.pe_set_event |= PTRACE_LWP_EXIT;

	xptrace(PT_SET_EVENT_MASK, pid, &pe, sizeof(pe));
}

static void
count_unstop(pid_t pid)
{
	ptrace_siginfo_t psi;
	int signo;

	xptrace(PT_GET_SIGINFO, pid, &psi, sizeof(psi));
	signo = psi.psi_siginfo.si_signo;

	if (signo == SIGTRAP) {
		switch (psi.psi_siginfo.si_code) {
		case TRAP_SCE:
			/* FALLTHROUGH */
		case TRAP_SCX:
			/* FALLTHROUGH */
		case TRAP_EXEC:
			/* FALLTHROUGH */
		case TRAP_LWP:
			/* FALLTHROUGH */
		case TRAP_CHLD:
			/* FALLTHROUGH */
		case TRAP_BRKPT:
			/* FALLTHROUGH */
		case TRAP_DBREG:
			/* FALLTHROUGH */
		case TRAP_TRACE:
			signo = 0;
			break;
		default:
			break;
		}
	}

	xptrace(PT_SYSCALL, pid, (void *)1, signo);
}

static void
count_continued(pid_t pid)
{
}

static void
count_signaled(pid_t pid, int sig, int core)
{
}

static void
count_exited(pid_t pid, int status)
{
}

static void
count_cleanup(pid_t pid)
{

	mtx_lock(&mtx);
	children_tree_remove(pid_tree, pid);
	mtx_unlock(&mtx);

	children_tree_destroy(pid_ctx->lwp_tree);

	free(pid_ctx);
}

static void
count_debugregister(pid_t pid, lwpid_t lid)
{
}

static void
count_singlestep(pid_t pid, lwpid_t lid)
{
}

static void
count_breakpoint(pid_t pid, lwpid_t lid)
{
}

static void
count_syscallentry(pid_t pid, lwpid_t lid, siginfo_t *si)
{
	struct lwp_context *lwp_ctx;
	struct syscall_stats *s;

	assert(si);
	assert(si->si_sysnum < SYS_NSYSENT);

	lwp_ctx = children_tree_find(pid_ctx->lwp_tree, lid);

	if (!lwp_ctx) {
		/* An event for unregistered LWP.. register this thread now */
		lwp_ctx = ecalloc(1, sizeof(*lwp_ctx));
		children_tree_insert(pid_ctx->lwp_tree, lid, lwp_ctx);
	}

	xtimespec_get(&lwp_ctx->sce_ts, TIME_UTC);

	if (lwp_ctx->current_syscall != -1) {
		s = &stats[si->si_sysnum];
		++(s->missed_scx);
	}

	lwp_ctx->current_syscall = si->si_sysnum;
}

static void
count_syscallexit(pid_t pid, lwpid_t lid, siginfo_t *si)
{
	struct timespec diff_ts;
	struct lwp_context *lwp_ctx;
	struct syscall_stats *s;

	assert(si);
	assert(si->si_sysnum < SYS_NSYSENT);

	lwp_ctx = children_tree_find(pid_ctx->lwp_tree, lid);

	if (!lwp_ctx) {
		/* An event for unregistered LWP.. register this thread now */
		lwp_ctx = ecalloc(1, sizeof(*lwp_ctx));
		children_tree_insert(pid_ctx->lwp_tree, lid, lwp_ctx);
		lwp_ctx->current_syscall = -1;
		return;
	}

	if (lwp_ctx->current_syscall == -1) {
		s = &stats[si->si_sysnum];
		++(s->missed_sce);
		return;
	}

	if (lwp_ctx->current_syscall != si->si_sysnum) {
		s = &stats[lwp_ctx->current_syscall];
		++(s->missed_scx);

		s = &stats[si->si_sysnum];
		++(s->missed_sce);

		return;
	}

	xtimespec_get(&lwp_ctx->scx_ts, TIME_UTC);

	s = &stats[si->si_sysnum];

	timespecsub(&lwp_ctx->scx_ts, &lwp_ctx->sce_ts, &diff_ts);
	timespecadd(&s->ts, &diff_ts, &s->ts);

	if (si->si_error != 0)
		++(s->nerrors);
	++(s->ncalls);

	lwp_ctx->current_syscall = -1;
}

static void
count_exec(pid_t pid, lwpid_t lid)
{
}

static void
count_forked(pid_t pid, lwpid_t lid, pid_t child)
{
	int status;

	xwaitpid(child, &status, 0);

	if (!WIFSTOPPED(status)) {
		warnx("waitpid(%d) returned non-stopped child", child);
		return;
	}

	if (WSTOPSIG(status) != SIGTRAP) {
		warnx("waitpid(%d) returned unexpected signal %s", child,
		    signalname(WSTOPSIG(status)));
		return;
	}

	launch_worker(child);
}

static void
count_vforked(pid_t pid, lwpid_t lid, pid_t child)
{
	int status;

	xwaitpid(child, &status, 0);

	if (!WIFSTOPPED(status)) {
		warnx("waitpid(%d) returned non-stopped child", child);
		return;
	}

	if (WSTOPSIG(status) != SIGTRAP) {
		warnx("waitpid(%d) returned unexpected signal %s", child,
		    signalname(WSTOPSIG(status)));
		return;
	}

	launch_worker(child);
}

static void
count_vforkdone(pid_t pid, lwpid_t lid, pid_t child)
{
}

static void
count_lwpcreated(pid_t pid, lwpid_t lid, lwpid_t lwp)
{
	struct lwp_context *lwp_ctx;

	lwp_ctx = ecalloc(1, sizeof(*lwp_ctx));
	children_tree_insert(pid_ctx->lwp_tree, lwp, lwp_ctx);
}

static void
count_lwpexited(pid_t pid, lwpid_t lid, lwpid_t lwp)
{

	children_tree_remove(pid_ctx->lwp_tree, lwp);
}

static void
count_spawned(pid_t pid, lwpid_t lid, pid_t child)
{
	int status;

	xwaitpid(child, &status, 0);

	if (!WIFSTOPPED(status)) {
		warnx("waitpid(%d) returned non-stopped child", child);
		return;
	}

	if (WSTOPSIG(status) != SIGTRAP) {
		warnx("waitpid(%d) returned unexpected signal %s", child,
		    signalname(WSTOPSIG(status)));
		return;
	}

	launch_worker(child);
}

static void
count_crashed(pid_t pid, lwpid_t lid, siginfo_t *si)
{
}

static void
count_stopped(pid_t pid, lwpid_t lid, siginfo_t *si)
{
}

static void
setup_ops(void)
{

	ops.end = count_end;
	ops.startup = count_startup;
	ops.unstop = count_unstop;
	ops.continued = count_continued;
	ops.signaled = count_signaled;
	ops.exited = count_exited;
	ops.cleanup = count_cleanup;
	ops.debugregister = count_debugregister;
	ops.singlestep = count_singlestep;
	ops.breakpoint = count_breakpoint;
	ops.syscallentry = count_syscallentry;
	ops.syscallexit = count_syscallexit;
	ops.exec = count_exec;
	ops.forked = count_forked;
	ops.vforked = count_vforked;
	ops.vforkdone = count_vforkdone;
	ops.lwpcreated = count_lwpcreated;
	ops.lwpexited = count_lwpexited;
	ops.spawned = count_spawned;
	ops.crashed = count_crashed;
	ops.stopped = count_stopped;
}

static void
print_summary(void)
{
	struct timespec total_ts;
	uint64_t ncalls, nerrors;
	uint64_t missed_sce, missed_scx;
	size_t i;

	timespecclear(&total_ts);
	ncalls = 0;
	nerrors = 0;
	missed_sce = 0;
	missed_scx = 0;

	PRINT("%-20s%15s%11s%11s%11s%11s\n", "syscall", "seconds", "calls", "errors", "missed-sce", "missed-scx");

	for (i = 0; i < SYS_NSYSENT; i++) {
		if (stats[i].ncalls > 0) {
			PRINT("%-20s%5jd.%09" PRIu64 "%11" PRIu64 "%11" PRIu64
			    "%11" PRIu64 "%11" PRIu64 "\n",
			    syscall_info[i].name,
			    stats[i].ts.tv_sec, stats[i].ts.tv_nsec,
			    stats[i].ncalls, stats[i].nerrors,
			    stats[i].missed_sce, stats[i].missed_scx);
			timespecadd(&total_ts, &stats[i].ts, &total_ts);
			ncalls += stats[i].ncalls;
			nerrors += stats[i].nerrors;
			missed_sce += stats[i].missed_sce;
			missed_scx += stats[i].missed_scx;
		}
	}

	PRINT("%20s%15s%11s%11s%11s%11s\n", "", "-------------", "-------", "-------", "-------", "-------");
	PRINT("%-20s%5jd.%09ld%11" PRIu64 "%11" PRIu64 "%11" PRIu64
	    "%11" PRIu64 "\n", "", total_ts.tv_sec, total_ts.tv_nsec,
	    ncalls, nerrors, missed_sce, missed_scx);
}

static void
resolve_child_name(pid_t pid, char *child_name, size_t maxlen)
{
	char buf[PATH_MAX];
	size_t buflen;
	int mib[4];

	mib[0] = CTL_KERN;
	mib[1] = KERN_PROC_ARGS;
	mib[2] = pid;
	mib[3] = KERN_PROC_PATHNAME;

	buflen = sizeof(buf);

	/*
	 * There must be used an intermediate buffer with sufficient length as
	 * otherwise the sysctl(3) call will reject the operation.
	 */
	xsysctl(mib, __arraycount(mib), buf, &buflen, NULL, 0);

	estrlcpy(child_name, basename(buf), maxlen);
}

static void
detach_child(pid_t pid)
{
	int status;

	kill(pid, SIGSTOP);

	xwaitpid(pid, &status, 0);

	xptrace(PT_DETACH, pid, (void *)1, 0);
}

static void
signal_handler(int sig)
{

	children_tree_dump(pid_tree, detach_child);

	exit(0);
}

static void
siginfo_child(pid_t pid)
{
	struct timespec diff_ts;
	struct pid_context *p_ctx;

	p_ctx = children_tree_find(pid_tree, pid);

	if (p_ctx == NULL) {
		/* This shall not happen, but if does bail out. */
		return;
	}

	timespecsub(&now_ts, &p_ctx->startup_ts, &diff_ts);

	printf("%s[%d] attached to child=%d ('%s') for %jd.%09ld seconds\n",
	    getprogname(), getpid(), pid, p_ctx->name, diff_ts.tv_sec,
	    diff_ts.tv_nsec);
}

static void
siginfo_handler(int dummy)
{	
	struct timespec diff_ts;

	xtimespec_get(&now_ts, TIME_UTC);

	timespecsub(&now_ts, &start_ts, &diff_ts);

	printf("%s[%d] running for %jd.%09ld seconds\n",
	    getprogname(), getpid(), diff_ts.tv_sec, diff_ts.tv_nsec);

	children_tree_dump(pid_tree, siginfo_child);

	print_summary();
}
