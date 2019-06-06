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


#include <sys/param.h>
#include <sys/types.h>
#include <machine/reg.h>

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
#include "trace.h"
#include "xutils.h"

static void usage(void) __dead;
static void attach(pid_t);
static void spawn(char **);
static void resolve_child_name(pid_t, char *, size_t);
static const char *sig2string(int num);
static void detach_child(pid_t pid);
static void signal_handler(int dummy);
static void siginfo_child(pid_t pid);
static void siginfo_handler(int dummy);

static bool inherit;
static FILE *output = stdout;

static volatile uint64_t global_count;
static mtx_t global_count_mtx;

struct pid_context {
	char name[NAME_MAX];
	volatile uint64_t count;
};

static void *pid_tree;
static thread_local struct pid_context *pid_ctx;

static mtx_t mtx;

static void
singlestepper_main(int argc, char **argv)
{
	pid_t pid;
	int ch;

	pid = 0;

	while ((ch = getopt(argc, argv, "e:f:io:p:")) != -1) {
		switch (ch) {
		case 'i':
			inherit = true;
			break;
		case 'o':
			/* Allow only single output file */
			if (output != stdout)
				usage();

			/* Set close-on-exec */
			output = efopen(optarg, "we");
			break;
		case 'p':
			pid = (pid_t)estrtoi(optarg, 0, 0, INT_MAX);
			break;
		case '?':
		default:
			usage();
		}
	}

	argc -= optind;
	argv += optind;

	/* No mode specified. */
	if (pid <= 0 && argc <= 0)
		usage();

	/* Attach and spawn modes specified. */
	if (pid > 0 && argc > 0)
		usage();

	xmtx_init(&mtx, mtx_plain);
	pid_tree = children_tree_init();

	xmtx_init(&global_count_mtx, mtx_plain);

	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);
	signal(SIGHUP, signal_handler);

	signal(SIGINFO, siginfo_handler);

	if (pid > 0)
		attach(pid);

	if (argc > 0)
		spawn(argv);
}

static void
singlestepper_end(void)
{

	fprintf(output, "Total count: %" PRId64 "\n", global_count);
}

static void
singlestepper_startup(pid_t pid)
{
	ptrace_event_t pe;
	struct ptrace_lwpinfo pl;

	pid_ctx = emalloc(sizeof(*pid_ctx));

	resolve_child_name(pid, pid_ctx->name, sizeof(pid_ctx->name));
	pid_ctx->count = 0;

	mtx_lock(&mtx);
	children_tree_insert(pid_tree, pid, pid_ctx);
	mtx_unlock(&mtx);

	if (inherit) {
		pe.pe_set_event |= PTRACE_FORK;
#if 0
		pe.pe_set_event |= PTRACE_VFORK;
		pe.pe_set_event |= PTRACE_VFORK_DONE;
#endif
	}

	pe.pe_set_event |= PTRACE_LWP_CREATE;
	pe.pe_set_event |= PTRACE_LWP_EXIT;

	pl.pl_lwpid = 0;
	while (ptrace(PT_LWPINFO, pid, (void *)&pl, sizeof(pl)) != -1
	    && pl.pl_lwpid != 0) {
		xptrace(PT_SETSTEP, pid, NULL, pl.pl_lwpid);
	}

	xptrace(PT_SET_EVENT_MASK, pid, &pe, sizeof(pe));
}

static void
singlestepper_unstop(pid_t pid)
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

	xptrace(PT_CONTINUE, pid, (void *)1, signo);
}

static void
singlestepper_continued(pid_t pid)
{
}

static void
singlestepper_signaled(pid_t pid, int sig, int core)
{
}

static void
singlestepper_exited(pid_t pid, int status)
{
}

static void
singlestepper_cleanup(pid_t pid)
{

	mtx_lock(&mtx);
	children_tree_remove(pid_tree, pid);
	mtx_unlock(&mtx);

	free(pid_ctx);
}

static void
singlestepper_debugregister(pid_t pid, lwpid_t lid)
{
}

static void
singlestepper_singlestep(pid_t pid, lwpid_t lid)
{

	++(pid_ctx->count);

	mtx_lock(&global_count_mtx);
	++global_count;
	mtx_unlock(&global_count_mtx);
}

static void
singlestepper_breakpoint(pid_t pid, lwpid_t lid)
{
}

static void
singlestepper_syscallentry(pid_t pid, lwpid_t lid, siginfo_t *si)
{
}

static void
singlestepper_syscallexit(pid_t pid, lwpid_t lid, siginfo_t *si)
{
}

static void
singlestepper_exec(pid_t pid, lwpid_t lid)
{
}

static void
singlestepper_forked(pid_t pid, lwpid_t lid, pid_t child)
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
singlestepper_vforked(pid_t pid, lwpid_t lid, pid_t child)
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
singlestepper_vforkdone(pid_t pid, lwpid_t lid, pid_t child)
{
}

static void
singlestepper_lwpcreated(pid_t pid, lwpid_t lid, lwpid_t lwp)
{

	xptrace(PT_SETSTEP, pid, NULL, lwp);
}

static void
singlestepper_lwpexited(pid_t pid, lwpid_t lid, lwpid_t lwp)
{
}

static void
singlestepper_crashed(pid_t pid, lwpid_t lid, siginfo_t *si)
{
}

static void
singlestepper_stopped(pid_t pid, lwpid_t lid, siginfo_t *si)
{

	/* If something stopped the traceee, detach. */
	if (si->si_signo == SIGSTOP) {
		xptrace(PT_DETACH, pid, (void *)1, SIGSTOP);
	}
}

static void __dead
usage(void)
{
	fprintf(stderr,
	    "Usage: %s [-i] [-o OUTPUT] [-p PID | <command> [<arg ...>]]\n",
	    getprogname());

	exit(EXIT_FAILURE);
}

static void
attach(pid_t pid)
{
	ptrace_siginfo_t psi;
	int status;

	xptrace(PT_ATTACH, pid, NULL, 0);

	xwaitpid(pid, &status, 0);

	if (!WIFSTOPPED(status))
		errx(EXIT_FAILURE,
		    "waitpid(%d) returned non-stopped child", pid);

	if (WSTOPSIG(status) != SIGSTOP)
		errx(EXIT_FAILURE,
		    "waitpid(%d) returned unexpected signal %s", pid,
		    signalname(WSTOPSIG(status)));

	xptrace(PT_GET_SIGINFO, pid, &psi, sizeof(psi));
	psi.psi_siginfo.si_signo = 0;
	xptrace(PT_SET_SIGINFO, pid, &psi, sizeof(psi));

	launch_worker(pid);
}

static void
spawn(char **argv)
{
	pid_t child;
	int status;

	child = xfork();

	if (child == 0) {
		xptrace(PT_TRACE_ME, 0, NULL, 0);

		execvp(argv[0], argv);

		err(EXIT_FAILURE, "execvp");

		/* NOTREACHABLE */
	}

	xwaitpid(child, &status, 0);

	if (!WIFSTOPPED(status))
		errx(EXIT_FAILURE,
		    "waitpid(%d) returned non-stopped child", child);

	if (WSTOPSIG(status) != SIGTRAP)
		errx(EXIT_FAILURE,
		    "waitpid(%d) returned unexpected signal %s", child,
		    signalname(WSTOPSIG(status)));

	launch_worker(child);
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

static const char *
sig2string(int num)
{

	if (num < 0 || num > MAXSIGNALS)
		return NULL;
	else
		return signals[num].name;
}

static void
detach_child(pid_t pid)
{
	struct pid_context *p_ctx;
	int status;

	p_ctx = children_tree_find(pid_tree, pid);

	fprintf(output, "DETACHING child=%d '%s'\n", pid, p_ctx->name);

	kill(pid, SIGSTOP);

	xwaitpid(pid, &status, 0);

	xptrace(PT_DETACH, pid, (void *)1, 0);
}

static void
signal_handler(int sig)
{
	const char *s;

	s = sig2string(sig);
	if (s) {
		fprintf(output, "RECEIVED %s\n", s);
	} else {
		fprintf(output, "RECEIVED signal %d\n", sig);
	}

	children_tree_dump(pid_tree, detach_child);

	fprintf(output, "Total count %" PRId64 "\n", global_count);
	fprintf(output, "EXITING\n");

	exit(0);
}

static void
siginfo_child(pid_t pid)
{
	struct pid_context *p_ctx;
	int status;

	p_ctx = children_tree_find(pid_tree, pid);

	printf("%s[%d] attached to child=%d '%s' count=%" PRId64 "\n",
	    getprogname(), getpid(), pid, p_ctx->name, p_ctx->count);
}

static void
siginfo_handler(int dummy)
{

	children_tree_dump(pid_tree, siginfo_child);

	printf("%s[%d] total count: %" PRId64 "\n",
	    getprogname(), getpid(), global_count);
}

struct trace_ops ops = {
	.main = singlestepper_main,
	.end = singlestepper_end,
	.startup = singlestepper_startup,
	.unstop = singlestepper_unstop,
	.continued = singlestepper_continued,
	.signaled = singlestepper_signaled,
	.exited = singlestepper_exited,
	.cleanup = singlestepper_cleanup,
	.debugregister = singlestepper_debugregister,
	.singlestep = singlestepper_singlestep,
	.breakpoint = singlestepper_breakpoint,
	.syscallentry = singlestepper_syscallentry,
	.syscallexit = singlestepper_syscallexit,
	.exec = singlestepper_exec,
	.forked = singlestepper_forked,
	.vforked = singlestepper_vforked,
	.vforkdone = singlestepper_vforkdone,
	.lwpcreated = singlestepper_lwpcreated,
	.lwpexited = singlestepper_lwpexited,
	.crashed = singlestepper_crashed,
	.stopped = singlestepper_stopped
};
