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
#include "xstringlist.h"
#include "xutils.h"

static void usage(void) __dead;
static void attach(pid_t);
static void spawn(char **);
static void resolve_child_name(pid_t, char *, size_t);
static char *copyinstr(pid_t pid, void *offs);
static const char *err2string(int num);
static const char *sig2string(int num);
static void detach_child(pid_t pid);
static void signal_handler(int dummy);
static void siginfo_child(pid_t pid);
static void siginfo_handler(int dummy);

static bool inherit;
static FILE *output = stdout;

struct pid_context {
	char name[NAME_MAX];
};

static void *pid_tree;
static thread_local struct pid_context *pid_ctx;

static mtx_t mtx;


static void
sigtracer_main(int argc, char **argv)
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
sigtracer_end(void)
{
}

static void
sigtracer_startup(pid_t pid)
{
	ptrace_event_t pe;

	pid_ctx = emalloc(sizeof(*pid_ctx));

	resolve_child_name(pid, pid_ctx->name, sizeof(pid_ctx->name));

	mtx_lock(&mtx);
	children_tree_insert(pid_tree, pid, pid_ctx);
	mtx_unlock(&mtx);

	if (inherit) {
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
sigtracer_unstop(pid_t pid)
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
sigtracer_continued(pid_t pid)
{
	StringList *sl;

	sl = xsl_initf("%6d %6d %14s ", pid, 0, pid_ctx->name);

	xsl_addf(sl, "CONTINUED\n");

	xsl_fdump(sl, output);
}

static void
sigtracer_signaled(pid_t pid, int sig, int core)
{
	StringList *sl;

	sl = xsl_initf("%6d %6d %14s ", pid, 0, pid_ctx->name);

	xsl_addf(sl, "SIGNALED signal=%s core=%s\n", signalname(sig),
	    core ? "true" : "false");

	xsl_fdump(sl, output);
}

static void
sigtracer_exited(pid_t pid, int status)
{
	StringList *sl;

	sl = xsl_initf("%6d %6d %14s ", pid, 0, pid_ctx->name);

	xsl_addf(sl, "EXITED status=%d\n", WEXITSTATUS(status));

	xsl_fdump(sl, output);
}

static void
sigtracer_cleanup(pid_t pid)
{

	mtx_lock(&mtx);
	children_tree_remove(pid_tree, pid);
	mtx_unlock(&mtx);

	free(pid_ctx);
}

static void
sigtracer_debugregister(pid_t pid, lwpid_t lid)
{
}

static void
sigtracer_singlestep(pid_t pid, lwpid_t lid)
{
}

static void
sigtracer_breakpoint(pid_t pid, lwpid_t lid)
{
}

static void
sigtracer_syscallentry(pid_t pid, lwpid_t lid, siginfo_t *si)
{
}

static void
sigtracer_syscallexit(pid_t pid, lwpid_t lid, siginfo_t *si)
{
}

static void
sigtracer_exec(pid_t pid, lwpid_t lid)
{
}

static void
sigtracer_forked(pid_t pid, lwpid_t lid, pid_t child)
{
	StringList *sl;
	int status;

	sl = xsl_initf("%6d %6d %14s ", pid, lid, pid_ctx->name);

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

	xsl_addf(sl, "FORKED child=%d\n", child);

	xsl_fdump(sl, output);
}

static void
sigtracer_vforked(pid_t pid, lwpid_t lid, pid_t child)
{
	StringList *sl;
	int status;

	sl = xsl_initf("%6d %6d %14s ", pid, lid, pid_ctx->name);

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

	xsl_addf(sl, "VFORKED child=%d\n", child);

	xsl_fdump(sl, output);
}

static void
sigtracer_vforkdone(pid_t pid, lwpid_t lid, pid_t child)
{
	StringList *sl;

	sl = xsl_initf("%6d %6d %14s ", pid, lid, pid_ctx->name);

	xsl_addf(sl, "VFORK_DONE child=%d\n", child);

	xsl_fdump(sl, output);
}

static void
sigtracer_lwpcreated(pid_t pid, lwpid_t lid, lwpid_t lwp)
{
	StringList *sl;

	sl = xsl_initf("%6d %6d %14s ", pid, lid, pid_ctx->name);

	xsl_addf(sl, "LWP_CREATED lwp=%d\n", lwp);

	xsl_fdump(sl, output);
}

static void
sigtracer_lwpexited(pid_t pid, lwpid_t lid, lwpid_t lwp)
{
	StringList *sl;

	sl = xsl_initf("%6d %6d %14s ", pid, lid, pid_ctx->name);

	xsl_addf(sl, "LWP_EXITED lwp=%d\n", lwp);
	xsl_fdump(sl, output);
}

static void
sigtracer_spawned(pid_t pid, lwpid_t lid, pid_t child)
{
	StringList *sl;
	int status;

	sl = xsl_initf("%6d %6d %14s ", pid, lid, pid_ctx->name);

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

	xsl_addf(sl, "SPAWNED child=%d\n", child);

	xsl_fdump(sl, output);
}

static void
sigtracer_crashed(pid_t pid, lwpid_t lid, siginfo_t *si)
{
	StringList *sl;
	const char *s;

	sl = xsl_initf("%6d %6d %14s ", pid, lid, pid_ctx->name);

	xsl_addf(sl, "CRASHED ");

	s = sig2string(si->si_signo);
	if (s) {
		xsl_addf(sl, "%s", s);
	} else {
		xsl_addf(sl, "signal#%d", si->si_code);
	}
	xsl_addf(sl, " si_code=%d si_addr=%p si_trap=%d\n", si->si_code,
	    si->si_addr, si->si_trap);

	xsl_fdump(sl, output);
}

static void
sigtracer_stopped(pid_t pid, lwpid_t lid, siginfo_t *si)
{
	StringList *sl;
	const char *s;

	sl = xsl_initf("%6d %6d %14s ", pid, lid, pid_ctx->name);

	xsl_addf(sl, "STOPPED ");

	s = sig2string(si->si_signo);
	if (s) {
		xsl_addf(sl, "%s", s);
	} else {
		xsl_addf(sl, "signal#%d", si->si_code);
	}
	xsl_addf(sl, " si_code=%d\n", si->si_code);

	xsl_fdump(sl, output);

	/* If something stopped the traceee, detach. */
	if (si->si_signo == SIGSTOP) {
		sl = xsl_initf("%6d %6d %14s ", pid, lid, pid_ctx->name);

		xsl_addf(sl, "DETACHING stopped trace=%d", pid);

		if (si->si_code == SI_USER) {
			xsl_addf(sl, " by pid=%d uid=%d", si->si_pid, si->si_uid);
		}


		xsl_addf(sl, "\n");
		xsl_fdump(sl, output);

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
err2string(int num)
{

	if (num < 0 || num > MAXERRNOS)
		return NULL;
	else
		return errnos[num].name;
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
	StringList *sl;
	int status;

	xsl_addf(sl, "%6d %6d %14s ", pid, 0, pid_ctx->name);

	xsl_addf(sl, "DETACHING child=%d\n", pid);
	xsl_fdump(sl, output);

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

	fprintf(output, "EXITING\n");

	exit(0);
}

static void
siginfo_child(pid_t pid)
{
	lwpid_t lid;
	int status;

	lid = -1;

	printf("%s[%d] attached to child=%d\n", getprogname(), getpid(), pid);
}

static void
siginfo_handler(int dummy)
{

	children_tree_dump(pid_tree, siginfo_child);
}

struct trace_ops ops = {
	.main = sigtracer_main,
	.end = sigtracer_end,
	.startup = sigtracer_startup,
	.unstop = sigtracer_unstop,
	.continued = sigtracer_continued,
	.signaled = sigtracer_signaled,
	.exited = sigtracer_exited,
	.cleanup = sigtracer_cleanup,
	.debugregister = sigtracer_debugregister,
	.singlestep = sigtracer_singlestep,
	.breakpoint = sigtracer_breakpoint,
	.syscallentry = sigtracer_syscallentry,
	.syscallexit = sigtracer_syscallexit,
	.exec = sigtracer_exec,
	.forked = sigtracer_forked,
	.vforked = sigtracer_vforked,
	.vforkdone = sigtracer_vforkdone,
	.lwpcreated = sigtracer_lwpcreated,
	.lwpexited = sigtracer_lwpexited,
	.spawned = sigtracer_spawned,
	.crashed = sigtracer_crashed,
	.stopped = sigtracer_stopped
};
