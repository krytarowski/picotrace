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
#include "trace.h"
#include "xutils.h"

static void usage(void) __dead;
static void attach(pid_t);
static void spawn(char **);
static void detach_child(pid_t pid);
static void signal_handler(int dummy);
static void siginfo_child(pid_t pid);
static void siginfo_handler(int dummy);

static char *corename;
static int corelen;

static bool inherit;

static void *pid_tree;

static mtx_t mtx;

static void
coredumper_main(int argc, char **argv)
{
	pid_t pid;
	int ch;

	pid = 0;

	while ((ch = getopt(argc, argv, "c:ip:")) != -1) {
		switch (ch) {
		case 'c':
			corename = optarg;
			corelen = strlen(corename);
			break;
		case 'i':
			inherit = true;
			break;
		case 'p':
			pid = estrtoi(optarg, 0, 0, INTMAX_MAX);
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
coredumper_end(void)
{
}

static void
coredumper_startup(pid_t pid)
{
	ptrace_event_t pe;

	mtx_lock(&mtx);
	children_tree_insert(pid_tree, pid, NULL);
	mtx_unlock(&mtx);

	if (inherit) {
		pe.pe_set_event |= PTRACE_FORK;
		pe.pe_set_event |= PTRACE_VFORK;
		pe.pe_set_event |= PTRACE_VFORK_DONE;
	}

	xptrace(PT_SET_EVENT_MASK, pid, &pe, sizeof(pe));
}

static void
coredumper_unstop(pid_t pid)
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
coredumper_continued(pid_t pid)
{
}

static void
coredumper_signaled(pid_t pid, int sig, int core)
{
}

static void
coredumper_exited(pid_t pid, int status)
{
}

static void
coredumper_cleanup(pid_t pid)
{

	mtx_lock(&mtx);
	children_tree_remove(pid_tree, pid);
	mtx_unlock(&mtx);
}

static void
coredumper_debugregister(pid_t pid, lwpid_t lid)
{
}

static void
coredumper_singlestep(pid_t pid, lwpid_t lid)
{
}

static void
coredumper_breakpoint(pid_t pid, lwpid_t lid)
{
}

static void
coredumper_syscallentry(pid_t pid, lwpid_t lid, siginfo_t *si)
{
}

static void
coredumper_syscallexit(pid_t pid, lwpid_t lid, siginfo_t *si)
{
}

static void
coredumper_exec(pid_t pid, lwpid_t lid)
{
}

static void
coredumper_forked(pid_t pid, lwpid_t lid, pid_t child)
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
coredumper_vforked(pid_t pid, lwpid_t lid, pid_t child)
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
coredumper_vforkdone(pid_t pid, lwpid_t lid, pid_t child)
{
}

static void
coredumper_lwpcreated(pid_t pid, lwpid_t lid, lwpid_t lwp)
{
}

static void
coredumper_lwpexited(pid_t pid, lwpid_t lid, lwpid_t lwp)
{
}

static void
coredumper_crashed(pid_t pid, lwpid_t lid, siginfo_t *si)
{

	xptrace(PT_DUMPCORE, pid, corename, corelen);
}

static void
coredumper_stopped(pid_t pid, lwpid_t lid, siginfo_t *si)
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
	    "Usage: %s [-c CORENAME] [-i] [-p PID | <command> [<arg ...>]]\n",
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
	const char *p;
	int status;

	p = getprogname();

	printf("%s[%d] attached to child=%d\n", p, getpid(), pid);
}

static void
siginfo_handler(int dummy)
{

	children_tree_dump(pid_tree, siginfo_child);
}

struct trace_ops ops = {
	.main = coredumper_main,
	.end = coredumper_end,
	.startup = coredumper_startup,
	.unstop = coredumper_unstop,
	.continued = coredumper_continued,
	.signaled = coredumper_signaled,
	.exited = coredumper_exited,
	.cleanup = coredumper_cleanup,
	.debugregister = coredumper_debugregister,
	.singlestep = coredumper_singlestep,
	.breakpoint = coredumper_breakpoint,
	.syscallentry = coredumper_syscallentry,
	.syscallexit = coredumper_syscallexit,
	.exec = coredumper_exec,
	.forked = coredumper_forked,
	.vforked = coredumper_vforked,
	.vforkdone = coredumper_vforkdone,
	.lwpcreated = coredumper_lwpcreated,
	.lwpexited = coredumper_lwpexited,
	.crashed = coredumper_crashed,
	.stopped = coredumper_stopped
};
