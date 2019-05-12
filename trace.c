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
#include <stdlib.h>
#include <string.h>
#include <threads.h>

#include <util.h>

#include "trace.h"
#include "trace_utils.h"

static int worker(void *);
static void monitor_sigtrap(pid_t);
static void monitor_crash(pid_t);
static void monitor_signal(pid_t);

static mtx_t mtx;
static cnd_t cnd;
static int workers;

static struct trace_ops *ops;

#define TRACE_MAIN(argc, argv) (*ops->main)(argc, argv)
#define TRACE_END() (*ops->end)()
#define TRACE_STARTUP(pid) (*ops->startup)(pid)
#define TRACE_UNSTOP(pid) (*ops->unstop)(pid)
#define TRACE_CONTINUED(pid) (*ops->continued)(pid)
#define TRACE_SIGNALED(pid, sig, core) (*ops->signaled)(pid, sig, core)
#define TRACE_EXITED(pid, status) (*ops->exited)(pid, status)
#define TRACE_CLEANUP(pid) (*ops->cleanup)(pid)
#define TRACE_DEBUGREGISTER(pid, lid) (*ops->debugregister)(pid, lid)
#define TRACE_SINGLESTEP(pid, lid) (*ops->singlestep)(pid, lid)
#define TRACE_BREAKPOINT(pid, lid) (*ops->breakpoint)(pid, lid)
#define TRACE_SYSCALLENTRY(pid, lid, si) (*ops->syscallentry)(pid, lid, si)
#define TRACE_SYSCALLEXIT(pid, lid, si) (*ops->syscallexit)(pid, lid, si)
#define TRACE_EXEC(pid, lid) (*ops->exec)(pid, lid)
#define TRACE_FORKED(pid, lid, child) (*ops->forked)(pid, lid, child)
#define TRACE_VFORKED(pid, lid, child) (*ops->vforked)(pid, lid, child)
#define TRACE_VFORKDONE(pid, lid, child) (*ops->vforkdone)(pid, lid, child)
#define TRACE_LWPCREATED(pid, lid, lwp) (*ops->lwpcreated)(pid, lid, lwp)
#define TRACE_LWPEXITED(pid, lid, lwp) (*ops->lwpexited)(pid, lid, lwp)
#define TRACE_CRASHED(pid, lid, si) (*ops->crashed)(pid, lid, si)
#define TRACE_STOPPED(pid, lid, si) (*ops->stopped)(pid, lid, si)

int
main(int argc, char **argv)
{
	const char *p;

	setprogname(argv[0]);

	p = getprogname();

	if (strcmp(p, "coredumper") == 0)
		ops = &trace_ops_coredumper;
	else if (strcmp(p, "picotrace") == 0)
		ops = &trace_ops_picotrace;
	else
		errx(EXIT_FAILURE, "unrecognized program name: '%s'", p);

	trace_cnd_init(&cnd);
	trace_mtx_init(&mtx, mtx_plain);

	TRACE_MAIN(argc, argv);

	trace_mtx_lock(&mtx);
	while (workers > 0)
		trace_cnd_wait(&cnd, &mtx);
	trace_mtx_unlock(&mtx);

	TRACE_END();

	return EXIT_SUCCESS;
}

void
launch_worker(pid_t pid)
{
	thrd_t t;

	trace_mtx_lock(&mtx);
	++workers;
	trace_mtx_unlock(&mtx);

	/* The t thread is not waited as the thread will perform selfdetach. */
	thrd_create(&t, worker, (void *)(intptr_t)pid);
}

static int
worker(void *arg)
{
	ptrace_siginfo_t psi;
	ptrace_event_t pe;
	pid_t pid;
	int status;

	assert(arg != NULL);

	pid = (pid_t)(intptr_t)arg;

	TRACE_STARTUP(pid);

	while (true) {
		TRACE_UNSTOP(pid);

		trace_waitpid(pid, &status, 0);

		/* Tracee terminating event */
		if (WIFSTOPPED(status)) {
			switch (WSTOPSIG(status)) {
			case SIGTRAP:
				monitor_sigtrap(pid);
				break;

			case SIGSEGV:
				/* FALLTHROUGH */
			case SIGILL:
				/* FALLTHROUGH */
			case SIGFPE:
				/* FALLTHROUGH */
			case SIGBUS:
				monitor_crash(pid);
				break;

			default:
				monitor_signal(pid);
			}
		}

		if (WIFCONTINUED(status)) {
			TRACE_CONTINUED(pid);
		}
		
		/* Tracee terminating event */
		if (WIFSIGNALED(status)) {
			TRACE_SIGNALED(pid, WTERMSIG(status), WCOREDUMP(status));
			break;
		}

		if (WIFEXITED(status)) {
			TRACE_EXITED(pid, status);
			break;
		}
	};

	TRACE_CLEANUP(pid);

	trace_mtx_lock(&mtx);
	--workers;
	trace_mtx_unlock(&mtx);

	trace_cnd_signal(&cnd);
		 
	trace_thrd_detach(thrd_current());

	thrd_exit(0);
}

static void
monitor_sigtrap(pid_t pid)
{
	char buf[1024];
	ptrace_state_t pst;
	ptrace_siginfo_t psi;
	lwpid_t lid;
	int status;

	trace_ptrace(PT_GET_SIGINFO, pid, &psi, sizeof(psi));

	lid = psi.psi_lwpid;

	switch (psi.psi_siginfo.si_code) {
	case TRAP_DBREG:
		TRACE_DEBUGREGISTER(pid, lid);
		break;

	case TRAP_TRACE:
		TRACE_SINGLESTEP(pid, lid);
		break;

	case TRAP_BRKPT:
		TRACE_BREAKPOINT(pid, lid);
		break;

	case TRAP_SCE:
		TRACE_SYSCALLENTRY(pid, lid, &psi.psi_siginfo);
		break;

	case TRAP_SCX:
		TRACE_SYSCALLEXIT(pid, lid, &psi.psi_siginfo);
		break;

	case TRAP_EXEC:
		TRACE_EXEC(pid, lid);
		break;

	case TRAP_LWP:
		/* FALLTHROUGH */
	case TRAP_CHLD:
		trace_ptrace(PT_GET_PROCESS_STATE, pid, &pst, sizeof(pst));
		switch (pst.pe_report_event) {
		case PTRACE_FORK:
			TRACE_FORKED(pid, lid, pst.pe_other_pid);
			break;

		case PTRACE_VFORK:
			TRACE_VFORKED(pid, lid, pst.pe_other_pid);
			break;

		case PTRACE_VFORK_DONE:
			TRACE_VFORKDONE(pid, lid, pst.pe_other_pid);
			break;

		case PTRACE_LWP_CREATE:
			TRACE_LWPCREATED(pid, lid, pst.pe_lwp);
			break;

		case PTRACE_LWP_EXIT:
			TRACE_LWPEXITED(pid, lid, pst.pe_lwp);
			break;
		}

	default:
		/* Fallback to regular crash/signal. */
		if (psi.psi_siginfo.si_code <= SI_USER)
			monitor_crash(pid);
		else
			monitor_signal(pid);
		break;
	}
}

static void
monitor_crash(pid_t pid)
{
	ptrace_siginfo_t psi;
	lwpid_t lid;

	trace_ptrace(PT_GET_SIGINFO, pid, &psi, sizeof(psi));

	lid = psi.psi_lwpid;

	TRACE_CRASHED(pid, lid, &psi.psi_siginfo);
}

static void
monitor_signal(pid_t pid)
{
	ptrace_siginfo_t psi;
	lwpid_t lid;

	trace_ptrace(PT_GET_SIGINFO, pid, &psi, sizeof(psi));

	lid = psi.psi_lwpid;

	TRACE_STOPPED(pid, lid, &psi.psi_siginfo);
}
