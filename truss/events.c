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
#include "trace_utils.h"

#include "truss.h"

#include "events.h"

static void setup_ops(void);

static void report(pid_t pid, lwpid_t lwp, char *format, ...);
static void resolve_child_name(pid_t, char *, size_t);
static const char *sig2string(int);
static const char *sicode2string(int, int);
static void read_argv(pid_t);
static void read_env(pid_t);
static void read_elf_auxv(pid_t);
static char *copyinstr(pid_t, void *);
static void detach_child(pid_t);
static void signal_handler(int);
static void siginfo_child(pid_t);
static void siginfo_handler(int);

static int mode;
static FILE *output;				/* -o */

#define SPRINTF(a,...)							\
	do {								\
		if (n < sizeof(buf))					\
			n += trace_snprintf(buf + n, sizeof(buf) - n,	\
				(a), ## __VA_ARGS__);			\
	} while (0)

#define PRINT(fmt, ...)							\
	do {								\
		fprintf(output, fmt, ## __VA_ARGS__);			\
	} while (0)


/* Global variables */
static struct timespec start_ts;
static struct timespec previous_ts;

static mtx_t mtx;		/* Protects pid_tree */

/* Process related variables */
struct pid_context {
	char name[NAME_MAX];
};

static void *pid_tree;
static thread_local struct pid_context *pid_ctx;


void
events_main(FILE *out, int m, size_t s)
{
	assert(out);
	assert(!(m & MODE_COUNT));

	output = out;
	mode = m;
	set_string_max_size(s);

	setup_ops();

	trace_mtx_init(&mtx, mtx_plain);
	pid_tree = children_tree_init();

	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);
	signal(SIGHUP, signal_handler);

	signal(SIGINFO, siginfo_handler);

	trace_timespec_get(&start_ts, TIME_UTC);

	previous_ts = start_ts;
}

static void
events_end(void)
{
}

static void
events_startup(pid_t pid)
{
	struct timespec ts;
	ptrace_event_t pe;

	pid_ctx = emalloc(sizeof(*pid_ctx));

	resolve_child_name(pid, pid_ctx->name, sizeof(pid_ctx->name));

	mtx_lock(&mtx);
	children_tree_insert(pid_tree, pid, pid_ctx);
	mtx_unlock(&mtx);

	if (mode & MODE_INHERIT) {
		pe.pe_set_event |= PTRACE_FORK;
#if 0
		pe.pe_set_event |= PTRACE_VFORK;
		pe.pe_set_event |= PTRACE_VFORK_DONE;
#endif
	}

	pe.pe_set_event |= PTRACE_LWP_CREATE;
	pe.pe_set_event |= PTRACE_LWP_EXIT;

	trace_ptrace(PT_SET_EVENT_MASK, pid, &pe, sizeof(pe));
}

static void
events_unstop(pid_t pid)
{
	ptrace_siginfo_t psi;
	int signo;

	trace_ptrace(PT_GET_SIGINFO, pid, &psi, sizeof(psi));
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

	trace_ptrace(PT_SYSCALL, pid, (void *)1, signo);
}

static void
events_continued(pid_t pid)
{

	if (!(mode & MODE_SIGNALS))
		return;

	report(pid, 0, "process continued");

	trace_timespec_get(&previous_ts, TIME_UTC);
}

static void
events_signaled(pid_t pid, int sig, int core)
{
	char buf[512];
	int n;
	const char *s;

	n = 0;

	s = sig2string(sig);

	SPRINTF("process killed, signal = ");

	if (s) {
		SPRINTF("%s", s);
	} else {
		SPRINTF("%d", sig);
	}

	if (core) {
		SPRINTF(" (core dumped)");
	}

	report(pid, 0, "%s", buf);

	trace_timespec_get(&previous_ts, TIME_UTC);
}

static void
events_exited(pid_t pid, int status)
{

	report(pid, 0, "process exit, rval = %d", status);

	trace_timespec_get(&previous_ts, TIME_UTC);
}

static void
events_cleanup(pid_t pid)
{

	mtx_lock(&mtx);
	children_tree_remove(pid_tree, pid);
	mtx_unlock(&mtx);

	free(pid_ctx);
}

static void
events_debugregister(pid_t pid, lwpid_t lid)
{
}

static void
events_singlestep(pid_t pid, lwpid_t lid)
{
}

static void
events_breakpoint(pid_t pid, lwpid_t lid)
{
}

static void
events_syscallentry(pid_t pid, lwpid_t lid, siginfo_t *si)
{

	assert(si);
	assert(si->si_sysnum < SYS_NSYSENT);
}

static void
events_syscallexit(pid_t pid, lwpid_t lid, siginfo_t *si)
{
	char buf[1024];
	char s[512];
	int n;

	assert(si);
	assert(si->si_sysnum < SYS_NSYSENT);

	n = 0;

	SPRINTF("%-50s", decode_args(pid, si, s, __arraycount(s)));

	SPRINTF("= %s", decode_retval(si, s, __arraycount(s)));

	report(pid, lid, "%s", buf);

	trace_timespec_get(&previous_ts, TIME_UTC);
}

static void
events_exec(pid_t pid, lwpid_t lid)
{

	report(pid, lid, "process exec'd");

	if (mode & MODE_EXEC_ARGS)
		read_argv(pid);
	if (mode & MODE_EXEC_ENV)
		read_env(pid);
	if (mode & MODE_EXEC_AUXV)
		read_elf_auxv(pid);

	trace_timespec_get(&previous_ts, TIME_UTC);
}

static void
events_forked(pid_t pid, lwpid_t lid, pid_t child)
{
	int status;

	assert(mode & MODE_INHERIT);

	trace_waitpid(child, &status, 0);

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

	trace_timespec_get(&previous_ts, TIME_UTC);
}

static void
events_vforked(pid_t pid, lwpid_t lid, pid_t child)
{
	int status;

	assert(mode & MODE_INHERIT);

	trace_waitpid(child, &status, 0);

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

	trace_timespec_get(&previous_ts, TIME_UTC);
}

static void
events_vforkdone(pid_t pid, lwpid_t lid, pid_t child)
{

	assert(mode & MODE_INHERIT);

	trace_timespec_get(&previous_ts, TIME_UTC);
}

static void
events_lwpcreated(pid_t pid, lwpid_t lid, lwpid_t lwp)
{

	report(pid, lid, "<new thread %d>", lwp);

	trace_timespec_get(&previous_ts, TIME_UTC);
}

static void
events_lwpexited(pid_t pid, lwpid_t lid, lwpid_t lwp)
{

	report(pid, lid, "<thread %d exited>", lwp);

	trace_timespec_get(&previous_ts, TIME_UTC);
}

static void
events_crashed(pid_t pid, lwpid_t lid, siginfo_t *si)
{
	char buf[512];
	int n;
	const char *s;

	n = 0;

	s = sig2string(si->si_signo);

	SPRINTF("SIGNAL %d (%s)", si->si_signo, s ? s : "?");

	s = sicode2string(si->si_signo, si->si_code);

	SPRINTF(" code=");

	if (s) {
		SPRINTF("%s", s);
	} else {
		SPRINTF("%d", si->si_code);
	}

	SPRINTF(" si_addr=%#p si_trap=%d\n", si->si_addr, si->si_trap);

	report(pid, lid, "%s", buf);

	trace_timespec_get(&previous_ts, TIME_UTC);
}

static void
events_stopped(pid_t pid, lwpid_t lid, siginfo_t *si)
{
	char buf[512];
	const char *s;
	int n;

	if (!(mode & MODE_SIGNALS))
		return;

	n = 0;

	s = sig2string(si->si_signo);

	SPRINTF("SIGNAL %d (%s)", si->si_signo, s ? s : "?");

	s = sicode2string(si->si_signo, si->si_code);

	SPRINTF(" code=");

	if (s) {
		SPRINTF("%s", s);
	} else {
		SPRINTF("%d", si->si_code);
	}

	switch (si->si_code) {
	case SI_USER:
	case SI_LWP:
		SPRINTF(" pid=%d uid=%d", si->si_pid, si->si_uid);
		break;
	case SI_QUEUE:
		SPRINTF(" pid=%d uid=%d", si->si_pid, si->si_uid);
		/* FALLTHROUGH */
	case SI_TIMER:
		SPRINTF(" value=%#p", si->si_value.sival_ptr);
		break;
	case SI_ASYNCIO:
		SPRINTF(" si_fd=%d si_band=%#lx", si->si_fd, si->si_band);
		break;
	case SI_MESGQ:
	case SI_NOINFO:
		/* No extra information */
		break;
	}

	report(pid, lid, "%s", buf);

	trace_timespec_get(&previous_ts, TIME_UTC);
}

static void
setup_ops(void)
{

	ops.end = events_end;
	ops.startup = events_startup;
	ops.unstop = events_unstop;
	ops.continued = events_continued;
	ops.signaled = events_signaled;
	ops.exited = events_exited;
	ops.cleanup = events_cleanup;
	ops.debugregister = events_debugregister;
	ops.singlestep = events_singlestep;
	ops.breakpoint = events_breakpoint;
	ops.syscallentry = events_syscallentry;
	ops.syscallexit = events_syscallexit;
	ops.exec = events_exec;
	ops.forked = events_forked;
	ops.vforked = events_vforked;
	ops.vforkdone = events_vforkdone;
	ops.lwpcreated = events_lwpcreated;
	ops.lwpexited = events_lwpexited;
	ops.crashed = events_crashed;
	ops.stopped = events_stopped;
}

void
report(pid_t pid, lwpid_t lwp, char *format, ...)
{
	char buf[1024];
	struct timespec diff_ts;
	struct timespec now_ts;
	va_list ap;
	int n;

	n = 0;

	trace_timespec_get(&now_ts, TIME_UTC);

	if (mode & MODE_INHERIT) {
		SPRINTF("%5d %s ", pid, pid_ctx->name);
	}

	if (mode & MODE_LWPID) {
		SPRINTF("%6d ", lwp);
	}

	if (mode & MODE_ABSOLUTE_TIMESTAMP) {
		timespecsub(&now_ts, &start_ts, &diff_ts);
		SPRINTF("%jd.%09ld ", diff_ts.tv_sec, diff_ts.tv_nsec);
	}

	if (mode & MODE_RELATIVE_TIMESTAMP) {
		timespecsub(&now_ts, &previous_ts, &diff_ts);
		SPRINTF("%jd.%09ld ", diff_ts.tv_sec, diff_ts.tv_nsec);
	}

	va_start(ap, format);
	n += vsnprintf(buf + n, sizeof(buf) - n, format, ap);
	va_end(ap);

	PRINT("%s\n", buf);

	previous_ts = now_ts;
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
	trace_sysctl(mib, __arraycount(mib), buf, &buflen, NULL, 0);

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

static const char *
sicode2string(int sig, int code)
{

#define case_SICODE(a) case a: return #a;

	switch (code) {
	case_SICODE(SI_USER)
	case_SICODE(SI_QUEUE)
	case_SICODE(SI_TIMER)
	case_SICODE(SI_ASYNCIO)
	case_SICODE(SI_MESGQ)
	case_SICODE(SI_LWP)
	case_SICODE(SI_NOINFO)
	}

	switch (sig) {
	case SIGILL:
		switch (code) {
		case_SICODE(ILL_ILLOPC)
		case_SICODE(ILL_ILLOPN)
		case_SICODE(ILL_ILLADR)
		case_SICODE(ILL_ILLTRP)
		case_SICODE(ILL_PRVOPC)
		case_SICODE(ILL_PRVREG)
		case_SICODE(ILL_COPROC)
		case_SICODE(ILL_BADSTK)
		}
		break;
	case SIGFPE:
		switch (code) {
		case_SICODE(FPE_INTDIV)
		case_SICODE(FPE_INTOVF)
		case_SICODE(FPE_FLTDIV)
		case_SICODE(FPE_FLTOVF)
		case_SICODE(FPE_FLTUND)
		case_SICODE(FPE_FLTRES)
		case_SICODE(FPE_FLTINV)
		}
		break;
	case SIGSEGV:
		switch (code) {
		case_SICODE(SEGV_MAPERR)
		case_SICODE(SEGV_ACCERR)
		}
		break;
	case SIGBUS:
		switch (code) {
		case_SICODE(BUS_ADRALN)
		case_SICODE(BUS_ADRERR)
		case_SICODE(BUS_OBJERR)
		}
		break;
	case SIGCHLD:
		switch (code) {
		case_SICODE(CLD_EXITED)
		case_SICODE(CLD_KILLED)
		case_SICODE(CLD_DUMPED)
		case_SICODE(CLD_TRAPPED)
		case_SICODE(CLD_STOPPED)
		case_SICODE(CLD_CONTINUED)
		}
		break;
	case SIGIO:
		switch (code) {
		case_SICODE(POLL_IN)
		case_SICODE(POLL_OUT)
		case_SICODE(POLL_MSG)
		case_SICODE(POLL_ERR)
		case_SICODE(POLL_PRI)
		case_SICODE(POLL_HUP)
		}
		break;
	}

#undef case_SICODE

	return NULL;
}

static void
read_argv(pid_t pid)
{
	int i;
	char *p;
	int argc;
	char *argv;
	size_t len;
	int mib[4];
	lwpid_t lid;

	lid = 0;

	mib[0] = CTL_KERN;
	mib[1] = KERN_PROC_ARGS;
	mib[2] = pid;
	mib[3] = KERN_PROC_NARGV;

	len = sizeof(argc);

	trace_sysctl(mib, __arraycount(mib), &argc, &len, NULL, 0);

	mib[3] = KERN_PROC_ARGV;
	len = 0;

	trace_sysctl(mib, __arraycount(mib), NULL, &len, NULL, 0);

	argv = emalloc(len);

	trace_sysctl(mib, __arraycount(mib), argv, &len, NULL, 0);

	p = argv;
	for (i = 0; i < argc; i++) {
		len = strlen(p);
		report(pid, lid, "ARGV[%d] '%s'", i, p);
		p += len + 1;
	}

	free(argv);
}

static void
read_env(pid_t pid)
{
	int i;
	char *p;
	int envc;
	char *envv;
	size_t len;
	int mib[4];
	lwpid_t lid;

	lid = 0;

	mib[0] = CTL_KERN;
	mib[1] = KERN_PROC_ARGS;
	mib[2] = pid;
	mib[3] = KERN_PROC_NENV;

	len = sizeof(envc);

	trace_sysctl(mib, __arraycount(mib), &envc, &len, NULL, 0);

	mib[3] = KERN_PROC_ENV;
	len = 0;

	trace_sysctl(mib, __arraycount(mib), NULL, &len, NULL, 0);

	envv = emalloc(len);

	trace_sysctl(mib, __arraycount(mib), envv, &len, NULL, 0);

	p = envv;
	for (i = 0; i < envc; i++) {
		len = strlen(p);
		report(pid, lid, "ENV[%d] '%s'", i, p);;
		p += len + 1;
	}

	free(envv);
}

static void
read_elf_auxv(pid_t pid)
{
	char vector[1024];
	const AuxInfo *aux;
	struct ptrace_io_desc pio;
	lwpid_t lid;
	char *name;
	char buf[512];
	int n;
	size_t i;

	lid = 0;
	i = 0;

	pio.piod_op = PIOD_READ_AUXV;
	pio.piod_offs = 0;
	pio.piod_addr = vector;
	pio.piod_len = sizeof(buf);

	trace_ptrace(PT_IO, pid, &pio, 0);

	for (aux = (const AuxInfo *)vector; aux->a_type != AT_NULL; ++aux) {
		n = 0; /* used by SNPRINTF */

		SPRINTF("AUXV[%zu] ", i++);

		switch (aux->a_type) {
		case AT_IGNORE:
			SPRINTF("AT_IGNORE");
			break;
		case AT_EXECFD:
			SPRINTF("AT_EXECFD=%#lx", aux->a_v);
			break;
		case AT_PHDR:
			SPRINTF("AT_PHDR=%#lx", aux->a_v);
			break;
		case AT_PHENT:
			SPRINTF("AT_PHENT=%#lx", aux->a_v);
			break;
		case AT_PHNUM:
			SPRINTF("AT_PHNUM=%#lx", aux->a_v);
			break;
		case AT_PAGESZ:
			SPRINTF("AT_PAGESZ=%#lx", aux->a_v);
			break;
		case AT_BASE:
			SPRINTF("AT_BASE=%#lx", aux->a_v);
			break;
		case AT_FLAGS:
			SPRINTF("AT_FLAGS=%#lx", aux->a_v);
			break;
		case AT_ENTRY:
			SPRINTF("AT_ENTRY=%#lx", aux->a_v);
			break;
		case AT_DCACHEBSIZE:
			SPRINTF("AT_DCACHEBSIZE=%#lx", aux->a_v);
			break;
		case AT_ICACHEBSIZE:
			SPRINTF("AT_ICACHEBSIZE=%#lx", aux->a_v);
			break;
		case AT_UCACHEBSIZE:
			SPRINTF("AT_UCACHEBSIZE=%#lx", aux->a_v);
			break;
		case AT_STACKBASE:
			SPRINTF("AT_STACKBASE=%#lx", aux->a_v);
			break;

#if 0
		case AT_MIPS_NOTELF: /* overlap with AT_DCACHEBSIZE? */
			SPRINTF("AT_DCACHEBSIZE=%#lx", aux->a_v);
			break;
#endif
		case AT_EUID:
			SPRINTF("AT_EUID=%ld", aux->a_v);
			break;
		case AT_RUID:
			SPRINTF("AT_RUID=%ld", aux->a_v);
			break;
		case AT_EGID:
			SPRINTF("AT_EGID=%ld", aux->a_v);
			break;
		case AT_RGID:
			SPRINTF("AT_RGID=%ld", aux->a_v);
			break;
		case AT_SUN_LDELF:
			SPRINTF("AT_SUN_LDELF=%#lx", aux->a_v);
			break;
		case AT_SUN_LDSHDR:
			SPRINTF("AT_SUN_LDSHDR=%#lx", aux->a_v);
			break;
		case AT_SUN_LDNAME:
			SPRINTF("AT_SUN_LDNAME=%#lx", aux->a_v);
			break;
		case AT_SUN_LPGSIZE:
			SPRINTF("AT_SUN_LPGSIZE=%#lx", aux->a_v);
			break;
		case AT_SUN_PLATFORM:
			SPRINTF("AT_SUN_PLATFORM=%#lx", aux->a_v);
			break;
		case AT_SUN_HWCAP:
			SPRINTF("AT_SUN_HWCAP=%#lx", aux->a_v);
			break;
		case AT_SUN_IFLUSH:
			SPRINTF("AT_SUN_IFLUSH=%#lx", aux->a_v);
			break;
		case AT_SUN_CPU:
			SPRINTF("AT_SUN_CPU=%#lx", aux->a_v);
			break;
		case AT_SUN_EMUL_ENTRY:
			SPRINTF("AT_SUN_EMUL_ENTRY=%#lx", aux->a_v);
			break;
		case AT_SUN_EMUL_EXECFD:
			SPRINTF("AT_SUN_EMUL_EXECFD=%#lx", aux->a_v);
			break;

		case AT_SUN_EXECNAME:
			name = copyinstr(pid, (void *)(intptr_t)aux->a_v);
			SPRINTF("AT_SUN_EXECNAME=");
			if (name)
				SPRINTF("'%s'", name);
			else
				SPRINTF("%#" PRIx64, name);
			free(name);
			break;
		default:
			SPRINTF("UNKNOWN-TAG-%ld=%#lx", aux->a_type, aux->a_v);
			break;
		}
		report(pid, lid, "%s", buf);
	}
}

static char *
copyinstr(pid_t pid, void *offs)
{
	struct ptrace_io_desc pio;
	char *buf = NULL;
	size_t bufchunks = 1;
	const size_t bufchunklen = 32;
	size_t i, n;
	bool canonical;

	ereallocarr(&buf, bufchunks, bufchunklen);

	pio.piod_op = PIOD_READ_D;
	pio.piod_offs = offs;
	pio.piod_addr = buf;
	pio.piod_len = bufchunklen;

	n = 0;

	canonical = false;

	for (;;) {
		errno = 0;
		ptrace(PT_IO, pid, &pio, 0);

		if (pio.piod_len == 0 || errno != 0) {
			/* EOF */
			break;
		}

		for (i = 0; i < MIN(bufchunklen, pio.piod_len); i++) {
			if (((char *)pio.piod_addr)[i] == '\0') {
				canonical = true;
				break;
			}
		}

		if (canonical)
			break;

		pio.piod_offs = (void *) ((intptr_t)pio.piod_offs + pio.piod_len);

		n += pio.piod_len;

		ereallocarr(&buf, ++bufchunks, bufchunklen);

		pio.piod_addr = (void *)&buf[n];
	}

	if (canonical)
		return buf;

	/* Free the buffer */
	ereallocarr(&buf, 0, bufchunklen);

	return NULL;
}

static void
detach_child(pid_t pid)
{
	int status;

	kill(pid, SIGSTOP);

	trace_waitpid(pid, &status, 0);

	trace_ptrace(PT_DETACH, pid, (void *)1, 0);
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

	printf("%s[%d] attached to child=%d\n", getprogname(), getpid(), pid);
}

static void
siginfo_handler(int dummy)
{

	children_tree_dump(pid_tree, siginfo_child);
}
