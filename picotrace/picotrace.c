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
static void print_argv(pid_t);
static void print_env(pid_t);
static void print_elf_auxv(pid_t);
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
picotrace_main(int argc, char **argv)
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
picotrace_end(void)
{
}

static void
picotrace_startup(pid_t pid)
{
	ptrace_event_t pe;

	pid_ctx = emalloc(sizeof(*pid_ctx));

	resolve_child_name(pid, pid_ctx->name, sizeof(pid_ctx->name));

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

	xptrace(PT_SET_EVENT_MASK, pid, &pe, sizeof(pe));

	print_argv(pid);
	print_env(pid);
	print_elf_auxv(pid);
}

static void
picotrace_unstop(pid_t pid)
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
picotrace_continued(pid_t pid)
{
	StringList *sl;

	sl = xsl_initf("%6d %6d %14s ", pid, 0, pid_ctx->name);

	xsl_addf(sl, "CONTINUED\n");

	xsl_fdump(sl, output);
}

static void
picotrace_signaled(pid_t pid, int sig, int core)
{
	StringList *sl;

	sl = xsl_initf("%6d %6d %14s ", pid, 0, pid_ctx->name);

	xsl_addf(sl, "SIGNALED signal=%s core=%s\n", signalname(sig),
	    core ? "true" : "false");

	xsl_fdump(sl, output);
}

static void
picotrace_exited(pid_t pid, int status)
{
	StringList *sl;

	sl = xsl_initf("%6d %6d %14s ", pid, 0, pid_ctx->name);

	xsl_addf(sl, "EXITED status=%d\n", WEXITSTATUS(status));

	xsl_fdump(sl, output);
}

static void
picotrace_cleanup(pid_t pid)
{

	mtx_lock(&mtx);
	children_tree_remove(pid_tree, pid);
	mtx_unlock(&mtx);

	free(pid_ctx);
}

static void
picotrace_debugregister(pid_t pid, lwpid_t lid)
{
}

static void
picotrace_singlestep(pid_t pid, lwpid_t lid)
{
}

static void
picotrace_breakpoint(pid_t pid, lwpid_t lid)
{
}

static void
picotrace_syscallentry(pid_t pid, lwpid_t lid, siginfo_t *si)
{
	StringList *sl;
	ssize_t nargs;
	const char *name;
	size_t i;
	bool recognized;

	assert(si);

	sl = xsl_initf("%6d %6d %14s ", pid, lid, pid_ctx->name);

	nargs = syscall_info[si->si_sysnum].nargs;
	name = syscall_info[si->si_sysnum].name;

	recognized = nargs != -1;

	xsl_addf(sl, "SCE ");

	if (recognized) {
		xsl_addf(sl, "%s", name);

		xsl_addf(sl, "(");
		if (nargs > 0) {
			xsl_addf(sl, "%#" PRIx64, si->si_args[0]);
			for (i = 1; i < nargs; i++) {
				xsl_addf(sl, ",%#" PRIx64, si->si_args[i]);
			}	
		}
		xsl_addf(sl, ")");
	} else {
		xsl_addf(sl, "UNKNOWN SYSCALL %d ", si->si_sysnum);
	}

	xsl_addf(sl, "\n");
	xsl_fdump(sl, output);
}

static void
picotrace_syscallexit(pid_t pid, lwpid_t lid, siginfo_t *si)
{
	StringList *sl;

	ssize_t nargs;
	const char *name;
	const char *rettype;

	size_t i;
	int e;
	bool recognized;
	bool is64bit_rettype;
	uint64_t u64;
	bool no_return;
	int rv0, rv1;

	assert(si);

	sl = xsl_initf("%6d %6d %14s ", pid, lid, pid_ctx->name);

	nargs = syscall_info[si->si_sysnum].nargs;
	name = syscall_info[si->si_sysnum].name;
	rettype = syscall_info[si->si_sysnum].rettype;

	recognized = nargs != -1;
	no_return = strcmp(rettype, "void") == 0;

	e = si->si_error;
	rv0 = si->si_retval[0];
	rv1 = si->si_retval[1];

	xsl_addf(sl, "SCX ");

	if (recognized) {
		xsl_addf(sl, "%s", name);

		if (no_return) {
		} else if (strcmp(rettype, "int") == 0) {
			is64bit_rettype = false;
		} else if (strcmp(rettype, "int32_t") == 0) {
			is64bit_rettype = false;
		} else if (strcmp(rettype, "gid_t") == 0) {
			is64bit_rettype = false;
		} else if (strcmp(rettype, "lwpid_t") == 0) {
			is64bit_rettype = false;
		} else if (strcmp(rettype, "mode_t") == 0) {
			is64bit_rettype = false;
		} else if (strcmp(rettype, "mqd_t") == 0) {
			is64bit_rettype = false;
		} else if (strcmp(rettype, "off_t") == 0) {
			is64bit_rettype = true;
		} else if (strcmp(rettype, "pid_t") == 0) {
			is64bit_rettype = false;
		} else if (strcmp(rettype, "quad_t") == 0) {
			is64bit_rettype = true;
		} else if (strcmp(rettype, "uid_t") == 0) {
			is64bit_rettype = false;
		} else if (strcmp(rettype, "int") == 0) {
			is64bit_rettype = false;
		} else if (strcmp(rettype, "ssize_t") == 0) {
			is64bit_rettype = true;
		} else if (strcmp(rettype, "void *") == 0) {
			is64bit_rettype = true;
		} else if (strcmp(rettype, "long") == 0) {
#if _LP64
			is64bit_rettype = true;
#else
			is64bit_rettype = false;
#endif
		} else {
			warnx("Unknwon return type '%s' in syscall %s",
			    rettype, name);
			is64bit_rettype = false;
		}

		xsl_addf(sl, " ");

		if (!no_return) {
			xsl_addf(sl, "= ");
			/* Special cases first */
			if (strcmp(name, "pipe") == 0) {
				xsl_addf(sl, "%#" PRIx32 " %#" PRIx32, rv0, rv1);
			} else if (is64bit_rettype) {
				/* These convoluted casts are needed */
				u64 = ((uint64_t)(unsigned)rv1 << 32);
				u64 |= (uint64_t)(unsigned)rv0;
				xsl_addf(sl, "%#" PRIx64, u64);
			} else {
				xsl_addf(sl, "%#" PRIx32, rv0);
			}
		}

		if (e != 0) {
			xsl_addf(sl, " Err#%d", e);
			if (err2string(e)) {
				xsl_addf(sl, " %s", err2string(e));
			}
		}
	} else {
		xsl_addf(sl, "UNKNOWN-SYSCALL-%d ", si->si_sysnum);

		xsl_addf(sl, " retval[0,1]= %#" PRIx32 " %#" PRIx32, rv0, rv1);

		xsl_addf(sl, " error= %#" PRIx32, e);
	}

	xsl_addf(sl, "\n");
	xsl_fdump(sl, output);
}

static void
picotrace_exec(pid_t pid, lwpid_t lid)
{
	StringList *sl;

	sl = xsl_initf("%6d %6d %14s ", pid, lid, pid_ctx->name);

	xsl_addf(sl, "EXEC\n");
	xsl_fdump(sl, output);
}

static void
picotrace_forked(pid_t pid, lwpid_t lid, pid_t child)
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
picotrace_vforked(pid_t pid, lwpid_t lid, pid_t child)
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
picotrace_vforkdone(pid_t pid, lwpid_t lid, pid_t child)
{
	StringList *sl;

	sl = xsl_initf("%6d %6d %14s ", pid, lid, pid_ctx->name);

	xsl_addf(sl, "VFORK_DONE child=%d\n", child);

	xsl_fdump(sl, output);
}

static void
picotrace_lwpcreated(pid_t pid, lwpid_t lid, lwpid_t lwp)
{
	StringList *sl;

	sl = xsl_initf("%6d %6d %14s ", pid, lid, pid_ctx->name);

	xsl_addf(sl, "LWP_CREATED lwp=%d\n", lwp);

	xsl_fdump(sl, output);
}

static void
picotrace_lwpexited(pid_t pid, lwpid_t lid, lwpid_t lwp)
{
	StringList *sl;

	sl = xsl_initf("%6d %6d %14s ", pid, lid, pid_ctx->name);

	xsl_addf(sl, "LWP_EXITED lwp=%d\n", lwp);
	xsl_fdump(sl, output);
}

static void
picotrace_crashed(pid_t pid, lwpid_t lid, siginfo_t *si)
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
picotrace_stopped(pid_t pid, lwpid_t lid, siginfo_t *si)
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
print_argv(pid_t pid)
{
	StringList *sl;
	int i;
	char *p;
	int argc;
	char *argv;
	size_t len;
        int mib[4];
	lwpid_t lid;

	mib[0] = CTL_KERN;
	mib[1] = KERN_PROC_ARGS;
	mib[2] = pid;
	mib[3] = KERN_PROC_NARGV;

	len = sizeof(argc);

        xsysctl(mib, __arraycount(mib), &argc, &len, NULL, 0);

	mib[3] = KERN_PROC_ARGV;
	len = 0;

        xsysctl(mib, __arraycount(mib), NULL, &len, NULL, 0);

	argv = emalloc(len);

        xsysctl(mib, __arraycount(mib), argv, &len, NULL, 0);

	p = argv;
	for (i = 0; i < argc; i++) {
		len = strlen(p);

		sl = xsl_initf("%6d %6d %14s ", pid, 0, pid_ctx->name);
		xsl_addf(sl, "ARGV[%d] '%s'\n", i, p);
		xsl_fdump(sl, output);
		p += len + 1;
	}

	free(argv);
}

static void
print_env(pid_t pid)
{
	StringList *sl;
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

        xsysctl(mib, __arraycount(mib), &envc, &len, NULL, 0);

	mib[3] = KERN_PROC_ENV;
	len = 0;

        xsysctl(mib, __arraycount(mib), NULL, &len, NULL, 0);

	envv = emalloc(len);

        xsysctl(mib, __arraycount(mib), envv, &len, NULL, 0);

	p = envv;
	for (i = 0; i < envc; i++) {
		len = strlen(p);
		sl = xsl_initf("%6d %6d %14s ", pid, 0, pid_ctx->name);
		xsl_addf(sl, "ENV[%d] '%s'\n", i, p);
		xsl_fdump(sl, output);
		p += len + 1;
	}

	free(envv);
}

static void
print_elf_auxv(pid_t pid)
{
	StringList *sl;
	char buf[512];
	char vector[1024];
	const AuxInfo *aux;
	struct ptrace_io_desc pio;
	lwpid_t lid;
	char *name;
	size_t i;

	i = 0;

	pio.piod_op = PIOD_READ_AUXV;
	pio.piod_offs = 0;
	pio.piod_addr = vector;
	pio.piod_len = sizeof(buf);

	xptrace(PT_IO, pid, &pio, 0);

	for (aux = (const AuxInfo *)vector; aux->a_type != AT_NULL; ++aux) {
		sl = xsl_initf("%6d %6d %14s ", pid, 0, pid_ctx->name);

		xsl_addf(sl, "AUXV[%zu] ", i++);

		switch (aux->a_type) {
		case AT_IGNORE:
			xsl_addf(sl, "AT_IGNORE");
			break;
		case AT_EXECFD:
			xsl_addf(sl, "AT_EXECFD=%#lx", aux->a_v);
			break;
		case AT_PHDR:
			xsl_addf(sl, "AT_PHDR=%#lx", aux->a_v);
			break;
		case AT_PHENT:
			xsl_addf(sl, "AT_PHENT=%#lx", aux->a_v);
			break;
		case AT_PHNUM:
			xsl_addf(sl, "AT_PHNUM=%#lx", aux->a_v);
			break;
		case AT_PAGESZ:
			xsl_addf(sl, "AT_PAGESZ=%#lx", aux->a_v);
			break;
		case AT_BASE:
			xsl_addf(sl, "AT_BASE=%#lx", aux->a_v);
			break;
		case AT_FLAGS:
			xsl_addf(sl, "AT_FLAGS=%#lx", aux->a_v);
			break;
		case AT_ENTRY:
			xsl_addf(sl, "AT_ENTRY=%#lx", aux->a_v);
			break;
		case AT_DCACHEBSIZE:
			xsl_addf(sl, "AT_DCACHEBSIZE=%#lx", aux->a_v);
			break;
		case AT_ICACHEBSIZE:
			xsl_addf(sl, "AT_ICACHEBSIZE=%#lx", aux->a_v);
			break;
		case AT_UCACHEBSIZE:
			xsl_addf(sl, "AT_UCACHEBSIZE=%#lx", aux->a_v);
			break;
		case AT_STACKBASE:
			xsl_addf(sl, "AT_STACKBASE=%#lx", aux->a_v);
			break;

#if 0
		case AT_MIPS_NOTELF: /* overlap with AT_DCACHEBSIZE? */
			xsl_addf(sl, "AT_DCACHEBSIZE=%#lx", aux->a_v);
			break;
#endif

		case AT_EUID:
			xsl_addf(sl, "AT_EUID=%ld", aux->a_v);
			break;
		case AT_RUID:
			xsl_addf(sl, "AT_RUID=%ld", aux->a_v);
			break;
		case AT_EGID:
			xsl_addf(sl, "AT_EGID=%ld", aux->a_v);
			break;
		case AT_RGID:
			xsl_addf(sl, "AT_RGID=%ld", aux->a_v);
			break;

		case AT_SUN_LDELF:
			xsl_addf(sl, "AT_SUN_LDELF=%#lx", aux->a_v);
			break;
		case AT_SUN_LDSHDR:
			xsl_addf(sl, "AT_SUN_LDSHDR=%#lx", aux->a_v);
			break;
		case AT_SUN_LDNAME:
			xsl_addf(sl, "AT_SUN_LDNAME=%#lx", aux->a_v);
			break;
		case AT_SUN_LPGSIZE:
			xsl_addf(sl, "AT_SUN_LPGSIZE=%#lx", aux->a_v);
			break;

		case AT_SUN_PLATFORM:
			xsl_addf(sl, "AT_SUN_PLATFORM=%#lx", aux->a_v);
			break;
		case AT_SUN_HWCAP:
			xsl_addf(sl, "AT_SUN_HWCAP=%#lx", aux->a_v);
			break;
		case AT_SUN_IFLUSH:
			xsl_addf(sl, "AT_SUN_IFLUSH=%#lx", aux->a_v);
			break;
		case AT_SUN_CPU:
			xsl_addf(sl, "AT_SUN_CPU=%#lx", aux->a_v);
			break;

		case AT_SUN_EMUL_ENTRY:
			xsl_addf(sl, "AT_SUN_EMUL_ENTRY=%#lx", aux->a_v);
			break;
		case AT_SUN_EMUL_EXECFD:
			xsl_addf(sl, "AT_SUN_EMUL_EXECFD=%#lx", aux->a_v);
			break;

		case AT_SUN_EXECNAME:
			name = copyinstr(pid, (void *)(intptr_t)aux->a_v);
			xsl_addf(sl, "AT_SUN_EXECNAME=");
			if (name)
				xsl_addf(sl, "'%s'", name);
			else
				xsl_addf(sl, "%#" PRIx64, aux->a_v);
			free(name);
			break;
		default:
			xsl_addf(sl, "UNKNOWN-TAG-%u=%#" PRIx64, aux->a_type, aux->a_v);
			break;
		}

		xsl_addf(sl, "\n");
		xsl_fdump(sl, output);
	}
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
	.main = picotrace_main,
	.end = picotrace_end,
	.startup = picotrace_startup,
	.unstop = picotrace_unstop,
	.continued = picotrace_continued,
	.signaled = picotrace_signaled,
	.exited = picotrace_exited,
	.cleanup = picotrace_cleanup,
	.debugregister = picotrace_debugregister,
	.singlestep = picotrace_singlestep,
	.breakpoint = picotrace_breakpoint,
	.syscallentry = picotrace_syscallentry,
	.syscallexit = picotrace_syscallexit,
	.exec = picotrace_exec,
	.forked = picotrace_forked,
	.vforked = picotrace_vforked,
	.vforkdone = picotrace_vforkdone,
	.lwpcreated = picotrace_lwpcreated,
	.lwpexited = picotrace_lwpexited,
	.crashed = picotrace_crashed,
	.stopped = picotrace_stopped
};
