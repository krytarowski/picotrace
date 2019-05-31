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
#include "xutils.h"

#include "truss.h"

static void usage(void) __dead;
static void attach(pid_t);
static void spawn(char **);

static void
truss_main(int argc, char **argv)
{
	FILE *output;
	size_t string_max_size;
	pid_t pid;
	int mode;
	int ch;

	output = stderr;				/* -o */
	string_max_size = 32;				/* -s */
	pid = 0;
	mode = 0;

	while ((ch = getopt(argc, argv, "DHSacdefo:p:s:x")) != -1) {
		switch (ch) {
		case 'D':
			mode |= MODE_RELATIVE_TIMESTAMP;
			break;
		case 'H':
			mode |= MODE_LWPID;
			break;
		case 'S':
			mode |= MODE_SIGNALS;
			break;
		case 'a':
			mode |= MODE_EXEC_ARGS;
			break;
		case 'c':
			mode |= MODE_COUNT;
			break;
		case 'e':
			mode |= MODE_EXEC_ENV;
			break;
		case 'd':
			mode |= MODE_ABSOLUTE_TIMESTAMP;
			break;
		case 'f':
			mode |= MODE_INHERIT;
			break;
		case 'o':
			/* Allow only single output file */
			if (output != stderr)
				usage();

			/* Set close-on-exec */
			output = efopen(optarg, "we");
			break;
		case 'p':
			pid = estrtoi(optarg, 0, 0, INTMAX_MAX);
			break;
		case 's':
			string_max_size = estrtou(optarg, 0, 3, SIZE_MAX);
			break;
		case 'x':
			mode |= MODE_EXEC_AUXV;
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

	if (mode & MODE_COUNT)
		count_main(output, mode);
	else
		events_main(output, mode, string_max_size);

	if (pid > 0)
		attach(pid);

	if (argc > 0)
		spawn(argv);
}

static void __dead
usage(void)
{

	fprintf(stderr,
	    "Usage: %s [-DHSacdefx] [-o OUTPUT] [-s #] "
	    "[-p PID | <command> [<arg ...>]]\n",
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

struct trace_ops ops = {
	.main = truss_main
};
