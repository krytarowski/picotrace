/*	$NetBSD$	*/

/*-
 * Copyright (c) 2019 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by 
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

#include <sys/cdefs.h>
#include <sys/param.h>
#include <sys/ptrace.h>
#include <sys/sysctl.h>
#include <sys/wait.h>

#include <err.h>
#include <errno.h>
#include <inttypes.h>
#include <libgen.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <threads.h>
#include <unistd.h>

int
trace_thrd_create(thrd_t *thr, thrd_start_t func, void *arg)
{

	switch (thrd_create(thr, func, arg)) {
	case thrd_success:
		return thrd_success;
	case thrd_nomem:
		errx(EXIT_FAILURE, "thrd_create returned NOMEM");
	case thrd_error:
	default:
		errx(EXIT_FAILURE, "thrd_create returned error");
	}
}

int
trace_thrd_detach(thrd_t thr)
{

	switch (thrd_detach(thr)) {
	case thrd_success:
		return thrd_success;
	case thrd_error:
	default:
		errx(EXIT_FAILURE, "thrd_detach returned error");
	}
}

int
trace_mtx_init(mtx_t *mtx, int type)
{

	switch (mtx_init(mtx, type)) {
	case thrd_success:
		return thrd_success;
	case thrd_error:
	default:
		errx(EXIT_FAILURE, "mtx_init returned error");
	}
}

int
trace_mtx_lock(mtx_t *mtx)
{

	switch (mtx_lock(mtx)) {
	case thrd_success:
		return thrd_success;
	case thrd_error:
	default:
		errx(EXIT_FAILURE, "mtx_lock returned error");
	}
}

int
trace_mtx_unlock(mtx_t *mtx)
{

	switch (mtx_unlock(mtx)) {
	case thrd_success:
		return thrd_success;
	case thrd_error:
	default:
		errx(EXIT_FAILURE, "mtx_unlock returned error");
	}
}

int
trace_cnd_init(cnd_t *cond)
{

	switch (cnd_init(cond)) {
	case thrd_success:
		return thrd_success;
	case thrd_error:
	default:
		errx(EXIT_FAILURE, "cnd_init returned error");
	}
}

int
trace_cnd_signal(cnd_t *cond)
{

	switch (cnd_signal(cond)) {
	case thrd_success:
		return thrd_success;
	case thrd_error:
	default:
		errx(EXIT_FAILURE, "cnd_signal returned error");
	}
}

int
trace_cnd_wait(cnd_t *cond, mtx_t *mtx)
{

	switch (cnd_wait(cond, mtx)) {
	case thrd_success:
		return thrd_success;
	case thrd_error:
	default:
		errx(EXIT_FAILURE, "cnd_init returned error");
	}
}

pid_t
trace_waitpid(pid_t pid, int *status, int options)
{
	pid_t wpid;

	wpid = waitpid(pid, status, options);

	if (wpid == -1)
		err(EXIT_FAILURE, "waitpid");

	if (pid != wpid)
		errx(EXIT_FAILURE, "waitpid(%d) returned %d", pid, wpid);

	return wpid;
}

int
trace_ptrace(int request, pid_t pid, void *addr, int data)
{
	int rv;

	errno = 0;
	if ((rv = ptrace(request, pid, addr, data)) == -1 && errno != 0)
		err(EXIT_FAILURE, "ptrace");

	return rv;
}

pid_t
trace_fork(void)
{
	pid_t pid;

	pid = fork();
 
	if (pid == -1)
		err(EXIT_FAILURE, "waitpid");

	return pid;
}

int
trace_sysctl(const int *name, u_int namelen, void *oldp, size_t *oldlenp,
        const void *newp, size_t newlen)
{
	int rv;

	if ((rv = sysctl(name, namelen, oldp, oldlenp, newp, newlen)) == -1)
		err(EXIT_FAILURE, "sysctl");

	return rv;
}

int
trace_snprintf(char * __restrict ret, size_t size,
          const char * __restrict format, ...)
{
	int rv;
	va_list ap;
	va_start(ap, format); 
	if ((rv = vsnprintf(ret, size, format, ap)) == -1)
		errx(EXIT_FAILURE, "Cannot format string");
	va_end(ap);
	return rv;
}
