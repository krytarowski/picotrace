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

#ifndef TRACE_H
#define TRACE_H

#include <sys/types.h>
#include <sys/siginfo.h>

void launch_worker(pid_t);

typedef void (*trace_main_func_t)(int, char **);
typedef void (*trace_end_func_t)(void);
typedef void (*trace_startup_func_t)(pid_t);
typedef void (*trace_unstop_func_t)(pid_t);
typedef void (*trace_continued_func_t)(pid_t);
typedef void (*trace_signaled_func_t)(pid_t, int, int);
typedef void (*trace_exited_func_t)(pid_t, int);
typedef void (*trace_cleanup_func_t)(pid_t);
typedef void (*trace_debugregister_func_t)(pid_t, lwpid_t);
typedef void (*trace_singlestep_func_t)(pid_t, lwpid_t);
typedef void (*trace_breakpoint_func_t)(pid_t, lwpid_t);
typedef void (*trace_syscallentry_func_t)(pid_t, lwpid_t, siginfo_t *);
typedef void (*trace_syscallexit_func_t)(pid_t, lwpid_t, siginfo_t *);
typedef void (*trace_exec_func_t)(pid_t, lwpid_t);
typedef void (*trace_forked_func_t)(pid_t, lwpid_t, pid_t);
typedef void (*trace_vforked_func_t)(pid_t, lwpid_t, pid_t);
typedef void (*trace_vforkdone_func_t)(pid_t, lwpid_t, pid_t);
typedef void (*trace_lwpcreated_func_t)(pid_t, lwpid_t, lwpid_t);
typedef void (*trace_lwpexited_func_t)(pid_t, lwpid_t, lwpid_t);
typedef void (*trace_crashed_func_t)(pid_t, lwpid_t, siginfo_t *);
typedef void (*trace_stopped_func_t)(pid_t, lwpid_t, siginfo_t *);

struct trace_ops {
	trace_main_func_t main;
	trace_end_func_t end;
	trace_startup_func_t startup;
	trace_unstop_func_t unstop;
	trace_continued_func_t continued;
	trace_signaled_func_t signaled;
	trace_exited_func_t exited;
	trace_cleanup_func_t cleanup;
	trace_debugregister_func_t debugregister;
	trace_singlestep_func_t singlestep;
	trace_breakpoint_func_t breakpoint;
	trace_syscallentry_func_t syscallentry;
	trace_syscallexit_func_t syscallexit;
	trace_exec_func_t exec;
	trace_forked_func_t forked;
	trace_vforked_func_t vforked;
	trace_vforkdone_func_t vforkdone;
	trace_lwpcreated_func_t lwpcreated;
	trace_lwpexited_func_t lwpexited;
	trace_crashed_func_t crashed;
	trace_stopped_func_t stopped;
};

struct trace_ops trace_ops_picotrace;

#endif /* TRACE_H */
