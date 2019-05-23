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
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/statvfs.h>
#include <sys/syscall.h>

#include <assert.h>
#include <ctype.h>
#include <elf.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stringlist.h>
#include <threads.h>
#include <unistd.h>
#include <vis.h>

#include <util.h>

#include "children.h"
#include "misc.h"
#include "syscalls.h"
#include "trace.h"
#include "trace_utils.h"

#include "events.h"

static char *copyinstr(pid_t, void *, size_t);
static void *copyin(pid_t, void *, size_t);
static char *get_strmode(mode_t);
static char *get_stat(pid_t, struct stat *);
static char *get_statvfs(pid_t, struct statvfs *);
static char *get_sigset(pid_t, sigset_t *);
static char *get_timespec(pid_t pid, struct timespec *tp);
static const char *err2string(int num);

static size_t string_max_size;				/* -s */

#define SPRINTF(a,...)							\
	do {								\
		if (n < len)						\
			n += trace_snprintf(buf + n, len - n,		\
				(a), ## __VA_ARGS__);			\
	} while (0)

void
set_string_max_size(size_t size)
{

	string_max_size = size;
}

char *
decode_args(pid_t pid, siginfo_t *si, char *buf, size_t len)
{
	ssize_t ssize;
	u_int uinteger;
	int integer;
	void *v;
	char *s;
	int n;

	n = 0;

	SPRINTF("%s(", syscall_info[si->si_sysnum]);

	switch (si->si_sysnum) {
	case SYS_syscall: /* 0 */
		/* Shall not happen */
		break;
	case SYS_exit: /* 1 */
		SPRINTF("%d", si->si_args[0]);
		break;
	case SYS_fork: /* 2 */
		break;
	case SYS_read: /* 3 */
		SPRINTF("%d, %#p, %zu", si->si_args[0], si->si_args[1],
		    si->si_args[2]);
		break;
	case SYS_write: /* 4 */
		s = copyinstr(pid, (void *)(intptr_t)si->si_args[1],
		    si->si_args[2]);
		SPRINTF("%d, %s, %zu", si->si_args[0], s, si->si_args[2]);
		free(s);
		break;
	case SYS_open: /* 5 */
		s = copyinstr(pid, (void *)(intptr_t)si->si_args[0], SIZE_MAX);
		SPRINTF("%s, ", s);
		free(s);

		if (si->si_args[1] & O_WRONLY)
			SPRINTF("O_WRONLY");
		else if (si->si_args[1] & O_RDWR)
			SPRINTF("O_RDWR");
		else
			SPRINTF("O_RDONLY");

#define check_flag(flag) if (si->si_args[1] & flag) SPRINTF("|" #flag)
		check_flag(O_NONBLOCK);
		check_flag(O_APPEND);
		check_flag(O_CREAT);
		check_flag(O_TRUNC);
		check_flag(O_EXCL);
		check_flag(O_SHLOCK);
		check_flag(O_EXLOCK);
		check_flag(O_NOFOLLOW);
		check_flag(O_CLOEXEC);
		check_flag(O_NOSIGPIPE);
		check_flag(O_DSYNC);
		check_flag(O_SYNC);
		check_flag(O_RSYNC);
		check_flag(O_ALT_IO);
		check_flag(O_NOCTTY);
		check_flag(O_DIRECT);
		check_flag(O_DIRECTORY);
		check_flag(O_REGULAR);
		check_flag(O_ASYNC);
#undef check_flag
		if (si->si_args[1] & O_CREAT) {
			s = get_strmode(si->si_args[2]);
			SPRINTF(", \"%s\"", s);
			free(s);
		}
		break;
	case SYS_close: /* 6 */
		SPRINTF("%d", si->si_args[0]);
		break;
	case SYS_compat_50_wait4: /* 7 */
		break;
	case SYS_compat_43_ocreat: /* 8 */
		break;
	case SYS_link: /* 9 */
		s = copyinstr(pid, (void *)(intptr_t)si->si_args[0], SIZE_MAX);
		SPRINTF("%s, ", s);
		free(s);
		s = copyinstr(pid, (void *)(intptr_t)si->si_args[1], SIZE_MAX);
		SPRINTF("%s", s);
		free(s);
		break;
	case SYS_unlink: /* 10 */
		s = copyinstr(pid, (void *)(intptr_t)si->si_args[0], SIZE_MAX);
		SPRINTF("%s", s);
		free(s);
		break;
	case SYS_chdir: /* 12 */
		s = copyinstr(pid, (void *)(intptr_t)si->si_args[0], SIZE_MAX);
		SPRINTF("%s", s);
		free(s);
		break;
	case SYS_fchdir: /* 13 */
		SPRINTF("%d", si->si_args[0]);
		break;
	case SYS_compat_50_mknod: /* 14 */
		break;
	case SYS_chmod: /* 15 */
		s = copyinstr(pid, (void *)(intptr_t)si->si_args[0], SIZE_MAX);
		SPRINTF("%s, ", s);
		free(s);

		s = get_strmode(si->si_args[1]);
		SPRINTF(", \"%s\"", s);
		free(s);
		break;
	case SYS_chown: /* 16 */
		s = copyinstr(pid, (void *)(intptr_t)si->si_args[0], SIZE_MAX);
		SPRINTF("%s, %d, %d", s, si->si_args[1], si->si_args[2]);
		free(s);
		break;
	case SYS_break: /* 17 */
		SPRINTF("%p", (void *)(intptr_t)si->si_args[0]);
		break;
	case SYS_compat_20_getfsstat: /* 18 */
		break;
	case SYS_compat_43_olseek: /* 19 */
		break;
	case SYS_getpid: /* 20 */
		SPRINTF("%d", si->si_args[0]);
		break;
	case SYS_compat_40_mount: /* 21 */
		break;
	case SYS_unmount: /* 22 */
		s = copyinstr(pid, (void *)(intptr_t)si->si_args[0], SIZE_MAX);
		SPRINTF("%s, 0", s);
		free(s);

#define check_flag(flag) if (si->si_args[1] & flag) SPRINTF("|" #flag)
		check_flag(MNT_RDONLY);
		check_flag(MNT_SYNCHRONOUS);
		check_flag(MNT_NOEXEC);
		check_flag(MNT_NOSUID);
		check_flag(MNT_NODEV);
		check_flag(MNT_UNION);
		check_flag(MNT_ASYNC);
		check_flag(MNT_NOCOREDUMP);
		check_flag(MNT_RELATIME);
		check_flag(MNT_IGNORE);
		check_flag(MNT_DISCARD);
		check_flag(MNT_EXTATTR);
		check_flag(MNT_LOG);
		check_flag(MNT_NOATIME);
		check_flag(MNT_AUTOMOUNTED);
		check_flag(MNT_SYMPERM);
		check_flag(MNT_NODEVMTIME);
		check_flag(MNT_SOFTDEP);
		check_flag(MNT_EXRDONLY);
		check_flag(MNT_EXPORTED);
		check_flag(MNT_DEFEXPORTED);
		check_flag(MNT_EXPORTANON);
		check_flag(MNT_EXKERB);
		check_flag(MNT_EXNORESPORT);
		check_flag(MNT_EXPUBLIC);
		check_flag(MNT_LOCAL);
		check_flag(MNT_QUOTA);
		check_flag(MNT_ROOTFS);
		check_flag(MNT_UPDATE);
		check_flag(MNT_RELOAD);
		check_flag(MNT_FORCE);
		check_flag(MNT_GETARGS);
#undef check_flag
		break;
	case SYS_setuid: /* 23 */
		SPRINTF("%d", si->si_args[0]);
		break;
	case SYS_getuid: /* 24 */
		/* No arguments */
		break;
	case SYS_geteuid: /* 25 */
		/* No arguments */
		break;
	case SYS_ptrace: /* 26 */
#define check_flag(flag) case flag: SPRINTF(#flag); break
		switch (si->si_args[0]) {
		check_flag(PT_TRACE_ME);
		check_flag(PT_READ_I);
		check_flag(PT_READ_D);
		check_flag(PT_WRITE_I);
		check_flag(PT_WRITE_D);
		check_flag(PT_CONTINUE);
		check_flag(PT_KILL);
		check_flag(PT_ATTACH);
		check_flag(PT_DETACH);
		check_flag(PT_IO);
		check_flag(PT_DUMPCORE);
		check_flag(PT_LWPINFO);
		check_flag(PT_SYSCALL);
		check_flag(PT_SYSCALLEMU);
		check_flag(PT_SET_EVENT_MASK);
		check_flag(PT_GET_EVENT_MASK);
		check_flag(PT_GET_PROCESS_STATE);
		check_flag(PT_SET_SIGINFO);
		check_flag(PT_GET_SIGINFO);
		check_flag(PT_RESUME);
		check_flag(PT_SUSPEND);
#ifdef PT_STEP
		check_flag(PT_STEP);
		check_flag(PT_SETSTEP);
		check_flag(PT_CLEARSTEP);
#endif
#if PT_GETREGS
		check_flag(PT_GETREGS);
		check_flag(PT_SETREGS);
#endif
#if PT_GETFPREGS
		check_flag(PT_GETFPREGS);
		check_flag(PT_SETFPREGS);
#endif
#if PT_GETDBREGS
		check_flag(PT_GETDBREGS);
		check_flag(PT_SETDBREGS);
#endif
#if PT_GETXMMREGS
		check_flag(PT_GETXMMREGS);
		check_flag(PT_SETXMMREGS);
#endif
#if PT_GETVECREGS
		check_flag(PT_GETVECREGS);
		check_flag(PT_SETVECREGS);
#endif
#undef check_flag
		}
		SPRINTF(", %d, %#p, %d", si->si_args[1], si->si_args[2],
		    si->si_args[3]);
		break;
	case SYS_recvmsg: /* 27 */
		SPRINTF("%d, %#p, 0", si->si_args[0], si->si_args[1]);
#define check_flag(flag) if (si->si_args[2] & flag) SPRINTF("|" #flag)
		check_flag(MSG_OOB);
		check_flag(MSG_PEEK);
		check_flag(MSG_DONTROUTE);
		check_flag(MSG_EOR);
		check_flag(MSG_TRUNC);
		check_flag(MSG_CTRUNC);
		check_flag(MSG_WAITALL);
		check_flag(MSG_DONTWAIT);
		check_flag(MSG_BCAST);
		check_flag(MSG_MCAST);
		check_flag(MSG_NOSIGNAL);
		check_flag(MSG_CMSG_CLOEXEC);
		check_flag(MSG_NBIO);
		check_flag(MSG_WAITFORONE);
		check_flag(MSG_NOTIFICATION);
		check_flag(MSG_NAMEMBUF);
		check_flag(MSG_CONTROLMBUF);
		check_flag(MSG_IOVUSRSPACE);
		check_flag(MSG_LENUSRSPACE);
#undef check_flag
		break;
	case SYS_sendmsg: /* 28 */
		break;
	case SYS_recvfrom: /* 29 */
		break;
	case SYS_accept: /* 30 */
		break;
	case SYS_getpeername: /* 31 */
		break;
	case SYS_getsockname: /* 32 */
		break;
	case SYS_access: /* 33 */
		s = copyinstr(pid, (void *)(intptr_t)si->si_args[0], SIZE_MAX);
		SPRINTF("%s", s);
		free(s);

		s = get_strmode(si->si_args[1]);
		SPRINTF(", \"%s\"", s);
		free(s);
		break;
	case SYS_chflags: /* 34 */
		break;
	case SYS_fchflags: /* 35 */
		break;
	case SYS_sync: /* 36 */
		break;
	case SYS_kill: /* 37 */
		break;
	case SYS_compat_43_stat43: /* 38 */
		break;
	case SYS_getppid: /* 39 */
		break;
	case SYS_compat_43_lstat43: /* 40 */
		break;
	case SYS_dup: /* 41 */
		break;
	case SYS_pipe: /* 42 */
		break;
	case SYS_getegid: /* 43 */
		break;
	case SYS_profil: /* 44 */
		break;
	case SYS_ktrace: /* 45 */
		break;
	case SYS_compat_13_sigaction13: /* 46 */
		break;
	case SYS_getgid: /* 47 */
		break;
	case SYS_compat_13_sigprocmask13: /* 48 */
		break;
	case SYS___getlogin: /* 49 */
		break;
	case SYS___setlogin: /* 50 */
		break;
	case SYS_acct: /* 51 */
		break;
	case SYS_compat_13_sigpending13: /* 52 */
		break;
	case SYS_compat_13_sigaltstack13: /* 53 */
		break;
	case SYS_ioctl: /* 54 */
		SPRINTF("%d, %lu, ...", si->si_args[0], si->si_args[1]);
		break;
	case SYS_compat_12_oreboot: /* 55 */
		break;
	case SYS_revoke: /* 56 */
		break;
	case SYS_symlink: /* 57 */
		break;
	case SYS_readlink: /* 58 */
		s = copyinstr(pid, (void *)(intptr_t)si->si_args[0], SIZE_MAX);
		SPRINTF("%s, ", s);
		free(s);

#if _LP64
		ssize = ((ssize_t)(unsigned)si->si_retval[1]) << 32 |
		    ((ssize_t)(unsigned)si->si_retval[0]);
#else
		ssize = si->si_retval[0];
#endif
		if (ssize > 0) {
			s = copyinstr(pid, (void *)(intptr_t)si->si_args[1],
			    ssize);
			SPRINTF("%s, ", s);
			free(s);
		} else if (ssize == 0) {
			SPRINTF("\"\", ");
		} else {
			SPRINTF("%#p, ", (void *)(intptr_t)si->si_args[1]);
		}

		SPRINTF("%zu", si->si_args[2]);
		break;
	case SYS_execve: /* 59 */
		break;
	case SYS_umask: /* 60 */
		break;
	case SYS_chroot: /* 61 */
		break;
	case SYS_compat_43_fstat43: /* 62 */
		break;
	case SYS_compat_43_ogetkerninfo: /* 63 */
		break;
	case SYS_compat_43_ogetpagesize: /* 64 */
		break;
	case SYS_compat_12_msync: /* 65 */
		break;
	case SYS_vfork: /* 66 */
		break;
	case SYS_compat_43_ommap: /* 71 */
		break;
	case SYS_vadvise: /* 72 */
		break;
	case SYS_munmap: /* 73 */
		SPRINTF("%#p, %zu", si->si_args[0], si->si_args[1]);
		break;
	case SYS_mprotect: /* 74 */
		SPRINTF("%#p, %zu, ", si->si_args[0], si->si_args[1]);
		if (si->si_args[2] & (PROT_EXEC|PROT_READ|PROT_WRITE)) {
			SPRINTF("0");
#define check_flag(flag) if (si->si_args[2] & flag) SPRINTF("|" #flag)
			check_flag(PROT_EXEC);
			check_flag(PROT_READ);
			check_flag(PROT_WRITE);
#undef check_flag
		} else {
			SPRINTF("PROT_NONE");
		}
#define check_flag(flag) if (si->si_args[2] & PROT_MPROTECT(flag)) \
			SPRINTF("|PROT_MPROTECT(" #flag ")")
		check_flag(PROT_EXEC);
		check_flag(PROT_READ);
		check_flag(PROT_WRITE);
#undef check_flag
		break;
	case SYS_madvise: /* 75 */
		SPRINTF("%#p, %zu, ", si->si_args[0], si->si_args[1]);
#define check_flag(flag) case flag: SPRINTF(#flag); break
		switch (si->si_args[2]) {
		check_flag(MADV_NORMAL);
		check_flag(MADV_RANDOM);
		check_flag(MADV_SEQUENTIAL);
		check_flag(MADV_WILLNEED);
		check_flag(MADV_DONTNEED);
		check_flag(MADV_SPACEAVAIL);
		check_flag(MADV_FREE);
		}
#undef check_flag
		break;
	case SYS_mincore: /* 78 */
		break;
	case SYS_getgroups: /* 79 */
		break;
	case SYS_setgroups: /* 80 */
		break;
	case SYS_getpgrp: /* 81 */
		break;
	case SYS_setpgid: /* 82 */
		break;
	case SYS_compat_50_setitimer: /* 83 */
		break;
	case SYS_compat_43_owait: /* 84 */
		break;
	case SYS_compat_12_oswapon: /* 85 */
		break;
	case SYS_compat_50_getitimer: /* 86 */
		break;
	case SYS_compat_43_ogethostname: /* 87 */
		break;
	case SYS_compat_43_osethostname: /* 88 */
		break;
	case SYS_compat_43_ogetdtablesize: /* 89 */
		break;
	case SYS_dup2: /* 90 */
		break;
	case SYS_fcntl: /* 92 */
		break;
	case SYS_compat_50_select: /* 93 */
		break;
	case SYS_fsync: /* 95 */
		break;
	case SYS_setpriority: /* 96 */
		break;
	case SYS_compat_30_socket: /* 97 */
		break;
	case SYS_connect: /* 98 */
		break;
	case SYS_compat_43_oaccept: /* 99 */
		break;
	case SYS_getpriority: /* 100 */
		break;
	case SYS_compat_43_osend: /* 101 */
		break;
	case SYS_compat_43_orecv: /* 102 */
		break;
	case SYS_compat_13_sigreturn13: /* 103 */
		break;
	case SYS_bind: /* 104 */
		break;
	case SYS_setsockopt: /* 105 */
		break;
	case SYS_listen: /* 106 */
		break;
	case SYS_compat_43_osigvec: /* 108 */
		break;
	case SYS_compat_43_osigblock: /* 109 */
		break;
	case SYS_compat_43_osigsetmask: /* 110 */
		break;
	case SYS_compat_13_sigsuspend13: /* 111 */
		break;
	case SYS_compat_43_osigstack: /* 112 */
		break;
	case SYS_compat_43_orecvmsg: /* 113 */
		break;
	case SYS_compat_43_osendmsg: /* 114 */
		break;
	case SYS_compat_50_gettimeofday: /* 116 */
		break;
	case SYS_compat_50_getrusage: /* 117 */
		break;
	case SYS_getsockopt: /* 118 */
		break;
	case SYS_readv: /* 120 */
		break;
	case SYS_writev: /* 121 */
		break;
	case SYS_compat_50_settimeofday: /* 122 */
		break;
	case SYS_fchown: /* 123 */
		break;
	case SYS_fchmod: /* 124 */
		break;
	case SYS_compat_43_orecvfrom: /* 125 */
		break;
	case SYS_setreuid: /* 126 */
		break;
	case SYS_setregid: /* 127 */
		break;
	case SYS_rename: /* 128 */
		break;
	case SYS_compat_43_otruncate: /* 129 */
		break;
	case SYS_compat_43_oftruncate: /* 130 */
		break;
	case SYS_flock: /* 131 */
		break;
	case SYS_mkfifo: /* 132 */
		break;
	case SYS_sendto: /* 133 */
		break;
	case SYS_shutdown: /* 134 */
		break;
	case SYS_socketpair: /* 135 */
		break;
	case SYS_mkdir: /* 136 */
		break;
	case SYS_rmdir: /* 137 */
		break;
	case SYS_compat_50_utimes: /* 138 */
		break;
	case SYS_compat_50_adjtime: /* 140 */
		break;
	case SYS_compat_43_ogetpeername: /* 141 */
		break;
	case SYS_compat_43_ogethostid: /* 142 */
		break;
	case SYS_compat_43_osethostid: /* 143 */
		break;
	case SYS_compat_43_ogetrlimit: /* 144 */
		break;
	case SYS_compat_43_osetrlimit: /* 145 */
		break;
	case SYS_compat_43_okillpg: /* 146 */
		break;
	case SYS_setsid: /* 147 */
		break;
	case SYS_compat_50_quotactl: /* 148 */
		break;
	case SYS_compat_43_oquota: /* 149 */
		break;
	case SYS_compat_43_ogetsockname: /* 150 */
		break;
	case SYS_nfssvc: /* 155 */
		break;
	case SYS_compat_43_ogetdirentries: /* 156 */
		break;
	case SYS_compat_20_statfs: /* 157 */
		break;
	case SYS_compat_20_fstatfs: /* 158 */
		break;
	case SYS_compat_30_getfh: /* 161 */
		break;
	case SYS_compat_09_ogetdomainname: /* 162 */
		break;
	case SYS_compat_09_osetdomainname: /* 163 */
		break;
	case SYS_compat_09_ouname: /* 164 */
		break;
	case SYS_sysarch: /* 165 */
		break;
#if !defined(_LP64)
	case SYS_compat_10_osemsys: /* 169 */
		break;
	case SYS_compat_10_omsgsys: /* 170 */
		break;
	case SYS_compat_10_oshmsys: /* 171 */
		break;
#endif
	case SYS_pread: /* 173 */
		break;
	case SYS_pwrite: /* 174 */
		break;
	case SYS_compat_30_ntp_gettime: /* 175 */
		break;
	case SYS_ntp_adjtime: /* 176 */
		break;
	case SYS_setgid: /* 181 */
		break;
	case SYS_setegid: /* 182 */
		break;
	case SYS_seteuid: /* 183 */
		break;
	case SYS_lfs_bmapv: /* 184 */
		break;
	case SYS_lfs_markv: /* 185 */
		break;
	case SYS_lfs_segclean: /* 186 */
		break;
	case SYS_compat_50_lfs_segwait: /* 187 */
		break;
	case SYS_compat_12_stat12: /* 188 */
		break;
	case SYS_compat_12_fstat12: /* 189 */
		break;
	case SYS_compat_12_lstat12: /* 190 */
		break;
	case SYS_pathconf: /* 191 */
		break;
	case SYS_fpathconf: /* 192 */
		break;
	case SYS_getsockopt2: /* 193 */
		break;
	case SYS_getrlimit: /* 194 */
		break;
	case SYS_setrlimit: /* 195 */
		break;
	case SYS_compat_12_getdirentries: /* 196 */
		break;
	case SYS_mmap: /* 197 */
		SPRINTF("%#p, %zu, ", si->si_args[0], si->si_args[1]);
		if (si->si_args[2] & (PROT_EXEC|PROT_READ|PROT_WRITE)) {
			SPRINTF("0");
#define check_flag(flag) if (si->si_args[2] & flag) SPRINTF("|" #flag)
			check_flag(PROT_EXEC);
			check_flag(PROT_READ);
			check_flag(PROT_WRITE);
#undef check_flag
		} else {
			SPRINTF("PROT_NONE");
		}
#define check_flag(flag) if (si->si_args[2] & PROT_MPROTECT(flag)) \
			SPRINTF("|PROT_MPROTECT(" #flag ")")
		check_flag(PROT_EXEC);
		check_flag(PROT_READ);
		check_flag(PROT_WRITE);
#undef check_flag
		SPRINTF(", 0");
#define check_flag(flag) if (si->si_args[3] & flag) SPRINTF("|" #flag)
		check_flag(MAP_SHARED);
		check_flag(MAP_PRIVATE);
		check_flag(MAP_REMAPDUP);
		check_flag(MAP_FIXED);
		check_flag(MAP_RENAME);
		check_flag(MAP_NORESERVE);
		check_flag(MAP_HASSEMAPHORE);
		check_flag(MAP_TRYFIXED);
		check_flag(MAP_WIRED);
		check_flag(MAP_FILE);
		check_flag(MAP_ANONYMOUS);
		check_flag(MAP_STACK);
#undef check_flag
		if (MAP_ALIGNMENT_MASK & si->si_args[3]) {
			SPRINTF("|MAP_ALIGNED(%#" PRIx8 ")",
			    (uint8_t)((MAP_ALIGNMENT_MASK & si->si_args[3])
			        >> MAP_ALIGNMENT_SHIFT));
		}
		/* Do not print args[5] as it's pad. */
		SPRINTF(", %d, %zd", si->si_args[4], si->si_args[6]);
		break;
	case SYS___syscall: /* 198 */
		break;
	case SYS_lseek: /* 199 */
		SPRINTF("%d, %zd, ", si->si_args[0], si->si_args[1]);
#define check_flag(flag) case flag: SPRINTF(#flag); break
		switch (si->si_args[2]) {
		check_flag(SEEK_SET);
		check_flag(SEEK_CUR);
		check_flag(SEEK_END);
		}
#undef check_flag
		break;
	case SYS_truncate: /* 200 */
		break;
	case SYS_ftruncate: /* 201 */
		break;
	case SYS___sysctl: /* 202 */
		if (si->si_args[1] > 0)
			v = copyin(pid, (void *)(intptr_t)si->si_args[0],
			    sizeof(int) * si->si_args[1]);
		else
			v = NULL;
		if (v == NULL) {
			SPRINTF("%#p", si->si_args[0]);
		} else {
			SPRINTF("{ ");
			SPRINTF("%d", *(int *)v);
			for (uinteger = 1; uinteger < si->si_args[1];
			    uinteger++) {
				SPRINTF(", %d", ((int *)v)[uinteger]);
			}
			SPRINTF(" }");

			free(v);
		}

		SPRINTF(", %u, %#p, %#p, %#p, %zu", si->si_args[1],
		    si->si_args[2], si->si_args[3], si->si_args[4],
		    si->si_args[5]);
		break;
	case SYS_mlock: /* 203 */
		break;
	case SYS_munlock: /* 204 */
		break;
	case SYS_undelete: /* 205 */
		break;
	case SYS_compat_50_futimes: /* 206 */
		break;
	case SYS_getpgid: /* 207 */
		break;
	case SYS_reboot: /* 208 */
		break;
	case SYS_poll: /* 209 */
		break;
	case SYS_afssys: /* 210 */
		break;
	case SYS_compat_14___semctl: /* 220 */
		break;
	case SYS_semget: /* 221 */
		break;
	case SYS_semop: /* 222 */
		break;
	case SYS_semconfig: /* 223 */
		break;
	case SYS_compat_14_msgctl: /* 224 */
		break;
	case SYS_msgget: /* 225 */
		break;
	case SYS_msgsnd: /* 226 */
		break;
	case SYS_msgrcv: /* 227 */
		break;
	case SYS_shmat: /* 228 */
		break;
	case SYS_compat_14_shmctl: /* 229 */
		break;
	case SYS_shmdt: /* 230 */
		break;
	case SYS_shmget: /* 231 */
		break;
	case SYS_compat_50_clock_gettime: /* 232 */
		break;
	case SYS_compat_50_clock_settime: /* 233 */
		break;
	case SYS_compat_50_clock_getres: /* 234 */
		break;
	case SYS_timer_create: /* 235 */
		break;
	case SYS_timer_delete: /* 236 */
		break;
	case SYS_compat_50_timer_settime: /* 237 */
		break;
	case SYS_compat_50_timer_gettime: /* 238 */
		break;
	case SYS_timer_getoverrun: /* 239 */
		break;
	case SYS_compat_50_nanosleep: /* 240 */
		break;
	case SYS_fdatasync: /* 241 */
		break;
	case SYS_mlockall: /* 242 */
		break;
	case SYS_munlockall: /* 243 */
		break;
	case SYS_compat_50___sigtimedwait: /* 244 */
		break;
	case SYS_sigqueueinfo: /* 245 */
		break;
	case SYS_modctl: /* 246 */
		break;
	case SYS__ksem_init: /* 247 */
		break;
	case SYS__ksem_open: /* 248 */
		break;
	case SYS__ksem_unlink: /* 249 */
		break;
	case SYS__ksem_close: /* 250 */
		break;
	case SYS__ksem_post: /* 251 */
		break;
	case SYS__ksem_wait: /* 252 */
		break;
	case SYS__ksem_trywait: /* 253 */
		break;
	case SYS__ksem_getvalue: /* 254 */
		break;
	case SYS__ksem_destroy: /* 255 */
		break;
	case SYS__ksem_timedwait: /* 256 */
		break;
	case SYS_mq_open: /* 257 */
		break;
	case SYS_mq_close: /* 258 */
		break;
	case SYS_mq_unlink: /* 259 */
		break;
	case SYS_mq_getattr: /* 260 */
		break;
	case SYS_mq_setattr: /* 261 */
		break;
	case SYS_mq_notify: /* 262 */
		break;
	case SYS_mq_send: /* 263 */
		break;
	case SYS_mq_receive: /* 264 */
		break;
	case SYS_compat_50_mq_timedsend: /* 265 */
		break;
	case SYS_compat_50_mq_timedreceive: /* 266 */
		break;
	case SYS___posix_rename: /* 270 */
		break;
	case SYS_swapctl: /* 271 */
		break;
	case SYS_compat_30_getdents: /* 272 */
		break;
	case SYS_minherit: /* 273 */
		break;
	case SYS_lchmod: /* 274 */
		break;
	case SYS_lchown: /* 275 */
		break;
	case SYS_compat_50_lutimes: /* 276 */
		break;
	case SYS___msync13: /* 277 */
		break;
	case SYS_compat_30___stat13: /* 278 */
		break;
	case SYS_compat_30___fstat13: /* 279 */
		break;
	case SYS_compat_30___lstat13: /* 280 */
		break;
	case SYS___sigaltstack14: /* 281 */
		break;
	case SYS___vfork14: /* 282 */
		break;
	case SYS___posix_chown: /* 283 */
		break;
	case SYS___posix_fchown: /* 284 */
		break;
	case SYS___posix_lchown: /* 285 */
		break;
	case SYS_getsid: /* 286 */
		break;
	case SYS___clone: /* 287 */
		break;
	case SYS_fktrace: /* 288 */
		break;
	case SYS_preadv: /* 289 */
		break;
	case SYS_pwritev: /* 290 */
		break;
	case SYS_compat_16___sigaction14: /* 291 */
		break;
	case SYS___sigpending14: /* 292 */
		break;
	case SYS___sigprocmask14: /* 293 */
#define check_flag(flag) case flag: SPRINTF(#flag); break
		switch (si->si_args[0]) {
		check_flag(SIG_BLOCK);
		check_flag(SIG_UNBLOCK);
		check_flag(SIG_SETMASK);
		}
#undef check_flag

		s = get_sigset(pid, (sigset_t *)(intptr_t)si->si_args[1]);
		SPRINTF(", %s", s);
		free(s);

		s = get_sigset(pid, (sigset_t *)(intptr_t)si->si_args[2]);
		SPRINTF(", %s", s);
		free(s);
		break;
	case SYS___sigsuspend14: /* 294 */
		break;
	case SYS_compat_16___sigreturn14: /* 295 */
		break;
	case SYS___getcwd: /* 296 */
		break;
	case SYS_fchroot: /* 297 */
		break;
	case SYS_compat_30_fhopen: /* 298 */
		break;
	case SYS_compat_30_fhstat: /* 299 */
		break;
	case SYS_compat_20_fhstatfs: /* 300 */
		break;
	case SYS_compat_50_____semctl13: /* 301 */
		break;
	case SYS_compat_50___msgctl13: /* 302 */
		break;
	case SYS_compat_50___shmctl13: /* 303 */
		break;
	case SYS_lchflags: /* 304 */
		break;
	case SYS_issetugid: /* 305 */
		break;
	case SYS_utrace: /* 306 */
		break;
	case SYS_getcontext: /* 307 */
		break;
	case SYS_setcontext: /* 308 */
		break;
	case SYS__lwp_create: /* 309 */
		break;
	case SYS__lwp_exit: /* 310 */
		break;
	case SYS__lwp_self: /* 311 */
		break;
	case SYS__lwp_wait: /* 312 */
		break;
	case SYS__lwp_suspend: /* 313 */
		break;
	case SYS__lwp_continue: /* 314 */
		break;
	case SYS__lwp_wakeup: /* 315 */
		break;
	case SYS__lwp_getprivate: /* 316 */
		break;
	case SYS__lwp_setprivate: /* 317 */
		SPRINTF("%#p", si->si_args[0]);
		break;
	case SYS__lwp_kill: /* 318 */
		break;
	case SYS__lwp_detach: /* 319 */
		break;
	case SYS_compat_50__lwp_park: /* 320 */
		break;
	case SYS__lwp_unpark: /* 321 */
		break;
	case SYS__lwp_unpark_all: /* 322 */
		break;
	case SYS__lwp_setname: /* 323 */
		break;
	case SYS__lwp_getname: /* 324 */
		break;
	case SYS__lwp_ctl: /* 325 */
		break;
	case SYS_compat_60_sa_register: /* 330 */
		break;
	case SYS_compat_60_sa_stacks: /* 331 */
		break;
	case SYS_compat_60_sa_enable: /* 332 */
		break;
	case SYS_compat_60_sa_setconcurrency: /* 333 */
		break;
	case SYS_compat_60_sa_yield: /* 334 */
		break;
	case SYS_compat_60_sa_preempt: /* 335 */
		break;
	case SYS___sigaction_sigtramp: /* 340 */
		break;
	case SYS_rasctl: /* 343 */
		break;
	case SYS_kqueue: /* 344 */
		break;
	case SYS_compat_50_kevent: /* 345 */
		break;
	case SYS__sched_setparam: /* 346 */
		break;
	case SYS__sched_getparam: /* 347 */
		break;
	case SYS__sched_setaffinity: /* 348 */
		break;
	case SYS__sched_getaffinity: /* 349 */
		break;
	case SYS_sched_yield: /* 350 */
		break;
	case SYS__sched_protect: /* 351 */
		break;
	case SYS_fsync_range: /* 354 */
		break;
	case SYS_uuidgen: /* 355 */
		break;
	case SYS_getvfsstat: /* 356 */
		SPRINTF("%#p, %zu, ", si->si_args[0], si->si_args[1]);

		SPRINTF("0");
#define check_flag(flag) if (si->si_args[2] & flag) SPRINTF("|" #flag)
		check_flag(ST_RDONLY);
		check_flag(ST_SYNCHRONOUS);
		check_flag(ST_NOEXEC);
		check_flag(ST_NOSUID);
		check_flag(ST_NODEV);
		check_flag(ST_UNION);
		check_flag(ST_ASYNC);
		check_flag(ST_NOCOREDUMP);
		check_flag(ST_RELATIME);
		check_flag(ST_IGNORE);
		check_flag(ST_NOATIME);
		check_flag(ST_SYMPERM);
		check_flag(ST_NODEVMTIME);
		check_flag(ST_SOFTDEP);
		check_flag(ST_LOG);
		check_flag(ST_EXTATTR);
		check_flag(ST_EXRDONLY);
		check_flag(ST_EXPORTED);
		check_flag(ST_DEFEXPORTED);
		check_flag(ST_EXPORTANON);
		check_flag(ST_EXKERB);
		check_flag(ST_EXNORESPORT);
		check_flag(ST_EXPUBLIC);
		check_flag(ST_LOCAL);
		check_flag(ST_QUOTA);
		check_flag(ST_ROOTFS);
		check_flag(ST_WAIT);
		check_flag(ST_NOWAIT);
#undef check_flag

		break;
	case SYS_statvfs1: /* 357 */
		s = copyinstr(pid, (void *)(intptr_t)si->si_args[0], SIZE_MAX);
		SPRINTF("%s, ", s);
		free(s);

		s = get_statvfs(pid, (void *)(intptr_t)si->si_args[1]);
		SPRINTF("%s, ", s);
		free(s);

		SPRINTF("0");
#define check_flag(flag) if (si->si_args[2] & flag) SPRINTF("|" #flag)
		check_flag(ST_RDONLY);
		check_flag(ST_SYNCHRONOUS);
		check_flag(ST_NOEXEC);
		check_flag(ST_NOSUID);
		check_flag(ST_NODEV);
		check_flag(ST_UNION);
		check_flag(ST_ASYNC);
		check_flag(ST_NOCOREDUMP);
		check_flag(ST_RELATIME);
		check_flag(ST_IGNORE);
		check_flag(ST_NOATIME);
		check_flag(ST_SYMPERM);
		check_flag(ST_NODEVMTIME);
		check_flag(ST_SOFTDEP);
		check_flag(ST_LOG);
		check_flag(ST_EXTATTR);
		check_flag(ST_EXRDONLY);
		check_flag(ST_EXPORTED);
		check_flag(ST_DEFEXPORTED);
		check_flag(ST_EXPORTANON);
		check_flag(ST_EXKERB);
		check_flag(ST_EXNORESPORT);
		check_flag(ST_EXPUBLIC);
		check_flag(ST_LOCAL);
		check_flag(ST_QUOTA);
		check_flag(ST_ROOTFS);
		check_flag(ST_WAIT);
		check_flag(ST_NOWAIT);
#undef check_flag
		break;
	case SYS_fstatvfs1: /* 358 */
		SPRINTF("%d, ", si->si_args[0]);

		s = get_statvfs(pid, (void *)(intptr_t)si->si_args[1]);
		SPRINTF("%s, ", s);
		free(s);

		SPRINTF("0");
#define check_flag(flag) if (si->si_args[2] & flag) SPRINTF("|" #flag)
		check_flag(ST_RDONLY);
		check_flag(ST_SYNCHRONOUS);
		check_flag(ST_NOEXEC);
		check_flag(ST_NOSUID);
		check_flag(ST_NODEV);
		check_flag(ST_UNION);
		check_flag(ST_ASYNC);
		check_flag(ST_NOCOREDUMP);
		check_flag(ST_RELATIME);
		check_flag(ST_IGNORE);
		check_flag(ST_NOATIME);
		check_flag(ST_SYMPERM);
		check_flag(ST_NODEVMTIME);
		check_flag(ST_SOFTDEP);
		check_flag(ST_LOG);
		check_flag(ST_EXTATTR);
		check_flag(ST_EXRDONLY);
		check_flag(ST_EXPORTED);
		check_flag(ST_DEFEXPORTED);
		check_flag(ST_EXPORTANON);
		check_flag(ST_EXKERB);
		check_flag(ST_EXNORESPORT);
		check_flag(ST_EXPUBLIC);
		check_flag(ST_LOCAL);
		check_flag(ST_QUOTA);
		check_flag(ST_ROOTFS);
		check_flag(ST_WAIT);
		check_flag(ST_NOWAIT);
#undef check_flag
		break;
	case SYS_compat_30_fhstatvfs1: /* 359 */
		break;
	case SYS_extattrctl: /* 360 */
		break;
	case SYS_extattr_set_file: /* 361 */
		break;
	case SYS_extattr_get_file: /* 362 */
		break;
	case SYS_extattr_delete_file: /* 363 */
		break;
	case SYS_extattr_set_fd: /* 364 */
		break;
	case SYS_extattr_get_fd: /* 365 */
		break;
	case SYS_extattr_delete_fd: /* 366 */
		break;
	case SYS_extattr_set_link: /* 367 */
		break;
	case SYS_extattr_get_link: /* 368 */
		break;
	case SYS_extattr_delete_link: /* 369 */
		break;
	case SYS_extattr_list_fd: /* 370 */
		break;
	case SYS_extattr_list_file: /* 371 */
		break;
	case SYS_extattr_list_link: /* 372 */
		break;
	case SYS_compat_50_pselect: /* 373 */
		break;
	case SYS_compat_50_pollts: /* 374 */
		break;
	case SYS_setxattr: /* 375 */
		break;
	case SYS_lsetxattr: /* 376 */
		break;
	case SYS_fsetxattr: /* 377 */
		break;
	case SYS_getxattr: /* 378 */
		break;
	case SYS_lgetxattr: /* 379 */
		break;
	case SYS_fgetxattr: /* 380 */
		break;
	case SYS_listxattr: /* 381 */
		break;
	case SYS_llistxattr: /* 382 */
		break;
	case SYS_flistxattr: /* 383 */
		break;
	case SYS_removexattr: /* 384 */
		break;
	case SYS_lremovexattr: /* 385 */
		break;
	case SYS_fremovexattr: /* 386 */
		break;
	case SYS_compat_50___stat30: /* 387 */
		break;
	case SYS_compat_50___fstat30: /* 388 */
		break;
	case SYS_compat_50___lstat30: /* 389 */
		break;
	case SYS___getdents30: /* 390 */
		SPRINTF("%d, %#p, %zu", si->si_args[0], si->si_args[1],
		    si->si_args[2]);
		break;
	case SYS_compat_30___fhstat30: /* 392 */
		break;
	case SYS_compat_50___ntp_gettime30: /* 393 */
		break;
	case SYS___socket30: /* 394 */
		break;
	case SYS___getfh30: /* 395 */
		break;
	case SYS___fhopen40: /* 396 */
		break;
	case SYS___fhstatvfs140: /* 397 */
		break;
	case SYS_compat_50___fhstat40: /* 398 */
		break;
	case SYS_aio_cancel: /* 399 */
		break;
	case SYS_aio_error: /* 400 */
		break;
	case SYS_aio_fsync: /* 401 */
		break;
	case SYS_aio_read: /* 402 */
		break;
	case SYS_aio_return: /* 403 */
		break;
	case SYS_compat_50_aio_suspend: /* 404 */
		break;
	case SYS_aio_write: /* 405 */
		break;
	case SYS_lio_listio: /* 406 */
		break;
	case SYS___mount50: /* 410 */
		break;
	case SYS_mremap: /* 411 */
		break;
	case SYS_pset_create: /* 412 */
		break;
	case SYS_pset_destroy: /* 413 */
		break;
	case SYS_pset_assign: /* 414 */
		break;
	case SYS__pset_bind: /* 415 */
		break;
	case SYS___posix_fadvise50: /* 416 */
		break;
	case SYS___select50: /* 417 */
		break;
	case SYS___gettimeofday50: /* 418 */
		break;
	case SYS___settimeofday50: /* 419 */
		break;
	case SYS___utimes50: /* 420 */
		break;
	case SYS___adjtime50: /* 421 */
		break;
	case SYS___lfs_segwait50: /* 422 */
		break;
	case SYS___futimes50: /* 423 */
		break;
	case SYS___lutimes50: /* 424 */
		break;
	case SYS___setitimer50: /* 425 */
		break;
	case SYS___getitimer50: /* 426 */
		break;
	case SYS___clock_gettime50: /* 427 */
#define check_flag(flag) case flag: SPRINTF(#flag); break
		switch (si->si_args[0]) {
		check_flag(CLOCK_REALTIME);
		check_flag(CLOCK_VIRTUAL);
		check_flag(CLOCK_PROF);
		check_flag(CLOCK_MONOTONIC);
		check_flag(CLOCK_THREAD_CPUTIME_ID);
		check_flag(CLOCK_PROCESS_CPUTIME_ID);
		}
#undef check_flag
		s = get_timespec(pid, (void *)(intptr_t)si->si_args[1]);
		SPRINTF(", %s", s);
		free(s);
		break;
	case SYS___clock_settime50: /* 428 */
		break;
	case SYS___clock_getres50: /* 429 */
		break;
	case SYS___nanosleep50: /* 430 */
		break;
	case SYS_____sigtimedwait50: /* 431 */
		break;
	case SYS___mq_timedsend50: /* 432 */
		break;
	case SYS___mq_timedreceive50: /* 433 */
		break;
	case SYS_compat_60__lwp_park: /* 434 */
		break;
	case SYS___kevent50: /* 435 */
		break;
	case SYS___pselect50: /* 436 */
		break;
	case SYS___pollts50: /* 437 */
		break;
	case SYS___aio_suspend50: /* 438 */
		break;
	case SYS___stat50: /* 439 */
		s = copyinstr(pid, (void *)(intptr_t)si->si_args[0], SIZE_MAX);
		SPRINTF("%s, ", s);
		free(s);

		s = get_stat(pid, (void *)(intptr_t)si->si_args[1]);
		SPRINTF("%s", s);
		free(s);
		break;
	case SYS___fstat50: /* 440 */
		SPRINTF("%d, ", si->si_args[0]);

		s = get_stat(pid, (void *)(intptr_t)si->si_args[1]);
		SPRINTF("%s", s);
		free(s);
		break;
	case SYS___lstat50: /* 441 */
		s = copyinstr(pid, (void *)(intptr_t)si->si_args[0], SIZE_MAX);
		SPRINTF("%s, ", s);
		free(s);

		s = get_stat(pid, (void *)(intptr_t)si->si_args[1]);
		SPRINTF("%s", s);
		free(s);
		break;
	case SYS_____semctl50: /* 442 */
		break;
	case SYS___shmctl50: /* 443 */
		break;
	case SYS___msgctl50: /* 444 */
		break;
	case SYS___getrusage50: /* 445 */
		break;
	case SYS___timer_settime50: /* 446 */
		break;
	case SYS___timer_gettime50: /* 447 */
		break;
	case SYS___ntp_gettime50: /* 448 */
		break;
	case SYS___wait450: /* 449 */
		break;
	case SYS___mknod50: /* 450 */
		break;
	case SYS___fhstat50: /* 451 */
		break;
	case SYS_pipe2: /* 453 */
		break;
	case SYS_dup3: /* 454 */
		break;
	case SYS_kqueue1: /* 455 */
		break;
	case SYS_paccept: /* 456 */
		break;
	case SYS_linkat: /* 457 */
		break;
	case SYS_renameat: /* 458 */
		break;
	case SYS_mkfifoat: /* 459 */
		break;
	case SYS_mknodat: /* 460 */
		break;
	case SYS_mkdirat: /* 461 */
		break;
	case SYS_faccessat: /* 462 */
		break;
	case SYS_fchmodat: /* 463 */
		break;
	case SYS_fchownat: /* 464 */
		break;
	case SYS_fexecve: /* 465 */
		break;
	case SYS_fstatat: /* 466 */
		break;
	case SYS_utimensat: /* 467 */
		break;
	case SYS_openat: /* 468 */
		break;
	case SYS_readlinkat: /* 469 */
		break;
	case SYS_symlinkat: /* 470 */
		break;
	case SYS_unlinkat: /* 471 */
		break;
	case SYS_futimens: /* 472 */
		break;
	case SYS___quotactl: /* 473 */
		break;
	case SYS_posix_spawn: /* 474 */
		break;
	case SYS_recvmmsg: /* 475 */
		break;
	case SYS_sendmmsg: /* 476 */
		break;
	case SYS_clock_nanosleep: /* 477 */
		break;
	case SYS____lwp_park60: /* 478 */
		break;
	case SYS_posix_fallocate: /* 479 */
		break;
	case SYS_fdiscard: /* 480 */
		break;
	case SYS_wait6: /* 481 */
		break;
	case SYS_clock_getcpuclockid2: /* 482 */
		break;
	};

	SPRINTF(")");

	return buf;
}

char *
decode_retval(siginfo_t *si, char *buf, size_t len)
{
	char error_buf[128];

	ssize_t nargs;
	const char *name;
	const char *rettype;

	size_t i;
	int n;
	int e;
	bool recognized;
	bool is64bit_rettype;
	uint64_t u64;
	bool no_return;
	int rv0, rv1;

	assert(si);
	assert(buf);
	assert(len > 0);

	n = 0; /* Used internally by SPRINTF() */

	nargs = syscall_info[si->si_sysnum].nargs;
	name = syscall_info[si->si_sysnum].name;
	rettype = syscall_info[si->si_sysnum].rettype;

	recognized = nargs != -1;
	no_return = strcmp(rettype, "void") == 0;

	e = si->si_error;
	rv0 = si->si_retval[0];
	rv1 = si->si_retval[1];

	if (recognized) {
		if (no_return) {
			SPRINTF("no-return-value", name);
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

		SPRINTF(" ");

		if (!no_return) {
			/* Special cases first */
			if (strcmp(name, "pipe") == 0) {
				SPRINTF("%#" PRIx32 " %#" PRIx32, rv0, rv1);
			} else if (is64bit_rettype) {
				/* These convoluted casts are needed */
				u64 = ((uint64_t)(unsigned)rv1 << 32);
				u64 |= (uint64_t)(unsigned)rv0;
				SPRINTF("%#" PRIx64, u64);
			} else {
				SPRINTF("%#" PRIx32, rv0);
			}
		}

		if (e != 0) {
			SPRINTF(" Err#%d", e);
			if (err2string(e)) {
				SPRINTF(" %s", err2string(e));
			}
		}
	} else {
		SPRINTF("retval[0,1]= %#" PRIx32 " %#" PRIx32 " ", rv0, rv1);

		SPRINTF("error= %#" PRIx32, e);
	}

	return buf;
}

static char *
copyinstr(pid_t pid, void *offs, size_t maxlen)
{
	struct ptrace_io_desc pio;
	char *buf;
	char *s;
	size_t buflen;
	size_t i, n, m;
	size_t max;
	bool canonical;

	max = MIN(string_max_size, maxlen);
	buf = emalloc(max);

	buf[0] = '"';

	pio.piod_op = PIOD_READ_D;
	pio.piod_offs = offs;
	pio.piod_addr = buf;
	pio.piod_len = max;

	n = 0;

	canonical = false;

	for (;;) {
		errno = 0;
		ptrace(PT_IO, pid, &pio, 0);

		if (pio.piod_len == 0 || errno != 0) {
			/* EOF */
			break;
		}

		if (maxlen == SIZE_MAX) {
			for (i = 0; i < MIN(string_max_size, pio.piod_len);
			     i++) {
				if (((char *)pio.piod_addr)[i] == '\0') {
					canonical = true;
					break;
				}
			}

			n += i;

			if (canonical)
				break;
		} else {
			n += pio.piod_len;
		}

		if (max == pio.piod_len)
			break;

		pio.piod_offs = (void *) ((intptr_t)offs + n);
		pio.piod_len = max - n;
		pio.piod_addr = (void *)&buf[n];
	}

	if (!canonical && n == 0) {
		trace_snprintf(buf, buflen, "???");
		return buf;
	}

	buflen = max * (sizeof("\\0123") - 1); /* The longest character form */
	buflen += 2 /* 2x\" */ + 3 /* "..." */ + 1 /* '\0' */;
	s = emalloc(buflen);

	s[0] = '\"';
	m = strnvisx(s + 1, max * (sizeof("\\0123") - 1), buf, n,
	             VIS_CSTYLE | VIS_OCTAL | VIS_TAB | VIS_NL | VIS_DQ);

	trace_snprintf(s + m + 1, buflen - m - 1,
	    (canonical || maxlen != SIZE_MAX) ? "\"" : "\"...");

	free(buf);

	return s;
}

static void *
copyin(pid_t pid, void *offs, size_t len)
{
	struct ptrace_io_desc pio;
	void *buf;
	size_t n;

	buf = emalloc(len);

	pio.piod_op = PIOD_READ_D;
	pio.piod_offs = offs;
	pio.piod_addr = buf;
	pio.piod_len = len;

	n = 0;

	for (;;) {
		errno = 0;
		ptrace(PT_IO, pid, &pio, 0);

		if (pio.piod_len == 0 || errno != 0) {
			/* EOF */
			break;
		}

		n += pio.piod_len;

		if (len == pio.piod_len)
			break;

		pio.piod_offs = (void *)((intptr_t)offs + n);
		pio.piod_len = len - n;
		pio.piod_addr = (void *)((intptr_t)(void *)buf + n);
	}

	if (n != len) {
		free(buf);
		return NULL;
	}

	return buf;
}

static char *
get_strmode(mode_t mode)
{
	char *buf;

	buf = emalloc(12);

	strmode(mode, buf);

	return buf;
}

static char *
get_stat(pid_t pid, struct stat *sb)
{
	char *s, *mode;
	struct stat *st;

	st = (struct stat *)copyin(pid, sb, sizeof(*sb));

	if (st == NULL) {
		asprintf(&s, "%#p", sb);
		return s;
	}

	mode = get_strmode(st->st_mode);
	asprintf(&s, "{ dev=%" PRId64 ", mode=\"%s\", ino=%" PRId64 ", "
	    "nlink=%" PRId32 ", uid=%d, gid=%d, rdev=%" PRId64
	    ", atime=%jd.%09ld, mtime=%jd.%09ld, ctime=%jd.%09ld, "
	    "blksize=%" PRId32", blocks=%" PRId64 "}",
	    st->st_dev, mode, st->st_ino, st->st_nlink, st->st_uid,
	    st->st_gid, st->st_rdev, st->st_atim.tv_sec, st->st_atim.tv_nsec,
	    st->st_mtim.tv_sec, st->st_mtim.tv_nsec,
	    st->st_ctim.tv_sec, st->st_ctim.tv_nsec,
	    st->st_blksize, st->st_blocks);
	free(mode);

	return s;
}

static char *
get_statvfs(pid_t pid, struct statvfs *sb)
{
	char *s, *mode;
	struct statvfs *st;

	st = (struct statvfs *)copyin(pid, sb, sizeof(*sb));

	if (st == NULL) {
		asprintf(&s, "%#p", sb);
		return s;
	}

	asprintf(&s, "{ flag=%lu, bsize=%lu, frsize=%lu, iosize=%lu, "
	    "blocks=%" PRIu64 ", bfree=%" PRIu64 ", bavail=%" PRIu64
	    ", bresvd=%" PRIu64
	    ", files=%" PRIu64 ", ffree=%" PRIu64 ", favail=%" PRIu64
	    ", fresvd=%" PRIu64
	    ", syncreads=%" PRIu64 ", syncwrites=%" PRIu64
	    ", asyncreads=%" PRIu64 ", asyncwrites=%" PRIu64
	    ", fsidx={%#" PRIx32 ", %#" PRIx32 "}"
	    ", fsid=%lx, namemax=%lx, owner=%d, fstypename='%s'"
	    ", mntonname='%s', mntfromname='%s'",
	    st->f_flag, st->f_bsize, st->f_frsize, st->f_iosize,
	    st->f_blocks, st->f_bfree, st->f_bavail, st->f_bresvd,
	    st->f_files, st->f_ffree, st->f_favail, st->f_fresvd,
	    st->f_syncreads, st->f_syncwrites,
	    st->f_asyncreads, st->f_asyncwrites,
	    st->f_fsidx.__fsid_val[0], st->f_fsidx.__fsid_val[1],
	    st->f_fsid, st->f_namemax, st->f_owner,
	    st->f_fstypename, st->f_mntonname, st->f_mntfromname);

	free(st);

	return s;
}

static char *
get_sigset(pid_t pid, sigset_t *rset)
{
	char *buf;
	size_t i, n, len;
	StringList *sigs;
	sigset_t *set;
	char *s;

	if (rset == NULL) {
		asprintf(&s, "%#p", rset);
		return s;
	}

	set = (sigset_t *)copyin(pid, rset, sizeof(*rset));

	if (set == NULL) {
		asprintf(&s, "%#p", rset);
		return s;
	}

	sigs = sl_init();
	len = 0;

	for (i = 1; i < NSIG; i++) {
		if (sigismember(set,i)) {
			sl_add(sigs, (char *)signals[i].name + 3);
			len += 1 /* '|' */ + strlen(signals[i].name) - 3;
		}
	}

	++len; /* '\0' */

	buf = emalloc(len);

	n = 0;

	for (i = 0; i < sigs->sl_cur; i++) {
		SPRINTF("|%s", sigs->sl_str[i]);
	}

	buf[len - 1] = '\0';

	asprintf(&s, "0%s", buf);

	sl_free(sigs, 0);
	free(set);
	free(buf);

	return s;
}

static char *
get_timespec(pid_t pid, struct timespec *tp)
{
	struct timespec *t;
	char *s;

	if (tp == NULL) {
		asprintf(&s, "%#p", tp);
		return s;
	}

	t = (struct timespec *)copyin(pid, tp, sizeof(*tp));

	if (t == NULL) {
		asprintf(&s, "%#p", tp);
		return s;
	}

	asprintf(&s, "%jd.%09ld", t->tv_sec, t->tv_nsec);

	free(t);

	return s;
}

static const char *
err2string(int num)
{

	if (num < 0 || num > MAXERRNOS)
		return NULL;
	else
		return errnos[num].name;
}
