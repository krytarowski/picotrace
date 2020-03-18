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

#define __LEGACY_PT_LWPINFO
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
#include "xutils.h"

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
			n += xsnprintf(buf + n, len - n,		\
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

	SPRINTF("%s(", syscall_info[si->si_sysnum].name);

	switch (si->si_sysnum) {
	case 0: /* SYS_syscall */
		/* Shall not happen */
		break;
	case 1: /* SYS_exit */
		SPRINTF("%d", (int)si->si_args[0]);
		break;
	case 2: /* SYS_fork */
		break;
	case 3: /* SYS_read */
		s = copyinstr(pid, (void *)(intptr_t)si->si_args[1],
		    si->si_args[2]);
		SPRINTF("%d, %s, %zu", (int)si->si_args[0], s,
		    (size_t)si->si_args[2]);
		free(s);
		break;
	case 4: /* SYS_write */
		s = copyinstr(pid, (void *)(intptr_t)si->si_args[1],
		    si->si_args[2]);
		SPRINTF("%d, %s, %zu", (int)si->si_args[0], s,
		    (size_t)si->si_args[2]);
		free(s);
		break;
	case 5: /* SYS_open */
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
	case 6: /* SYS_close */
		SPRINTF("%d", (int)si->si_args[0]);
		break;
	case 7: /* SYS_compat_50_wait4 */
		break;
	case 8: /* SYS_compat_43_ocreat */
		break;
	case 9: /* SYS_link */
		s = copyinstr(pid, (void *)(intptr_t)si->si_args[0], SIZE_MAX);
		SPRINTF("%s, ", s);
		free(s);
		s = copyinstr(pid, (void *)(intptr_t)si->si_args[1], SIZE_MAX);
		SPRINTF("%s", s);
		free(s);
		break;
	case 10: /* SYS_unlink */
		s = copyinstr(pid, (void *)(intptr_t)si->si_args[0], SIZE_MAX);
		SPRINTF("%s", s);
		free(s);
		break;
	case 12: /* SYS_chdir */
		s = copyinstr(pid, (void *)(intptr_t)si->si_args[0], SIZE_MAX);
		SPRINTF("%s", s);
		free(s);
		break;
	case 13: /* SYS_fchdir */
		SPRINTF("%d", (int)si->si_args[0]);
		break;
	case 14: /* SYS_compat_50_mknod */
		break;
	case 15: /* SYS_chmod */
		s = copyinstr(pid, (void *)(intptr_t)si->si_args[0], SIZE_MAX);
		SPRINTF("%s, ", s);
		free(s);

		s = get_strmode(si->si_args[1]);
		SPRINTF(", \"%s\"", s);
		free(s);
		break;
	case 16: /* SYS_chown */
		s = copyinstr(pid, (void *)(intptr_t)si->si_args[0], SIZE_MAX);
		SPRINTF("%s, %d, %d", s, (int)si->si_args[1],
		    (int)si->si_args[2]);
		free(s);
		break;
	case 17: /* SYS_break */
		SPRINTF("%p", (void *)(intptr_t)si->si_args[0]);
		break;
	case 18: /* SYS_compat_20_getfsstat */
		break;
	case 19: /* SYS_compat_43_olseek */
		break;
	case 20: /* SYS_getpid */
		SPRINTF("%d", (int)si->si_args[0]);
		break;
	case 21: /* SYS_compat_40_mount */
		break;
	case 22: /* SYS_unmount */
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
	case 23: /* SYS_setuid */
		SPRINTF("%d", (int)si->si_args[0]);
		break;
	case 24: /* SYS_getuid */
		/* No arguments */
		break;
	case 25: /* SYS_geteuid */
		/* No arguments */
		break;
	case 26: /* SYS_ptrace */
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
		SPRINTF(", %d, %p, %d", (int)si->si_args[1],
		    (void *)(intptr_t)si->si_args[2], (int)si->si_args[3]);
		break;
	case 27: /* SYS_recvmsg */
		SPRINTF("%d, %p, 0", (int)si->si_args[0],
		    (void *)(intptr_t)si->si_args[1]);
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
	case 28: /* SYS_sendmsg */
		break;
	case 29: /* SYS_recvfrom */
		break;
	case 30: /* SYS_accept */
		break;
	case 31: /* SYS_getpeername */
		break;
	case 32: /* SYS_getsockname */
		break;
	case 33: /* SYS_access */
		s = copyinstr(pid, (void *)(intptr_t)si->si_args[0], SIZE_MAX);
		SPRINTF("%s", s);
		free(s);

		s = get_strmode(si->si_args[1]);
		SPRINTF(", \"%s\"", s);
		free(s);
		break;
	case 34: /* SYS_chflags */
		break;
	case 35: /* SYS_fchflags */
		break;
	case 36: /* SYS_sync */
		break;
	case 37: /* SYS_kill */
		break;
	case 38: /* SYS_compat_43_stat43 */
		break;
	case 39: /* SYS_getppid */
		break;
	case 40: /* SYS_compat_43_lstat43 */
		break;
	case 41: /* SYS_dup */
		SPRINTF("%d", (int)si->si_args[0]);
		break;
	case 42: /* SYS_pipe */
		break;
	case 43: /* SYS_getegid */
		break;
	case 44: /* SYS_profil */
		break;
	case 45: /* SYS_ktrace */
		break;
	case 46: /* SYS_compat_13_sigaction13 */
		break;
	case 47: /* SYS_getgid */
		break;
	case 48: /* SYS_compat_13_sigprocmask13 */
		break;
	case 49: /* SYS___getlogin */
		break;
	case 50: /* SYS___setlogin */
		break;
	case 51: /* SYS_acct */
		break;
	case 52: /* SYS_compat_13_sigpending13 */
		break;
	case 53: /* SYS_compat_13_sigaltstack13 */
		break;
	case 54: /* SYS_ioctl */
		SPRINTF("%d, %lu, ...", (int)si->si_args[0],
		    (unsigned long)si->si_args[1]);
		break;
	case 55: /* SYS_compat_12_oreboot */
		break;
	case 56: /* SYS_revoke */
		break;
	case 57: /* SYS_symlink */
		break;
	case 58: /* SYS_readlink */
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
			SPRINTF("%p, ", (void *)(intptr_t)si->si_args[1]);
		}

		SPRINTF("%zu", (size_t)si->si_args[2]);
		break;
	case 59: /* SYS_execve */
		break;
	case 60: /* SYS_umask */
		break;
	case 61: /* SYS_chroot */
		break;
	case 62: /* SYS_compat_43_fstat43 */
		break;
	case 63: /* SYS_compat_43_ogetkerninfo */
		break;
	case 64: /* SYS_compat_43_ogetpagesize */
		break;
	case 65: /* SYS_compat_12_msync */
		break;
	case 66: /* SYS_vfork */
		break;
	case 71: /* SYS_compat_43_ommap */
		break;
	case 72: /* SYS_vadvise */
		break;
	case 73: /* SYS_munmap */
		SPRINTF("%p, %zu", (void *)(intptr_t)si->si_args[0],
		    (size_t)si->si_args[1]);
		break;
	case 74: /* SYS_mprotect */
		SPRINTF("%p, %zu, ", (void *)(intptr_t)si->si_args[0],
		    (size_t)si->si_args[1]);
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
	case 75: /* SYS_madvise */
		SPRINTF("%p, %zu, ", (void *)(intptr_t)si->si_args[0],
		    (size_t)si->si_args[1]);
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
	case 78: /* SYS_mincore */
		break;
	case 79: /* SYS_getgroups */
		break;
	case 80: /* SYS_setgroups */
		break;
	case 81: /* SYS_getpgrp */
		break;
	case 82: /* SYS_setpgid */
		break;
	case 83: /* SYS_compat_50_setitimer */
		break;
	case 84: /* SYS_compat_43_owait */
		break;
	case 85: /* SYS_compat_12_oswapon */
		break;
	case 86: /* SYS_compat_50_getitimer */
		break;
	case 87: /* SYS_compat_43_ogethostname */
		break;
	case 88: /* SYS_compat_43_osethostname */
		break;
	case 89: /* SYS_compat_43_ogetdtablesize */
		break;
	case 90: /* SYS_dup2 */
		SPRINTF("%d, %d", (int)si->si_args[0], (int)si->si_args[1]);
		break;
	case 92: /* SYS_fcntl */
		break;
	case 93: /* SYS_compat_50_select */
		break;
	case 95: /* SYS_fsync */
		break;
	case 96: /* SYS_setpriority */
		break;
	case 97: /* SYS_compat_30_socket */
		break;
	case 98: /* SYS_connect */
		break;
	case 99: /* SYS_compat_43_oaccept */
		break;
	case 100: /* SYS_getpriority */
		break;
	case 101: /* SYS_compat_43_osend */
		break;
	case 102: /* SYS_compat_43_orecv */
		break;
	case 103: /* SYS_compat_13_sigreturn13 */
		break;
	case 104: /* SYS_bind */
		break;
	case 105: /* SYS_setsockopt */
		break;
	case 106: /* SYS_listen */
		break;
	case 108: /* SYS_compat_43_osigvec */
		break;
	case 109: /* SYS_compat_43_osigblock */
		break;
	case 110: /* SYS_compat_43_osigsetmask */
		break;
	case 111: /* SYS_compat_13_sigsuspend13 */
		break;
	case 112: /* SYS_compat_43_osigstack */
		break;
	case 113: /* SYS_compat_43_orecvmsg */
		break;
	case 114: /* SYS_compat_43_osendmsg */
		break;
	case 116: /* SYS_compat_50_gettimeofday */
		break;
	case 117: /* SYS_compat_50_getrusage */
		break;
	case 118: /* SYS_getsockopt */
		break;
	case 120: /* SYS_readv */
		break;
	case 121: /* SYS_writev */
		break;
	case 122: /* SYS_compat_50_settimeofday */
		break;
	case 123: /* SYS_fchown */
		break;
	case 124: /* SYS_fchmod */
		break;
	case 125: /* SYS_compat_43_orecvfrom */
		break;
	case 126: /* SYS_setreuid */
		break;
	case 127: /* SYS_setregid */
		break;
	case 128: /* SYS_rename */
		break;
	case 129: /* SYS_compat_43_otruncate */
		break;
	case 130: /* SYS_compat_43_oftruncate */
		break;
	case 131: /* SYS_flock */
		break;
	case 132: /* SYS_mkfifo */
		break;
	case 133: /* SYS_sendto */
		break;
	case 134: /* SYS_shutdown */
		break;
	case 135: /* SYS_socketpair */
		break;
	case 136: /* SYS_mkdir */
		break;
	case 137: /* SYS_rmdir */
		break;
	case 138: /* SYS_compat_50_utimes */
		break;
	case 140: /* SYS_compat_50_adjtime */
		break;
	case 141: /* SYS_compat_43_ogetpeername */
		break;
	case 142: /* SYS_compat_43_ogethostid */
		break;
	case 143: /* SYS_compat_43_osethostid */
		break;
	case 144: /* SYS_compat_43_ogetrlimit */
		break;
	case 145: /* SYS_compat_43_osetrlimit */
		break;
	case 146: /* SYS_compat_43_okillpg */
		break;
	case 147: /* SYS_setsid */
		break;
	case 148: /* SYS_compat_50_quotactl */
		break;
	case 149: /* SYS_compat_43_oquota */
		break;
	case 150: /* SYS_compat_43_ogetsockname */
		break;
	case 155: /* SYS_nfssvc */
		break;
	case 156: /* SYS_compat_43_ogetdirentries */
		break;
	case 157: /* SYS_compat_20_statfs */
		break;
	case 158: /* SYS_compat_20_fstatfs */
		break;
	case 161: /* SYS_compat_30_getfh */
		break;
	case 162: /* SYS_compat_09_ogetdomainname */
		break;
	case 163: /* SYS_compat_09_osetdomainname */
		break;
	case 164: /* SYS_compat_09_ouname */
		break;
	case 165: /* SYS_sysarch */
		break;
#if !defined(_LP64)
	case 169: /* SYS_compat_10_osemsys */
		break;
	case 170: /* SYS_compat_10_omsgsys */
		break;
	case 171: /* SYS_compat_10_oshmsys */
		break;
#endif
	case 173: /* SYS_pread */
		break;
	case 174: /* SYS_pwrite */
		break;
	case 175: /* SYS_compat_30_ntp_gettime */
		break;
	case 176: /* SYS_ntp_adjtime */
		break;
	case 181: /* SYS_setgid */
		break;
	case 182: /* SYS_setegid */
		break;
	case 183: /* SYS_seteuid */
		break;
	case 184: /* SYS_lfs_bmapv */
		break;
	case 185: /* SYS_lfs_markv */
		break;
	case 186: /* SYS_lfs_segclean */
		break;
	case 187: /* SYS_compat_50_lfs_segwait */
		break;
	case 188: /* SYS_compat_12_stat12 */
		break;
	case 189: /* SYS_compat_12_fstat12 */
		break;
	case 190: /* SYS_compat_12_lstat12 */
		break;
	case 191: /* SYS_pathconf */
		break;
	case 192: /* SYS_fpathconf */
		break;
	case 193: /* SYS_getsockopt2 */
		break;
	case 194: /* SYS_getrlimit */
		break;
	case 195: /* SYS_setrlimit */
		break;
	case 196: /* SYS_compat_12_getdirentries */
		break;
	case 197: /* SYS_mmap */
		SPRINTF("%p, %zu, ", (void *)(intptr_t)si->si_args[0],
		    (size_t)si->si_args[1]);
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
		SPRINTF(", %d, %zd", (int)si->si_args[4],
		    (ssize_t)si->si_args[6]);
		break;
	case 198: /* SYS___syscall */
		break;
	case 199: /* SYS_lseek */
		SPRINTF("%d, %zd, ", (int)si->si_args[0],
		    (ssize_t)si->si_args[1]);
#define check_flag(flag) case flag: SPRINTF(#flag); break
		switch (si->si_args[2]) {
		check_flag(SEEK_SET);
		check_flag(SEEK_CUR);
		check_flag(SEEK_END);
		}
#undef check_flag
		break;
	case 200: /* SYS_truncate */
		break;
	case 201: /* SYS_ftruncate */
		break;
	case 202: /* SYS___sysctl */
		if (si->si_args[1] > 0)
			v = copyin(pid, (void *)(intptr_t)si->si_args[0],
			    sizeof(int) * si->si_args[1]);
		else
			v = NULL;
		if (v == NULL) {
			SPRINTF("%p", (void *)(intptr_t)si->si_args[0]);
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

		SPRINTF(", %u, %p, %p, %p, %zu", (unsigned)si->si_args[1],
		    (void *)(intptr_t)si->si_args[2],
		    (void *)(intptr_t)si->si_args[3],
		    (void *)(intptr_t)si->si_args[4],
		    (size_t)si->si_args[5]);
		break;
	case 203: /* SYS_mlock */
		break;
	case 204: /* SYS_munlock */
		break;
	case 205: /* SYS_undelete */
		break;
	case 206: /* SYS_compat_50_futimes */
		break;
	case 207: /* SYS_getpgid */
		break;
	case 208: /* SYS_reboot */
		break;
	case 209: /* SYS_poll */
		break;
	case 210: /* SYS_afssys */
		break;
	case 220: /* SYS_compat_14___semctl */
		break;
	case 221: /* SYS_semget */
		break;
	case 222: /* SYS_semop */
		break;
	case 223: /* SYS_semconfig */
		break;
	case 224: /* SYS_compat_14_msgctl */
		break;
	case 225: /* SYS_msgget */
		break;
	case 226: /* SYS_msgsnd */
		break;
	case 227: /* SYS_msgrcv */
		break;
	case 228: /* SYS_shmat */
		break;
	case 229: /* SYS_compat_14_shmctl */
		break;
	case 230: /* SYS_shmdt */
		break;
	case 231: /* SYS_shmget */
		break;
	case 232: /* SYS_compat_50_clock_gettime */
		break;
	case 233: /* SYS_compat_50_clock_settime */
		break;
	case 234: /* SYS_compat_50_clock_getres */
		break;
	case 235: /* SYS_timer_create */
		break;
	case 236: /* SYS_timer_delete */
		break;
	case 237: /* SYS_compat_50_timer_settime */
		break;
	case 238: /* SYS_compat_50_timer_gettime */
		break;
	case 239: /* SYS_timer_getoverrun */
		break;
	case 240: /* SYS_compat_50_nanosleep */
		break;
	case 241: /* SYS_fdatasync */
		break;
	case 242: /* SYS_mlockall */
		break;
	case 243: /* SYS_munlockall */
		break;
	case 244: /* SYS_compat_50___sigtimedwait */
		break;
	case 245: /* SYS_sigqueueinfo */
		break;
	case 246: /* SYS_modctl */
		break;
	case 247: /* SYS__ksem_init */
		break;
	case 248: /* SYS__ksem_open */
		break;
	case 249: /* SYS__ksem_unlink */
		break;
	case 250: /* SYS__ksem_close */
		break;
	case 251: /* SYS__ksem_post */
		break;
	case 252: /* SYS__ksem_wait */
		break;
	case 253: /* SYS__ksem_trywait */
		break;
	case 254: /* SYS__ksem_getvalue */
		break;
	case 255: /* SYS__ksem_destroy */
		break;
	case 256: /* SYS__ksem_timedwait */
		break;
	case 257: /* SYS_mq_open */
		break;
	case 258: /* SYS_mq_close */
		break;
	case 259: /* SYS_mq_unlink */
		break;
	case 260: /* SYS_mq_getattr */
		break;
	case 261: /* SYS_mq_setattr */
		break;
	case 262: /* SYS_mq_notify */
		break;
	case 263: /* SYS_mq_send */
		break;
	case 264: /* SYS_mq_receive */
		break;
	case 265: /* SYS_compat_50_mq_timedsend */
		break;
	case 266: /* SYS_compat_50_mq_timedreceive */
		break;
	case 270: /* SYS___posix_rename */
		break;
	case 271: /* SYS_swapctl */
		break;
	case 272: /* SYS_compat_30_getdents */
		break;
	case 273: /* SYS_minherit */
		break;
	case 274: /* SYS_lchmod */
		break;
	case 275: /* SYS_lchown */
		break;
	case 276: /* SYS_compat_50_lutimes */
		break;
	case 277: /* SYS___msync13 */
		break;
	case 278: /* SYS_compat_30___stat13 */
		break;
	case 279: /* SYS_compat_30___fstat13 */
		break;
	case 280: /* SYS_compat_30___lstat13 */
		break;
	case 281: /* SYS___sigaltstack14 */
		break;
	case 282: /* SYS___vfork14 */
		break;
	case 283: /* SYS___posix_chown */
		break;
	case 284: /* SYS___posix_fchown */
		break;
	case 285: /* SYS___posix_lchown */
		break;
	case 286: /* SYS_getsid */
		break;
	case 287: /* SYS___clone */
		break;
	case 288: /* SYS_fktrace */
		break;
	case 289: /* SYS_preadv */
		break;
	case 290: /* SYS_pwritev */
		break;
	case 291: /* SYS_compat_16___sigaction14 */
		break;
	case 292: /* SYS___sigpending14 */
		break;
	case 293: /* SYS___sigprocmask14 */
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
	case 294: /* SYS___sigsuspend14 */
		break;
	case 295: /* SYS_compat_16___sigreturn14 */
		break;
	case 296: /* SYS___getcwd */
		break;
	case 297: /* SYS_fchroot */
		break;
	case 298: /* SYS_compat_30_fhopen */
		break;
	case 299: /* SYS_compat_30_fhstat */
		break;
	case 300: /* SYS_compat_20_fhstatfs */
		break;
	case 301: /* SYS_compat_50_____semctl13 */
		break;
	case 302: /* SYS_compat_50___msgctl13 */
		break;
	case 303: /* SYS_compat_50___shmctl13 */
		break;
	case 304: /* SYS_lchflags */
		break;
	case 305: /* SYS_issetugid */
		break;
	case 306: /* SYS_utrace */
		break;
	case 307: /* SYS_getcontext */
		break;
	case 308: /* SYS_setcontext */
		break;
	case 309: /* SYS__lwp_create */
		break;
	case 310: /* SYS__lwp_exit */
		break;
	case 311: /* SYS__lwp_self */
		break;
	case 312: /* SYS__lwp_wait */
		break;
	case 313: /* SYS__lwp_suspend */
		break;
	case 314: /* SYS__lwp_continue */
		break;
	case 315: /* SYS__lwp_wakeup */
		break;
	case 316: /* SYS__lwp_getprivate */
		break;
	case 317: /* SYS__lwp_setprivate */
		SPRINTF("%p", (void *)(intptr_t)si->si_args[0]);
		break;
	case 318: /* SYS__lwp_kill */
		break;
	case 319: /* SYS__lwp_detach */
		break;
	case 320: /* SYS_compat_50__lwp_park */
		break;
	case 321: /* SYS__lwp_unpark */
		break;
	case 322: /* SYS__lwp_unpark_all */
		break;
	case 323: /* SYS__lwp_setname */
		break;
	case 324: /* SYS__lwp_getname */
		break;
	case 325: /* SYS__lwp_ctl */
		break;
	case 330: /* SYS_compat_60_sa_register */
		break;
	case 331: /* SYS_compat_60_sa_stacks */
		break;
	case 332: /* SYS_compat_60_sa_enable */
		break;
	case 333: /* SYS_compat_60_sa_setconcurrency */
		break;
	case 334: /* SYS_compat_60_sa_yield */
		break;
	case 335: /* SYS_compat_60_sa_preempt */
		break;
	case 340: /* SYS___sigaction_sigtramp */
		break;
	case 343: /* SYS_rasctl */
		break;
	case 344: /* SYS_kqueue */
		break;
	case 345: /* SYS_compat_50_kevent */
		break;
	case 346: /* SYS__sched_setparam */
		break;
	case 347: /* SYS__sched_getparam */
		break;
	case 348: /* SYS__sched_setaffinity */
		break;
	case 349: /* SYS__sched_getaffinity */
		break;
	case 350: /* SYS_sched_yield */
		break;
	case 351: /* SYS__sched_protect */
		break;
	case 354: /* SYS_fsync_range */
		break;
	case 355: /* SYS_uuidgen */
		break;
	case 356: /* SYS_getvfsstat */
		SPRINTF("%p, %zu, ", (void *)(intptr_t)si->si_args[0],
		    (size_t)si->si_args[1]);

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
	case 357: /* SYS_statvfs1 */
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
	case 358: /* SYS_fstatvfs1 */
		SPRINTF("%d, ", (int)si->si_args[0]);

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
	case 359: /* SYS_compat_30_fhstatvfs1 */
		break;
	case 360: /* SYS_extattrctl */
		break;
	case 361: /* SYS_extattr_set_file */
		break;
	case 362: /* SYS_extattr_get_file */
		break;
	case 363: /* SYS_extattr_delete_file */
		break;
	case 364: /* SYS_extattr_set_fd */
		break;
	case 365: /* SYS_extattr_get_fd */
		break;
	case 366: /* SYS_extattr_delete_fd */
		break;
	case 367: /* SYS_extattr_set_link */
		break;
	case 368: /* SYS_extattr_get_link */
		break;
	case 369: /* SYS_extattr_delete_link */
		break;
	case 370: /* SYS_extattr_list_fd */
		break;
	case 371: /* SYS_extattr_list_file */
		break;
	case 372: /* SYS_extattr_list_link */
		break;
	case 373: /* SYS_compat_50_pselect */
		break;
	case 374: /* SYS_compat_50_pollts */
		break;
	case 375: /* SYS_setxattr */
		break;
	case 376: /* SYS_lsetxattr */
		break;
	case 377: /* SYS_fsetxattr */
		break;
	case 378: /* SYS_getxattr */
		break;
	case 379: /* SYS_lgetxattr */
		break;
	case 380: /* SYS_fgetxattr */
		break;
	case 381: /* SYS_listxattr */
		break;
	case 382: /* SYS_llistxattr */
		break;
	case 383: /* SYS_flistxattr */
		break;
	case 384: /* SYS_removexattr */
		break;
	case 385: /* SYS_lremovexattr */
		break;
	case 386: /* SYS_fremovexattr */
		break;
	case 387: /* SYS_compat_50___stat30 */
		break;
	case 388: /* SYS_compat_50___fstat30 */
		break;
	case 389: /* SYS_compat_50___lstat30 */
		break;
	case 390: /* SYS___getdents30 */
		SPRINTF("%d, %p, %zu", (int)si->si_args[0],
		    (void *)(intptr_t)si->si_args[1], (size_t)si->si_args[2]);
		break;
	case 392: /* SYS_compat_30___fhstat30 */
		break;
	case 393: /* SYS_compat_50___ntp_gettime30 */
		break;
	case 394: /* SYS___socket30 */
		break;
	case 395: /* SYS___getfh30 */
		break;
	case 396: /* SYS___fhopen40 */
		break;
	case 397: /* SYS___fhstatvfs140 */
		break;
	case 398: /* SYS_compat_50___fhstat40 */
		break;
	case 399: /* SYS_aio_cancel */
		break;
	case 400: /* SYS_aio_error */
		break;
	case 401: /* SYS_aio_fsync */
		break;
	case 402: /* SYS_aio_read */
		break;
	case 403: /* SYS_aio_return */
		break;
	case 404: /* SYS_compat_50_aio_suspend */
		break;
	case 405: /* SYS_aio_write */
		break;
	case 406: /* SYS_lio_listio */
		break;
	case 410: /* SYS___mount50 */
		break;
	case 411: /* SYS_mremap */
		break;
	case 412: /* SYS_pset_create */
		break;
	case 413: /* SYS_pset_destroy */
		break;
	case 414: /* SYS_pset_assign */
		break;
	case 415: /* SYS__pset_bind */
		break;
	case 416: /* SYS___posix_fadvise50 */
		break;
	case 417: /* SYS___select50 */
		break;
	case 418: /* SYS___gettimeofday50 */
		break;
	case 419: /* SYS___settimeofday50 */
		break;
	case 420: /* SYS___utimes50 */
		break;
	case 421: /* SYS___adjtime50 */
		break;
	case 422: /* SYS___lfs_segwait50 */
		break;
	case 423: /* SYS___futimes50 */
		break;
	case 424: /* SYS___lutimes50 */
		break;
	case 425: /* SYS___setitimer50 */
		break;
	case 426: /* SYS___getitimer50 */
		break;
	case 427: /* SYS___clock_gettime50 */
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
	case 428: /* SYS___clock_settime50 */
		break;
	case 429: /* SYS___clock_getres50 */
		break;
	case 430: /* SYS___nanosleep50 */
		break;
	case 431: /* SYS_____sigtimedwait50 */
		break;
	case 432: /* SYS___mq_timedsend50 */
		break;
	case 433: /* SYS___mq_timedreceive50 */
		break;
	case 434: /* SYS_compat_60__lwp_park */
		break;
	case 435: /* SYS___kevent50 */
		break;
	case 436: /* SYS___pselect50 */
		break;
	case 437: /* SYS___pollts50 */
		break;
	case 438: /* SYS___aio_suspend50 */
		break;
	case 439: /* SYS___stat50 */
		s = copyinstr(pid, (void *)(intptr_t)si->si_args[0], SIZE_MAX);
		SPRINTF("%s, ", s);
		free(s);

		s = get_stat(pid, (void *)(intptr_t)si->si_args[1]);
		SPRINTF("%s", s);
		free(s);
		break;
	case 440: /* SYS___fstat50 */
		SPRINTF("%d, ", (int)si->si_args[0]);

		s = get_stat(pid, (void *)(intptr_t)si->si_args[1]);
		SPRINTF("%s", s);
		free(s);
		break;
	case 441: /* SYS___lstat50 */
		s = copyinstr(pid, (void *)(intptr_t)si->si_args[0], SIZE_MAX);
		SPRINTF("%s, ", s);
		free(s);

		s = get_stat(pid, (void *)(intptr_t)si->si_args[1]);
		SPRINTF("%s", s);
		free(s);
		break;
	case 442: /* SYS_____semctl50 */
		break;
	case 443: /* SYS___shmctl50 */
		break;
	case 444: /* SYS___msgctl50 */
		break;
	case 445: /* SYS___getrusage50 */
		break;
	case 446: /* SYS___timer_settime50 */
		break;
	case 447: /* SYS___timer_gettime50 */
		break;
	case 448: /* SYS___ntp_gettime50 */
		break;
	case 449: /* SYS___wait450 */
		break;
	case 450: /* SYS___mknod50 */
		break;
	case 451: /* SYS___fhstat50 */
		break;
	case 453: /* SYS_pipe2 */
		break;
	case 454: /* SYS_dup3 */
		break;
	case 455: /* SYS_kqueue1 */
		break;
	case 456: /* SYS_paccept */
		break;
	case 457: /* SYS_linkat */
		break;
	case 458: /* SYS_renameat */
		break;
	case 459: /* SYS_mkfifoat */
		break;
	case 460: /* SYS_mknodat */
		break;
	case 461: /* SYS_mkdirat */
		break;
	case 462: /* SYS_faccessat */
		break;
	case 463: /* SYS_fchmodat */
		break;
	case 464: /* SYS_fchownat */
		break;
	case 465: /* SYS_fexecve */
		break;
	case 466: /* SYS_fstatat */
		break;
	case 467: /* SYS_utimensat */
		break;
	case 468: /* SYS_openat */
		break;
	case 469: /* SYS_readlinkat */
		break;
	case 470: /* SYS_symlinkat */
		break;
	case 471: /* SYS_unlinkat */
		break;
	case 472: /* SYS_futimens */
		break;
	case 473: /* SYS___quotactl */
		break;
	case 474: /* SYS_posix_spawn */
		break;
	case 475: /* SYS_recvmmsg */
		break;
	case 476: /* SYS_sendmmsg */
		break;
	case 477: /* SYS_clock_nanosleep */
		break;
	case 478: /* SYS____lwp_park60 */
		break;
	case 479: /* SYS_posix_fallocate */
		break;
	case 480: /* SYS_fdiscard */
		break;
	case 481: /* SYS_wait6 */
		break;
	case 482: /* SYS_clock_getcpuclockid2 */
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
			SPRINTF("no-return-value");
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
		xsnprintf(buf, buflen, "???");
		return buf;
	}

	buflen = max * (sizeof("\\0123") - 1); /* The longest character form */
	buflen += 2 /* 2x\" */ + 3 /* "..." */ + 1 /* '\0' */;
	s = emalloc(buflen);

	s[0] = '\"';
	m = strnvisx(s + 1, max * (sizeof("\\0123") - 1), buf, n,
	             VIS_CSTYLE | VIS_OCTAL | VIS_TAB | VIS_NL | VIS_DQ);

	xsnprintf(s + m + 1, buflen - m - 1,
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
		asprintf(&s, "%p", sb);
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
		asprintf(&s, "%p", sb);
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
		asprintf(&s, "%p", rset);
		return s;
	}

	set = (sigset_t *)copyin(pid, rset, sizeof(*rset));

	if (set == NULL) {
		asprintf(&s, "%p", rset);
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
		asprintf(&s, "%p", tp);
		return s;
	}

	t = (struct timespec *)copyin(pid, tp, sizeof(*tp));

	if (t == NULL) {
		asprintf(&s, "%p", tp);
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
