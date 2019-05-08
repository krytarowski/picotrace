#!/bin/awk -f
#
#	$NetBSD$
#
# Copyright (c) 2019 The NetBSD Foundation, Inc.
# All rights reserved.
#
# This code is derived from software contributed to The NetBSD Foundation
# by Kamil Rytarowski.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
# ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
# TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
# PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
# BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#

BEGIN {
	num = 0
}

NR == 1 {
	split($0, arr, "$")
	commit_id=arr[2]
}

/syscall:/ {
	n = split($0, arr, "\"")

	if (arr[2] == "syscall" || arr[2] == "__syscall") {
		syscall_nargs[arr[2]] = 8
	} else {
		syscall_nargs[arr[2]] = (n-3)/2 - 1
	}

	syscall_return_type[arr[2]] = arr[4]
	syscall[num++] = arr[2]
}

/#define[[:space:]]SYS_[a-z_]/ {
	syscall_no[substr($2, 5)] = $3
	assigned_sysnum[$3] = substr($2, 5)
	max_syscall_num = $3
}

END {

	print "/*	$NetBSD$	*/"
	print ""
	print "/*-"
	print " * Copyright (c) 2019 The NetBSD Foundation, Inc."
	print " * All rights reserved."
	print " *"
	print " * This code is derived from software contributed to The NetBSD Foundation"
	print " * by Kamil Rytarowski."
	print " *"
	print " * Redistribution and use in source and binary forms, with or without"
	print " * modification, are permitted provided that the following conditions"
	print " * are met:"
	print " * 1. Redistributions of source code must retain the above copyright"
	print " *    notice, this list of conditions and the following disclaimer."
	print " * 2. Redistributions in binary form must reproduce the above copyright"
	print " *    notice, this list of conditions and the following disclaimer in the"
	print " *    documentation and/or other materials provided with the distribution."
	print " *"
	print " * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS"
	print " * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED"
	print " * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR"
	print " * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS"
	print " * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR"
	print " * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF"
	print " * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS"
	print " * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN"
	print " * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)"
	print " * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE"
	print " * POSSIBILITY OF SUCH DAMAGE."
	print " */"
	print ""
	print "/*"
	print " * THIS FILE HAS BEEN GENERATED"
	print " * ! ! DO NOT EDIT MANUALLY ! !"
	print " *"
	print " * Created from: " commit_id
	print " */"
	print ""
	print "#include <stddef.h>"
	print ""
	print "static const size_t max_syscall_number = " max_syscall_num ";"
	print ""
	print "static const struct {"
	print "\tssize_t nargs;"
	print "\tconst char *name;"
	print "\tconst char *rettype;"
	print "} syscall_info[] = {"

	for (i = 0; i <= max_syscall_num; i++) {
		if (i in assigned_sysnum) {
			print "\t/* " i " */  { " syscall_nargs[assigned_sysnum[i]] ", \"" assigned_sysnum[i] "\", \"" syscall_return_type[assigned_sysnum[i]] "\" },"
		} else {
			print "\t/* " i " */  { -1, NULL, NULL },"
		}
	}

	print "};"
}
