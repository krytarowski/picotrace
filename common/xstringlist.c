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


#include <sys/cdefs.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stringlist.h>

#include <util.h>

#include "xstringlist.h"
#include "xutils.h"

char *
sl_concat(StringList *sl)
{
	char *buf;
	size_t i, len, offset;
	size_t *sizes = NULL;

	/* Assume that sl_cur is the last element. */
	ereallocarr(&sizes, sl->sl_cur + 1, sizeof(*sizes));

	len = 0;
	for (i = 0; i < sl->sl_cur; i++) {
		sizes[i] = strlen(sl->sl_str[i]);
		len += sizes[i];
	}

	len += 1; /* Trailing '\0' */

	buf = emalloc(len);

	offset = 0;
	for (i = 0; i < sl->sl_cur; i++) {
		memcpy(buf + offset, sl->sl_str[i], sizes[i]);
		offset += sizes[i];
	}
	buf[offset] = '\0';

	free(sizes);

	return buf;
}

StringList *
sl_initf(const char * restrict format, ...)
{
	StringList *sl;
	va_list ap;

	va_start(ap, format);
	sl = sl_vinitf(format, ap);
	va_end(ap);

	return sl;
}

StringList *
sl_vinitf( const char * restrict format, va_list ap)
{
	StringList *sl;
	int rv;

	sl = sl_init();

	if (sl == NULL)
		return NULL;

	rv = sl_vaddf(sl, format, ap);

	if (rv == -1) {
		sl_free(sl, 0);
		return NULL;
	}

	return sl;
}

int
sl_addf(StringList *sl, const char * restrict format, ...)
{
	int rv;
	va_list ap;

	va_start(ap, format);
	rv = sl_vaddf(sl, format, ap);
	va_end(ap);

	return rv;
}

int
sl_vaddf(StringList *sl, const char * restrict format, va_list ap)
{
	char *buf;
	int rv;

	rv = vasprintf(&buf, format, ap);
	if (rv >= 0)
		rv = sl_add(sl, buf);

	return rv;
}

size_t
sl_fwrite(StringList * restrict sl, FILE * restrict fp)
{
	int rv;
	char *buf;

	buf = sl_concat(sl);
	if (buf == NULL)
		return (size_t)-1;

	rv = fprintf(fp, "%s", buf);

	free(buf);

	return (size_t)rv;
}

size_t
sl_fdump(StringList * restrict sl, FILE * restrict fp)
{
	size_t sz;

	sz = sl_fwrite(sl, fp);
	if (sz == SIZE_MAX)
		return sz;

	sl_free(sl, 1);

	return sz;
}
