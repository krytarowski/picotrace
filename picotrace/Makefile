#	$NetBSD$

PROG=	picotrace

SRCS+=	picotrace.c

# Common files, shared between tracers.
.PATH:	../common
SRCS+=	children.c misc.c trace.c trace_utils.c

CPPFLAGS+=	-I../common

DPADD+=	${LIBUTIL}
LDADD+=	-lutil

COPTS+=	-pthread
DPADD+=	${LIBPTHREAD}
LDADD+=	-lpthread

#COPTS+=	-g -O0

.include <bsd.prog.mk>
