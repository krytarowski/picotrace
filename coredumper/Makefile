#	$NetBSD$

PROG=	coredumper

SRCS+=	children.c coredumper.c

# Common files, shared between tracers.
.PATH:	..
SRCS+=	trace.c trace_utils.c

CPPFLAGS+=	-I..

DPADD+=	${LIBUTIL}
LDADD+=	-lutil

COPTS+=	-pthread
DPADD+=	${LIBPTHREAD}
LDADD+=	-lpthread

#COPTS+=	-g -O0

.include <bsd.prog.mk>
