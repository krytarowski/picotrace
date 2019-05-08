#	$NetBSD$

PROG=	picotrace

# misc.c and misc.h are taken from src/usr.bin/ktruss
# picotrace.h is pregenerated with picotrace.awk

SRCS+=	children.c picotrace misc.c

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
