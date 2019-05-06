#	$NetBSD$

PROG=	picotrace

# misc.c and misc.h are taken from src/usr.bin/ktruss
# picotrace.h is pregenerated with picotrace.awk

SRCS+=	children.c picotrace trace.c trace_utils.c misc.c

DPADD+=	${LIBUTIL}
LDADD+=	-lutil

COPTS+=	-pthread
DPADD+=	${LIBPTHREAD}
LDADD+=	-lpthread

#COPTS+=	-g -O0

.include <bsd.prog.mk>
