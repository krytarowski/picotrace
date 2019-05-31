#	$NetBSD$

PROG=	truss

SRCS+=	truss.c count.c events.c decoder.c

# Common files, shared between tracers.
.PATH:	../common
SRCS+=	children.c misc.c trace.c xutils.c

CPPFLAGS+=	-I../common

DPADD+=	${LIBUTIL}
LDADD+=	-lutil

COPTS+=	-pthread
DPADD+=	${LIBPTHREAD}
LDADD+=	-lpthread

#COPTS+=	-g -O0

#COPTS+=	-fsanitize=address
#LDADD+=	-fsanitize=address

#COPTS+=	-fsanitize=undefined
#LDADD+=	-fsanitize=undefined

.include <bsd.prog.mk>
