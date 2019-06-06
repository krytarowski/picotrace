#	$NetBSD$

PROG=	singlestepper

SRCS+=	singlestepper.c

# Common files, shared between tracers.
.PATH:	../common
SRCS+=	children.c misc.c trace.c xutils.c xstringlist.c

CPPFLAGS+=	-D_KERNTYPES
CPPFLAGS+=	-I../common

DPADD+=	${LIBUTIL}
LDADD+=	-lutil

COPTS+=	-pthread
DPADD+=	${LIBPTHREAD}
LDADD+=	-lpthread

#COPTS+=	-g -O0

#COPTS+=        -fsanitize=address
#LDADD+=        -fsanitize=address

#COPTS+=        -fsanitize=undefined
#LDADD+=        -fsanitize=undefined

.include <bsd.prog.mk>
