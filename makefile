# makefile for vblade on cygwin/windows

# see README for others
#PLATFORM=linux
PLATFORM=winpcap_if

prefix = /usr
sbindir = ${prefix}/sbin
sharedir = ${prefix}/share
mandir = ${sharedir}/man

O=aoe.o bpf.o ${PLATFORM}.o ata.o
CFLAGS += -Og -g3 -flto -Wall -DWPCAP -DHAVE_U_INT32_T -DHAVE_U_INT8_T -DWIN32 -D_WIN32 -DBPF_MAJOR_VERSION=7 \
          -DHAVE_REMOTE  -Ilibpcap/Include
CC = gcc
LINKFLAGS = -flto -Wl,-Map=vblade.map -lwpcap -lPacket 
ifeq ($(firstword $(subst -, ,$(shell $(CC) -dumpmachine))),x86_64)
LINKFLAGS += -Llibpcap/Lib/x64
else
LINKFLAGS += -Llibpcap/Lib
endif

vblade: $O
	${CC} -o vblade $O  ${LINKFLAGS}

aoe.o : aoe.c config.h dat.h fns.h makefile
	${CC} ${CFLAGS} -c $<

${PLATFORM}.o : ${PLATFORM}.c config.h dat.h fns.h makefile
	${CC} ${CFLAGS} -c $<

ata.o : ata.c config.h dat.h fns.h makefile
	${CC} ${CFLAGS} -c $<

bpf.o : bpf.c
	${CC} ${CFLAGS} -c $<

config.h : config/config.h.in makefile
	@if ${CC} ${CFLAGS} config/u64.c > /dev/null 2>&1; then \
	  sh -xc "cp config/config.h.in config.h"; \
	else \
	  sh -xc "sed 's!^//u64 !!' config/config.h.in > config.h"; \
	fi

clean :
	rm -f $O vblade

install : vblade vbladed
	install vblade ${sbindir}/
	install vbladed ${sbindir}/
	install vblade.8 ${mandir}/man8/
