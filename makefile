CC=gcc
RM=rm -f
USE_OPENSSL ?= 0
CFLAGS=-g -Wall -pthread -DUSE_VNCSNAPSHOT
LDFLAGS=-g
LDLIBS=-lcap -lreadline -ljpeg -pthread

ifeq ($(USE_OPENSSL),1)
	LDLIBS += -lcrypto
endif

SRCS=vncsnatch.c file_utils.c misc_utils.c network_utils.c vncgrab.c des.c
OBJS=$(subst .c,.o,$(SRCS))

all: vncsnatch

vncsnatch: $(OBJS)
				$(CC) $(LDFLAGS) -o vncsnatch $(OBJS) $(LDLIBS)

depend: .depend

.depend: $(SRCS)
				$(RM) ./.depend
				$(CC) $(CFLAGS) -MM $^>>./.depend;

clean:
				$(RM) $(OBJS)

distclean: clean
				$(RM) *~ .depend

test:
				./tests/run_tests.sh

cleanroom:
				$(MAKE) CFLAGS="-g -Wall -pthread" LDLIBS="-lcap -lreadline -ljpeg -pthread" USE_OPENSSL=$(USE_OPENSSL)

-include .depend
