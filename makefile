CC=gcc
RM=rm -f
USE_OPENSSL ?= 0
USE_VNCSNAPSHOT ?= 0
CFLAGS=-g -Wall -pthread
LDFLAGS=-g
LDLIBS=-lcap -lreadline -ljpeg -pthread

ifeq ($(USE_OPENSSL),1)
	LDLIBS += -lcrypto
endif

ifeq ($(USE_VNCSNAPSHOT),1)
	CFLAGS += -DUSE_VNCSNAPSHOT
endif

SRCS=src/vncsnatch.c src/file_utils.c src/misc_utils.c src/network_utils.c src/vncgrab.c src/des.c
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
				$(RM) -r tests/bin

distclean: clean
				$(RM) *~ .depend

test:
				./tests/run_tests.sh

cleanroom:
				$(MAKE) USE_VNCSNAPSHOT=0 USE_OPENSSL=$(USE_OPENSSL)

test-cleanroom:
				$(MAKE) USE_VNCSNAPSHOT=0 USE_OPENSSL=$(USE_OPENSSL) test

-include .depend
