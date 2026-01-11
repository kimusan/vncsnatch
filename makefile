CC=gcc
RM=rm -f
CFLAGS=-g -Wall -pthread
LDFLAGS=-g
LDLIBS=-lcap -lreadline -pthread

SRCS=vncsnatch.c file_utils.c misc_utils.c network_utils.c 
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

-include .depend
