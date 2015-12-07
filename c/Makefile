PROG    = pr-context pr-version sync-addr async-addr responsedict \
	  sync-general async-general
INCLUDE = -I. -I/usr/local/include
CFLAGS  = -g -std=c99 -Wall -Wextra $(INCLUDE)
LDFLAGS = -L/usr/local/lib -Wl,-rpath -Wl,/usr/local/lib
LIBS    = -lgetdns_ext_event -lgetdns -levent_core -lunbound -lidn \
		-lldns -lssl  -lcrypto
CC      = gcc

all:		$(PROG)

pr-context:	pr-context.o
		$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

pr-version:	pr-version.o util.o
		$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

responsedict:	responsedict.o util.o
		$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

sync-addr:	sync-addr.o
		$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

async-addr:	async-addr.o
		$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

sync-general:	sync-general.o util.o
		$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

async-general:	async-general.o util.o
		$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

pr-version.o:	util.h

.PHONY:		clean count
clean:
		rm -rf *.o $(PROG)
count:
		wc -c *.[ch]
