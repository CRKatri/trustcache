OBJS = trustcache.o
OBJS += append.o create.o info.o remove.o
OBJS += machoparse/cdhash.o cache_from_tree.o sort.o
OBJS += uuid/gen_uuid.o uuid/pack.o uuid/unpack.o uuid/parse.o uuid/unparse.o uuid/copy.o
OBJS += compat_strtonum.o

DESTDIR ?=
PREFIX  ?= ~/.local
BINDIR  ?= $(DESTDIR)$(PREFIX)/bin
MANDIR  ?= $(DESTDIR)$(PREFIX)/share/man

VERSION ?= 1.0
CFLAGS  += -DVERSION=$(VERSION)

ifeq ($(shell uname -s),Darwin)
	COMMONCRYPTO ?= 1
endif

ifeq ($(COMMONCRYPTO),1)
	CFLAGS += -DCOMMONCRYPTO
else
	LIBS   += -lcrypto
endif

all: trustcache

install: trustcache trustcache.1
	install -d $(BINDIR)
	install -m 755 trustcache $(BINDIR)/
	install -d $(MANDIR)/man1/
	install -m 644 trustcache.1 $(MANDIR)/man1/

uninstall:
	rm -i $(BINDIR)/trustcache $(MANDIR)/man1/trustcache.1

trustcache: $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) $(OBJS) -o $@ $(LIBS)

README.txt: trustcache.1
	mandoc $^ | col -bx > $@

clean:
	rm -f trustcache $(OBJS)

.PHONY: all clean install uninstall
