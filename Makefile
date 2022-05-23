OBJS = tc.o
OBJS += append.o create.o info.o remove.o
OBJS += machoparse/cdhash.o cache_from_tree.o sort.o
OBJS += uuid/gen_uuid.o uuid/pack.o uuid/unpack.o uuid/parse.o uuid/unparse.o uuid/copy.o
OBJS += compat_strtonum.o

PREFIX ?= ~/.local
BINDIR ?= $(PREFIX)/bin
MANDIR ?= $(PREFIX)/share/man

ifeq ($(shell uname -s),Darwin)
	COMMONCRYPTO ?= 1
endif

ifeq ($(COMMONCRYPTO),1)
	CFLAGS += -DCOMMONCRYPTO
else
	LIBS   += -lcrypto
endif

all: tc

install: tc tc.1
	install -d $(BINDIR)
	install -m 755 tc $(BINDIR)/
	install -d $(MANDIR)/man1/
	install -m 644 tc.1 $(MANDIR)/man1/

uninstall:
	rm -i $(BINDIR)/tc $(MANDIR)/man1/tc.1

tc: $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) $(OBJS) -o $@ $(LIBS)

README.txt: tc.1
	mandoc $^ | col -bx > $@

clean:
	rm -f tc $(OBJS)

.PHONY: all clean install uninstall
