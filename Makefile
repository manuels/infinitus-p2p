CC=gcc
CFLAGS=

OPENSSL_CFLAGS=$(shell pkg-config --cflags openssl)
OPENSSL_LDFLAGS=$(shell pkg-config --libs openssl)

GLIB_CFLAGS=$(shell pkg-config --cflags dbus-glib-1 glib-2.0 gio-2.0)
GLIB_LDFLAGS=$(shell pkg-config --libs dbus-glib-1 glib-2.0 gio-2.0)

NICE_CFLAGS=$(shell pkg-config --cflags nice)
NICE_LDFLAGS=$(shell pkg-config --libs nice)

CFLAGS += $(OPENSSL_CFLAGS) $(GLIB_CFLAGS) $(NICE_CFLAGS)
LDFLAGS += $(OPENSSL_LDFLAGS) $(GLIB_LDFLAGS) $(NICE_LDFLAGS)

OBJS=\
	util/strv.c \
	identity.c \
	pem.c \
	peer.c \
	signal.c \
	ice_connection.c \
	ssl_connection.c

VALGRIND=valgrind
VALGRINDFLAGS=--leak-check=yes --show-possibly-lost=no --quiet

CTESTFLAGS=-g -O0
CTESTFLAGS += $(OPENSSL_CFLAGS) $(GLIB_CFLAGS) $(NICE_CFLAGS)
LDTESTFLAGS += $(OPENSSL_LDFLAGS) $(GLIB_LDFLAGS) $(NICE_LDFLAGS)

TEST_FILES=$(shell find . -iname '*_test.c')

tests: $(TEST_FILES)
	$(foreach f, $(TEST_FILES), $(CC) $(OBJS) $(CTESTFLAGS) $(LDTESTFLAGS) $(f) && $(VALGRIND) $(VALGRINDFLAGS) ./a.out;)
	rm -f a.out
