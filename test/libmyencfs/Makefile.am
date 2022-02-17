MAINTAINERCLEANFILES = \
	$(srcdir)/Makefile.in \
	$(NULL)

TESTS = \
	test-error \
	test-realtime \
	test-sanity \
	$(NULL)

noinst_PROGRAMS = \
	test-error \
	test-realtime \
	test-sanity \
	$(NULL)

AM_CPPFLAGS = \
	-I$(top_srcdir)/include \
	$(NULL)

test_error_CFLAGS = \
	-I$(top_srcdir)/src/libmyencfs \
	$(NULL)
test_error_SOURCES = \
	test-error.c \
	$(NULL)
test_error_LDADD = \
	$(top_builddir)/src/libmyencfs/libmyencfs-internal.la \
	$(NULL)

test_sanity_SOURCES = \
	test-sanity.c \
	$(NULL)
test_sanity_LDADD = \
	$(top_builddir)/src/libmyencfs/libmyencfs.la \
	$(NULL)

test_realtime_SOURCES = \
	test-realtime.c \
	$(NULL)
test_realtime_LDADD = \
	$(top_builddir)/src/libmyencfs/libmyencfs.la \
	$(NULL)

TESTS_ENVIRONMENT = \
	LIBTOOL="$(LIBTOOL)" \
	MYENCFS_TOOL="$(top_builddir)/src/myencfs-tool/myencfs-tool$(EXEEXT)" \
	VALGRIND="$(VALGRIND)" \
	builddir="$(builddir)" \
	top_builddir="$(top_builddir)" \
	$(NULL)
LOG_COMPILER = \
	$(SHELL) $(top_srcdir)/build/valgrind-wrapper.sh \
	$(NULL)
