MAINTAINERCLEANFILES = \
	$(srcdir)/Makefile.in \
	$(NULL)

EXTRA_DIST = \
	fuse.valgrind.supp \
	$(NULL)

if !BUILD_WINDOWS
TESTS = \
	test-sanity.sh \
	test-valgrind.sh \
	$(NULL)
endif

dist_noinst_SCRIPTS = \
	test-sanity.sh \
	test-valgrind.sh \
	$(NULL)

TESTS_ENVIRONMENT = \
	FUSERMOUNT="$(FUSERMOUNT)" \
	LIBTOOL="$(LIBTOOL)" \
	MYENCFS_FUSE="$(top_builddir)/src/myencfs-fuse/myencfs-fuse$(EXEEXT)" \
	MYENCFS_TOOL="$(top_builddir)/src/myencfs-tool/myencfs-tool$(EXEEXT)" \
	VALGRIND="$(VALGRIND)" \
	builddir="$(builddir)" \
	top_builddir="$(top_builddir)" \
	$(NULL)
