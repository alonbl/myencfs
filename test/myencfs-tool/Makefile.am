MAINTAINERCLEANFILES = \
	$(srcdir)/Makefile.in \
	$(NULL)

if !BUILD_WINDOWS
TESTS = \
	test-sanity.sh \
	$(NULL)

endif

dist_noinst_SCRIPTS = \
	test-sanity.sh \
	$(NULL)

TESTS_ENVIRONMENT = \
	LIBTOOL="$(LIBTOOL)" \
	MYENCFS_TOOL="$(top_builddir)/src/myencfs-tool/myencfs-tool$(EXEEXT)" \
	VALGRIND="$(VALGRIND)" \
	builddir="$(builddir)" \
	top_builddir="$(top_builddir)" \
	$(NULL)
