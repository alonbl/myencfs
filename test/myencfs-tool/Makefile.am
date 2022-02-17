MAINTAINERCLEANFILES = \
	$(srcdir)/Makefile.in \
	$(NULL)

TESTS = \
	test-myencfs-tool-sanity.sh \
	$(NULL)

dist_noinst_SCRIPTS = \
	test-myencfs-tool-sanity.sh \
	$(NULL)

dist_noinst_DATA = \
	test-myencfs-tool-sanity.cmd \
	$(NULL)

TESTS_ENVIRONMENT = \
	LIBTOOL="$(LIBTOOL)" \
	MYENCFS_TOOL="$(top_builddir)/src/myencfs-tool/myencfs-tool$(EXEEXT)" \
	VALGRIND="$(VALGRIND)" \
	builddir="$(builddir)" \
	top_builddir="$(top_builddir)" \
	$(NULL)
