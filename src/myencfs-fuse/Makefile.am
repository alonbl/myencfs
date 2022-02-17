MAINTAINERCLEANFILES = \
	$(srcdir)/Makefile.in \
	$(NULL)

if ENABLE_FUSE
bin_PROGRAMS = \
	myencfs-fuse \
	$(NULL)
endif

AM_CFLAGS = \
	$(FUSE_CFLAGS) \
	-I$(top_srcdir)/include \
	$(NULL)
myencfs_fuse_SOURCES = \
	main.c \
	$(NULL)
myencfs_fuse_LDADD = \
	$(builddir)/../libmyencfs/libmyencfs.la \
	$(FUSE_LIBS) \
	$(NULL)
