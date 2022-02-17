include $(top_srcdir)/build/ltrc.inc

MAINTAINERCLEANFILES = \
	$(srcdir)/Makefile.in \
	$(NULL)

if ENABLE_TOOL
bin_PROGRAMS = \
	myencfs-tool \
	$(NULL)
endif

AM_CPPFLAGS = \
	-I$(top_srcdir)/include \
	$(NULL)

myencfs_tool_SOURCES = \
	compat-getopt.c \
	compat-getopt.h \
	getoptutil.c \
	getoptutil.h \
	main.c \
	util.c \
	util.h \
	$(NULL)
nodist_myencfs_tool_SOURCES = \
	$(NULL)
if ENABLE_ENCRYPT
myencfs_tool_SOURCES += \
	cmd-encrypt.c \
	cmd-encrypt.h \
	$(NULL)
endif
if ENABLE_DECRYPT
myencfs_tool_SOURCES += \
	cmd-decrypt.c \
	cmd-decrypt.h \
	$(NULL)
endif
if BUILD_WINDOWS
nodist_myencfs_tool_SOURCES += \
	versioninfo.rc \
	$(NULL)
endif
myencfs_tool_LDADD = \
	$(builddir)/../libmyencfs/libmyencfs.la \
	$(CRYPTO_LIBS) \
	$(NULL)
