AM_CPPFLAGS = -I$(srcdir)/../../include $(ICU_CPPFLAGS)

libfstdir = @libfstdir@

if HAVE_SCRIPT
libfst_LTLIBRARIES = libfstfarscript.la libfstfar.la
else
libfst_LTLIBRARIES = libfstfar.la
endif

libfstfar_la_SOURCES = sttable.cc stlist.cc
libfstfar_la_LDFLAGS = -version-info 1:0:0

if HAVE_SCRIPT
libfstfarscript_la_SOURCES = farscript.cc strings.cc main.cc
libfstfarscript_la_LDFLAGS = -version-info 1:0:0
endif

if HAVE_BIN
bin_PROGRAMS = farcompilestrings farcreate farequal farextract farinfo \
	farprintstrings

LDADD = libfstfarscript.la libfstfar.la ../../script/libfstscript.la \
        ../../lib/libfst.la -lm -ldl

farcompilestrings_SOURCES = farcompilestrings.cc

farcreate_SOURCES = farcreate.cc

farequal_SOURCES = farequal.cc

farextract_SOURCES = farextract.cc

farinfo_SOURCES = farinfo.cc

farprintstrings_SOURCES = farprintstrings.cc
endif
