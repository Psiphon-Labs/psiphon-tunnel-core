AM_CPPFLAGS = -I$(srcdir)/../../include $(ICU_CPPFLAGS)

if HAVE_BIN
bin_PROGRAMS = fstlinear fstloglinearapply

LDADD = libfstlinearscript.la ../../script/libfstscript.la \
	../../lib/libfst.la -lm -ldl

fstlinear_SOURCES = fstlinear.cc

fstloglinearapply_SOURCES = fstloglinearapply.cc
endif

if HAVE_SCRIPT
libfstlinearscript_la_SOURCES = linearscript.cc
libfstlinearscript_la_LDFLAGS = -version-info 1:0:0
endif

if HAVE_SCRIPT
libfst_LTLIBRARIES = libfstlinearscript.la linear_tagger-fst.la \
	linear_classifier-fst.la
else
libfst_LTLIBRARIES = linear_tagger-fst.la linear_classifier-fst.la
endif

libfstdir = @libfstdir@

linear_tagger_fst_la_SOURCES = linear-tagger-fst.cc
linear_tagger_fst_la_LDFLAGS = -module

linear_classifier_fst_la_SOURCES = linear-classifier-fst.cc
linear_classifier_fst_la_LDFLAGS = -module
