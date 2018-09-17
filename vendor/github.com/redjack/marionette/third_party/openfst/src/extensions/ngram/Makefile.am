AM_CPPFLAGS = -I$(srcdir)/../../include $(ICU_CPPFLAGS)

libfstdir = @libfstdir@
libfst_LTLIBRARIES = libfstngram.la ngram-fst.la

ngram_fst_la_SOURCES = bitmap-index.cc ngram-fst.cc nthbit.cc
ngram_fst_la_LDFLAGS = -module

libfstngram_la_SOURCES = bitmap-index.cc ngram-fst.cc nthbit.cc
libfstngram_la_LDFLAGS = -version-info 1:0:0
