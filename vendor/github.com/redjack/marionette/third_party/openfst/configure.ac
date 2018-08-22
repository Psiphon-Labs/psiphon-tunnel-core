AC_INIT([OpenFst], [1.4.1], [help@www.openfst.org])
AM_INIT_AUTOMAKE([foreign nostdinc -Wall -Werror])

CXXFLAGS="$CXXFLAGS -std=c++0x"

AC_PROG_CXX
AC_DISABLE_STATIC
AC_PROG_LIBTOOL

AC_CONFIG_HEADERS([config.h src/include/fst/config.h])
AC_CONFIG_SRCDIR([src/lib/fst.cc])
AC_CONFIG_FILES([
  Makefile
  src/Makefile
  src/include/Makefile
  src/lib/Makefile
  src/bin/Makefile
  src/test/Makefile
  src/extensions/Makefile
  src/extensions/compact/Makefile
  src/extensions/const/Makefile
  src/extensions/far/Makefile
  src/extensions/linear/Makefile
  src/extensions/lookahead/Makefile
  src/extensions/ngram/Makefile
  src/extensions/pdt/Makefile
  src/script/Makefile
])
AC_CONFIG_MACRO_DIR([m4])
AC_LANG([C++])

AC_ARG_ENABLE(
	[bin],
	[AS_HELP_STRING(
		[--enable-bin],
		[enable fst::script and command-line binaries])],
	[],
	[enable_bin=yes])
AM_CONDITIONAL([HAVE_BIN], [test "x$enable_bin" != xno])
AM_CONDITIONAL([HAVE_SCRIPT], [test "x$enable_bin" != xno])

AC_ARG_ENABLE(
	[compact-fsts],
	[AS_HELP_STRING(
		[--enable-compact-fsts],
		[enable all CompactFst extensions])],
	[],
	[enable_compact_fsts=no])
AM_CONDITIONAL([HAVE_COMPACT], [test "x$enable_compact_fsts" != xno])

AC_ARG_ENABLE(
	[const-fsts],
	[AS_HELP_STRING(
		[--enable-const-fsts],
		[enable all ConstFst extensions])],
	[],
	[enable_const_fsts=no])
AM_CONDITIONAL([HAVE_CONST], [test "x$enable_const_fsts" != xno])

AC_ARG_ENABLE([far], [AS_HELP_STRING([--enable-far], [enable FAR extensions])],
              [], [enable_far=no])
AM_CONDITIONAL([HAVE_FAR], [test "x$enable_far" != xno])

AC_ARG_ENABLE(
	[linear-fsts],
	[AS_HELP_STRING(
		[--enable-linear-fsts],
		[enable all LinearTagger/ClassifierFst extensions])],
	[],
	[enable_linear_fsts=no])
AM_CONDITIONAL([HAVE_LINEAR], [test "x$enable_linear_fsts" != xno])

AC_ARG_ENABLE(
	[ngram-fsts],
	[AS_HELP_STRING(
		[--enable-ngram-fsts],
		[enable NGramFst extension])],
	[],
	[enable_ngram_fsts=no])
AM_CONDITIONAL([HAVE_NGRAM], [test "x$enable_ngram_fsts" != xno])

AC_ARG_ENABLE(
	[lookahead-fsts],
	[AS_HELP_STRING(
		[--enable-lookahead-fsts],
		[enable LookAheadFst extensions])],
	[],
	[enable_lookahead_fsts=no])
AM_CONDITIONAL([HAVE_LOOKAHEAD], [test "x$enable_lookahead_fsts" != xno])

AC_ARG_ENABLE([pdt], [AS_HELP_STRING([--enable-pdt], [enable PDT extensions])],
              [], [enable_pdt=no])
AM_CONDITIONAL([HAVE_PDT], [test "x$enable_pdt" != xno])

AC_SUBST([libfstdir], [${libdir}/fst])

AC_OUTPUT
