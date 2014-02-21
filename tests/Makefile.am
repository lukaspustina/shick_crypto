if COND_GCOV
TESTS = unittests acceptancetests gcov
else
TESTS = unittests acceptancetests
endif

check_PROGRAMS = unittests acceptancetests

unittests_SOURCES = unittests.c $(top_builddir)/src/shick_crypto.h
unittests_CFLAGS = @CHECK_CFLAGS@
unittests_LDADD = $(top_builddir)/src/libshickcrypto.la @CHECK_LIBS@

acceptancetests_SOURCES = acceptancetests.c $(top_builddir)/src/shick_crypto.h
acceptancetests_CFLAGS = @CHECK_CFLAGS@
acceptancetests_LDADD = $(top_builddir)/src/libshickcrypto.la @CHECK_LIBS@

