SUBDIRS = src . tests examples

MOSTLYCLEANFILES = *.gcda *.gcno *.gcov tests/gcov.log tests/gcov.trs tests/*.xml

if COND_GCOV
MAYBE_COVERAGE=-fprofile-arcs -ftest-coverage
endif

AM_CFLAGS := $(MAYBE_COVERAGE) $(AM_CFLAGS)

