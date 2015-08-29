bin_PROGRAMS = fs-hasher hf-stat hf-simdex
lib_LIBRARIES = libhashfile.a
include_HEADERS = libhashfile.h
dist_man1_MANS = manpages/fs-hasher.1 manpages/hf-stat.1 manpages/hf-anonymizer.1 manpages/hf-simdex.1 manpages/libhashfile.3

dist_noinst_DATA= examples/README examples/read_hashfile.c examples/coreutils-8.22.hash examples/Makefile

if COMPILE_ANONYMIZER
bin_PROGRAMS += hf-anonymizer
hf_anonymizer_SOURCES = hf-anonymizer.c libhashfile.c libhashfile.h liblog.c liblog.h
endif

fs_hasher_SOURCES = fs-hasher.c libhashfile.c libhashfile.h liblog.c liblog.h murmurhash3.c murmurhash3.h

hf_stat_SOURCES = hf-stat.c libhashfile.c libhashfile.h liblog.c liblog.h

hf_simdex_SOURCES = hf-simdex.c libhashfile.c libhashfile.h rbtree.c rbtree.h list.h

libhashfile_a_SOURCES = libhashfile.c libhashfile.h
