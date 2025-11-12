Makefile:
	wget -q https://raw.githubusercontent.com/cyrus-and/dry-makefile/master/Makefile

SOURCES        := $(wildcard src/*.c) tests/killer_pipe_test.c tests/pool_benchmark.c
EXECUTABLES    := src/zizzania.c tests/killer_pipe_test.c tests/pool_benchmark.c
COMPILER_FLAGS := -Wall -Isrc -isystem external/
LINKER_FLAGS   := -pthread
LIBRARIES      := -lpcap
BUILD_PROFILES := release debug
SETUP_HOOK     := external/uthash.h
CLEANUP_HOOK   := -cleanup

release: COMPILER_FLAGS += -O3 -Os
debug:   COMPILER_FLAGS += -ggdb3 -Werror -pedantic -DDEBUG -Wno-gnu-zero-variadic-macro-arguments

external/uthash.h:
	wget -q -P external/ https://raw.githubusercontent.com/troydhanson/uthash/v2.1.0/src/uthash.h

.PHONY: -cleanup
-cleanup:
	$(RM) -r Makefile external/
