all: config

.PHONY: all config

config: Makefile external/uthash.h
	@echo "Build helpers are up to date."

Makefile: build_support/dry.Makefile
	cp $< Makefile

SOURCES        := $(wildcard src/*.c)
EXECUTABLES    := src/airsnare.c
COMPILER_FLAGS := -Wall -Isrc -isystem external/
LINKER_FLAGS   := -pthread
LIBRARIES      := -lpcap
BUILD_PROFILES := release debug
SETUP_HOOK     := external/uthash.h
CLEANUP_HOOK   := -cleanup
INSTALL_DIR    ?= /usr/local/bin
INSTALL_PATH   := $(DESTDIR)$(INSTALL_DIR)
INSTALL_NAME   ?= airsnare
DRY_DISABLE_DEFAULT_INSTALL := 1

release: COMPILER_FLAGS += -O3 -Os
debug:   COMPILER_FLAGS += -ggdb3 -Werror -pedantic -DDEBUG -Wno-gnu-zero-variadic-macro-arguments

external/uthash.h: build_support/uthash.h
	mkdir -p external
	cp $< external/uthash.h

.PHONY: install uninstall
install: release
	install -d $(INSTALL_PATH)
	install -m 0755 src/airsnare $(INSTALL_PATH)/$(INSTALL_NAME)

uninstall:
	$(RM) $(INSTALL_PATH)/$(INSTALL_NAME)

.PHONY: -cleanup
-cleanup:
	$(RM) -r external/
