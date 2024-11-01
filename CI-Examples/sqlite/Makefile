# Copyright (C) 2023 Gramine contributors
# SPDX-License-Identifier: BSD-3-Clause

ARCH_LIBDIR ?= /lib/$(shell $(CC) -dumpmachine)

ifeq ($(DEBUG),1)
GRAMINE_LOG_LEVEL = debug
else
GRAMINE_LOG_LEVEL = error
endif

.PHONY: all
all: sqlite3.manifest
ifeq ($(SGX),1)
all: sqlite3.manifest.sgx sqlite3.sig
endif

sqlite3.manifest: manifest.template
	gramine-manifest \
		-Dlog_level=$(GRAMINE_LOG_LEVEL) \
		-Dexecdir=$(shell dirname $(shell which sqlite3)) \
		-Darch_libdir=$(ARCH_LIBDIR) \
		$< >$@

sqlite3.manifest.sgx sqlite3.sig &: sqlite3.manifest
	gramine-sgx-sign \
		--manifest $< \
		--output $<.sgx

ifeq ($(SGX),)
GRAMINE = gramine-direct
else
GRAMINE = gramine-sgx
endif

# Note that command-line arguments are hardcoded in the manifest file.
.PHONY: regression
regression: all
	@$(RM) db/*

	$(GRAMINE) sqlite3 < scripts/create.sql
	@echo "[ Success 1/3 ]"

	$(GRAMINE) sqlite3 < scripts/update.sql
	@echo "[ Success 2/3 ]"

	$(GRAMINE) sqlite3 < scripts/select.sql > OUTPUT
	diff OUTPUT scripts/select.txt
	@echo "[ Success 3/3 ]"

.PHONY: clean
clean:
	$(RM) *.manifest *.manifest.sgx *.token *.sig OUTPUT db/*

.PHONY: distclean
distclean: clean
