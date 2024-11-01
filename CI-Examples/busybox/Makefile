# Copyright (C) 2023 Gramine contributors
# SPDX-License-Identifier: BSD-3-Clause

BUSYBOX ?= $(shell sh -c 'command -v busybox')

ifeq ($(DEBUG),1)
GRAMINE_LOG_LEVEL = debug
else
GRAMINE_LOG_LEVEL = error
endif

RA_TYPE ?= none
RA_CLIENT_SPID ?=
RA_CLIENT_LINKABLE ?= 0

.PHONY: all
all: busybox.manifest
ifeq ($(SGX),1)
all: busybox.manifest.sgx busybox.sig
endif

busybox.manifest: busybox.manifest.template
	gramine-manifest \
		-Dbusybox=$(BUSYBOX) \
		-Dlog_level=$(GRAMINE_LOG_LEVEL) \
		-Dra_type=$(RA_TYPE) \
		-Dra_client_spid=$(RA_CLIENT_SPID) \
		-Dra_client_linkable=$(RA_CLIENT_LINKABLE) \
		$< > $@

busybox.manifest.sgx busybox.sig &: busybox.manifest
	gramine-sgx-sign \
		--manifest $< \
		--output $<.sgx

ifeq ($(SGX),)
GRAMINE = gramine-direct
else
GRAMINE = gramine-sgx
endif

.PHONY: check
check: all
	$(GRAMINE) busybox echo "Hello" > OUTPUT
	@grep -q "Hello" OUTPUT && echo "[ Success 1/1 ]"
	@rm OUTPUT

.PHONY: clean
clean:
	$(RM) *.token *.sig *.manifest.sgx *.manifest OUTPUT

.PHONY: distclean
distclean: clean
