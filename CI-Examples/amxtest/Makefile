CFLAGS = -Wall -Wextra

ifeq ($(DEBUG),1)
GRAMINE_LOG_LEVEL = all
CFLAGS += -g
else
GRAMINE_LOG_LEVEL = error
CFLAGS += -O3
endif

.PHONY: all
all: amxtest amxtest.manifest
ifeq ($(SGX),1)
all: amxtest.manifest.sgx amxtest.sig
endif

amxtest: amxtest.o

amxtest.o: amxtest.c

amxtest.manifest: amxtest.manifest.template
	gramine-manifest \
		-Dlog_level=$(GRAMINE_LOG_LEVEL) \
		$< $@

# Make on Ubuntu <= 20.04 doesn't support "Rules with Grouped Targets" (`&:`),
# see the helloworld example for details on this workaround.
amxtest.sig amxtest.manifest.sgx: sgx_sign
	@:

.INTERMEDIATE: sgx_sign
sgx_sign: amxtest.manifest amxtest
	gramine-sgx-sign \
		--manifest $< \
		--output $<.sgx

.PHONY: clean
clean:
	$(RM) *.token *.sig *.manifest.sgx *.manifest *.o amxtest OUTPUT

.PHONY: distclean
distclean: clean
