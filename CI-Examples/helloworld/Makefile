SGX_SIGNER_KEY ?= ../../Pal/src/host/Linux-SGX/signer/enclave-key.pem

CFLAGS = -Wall -Wextra

ifeq ($(DEBUG),1)
GRAMINE_LOG_LEVEL = debug
CFLAGS += -g
else
GRAMINE_LOG_LEVEL = error
CFLAGS += -O3
endif

.PHONY: all
all: helloworld helloworld.manifest
ifeq ($(SGX),1)
all: helloworld.manifest.sgx helloworld.sig helloworld.token
endif

helloworld: helloworld.o

helloworld.o: helloworld.c

helloworld.manifest: helloworld.manifest.template
	gramine-manifest \
		-Dlog_level=$(GRAMINE_LOG_LEVEL) \
		$< $@

helloworld.manifest.sgx: helloworld.manifest helloworld
	@test -s $(SGX_SIGNER_KEY) || \
	    { echo "SGX signer private key was not found, please specify SGX_SIGNER_KEY!"; exit 1; }
	gramine-sgx-sign \
		--key $(SGX_SIGNER_KEY) \
		--manifest $< \
		--output $@

helloworld.sig: helloworld.manifest.sgx

helloworld.token: helloworld.sig
	gramine-sgx-get-token \
		--output $@ --sig $<

ifeq ($(SGX),)
GRAMINE = gramine-direct
else
GRAMINE = gramine-sgx
endif

.PHONY: check
check: all
	$(GRAMINE) helloworld > OUTPUT
	echo "Hello, world" | diff OUTPUT -
	@echo "[ Success ]"

.PHONY: clean
clean:
	$(RM) *.token *.sig *.manifest.sgx *.manifest helloworld.o helloworld OUTPUT

.PHONY: distclean
distclean: clean
