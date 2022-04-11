ARCH_LIBDIR ?= /lib/$(shell $(CC) -dumpmachine)

.PHONY: all
all: build-rust rust-hyper-http-server.manifest
ifeq ($(SGX),1)
all: rust-hyper-http-server.manifest.sgx rust-hyper-http-server.sig rust-hyper-http-server.token
endif

ifeq ($(DEBUG),1)
GRAMINE_LOG_LEVEL = debug
CARGO_TARGET = debug
CARGO_PROFILE = dev
else
GRAMINE_LOG_LEVEL = error
CARGO_TARGET = release
CARGO_PROFILE = release
endif

# Defer incremental compilation of Rust to Cargo.
.PHONY: build-rust
build-rust:
	cargo build --profile $(CARGO_PROFILE)

SELF_EXE := target/$(CARGO_TARGET)/rust-hyper-http-server

rust-hyper-http-server.manifest: rust-hyper-http-server.manifest.template
	gramine-manifest \
		-Dlog_level=$(GRAMINE_LOG_LEVEL) \
		-Darch_libdir=$(ARCH_LIBDIR) \
		-Dself_exe=$(SELF_EXE) \
		$< $@

rust-hyper-http-server.manifest.sgx: rust-hyper-http-server.manifest build-rust
	gramine-sgx-sign \
		--manifest $< \
		--output $@

rust-hyper-http-server.sig: rust-hyper-http-server.manifest.sgx

rust-hyper-http-server.token: rust-hyper-http-server.sig
	gramine-sgx-get-token \
		--output $@ --sig $<

ifeq ($(SGX),)
GRAMINE = gramine-direct
else
GRAMINE = gramine-sgx
endif

.PHONY: start-gramine-server
start-gramine-server: all
	$(GRAMINE) rust-hyper-http-server

.PHONY: clean
clean:
	$(RM) -rf *.token *.sig *.manifest.sgx *.manifest target/ result-* OUTPUT

.PHONY: distclean
distclean: clean
