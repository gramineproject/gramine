ARCH_LIBDIR ?= /lib/$(shell $(CC) -dumpmachine)

.PHONY: all
all: build-rust rust.manifest
ifeq ($(SGX),1)
all: rust.manifest.sgx rust.sig rust.token
endif

ifeq ($(DEBUG),1)
GRAMINE_LOG_LEVEL = debug

.PHONY: build-rust
build-rust:
	cargo build

SELF_EXE = target/debug/rust
else
GRAMINE_LOG_LEVEL = error

.PHONY: build-rust
build-rust:
	cargo build --release

SELF_EXE = target/release/rust
endif

rust.manifest: rust.manifest.template
	gramine-manifest \
		-Dlog_level=$(GRAMINE_LOG_LEVEL) \
		-Darch_libdir=$(ARCH_LIBDIR) \
		-Dself_exe=$(SELF_EXE) \
		$< $@

rust.manifest.sgx: rust.manifest build-rust
	gramine-sgx-sign \
		--manifest $< \
		--output $@

rust.sig: rust.manifest.sgx

rust.token: rust.sig
	gramine-sgx-get-token \
		--output $@ --sig $<

ifeq ($(SGX),)
GRAMINE = gramine-direct
else
GRAMINE = gramine-sgx
endif

.PHONY: check
start-gramine-server: all
	$(GRAMINE) rust

.PHONY: clean
clean:
	$(RM) -rf *.token *.sig *.manifest.sgx *.manifest target/ OUTPUT

.PHONY: distclean
distclean: clean
