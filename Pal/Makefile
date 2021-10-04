include ../Scripts/Makefile.configs

DIRS = regression

.PHONY: all
all:
	@:

clean_targets = clean distclean
.PHONY: $(clean_targets)
$(clean_targets):
	$(MAKE) -C regression $@

.PHONY: test
test:
	$(MAKE) -C regression

.PHONY: sgx-tokens
sgx-tokens:
	$(MAKE) -C regression sgx-tokens

.PHONY: distclean
distclean: clean
