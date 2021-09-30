include ../../Scripts/Makefile.configs
include ../../Scripts/Makefile.rules

HOST_DIR = host/$(PAL_HOST)

.PHONY: all
all: host_lib_recurse

.PHONY: host_lib_recurse
host_lib_recurse:
ifeq ($(PAL_HOST),Linux-SGX)
	$(MAKE) -C $(HOST_DIR)
else
	@:
endif

clean_targets = clean distclean
.PHONY: $(clean_targets)

$(clean_targets):
ifeq ($(PAL_HOST),Linux-SGX)
	$(MAKE) -C $(HOST_DIR) $@
else
	@:
endif

.PHONY: test
test:
	$(MAKE) -C $(HOST_DIR) test

.PHONY: sgx-tokens
sgx-tokens:
	$(MAKE) -C $(HOST_DIR) sgx-tokens
