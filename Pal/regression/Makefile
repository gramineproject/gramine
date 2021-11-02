include ../../Scripts/Makefile.configs

# Disable implicit rules so that Make doesn't try to compile the binaries
.SUFFIXES:

GRAMINE_PKGLIBDIR ?= $(shell python3 -c 'import graminelibos; print(graminelibos._CONFIG_PKGLIBDIR)')
BINARY_DIR = $(GRAMINE_PKGLIBDIR)/tests/pal

executables-x86_64 = \
    Exception \
    Exception2 \
    Segment \
    Thread

ifeq ($(SGX),1)
	executables-x86_64 += AttestationReport
endif

executables = \
	..Bootstrap \
	avl_tree_test \
	Bootstrap \
	Bootstrap7 \
	Directory \
	Event \
	Exit \
	File \
	File2 \
	HelloWorld \
	Hex \
	Memory \
	Misc \
	Pie \
	Pipe \
	Process \
	Process4 \
	Select \
	SendHandle \
	Socket \
	Symbols \
	Tcp \
	Thread2 \
	Udp \
	normalize_path \
	printf_test \
	$(executables-$(ARCH))

repo_manifests = \
	Bootstrap6.manifest \
	Bootstrap7.manifest \
	File.manifest \
	Thread2.manifest \
	Thread2_exitless.manifest

gen_manifests = $(addsuffix .manifest,$(executables))
all_manifests = $(repo_manifests) $(gen_manifests)

# Variables passed to `gramine-manifest`
extra_rules = -Dbinary_dir=$(BINARY_DIR)

target = $(all_manifests)

clean-extra += clean-tmp

include ../../Scripts/manifest.mk
include ../../Scripts/Makefile.Test

.PHONY: sgx-tokens
sgx-tokens: $(call expand_target_to_token,$(target))

.PHONY: regression
regression: $(target)
	$(RM) pal-regression.xml
	$(MAKE) pal-regression.xml

pal-regression.xml: test_pal.py $(target) $(call expand_target_to_sig,$(target)) $(call expand_target_to_sgx,$(target)) $(call expand_target_to_token,$(target))
	../../Scripts/run-pytest --junit-xml $@ -v $<

.PHONY: clean-tmp
clean-tmp:
	$(RM) -r \
		$(all_manifests) \
		*.d \
		.*.d \
		*.manifest.sgx \
		.*.manifest.sgx \
		*.o \
		*.sig \
		.*.sig \
		*.tmp \
		*.token \
		.*.token \
		.output.* \
		.pytest_cache \
		__pycache__ \
		pal-regression.xml

.PHONY: distclean
distclean: clean
