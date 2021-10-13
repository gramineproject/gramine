include ../../Scripts/Makefile.configs
include ../../Scripts/Makefile.rules

# Disable implicit rules so that Make doesn't try to compile the binaries
.SUFFIXES:

GRAMINE_PKGLIBDIR ?= $(shell python3 -c 'import graminelibos; print(graminelibos._CONFIG_PKGLIBDIR)')

preloads = \
	Preload1.so \
	Preload2.so

executables-x86_64 = \
    Exception \
    Exception2 \
    Segment \
    Thread

executables = \
	..Bootstrap \
	AttestationReport \
	avl_tree_test \
	Bootstrap \
	Bootstrap3 \
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
	Process3 \
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
	Bootstrap3.manifest \
	Bootstrap6.manifest \
	Bootstrap7.manifest \
	File.manifest \
	Process3.manifest \
	Thread2.manifest \
	Thread2_exitless.manifest

# Empty rule to prevent overriding them using "%.manifest: manifest.template" rule.
$(repo_manifests): ;

gen_manifests = $(filter-out $(repo_manifests),$(addsuffix .manifest,$(executables)))
all_manifests = $(repo_manifests) $(gen_manifests)

target = \
	$(executables) \
	$(preloads) \
	$(all_manifests)

include ../../Scripts/manifest.mk

.PHONY: all
all: $(target) $(call expand_target_to_sig,$(target)) \
     $(call expand_target_to_sgx,$(target)) $(preloads)

.PHONY: sgx-tokens
sgx-tokens: $(call expand_target_to_token,$(target))

$(preloads) $(executables): %: $(GRAMINE_PKGLIBDIR)/tests/pal/%
	$(call cmd,symlink)

.PHONY: regression
regression:
	$(RM) pal-regression.xml
	$(MAKE) pal-regression.xml

pal-regression.xml: test_pal.py $(target) $(call expand_target_to_sig,$(target)) $(call expand_target_to_sgx,$(target)) $(call expand_target_to_token,$(target))
	../../Scripts/run-pytest --junit-xml $@ -v $<

.PHONY: clean
clean:
	$(RM) -r \
		$(executables) \
		$(gen_manifests) \
		$(preloads) \
		*.cached \
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
		.cache \
		.lib \
		.output.* \
		.pytest_cache \
		__pycache__ \
		pal-regression.xml

.PHONY: distclean
distclean: clean
