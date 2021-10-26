# Disable implicit rules so that Make doesn't try to compile the binaries
.SUFFIXES:

GRAMINE_PKGLIBDIR ?= $(shell python3 -c 'import graminelibos; print(graminelibos._CONFIG_PKGLIBDIR)')
BINARY_DIR = $(GRAMINE_PKGLIBDIR)/tests/libos/fs

copy_mmap_execs = \
	copy_mmap_rev \
	copy_mmap_seq \
	copy_mmap_whole

copy_execs = \
	copy_rev \
	copy_sendfile \
	copy_seq \
	copy_whole

execs = \
	$(copy_execs) \
	$(copy_mmap_execs) \
	delete \
	multiple_writers \
	open_close \
	open_flags \
	read_write \
	seek_tell \
	stat \
	truncate

all_manifests = $(addsuffix .manifest,$(execs))

target = $(all_manifests)

clean-extra += clean-tmp

# Variables passed to `gramine-manifest`
extra_rules = -Dbinary_dir=$(BINARY_DIR)

.PHONY: default
default: all

include ../../../../Scripts/Makefile.configs
include ../../../../Scripts/manifest.mk
include ../../../../Scripts/Makefile.Test

.PHONY: fs-test
fs-test: $(target)
	$(RM) fs-test.xml
	$(MAKE) fs-test.xml

.PHONY: tmpfs-test
tmpfs-test: $(target)
	$(RM) tmpfs-test.xml
	$(MAKE) tmpfs-test.xml

.PHONY: pf-test
pf-test: $(target)
	$(RM) pf-test.xml
	$(MAKE) pf-test.xml

.PHONY: test
test: fs-test tmpfs-test pf-test

fs-test.xml: test_fs.py $(call expand_target_to_token,$(target))
	$(SCRIPTS_DIR)/run-pytest --junit-xml $@ -v $<

tmpfs-test.xml: test_tmpfs.py $(call expand_target_to_token,$(target))
	$(SCRIPTS_DIR)/run-pytest --junit-xml $@ -v $<

pf-test.xml: test_pf.py $(call expand_target_to_token,$(target))
	$(SCRIPTS_DIR)/run-pytest --junit-xml $@ -v $<

.PHONY: clean-tmp
clean-tmp:
	$(RM) -r \
		*.manifest \
		*.manifest.sgx \
		*.sig \
		*.token \
		.pytest_cache \
		__pycache__ \
		*.xml \
		tmp/*
