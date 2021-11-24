
ROOTDIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

SRCDIR = $(ROOTDIR)/src
BUILDDIR = $(ROOTDIR)/build
INSTALLDIR = $(ROOTDIR)/install
TESTCASEDIR = $(INSTALLDIR)/testcases/bin
LTPSCENARIO = $(INSTALLDIR)/runtest/syscalls

clean-extra += clean-build

RUNLTPOPTS =

ifeq ($(V),1)
	RUNLTPOPTS += -v
endif

ifneq ($(LTP_TIMEOUT_FACTOR),)
	RUNLTPOPTS += -T $(LTP_TIMEOUT_FACTOR)
endif

.PHONY: all
all: $(INSTALLDIR)/INSTALL_SUCCESS manifests etc/nsswitch.conf etc/passwd

$(SRCDIR)/Makefile:
	$(error "$(SRCDIR) is empty. Please run `git submodule update --init $(SRCDIR)` or download the LTP source code (https://github.com/linux-test-project/ltp) into $(SRCDIR).")

$(SRCDIR)/configure: $(SRCDIR)/Makefile
	$(MAKE) -C $(SRCDIR) autotools

.SECONDARY: $(BUILDDIR)/BUILD_SUCCESS
$(BUILDDIR)/BUILD_SUCCESS: $(SRCDIR)/configure
	# Out-of-tree build steps were taken from ltp/INSTALL.
	# The instructions below assume that SRCDIR and BUILDDIR are absolute.
	mkdir -p $(BUILDDIR)
	# Kernel module tests are not meaningful for our LibOS and building them causes troubles on
	# incompatible host kernels.
	cd $(BUILDDIR) && $(SRCDIR)/configure --without-modules --prefix $(INSTALLDIR)
	$(MAKE) -C $(BUILDDIR) -f $(SRCDIR)/Makefile top_srcdir=$(SRCDIR) top_builddir=$(BUILDDIR) all
	touch $@

.SECONDARY: $(INSTALLDIR)/INSTALL_SUCCESS
$(INSTALLDIR)/INSTALL_SUCCESS: $(BUILDDIR)/BUILD_SUCCESS
	$(MAKE) -C $(BUILDDIR) -f $(SRCDIR)/Makefile top_srcdir=$(SRCDIR) top_builddir=$(BUILDDIR) SKIP_IDCHECK=1 install
	ln -sf $(abspath Makefile.testcases) $(TESTCASEDIR)/Makefile
	touch $@

.PHONY: manifests
manifests: $(INSTALLDIR)/INSTALL_SUCCESS
	gramine-test build

etc/nsswitch.conf:
	mkdir -p etc
	printf "passwd: compat\ngroup: compat\nshadow: compat\nhosts: files\n" > $@

etc/passwd:
	mkdir -p etc
	printf "root:x:0:0:root:/root:/bin/bash\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n" > $@

.PHONY: regression
regression:
ifeq ($(SGX),"1")
	$(RM) ltp-sgx.xml
	$(MAKE) ltp-sgx.xml
else
	$(RM) ltp.xml
	$(MAKE) ltp.xml
endif

ltp.xml: CFG = ltp.cfg
ltp-sgx.xml: CFG = ltp.cfg ltp-sgx.cfg ltp-bug-1075.cfg

%.xml: $(CFG) $(INSTALLDIR)/INSTALL_SUCCESS manifests
	./contrib/conf_lint.py $(CFG) --scenario $(LTPSCENARIO)
	./runltp_xml.py $(RUNLTPOPTS) $(foreach cfg,$(CFG),-c $(cfg)) $(LTPSCENARIO) -O $@

.PHONY: clean
clean:
	if test -f $(INSTALLDIR)/INSTALL_SUCCESS; then gramine-test clean; fi
	$(MAKE) -C $(SRCDIR) clean
	$(RM) -r $(BUILDDIR) $(INSTALLDIR) ltp*.xml etc/
