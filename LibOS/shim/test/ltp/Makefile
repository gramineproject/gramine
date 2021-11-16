include makevars.mk

GRAMINE_PKGLIBDIR ?= $(shell python3 -c 'import graminelibos; print(graminelibos._CONFIG_PKGLIBDIR)')

target = $(INSTALLDIR)/INSTALL_SUCCESS build-manifest
exec_target =

clean-extra += clean-build

include ../../../../Scripts/Makefile.rules
include ../../../../Scripts/Makefile.configs
# Make ARCH_LIBDIR visible in Makefile.Test
export ARCH_LIBDIR
include Makefile.Test

ifeq ($(BUILD_VERBOSE),1)
	RUNLTPOPTS += -v
endif

ifneq ($(LTP_TIMEOUT_FACTOR),)
	RUNLTPOPTS += -T $(LTP_TIMEOUT_FACTOR)
endif

# TODO: Use the already installed LTP binaries instead of copying them to our directory.
.SECONDARY: $(INSTALLDIR)/INSTALL_SUCCESS
$(INSTALLDIR)/INSTALL_SUCCESS: $(GRAMINE_PKGLIBDIR)/tests/ltp
	rm -rf $(INSTALLDIR)
	cp -r $< $(INSTALLDIR)
	ln -sf $(abspath Makefile.testcases) $(TESTCASEDIR)/Makefile
	touch $@

.PHONY: build-manifest
build-manifest: $(TESTCASEDIR)/manifest.template $(INSTALLDIR)/INSTALL_SUCCESS
	$(MAKE) -C $(TESTCASEDIR)

$(TESTCASEDIR)/manifest.template: manifest.template $(INSTALLDIR)/INSTALL_SUCCESS
	sed -e 's|$$(ARCH_LIBDIR)|'"$(ARCH_LIBDIR)"'|g' \
		$< > $@

.PHONY: sgx-tokens
sgx-tokens: build-manifest
	$(MAKE) -C $(TESTCASEDIR) $@

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

%.xml: $(CFG) $(target) $(INSTALLDIR)/INSTALL_SUCCESS
	./contrib/conf_lint.py $(CFG) --scenario $(LTPSCENARIO)
	./runltp_xml.py $(RUNLTPOPTS) $(foreach cfg,$(CFG),-c $(cfg)) $(LTPSCENARIO) -O $@

.PHONY: clean-build
clean-build:
	$(RM) -r $(INSTALLDIR) ltp*.xml
