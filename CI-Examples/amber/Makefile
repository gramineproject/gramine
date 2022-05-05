GRAMINEDIR ?= ../..
GRAMINE_PKGLIBDIR ?= /usr/lib/x86_64-linux-gnu/gramine # this is debian/ubuntu specific

ARCH_LIBDIR ?= /lib/$(shell $(CC) -dumpmachine)

ifeq ($(DEBUG),1)
GRAMINE_LOG_LEVEL = debug
CFLAGS += -O0 -ggdb3
else
GRAMINE_LOG_LEVEL = error
CFLAGS += -O2
endif

CFLAGS += -fPIE
LDFLAGS += -pie

.PHONY: all
all: app_deps

.PHONY: app_deps
app_deps: app.manifest.sgx app.sig app.token app

######################### APP EXECUTABLES ###########################

app: src/app.c
	$(CC) $< $(CFLAGS) $(LDFLAGS) -o $@

############################### SERVER MANIFEST ###############################

app.manifest: app.manifest.template
	gramine-manifest \
		-Dlog_level=$(GRAMINE_LOG_LEVEL) \
		-Darch_libdir=$(ARCH_LIBDIR) \
		$< > $@

app.manifest.sgx: app.manifest app
	gramine-sgx-sign \
		--manifest $< \
		--output $@

app.sig: app.manifest.sgx

app.token: app.sig
	gramine-sgx-get-token --output $@ --sig $<

############################### SGX CHECKS FOR CI #############################

.PHONY: check_app
check_app: app_deps
	gramine-sgx app >/dev/null
	@grep -q "using default SGX-measurement verification callback" OUTPUT && echo "[ Success 1/4 ]"
	@grep -q "using our own SGX-measurement verification callback" OUTPUT && echo "[ Success 2/4 ]"
	@grep -q "Verifying peer X.509 certificate... ok" OUTPUT && echo "[ Success 3/4 ]"
	@(exit `grep -c "failed" "OUTPUT"`) && echo "[ Success 4/4 ]"
	@rm OUTPUT

.PHONY: check_app_fail
check_app_fail: app_deps
	gramine-sgx app >/dev/null

################################## CLEANUP ####################################

.PHONY: clean
clean:
	$(RM) -r \
		*.token *.sig *.manifest.sgx *.manifest app *.so *.so.* OUTPUT

.PHONY: distclean

distclean: clean
