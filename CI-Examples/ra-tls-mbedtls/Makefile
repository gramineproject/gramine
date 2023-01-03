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

RA_TYPE ?= none
RA_CLIENT_SPID ?=
RA_CLIENT_LINKABLE ?= 0

.PHONY: all
all: app epid  # by default, only build EPID because it doesn't rely on additional (DCAP) libs

.PHONY: app
app: ssl/server.crt server.manifest.sgx server.sig client

.PHONY: epid
epid: client_epid.manifest.sgx client_epid.sig

.PHONY: dcap
dcap: client_dcap.manifest.sgx client_dcap.sig

############################# SSL DATA DEPENDENCY #############################

# SSL data: key and x.509 self-signed certificate
ssl/server.crt: ssl/ca_config.conf
	openssl genrsa -out ssl/ca.key 2048
	openssl req -x509 -new -nodes -key ssl/ca.key -sha256 -days 1024 -out ssl/ca.crt -config ssl/ca_config.conf
	openssl genrsa -out ssl/server.key 2048
	openssl req -new -key ssl/server.key -out ssl/server.csr -config ssl/ca_config.conf
	openssl x509 -req -days 360 -in ssl/server.csr -CA ssl/ca.crt -CAkey ssl/ca.key -CAcreateserial -out ssl/server.crt

######################### CLIENT/SERVER EXECUTABLES ###########################

CFLAGS += $(shell pkg-config --cflags mbedtls_gramine)
LDFLAGS += -ldl -Wl,--enable-new-dtags $(shell pkg-config --libs mbedtls_gramine)

server: src/server.c
	$(CC) $< $(CFLAGS) $(LDFLAGS) -o $@

client: src/client.c
	$(CC) $< $(CFLAGS) $(LDFLAGS) -o $@

############################### SERVER MANIFEST ###############################

server.manifest: server.manifest.template
	gramine-manifest \
		-Dlog_level=$(GRAMINE_LOG_LEVEL) \
		-Darch_libdir=$(ARCH_LIBDIR) \
		-Dra_type=$(RA_TYPE) \
		-Dra_client_spid=$(RA_CLIENT_SPID) \
		-Dra_client_linkable=$(RA_CLIENT_LINKABLE) \
		$< > $@

# Make on Ubuntu <= 20.04 doesn't support "Rules with Grouped Targets" (`&:`),
# see the helloworld example for details on this workaround.
server.manifest.sgx server.sig: sgx_sign_server
	@:

.INTERMEDIATE: sgx_sign_server
sgx_sign_server: server.manifest server
	gramine-sgx-sign \
		--manifest $< \
		--output $<.sgx

########################### CLIENT (DCAP) MANIFEST ############################

client_dcap.manifest: client.manifest.template
	gramine-manifest \
		-Dlog_level=$(GRAMINE_LOG_LEVEL) \
		-Darch_libdir=$(ARCH_LIBDIR) \
		$< >$@

client_dcap.manifest.sgx client_dcap.sig: sgx_sign_client_dcap
	@:

.INTERMEDIATE: sgx_sign_client_dcap
sgx_sign_client_dcap: client_dcap.manifest client
	gramine-sgx-sign \
		--manifest $< \
		--output $<.sgx

########################### CLIENT (EPID) MANIFEST ############################

client_epid.manifest: client.manifest.template
	gramine-manifest \
		-Dlog_level=$(GRAMINE_LOG_LEVEL) \
		-Darch_libdir=$(ARCH_LIBDIR) \
		$< >$@

client_epid.manifest.sgx client_epid.sig: sgx_sign_client_epid
	@:

.INTERMEDIATE: sgx_sign_client_epid
sgx_sign_client_epid: client_epid.manifest client
	gramine-sgx-sign \
		--manifest $< \
		--output $<.sgx

############################### SGX CHECKS FOR CI #############################

.PHONY: check_epid
check_epid: app epid
	gramine-sgx server & SERVER_ID=$$!; \
	sleep 30; \
	./client epid > OUTPUT; \
	./client epid 0 0 0 0 >> OUTPUT; \
	kill -9 $$SERVER_ID
	@grep -q "using default SGX-measurement verification callback" OUTPUT && echo "[ Success 1/4 ]"
	@grep -q "using our own SGX-measurement verification callback" OUTPUT && echo "[ Success 2/4 ]"
	@grep -q "Verifying peer X.509 certificate... ok" OUTPUT && echo "[ Success 3/4 ]"
	@(exit `grep -c "failed" "OUTPUT"`) && echo "[ Success 4/4 ]"
	@rm OUTPUT

.PHONY: check_epid_fail
check_epid_fail: app epid
	gramine-sgx server --test-malicious-quote >/dev/null & SERVER_ID=$$!; \
	sleep 30; \
	./client epid && exit 1 || echo "[ Success 1/1 ]"; \
	kill -9 $$SERVER_ID

.PHONY: check_dcap
check_dcap: app dcap
	gramine-sgx server >/dev/null & SERVER_ID=$$!; \
	sleep 30; \
	./client dcap > OUTPUT; \
	./client dcap 0 0 0 0 >> OUTPUT; \
	kill -9 $$SERVER_ID
	@grep -q "using default SGX-measurement verification callback" OUTPUT && echo "[ Success 1/4 ]"
	@grep -q "using our own SGX-measurement verification callback" OUTPUT && echo "[ Success 2/4 ]"
	@grep -q "Verifying peer X.509 certificate... ok" OUTPUT && echo "[ Success 3/4 ]"
	@(exit `grep -c "failed" "OUTPUT"`) && echo "[ Success 4/4 ]"
	@rm OUTPUT

.PHONY: check_dcap_fail
check_dcap_fail: app dcap
	gramine-sgx server --test-malicious-quote >/dev/null & SERVER_ID=$$!; \
	sleep 30; \
	./client dcap && exit 1 || echo "[ Success 1/1 ]"; \
	kill -9 $$SERVER_ID

################################## CLEANUP ####################################

.PHONY: clean
clean:
	$(RM) -r \
		*.token *.sig *.manifest.sgx *.manifest server client *.so *.so.* OUTPUT

.PHONY: distclean
distclean: clean
	$(RM) -r ssl/ca.* ssl/server.*
