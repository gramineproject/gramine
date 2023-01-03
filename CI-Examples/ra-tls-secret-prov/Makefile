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

.PHONY: clients
clients: secret_prov_minimal/client secret_prov/client secret_prov_pf/client

.PHONY: all
all: app epid  # by default, only build EPID because it doesn't rely on additional (DCAP) libs

.PHONY: app
app: \
     ssl/server.crt \
     secret_prov_minimal/client.manifest.sgx secret_prov_minimal/client.sig \
     secret_prov/client.manifest.sgx     secret_prov/client.sig \
     secret_prov_pf/client.manifest.sgx  secret_prov_pf/client.sig

.PHONY: epid
epid: ssl/server.crt secret_prov_minimal/server_epid secret_prov/server_epid secret_prov_pf/server_epid \
      secret_prov_pf/wrap_key secret_prov_pf/enc_files/input.txt

.PHONY: dcap
dcap: ssl/server.crt secret_prov_minimal/server_dcap secret_prov/server_dcap secret_prov_pf/server_dcap \
      secret_prov_pf/wrap_key secret_prov_pf/enc_files/input.txt

############################# SSL DATA DEPENDENCY #############################

# SSL data: key and x.509 self-signed certificate
ssl/server.crt: ssl/ca_config.conf
	openssl genrsa -out ssl/ca.key 2048
	openssl req -x509 -new -nodes -key ssl/ca.key -sha256 -days 1024 -out ssl/ca.crt -config ssl/ca_config.conf
	openssl genrsa -out ssl/server.key 2048
	openssl req -new -key ssl/server.key -out ssl/server.csr -config ssl/ca_config.conf
	openssl x509 -req -days 360 -in ssl/server.csr -CA ssl/ca.crt -CAkey ssl/ca.key -CAcreateserial -out ssl/server.crt

######################### CLIENT/SERVER EXECUTABLES ###########################

# Use hard-coded GRAMINEDIR because we currently fail to provide secret prov headers in Gramine
# installation. We also use `mbedtls_gramine` pkg-config because we don't have a secret prov one.
# TODO: Create a pkg-config file for secretprov_gramine libs, and use it in below
#       CFLAGS/LDFLAGS lines (via `pkg-config {--cflags|--libs} secretprov_gramine`).
GRAMINEDIR ?= ../..
CFLAGS += -Wall -std=c11 -I$(GRAMINEDIR)/tools/sgx/ra-tls
LDFLAGS += -Wl,--enable-new-dtags $(shell pkg-config --libs mbedtls_gramine)

%/server_epid: %/server.c
	$(CC) $< $(CFLAGS) $(LDFLAGS) -lsecret_prov_verify_epid -pthread -o $@

# linker option --no-as-needed is required because SGX DCAP library (libsgx_dcap_quoteverify.so)
# does dlopen() instead of directly linking against libsgx_urts.so, and without this option
# compilers remove the "seemingly unused" libsgx_urts.so
%/server_dcap: %/server.c
	$(CC) $< $(CFLAGS) $(LDFLAGS) -Wl,--no-as-needed -lsgx_urts -lsecret_prov_verify_dcap -pthread -o $@

secret_prov/client: secret_prov/client.c
	$(CC) $< $(CFLAGS) $(LDFLAGS) -lsecret_prov_attest -o $@

secret_prov_minimal/client: secret_prov_minimal/client.c
	$(CC) $< $(CFLAGS) $(LDFLAGS) -o $@

secret_prov_pf/client: secret_prov_pf/client.c
	$(CC) $< $(CFLAGS) $(LDFLAGS) -o $@

############################# MIN CLIENT MANIFEST #############################

# TODO: Simplify after https://github.com/gramineproject/gramine/issues/878 is fixed (manifest paths
#       should be relative to the manifest, not to current dir) - drop `cd` and `notdir`.
secret_prov_minimal/client.manifest: secret_prov_minimal/client.manifest.template
	cd secret_prov_minimal && \
	gramine-manifest \
		-Dlog_level=$(GRAMINE_LOG_LEVEL) \
		-Darch_libdir=$(ARCH_LIBDIR) \
		-Dra_type=$(RA_TYPE) \
		-Dra_client_spid=$(RA_CLIENT_SPID) \
		-Dra_client_linkable=$(RA_CLIENT_LINKABLE) \
		$(notdir $<) > $(notdir $@)

# Make on Ubuntu <= 20.04 doesn't support "Rules with Grouped Targets" (`&:`),
# see the helloworld example for details on this workaround.
secret_prov_minimal/client.manifest.sgx secret_prov_minimal/client.sig: sgx_sign_secret_prov_minimal_client
	@:

.INTERMEDIATE: sgx_sign_secret_prov_minimal_client
sgx_sign_secret_prov_minimal_client: secret_prov_minimal/client.manifest secret_prov_minimal/client
	cd secret_prov_minimal && \
	gramine-sgx-sign \
		--manifest $(notdir $<) \
		--output $(notdir $<.sgx)

############################### CLIENT MANIFEST ###############################

secret_prov/client.manifest: secret_prov/client.manifest.template
	cd secret_prov && \
	gramine-manifest \
		-Dlog_level=$(GRAMINE_LOG_LEVEL) \
		-Darch_libdir=$(ARCH_LIBDIR) \
		-Dra_type=$(RA_TYPE) \
		-Dra_client_spid=$(RA_CLIENT_SPID) \
		-Dra_client_linkable=$(RA_CLIENT_LINKABLE) \
		$(notdir $<) > $(notdir $@)

secret_prov/client.manifest.sgx secret_prov/client.sig: sgx_sign_secret_prov_client
	@:

.INTERMEDIATE: sgx_sign_secret_prov_client
sgx_sign_secret_prov_client: secret_prov/client.manifest secret_prov/client
	cd secret_prov && \
	gramine-sgx-sign \
		--manifest $(notdir $<) \
		--output $(notdir $<.sgx)

############################## PF CLIENT MANIFEST #############################

secret_prov_pf/client.manifest: secret_prov_pf/client.manifest.template
	cd secret_prov_pf && \
	gramine-manifest \
		-Dlog_level=$(GRAMINE_LOG_LEVEL) \
		-Darch_libdir=$(ARCH_LIBDIR) \
		-Dra_type=$(RA_TYPE) \
		-Dra_client_spid=$(RA_CLIENT_SPID) \
		-Dra_client_linkable=$(RA_CLIENT_LINKABLE) \
		$(notdir $<) > $(notdir $@)

secret_prov_pf/client.manifest.sgx secret_prov_pf/client.sig: sgx_sign_secret_prov_pf_client
	@:

.INTERMEDIATE: sgx_sign_secret_prov_pf_client
sgx_sign_secret_prov_pf_client: secret_prov_pf/client.manifest secret_prov_pf/client
	cd secret_prov_pf && \
	gramine-sgx-sign \
		--manifest $(notdir $<) \
		--output $(notdir $<.sgx)

########################## PREPARE PROTECTED FILES ############################

secret_prov_pf/wrap_key:
	dd if=/dev/urandom of=$@ bs=16 count=1

secret_prov_pf/enc_files/input.txt: secret_prov_pf/wrap_key secret_prov_pf/plain_files/input.txt
	cd secret_prov_pf && \
	gramine-sgx-pf-crypt encrypt -w wrap_key -i plain_files/input.txt -o enc_files/input.txt

############################# SGX CHECKS FOR CI ###############################

# Note: `wait_for_server` unfortunately causes the server to emit the following error:
#     client_connection: Secret Provisioning failed during mbedtls_ssl_handshake with error -29312
# It just means that there was an EOF before finishing SSL handshake, which is expected in this
# case.

.PHONY: check_epid
check_epid: app epid
	# secret_prov_minimal
	cd secret_prov_minimal; \
	./server_epid >/dev/null & SERVER_ID=$$!; \
	../../../scripts/wait_for_server 60 127.0.0.1 4433; \
	gramine-sgx client > ../OUTPUT; \
	kill -9 $$SERVER_ID;
	@grep -E "Received secret = 'A_SIMPLE_SECRET'" OUTPUT && echo "[ Success 1/4 ]"

	# secret_prov
	cd secret_prov; \
	./server_epid >/dev/null & SERVER_ID=$$!; \
	../../../scripts/wait_for_server 60 127.0.0.1 4433; \
	gramine-sgx client > ../OUTPUT; \
	kill -9 $$SERVER_ID;
	@grep -E "Received secret1 = 'FIRST_SECRET', secret2 = '42'" OUTPUT && echo "[ Success 2/4 ]"

	# secret_prov_pf
	cd secret_prov_pf; \
	./server_epid wrap_key >/dev/null & SERVER_ID=$$!; \
	../../../scripts/wait_for_server 60 127.0.0.1 4433; \
	gramine-sgx client > ../OUTPUT; \
	kill -9 $$SERVER_ID;
	@grep -E "\[parent\] Read from protected file: 'helloworld'" OUTPUT && echo "[ Success 3/4 ]"
	@grep -E "\[child\] Read from protected file: 'helloworld'" OUTPUT && echo "[ Success 4/4 ]"

	@rm OUTPUT

.PHONY: check_dcap
check_dcap: app dcap
	# secret_prov_minimal
	cd secret_prov_minimal; \
	./server_dcap >/dev/null & SERVER_ID=$$!; \
	../../../scripts/wait_for_server 60 127.0.0.1 4433; \
	gramine-sgx client > ../OUTPUT; \
	kill -9 $$SERVER_ID;
	@grep -E "Received secret = 'A_SIMPLE_SECRET'" OUTPUT && echo "[ Success 1/4 ]"

	# secret_prov
	cd secret_prov; \
	./server_dcap >/dev/null & SERVER_ID=$$!; \
	../../../scripts/wait_for_server 60 127.0.0.1 4433; \
	gramine-sgx client > ../OUTPUT; \
	kill -9 $$SERVER_ID;
	@grep -E "Received secret1 = 'FIRST_SECRET', secret2 = '42'" OUTPUT && echo "[ Success 2/4 ]"

	# secret_prov_pf
	cd secret_prov_pf; \
	./server_dcap wrap_key >/dev/null & SERVER_ID=$$!; \
	../../../scripts/wait_for_server 60 127.0.0.1 4433; \
	gramine-sgx client > ../OUTPUT; \
	kill -9 $$SERVER_ID;
	@grep -E "\[parent\] Read from protected file: 'helloworld'" OUTPUT && echo "[ Success 3/4 ]"
	@grep -E "\[child\] Read from protected file: 'helloworld'" OUTPUT && echo "[ Success 4/4 ]"

	@rm OUTPUT

################################## CLEANUP ####################################

.PHONY: clean
clean:
	$(RM) OUTPUT
	cd secret_prov_minimal; $(RM) client server_* *.token *.sig *.manifest.sgx *.manifest
	cd secret_prov;         $(RM) client server_* *.token *.sig *.manifest.sgx *.manifest
	cd secret_prov_pf;      $(RM) client server_* *.token *.sig *.manifest.sgx *.manifest

.PHONY: distclean
distclean: clean
	$(RM) -r secret_prov_pf/wrap_key secret_prov_pf/enc_files/input.txt ssl/ca.* ssl/server.*
