RA_TYPE ?= dcap

ifeq ($(DEBUG),1)
GRAMINE_LOG_LEVEL = debug
else
GRAMINE_LOG_LEVEL = error
endif

.PHONY: check
check: check-cat-pem check-cat-der

gramine-ratls-cat-%.manifest: gramine-ratls-cat.manifest.template
	gramine-manifest \
		-Dentrypoint=$$(command -v gramine-ratls) \
		-Dlog_level=$(GRAMINE_LOG_LEVEL) \
		-Dra_type=$(RA_TYPE) \
		-Dra_client_spid=$(RA_CLIENT_SPID) \
		-Dra_client_linkable=$(RA_CLIENT_LINKABLE) \
		$(GRAMINE_MANIFEST_OPTS) \
		$< > $@

gramine-ratls-cat-pem.manifest: GRAMINE_MANIFEST_OPTS = -Dformat=-P
gramine-ratls-cat-der.manifest: GRAMINE_MANIFEST_OPTS = -Dformat=-D

%.manifest.sgx %.sig: sgx-sign-%
	@:

.INTERMEDIATE: sgx-sign-%
sgx-sign-%: %.manifest
	gramine-sgx-sign \
		--manifest $< \
		--output $<.sgx

.PHONY: check-cat-%
check-cat-%: gramine-ratls-cat-%.manifest.sgx gramine-ratls-cat-%.sig
	gramine-sgx gramine-ratls-cat-$* \
		| openssl x509 -inform $* -noout -text \
		| grep -q 'Subject: CN = RATLS, O = GramineDevelopers' \
		&& echo OK - $@

.PHONY: clean
clean:
	$(RM) -r \
		*.manifest \
		*.manifest.sgx \
		*.sig \
		*.token
