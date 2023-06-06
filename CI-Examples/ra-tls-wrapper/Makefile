RA_TYPE ?= dcap

.PHONY: check
check: check-cat

gramine-ratls-cat.manifest: gramine-ratls-cat.manifest.template
	gramine-manifest \
		-Dentrypoint=$$(command -v gramine-ratls) \
		-Dlog_level=$(if $(intcmp $(DEBUG),0,1),debug,error) \
		-Dra_type=$(RA_TYPE) \
		-Dra_client_spid=$(RA_CLIENT_SPID) \
		-Dra_client_linkable=$(RA_CLIENT_LINKABLE) \
		$< > $@

gramine-ratls-cat.manifest.sgx gramine-ratls-cat.sig: gramine-ratls-cat.manifest
	gramine-sgx-sign \
		--manifest $< \
		--output $@

.PHONY: check-cat
check-cat: gramine-ratls-cat.manifest.sgx gramine-ratls-cat.sig
	gramine-sgx gramine-ratls-cat \
	| openssl x509 -inform der -noout -text \
	| grep -q 'Subject: CN = RATLS, O = GramineDevelopers'

# TODO: check-nginx

.PHONY: clean
clean:
	$(RM) -r \
		*.manifest \
		*.manifest.sgx \
		*.sig \
		*.token
