RA_TYPE ?= dcap

.PHONY: check
check: check-cat-pem check-cat-der

gramine-ratls-cat-pem.manifest: gramine-ratls-cat.manifest.template
	gramine-manifest \
		-Dentrypoint=$$(command -v gramine-ratls) \
		-Dformat=-P \
		-Dlog_level=$(if $(intcmp $(DEBUG),0,1),debug,error) \
		-Dra_type=$(RA_TYPE) \
		-Dra_client_spid=$(RA_CLIENT_SPID) \
		-Dra_client_linkable=$(RA_CLIENT_LINKABLE) \
		$< > $@

gramine-ratls-cat-der.manifest: gramine-ratls-cat.manifest.template
	gramine-manifest \
		-Dentrypoint=$$(command -v gramine-ratls) \
		-Dformat=-D \
		-Dlog_level=$(if $(intcmp $(DEBUG),0,1),debug,error) \
		-Dra_type=$(RA_TYPE) \
		-Dra_client_spid=$(RA_CLIENT_SPID) \
		-Dra_client_linkable=$(RA_CLIENT_LINKABLE) \
		$< > $@

%.manifest.sgx %.sig: %.manifest
	gramine-sgx-sign \
		--manifest $< \
		--output $@

.PHONY: check-cat-pem
check-cat-pem: gramine-ratls-cat-pem.manifest.sgx gramine-ratls-cat-pem.sig
	gramine-sgx gramine-ratls-cat-pem \
	| openssl x509 -inform pem -noout -text \
	| grep -q 'Subject: CN = RATLS, O = GramineDevelopers' \
	&& echo 'OK (PEM)'

.PHONY: check-cat-der
check-cat-der: gramine-ratls-cat-der.manifest.sgx gramine-ratls-cat-der.sig
	gramine-sgx gramine-ratls-cat-der \
	| openssl x509 -inform der -noout -text \
	| grep -q 'Subject: CN = RATLS, O = GramineDevelopers' \
	&& echo 'OK (DER)'

# TODO: check-nginx

.PHONY: clean
clean:
	$(RM) -r \
		*.manifest \
		*.manifest.sgx \
		*.sig \
		*.token
