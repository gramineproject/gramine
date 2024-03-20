AZURESSHPRVKEYFILE ?= ~/cvm_key.pem
AZURESSHIP ?= 127.0.0.1

APPNAME := app
APPVERSION := 0.7

GRAMINEMANIFEST := gramine.manifest
ITA_SERVER := api.trustauthority.intel.com
ITA_IP := $(shell dig +short $(ITA_SERVER) | tail -1)
ITA_CA_CERT := $(shell openssl s_client -showcerts -connect $(ITA_SERVER):443 </dev/null 2>/dev/null | awk '/BEGIN CERTIFICATE/,/END CERTIFICATE/{ if(/BEGIN CERTIFICATE/){a++}; if (a>1) {print} }' | tr '\n' '\r')
ITA_API_KEY :=

APPIMAGETAGNAME := $(APPNAME):$(APPVERSION)
GSCAPPIMAGETAGNAME := gsc-$(APPNAME):$(APPVERSION)

GSC_GITURL := https://github.com/gramineproject/gsc.git
GSC_GITCOMMIT := c0be56daaa5a3a8a94f1b9c11a241100fec18b4b

.PHONY: all gsc-app docker-app test-app deploy clean

all: gsc-app

init-manifest: | gramine.manifest.in
ifeq (,$(wildcard $(GRAMINEMANIFEST)))
	@cp $| $(GRAMINEMANIFEST)
	@sed -i 's/<ITA_SERVER>/$(ITA_SERVER)/g' $(GRAMINEMANIFEST)
	@sed -i 's/<ITA_IP>/$(ITA_IP)/g' $(GRAMINEMANIFEST)
	@sed -i 's/<ITA_API_KEY>/$(ITA_API_KEY)/g' $(GRAMINEMANIFEST)
	@sed -i 's!<ITA_CA_CERT>!$(ITA_CA_CERT)!g' $(GRAMINEMANIFEST)
	@sed -i '/^-----BEGIN CERTIFICATE-----/s/\r/\n/g' $(GRAMINEMANIFEST)
	@sed -i '/^$$/d' $(GRAMINEMANIFEST)
else
	$(error "$(GRAMINEMANIFEST) already exists")
endif

setup-gsc:
	rm -rf gsc
	git clone $(GSC_GITURL) && cd gsc && git checkout $(GSC_GITCOMMIT)
	cp config.yaml gsc/

gsc-app: $(GRAMINEMANIFEST) setup-gsc docker-app
	cp gramine.manifest gsc/
	cd gsc; \
	openssl genrsa -3 -out gramine-enclave-key.pem 3072 && \
	./gsc build --no-cache --rm $(APPIMAGETAGNAME) gramine.manifest && \
	./gsc sign-image $(APPIMAGETAGNAME) gramine-enclave-key.pem

docker-app:
	cd app; \
	cat Dockerfile | docker build \
		-t $(APPIMAGETAGNAME) \
		--progress=plain \
		-f - .

test-app:
	$(info [NOTICE] It is expected to fail as lack of device files needed.)
	docker run --rm $(APPIMAGETAGNAME) || [ $$? -eq 255 ]

test-gsc-app:
	docker run --rm --device=/dev/sgx_enclave --device=/dev/sgx/enclave -v /var/run/aesmd/aesm.socket:/var/run/aesmd/aesm.socket $(GSCAPPIMAGETAGNAME)

deploy:
	@echo "AZURE ssh private key file: $(AZURESSHPRVKEYFILE)"
	@echo "AZURE ssh ip address: $(AZURESSHIP)"
ifeq ($(shell docker image inspect $(GSCAPPIMAGETAGNAME) 2> /dev/null > /dev/null; echo $$?), 0)
	@echo Preparing $(GSCAPPIMAGETAGNAME) for deployment
	@docker save $(GSCAPPIMAGETAGNAME) | bzip2 | pv | ssh -i $(AZURESSHPRVKEYFILE) azureuser@$(AZURESSHIP) docker load
else
	$(error $(GSCAPPIMAGETAGNAME) not found)
endif

clean:
	@rm -rf gsc
	@echo "Please manually clean up your docker images before re-building it."
