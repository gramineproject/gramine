GRAMINEDIR ?= ../..
RA_TYPE ?= dcap

CFLAGS = -Wall -Wextra -I$(GRAMINEDIR)/pal/src/host/linux-sgx

ifeq ($(DEBUG),1)
GRAMINE_LOG_LEVEL = debug
CFLAGS += -g
else
GRAMINE_LOG_LEVEL = error
CFLAGS += -O3
endif

.PHONY: all
all: kss-helloworld.manifest.sgx kss-helloworld.sig kss-helloworld.token

kss-helloworld: kss-helloworld.o

kss-helloworld.o: kss-helloworld.c

kss-helloworld.manifest: kss-helloworld.manifest.template
	gramine-manifest \
		-Dlog_level=$(GRAMINE_LOG_LEVEL) \
		-Dra_type=$(RA_TYPE) \
		$< $@

# gramine-sgx-sign generates both a .sig file and a .manifest.sgx file. This is somewhat
# hard to express properly in Make. The simple solution would be to use
# "Rules with Grouped Targets" (`&:`), however make on Ubuntu <= 20.04 doesn't support it.
#
# Simply using a normal rule with "two targets" is equivalent to creating separate rules
# for each of the targets, and when using `make -j`, this might cause two instances
# of gramine-sgx-sign to get launched simultaneously, potentially breaking the build.
#
# As a workaround, we use a dummy intermediate target, and mark both files as depending on it, to
# get the dependency graph we want. We mark this dummy target as .INTERMEDIATE, which means
# that make will consider the source tree up-to-date even if the sgx_sign file doesn't exist,
# as long as the other dependencies check out. This is in contrast to .PHONY, which would
# be rebuilt on every invocation of make.
kss-helloworld.sig kss-helloworld.manifest.sgx: sgx_sign
	@:

.INTERMEDIATE: sgx_sign
sgx_sign: kss-helloworld.manifest kss-helloworld
	gramine-sgx-sign \
		--manifest $< \
		--output $<.sgx

kss-helloworld.token: kss-helloworld.sig
	gramine-sgx-get-token \
		--output $@ --sig $<

GRAMINE = gramine-sgx

.PHONY: check
check: all
	$(GRAMINE) kss-helloworld

.PHONY: clean
clean:
	$(RM) *.token *.sig *.manifest.sgx *.manifest kss-helloworld.o kss-helloworld OUTPUT

.PHONY: distclean
distclean: clean
