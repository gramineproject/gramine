graphene_lib = .lib/graphene-lib.a

.PHONY: all
all: graphene_lib_recurse

.PHONY: graphene_lib_recurse
graphene_lib_recurse:
	CFLAGS="-DIN_SHIM" $(MAKE) -C ../../../common/src target=$(abspath .lib)/

.PHONY: clean
clean:
	$(RM) -r .lib

.PHONY: distclean
distclean: clean
