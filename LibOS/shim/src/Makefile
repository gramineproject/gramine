gramine_lib = .lib/gramine-lib.a

.PHONY: all
all: gramine_lib_recurse

.PHONY: gramine_lib_recurse
gramine_lib_recurse:
	CFLAGS="-DIN_SHIM" $(MAKE) -C ../../../common/src target=$(abspath .lib)/

.PHONY: clean
clean:
	$(RM) -r .lib

.PHONY: distclean
distclean: clean
