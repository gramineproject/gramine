include ../../../../Scripts/Makefile.configs
include ../../../../Scripts/Makefile.rules

.PHONY: all
all: gdb_integration/sgx_gdb.so quote/aesm.pb-c.c quote/aesm.pb-c.h gsgx.h

gdb_integration/sgx_gdb.so: CFLAGS =
CFLAGS-gdb_integration/sgx_gdb.so = -shared -Wall -fPIC -O2 -std=c11
gdb_integration/sgx_gdb.so: gdb_integration/sgx_gdb.c
	$(call cmd,csingle)

quote/aesm.pb-c.c quote/aesm.pb-c.h: quote/aesm.proto
	@echo [ host/Linux-SGX/quote/aesm.pb-c.c ]
	@echo [ host/Linux-SGX/quote/aesm.pb-c.h ]
	@protoc-c --c_out=. $<

gsgx.h: gsgx.h.in
	./link-intel-driver.py --input $< --output $@

CLEAN_FILES += gdb_integration/sgx_gdb.so
CLEAN_FILES += quote/aesm.pb-c.c quote/aesm.pb-c.h
CLEAN_FILES += gsgx.h

.PHONY: clean
clean:
	$(RM) -r *.o *.e *.i *.s $(host_files) $(CLEAN_FILES) *.d gdb_integration/*.d signer/*.pyc \
	         __pycache__ signer/__pycache__

.PHONY: distclean
distclean: clean
	@:
