KVER := $(shell uname -r)
KDIR ?= /lib/modules/$(KVER)/build

default:
	$(MAKE) -C $(KDIR) M=$$PWD

install:
	$(MAKE) -C $(KDIR) M=$$PWD modules_install
	cp -f gramine_test_dev_ioctl.h /usr/local/include/

clean:
	$(MAKE) -C $(KDIR) M=$$PWD clean
