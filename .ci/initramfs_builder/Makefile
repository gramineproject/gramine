.PHONY: all
all: initramfs.cpio.gz

BUSYBOX_MIRRORS := https://busybox.net/downloads
BUSYBOX_FNAME := busybox-1.34.1
BUSYBOX_PACKED_EXT := .tar.bz2
BUSYBOX_SHA256 := 415fbd89e5344c96acf449d94a6f956dbed62e18e835fc83e064db33a34bd549
BUSYBOX_SRC_DIR := src

INITRAMFS_DIR := initramfs

busybox$(BUSYBOX_PACKED_EXT):
	../../scripts/download --output $@ --sha256 $(BUSYBOX_SHA256) \
		$(foreach mirror,$(BUSYBOX_MIRRORS),--url $(mirror)/$(BUSYBOX_FNAME)$(BUSYBOX_PACKED_EXT))

$(BUSYBOX_SRC_DIR)/.unpacked: busybox$(BUSYBOX_PACKED_EXT)
	$(RM) -r $(BUSYBOX_SRC_DIR)
	mkdir $(BUSYBOX_SRC_DIR)
	tar -C $(BUSYBOX_SRC_DIR) --strip-components=1 -xf $<
	touch $@

$(BUSYBOX_SRC_DIR)/.config: $(BUSYBOX_SRC_DIR)/.unpacked
	$(MAKE) -C $(BUSYBOX_SRC_DIR) clean
	$(MAKE) -C $(BUSYBOX_SRC_DIR) defconfig
	sed -e 's/.*CONFIG_STATIC is not set.*/CONFIG_STATIC=y/' -i $@

$(BUSYBOX_SRC_DIR)/busybox: $(BUSYBOX_SRC_DIR)/.config
	$(MAKE) -C $(BUSYBOX_SRC_DIR)

$(BUSYBOX_SRC_DIR)/_install/bin/busybox: $(BUSYBOX_SRC_DIR)/busybox
	$(MAKE) -C $(BUSYBOX_SRC_DIR) install

$(INITRAMFS_DIR)/bin/busybox: $(BUSYBOX_SRC_DIR)/_install/bin/busybox
	$(RM) -r $(INITRAMFS_DIR) && mkdir $(INITRAMFS_DIR)
	cp -r $(BUSYBOX_SRC_DIR)/_install/. $(INITRAMFS_DIR)

INIT_FILES := init new_init

$(addprefix $(INITRAMFS_DIR)/,$(INIT_FILES)): $(INITRAMFS_DIR)/%: % $(INITRAMFS_DIR)/bin/busybox
	cp $< $@

# This might generate duplicate commands, which will throw some warning when executed. Since getting
# rid of duplicates in bash would be cumbersome and these warnings are harmless, we leave it as is.
insert_modules.sh:
	modprobe --show-depends 9p > $@
	modprobe --show-depends 9pnet_virtio >> $@
	modprobe --show-depends overlay >> $@
	sed -i '/builtin/d' $@

$(INITRAMFS_DIR)/insert_modules.sh: insert_modules.sh $(INITRAMFS_DIR)/bin/busybox
	mkdir -p $(INITRAMFS_DIR)/modules
	cp -t $(INITRAMFS_DIR)/modules $(shell sed 's/insmod//' $< 2>/dev/null) || true
	sed 's/insmod \(.*\)\//insmod \/modules\//' $< > $@

initramfs.cpio.gz: $(addprefix $(INITRAMFS_DIR)/,$(INIT_FILES)) $(INITRAMFS_DIR)/insert_modules.sh
	cd $(INITRAMFS_DIR) && find . | cpio -o -H newc -R +0:+0 | gzip -9 > ../$@

.PHONY: clean
clean:
	$(RM) -r $(INITRAMFS_DIR) initramfs.cpio.gz insert_modules.sh

.PHONY: distclean
distclean: clean
	$(RM) -r busybox$(BUSYBOX_PACKED_EXT) $(BUSYBOX_SRC_DIR)
