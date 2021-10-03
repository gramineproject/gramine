
.PHONY: all
all:
	@echo Please build and install Graphene using Meson!
	@echo See https://gramine.readthedocs.io/en/latest/building.html for more details.

.PHONY: clean
clean:
	$(MAKE) -C LibOS clean
	$(MAKE) -C Scripts clean
