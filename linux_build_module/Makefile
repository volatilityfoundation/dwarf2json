obj-m += module.o
KVER ?= $(shell uname -r)
KDIR ?= /lib/modules/$(KVER)/build/

-include version.mk

all: dwarf 

dwarf: module.c
	$(MAKE) -C $(KDIR) CONFIG_DEBUG_INFO=y M="$(PWD)" modules

clean:
	$(MAKE) -C $(KDIR) CONFIG_DEBUG_INFO=y M="$(PWD)" clean