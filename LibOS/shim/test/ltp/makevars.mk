# Everything here must be absolute because other Makefiles assume this.
ROOTDIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

INSTALLDIR = $(ROOTDIR)/install
TESTCASEDIR = $(INSTALLDIR)/testcases/bin
LTPSCENARIO = $(INSTALLDIR)/runtest/syscalls
RUNLTPOPTS =
