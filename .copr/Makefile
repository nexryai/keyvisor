.PHONY: srpm

project_root := $(abspath $(dir $(lastword $(MAKEFILE_LIST)))/..)
spec ?= $(project_root)/keyvisor.spec

srpm:
	dnf -y install cargo rpm-build xz
	"$(project_root)/build-aux/srpm.sh" "$(outdir)" "$(spec)"
