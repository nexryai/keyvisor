.PHONY: srpm

spec ?= keyvisor.spec

srpm:
	# The make_srpm stage is networked and runs separately from the offline RPM build.
	dnf -y install cargo rpm-build xz
	./build-aux/make-srpm.sh "$(outdir)" "$(spec)"
