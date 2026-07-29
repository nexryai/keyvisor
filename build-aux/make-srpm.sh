#!/usr/bin/bash
set -euo pipefail

project_root=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
output_dir=${1:-"${project_root}/dist"}
spec_file=${2:-"${project_root}/keyvisor.spec"}

for command_name in cargo rpmbuild tar xz; do
    if ! command -v "${command_name}" >/dev/null 2>&1; then
        echo "Required command is not installed: ${command_name}" >&2
        exit 1
    fi
done

mkdir -p -- "${output_dir}"
output_dir=$(CDPATH= cd -- "${output_dir}" && pwd)
rpm_topdir="${output_dir}/rpmbuild"
mkdir -p -- \
    "${rpm_topdir}/BUILD" \
    "${rpm_topdir}/BUILDROOT" \
    "${rpm_topdir}/RPMS" \
    "${rpm_topdir}/SOURCES" \
    "${rpm_topdir}/SPECS" \
    "${rpm_topdir}/SRPMS"

"${project_root}/build-aux/make-dist.sh" "${output_dir}"

# Keeping SOURCES and SRPMS together makes the result easy to upload to COPR.
rpmbuild \
    -bs "${spec_file}" \
    --define "_topdir ${rpm_topdir}" \
    --define "_sourcedir ${output_dir}" \
    --define "_srcrpmdir ${output_dir}"
