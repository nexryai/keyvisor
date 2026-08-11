#!/usr/bin/bash
set -euo pipefail

project_root=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
output_dir=${1:-"${project_root}/dist"}
version=$(
    sed -n \
        '/^\[workspace\.package\]/,/^\[/s/^version = "\([^"]*\)"/\1/p' \
        "${project_root}/Cargo.toml"
)
spec_version=$(
    sed -n 's/^Version:[[:space:]]*//p' "${project_root}/keyvisor.spec"
)

if [[ -z ${version} ]]; then
    echo "Could not read the workspace version from Cargo.toml." >&2
    exit 1
fi
if [[ ${spec_version} != "${version}" ]]; then
    echo "Cargo.toml and keyvisor.spec versions must match." >&2
    exit 1
fi

archive_root="keyvisor-${version}"
source_date_epoch=${SOURCE_DATE_EPOCH:-0}
work_dir=$(mktemp -d)
source_archive="${work_dir}/${archive_root}.tar.xz"
vendor_archive="${work_dir}/${archive_root}-vendor.tar.xz"

cleanup() {
    rm -rf -- "${work_dir}"
}
trap cleanup EXIT

mkdir -p -- "${output_dir}"

# secretive/ is a design reference and must never become part of a release.
tar \
    --create \
    --xz \
    --file "${source_archive}" \
    --directory "${project_root}" \
    --exclude='./.agents' \
    --exclude='./.codex' \
    --exclude='./.git' \
    --exclude='./build' \
    --exclude='./dist' \
    --exclude='./rpmbuild' \
    --exclude='./secretive' \
    --exclude='./target' \
    --exclude='./vendor' \
    --sort=name \
    --mtime="@${source_date_epoch}" \
    --clamp-mtime \
    --owner=0 \
    --group=0 \
    --numeric-owner \
    --transform "s,^\.,${archive_root}," \
    .

# Cargo's checksum files let the offline RPM build verify every vendored crate.
cargo vendor \
    --quiet \
    --locked \
    --versioned-dirs \
    "${work_dir}/vendor" \
    --manifest-path "${project_root}/Cargo.toml" \
    >/dev/null

tar \
    --create \
    --xz \
    --file "${vendor_archive}" \
    --directory "${work_dir}" \
    --sort=name \
    --mtime="@${source_date_epoch}" \
    --clamp-mtime \
    --owner=0 \
    --group=0 \
    --numeric-owner \
    vendor

install -m0644 "${source_archive}" "${output_dir}/${archive_root}.tar.xz"
install -m0644 "${vendor_archive}" "${output_dir}/${archive_root}-vendor.tar.xz"
sha256sum \
    "${output_dir}/${archive_root}.tar.xz" \
    "${output_dir}/${archive_root}-vendor.tar.xz"
