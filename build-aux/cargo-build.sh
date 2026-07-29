#!/bin/sh
set -eu

source_root=$1
build_root=$2
profile=$3
target_dir=${CARGO_TARGET_DIR:-"$build_root/cargo-target"}
manifest="$source_root/Cargo.toml"

if [ "$profile" = "release" ]; then
  CARGO_TARGET_DIR="$target_dir" cargo build \
    --locked \
    --manifest-path "$manifest" \
    --package keyvisor-ui \
    --package keyvisor-agent \
    --release
else
  CARGO_TARGET_DIR="$target_dir" cargo build \
    --locked \
    --manifest-path "$manifest" \
    --package keyvisor-ui \
    --package keyvisor-agent
fi

install -m 0755 "$target_dir/$profile/keyvisor" "$build_root/keyvisor"
install -m 0755 "$target_dir/$profile/keyvisor-agent" "$build_root/keyvisor-agent"
