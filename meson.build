project(
  'keyvisor',
  version: '0.1.0',
  meson_version: '>= 1.3.0',
)

cargo = find_program('cargo')
cargo_builder = find_program('build-aux/cargo-build.sh')

cargo_profile = get_option('cargo-profile')
if cargo_profile == 'auto'
  cargo_profile = 'debug'
  if get_option('buildtype') == 'release'
    cargo_profile = 'release'
  endif
endif

custom_target(
  'keyvisor',
  output: ['keyvisor', 'keyvisor-agent'],
  command: [
    cargo_builder,
    meson.project_source_root(),
    meson.project_build_root(),
    cargo_profile,
  ],
  build_always_stale: true,
  build_by_default: true,
  install: true,
  install_dir: get_option('bindir'),
)

run_target(
  'cargo-build',
  command: [
    cargo,
    'build',
    '--manifest-path', meson.project_source_root() / 'Cargo.toml',
    '--workspace',
  ],
)

run_target(
  'cargo-test',
  command: [
    cargo,
    'test',
    '--manifest-path', meson.project_source_root() / 'Cargo.toml',
    '--workspace',
  ],
)

subdir('data')
