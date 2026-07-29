datadir = get_option('datadir')
systemd = dependency('systemd')
systemd_user_unit_dir = systemd.get_variable(pkgconfig: 'systemduserunitdir')

install_data(
  'me.nexryai.keyvisor.desktop',
  install_dir: datadir / 'applications',
)

install_data(
  'me.nexryai.keyvisor.metainfo.xml',
  install_dir: datadir / 'metainfo',
)

install_data(
  'icons/hicolor/scalable/apps/me.nexryai.keyvisor.svg',
  install_dir: datadir / 'icons/hicolor/scalable/apps',
)

install_data(
  'icons/hicolor/symbolic/apps/me.nexryai.keyvisor-symbolic.svg',
  install_dir: datadir / 'icons/hicolor/symbolic/apps',
)

service_configuration = configuration_data()
service_configuration.set(
  'bindir',
  get_option('prefix') / get_option('bindir'),
)

configure_file(
  input: 'me.nexryai.keyvisor-agent.service.in',
  output: 'me.nexryai.keyvisor-agent.service',
  configuration: service_configuration,
  install: true,
  install_dir: systemd_user_unit_dir,
)

install_data(
  'me.nexryai.keyvisor-agent.socket',
  install_dir: systemd_user_unit_dir,
)
