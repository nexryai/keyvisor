systemd = dependency('systemd')
systemd_user_unit_dir = systemd.get_variable(pkgconfig: 'systemduserunitdir')

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
