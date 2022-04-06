get_token_features = []

if sgx_driver == 'oot'
  get_token_features += ['--features', 'oot']
endif

custom_target(
  'gramine-sgx-get-token',
  input: 'Cargo.toml',
  output: 'gramine-sgx-get-token',
  depfile: 'gramine-sgx-get-token.d',
  command: run_cargo_cmd + get_token_features,
  install: true,
  install_dir: get_option('bindir'),
  console: true,
)
