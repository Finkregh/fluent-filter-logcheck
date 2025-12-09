# frozen_string_literal: true

lib = File.expand_path('lib', __dir__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)

Gem::Specification.new do |spec|
  spec.name          = 'fluent-plugin-logcheck'
  spec.version       = '0.1.0'
  spec.authors       = ['Oluf Lorenzen']
  spec.email         = ['finkregh+githubfluentdlogecheck@mafia-server.net']

  spec.summary       = 'Fluentd filter plugin that applies logcheck rules for log filtering and security monitoring'
  spec.description   = 'A Fluentd filter plugin that implements logcheck functionality, allowing users to filter and categorize log entries based on predefined regular expression rules. Supports ignore, cracking, and violations rule types with proper precedence handling.'
  spec.homepage      = 'https://github.com/finkregh/fluent-plugin-logcheck'
  spec.license       = 'Apache-2.0'

  spec.files         = Dir[
    'lib/**/*',
    'README.md',
    'CHANGELOG.md',
    'LICENSE',
    'fluent-plugin-logcheck.gemspec',
    'examples/**/*',
    'docs/**/*'
  ]
  spec.bindir        = 'exe'
  spec.executables   = spec.files.grep(%r{^bin/}) { |f| File.basename(f) }
  spec.require_paths = ['lib']

  spec.required_ruby_version = '>= 2.4.0'

  # Runtime dependencies
  spec.add_dependency 'fluentd', ['>= 0.14.10', '< 2']
end
