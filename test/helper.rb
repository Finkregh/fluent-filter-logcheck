# typed: false
# frozen_string_literal: true

$LOAD_PATH.unshift(File.expand_path('../lib', __dir__))

require 'test-unit'
require 'fluent/test'
require 'fluent/test/driver/filter'
require 'fluent/test/helpers'

# Enable coverage if requested
if ENV['COVERAGE']
  require 'simplecov'
  require 'simplecov-cobertura'

  SimpleCov.start do
    add_filter '/test/'
    add_filter '/vendor/'
    add_filter '/knowlege/'

    # Configure formatters for both HTML and Cobertura XML
    if ENV['CI']
      # In CI, generate both HTML and Cobertura XML
      formatter SimpleCov::Formatter::MultiFormatter.new([
                                                           SimpleCov::Formatter::HTMLFormatter,
                                                           SimpleCov::Formatter::CoberturaFormatter
                                                         ])
    else
      # Locally, just generate HTML to avoid XML parsing issues
      formatter SimpleCov::Formatter::HTMLFormatter
    end

    # Set minimum coverage thresholds (adjusted for current codebase)
    minimum_coverage 30
    minimum_coverage_by_file 20

    # Track branches for more detailed coverage
    enable_coverage :branch
  end
end

# Include test helpers
Test::Unit::TestCase.include(Fluent::Test::Helpers)
Test::Unit::TestCase.extend(Fluent::Test::Helpers)

# Test utilities
module TestUtils
  # Create a temporary file with given content
  def create_temp_file(content, filename = 'test_rules')
    file = Tempfile.new(filename)
    file.write(content)
    file.close
    file.path
  end

  # Create a temporary directory with rule files
  def create_temp_dir_with_rules(rules_by_file = {})
    dir = Dir.mktmpdir
    rules_by_file.each do |filename, content|
      File.write(File.join(dir, filename), content)
    end
    dir
  end

  # Clean up temporary files and directories
  def cleanup_temp_files(*paths)
    paths.each do |path|
      if File.directory?(path)
        FileUtils.rm_rf(path)
      else
        FileUtils.rm_f(path)
      end
    end
  end

  # Create sample logcheck rules for testing
  def sample_ignore_rules
    [
      '^(\w{3} [ :[:digit:]]{11}|[0-9T:.+-]{32}) [._[:alnum:]-]+ systemd\[[0-9]+\]: (Start|Stopp)ed .+\.$',
      '^(\w{3} [ :[:digit:]]{11}|[0-9T:.+-]{32}) [._[:alnum:]-]+ systemd\[[0-9]+\]: Reached target .+\.$'
    ].join("\n")
  end

  def sample_cracking_rules
    [
      '^(\w{3} [ :[:digit:]]{11}|[0-9T:.+-]{32}) [._[:alnum:]-]+ sshd\[[[:digit:]]+\]: Failed password for .* from [.:[:xdigit:]]+ port [[:digit:]]+ ssh2$',
      '^(\w{3} [ :[:digit:]]{11}|[0-9T:.+-]{32}) [._[:alnum:]-]+ sshd\[[[:digit:]]+\]: Invalid user .* from [.:[:xdigit:]]+$'
    ].join("\n")
  end

  def sample_violations_rules
    [
      '^(\w{3} [ :[:digit:]]{11}|[0-9T:.+-]{32}) [._[:alnum:]-]+ kernel:.*media error.*bad sector.*$',
      '^(\w{3} [ :[:digit:]]{11}|[0-9T:.+-]{32}) [._[:alnum:]-]+ kernel:.*I/O error.*$'
    ].join("\n")
  end

  # Create sample log messages for testing
  def sample_log_messages
    {
      systemd_start: 'Dec  8 10:00:00 server systemd[1]: Started nginx.service.',
      systemd_target: 'Dec  8 10:00:00 server systemd[1]: Reached target multi-user.target.',
      ssh_failed: 'Dec  8 10:01:00 server sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2',
      ssh_invalid: 'Dec  8 10:01:00 server sshd[1234]: Invalid user hacker from 192.168.1.100',
      kernel_error: 'Dec  8 10:02:00 server kernel: [12345.678] sda: media error (bad sector): status=0x51',
      kernel_io: 'Dec  8 10:02:00 server kernel: [12345.678] I/O error, dev sda, sector 12345',
      normal_app: 'Dec  8 10:03:00 server myapp[5678]: Application started successfully'
    }
  end
end

# Include test utilities in all test cases
Test::Unit::TestCase.include(TestUtils)
