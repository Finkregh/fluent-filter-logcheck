# typed: false
# frozen_string_literal: true

$LOAD_PATH.unshift(File.expand_path('../lib', __dir__))

require 'test-unit'
require 'fluent/test'
require 'fluent/test/driver/filter'
require 'fluent/test/helpers'

# Load test support files
require_relative 'support/rule_file_helpers'

# Enable coverage if requested
if ENV['COVERAGE']
  require 'simplecov'
  require 'simplecov-cobertura'
  require 'simplecov-lcov'

  SimpleCov.start do
    add_filter '/test/'
    add_filter '/vendor/'
    add_filter '/knowlege/'

    # Configure LCOV formatter for IDE integration
    SimpleCov::Formatter::LcovFormatter.config do |c|
      c.report_with_single_file = true
      c.output_directory = 'coverage'
      c.lcov_file_name = 'lcov.info'
    end

    # Configure formatters
    if ENV['CI']
      # In CI, generate HTML, Cobertura XML, and LCOV for IDE integration
      formatter SimpleCov::Formatter::MultiFormatter.new([
                                                           SimpleCov::Formatter::HTMLFormatter,
                                                           SimpleCov::Formatter::CoberturaFormatter,
                                                           SimpleCov::Formatter::LcovFormatter
                                                         ])
    else
      # Locally, generate HTML and LCOV for IDE integration
      formatter SimpleCov::Formatter::MultiFormatter.new([
                                                           SimpleCov::Formatter::HTMLFormatter,
                                                           SimpleCov::Formatter::LcovFormatter
                                                         ])
    end

    # Set minimum coverage thresholds to match current coverage levels
    minimum_coverage 43
    minimum_coverage_by_file 20

    # Track branches for more detailed coverage
    enable_coverage :branch

    # Coverage groups for better reporting
    add_group 'Core Plugin', 'lib/fluent/plugin/filter_logcheck.rb'
    add_group 'Rule Engine', 'lib/fluent/plugin/logcheck/rule_engine.rb'
    add_group 'Rule Loading', 'lib/fluent/plugin/logcheck/rule_loader.rb'
    add_group 'Rule Classes', ['lib/fluent/plugin/logcheck/rule.rb',
                               'lib/fluent/plugin/logcheck/rule_types.rb']
    add_group 'Decisions', 'lib/fluent/plugin/logcheck/filter_decision.rb'
  end

  # Add at_exit hook to manually generate XML if needed
  if ENV['CI']
    at_exit do
      puts 'Coverage formatters executed. Checking for XML files...'
      xml_files = Dir.glob('**/*.xml')
      xml_files.each { |f| puts "Found XML file: #{f}" }

      # If no XML files found, try to generate one manually
      if xml_files.empty?
        puts 'No XML files found, attempting manual generation...'
        begin
          result = SimpleCov.result
          cobertura_formatter = SimpleCov::Formatter::CoberturaFormatter.new
          cobertura_formatter.format(result)
          puts 'Manual XML generation completed'
        rescue StandardError => e
          puts "Manual XML generation failed: #{e.message}"
          # Create a simple XML file as fallback
          xml_content = <<~XML
            <!-- Fallback Cobertura XML generated due to error -->
            <?xml version="1.0" encoding="UTF-8"?>
            <coverage line-rate="#{result.covered_percent / 100.0}" branch-rate="0.0" lines-covered="#{result.covered_lines}" lines-valid="#{result.total_lines}" timestamp="#{Time.now.to_i}" complexity="0" version="0.1">
              <sources>
                <source>#{SimpleCov.root}</source>
              </sources>
              <packages>
                <package name="root" line-rate="#{result.covered_percent / 100.0}" branch-rate="0.0" complexity="0">
                  <classes>
                  </classes>
                </package>
              </packages>
            </coverage>
          XML
          File.write('coverage/cobertura.xml', xml_content)
          puts 'Created fallback XML file at coverage/cobertura.xml'
        end
      end
    end
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
    file.flush  # Explicitly flush before closing
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
Test::Unit::TestCase.include(RuleFileHelpers)
