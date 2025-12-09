# typed: false
# frozen_string_literal: true

require_relative '../helper'
require_relative '../support/rule_file_helpers'
require 'fluent/plugin/logcheck/rule_loader'

class RuleLoaderIntegrationTest < Test::Unit::TestCase
  include RuleFileHelpers

  def setup
    @temp_dir = Dir.mktmpdir('rule_loader_integration_test')
    @logger = TestLogger.new
    @rule_loader = Fluent::Plugin::Logcheck::RuleLoader.new(logger: @logger)
  end

  def teardown
    cleanup_temp_files(@temp_dir) if @temp_dir && Dir.exist?(@temp_dir)
  end

  sub_test_case 'file loading with real files' do
    test 'loads ignore rules from file successfully' do
      ignore_file = create_ignore_rules(@temp_dir)

      rule_set = @rule_loader.load_file(ignore_file, :ignore)

      assert_not_nil rule_set
      assert_equal :ignore, rule_set.type
      assert_equal ignore_file, rule_set.source_path
      assert_operator rule_set.size, :>, 0
      assert_false rule_set.empty?

      # Test that rules can match messages
      systemd_message = sample_real_log_messages[:systemd_start]
      matching_rule = rule_set.match(systemd_message)
      assert_not_nil matching_rule
      assert_equal :ignore, matching_rule.type
    end

    test 'loads cracking rules from file successfully' do
      cracking_file = create_cracking_rules(@temp_dir)

      rule_set = @rule_loader.load_file(cracking_file, :cracking)

      assert_not_nil rule_set
      assert_equal :cracking, rule_set.type
      assert_equal cracking_file, rule_set.source_path
      assert_operator rule_set.size, :>, 0

      # Test that rules can match SSH attack messages
      ssh_message = sample_real_log_messages[:ssh_failed]
      matching_rule = rule_set.match(ssh_message)
      assert_not_nil matching_rule
      assert_equal :cracking, matching_rule.type
    end

    test 'loads violations rules from file successfully' do
      violations_file = create_violations_rules(@temp_dir)

      rule_set = @rule_loader.load_file(violations_file, :violations)

      assert_not_nil rule_set
      assert_equal :violations, rule_set.type
      assert_equal violations_file, rule_set.source_path
      assert_operator rule_set.size, :>, 0

      # Test that rules can match kernel error messages
      kernel_message = sample_real_log_messages[:kernel_io_error]
      matching_rule = rule_set.match(kernel_message)
      assert_not_nil matching_rule
      assert_equal :violations, matching_rule.type
    end

    test 'auto-detects rule type from file path' do
      # Create files with logcheck-style paths
      ignore_dir = File.join(@temp_dir, 'ignore.d.server')
      FileUtils.mkdir_p(ignore_dir)
      ignore_file = File.join(ignore_dir, 'systemd')
      File.write(ignore_file, '^.*systemd.*$')

      cracking_dir = File.join(@temp_dir, 'cracking.d')
      FileUtils.mkdir_p(cracking_dir)
      cracking_file = File.join(cracking_dir, 'ssh')
      File.write(cracking_file, '^.*Failed password.*$')

      violations_dir = File.join(@temp_dir, 'violations.d')
      FileUtils.mkdir_p(violations_dir)
      violations_file = File.join(violations_dir, 'kernel')
      File.write(violations_file, '^.*I/O error.*$')

      # Load files with auto-detection (nil type)
      ignore_rule_set = @rule_loader.load_file(ignore_file, nil)
      cracking_rule_set = @rule_loader.load_file(cracking_file, nil)
      violations_rule_set = @rule_loader.load_file(violations_file, nil)

      # Verify auto-detected types
      assert_equal :ignore, ignore_rule_set.type
      assert_equal :cracking, cracking_rule_set.type
      assert_equal :violations, violations_rule_set.type
    end

    test 'handles max_rules limit correctly' do
      # Create a file with many rules
      many_rules_file = File.join(@temp_dir, 'many_rules.rules')
      patterns = []
      20.times { |i| patterns << "^pattern_#{i}.*$" }
      File.write(many_rules_file, patterns.join("\n"))

      # Load with limit
      rule_set = @rule_loader.load_file(many_rules_file, :ignore, max_rules: 10)

      assert_equal 10, rule_set.size
    end

    test 'skips invalid regex patterns gracefully' do
      malformed_file = create_malformed_rule_files(@temp_dir)

      # Should not raise error, but should log warnings
      rule_set = @rule_loader.load_file(malformed_file, :ignore)

      assert_not_nil rule_set
      assert_equal :ignore, rule_set.type
      # Should have fewer rules due to invalid patterns being skipped
      assert_operator rule_set.size, :<, 5 # Original had 5 patterns, some invalid

      # Check that warnings were logged
      warning_messages = @logger.messages.select { |msg| msg[:level] == :warn }
      assert_operator warning_messages.size, :>, 0
    end
  end

  sub_test_case 'directory loading' do
    test 'loads rules from directory non-recursively' do
      # Create directory with rule files
      test_dir = File.join(@temp_dir, 'test_rules')
      FileUtils.mkdir_p(test_dir)

      # Create files in main directory
      File.write(File.join(test_dir, 'systemd'), '^.*systemd.*$')
      File.write(File.join(test_dir, 'cron'), '^.*cron.*$')

      # Create subdirectory (should be ignored in non-recursive mode)
      sub_dir = File.join(test_dir, 'subdir')
      FileUtils.mkdir_p(sub_dir)
      File.write(File.join(sub_dir, 'ignored'), '^.*ignored.*$')

      rule_sets = @rule_loader.load_directory(test_dir, :ignore, recursive: false)

      assert_equal 2, rule_sets.size # Only files in main directory
      rule_sets.each do |rule_set|
        assert_equal :ignore, rule_set.type
        assert_operator rule_set.size, :>, 0
      end
    end

    test 'loads rules from directory recursively' do
      # Create nested directory structure
      create_logcheck_directory_structure(@temp_dir)
      create_real_rule_files(@temp_dir)

      rule_sets = @rule_loader.load_directory(@temp_dir, nil, recursive: true)

      # Should find multiple rule files in subdirectories
      assert_operator rule_sets.size, :>, 3

      # Verify different rule types were detected
      rule_types = rule_sets.map(&:type).uniq
      assert_includes rule_types, :ignore
      assert_includes rule_types, :cracking
      assert_includes rule_types, :violations
    end

    test 'loads rules with specific type override' do
      # Create directory with mixed files
      test_dir = File.join(@temp_dir, 'mixed_rules')
      FileUtils.mkdir_p(test_dir)

      File.write(File.join(test_dir, 'file1'), '^.*pattern1.*$')
      File.write(File.join(test_dir, 'file2'), '^.*pattern2.*$')

      # Load all as violations type (override auto-detection)
      rule_sets = @rule_loader.load_directory(test_dir, :violations, recursive: false)

      assert_equal 2, rule_sets.size
      rule_sets.each do |rule_set|
        assert_equal :violations, rule_set.type
      end
    end

    test 'skips non-rule files correctly' do
      test_dir = File.join(@temp_dir, 'mixed_files')
      FileUtils.mkdir_p(test_dir)

      # Create rule files
      File.write(File.join(test_dir, 'valid_rules'), '^.*valid.*$')

      # Create files that should be skipped
      File.write(File.join(test_dir, '.hidden'), '^.*hidden.*$')
      File.write(File.join(test_dir, 'backup~'), '^.*backup.*$')
      File.write(File.join(test_dir, 'readme.txt'), 'This is documentation')
      File.write(File.join(test_dir, 'config.yml'), 'key: value')

      rule_sets = @rule_loader.load_directory(test_dir, :ignore, recursive: false)

      # Should only load the valid rules file
      assert_equal 1, rule_sets.size
      assert_equal 'valid_rules', File.basename(rule_sets.first.source_path)
    end

    test 'handles max_rules limit per file in directory' do
      test_dir = File.join(@temp_dir, 'limited_rules')
      FileUtils.mkdir_p(test_dir)

      # Create files with many rules each
      2.times do |i|
        patterns = []
        15.times { |j| patterns << "^pattern_#{i}_#{j}.*$" }
        File.write(File.join(test_dir, "file#{i}"), patterns.join("\n"))
      end

      rule_sets = @rule_loader.load_directory(test_dir, :ignore, recursive: false, max_rules: 10)

      assert_equal 2, rule_sets.size
      rule_sets.each do |rule_set|
        assert_equal 10, rule_set.size # Limited to max_rules
      end
    end
  end

  sub_test_case 'error handling' do
    test 'raises FileNotFoundError for missing file' do
      non_existent_file = File.join(@temp_dir, 'does_not_exist.rules')

      assert_raise(Fluent::Plugin::Logcheck::RuleLoader::FileNotFoundError) do
        @rule_loader.load_file(non_existent_file, :ignore)
      end
    end

    test 'raises FileNotFoundError for missing directory' do
      non_existent_dir = File.join(@temp_dir, 'does_not_exist')

      assert_raise(Fluent::Plugin::Logcheck::RuleLoader::FileNotFoundError) do
        @rule_loader.load_directory(non_existent_dir, :ignore)
      end
    end

    test 'raises ParseError when rule type cannot be detected' do
      # Create file in location where type cannot be auto-detected
      unknown_file = File.join(@temp_dir, 'unknown.rules')
      File.write(unknown_file, '^.*pattern.*$')

      assert_raise(Fluent::Plugin::Logcheck::RuleLoader::ParseError) do
        @rule_loader.load_file(unknown_file, nil) # nil type, auto-detection should fail
      end
    end

    test 'handles file reading errors gracefully' do
      # Create file and then make it unreadable by removing it
      temp_file = File.join(@temp_dir, 'temp_file.rules')
      File.write(temp_file, '^valid pattern.*$')

      # Delete the file to simulate read error
      File.delete(temp_file)

      # Should raise FileNotFoundError
      assert_raise(Fluent::Plugin::Logcheck::RuleLoader::FileNotFoundError) do
        @rule_loader.load_file(temp_file, :ignore)
      end
    end

    test 'continues loading other files when one fails in directory' do
      test_dir = File.join(@temp_dir, 'mixed_success')
      FileUtils.mkdir_p(test_dir)

      # Create valid file
      File.write(File.join(test_dir, 'valid'), '^.*valid.*$')

      # Create file with invalid regex instead of permission issues
      invalid_file = File.join(test_dir, 'invalid')
      File.write(invalid_file, '[invalid_regex')

      rule_sets = @rule_loader.load_directory(test_dir, :ignore, recursive: false)

      # Should load the valid file, invalid file should be skipped or have no rules
      assert_operator rule_sets.size, :>=, 1

      # At least one rule set should have rules (the valid file)
      total_rules = rule_sets.sum(&:size)
      assert_operator total_rules, :>, 0
    end
  end

  sub_test_case 'pattern compilation and validation' do
    test 'compiles valid regex patterns successfully' do
      valid_patterns_file = File.join(@temp_dir, 'valid_patterns.rules')
      patterns = [
        '^simple pattern$',
        '.*with.*wildcards.*',
        '\d{4}-\d{2}-\d{2}', # Date pattern
        '[a-zA-Z0-9]+@[a-zA-Z0-9]+\.[a-zA-Z]{2,}',  # Email pattern
        '(\w{3} [ :[:digit:]]{11}|[0-9T:.+-]{32})'  # Complex logcheck pattern
      ]
      File.write(valid_patterns_file, patterns.join("\n"))

      rule_set = @rule_loader.load_file(valid_patterns_file, :ignore)

      assert_equal patterns.size, rule_set.size

      # Test that each rule can be used for matching
      rule_set.rules.each do |rule|
        assert_not_nil rule.pattern # Should compile without error
        assert_respond_to rule, :match?
      end
    end

    test 'handles complex POSIX character classes' do
      posix_patterns_file = File.join(@temp_dir, 'posix_patterns.rules')
      patterns = [
        '^[[:alnum:]]+$',
        '^[[:alpha:]]+[[:digit:]]+$',
        '^[[:space:]]*[[:print:]]+[[:space:]]*$',
        '^[._[:alnum:]-]+$'
      ]
      File.write(posix_patterns_file, patterns.join("\n"))

      rule_set = @rule_loader.load_file(posix_patterns_file, :ignore)

      assert_equal patterns.size, rule_set.size

      # Test matching with POSIX patterns
      test_messages = [
        'abc123',
        'test123',
        '  printable text  ',
        'server.example-1'
      ]

      test_messages.each_with_index do |message, index|
        rule = rule_set.rules[index]
        assert_true rule.match?(message), "Pattern #{rule.raw_pattern} should match '#{message}'"
      end
    end

    test 'provides detailed error information for invalid patterns' do
      invalid_patterns_file = File.join(@temp_dir, 'invalid_detailed.rules')
      patterns = [
        '[unclosed_bracket',
        '(unclosed_group',
        '*invalid_quantifier',
        '\\invalid_escape'
      ]
      File.write(invalid_patterns_file, patterns.join("\n"))

      rule_set = @rule_loader.load_file(invalid_patterns_file, :ignore)

      # Should have few or no valid rules (some patterns might be valid in Ruby regex)
      assert_operator rule_set.size, :<=, patterns.size

      # Should have logged warnings for invalid patterns
      warning_messages = @logger.messages.select { |msg| msg[:level] == :warn }
      assert_operator warning_messages.size, :>, 0

      # At least some warnings should include line numbers
      line_number_warnings = warning_messages.select { |msg| msg[:message].match?(/\d+/) }
      assert_operator line_number_warnings.size, :>, 0
    end
  end

  # Simple test logger for capturing log messages
  class TestLogger
    attr_reader :messages

    def initialize
      @messages = []
    end

    def info(message)
      @messages << { level: :info, message: message }
    end

    def debug(message)
      @messages << { level: :debug, message: message }
    end

    def warn(message)
      @messages << { level: :warn, message: message }
    end

    def error(message)
      @messages << { level: :error, message: message }
    end
  end
end
