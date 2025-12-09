# frozen_string_literal: true

require_relative '../helper'
require 'fluent/plugin/filter_logcheck'
require 'tempfile'
require 'fileutils'

class ErrorHandlingTest < Test::Unit::TestCase
  include Fluent::Test::Helpers

  def setup
    Fluent::Test.setup
    @temp_dir = Dir.mktmpdir('logcheck_error_test')
    create_test_files
  end

  def teardown
    FileUtils.rm_rf(@temp_dir) if @temp_dir && Dir.exist?(@temp_dir)
  end

  sub_test_case 'rule loading error handling' do
    test 'handles missing rule files gracefully' do
      non_existent_file = File.join(@temp_dir, 'missing.rules')
      config = %[
        rules_file #{non_existent_file}
        log_rule_errors true
      ]
      
      d = create_driver(config)
      
      # Should not raise, but should log warning
      assert_nothing_raised do
        d.run(default_tag: 'test') do
          d.feed(event_time, { 'message' => 'test message' })
        end
      end
      
      # Message should pass through since no rules loaded
      assert_equal 1, d.filtered_records.size
    end

    test 'handles missing rule directories gracefully' do
      non_existent_dir = File.join(@temp_dir, 'missing_dir')
      config = %[
        rules_dir #{non_existent_dir}
        log_rule_errors true
      ]
      
      d = create_driver(config)
      
      # Should not raise, but should log warning
      assert_nothing_raised do
        d.run(default_tag: 'test') do
          d.feed(event_time, { 'message' => 'test message' })
        end
      end
      
      # Message should pass through since no rules loaded
      assert_equal 1, d.filtered_records.size
    end

    test 'handles malformed rule files gracefully' do
      malformed_file = File.join(@temp_dir, 'malformed.rules')
      File.write(malformed_file, "[invalid_regex\n(unclosed_group\n")
      
      config = %[
        rules_file #{malformed_file}
        ignore_parse_errors true
        log_rule_errors true
      ]
      
      d = create_driver(config)
      
      # Should not raise during initialization or processing
      assert_nothing_raised do
        d.run(default_tag: 'test') do
          d.feed(event_time, { 'message' => 'test message' })
        end
      end
      
      # Message should pass through since no valid rules loaded
      assert_equal 1, d.filtered_records.size
    end

    test 'handles file permission errors gracefully' do
      restricted_file = File.join(@temp_dir, 'restricted.rules')
      File.write(restricted_file, "test.*pattern")
      
      begin
        File.chmod(0000, restricted_file)
        
        config = %[
          rules_file #{restricted_file}
          ignore_parse_errors true
          log_rule_errors true
        ]
        
        d = create_driver(config)
        
        # Should not raise
        assert_nothing_raised do
          d.run(default_tag: 'test') do
            d.feed(event_time, { 'message' => 'test message' })
          end
        end
        
        # Message should pass through since rules couldn't be loaded
        assert_equal 1, d.filtered_records.size
      ensure
        File.chmod(0644, restricted_file) rescue nil
      end
    end
  end

  sub_test_case 'record processing error handling' do
    test 'handles missing message field gracefully' do
      config = %[
        rules_file #{@valid_rules_file}
        match_field message
      ]
      
      d = create_driver(config)
      
      # Record without message field
      assert_nothing_raised do
        d.run(default_tag: 'test') do
          d.feed(event_time, { 'other_field' => 'some value' })
        end
      end
      
      # Record should pass through unchanged
      assert_equal 1, d.filtered_records.size
      assert_equal 'some value', d.filtered_records.first['other_field']
    end

    test 'handles nil message field gracefully' do
      config = %[
        rules_file #{@valid_rules_file}
        match_field message
      ]
      
      d = create_driver(config)
      
      # Record with nil message field
      assert_nothing_raised do
        d.run(default_tag: 'test') do
          d.feed(event_time, { 'message' => nil, 'other_field' => 'value' })
        end
      end
      
      # Record should pass through unchanged
      assert_equal 1, d.filtered_records.size
      assert_nil d.filtered_records.first['message']
    end

    test 'handles empty message field gracefully' do
      config = %[
        rules_file #{@valid_rules_file}
        match_field message
      ]
      
      d = create_driver(config)
      
      # Record with empty message field
      assert_nothing_raised do
        d.run(default_tag: 'test') do
          d.feed(event_time, { 'message' => '', 'other_field' => 'value' })
        end
      end
      
      # Record should pass through unchanged
      assert_equal 1, d.filtered_records.size
      assert_equal '', d.filtered_records.first['message']
    end

    test 'handles non-string message field gracefully' do
      config = %[
        rules_file #{@valid_rules_file}
        match_field message
      ]
      
      d = create_driver(config)
      
      # Record with numeric message field
      assert_nothing_raised do
        d.run(default_tag: 'test') do
          d.feed(event_time, { 'message' => 12345, 'other_field' => 'value' })
        end
      end
      
      # Record should be processed (converted to string)
      assert_equal 1, d.filtered_records.size
    end

    test 'handles nested field access errors gracefully' do
      config = %[
        rules_file #{@valid_rules_file}
        match_field nested.field.that.does.not.exist
      ]
      
      d = create_driver(config)
      
      # Record without nested field
      assert_nothing_raised do
        d.run(default_tag: 'test') do
          d.feed(event_time, { 'message' => 'test', 'nested' => { 'other' => 'value' } })
        end
      end
      
      # Record should pass through unchanged
      assert_equal 1, d.filtered_records.size
    end
  end

  sub_test_case 'rule engine error handling' do
    test 'handles rule engine exceptions gracefully' do
      config = %[
        rules_file #{@valid_rules_file}
        log_rule_errors true
      ]
      
      d = create_driver(config)
      
      # Mock rule engine to throw exception
      d.instance.instance_variable_get(:@rule_engine).define_singleton_method(:filter) do |text|
        raise StandardError, "Simulated rule engine error"
      end
      
      # Should not raise, should return original record
      assert_nothing_raised do
        d.run(default_tag: 'test') do
          d.feed(event_time, { 'message' => 'test message' })
        end
      end
      
      # Record should pass through unchanged due to error handling
      assert_equal 1, d.filtered_records.size
      assert_equal 'test message', d.filtered_records.first['message']
    end

    test 'handles filter decision application errors gracefully' do
      config = %[
        rules_file #{@valid_rules_file}
        mark_matches true
        log_rule_errors true
      ]
      
      d = create_driver(config)
      
      # Create a decision that might cause issues
      decision = Fluent::Plugin::Logcheck::FilterDecision.new(:unknown_decision, nil, 'test')
      
      # Mock make_filter_decision to return problematic decision
      d.instance.define_singleton_method(:make_filter_decision) do |text|
        decision
      end
      
      # Should not raise, should apply default action
      assert_nothing_raised do
        d.run(default_tag: 'test') do
          d.feed(event_time, { 'message' => 'test message' })
        end
      end
      
      # Record should pass through (default action for unknown decision)
      assert_equal 1, d.filtered_records.size
    end
  end

  sub_test_case 'configuration error recovery' do
    test 'continues processing with partial rule loading failures' do
      # Create mixed scenario: some valid, some invalid rule sources
      valid_file = File.join(@temp_dir, 'valid.rules')
      File.write(valid_file, "^valid.*pattern$")
      
      invalid_file = File.join(@temp_dir, 'invalid.rules')
      File.write(invalid_file, "[invalid_regex")
      
      config = %[
        <rules>
          path #{valid_file}
          type ignore
        </rules>
        <rules>
          path #{invalid_file}
          type ignore
        </rules>
        ignore_parse_errors true
        log_rule_errors true
      ]
      
      d = create_driver(config)
      
      # Should load valid rules and continue processing
      assert_nothing_raised do
        d.run(default_tag: 'test') do
          d.feed(event_time, { 'message' => 'valid test pattern' })
          d.feed(event_time, { 'message' => 'unmatched message' })
        end
      end
      
      # First message should be ignored (matches valid rule)
      # Second message should pass through
      assert_equal 1, d.filtered_records.size
      assert_equal 'unmatched message', d.filtered_records.first['message']
    end
  end

  sub_test_case 'logging and debugging' do
    test 'provides detailed error information when log_rule_errors is true' do
      config = %[
        rules_file #{@valid_rules_file}
        log_rule_errors true
      ]
      
      d = create_driver(config)
      
      # Process some records to generate log entries
      d.run(default_tag: 'test') do
        d.feed(event_time, { 'message' => 'test ignore pattern' })
        d.feed(event_time, { 'message' => 'unmatched message' })
      end
      
      # Should have logged debug information
      logs = d.logs
      assert_operator logs.size, :>, 0
    end

    test 'suppresses detailed logging when log_rule_errors is false' do
      config = %[
        rules_file #{@valid_rules_file}
        log_rule_errors false
      ]
      
      d = create_driver(config)
      
      # Process some records
      d.run(default_tag: 'test') do
        d.feed(event_time, { 'message' => 'test ignore pattern' })
      end
      
      # Should have minimal logging
      logs = d.logs
      debug_logs = logs.select { |log| log.include?('Ignoring message') }
      assert_equal 0, debug_logs.size
    end
  end

  private

  def create_driver(conf)
    Fluent::Test::Driver::Filter.new(Fluent::Plugin::LogcheckFilter).configure(conf)
  end

  def create_test_files
    @valid_rules_file = File.join(@temp_dir, 'valid.rules')
    File.write(@valid_rules_file, [
      "^test ignore pattern$",
      "^another ignore pattern$"
    ].join("\n"))
    
    # Create a test directory structure
    ignore_dir = File.join(@temp_dir, 'ignore.d.server')
    FileUtils.mkdir_p(ignore_dir)
    File.write(File.join(ignore_dir, 'test'), "^.*ignore.*$")
  end
end
