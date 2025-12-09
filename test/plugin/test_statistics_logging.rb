# typed: false
# frozen_string_literal: true

require_relative '../helper'
require 'fluent/plugin/filter_logcheck'

class StatisticsLoggingTest < Test::Unit::TestCase
  include Fluent::Test::Helpers

  def setup
    Fluent::Test.setup
    @temp_files = []
  end

  def teardown
    cleanup_temp_files(*@temp_files)
  end

  def create_driver(conf)
    Fluent::Test::Driver::Filter.new(Fluent::Plugin::LogcheckFilter).configure(conf)
  end

  # Test periodic statistics logging

  def test_periodic_statistics_logging_enabled
    # Test that periodic statistics are logged when enabled
    rule_content = sample_ignore_rules
    rule_file = create_temp_file(rule_content, 'ignore_rules')
    @temp_files << rule_file

    config = %(
      rules_file #{rule_file}
      match_field message
      log_statistics true
      statistics_interval 1
    )

    d = create_driver(config)

    # Capture log output
    logs = []
    d.instance.log.define_singleton_method(:info) { |msg| logs << msg }

    # Start the plugin
    d.instance.start

    # Manually trigger statistics logging by setting last_stats_log to past time
    d.instance.instance_variable_set(:@last_stats_log, Time.now - 2)

    # Process a message to trigger periodic logging check
    d.run(default_tag: 'test') do
      d.feed(event_time, { 'message' => 'test message' })
    end

    # Verify periodic statistics were logged
    assert_true logs.any? { |log| log.include?('=== Logcheck Statistics ===') }
    assert_true logs.any? { |log| log.include?('Uptime:') }
    assert_true logs.any? { |log| log.include?('Processed:') }
  end

  def test_periodic_statistics_logging_disabled
    # Test that periodic statistics are NOT logged when disabled
    rule_content = sample_ignore_rules
    rule_file = create_temp_file(rule_content, 'ignore_rules')
    @temp_files << rule_file

    config = %(
      rules_file #{rule_file}
      match_field message
      log_statistics false
    )

    d = create_driver(config)

    # Capture log output
    logs = []
    d.instance.log.define_singleton_method(:info) { |msg| logs << msg }

    # Start the plugin
    d.instance.start

    # Process a message
    d.run(default_tag: 'test') do
      d.feed(event_time, { 'message' => 'test message' })
    end

    # Verify periodic statistics were NOT logged
    assert_false logs.any? { |log| log.include?('=== Logcheck Statistics ===') }
  end

  def test_periodic_statistics_configuration
    # Test that periodic statistics configuration is properly set
    rule_content = sample_ignore_rules
    rule_file = create_temp_file(rule_content, 'ignore_rules')
    @temp_files << rule_file

    config = %(
      rules_file #{rule_file}
      match_field message
      log_statistics true
      statistics_interval 60
    )

    d = create_driver(config)

    # Verify configuration is set correctly
    assert_true d.instance.log_statistics
    assert_equal 60, d.instance.statistics_interval

    # Start the plugin
    d.instance.start

    # Verify last_stats_log is initialized
    assert_not_nil d.instance.instance_variable_get(:@last_stats_log)
  end

  # Test final statistics reporting

  def test_final_statistics_reporting_with_log_statistics_enabled
    # Test final statistics are reported when log_statistics is enabled
    rule_content = sample_cracking_rules
    rule_file = create_temp_file(rule_content, 'cracking_rules')
    @temp_files << rule_file

    config = %(
      rules_file #{rule_file}
      match_field message
      log_statistics true
    )

    d = create_driver(config)

    # Capture log output
    logs = []
    d.instance.log.define_singleton_method(:info) { |msg| logs << msg }

    # Start the plugin
    d.instance.start

    # Process some messages to generate statistics
    d.run(default_tag: 'test') do
      d.feed(event_time, { 'message' => 'normal message' })
      d.feed(event_time, { 'message' => 'another normal message' })
    end

    # Shutdown the plugin
    d.instance.shutdown

    # Verify final statistics were logged
    assert_true logs.any? { |log| log.include?('=== Final Logcheck Statistics ===') }
    assert_true logs.any? { |log| log.include?('Processed: 2') }
  end

  def test_final_statistics_reporting_with_debug_mode_enabled
    # Test final statistics are reported when debug_mode is enabled (even if log_statistics is false)
    rule_content = sample_violations_rules
    rule_file = create_temp_file(rule_content, 'violations_rules')
    @temp_files << rule_file

    config = %(
      rules_file #{rule_file}
      match_field message
      log_statistics false
      debug_mode true
    )

    d = create_driver(config)

    # Capture log output
    logs = []
    d.instance.log.define_singleton_method(:info) { |msg| logs << msg }

    # Start the plugin
    d.instance.start

    # Process a message
    d.run(default_tag: 'test') do
      d.feed(event_time, { 'message' => 'test message' })
    end

    # Shutdown the plugin
    d.instance.shutdown

    # Verify final statistics were logged due to debug mode
    assert_true logs.any? { |log| log.include?('=== Final Logcheck Statistics ===') }
  end

  def test_final_statistics_reporting_disabled
    # Test final statistics are NOT reported when both log_statistics and debug_mode are false
    rule_content = sample_ignore_rules
    rule_file = create_temp_file(rule_content, 'ignore_rules')
    @temp_files << rule_file

    config = %(
      rules_file #{rule_file}
      match_field message
      log_statistics false
      debug_mode false
    )

    d = create_driver(config)

    # Capture log output
    logs = []
    d.instance.log.define_singleton_method(:info) { |msg| logs << msg }

    # Start the plugin
    d.instance.start

    # Process a message
    d.run(default_tag: 'test') do
      d.feed(event_time, { 'message' => 'test message' })
    end

    # Shutdown the plugin
    d.instance.shutdown

    # Verify final statistics were NOT logged
    assert_false logs.any? { |log| log.include?('=== Final Logcheck Statistics ===') }
    # But basic shutdown message should be present
    assert_true logs.any? { |log| log.include?('Logcheck filter stopped') }
  end

  def test_final_statistics_with_rule_engine_stats
    # Test final statistics include rule engine statistics when available
    rule_content = sample_cracking_rules
    rule_file = create_temp_file(rule_content, 'cracking_rules')
    @temp_files << rule_file

    config = %(
      rules_file #{rule_file}
      match_field message
      log_statistics true
    )

    d = create_driver(config)

    # Capture log output
    logs = []
    d.instance.log.define_singleton_method(:info) { |msg| logs << msg }

    # Start the plugin
    d.instance.start

    # Process a message
    d.run(default_tag: 'test') do
      d.feed(event_time, { 'message' => 'test message' })
    end

    # Shutdown the plugin
    d.instance.shutdown

    # Verify rule engine statistics were logged
    assert_true logs.any? { |log| log.include?('Rule engine statistics:') }
  end

  # Test rule summary logging in debug mode

  def test_rule_summary_logging_in_debug_mode
    # Test that rule summary is logged when debug mode is enabled
    rules_by_file = {
      'ignore.rules' => sample_ignore_rules,
      'cracking.rules' => sample_cracking_rules
    }
    rule_dir = create_temp_dir_with_rules(rules_by_file)
    @temp_files << rule_dir

    config = %(
      rules_dir #{rule_dir}
      match_field message
      debug_mode true
    )

    d = create_driver(config)

    # Capture log output
    logs = []
    d.instance.log.define_singleton_method(:info) { |msg| logs << msg }

    # Start the plugin
    d.instance.start

    # Verify rule summary was logged
    assert_true logs.any? { |log| log.include?('=== Rule Summary ===') }
    assert_true logs.any? { |log| log.include?('rules (type:') }
    assert_true logs.any? { |log| log.include?('Rule counts by type:') }
    assert_true logs.any? { |log| log.include?('Rule priority order:') }
  end

  def test_rule_summary_not_logged_without_debug_mode
    # Test that rule summary is NOT logged when debug mode is disabled
    rules_by_file = {
      'ignore.rules' => sample_ignore_rules,
      'cracking.rules' => sample_cracking_rules
    }
    rule_dir = create_temp_dir_with_rules(rules_by_file)
    @temp_files << rule_dir

    config = %(
      rules_dir #{rule_dir}
      match_field message
      debug_mode false
    )

    d = create_driver(config)

    # Capture log output
    logs = []
    d.instance.log.define_singleton_method(:info) { |msg| logs << msg }

    # Start the plugin
    d.instance.start

    # Verify rule summary was NOT logged
    assert_false logs.any? { |log| log.include?('=== Rule Summary ===') }
  end

  # Test error logging and debug information

  def test_error_logging_in_filter_method
    # Test that errors in filter method are properly logged
    rule_content = sample_ignore_rules
    rule_file = create_temp_file(rule_content, 'ignore_rules')
    @temp_files << rule_file

    config = %(
      rules_file #{rule_file}
      match_field message
      debug_mode true
    )

    d = create_driver(config)

    # Capture log output
    logs = []
    d.instance.log.define_singleton_method(:error) { |msg| logs << msg }
    d.instance.log.define_singleton_method(:error_backtrace) { |backtrace| logs << "Backtrace: #{backtrace}" }

    # Start the plugin
    d.instance.start

    # Mock the rule engine to raise an error
    rule_engine = d.instance.instance_variable_get(:@rule_engine)
    rule_engine.define_singleton_method(:filter) { |_text| raise StandardError, 'Test error' }

    # Process a message (should trigger error handling)
    d.run(default_tag: 'test') do
      d.feed(event_time, { 'message' => 'test message' })
    end

    # Verify error was logged
    assert_true logs.any? { |log| log.include?('Error processing record: Test error') }
    # In debug mode, backtrace should also be logged
    assert_true logs.any? { |log| log.include?('Backtrace:') }

    # Verify statistics were updated
    stats = d.instance.instance_variable_get(:@statistics)
    assert_equal 1, stats[:errors]
  end

  def test_debug_information_logging
    # Test that debug information is logged when debug_mode is enabled
    rule_content = sample_cracking_rules
    rule_file = create_temp_file(rule_content, 'cracking_rules')
    @temp_files << rule_file

    config = %(
      rules_file #{rule_file}
      match_field message
      debug_mode true
    )

    d = create_driver(config)

    # Capture log output
    logs = []
    d.instance.log.define_singleton_method(:debug) { |msg| logs << msg }

    # Start the plugin
    d.instance.start

    # Process a message
    d.run(default_tag: 'test') do
      d.feed(event_time, { 'message' => 'test message for debugging' })
    end

    # Verify debug information was logged
    assert_true logs.any? { |log| log.include?('Processing message:') }
    assert_true logs.any? { |log| log.include?('Filter decision:') }
  end

  def test_debug_information_not_logged_without_debug_mode
    # Test that debug information is NOT logged when debug_mode is disabled
    rule_content = sample_cracking_rules
    rule_file = create_temp_file(rule_content, 'cracking_rules')
    @temp_files << rule_file

    config = %(
      rules_file #{rule_file}
      match_field message
      debug_mode false
    )

    d = create_driver(config)

    # Capture log output
    logs = []
    d.instance.log.define_singleton_method(:debug) { |msg| logs << msg }

    # Start the plugin
    d.instance.start

    # Process a message
    d.run(default_tag: 'test') do
      d.feed(event_time, { 'message' => 'test message' })
    end

    # Verify debug information was NOT logged
    assert_false logs.any? { |log| log.include?('Processing message:') }
    assert_false logs.any? { |log| log.include?('Filter decision:') }
  end

  # Test statistics reset functionality

  def test_statistics_initialization_on_start
    # Test that statistics are properly initialized when plugin starts
    rule_content = sample_ignore_rules
    rule_file = create_temp_file(rule_content, 'ignore_rules')
    @temp_files << rule_file

    config = %(
      rules_file #{rule_file}
      match_field message
    )

    d = create_driver(config)

    # Before start
    stats = d.instance.instance_variable_get(:@statistics)
    assert_nil stats[:start_time]

    # Start the plugin
    d.instance.start

    # After start
    stats = d.instance.instance_variable_get(:@statistics)
    assert_not_nil stats[:start_time]
    assert_not_nil d.instance.instance_variable_get(:@last_stats_log)

    # Verify start_time is recent
    assert_true (Time.now - stats[:start_time]) < 1.0
  end

  def test_statistics_tracking_during_processing
    # Test that statistics are properly tracked during message processing
    rule_content = sample_ignore_rules
    rule_file = create_temp_file(rule_content, 'ignore_rules')
    @temp_files << rule_file

    config = %(
      rules_file #{rule_file}
      match_field message
    )

    d = create_driver(config)

    # Start the plugin
    d.instance.start

    # Initial statistics
    stats = d.instance.instance_variable_get(:@statistics)
    initial_processed = stats[:processed]

    # Process messages
    d.run(default_tag: 'test') do
      d.feed(event_time, { 'message' => 'first message' })
      d.feed(event_time, { 'message' => 'second message' })
      d.feed(event_time, { 'message' => 'third message' })
    end

    # Verify statistics were updated
    stats = d.instance.instance_variable_get(:@statistics)
    assert_equal initial_processed + 3, stats[:processed]
  end

  def test_statistics_uptime_calculation
    # Test that uptime is correctly calculated in statistics
    rule_content = sample_ignore_rules
    rule_file = create_temp_file(rule_content, 'ignore_rules')
    @temp_files << rule_file

    config = %(
      rules_file #{rule_file}
      match_field message
      log_statistics true
      statistics_interval 1
    )

    d = create_driver(config)

    # Capture log output
    logs = []
    d.instance.log.define_singleton_method(:info) { |msg| logs << msg }

    # Start the plugin
    d.instance.start

    # Wait a bit and then trigger statistics logging
    sleep(0.1)
    d.instance.instance_variable_set(:@last_stats_log, Time.now - 2)

    # Process a message to trigger periodic logging
    d.run(default_tag: 'test') do
      d.feed(event_time, { 'message' => 'test message' })
    end

    # Verify uptime was calculated and logged
    uptime_logs = logs.select { |log| log.include?('Uptime:') }
    assert_not_empty uptime_logs

    # Extract uptime value and verify it's reasonable
    uptime_log = uptime_logs.first
    uptime_match = uptime_log.match(/Uptime: ([\d.]+)s/)
    assert_not_nil uptime_match
    uptime = uptime_match[1].to_f
    assert_true uptime > 0.0
    assert_true uptime < 10.0 # Should be less than 10 seconds for this test
  end

  private

  def event_time
    Fluent::EventTime.now
  end
end
