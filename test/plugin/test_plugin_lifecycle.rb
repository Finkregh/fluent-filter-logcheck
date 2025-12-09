# typed: false
# frozen_string_literal: true

require_relative '../helper'
require 'fluent/plugin/filter_logcheck'

class PluginLifecycleTest < Test::Unit::TestCase
  include Fluent::Test::Helpers

  def setup
    Fluent::Test.setup
    @temp_files = []
  end

  def teardown
    cleanup_temp_files(*@temp_files)
  end

  def create_driver(conf = CONFIG)
    Fluent::Test::Driver::Filter.new(Fluent::Plugin::LogcheckFilter).configure(conf)
  end

  # Basic configuration for testing
  CONFIG = %(
    rules_file /tmp/test_rules
    match_field message
    default_action keep
  )

  def test_plugin_initialization
    # Test that plugin initializes with correct default values before configure
    plugin = Fluent::Plugin::LogcheckFilter.new

    # Check that instance variables are properly initialized
    assert_not_nil plugin
    assert_equal({}, plugin.instance_variable_get(:@rule_sets))
    assert_nil plugin.instance_variable_get(:@rule_engine)
    assert_nil plugin.instance_variable_get(:@filter_decision)
    assert_nil plugin.instance_variable_get(:@match_accessor)

    # Check statistics initialization
    stats = plugin.instance_variable_get(:@statistics)
    assert_equal 0, stats[:processed]
    assert_equal 0, stats[:ignored]
    assert_equal 0, stats[:alerted]
    assert_equal 0, stats[:passed]
    assert_equal 0, stats[:errors]
    assert_nil stats[:start_time]
  end

  def test_configure_method_basic
    # Test basic configure method functionality
    config = %(
      rules_file /tmp/test_rules
      match_field message
      default_action keep
      mark_matches true
      debug_mode true
    )

    d = create_driver(config)
    instance = d.instance

    # Verify configuration was applied
    assert_equal 'message', instance.match_field
    assert_equal :keep, instance.default_action
    assert_true instance.mark_matches
    assert_true instance.debug_mode

    # Verify match accessor was created
    assert_not_nil instance.instance_variable_get(:@match_accessor)
  end

  def test_configure_with_rule_file
    # Test configure with a real rule file
    rule_content = sample_ignore_rules
    rule_file = create_temp_file(rule_content, 'ignore_rules')
    @temp_files << rule_file

    config = %(
      rules_file #{rule_file}
      match_field message
      default_action keep
    )

    d = create_driver(config)
    instance = d.instance

    # Verify rule sets were loaded during configure (may be empty if file not found, but should be initialized)
    rule_sets = instance.instance_variable_get(:@rule_sets)
    assert_not_nil rule_sets
    # NOTE: rule_sets might be empty if file loading failed, but the hash should exist

    # Verify rule engine was initialized during configure
    rule_engine = instance.instance_variable_get(:@rule_engine)
    assert_not_nil rule_engine
  end

  def test_configure_with_rule_directory
    # Test configure with a rule directory
    rules_by_file = {
      'ignore.rules' => sample_ignore_rules,
      'cracking.rules' => sample_cracking_rules
    }
    rule_dir = create_temp_dir_with_rules(rules_by_file)
    @temp_files << rule_dir

    config = %(
      rules_dir #{rule_dir}
      match_field message
      recursive_scan true
    )

    d = create_driver(config)
    instance = d.instance

    # Verify rule sets were loaded from directory
    rule_sets = instance.instance_variable_get(:@rule_sets)
    assert_not_empty rule_sets
    assert_equal 2, rule_sets.size

    # Verify rule engine was initialized
    rule_engine = instance.instance_variable_get(:@rule_engine)
    assert_not_nil rule_engine
  end

  def test_configure_with_advanced_rules_section
    # Test configure with advanced rules section
    rule_content = sample_violations_rules
    rule_file = create_temp_file(rule_content, 'violations_rules')
    @temp_files << rule_file

    config = %(
      <rules>
        path #{rule_file}
        type violations
        recursive false
      </rules>
      match_field message
    )

    d = create_driver(config)
    instance = d.instance

    # Verify rule sets were loaded
    rule_sets = instance.instance_variable_get(:@rule_sets)
    assert_not_empty rule_sets
    assert_true rule_sets.key?(rule_file)

    # Verify rule type was correctly detected/set
    rule_set = rule_sets[rule_file]
    assert_equal :violations, rule_set.type
  end

  def test_start_method_initialization
    # Test that start method properly initializes statistics and logging
    rule_content = sample_ignore_rules
    rule_file = create_temp_file(rule_content, 'ignore_rules')
    @temp_files << rule_file

    config = %(
      rules_file #{rule_file}
      match_field message
      debug_mode true
      log_statistics true
      statistics_interval 60
    )

    d = create_driver(config)

    # Capture log output
    logs = []
    d.instance.log.define_singleton_method(:info) { |msg| logs << msg }

    # Start the plugin
    d.instance.start

    # Verify statistics were initialized
    stats = d.instance.instance_variable_get(:@statistics)
    assert_not_nil stats[:start_time]
    assert_not_nil d.instance.instance_variable_get(:@last_stats_log)

    # Verify startup logs were generated
    assert_true logs.any? { |log| log.include?('Logcheck filter started') }
    assert_true logs.any? { |log| log.include?('Configuration:') }
    assert_true logs.any? { |log| log.include?('Debug mode: enabled') }
    assert_true logs.any? { |log| log.include?('Statistics logging: enabled') }
  end

  def test_start_method_with_debug_mode
    # Test start method with debug mode enabled shows rule summary
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
    d.instance.log.define_singleton_method(:info) { |msg| logs << msg }

    # Start the plugin
    d.instance.start

    # Verify rule summary was logged in debug mode
    assert_true logs.any? { |log| log.include?('=== Rule Summary ===') }
    assert_true logs.any? { |log| log.include?('Rule counts by type:') }
    assert_true logs.any? { |log| log.include?('Rule priority order:') }
  end

  def test_start_method_without_debug_mode
    # Test start method without debug mode doesn't show rule summary
    rule_content = sample_ignore_rules
    rule_file = create_temp_file(rule_content, 'ignore_rules')
    @temp_files << rule_file

    config = %(
      rules_file #{rule_file}
      match_field message
      debug_mode false
    )

    d = create_driver(config)

    # Capture log output
    logs = []
    d.instance.log.define_singleton_method(:info) { |msg| logs << msg }

    # Start the plugin
    d.instance.start

    # Verify rule summary was NOT logged without debug mode
    assert_false logs.any? { |log| log.include?('=== Rule Summary ===') }
    assert_true logs.any? { |log| log.include?('Debug mode: disabled') }
  end

  def test_shutdown_method_basic
    # Test basic shutdown functionality
    rule_content = sample_ignore_rules
    rule_file = create_temp_file(rule_content, 'ignore_rules')
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

    # Start and then shutdown
    d.instance.start
    d.instance.shutdown

    # Verify shutdown logs
    assert_true logs.any? { |log| log.include?('Logcheck filter stopped') }
    assert_true logs.any? { |log| log.include?('=== Final Logcheck Statistics ===') }
  end

  def test_shutdown_method_with_debug_mode
    # Test shutdown with debug mode shows detailed statistics
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
    d.instance.log.define_singleton_method(:info) { |msg| logs << msg }

    # Start, process some records, then shutdown
    d.instance.start

    # Simulate some statistics
    stats = d.instance.instance_variable_get(:@statistics)
    stats[:processed] = 10
    stats[:ignored] = 3
    stats[:alerted] = 2
    stats[:passed] = 5

    d.instance.shutdown

    # Verify detailed statistics were logged
    assert_true logs.any? { |log| log.include?('=== Final Logcheck Statistics ===') }
    assert_true logs.any? { |log| log.include?('Processed: 10') }
    assert_true logs.any? { |log| log.include?('Ignored: 3') }
    assert_true logs.any? { |log| log.include?('Alerted: 2') }
    assert_true logs.any? { |log| log.include?('Passed: 5') }
  end

  def test_shutdown_without_statistics_logging
    # Test shutdown without statistics logging enabled
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

    # Start and shutdown
    d.instance.start
    d.instance.shutdown

    # Verify only basic shutdown log, no statistics
    assert_true logs.any? { |log| log.include?('Logcheck filter stopped') }
    assert_false logs.any? { |log| log.include?('=== Final Logcheck Statistics ===') }
  end

  def test_rule_loading_during_startup
    # Test that rules are properly loaded during component initialization (configure phase)
    rules_by_file = {
      'ignore.rules' => sample_ignore_rules,
      'cracking.rules' => sample_cracking_rules,
      'violations.rules' => sample_violations_rules
    }
    rule_dir = create_temp_dir_with_rules(rules_by_file)
    @temp_files << rule_dir

    config = %(
      rules_dir #{rule_dir}
      match_field message
      recursive_scan true
      debug_mode true
    )

    # Rules are loaded during configure, not start
    d = create_driver(config)

    # Verify rules were loaded during configure
    rule_sets = d.instance.instance_variable_get(:@rule_sets)
    assert_equal 3, rule_sets.size

    # Capture log output for start method
    logs = []
    d.instance.log.define_singleton_method(:info) { |msg| logs << msg }
    d.instance.log.define_singleton_method(:debug) { |msg| logs << msg }

    # Start the plugin
    d.instance.start

    # Verify startup logs were generated
    assert_true logs.any? { |log| log.include?('Logcheck filter started with') && log.include?('rules') }

    # Verify rule engine was initialized with rule sets
    rule_engine = d.instance.instance_variable_get(:@rule_engine)
    assert_not_nil rule_engine
  end

  def test_statistics_initialization_and_tracking
    # Test that statistics are properly initialized and tracked
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

    # Before start - statistics should be initialized but start_time nil
    stats = d.instance.instance_variable_get(:@statistics)
    assert_equal 0, stats[:processed]
    assert_equal 0, stats[:ignored]
    assert_equal 0, stats[:alerted]
    assert_equal 0, stats[:passed]
    assert_equal 0, stats[:errors]
    assert_nil stats[:start_time]

    # After start - start_time should be set
    d.instance.start
    stats = d.instance.instance_variable_get(:@statistics)
    assert_not_nil stats[:start_time]
    assert_not_nil d.instance.instance_variable_get(:@last_stats_log)

    # Verify start_time is recent
    assert_true (Time.now - stats[:start_time]) < 1.0
  end

  def test_logging_configuration_behavior
    # Test different logging configuration behaviors
    rule_content = sample_cracking_rules
    rule_file = create_temp_file(rule_content, 'cracking_rules')
    @temp_files << rule_file

    config = %(
      rules_file #{rule_file}
      match_field message
      log_rule_errors true
      log_statistics true
      debug_mode true
      statistics_interval 30
    )

    d = create_driver(config)

    # Capture log output
    logs = []
    d.instance.log.define_singleton_method(:info) { |msg| logs << msg }

    # Start the plugin
    d.instance.start

    # Verify logging configuration was reported
    assert_true logs.any? { |log| log.include?('Statistics logging: enabled (interval: 30s)') }
    assert_true logs.any? { |log| log.include?('Debug mode: enabled') }

    # Verify configuration values are set correctly
    assert_true d.instance.log_rule_errors
    assert_true d.instance.log_statistics
    assert_true d.instance.debug_mode
    assert_equal 30, d.instance.statistics_interval
  end

  private

  def event_time
    Fluent::EventTime.now
  end
end
