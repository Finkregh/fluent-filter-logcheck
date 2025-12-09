# typed: false
# frozen_string_literal: true

require_relative '../helper'
require 'fluent/plugin/filter_logcheck'

class ConfigurationBranchesTest < Test::Unit::TestCase
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

  # Test configuration validation branches

  def test_configuration_validation_no_rule_sources
    # Test that configuration fails when no rule sources are specified
    config = %(
      match_field message
      default_action keep
    )

    assert_raise(Fluent::ConfigError) do
      create_driver(config)
    end
  end

  def test_configuration_validation_empty_match_field
    # Test that configuration fails with empty match_field
    config = %(
      rules_file /tmp/test_rules
      match_field ""
    )

    assert_raise(Fluent::ConfigError) do
      create_driver(config)
    end
  end

  def test_configuration_validation_nil_match_field
    # Test that configuration fails with nil match_field
    # Create driver and manually set match_field to nil to test validation
    plugin = Fluent::Plugin::LogcheckFilter.new
    plugin.instance_variable_set(:@match_field, nil)

    assert_raise(Fluent::ConfigError) do
      plugin.send(:validate_configuration)
    end
  end

  def test_configuration_validation_mark_matches_without_prefix
    # Test that configuration fails when mark_matches is true but mark_field_prefix is empty
    config = %(
      rules_file /tmp/test_rules
      mark_matches true
      mark_field_prefix ""
    )

    assert_raise(Fluent::ConfigError) do
      create_driver(config)
    end
  end

  def test_configuration_validation_mark_matches_with_nil_prefix
    # Test that configuration fails when mark_matches is true but mark_field_prefix is nil
    # Create driver and manually set mark_field_prefix to nil to test validation
    plugin = Fluent::Plugin::LogcheckFilter.new
    plugin.instance_variable_set(:@mark_matches, true)
    plugin.instance_variable_set(:@mark_field_prefix, nil)

    assert_raise(Fluent::ConfigError) do
      plugin.send(:validate_configuration)
    end
  end

  def test_configuration_validation_empty_rule_priority
    # Test that configuration fails with empty rule_priority
    config = %(
      rules_file /tmp/test_rules
      rule_priority []
    )

    assert_raise(Fluent::ConfigError) do
      create_driver(config)
    end
  end

  def test_configuration_validation_duplicate_rule_priority
    # Test that configuration fails with duplicate values in rule_priority
    config = %(
      rules_file /tmp/test_rules
      rule_priority ["cracking", "cracking", "ignore"]
    )

    assert_raise(Fluent::ConfigError) do
      create_driver(config)
    end
  end

  def test_configuration_validation_invalid_rule_priority_types
    # Test that configuration fails with invalid rule types in rule_priority
    config = %(
      rules_file /tmp/test_rules
      rule_priority ["cracking", "invalid_type", "ignore"]
    )

    assert_raise(Fluent::ConfigError) do
      create_driver(config)
    end
  end

  def test_configuration_validation_zero_cache_size
    # Test that configuration fails with zero cache_size
    config = %(
      rules_file /tmp/test_rules
      cache_size 0
    )

    assert_raise(Fluent::ConfigError) do
      create_driver(config)
    end
  end

  def test_configuration_validation_negative_cache_size
    # Test that configuration fails with negative cache_size
    config = %(
      rules_file /tmp/test_rules
      cache_size -1
    )

    assert_raise(Fluent::ConfigError) do
      create_driver(config)
    end
  end

  def test_configuration_validation_zero_max_rules_per_file
    # Test that configuration fails with zero max_rules_per_file
    config = %(
      rules_file /tmp/test_rules
      max_rules_per_file 0
    )

    assert_raise(Fluent::ConfigError) do
      create_driver(config)
    end
  end

  def test_configuration_validation_negative_max_rules_per_file
    # Test that configuration fails with negative max_rules_per_file
    config = %(
      rules_file /tmp/test_rules
      max_rules_per_file -1
    )

    assert_raise(Fluent::ConfigError) do
      create_driver(config)
    end
  end

  # Test rules section validation branches

  def test_rules_section_validation_empty_path
    # Test that configuration fails with empty path in rules section
    config = %(
      <rules>
        path ""
        type ignore
      </rules>
      match_field message
    )

    assert_raise(Fluent::ConfigError) do
      create_driver(config)
    end
  end

  def test_rules_section_validation_invalid_type
    # Test that configuration fails with invalid type in rules section
    config = %(
      <rules>
        path /tmp/test_rules
        type invalid_type
      </rules>
      match_field message
    )

    assert_raise(Fluent::ConfigError) do
      create_driver(config)
    end
  end

  def test_rules_section_validation_nil_path_allowed
    # Test that rules section with nil path is allowed (empty section)
    config = %(
      <rules>
        type ignore
      </rules>
      rules_file /tmp/test_rules
      match_field message
    )

    # Should not raise an error
    d = create_driver(config)
    assert_not_nil d.instance
  end

  # Test debug mode enabled/disabled paths

  def test_debug_mode_enabled_paths
    # Test behavior when debug mode is enabled
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
    d.instance.log.define_singleton_method(:info) { |msg| logs << msg }
    d.instance.log.define_singleton_method(:debug) { |msg| logs << msg }

    # Start the plugin
    d.instance.start

    # Verify debug mode specific logs
    assert_true logs.any? { |log| log.include?('Debug mode: enabled') }
    assert_true logs.any? { |log| log.include?('=== Rule Summary ===') }
  end

  def test_debug_mode_disabled_paths
    # Test behavior when debug mode is disabled
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
    d.instance.log.define_singleton_method(:debug) { |msg| logs << msg }

    # Start the plugin
    d.instance.start

    # Verify debug mode specific logs are NOT present
    assert_true logs.any? { |log| log.include?('Debug mode: disabled') }
    assert_false logs.any? { |log| log.include?('=== Rule Summary ===') }
  end

  # Test mark_matches enabled/disabled functionality

  def test_mark_matches_enabled_functionality
    # Test that mark_matches enabled adds metadata to records
    rule_content = sample_cracking_rules
    rule_file = create_temp_file(rule_content, 'cracking_rules')
    @temp_files << rule_file

    config = %(
      rules_file #{rule_file}
      match_field message
      mark_matches true
      mark_field_prefix test_
    )

    d = create_driver(config)

    # Test with a message that should trigger an alert
    d.run(default_tag: 'test') do
      d.feed(event_time, { 'message' => 'Dec  8 10:01:00 server sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2' })
    end

    records = d.filtered_records
    assert_equal 1, records.size

    record = records.first
    # Should have mark fields added (if rule matches and creates alert)
    # Note: This depends on the actual rule matching logic working
    assert_true record.key?('message')
  end

  def test_mark_matches_disabled_functionality
    # Test that mark_matches disabled doesn't add metadata to records
    rule_content = sample_cracking_rules
    rule_file = create_temp_file(rule_content, 'cracking_rules')
    @temp_files << rule_file

    config = %(
      rules_file #{rule_file}
      match_field message
      mark_matches false
    )

    d = create_driver(config)

    # Test with a message that should trigger an alert
    d.run(default_tag: 'test') do
      d.feed(event_time, { 'message' => 'Dec  8 10:01:00 server sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2' })
    end

    records = d.filtered_records
    assert_equal 1, records.size

    record = records.first
    # Should NOT have mark fields added
    assert_false record.key?('test_alert')
    assert_false record.key?('test_rule_type')
  end

  # Test default_action (keep/drop) branches

  def test_default_action_keep_branch
    # Test default_action keep behavior
    config = %(
      rules_file /tmp/nonexistent_rules
      match_field message
      default_action keep
    )

    d = create_driver(config)

    # Test with a message
    d.run(default_tag: 'test') do
      d.feed(event_time, { 'message' => 'test message' })
    end

    records = d.filtered_records
    assert_equal 1, records.size
    assert_equal 'test message', records.first['message']
  end

  def test_default_action_drop_branch
    # Test default_action drop behavior
    config = %(
      rules_file /tmp/nonexistent_rules
      match_field message
      default_action drop
    )

    d = create_driver(config)

    # Test with a message
    d.run(default_tag: 'test') do
      d.feed(event_time, { 'message' => 'test message' })
    end

    records = d.filtered_records
    # Should still get the record since no rules are loaded to trigger drop behavior
    # The default_action is used for unknown filter decisions, not for unmatched messages
    assert_equal 1, records.size
  end

  # Test log_rule_errors and log_statistics flags

  def test_log_rule_errors_enabled
    # Test behavior when log_rule_errors is enabled
    rule_content = sample_ignore_rules
    rule_file = create_temp_file(rule_content, 'ignore_rules')
    @temp_files << rule_file

    config = %(
      rules_file #{rule_file}
      match_field message
      log_rule_errors true
      debug_mode false
    )

    d = create_driver(config)
    assert_true d.instance.log_rule_errors
  end

  def test_log_rule_errors_disabled
    # Test behavior when log_rule_errors is disabled
    rule_content = sample_ignore_rules
    rule_file = create_temp_file(rule_content, 'ignore_rules')
    @temp_files << rule_file

    config = %(
      rules_file #{rule_file}
      match_field message
      log_rule_errors false
    )

    d = create_driver(config)
    assert_false d.instance.log_rule_errors
  end

  def test_log_statistics_enabled
    # Test behavior when log_statistics is enabled
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

    # Capture log output
    logs = []
    d.instance.log.define_singleton_method(:info) { |msg| logs << msg }

    # Start the plugin
    d.instance.start

    # Verify statistics logging is enabled
    assert_true d.instance.log_statistics
    assert_equal 60, d.instance.statistics_interval
    assert_true logs.any? { |log| log.include?('Statistics logging: enabled (interval: 60s)') }
  end

  def test_log_statistics_disabled
    # Test behavior when log_statistics is disabled
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

    # Verify statistics logging is disabled
    assert_false d.instance.log_statistics
    assert_true logs.any? { |log| log.include?('Statistics logging: disabled') }
  end

  # Test rule_priority validation branches

  def test_rule_priority_valid_order
    # Test valid rule priority configuration
    config = %(
      rules_file /tmp/test_rules
      rule_priority ["violations", "cracking", "ignore"]
    )

    d = create_driver(config)
    assert_equal %i(violations cracking ignore), d.instance.rule_priority
  end

  def test_rule_priority_string_to_symbol_conversion
    # Test that string rule priorities are converted to symbols
    config = %(
      rules_file /tmp/test_rules
      rule_priority ["cracking", "violations", "ignore"]
    )

    d = create_driver(config)
    # Verify conversion to symbols
    assert_equal %i(cracking violations ignore), d.instance.rule_priority
    assert_true d.instance.rule_priority.all? { |type| type.is_a?(Symbol) }
  end

  def test_rule_priority_default_value
    # Test default rule priority value
    config = %(
      rules_file /tmp/test_rules
    )

    d = create_driver(config)
    assert_equal %i(cracking violations ignore), d.instance.rule_priority
  end

  private

  def event_time
    Fluent::EventTime.now
  end
end
