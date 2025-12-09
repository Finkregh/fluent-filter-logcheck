# typed: false
# frozen_string_literal: true

require_relative '../helper'
require 'fluent/plugin/filter_logcheck'

class FilterLogcheckTest < Test::Unit::TestCase
  include Fluent::Test::Helpers

  def setup
    Fluent::Test.setup
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

  def test_plugin_registration
    # Test that the plugin is properly registered
    assert_not_nil Fluent::Plugin.new_filter('logcheck')
  end

  def test_basic_configuration
    # Test basic plugin configuration
    config = %(
      rules_file /tmp/test_rules
      match_field message
      default_action keep
    )

    d = create_driver(config)
    assert_not_nil d.instance
    assert_equal 'message', d.instance.match_field
    assert_equal :keep, d.instance.default_action
  end

  def test_configuration_validation_no_rules
    # Test that configuration fails when no rule sources are specified
    config = %(
      match_field message
      default_action keep
    )

    assert_raise(Fluent::ConfigError) do
      create_driver(config)
    end
  end

  def test_configuration_validation_invalid_cache_size
    # Test that configuration fails with invalid cache size
    config = %(
      rules_file /tmp/test_rules
      cache_size 0
    )

    assert_raise(Fluent::ConfigError) do
      create_driver(config)
    end
  end

  def test_configuration_validation_invalid_rule_priority
    # Test that configuration fails with invalid rule priority
    config = %(
      rules_file /tmp/test_rules
      rule_priority ["invalid_type"]
    )

    assert_raise(Fluent::ConfigError) do
      create_driver(config)
    end
  end

  def test_advanced_configuration
    # Test advanced configuration with multiple rule sources
    config = %(
      <rules>
        path /etc/logcheck/ignore.d.server
        type ignore
        recursive true
      </rules>
      <rules>
        path /etc/logcheck/cracking.d
        type cracking
      </rules>

      match_field message
      mark_matches true
      mark_field_prefix logcheck_
      rule_priority ["cracking", "violations", "ignore"]
    )

    d = create_driver(config)
    assert_not_nil d.instance
    assert_equal 'message', d.instance.match_field
    assert_true d.instance.mark_matches
    assert_equal 'logcheck_', d.instance.mark_field_prefix
    assert_equal %i(cracking violations ignore), d.instance.rule_priority
  end

  def test_default_values
    # Test that default configuration values are set correctly
    config = %(
      rules_file /tmp/test_rules
    )

    d = create_driver(config)
    instance = d.instance

    assert_equal 'message', instance.match_field
    assert_equal :keep, instance.default_action
    assert_false instance.mark_matches
    assert_equal 'logcheck_', instance.mark_field_prefix
    assert_equal 1000, instance.cache_size
    assert_true instance.recursive_scan
    assert_true instance.ignore_parse_errors
    assert_true instance.log_rule_errors
    assert_equal 1000, instance.max_rules_per_file
    assert_equal %i(cracking violations ignore), instance.rule_priority
  end

  def test_filter_with_no_rules_loaded
    # Test filtering behavior when no rules are loaded (skeleton implementation)
    config = %(
      rules_file /tmp/nonexistent_rules
      default_action keep
    )

    d = create_driver(config)

    # Since we haven't implemented rule loading yet, this should just pass through
    d.run(default_tag: 'test') do
      d.feed(event_time, { 'message' => 'test log message' })
    end

    records = d.filtered_records
    assert_equal 1, records.size
    assert_equal 'test log message', records.first['message']
  end

  def test_filter_with_different_match_fields
    # Test filtering with different match fields
    config = %(
      rules_file /tmp/test_rules
      match_field log_text
      default_action keep
    )

    d = create_driver(config)

    d.run(default_tag: 'test') do
      d.feed(event_time, { 'log_text' => 'test message', 'other_field' => 'value' })
    end

    records = d.filtered_records
    assert_equal 1, records.size
    assert_equal 'test message', records.first['log_text']
  end

  def test_filter_with_missing_match_field
    # Test filtering when match field is missing from record
    config = %(
      rules_file /tmp/test_rules
      match_field message
      default_action keep
    )

    d = create_driver(config)

    d.run(default_tag: 'test') do
      d.feed(event_time, { 'other_field' => 'value' })
    end

    records = d.filtered_records
    assert_equal 1, records.size
    assert_equal 'value', records.first['other_field']
  end

  def test_filter_error_handling
    # Test that filter handles errors gracefully
    config = %(
      rules_file /tmp/test_rules
      match_field message
    )

    d = create_driver(config)

    # This should not raise an error even with our skeleton implementation
    d.run(default_tag: 'test') do
      d.feed(event_time, { 'message' => 'test' })
    end

    records = d.filtered_records
    assert_equal 1, records.size
  end

  def test_configuration_with_rules_dir
    # Test configuration with rules_dir parameter
    config = %(
      rules_dir /etc/logcheck/ignore.d.server
      match_field message
    )

    d = create_driver(config)
    assert_equal '/etc/logcheck/ignore.d.server', d.instance.rules_dir
  end

  def test_configuration_with_both_file_and_dir
    # Test configuration with both rules_file and rules_dir
    config = %(
      rules_file /tmp/test_rules
      rules_dir /etc/logcheck/ignore.d.server
      match_field message
    )

    # Should not raise an error - both can be specified
    d = create_driver(config)
    assert_equal '/tmp/test_rules', d.instance.rules_file
    assert_equal '/etc/logcheck/ignore.d.server', d.instance.rules_dir
  end

  private

  def event_time
    Fluent::EventTime.now
  end
end
