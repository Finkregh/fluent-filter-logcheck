# frozen_string_literal: true

require_relative '../helper'
require 'fluent/plugin/logcheck/rule_types'

class RuleTypesTest < Test::Unit::TestCase
  def test_constants_defined
    # Verify all rule type constants are defined
    assert_equal :ignore, Fluent::Plugin::Logcheck::RuleTypes::IGNORE
    assert_equal :cracking, Fluent::Plugin::Logcheck::RuleTypes::CRACKING
    assert_equal :violations, Fluent::Plugin::Logcheck::RuleTypes::VIOLATIONS
  end

  def test_all_types_array
    # Verify ALL_TYPES contains all rule types
    expected_types = %i(ignore cracking violations)
    assert_equal expected_types, Fluent::Plugin::Logcheck::RuleTypes::ALL_TYPES
  end

  def test_default_priority
    # Verify default priority order (security types first)
    expected_priority = %i(cracking violations ignore)
    assert_equal expected_priority, Fluent::Plugin::Logcheck::RuleTypes::DEFAULT_PRIORITY
  end

  def test_detect_from_path_ignore
    # Test ignore rule detection from various paths
    ignore_paths = [
      '/etc/logcheck/ignore.d.server/ssh',
      '/path/to/ignore.d.paranoid/kernel',
      'ignore.d.workstation/systemd',
      '/home/user/rules/ignore.d/custom'
    ]

    ignore_paths.each do |path|
      assert_equal :ignore, Fluent::Plugin::Logcheck::RuleTypes.detect_from_path(path),
                   "Failed to detect ignore type for path: #{path}"
    end
  end

  def test_detect_from_path_cracking
    # Test cracking rule detection from various paths
    cracking_paths = [
      '/etc/logcheck/cracking.d/ssh',
      '/path/to/cracking.d/kernel',
      'cracking.d/custom',
      '/home/user/rules/cracking.d/security'
    ]

    cracking_paths.each do |path|
      assert_equal :cracking, Fluent::Plugin::Logcheck::RuleTypes.detect_from_path(path),
                   "Failed to detect cracking type for path: #{path}"
    end
  end

  def test_detect_from_path_violations
    # Test violations rule detection from various paths
    violations_paths = [
      '/etc/logcheck/violations.d/kernel',
      '/path/to/violations.d/system',
      'violations.d/custom',
      '/home/user/rules/violations.d/errors'
    ]

    violations_paths.each do |path|
      assert_equal :violations, Fluent::Plugin::Logcheck::RuleTypes.detect_from_path(path),
                   "Failed to detect violations type for path: #{path}"
    end
  end

  def test_detect_from_path_unknown
    # Test unknown path handling
    unknown_paths = [
      '/unknown/path/file',
      '/etc/logcheck/unknown.d/test',
      'random_file.txt',
      '/path/without/type/indicator'
    ]

    unknown_paths.each do |path|
      assert_nil Fluent::Plugin::Logcheck::RuleTypes.detect_from_path(path),
                 "Should return nil for unknown path: #{path}"
    end
  end

  def test_valid_type
    # Test rule type validation for valid types
    Fluent::Plugin::Logcheck::RuleTypes::ALL_TYPES.each do |type|
      assert_true Fluent::Plugin::Logcheck::RuleTypes.valid_type?(type),
                  "#{type} should be a valid rule type"
    end
  end

  def test_invalid_type
    # Test rule type validation for invalid types
    invalid_types = [:unknown, :invalid, nil, '', 'string', 123]

    invalid_types.each do |type|
      assert_false Fluent::Plugin::Logcheck::RuleTypes.valid_type?(type),
                   "#{type.inspect} should not be a valid rule type"
    end
  end

  def test_priority
    # Test rule type priority values
    assert_equal 0, Fluent::Plugin::Logcheck::RuleTypes.priority(:cracking)
    assert_equal 1, Fluent::Plugin::Logcheck::RuleTypes.priority(:violations)
    assert_equal 2, Fluent::Plugin::Logcheck::RuleTypes.priority(:ignore)
  end

  def test_priority_unknown_type
    # Test priority for unknown types
    assert_equal 999, Fluent::Plugin::Logcheck::RuleTypes.priority(:unknown)
    assert_equal 999, Fluent::Plugin::Logcheck::RuleTypes.priority(nil)
  end

  def test_security_type
    # Test security type detection
    assert_true Fluent::Plugin::Logcheck::RuleTypes.security_type?(:cracking)
    assert_true Fluent::Plugin::Logcheck::RuleTypes.security_type?(:violations)
    assert_false Fluent::Plugin::Logcheck::RuleTypes.security_type?(:ignore)
    assert_false Fluent::Plugin::Logcheck::RuleTypes.security_type?(:unknown)
    assert_false Fluent::Plugin::Logcheck::RuleTypes.security_type?(nil)
  end

  def test_path_patterns_frozen
    # Verify PATH_PATTERNS is frozen to prevent modification
    assert_true Fluent::Plugin::Logcheck::RuleTypes::PATH_PATTERNS.frozen?
  end

  def test_all_types_frozen
    # Verify ALL_TYPES is frozen to prevent modification
    assert_true Fluent::Plugin::Logcheck::RuleTypes::ALL_TYPES.frozen?
  end

  def test_default_priority_frozen
    # Verify DEFAULT_PRIORITY is frozen to prevent modification
    assert_true Fluent::Plugin::Logcheck::RuleTypes::DEFAULT_PRIORITY.frozen?
  end
end
