# typed: false
# frozen_string_literal: true

require_relative '../helper'
require_relative '../support/rule_file_helpers'
require 'fluent/plugin/logcheck/rule_engine'
require 'fluent/plugin/logcheck/rule_loader'

class RuleEngineIntegrationTest < Test::Unit::TestCase
  include RuleFileHelpers

  def setup
    @temp_dir = Dir.mktmpdir('rule_engine_integration_test')
    setup_test_rules
    @logger = TestLogger.new
  end

  def teardown
    cleanup_temp_files(@temp_dir) if @temp_dir && Dir.exist?(@temp_dir)
  end

  def setup_test_rules
    @ignore_file = create_ignore_rules(@temp_dir)
    @cracking_file = create_cracking_rules(@temp_dir)
    @violations_file = create_violations_rules(@temp_dir)
  end

  sub_test_case 'rule engine filtering' do
    test 'filters messages with ignore rules' do
      engine = Fluent::Plugin::Logcheck::RuleEngine.new(logger: @logger)
      rule_loader = Fluent::Plugin::Logcheck::RuleLoader.new(logger: @logger)

      # Load ignore rules
      ignore_rule_set = rule_loader.load_file(@ignore_file, :ignore)
      engine.add_rule_set(ignore_rule_set)

      # Test systemd message that should be ignored
      decision = engine.filter(sample_real_log_messages[:systemd_start])

      assert_equal Fluent::Plugin::Logcheck::FilterDecision::IGNORE, decision.decision
      assert_true decision.ignore?
      assert_false decision.alert?
      assert_false decision.pass?
      assert_true decision.matched?
      assert_equal :ignore, decision.rule_type
    end

    test 'creates alerts for cracking rules' do
      engine = Fluent::Plugin::Logcheck::RuleEngine.new(logger: @logger)
      rule_loader = Fluent::Plugin::Logcheck::RuleLoader.new(logger: @logger)

      # Load cracking rules
      cracking_rule_set = rule_loader.load_file(@cracking_file, :cracking)
      engine.add_rule_set(cracking_rule_set)

      # Test SSH attack message that should trigger alert
      decision = engine.filter(sample_real_log_messages[:ssh_failed])

      assert_equal Fluent::Plugin::Logcheck::FilterDecision::ALERT, decision.decision
      assert_false decision.ignore?
      assert_true decision.alert?
      assert_false decision.pass?
      assert_true decision.matched?
      assert_equal :cracking, decision.rule_type
    end

    test 'creates alerts for violations rules' do
      engine = Fluent::Plugin::Logcheck::RuleEngine.new(logger: @logger)
      rule_loader = Fluent::Plugin::Logcheck::RuleLoader.new(logger: @logger)

      # Load violations rules
      violations_rule_set = rule_loader.load_file(@violations_file, :violations)
      engine.add_rule_set(violations_rule_set)

      # Test kernel error message that should trigger alert
      decision = engine.filter(sample_real_log_messages[:kernel_io_error])

      assert_equal Fluent::Plugin::Logcheck::FilterDecision::ALERT, decision.decision
      assert_true decision.alert?
      assert_equal :violations, decision.rule_type
    end

    test 'passes through unmatched messages' do
      engine = Fluent::Plugin::Logcheck::RuleEngine.new(logger: @logger)
      rule_loader = Fluent::Plugin::Logcheck::RuleLoader.new(logger: @logger)

      # Load some rules
      ignore_rule_set = rule_loader.load_file(@ignore_file, :ignore)
      engine.add_rule_set(ignore_rule_set)

      # Test message that doesn't match any rules
      decision = engine.filter(sample_real_log_messages[:normal_app])

      assert_equal Fluent::Plugin::Logcheck::FilterDecision::PASS, decision.decision
      assert_false decision.ignore?
      assert_false decision.alert?
      assert_true decision.pass?
      assert_false decision.matched?
      assert_nil decision.rule_type
    end
  end

  sub_test_case 'rule precedence logic' do
    test 'cracking rules take precedence over ignore rules' do
      engine = Fluent::Plugin::Logcheck::RuleEngine.new(logger: @logger)
      rule_loader = Fluent::Plugin::Logcheck::RuleLoader.new(logger: @logger)

      # Create overlapping rules
      overlapping_ignore = File.join(@temp_dir, 'overlap_ignore.rules')
      File.write(overlapping_ignore, '^.*sshd.*$') # Broad pattern that matches SSH messages

      overlapping_cracking = File.join(@temp_dir, 'overlap_cracking.rules')
      File.write(overlapping_cracking, '^.*Failed password.*$') # Specific cracking pattern

      # Load both rule sets
      ignore_rule_set = rule_loader.load_file(overlapping_ignore, :ignore)
      cracking_rule_set = rule_loader.load_file(overlapping_cracking, :cracking)

      engine.add_rule_set(ignore_rule_set)
      engine.add_rule_set(cracking_rule_set)

      # Test message that matches both rules
      decision = engine.filter(sample_real_log_messages[:ssh_failed])

      # Should be treated as cracking (higher precedence)
      assert_equal Fluent::Plugin::Logcheck::FilterDecision::ALERT, decision.decision
      assert_equal :cracking, decision.rule_type
    end

    test 'violations rules take precedence over ignore rules' do
      engine = Fluent::Plugin::Logcheck::RuleEngine.new(logger: @logger)
      rule_loader = Fluent::Plugin::Logcheck::RuleLoader.new(logger: @logger)

      # Create overlapping rules
      overlapping_ignore = File.join(@temp_dir, 'overlap_ignore2.rules')
      File.write(overlapping_ignore, '^.*kernel.*$') # Broad pattern

      overlapping_violations = File.join(@temp_dir, 'overlap_violations.rules')
      File.write(overlapping_violations, '^.*I/O error.*$') # Specific violations pattern

      # Load both rule sets
      ignore_rule_set = rule_loader.load_file(overlapping_ignore, :ignore)
      violations_rule_set = rule_loader.load_file(overlapping_violations, :violations)

      engine.add_rule_set(ignore_rule_set)
      engine.add_rule_set(violations_rule_set)

      # Test message that matches both rules
      decision = engine.filter(sample_real_log_messages[:kernel_io_error])

      # Should be treated as violations (higher precedence)
      assert_equal Fluent::Plugin::Logcheck::FilterDecision::ALERT, decision.decision
      assert_equal :violations, decision.rule_type
    end

    test 'cracking rules take precedence over violations rules' do
      engine = Fluent::Plugin::Logcheck::RuleEngine.new(logger: @logger)
      rule_loader = Fluent::Plugin::Logcheck::RuleLoader.new(logger: @logger)

      # Create overlapping rules
      overlapping_violations = File.join(@temp_dir, 'overlap_violations2.rules')
      File.write(overlapping_violations, '^.*authentication.*$') # Broad pattern

      overlapping_cracking = File.join(@temp_dir, 'overlap_cracking2.rules')
      File.write(overlapping_cracking, '^.*Failed password.*$') # Specific cracking pattern

      # Load both rule sets
      violations_rule_set = rule_loader.load_file(overlapping_violations, :violations)
      cracking_rule_set = rule_loader.load_file(overlapping_cracking, :cracking)

      engine.add_rule_set(violations_rule_set)
      engine.add_rule_set(cracking_rule_set)

      # Create message that matches both
      message = 'Dec  8 10:01:00 server sshd[1234]: Failed password authentication failure'
      decision = engine.filter(message)

      # Should be treated as cracking (highest precedence)
      assert_equal Fluent::Plugin::Logcheck::FilterDecision::ALERT, decision.decision
      assert_equal :cracking, decision.rule_type
    end
  end

  sub_test_case 'multiple rule set handling' do
    test 'handles multiple rule sets of same type' do
      engine = Fluent::Plugin::Logcheck::RuleEngine.new(logger: @logger)
      rule_loader = Fluent::Plugin::Logcheck::RuleLoader.new(logger: @logger)

      # Create multiple ignore rule files
      ignore_file1 = File.join(@temp_dir, 'ignore1.rules')
      File.write(ignore_file1, '^.*systemd.*$')

      ignore_file2 = File.join(@temp_dir, 'ignore2.rules')
      File.write(ignore_file2, '^.*cron.*$')

      # Load both rule sets
      ignore_rule_set1 = rule_loader.load_file(ignore_file1, :ignore)
      ignore_rule_set2 = rule_loader.load_file(ignore_file2, :ignore)

      engine.add_rule_set(ignore_rule_set1)
      engine.add_rule_set(ignore_rule_set2)

      # Test messages that match different rule sets
      decision1 = engine.filter(sample_real_log_messages[:systemd_start])
      decision2 = engine.filter(sample_real_log_messages[:cron_job])

      # Both should be ignored
      assert_equal Fluent::Plugin::Logcheck::FilterDecision::IGNORE, decision1.decision
      assert_equal Fluent::Plugin::Logcheck::FilterDecision::IGNORE, decision2.decision
    end

    test 'handles mixed rule types correctly' do
      engine = Fluent::Plugin::Logcheck::RuleEngine.new(logger: @logger)
      rule_loader = Fluent::Plugin::Logcheck::RuleLoader.new(logger: @logger)

      # Load all types of rules
      ignore_rule_set = rule_loader.load_file(@ignore_file, :ignore)
      cracking_rule_set = rule_loader.load_file(@cracking_file, :cracking)
      violations_rule_set = rule_loader.load_file(@violations_file, :violations)

      engine.add_rule_set(ignore_rule_set)
      engine.add_rule_set(cracking_rule_set)
      engine.add_rule_set(violations_rule_set)

      # Test different message types
      ignore_decision = engine.filter(sample_real_log_messages[:systemd_start])
      cracking_decision = engine.filter(sample_real_log_messages[:ssh_failed])
      violations_decision = engine.filter(sample_real_log_messages[:kernel_io_error])
      pass_decision = engine.filter(sample_real_log_messages[:normal_app])

      # Verify correct decisions
      assert_equal Fluent::Plugin::Logcheck::FilterDecision::IGNORE, ignore_decision.decision
      assert_equal Fluent::Plugin::Logcheck::FilterDecision::ALERT, cracking_decision.decision
      assert_equal Fluent::Plugin::Logcheck::FilterDecision::ALERT, violations_decision.decision
      assert_equal Fluent::Plugin::Logcheck::FilterDecision::PASS, pass_decision.decision

      # Verify rule types
      assert_equal :ignore, ignore_decision.rule_type
      assert_equal :cracking, cracking_decision.rule_type
      assert_equal :violations, violations_decision.rule_type
      assert_nil pass_decision.rule_type
    end
  end

  sub_test_case 'statistics tracking' do
    test 'tracks filtering statistics correctly' do
      engine = Fluent::Plugin::Logcheck::RuleEngine.new(logger: @logger)
      rule_loader = Fluent::Plugin::Logcheck::RuleLoader.new(logger: @logger)

      # Load all types of rules
      ignore_rule_set = rule_loader.load_file(@ignore_file, :ignore)
      cracking_rule_set = rule_loader.load_file(@cracking_file, :cracking)

      engine.add_rule_set(ignore_rule_set)
      engine.add_rule_set(cracking_rule_set)

      # Process various messages
      engine.filter(sample_real_log_messages[:systemd_start]) # ignore
      engine.filter(sample_real_log_messages[:ssh_failed])      # alert
      engine.filter(sample_real_log_messages[:normal_app])      # pass
      engine.filter(sample_real_log_messages[:cron_job])        # ignore
      engine.filter(sample_real_log_messages[:ssh_invalid])     # alert

      stats = engine.statistics

      # Verify statistics
      assert_equal 5, stats[:total_messages]
      assert_equal 2, stats[:ignored_messages]
      assert_equal 2, stats[:alert_messages]
      assert_equal 1, stats[:passed_messages]

      # Verify rule match counts
      rule_matches = stats[:rule_matches]
      assert_equal 2, rule_matches[:ignore]
      assert_equal 2, rule_matches[:cracking]
    end

    test 'resets statistics correctly' do
      engine = Fluent::Plugin::Logcheck::RuleEngine.new(logger: @logger)
      rule_loader = Fluent::Plugin::Logcheck::RuleLoader.new(logger: @logger)

      # Load rules and process some messages
      ignore_rule_set = rule_loader.load_file(@ignore_file, :ignore)
      engine.add_rule_set(ignore_rule_set)

      engine.filter(sample_real_log_messages[:systemd_start])
      engine.filter(sample_real_log_messages[:normal_app])

      # Verify we have some statistics
      stats_before = engine.statistics
      assert_operator stats_before[:total_messages], :>, 0

      # Reset statistics
      engine.reset_statistics

      # Verify statistics are reset
      stats_after = engine.statistics
      assert_equal 0, stats_after[:total_messages]
      assert_equal 0, stats_after[:ignored_messages]
      assert_equal 0, stats_after[:alert_messages]
      assert_equal 0, stats_after[:passed_messages]
    end
  end

  sub_test_case 'rule set management' do
    test 'adds rule sets correctly' do
      engine = Fluent::Plugin::Logcheck::RuleEngine.new(logger: @logger)
      rule_loader = Fluent::Plugin::Logcheck::RuleLoader.new(logger: @logger)

      assert_equal 0, engine.rule_set_count
      assert_equal 0, engine.total_rule_count

      # Add first rule set
      ignore_rule_set = rule_loader.load_file(@ignore_file, :ignore)
      engine.add_rule_set(ignore_rule_set)

      assert_equal 1, engine.rule_set_count
      assert_operator engine.total_rule_count, :>, 0

      # Add second rule set
      cracking_rule_set = rule_loader.load_file(@cracking_file, :cracking)
      engine.add_rule_set(cracking_rule_set)

      assert_equal 2, engine.rule_set_count
      assert_operator engine.total_rule_count, :>, ignore_rule_set.size
    end

    test 'adds multiple rule sets at once' do
      engine = Fluent::Plugin::Logcheck::RuleEngine.new(logger: @logger)
      rule_loader = Fluent::Plugin::Logcheck::RuleLoader.new(logger: @logger)

      # Load multiple rule sets
      ignore_rule_set = rule_loader.load_file(@ignore_file, :ignore)
      cracking_rule_set = rule_loader.load_file(@cracking_file, :cracking)
      violations_rule_set = rule_loader.load_file(@violations_file, :violations)

      rule_sets = [ignore_rule_set, cracking_rule_set, violations_rule_set]
      engine.add_rule_sets(rule_sets)

      assert_equal 3, engine.rule_set_count
      expected_total = ignore_rule_set.size + cracking_rule_set.size + violations_rule_set.size
      assert_equal expected_total, engine.total_rule_count
    end

    test 'clears rule sets correctly' do
      engine = Fluent::Plugin::Logcheck::RuleEngine.new(logger: @logger)
      rule_loader = Fluent::Plugin::Logcheck::RuleLoader.new(logger: @logger)

      # Add some rule sets
      ignore_rule_set = rule_loader.load_file(@ignore_file, :ignore)
      cracking_rule_set = rule_loader.load_file(@cracking_file, :cracking)

      engine.add_rule_set(ignore_rule_set)
      engine.add_rule_set(cracking_rule_set)

      assert_equal 2, engine.rule_set_count

      # Clear rule sets
      engine.clear_rule_sets

      assert_equal 0, engine.rule_set_count
      assert_equal 0, engine.total_rule_count
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
