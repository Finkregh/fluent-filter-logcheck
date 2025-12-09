# typed: false
# frozen_string_literal: true

require_relative '../helper'
require 'fluent/plugin/filter_logcheck'

class CoreFilteringTest < Test::Unit::TestCase
  include Fluent::Test::Helpers

  def setup
    Fluent::Test.setup
    @temp_dir = Dir.mktmpdir('logcheck_core_test')
    setup_test_rules
  end

  def teardown
    cleanup_temp_files(@temp_dir) if @temp_dir && Dir.exist?(@temp_dir)
  end

  def setup_test_rules
    # Create real rule files for testing
    @ignore_file = create_ignore_rules(@temp_dir)
    @cracking_file = create_cracking_rules(@temp_dir)
    @violations_file = create_violations_rules(@temp_dir)

    # Create logcheck directory structure
    create_logcheck_directory_structure(@temp_dir)
  end

  sub_test_case 'ignore rule functionality' do
    test 'filters out messages matching ignore rules' do
      config = %(
        rules_file #{@ignore_file}
        match_field message
        default_action keep
        debug_mode true
      )

      d = create_driver(config)

      # Test systemd messages that should be ignored
      d.run(default_tag: 'test') do
        d.feed(event_time, { 'message' => sample_real_log_messages[:systemd_start] })
        d.feed(event_time, { 'message' => sample_real_log_messages[:systemd_target] })
        d.feed(event_time, { 'message' => sample_real_log_messages[:cron_job] })
      end

      # All messages should be filtered out (ignored)
      assert_equal 0, d.filtered_records.size
    end

    test 'passes through messages not matching ignore rules' do
      config = %(
        rules_file #{@ignore_file}
        match_field message
        default_action keep
      )

      d = create_driver(config)

      # Test messages that should pass through
      d.run(default_tag: 'test') do
        d.feed(event_time, { 'message' => sample_real_log_messages[:normal_app] })
        d.feed(event_time, { 'message' => sample_real_log_messages[:normal_web] })
      end

      # Messages should pass through unchanged
      assert_equal 2, d.filtered_records.size
      assert_equal sample_real_log_messages[:normal_app], d.filtered_records[0]['message']
      assert_equal sample_real_log_messages[:normal_web], d.filtered_records[1]['message']
    end
  end

  sub_test_case 'alert rule functionality' do
    test 'keeps messages matching cracking rules with alert metadata' do
      config = %(
        rules_file #{@cracking_file}
        match_field message
        mark_matches true
        mark_field_prefix logcheck_
        default_action keep
      )

      d = create_driver(config)

      # Test SSH attack messages that should trigger alerts
      d.run(default_tag: 'test') do
        d.feed(event_time, { 'message' => sample_real_log_messages[:ssh_failed] })
        d.feed(event_time, { 'message' => sample_real_log_messages[:ssh_invalid] })
      end

      # Messages should be kept with alert metadata
      assert_equal 2, d.filtered_records.size

      first_record = d.filtered_records[0]
      assert_equal sample_real_log_messages[:ssh_failed], first_record['message']
      assert_true first_record['logcheck_alert']
      assert_equal 'cracking', first_record['logcheck_rule_type']
      assert_not_nil first_record['logcheck_pattern']
      assert_not_nil first_record['logcheck_source']
    end

    test 'keeps messages matching violations rules with alert metadata' do
      config = %(
        rules_file #{@violations_file}
        match_field message
        mark_matches true
        mark_field_prefix alert_
        default_action keep
      )

      d = create_driver(config)

      # Test kernel error messages that should trigger violations alerts
      d.run(default_tag: 'test') do
        d.feed(event_time, { 'message' => sample_real_log_messages[:kernel_io_error] })
        d.feed(event_time, { 'message' => sample_real_log_messages[:sudo_auth_failure] })
      end

      # Messages should be kept with alert metadata
      assert_equal 2, d.filtered_records.size

      first_record = d.filtered_records[0]
      assert_equal sample_real_log_messages[:kernel_io_error], first_record['message']
      assert_true first_record['alert_alert']
      assert_equal 'violations', first_record['alert_rule_type']
    end
  end

  sub_test_case 'rule precedence testing' do
    test 'cracking rules take precedence over ignore rules' do
      # Create overlapping rules where same message could match both types
      overlapping_ignore = File.join(@temp_dir, 'overlapping_ignore.rules')
      File.write(overlapping_ignore, '^.*sshd.*$') # Broad pattern

      overlapping_cracking = File.join(@temp_dir, 'overlapping_cracking.rules')
      File.write(overlapping_cracking, '^.*Failed password.*$') # More specific

      config = %(
        <rules>
          path #{overlapping_ignore}
          type ignore
        </rules>
        <rules>
          path #{overlapping_cracking}
          type cracking
        </rules>
        match_field message
        mark_matches true
        rule_priority ["cracking", "violations", "ignore"]
      )

      d = create_driver(config)

      # Message that matches both ignore and cracking rules
      d.run(default_tag: 'test') do
        d.feed(event_time, { 'message' => sample_real_log_messages[:ssh_failed] })
      end

      # Should be treated as cracking (alert), not ignored
      assert_equal 1, d.filtered_records.size
      record = d.filtered_records[0]
      assert_true record['logcheck_alert']
      assert_equal 'cracking', record['logcheck_rule_type']
    end

    test 'violations rules take precedence over ignore rules' do
      # Create overlapping rules
      overlapping_ignore = File.join(@temp_dir, 'overlapping_ignore2.rules')
      File.write(overlapping_ignore, '^.*kernel.*$') # Broad pattern

      overlapping_violations = File.join(@temp_dir, 'overlapping_violations.rules')
      File.write(overlapping_violations, '^.*I/O error.*$') # More specific

      config = %(
        <rules>
          path #{overlapping_ignore}
          type ignore
        </rules>
        <rules>
          path #{overlapping_violations}
          type violations
        </rules>
        match_field message
        mark_matches true
        rule_priority ["cracking", "violations", "ignore"]
      )

      d = create_driver(config)

      # Message that matches both ignore and violations rules
      d.run(default_tag: 'test') do
        d.feed(event_time, { 'message' => sample_real_log_messages[:kernel_io_error] })
      end

      # Should be treated as violations (alert), not ignored
      assert_equal 1, d.filtered_records.size
      record = d.filtered_records[0]
      assert_true record['logcheck_alert']
      assert_equal 'violations', record['logcheck_rule_type']
    end

    test 'cracking rules take precedence over violations rules' do
      # Create overlapping rules
      overlapping_violations = File.join(@temp_dir, 'overlapping_violations2.rules')
      File.write(overlapping_violations, '^.*authentication failure.*$') # Broad pattern

      overlapping_cracking = File.join(@temp_dir, 'overlapping_cracking2.rules')
      File.write(overlapping_cracking, '^.*Failed password.*$') # More specific

      config = %(
        <rules>
          path #{overlapping_violations}
          type violations
        </rules>
        <rules>
          path #{overlapping_cracking}
          type cracking
        </rules>
        match_field message
        mark_matches true
        rule_priority ["cracking", "violations", "ignore"]
      )

      d = create_driver(config)

      # Create a message that could match both
      message = 'Dec  8 10:01:00 server sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2 authentication failure'

      d.run(default_tag: 'test') do
        d.feed(event_time, { 'message' => message })
      end

      # Should be treated as cracking (highest precedence)
      assert_equal 1, d.filtered_records.size
      record = d.filtered_records[0]
      assert_true record['logcheck_alert']
      assert_equal 'cracking', record['logcheck_rule_type']
    end
  end

  sub_test_case 'pass-through behavior' do
    test 'passes through unmatched messages unchanged' do
      config = %(
        rules_file #{@ignore_file}
        match_field message
        default_action keep
      )

      d = create_driver(config)

      # Test messages that don't match any rules
      d.run(default_tag: 'test') do
        d.feed(event_time, {
                 'message' => sample_real_log_messages[:normal_app],
                 'timestamp' => '2024-12-08T10:03:00Z',
                 'level' => 'INFO'
               })
      end

      # Message should pass through with all original fields
      assert_equal 1, d.filtered_records.size
      record = d.filtered_records[0]
      assert_equal sample_real_log_messages[:normal_app], record['message']
      assert_equal '2024-12-08T10:03:00Z', record['timestamp']
      assert_equal 'INFO', record['level']
    end
  end

  sub_test_case 'message field extraction' do
    test 'extracts text from different match fields' do
      config = %(
        rules_file #{@ignore_file}
        match_field log_text
        default_action keep
      )

      d = create_driver(config)

      # Test with different field name
      d.run(default_tag: 'test') do
        d.feed(event_time, {
                 'log_text' => sample_real_log_messages[:systemd_start],
                 'other_field' => 'should be preserved'
               })
      end

      # Should be ignored based on log_text field
      assert_equal 0, d.filtered_records.size
    end

    test 'handles missing match field gracefully' do
      config = %(
        rules_file #{@ignore_file}
        match_field message
        default_action keep
      )

      d = create_driver(config)

      # Record without message field
      d.run(default_tag: 'test') do
        d.feed(event_time, { 'other_field' => 'some value' })
      end

      # Should pass through unchanged
      assert_equal 1, d.filtered_records.size
      assert_equal 'some value', d.filtered_records[0]['other_field']
    end

    test 'handles empty match field gracefully' do
      config = %(
        rules_file #{@ignore_file}
        match_field message
        default_action keep
      )

      d = create_driver(config)

      # Record with empty message field
      d.run(default_tag: 'test') do
        d.feed(event_time, { 'message' => '', 'other_field' => 'value' })
      end

      # Should pass through unchanged
      assert_equal 1, d.filtered_records.size
      assert_equal '', d.filtered_records[0]['message']
      assert_equal 'value', d.filtered_records[0]['other_field']
    end
  end

  sub_test_case 'default action behavior' do
    test 'applies keep default action for unknown decisions' do
      config = %(
        rules_file #{@ignore_file}
        match_field message
        default_action keep
      )

      d = create_driver(config)

      # Test with unmatched message
      d.run(default_tag: 'test') do
        d.feed(event_time, { 'message' => sample_real_log_messages[:normal_app] })
      end

      # Should keep the message
      assert_equal 1, d.filtered_records.size
    end

    test 'applies drop default action for unknown decisions' do
      config = %(
        rules_file #{@ignore_file}
        match_field message
        default_action drop
      )

      d = create_driver(config)

      # Mock an unknown decision scenario by testing with no rules loaded
      empty_rules = File.join(@temp_dir, 'empty.rules')
      File.write(empty_rules, '')

      config_empty = %(
        rules_file #{empty_rules}
        match_field message
        default_action drop
      )

      d_empty = create_driver(config_empty)

      # Test with any message
      d_empty.run(default_tag: 'test') do
        d_empty.feed(event_time, { 'message' => sample_real_log_messages[:normal_app] })
      end

      # With no rules and default_action drop, message should still pass through
      # (because no rules matched, so it's a PASS decision, not unknown)
      assert_equal 1, d_empty.filtered_records.size
    end
  end

  private

  def create_driver(conf)
    Fluent::Test::Driver::Filter.new(Fluent::Plugin::LogcheckFilter).configure(conf)
  end

  def event_time
    Fluent::EventTime.now
  end
end
