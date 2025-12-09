# typed: false
# frozen_string_literal: true

require_relative '../helper'
require 'fluent/plugin/filter_logcheck'
require 'tempfile'
require 'fileutils'

class EndToEndFilteringTest < Test::Unit::TestCase
  include Fluent::Test::Helpers

  def setup
    Fluent::Test.setup
    @temp_dir = Dir.mktmpdir('logcheck_e2e_test')
    create_test_rule_files
  end

  def teardown
    FileUtils.rm_rf(@temp_dir) if @temp_dir && Dir.exist?(@temp_dir)
  end

  def test_complete_filtering_workflow
    # Create driver with real logcheck rules
    config = %(
      rules_dir #{@temp_dir}
      recursive_scan true
      mark_matches true
      mark_field_prefix logcheck_
      log_rule_errors true
    )

    d = create_driver(config)

    # Test messages that should trigger different behaviors
    test_cases = [
      {
        message: 'Dec  8 20:15:32 hostname systemd[1]: Started some service.',
        expected_action: :ignore,
        description: 'systemd start message should be ignored'
      },
      {
        message: 'Dec  8 20:15:32 hostname sshd[1234]: Failed password for user from 192.168.1.1',
        expected_action: :alert,
        description: 'SSH failed password should trigger alert'
      },
      {
        message: 'Dec  8 20:15:32 hostname sudo: user : command not allowed ; TTY=pts/0',
        expected_action: :alert,
        description: 'sudo violation should trigger alert'
      },
      {
        message: 'Dec  8 20:15:32 hostname myapp: Some application message',
        expected_action: :pass,
        description: 'unmatched message should pass through'
      }
    ]

    d.run(default_tag: 'test.logcheck') do
      test_cases.each do |test_case|
        d.feed(event_time, { 'message' => test_case[:message] })
      end
    end

    # Analyze results
    filtered_records = d.filtered_records

    # Should have 3 records (ignore case drops the record)
    assert_equal 3, filtered_records.size, 'Expected 3 records after filtering'

    # Check SSH alert record
    ssh_record = filtered_records.find { |r| r['message'].include?('Failed password') }
    assert_not_nil ssh_record, 'SSH alert record should be present'
    assert_true ssh_record['logcheck_alert'], 'SSH record should be marked as alert'
    assert_equal 'cracking', ssh_record['logcheck_rule_type'], 'SSH should be cracking type'
    assert_not_nil ssh_record['logcheck_pattern'], 'SSH record should have pattern'

    # Check sudo alert record
    sudo_record = filtered_records.find { |r| r['message'].include?('command not allowed') }
    assert_not_nil sudo_record, 'Sudo alert record should be present'
    assert_true sudo_record['logcheck_alert'], 'Sudo record should be marked as alert'
    assert_equal 'violations', sudo_record['logcheck_rule_type'], 'Sudo should be violations type'

    # Check pass-through record
    app_record = filtered_records.find { |r| r['message'].include?('myapp') }
    assert_not_nil app_record, 'Application record should be present'
    assert_nil app_record['logcheck_alert'], 'Application record should not be marked as alert'

    # Verify systemd message was dropped (ignored)
    systemd_record = filtered_records.find { |r| r['message'].include?('systemd') }
    assert_nil systemd_record, 'Systemd record should be dropped (ignored)'
  end

  def test_rule_precedence_in_action
    # Test that cracking rules take precedence over ignore rules
    config = %(
      rules_dir #{@temp_dir}
      recursive_scan true
      mark_matches true
    )

    d = create_driver(config)

    # This message could match both ignore and cracking rules
    # but cracking should take precedence
    message = 'Dec  8 20:15:32 hostname sshd[1234]: Failed password for root from 192.168.1.1'

    d.run(default_tag: 'test.precedence') do
      d.feed(event_time, { 'message' => message })
    end

    filtered_records = d.filtered_records
    assert_equal 1, filtered_records.size, 'Should have one record'

    record = filtered_records.first
    assert_true record['logcheck_alert'], 'Should be marked as alert (not ignored)'
    assert_equal 'cracking', record['logcheck_rule_type'], 'Should be cracking type'
  end

  def test_performance_with_many_rules
    # Create a larger rule set for performance testing
    create_large_rule_set

    config = %(
      rules_dir #{@temp_dir}
      recursive_scan true
      mark_matches false
      log_rule_errors false
    )

    d = create_driver(config)

    # Test with many messages
    messages = []
    100.times do |i|
      messages << "Dec  8 20:15:32 hostname app#{i}: Test message #{i}"
    end

    start_time = Time.now
    d.run(default_tag: 'test.performance') do
      messages.each do |message|
        d.feed(event_time, { 'message' => message })
      end
    end
    end_time = Time.now

    processing_time = end_time - start_time

    # Should process 100 messages in reasonable time
    assert_operator processing_time, :<, 1.0, 'Should process 100 messages within 1 second'

    # All messages should pass through (no matching rules)
    assert_equal 100, d.filtered_records.size, 'All messages should pass through'
  end

  private

  def create_driver(conf)
    Fluent::Test::Driver::Filter.new(Fluent::Plugin::LogcheckFilter).configure(conf)
  end

  def create_test_rule_files
    # Create ignore rules (systemd)
    ignore_dir = File.join(@temp_dir, 'ignore.d.server')
    FileUtils.mkdir_p(ignore_dir)
    File.write(File.join(ignore_dir, 'systemd'), [
      '^([[:alpha:]]{3} [ :[:digit:]]{11}|[0-9T:.+-]{32}) [._[:alnum:]-]+ systemd\\[[0-9]+\\]: (Start|Stopp)ed .*\\.$',
      '^([[:alpha:]]{3} [ :[:digit:]]{11}|[0-9T:.+-]{32}) [._[:alnum:]-]+ systemd\\[[0-9]+\\]: (Start|Stopp)ing .*\\.$'
    ].join("\n"))

    # Create cracking rules (SSH attacks)
    cracking_dir = File.join(@temp_dir, 'cracking.d')
    FileUtils.mkdir_p(cracking_dir)
    File.write(File.join(cracking_dir, 'ssh'), [
      '^([[:alpha:]]{3} [ :[:digit:]]{11}|[0-9T:.+-]{32}) [._[:alnum:]-]+ sshd\\[[0-9]+\\]: Failed password .*$',
      '^([[:alpha:]]{3} [ :[:digit:]]{11}|[0-9T:.+-]{32}) [._[:alnum:]-]+ sshd\\[[0-9]+\\]: Invalid user .*$'
    ].join("\n"))

    # Create violations rules (sudo)
    violations_dir = File.join(@temp_dir, 'violations.d')
    FileUtils.mkdir_p(violations_dir)
    File.write(File.join(violations_dir, 'sudo'), [
      '^([[:alpha:]]{3} [ :[:digit:]]{11}|[0-9T:.+-]{32}) [._[:alnum:]-]+ sudo: .* : command not allowed .*$'
    ].join("\n"))
  end

  def create_large_rule_set
    # Create a large ignore rule set for performance testing
    large_ignore_dir = File.join(@temp_dir, 'ignore.d.performance')
    FileUtils.mkdir_p(large_ignore_dir)

    large_rules = []
    100.times do |i|
      large_rules << "^.* performance_test_#{i}: .*$"
    end

    File.write(File.join(large_ignore_dir, 'performance'), large_rules.join("\n"))
  end
end
