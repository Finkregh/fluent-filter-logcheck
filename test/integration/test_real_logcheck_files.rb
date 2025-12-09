# typed: false
# frozen_string_literal: true

require_relative '../helper'
require 'fluent/plugin/logcheck/rule_loader'
require 'tempfile'
require 'fileutils'

class RealLogcheckFilesTest < Test::Unit::TestCase
  include Fluent::Test::Helpers

  def setup
    @temp_dir = Dir.mktmpdir('logcheck_integration_test')
    @rule_loader = Fluent::Plugin::Logcheck::RuleLoader.new
  end

  def teardown
    FileUtils.rm_rf(@temp_dir) if @temp_dir && Dir.exist?(@temp_dir)
  end

  def test_load_real_systemd_rules
    # Test loading the actual systemd rules from our knowledge base
    systemd_rules = [
      '## services, and other units',
      '#   https://salsa.debian.org/systemd-team/systemd/-/blob/debian/master/src/core/job.c#L647 #L659 #587 #589',
      '#   from: job_start_message_format, job_done_message_format',
      '# not including: Reloaded/Reloading',
      '^([[:alpha:]]{3} [ :[:digit:]]{11}|[0-9T:.+-]{32}) [._[:alnum:]-]+ systemd\[[0-9]+\]: (Start|Stopp)ed .+\.$',
      '^([[:alpha:]]{3} [ :[:digit:]]{11}|[0-9T:.+-]{32}) [._[:alnum:]-]+ systemd\[[0-9]+\]: (Start|Stopp)ing .+\.$',
      '',
      '# eg, units started by timers',
      '#   https://salsa.debian.org/systemd-team/systemd/-/blob/debian/master/src/core/unit.c#6023',
      '#   from: unit_log_success',
      '^([[:alpha:]]{3} [ :[:digit:]]{11}|[0-9T:.+-]{32}) [._[:alnum:]-]+ systemd\[[0-9]+\]: [^ ]+: Deactivated successfully\.$',
      '',
      '# possibly from: unit_notify, https://salsa.debian.org/systemd-team/systemd/-/blob/debian/master/src/core/unit.c/#L2706',
      '^([[:alpha:]]{3} [ :[:digit:]]{11}|[0-9T:.+-]{32}) [._[:alnum:]-]+ systemd\[[0-9]+\]: [^ ]+: Succeeded\.$',
      '',
      '# https://salsa.debian.org/systemd-team/systemd/-/blob/debian/master/src/core/unit.c/#L2350',
      '# from: unit_log_resources, optional memory peak from memory_fields added from strextendf_with_separator at L2377',
      '^([[:alpha:]]{3} [ :[:digit:]]{11}|[0-9T:.+-]{32}) [._[:alnum:]-]+ systemd\[[0-9]+\]: [^ ]+: Consumed .+ CPU time(, .+ memory peak)?\.$',
      '',
      '# services with Type=Oneshot print \'Finished\' on exit',
      '# https://salsa.debian.org/systemd-team/systemd/-/blob/debian/master/src/core/service.c/#L5425',
      '# from: service_finished_job',
      '^([[:alpha:]]{3} [ :[:digit:]]{11}|[0-9T:.+-]{32}) [._[:alnum:]-]+ systemd\[[0-9]+\]: Finished .+\.$',
      '',
      '# services with Restart=always (eg console-getty.service)',
      '# https://salsa.debian.org/systemd-team/systemd/-/blob/debian/master/src/core/service.c#L2680',
      '# from: service_enter_restart',
      '^([[:alpha:]]{3} [ :[:digit:]]{11}|[0-9T:.+-]{32}) [._[:alnum:]-]+ systemd\[[0-9]+\]: [^ ]+\.service: Scheduled restart job, restart counter is at [0-9]+\.$',
      '',
      '## timers',
      '# no longer produced normally?',
      '#^([[:alpha:]]{3} [ :[:digit:]]{11}|[0-9T:.+-]{32}) [._[:alnum:]-]+ systemd\[[0-9]+\]: [^ ]+\.timer: Adding .+ random time\.$',
      '',
      '## slices',
      '# https://salsa.debian.org/systemd-team/systemd/-/blob/debian/master/src/core/slice.c#L428-431',
      '# from: .status_message_formats in slice_vtable',
      '^([[:alpha:]]{3} [ :[:digit:]]{11}|[0-9T:.+-]{32}) [._[:alnum:]-]+ systemd\[[0-9]+\]: (Creat|Remov)ed slice .+\.$',
      '',
      '## targets',
      '# https://salsa.debian.org/systemd-team/systemd/-/blob/debian/master/src/core/target.c/#L201',
      '# # from: .status_message_formats in target_vtable (\'Stopped target xxx\' already matched by first rule)',
      '^([[:alpha:]]{3} [ :[:digit:]]{11}|[0-9T:.+-]{32}) [._[:alnum:]-]+ systemd\[[0-9]+\]: Reached target .+\.$',
      '',
      '# eg on logout from console',
      '# https://salsa.debian.org/systemd-team/systemd/-/blob/debian/master/src/core/manager.c/#L3062',
      '# from: manager_start_special',
      '^([[:alpha:]]{3} [ :[:digit:]]{11}|[0-9T:.+-]{32}) [._[:alnum:]-]+ systemd\[[0-9]+\]: Activating special unit exit\.target\.\.\.$',
      '',
      '## sockets',
      '# https://salsa.debian.org/systemd-team/systemd/-/blob/debian/master/src/core/socket.c/#L3626-3631',
      '# from: .status_message_formats socket_vtable',
      '^([[:alpha:]]{3} [ :[:digit:]]{11}|[0-9T:.+-]{32}) [._[:alnum:]-]+ systemd\[[0-9]+\]: Listening on .+\.$',
      '^([[:alpha:]]{3} [ :[:digit:]]{11}|[0-9T:.+-]{32}) [._[:alnum:]-]+ systemd\[[0-9]+\]: Closed .+\.$',
      '',
      '## The following seem to be produced only when systemd-sysv is installed (which is usually the case)',
      '# https://salsa.debian.org/systemd-team/systemd/-/blob/debian/master/src/core/main.c/#L2605',
      '# from: do_queue_default_job',
      '^([[:alpha:]]{3} [ :[:digit:]]{11}|[0-9T:.+-]{32}) [._[:alnum:]-]+ systemd\[[0-9]+\]: Queued start job for default target .+\.$',
      '',
      '# https://salsa.debian.org/systemd-team/systemd/-/blob/debian/master/src/core/manager.c/#L3919-3949',
      '# from: manager_notify_finished',
      '^([[:alpha:]]{3} [ :[:digit:]]{11}|[0-9T:.+-]{32}) [._[:alnum:]-]+ systemd\[[0-9]+\]: Startup finished in .+\.$'
    ]

    systemd_file = create_temp_file('systemd', systemd_rules)
    rule_set = @rule_loader.load_file(systemd_file, :ignore)

    # Should load 14 valid regex patterns (excluding comments and empty lines)
    assert_equal 14, rule_set.size
    assert_equal :ignore, rule_set.type
    assert_equal systemd_file, rule_set.source_path

    # Test that all patterns are valid regex
    rule_set.rules.each do |rule|
      assert_not_nil rule.pattern
      assert_kind_of Regexp, rule.pattern
    end
  end

  def test_systemd_rules_match_real_log_messages
    # Test that our loaded systemd rules actually match real systemd log messages
    systemd_rules = [
      '^([[:alpha:]]{3} [ :[:digit:]]{11}|[0-9T:.+-]{32}) [._[:alnum:]-]+ systemd\[[0-9]+\]: (Start|Stopp)ed .+\.$',
      '^([[:alpha:]]{3} [ :[:digit:]]{11}|[0-9T:.+-]{32}) [._[:alnum:]-]+ systemd\[[0-9]+\]: (Start|Stopp)ing .+\.$',
      '^([[:alpha:]]{3} [ :[:digit:]]{11}|[0-9T:.+-]{32}) [._[:alnum:]-]+ systemd\[[0-9]+\]: [^ ]+: Deactivated successfully\.$',
      '^([[:alpha:]]{3} [ :[:digit:]]{11}|[0-9T:.+-]{32}) [._[:alnum:]-]+ systemd\[[0-9]+\]: Finished .+\.$'
    ]

    systemd_file = create_temp_file('systemd_test', systemd_rules)
    rule_set = @rule_loader.load_file(systemd_file, :ignore)

    # Test real systemd log messages
    test_messages = [
      'Dec  8 20:15:32 hostname systemd[1]: Started User Manager for UID 1000.',
      '2023-12-08T20:15:32.123456+00:00 hostname systemd[1]: Stopping NetworkManager.service.',
      'Dec  8 20:15:32 hostname systemd[1]: user@1000.service: Deactivated successfully.',
      'Dec  8 20:15:32 hostname systemd[1]: Finished Update UTMP about System Runlevel Changes.'
    ]

    test_messages.each do |message|
      matching_rule = rule_set.match(message)
      assert_not_nil matching_rule, "No rule matched message: #{message}"
    end

    # Test messages that should NOT match
    non_matching_messages = [
      'Dec  8 20:15:32 hostname kernel: USB disconnect, address 1',
      'Dec  8 20:15:32 hostname sshd[1234]: Accepted password for user from 192.168.1.1'
    ]

    non_matching_messages.each do |message|
      matching_rule = rule_set.match(message)
      assert_nil matching_rule, "Rule incorrectly matched message: #{message}"
    end
  end

  def test_load_directory_with_mixed_rule_types
    # Test loading a directory structure similar to real logcheck setup
    create_logcheck_directory_structure

    rule_sets = @rule_loader.load_directory(@temp_dir, nil, recursive: true)

    # Should find rule sets for different types
    ignore_sets = rule_sets.select { |rs| rs.type == :ignore }
    cracking_sets = rule_sets.select { |rs| rs.type == :cracking }
    violations_sets = rule_sets.select { |rs| rs.type == :violations }

    assert_equal 2, ignore_sets.size, 'Should find 2 ignore rule sets'
    assert_equal 1, cracking_sets.size, 'Should find 1 cracking rule set'
    assert_equal 1, violations_sets.size, 'Should find 1 violations rule set'

    # Verify total rule count
    total_rules = rule_sets.sum(&:size)
    assert_operator total_rules, :>, 0, 'Should load some rules'
  end

  def test_rule_type_detection_from_paths
    # Test that rule types are correctly detected from file paths
    test_cases = [
      { path: 'ignore.d.server/systemd', expected_type: :ignore },
      { path: 'ignore.d.workstation/kde', expected_type: :ignore },
      { path: 'cracking.d/ssh', expected_type: :cracking },
      { path: 'cracking.d/web-attacks', expected_type: :cracking },
      { path: 'violations.d/kernel', expected_type: :violations },
      { path: 'violations.d.ignore/sudo', expected_type: :violations }
    ]

    test_cases.each do |test_case|
      dir_path = File.join(@temp_dir, File.dirname(test_case[:path]))
      FileUtils.mkdir_p(dir_path)

      file_path = File.join(@temp_dir, test_case[:path])
      File.write(file_path, "test_pattern_#{test_case[:expected_type]}")

      rule_set = @rule_loader.load_file(file_path, nil) # Auto-detect type
      assert_equal test_case[:expected_type], rule_set.type,
                   "Wrong type detected for path: #{test_case[:path]}"
    end
  end

  def test_performance_with_large_rule_files
    # Test performance with larger rule files (similar to real logcheck databases)
    large_rules = []

    # Generate realistic systemd-style rules
    100.times do |i|
      large_rules << "^([[:alpha:]]{3} [ :[:digit:]]{11}|[0-9T:.+-]{32}) [._[:alnum:]-]+ systemd\\[[0-9]+\\]: Test pattern #{i} .+\\.$"
    end

    large_file = create_temp_file('large_systemd', large_rules)

    start_time = Time.now
    rule_set = @rule_loader.load_file(large_file, :ignore)
    load_time = Time.now - start_time

    assert_equal 100, rule_set.size
    assert_operator load_time, :<, 1.0, 'Loading should complete within 1 second'

    # Test pattern matching performance
    test_message = 'Dec  8 20:15:32 hostname systemd[1]: Test pattern 50 some service started.'

    start_time = Time.now
    matching_rule = rule_set.match(test_message)
    match_time = Time.now - start_time

    assert_not_nil matching_rule
    assert_operator match_time, :<, 0.1, 'Pattern matching should complete within 0.1 seconds'
  end

  private

  def create_temp_file(name, lines)
    file_path = File.join(@temp_dir, name)
    File.write(file_path, lines.join("\n"))
    file_path
  end

  def create_logcheck_directory_structure
    # Create a realistic logcheck directory structure
    ignore_dir = File.join(@temp_dir, 'ignore.d.server')
    cracking_dir = File.join(@temp_dir, 'cracking.d')
    violations_dir = File.join(@temp_dir, 'violations.d')

    FileUtils.mkdir_p(ignore_dir)
    FileUtils.mkdir_p(cracking_dir)
    FileUtils.mkdir_p(violations_dir)

    # Create ignore rules
    File.write(File.join(ignore_dir, 'systemd'), [
      '^.* systemd\\[[0-9]+\\]: Started .*\\.$',
      '^.* systemd\\[[0-9]+\\]: Stopped .*\\.$'
    ].join("\n"))

    File.write(File.join(ignore_dir, 'kernel'), [
      '^.* kernel: .*$'
    ].join("\n"))

    # Create cracking rules
    File.write(File.join(cracking_dir, 'ssh'), [
      '^.* sshd\\[[0-9]+\\]: Failed password .*$',
      '^.* sshd\\[[0-9]+\\]: Invalid user .*$'
    ].join("\n"))

    # Create violations rules
    File.write(File.join(violations_dir, 'sudo'), [
      '^.* sudo: .* : command not allowed .*$'
    ].join("\n"))
  end
end
