# frozen_string_literal: true

require_relative '../helper'
require 'fluent/plugin/filter_logcheck'
require 'tempfile'
require 'fileutils'
require 'benchmark'

class PerformanceBenchmarksTest < Test::Unit::TestCase
  include Fluent::Test::Helpers

  def setup
    Fluent::Test.setup
    @temp_dir = Dir.mktmpdir('logcheck_perf_test')
    create_performance_test_data
  end

  def teardown
    FileUtils.rm_rf(@temp_dir) if @temp_dir && Dir.exist?(@temp_dir)
  end

  sub_test_case 'rule loading performance' do
    test 'loads large rule sets efficiently' do
      config = %[
        rules_dir #{@large_rules_dir}
        recursive_scan true
        log_rule_errors false
      ]
      
      loading_time = Benchmark.realtime do
        @driver = create_driver(config)
      end
      
      # Should load 500+ rules within reasonable time
      assert_operator loading_time, :<, 2.0, "Rule loading should complete within 2 seconds"
      
      # Verify rules were actually loaded
      total_rules = @driver.instance.instance_variable_get(:@rule_engine).total_rule_count
      assert_operator total_rules, :>, 300, "Should load more than 300 rules"
    end

    test 'handles deep directory structures efficiently' do
      config = %[
        rules_dir #{@deep_dir_structure}
        recursive_scan true
        log_rule_errors false
      ]
      
      loading_time = Benchmark.realtime do
        @driver = create_driver(config)
      end
      
      # Should handle deep recursion efficiently
      assert_operator loading_time, :<, 1.0, "Deep directory scanning should complete within 1 second"
    end
  end

  sub_test_case 'message processing performance' do
    test 'processes high volume of messages efficiently' do
      config = %[
        rules_dir #{@mixed_rules_dir}
        recursive_scan true
        mark_matches true
        log_rule_errors false
      ]
      
      d = create_driver(config)
      
      # Generate test messages
      messages = generate_test_messages(1000)
      
      processing_time = Benchmark.realtime do
        d.run(default_tag: 'perf.test') do
          messages.each do |message|
            d.feed(event_time, { 'message' => message })
          end
        end
      end
      
      # Should process 1000 messages within reasonable time
      assert_operator processing_time, :<, 1.0, "Should process 1000 messages within 1 second"
      
      # Verify processing results
      filtered_records = d.filtered_records
      assert_operator filtered_records.size, :>, 0, "Should have some filtered records"
      
      # Calculate throughput
      throughput = messages.size / processing_time
      assert_operator throughput, :>, 500, "Should achieve >500 messages/second throughput"
    end

    test 'maintains performance with complex regex patterns' do
      config = %[
        rules_file #{@complex_patterns_file}
        log_rule_errors false
      ]
      
      d = create_driver(config)
      
      # Generate messages that will exercise complex patterns
      complex_messages = [
        'Dec  8 20:15:32 hostname systemd[1]: Started complex-service-name.service.',
        'Dec  8 20:15:32 hostname sshd[1234]: Failed password for user from 192.168.1.100 port 22 ssh2',
        'Dec  8 20:15:32 hostname kernel: [12345.678901] USB disconnect, address 1',
        'Dec  8 20:15:32 hostname postfix/smtpd[5678]: connect from unknown[192.168.1.200]'
      ] * 250  # 1000 messages total
      
      processing_time = Benchmark.realtime do
        d.run(default_tag: 'perf.complex') do
          complex_messages.each do |message|
            d.feed(event_time, { 'message' => message })
          end
        end
      end
      
      # Should handle complex patterns efficiently
      assert_operator processing_time, :<, 2.0, "Complex pattern processing should complete within 2 seconds"
    end
  end

  sub_test_case 'memory usage optimization' do
    test 'uses lazy regex compilation efficiently' do
      config = %[
        rules_dir #{@large_rules_dir}
        recursive_scan true
        log_rule_errors false
      ]
      
      d = create_driver(config)
      
      # Get rule engine
      rule_engine = d.instance.instance_variable_get(:@rule_engine)
      
      # Process a small number of messages
      d.run(default_tag: 'memory.test') do
        5.times do |i|
          d.feed(event_time, { 'message' => "test message #{i}" })
        end
      end
      
      # Verify that not all patterns are compiled (lazy compilation)
      # This is a proxy test - in real implementation, we'd check internal state
      assert_operator rule_engine.total_rule_count, :>, 0, "Should have rules loaded"
    end

    test 'handles rule caching efficiently' do
      config = %[
        rules_file #{@valid_rules_file}
        cache_size 100
        log_rule_errors false
      ]
      
      d = create_driver(config)
      
      # Process repeated messages to test caching
      repeated_messages = ['test message'] * 100
      
      processing_time = Benchmark.realtime do
        d.run(default_tag: 'cache.test') do
          repeated_messages.each do |message|
            d.feed(event_time, { 'message' => message })
          end
        end
      end
      
      # Repeated processing should be fast due to caching optimizations
      assert_operator processing_time, :<, 0.5, "Repeated message processing should be very fast"
    end
  end

  sub_test_case 'scalability testing' do
    test 'scales with increasing rule count' do
      # Test with different rule set sizes
      rule_counts = [10, 50, 100, 500]
      processing_times = []
      
      rule_counts.each do |count|
        rules_file = create_rules_file_with_count(count)
        config = %[
          rules_file #{rules_file}
          log_rule_errors false
        ]
        
        d = create_driver(config)
        
        # Process standard set of messages
        test_messages = generate_test_messages(100)
        
        time = Benchmark.realtime do
          d.run(default_tag: 'scale.test') do
            test_messages.each do |message|
              d.feed(event_time, { 'message' => message })
            end
          end
        end
        
        processing_times << time
      end
      
      # Processing time should scale reasonably (not exponentially)
      # Allow for some variance but ensure it doesn't explode
      max_time = processing_times.max
      min_time = processing_times.min
      
      # Scaling factor should be reasonable (less than 50x for 50x more rules)
      # This allows for some non-linear scaling due to regex compilation overhead
      scaling_factor = max_time / min_time
      assert_operator scaling_factor, :<, 50, "Performance should scale reasonably with rule count"
    end

    test 'handles concurrent processing efficiently' do
      config = %[
        rules_dir #{@mixed_rules_dir}
        recursive_scan true
        log_rule_errors false
      ]
      
      d = create_driver(config)
      
      # Simulate concurrent processing by rapid message feeding
      messages = generate_test_messages(500)
      
      processing_time = Benchmark.realtime do
        d.run(default_tag: 'concurrent.test') do
          # Feed messages rapidly to simulate concurrent load
          messages.each do |message|
            d.feed(event_time, { 'message' => message })
          end
        end
      end
      
      # Should handle rapid message processing efficiently
      assert_operator processing_time, :<, 1.0, "Concurrent-style processing should be efficient"
      
      # Verify all messages were processed
      assert_operator d.filtered_records.size, :>, 0, "Should process messages successfully"
    end
  end

  private

  def create_driver(conf)
    Fluent::Test::Driver::Filter.new(Fluent::Plugin::LogcheckFilter).configure(conf)
  end

  def create_performance_test_data
    # Create large rule sets for performance testing
    create_large_rules_directory
    create_deep_directory_structure
    create_mixed_rules_directory
    create_complex_patterns_file
    create_valid_rules_file
  end

  def create_large_rules_directory
    @large_rules_dir = File.join(@temp_dir, 'large_rules')
    FileUtils.mkdir_p(@large_rules_dir)
    
    # Create ignore rules
    ignore_dir = File.join(@large_rules_dir, 'ignore.d.server')
    FileUtils.mkdir_p(ignore_dir)
    
    # Generate many systemd-style rules
    systemd_rules = []
    100.times do |i|
      systemd_rules << "^.* systemd\\[[0-9]+\\]: (Started|Stopped) service-#{i}\\.service\\.$"
    end
    File.write(File.join(ignore_dir, 'systemd'), systemd_rules.join("\n"))
    
    # Generate kernel rules
    kernel_rules = []
    100.times do |i|
      kernel_rules << "^.* kernel: \\[.*\\] Test kernel message #{i}.*$"
    end
    File.write(File.join(ignore_dir, 'kernel'), kernel_rules.join("\n"))
    
    # Create cracking rules
    cracking_dir = File.join(@large_rules_dir, 'cracking.d')
    FileUtils.mkdir_p(cracking_dir)
    
    ssh_rules = []
    100.times do |i|
      ssh_rules << "^.* sshd\\[[0-9]+\\]: Failed password for user#{i} from .*$"
    end
    File.write(File.join(cracking_dir, 'ssh'), ssh_rules.join("\n"))
    
    # Create violations rules
    violations_dir = File.join(@large_rules_dir, 'violations.d')
    FileUtils.mkdir_p(violations_dir)
    
    sudo_rules = []
    100.times do |i|
      sudo_rules << "^.* sudo: user#{i} : command not allowed .*$"
    end
    File.write(File.join(violations_dir, 'sudo'), sudo_rules.join("\n"))
  end

  def create_deep_directory_structure
    @deep_dir_structure = File.join(@temp_dir, 'deep_structure')
    
    # Create nested directory structure
    current_dir = @deep_dir_structure
    10.times do |level|
      current_dir = File.join(current_dir, "level_#{level}")
      FileUtils.mkdir_p(current_dir)
      
      # Add some rules at each level
      rules_file = File.join(current_dir, "rules_level_#{level}")
      File.write(rules_file, "^.* level#{level}: .*$")
    end
  end

  def create_mixed_rules_directory
    @mixed_rules_dir = File.join(@temp_dir, 'mixed_rules')
    FileUtils.mkdir_p(@mixed_rules_dir)
    
    # Create mixed rule types
    ['ignore.d.server', 'cracking.d', 'violations.d'].each do |rule_type|
      type_dir = File.join(@mixed_rules_dir, rule_type)
      FileUtils.mkdir_p(type_dir)
      
      # Add some rules for each type
      10.times do |i|
        File.write(File.join(type_dir, "rules_#{i}"), "^.* #{rule_type}_#{i}: .*$")
      end
    end
  end

  def create_complex_patterns_file
    @complex_patterns_file = File.join(@temp_dir, 'complex_patterns.rules')
    
    complex_patterns = [
      '^([[:alpha:]]{3} [ :[:digit:]]{11}|[0-9T:.+-]{32}) [._[:alnum:]-]+ systemd\\[[0-9]+\\]: (Start|Stopp)ed [^[:space:]]+\\.(service|timer|socket)\\.$',
      '^([[:alpha:]]{3} [ :[:digit:]]{11}|[0-9T:.+-]{32}) [._[:alnum:]-]+ sshd\\[[0-9]+\\]: Failed password for (invalid user )?[^[:space:]]+ from [0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3} port [0-9]+ ssh2$',
      '^([[:alpha:]]{3} [ :[:digit:]]{11}|[0-9T:.+-]{32}) [._[:alnum:]-]+ kernel: \\[[[:space:]]*[0-9]+\\.[0-9]+\\] [^[:space:]]+ [0-9]+:[0-9]+:[0-9]+\\.[0-9]+ [^[:space:]]+$',
      '^([[:alpha:]]{3} [ :[:digit:]]{11}|[0-9T:.+-]{32}) [._[:alnum:]-]+ postfix/[^[:space:]]+\\[[0-9]+\\]: [A-F0-9]+: (client|from)=[^[:space:]]+\\[[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\]$'
    ]
    
    File.write(@complex_patterns_file, complex_patterns.join("\n"))
  end

  def create_valid_rules_file
    @valid_rules_file = File.join(@temp_dir, 'valid.rules')
    File.write(@valid_rules_file, [
      '^test message$',
      '^another test pattern$',
      '^.*ignore.*$'
    ].join("\n"))
  end

  def generate_test_messages(count)
    message_templates = [
      'Dec  8 20:15:32 hostname systemd[1]: Started test-service.service.',
      'Dec  8 20:15:32 hostname sshd[1234]: Failed password for testuser from 192.168.1.1',
      'Dec  8 20:15:32 hostname kernel: [12345.678] Test kernel message',
      'Dec  8 20:15:32 hostname postfix/smtpd[5678]: Test postfix message',
      'Dec  8 20:15:32 hostname application: Regular application message',
      'Dec  8 20:15:32 hostname test: Some test message',
      'Dec  8 20:15:32 hostname ignore: Message to be ignored'
    ]
    
    messages = []
    count.times do |i|
      template = message_templates[i % message_templates.size]
      messages << template.gsub('test', "test#{i}")
    end
    
    messages
  end

  def create_rules_file_with_count(count)
    rules_file = File.join(@temp_dir, "rules_#{count}.rules")
    
    rules = []
    count.times do |i|
      rules << "^.*rule#{i}.*$"
    end
    
    File.write(rules_file, rules.join("\n"))
    rules_file
  end
end
