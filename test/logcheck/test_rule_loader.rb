# frozen_string_literal: true

require_relative '../helper'
require 'fluent/plugin/logcheck/rule_loader'
require 'tempfile'
require 'fileutils'

class RuleLoaderTest < Test::Unit::TestCase
  include Fluent::Test::Helpers

  def setup
    @temp_dir = Dir.mktmpdir('logcheck_test')
    @rule_loader = Fluent::Plugin::Logcheck::RuleLoader.new
  end

  def teardown
    FileUtils.rm_rf(@temp_dir) if @temp_dir && Dir.exist?(@temp_dir)
  end

  def test_load_single_file_with_ignore_rules
    # Test loading a single file with ignore rules
    rule_file = create_temp_file('ignore_rules', [
                                   '# This is a comment',
                                   '',
                                   '^([[:alpha:]]{3} [ :[:digit:]]{11}|[0-9T:.+-]{32}) [._[:alnum:]-]+ systemd\[[0-9]+\]: Started .+\.$',
                                   '^([[:alpha:]]{3} [ :[:digit:]]{11}|[0-9T:.+-]{32}) [._[:alnum:]-]+ systemd\[[0-9]+\]: Stopped .+\.$'
                                 ])

    rule_set = @rule_loader.load_file(rule_file, :ignore)
    
    assert_not_nil rule_set
    assert_equal :ignore, rule_set.type
    assert_equal 2, rule_set.size
    assert_equal rule_file, rule_set.source_path
  end

  def test_load_single_file_with_cracking_rules
    # Test loading a single file with cracking rules
    rule_file = create_temp_file('cracking_rules', [
                                   '# Security rules',
                                   '^.* Failed password for .* from .* port .*',
                                   '^.* Invalid user .* from .*'
                                 ])

    rule_set = @rule_loader.load_file(rule_file, :cracking)
    
    assert_not_nil rule_set
    assert_equal :cracking, rule_set.type
    assert_equal 2, rule_set.size
  end

  def test_load_file_with_empty_lines_and_comments
    # Test that empty lines and comments are properly filtered
    rule_file = create_temp_file('mixed_content', [
                                   '# Header comment',
                                   '',
                                   '  # Indented comment',
                                   'valid_rule_pattern',
                                   '',
                                   '   ',
                                   '# Another comment',
                                   'another_valid_pattern',
                                   ''
                                 ])

    rule_set = @rule_loader.load_file(rule_file, :ignore)
    
    assert_equal 2, rule_set.size
    patterns = rule_set.rules.map(&:raw_pattern)
    assert_includes patterns, 'valid_rule_pattern'
    assert_includes patterns, 'another_valid_pattern'
  end

  def test_load_nonexistent_file
    # Test loading a file that doesn't exist
    assert_raise(Fluent::Plugin::Logcheck::RuleLoader::FileNotFoundError) do
      @rule_loader.load_file('/nonexistent/file', :ignore)
    end
  end

  def test_load_file_with_invalid_regex
    # Test loading a file with invalid regex patterns
    rule_file = create_temp_file('invalid_regex', [
                                   'valid_pattern',
                                   '[invalid_regex', # Missing closing bracket
                                   'another_valid_pattern'
                                 ])

    # Should not raise an error but should log warnings
    rule_set = @rule_loader.load_file(rule_file, :ignore)
    
    # Should only load valid patterns
    assert_equal 2, rule_set.size
  end

  def test_load_directory_recursively
    # Test loading rules from a directory recursively
    create_directory_structure

    rule_sets = @rule_loader.load_directory(@temp_dir, :ignore, recursive: true)
    
    assert_equal 3, rule_sets.size # 3 files created
    total_rules = rule_sets.sum(&:size)
    assert_equal 6, total_rules # 2 rules per file
  end

  def test_load_directory_non_recursively
    # Test loading rules from a directory non-recursively
    create_directory_structure

    rule_sets = @rule_loader.load_directory(@temp_dir, :ignore, recursive: false)
    
    assert_equal 1, rule_sets.size # Only top-level file
    assert_equal 2, rule_sets.first.size
  end

  def test_load_directory_with_type_detection
    # Test loading directory with automatic type detection
    create_typed_directory_structure

    rule_sets = @rule_loader.load_directory(@temp_dir, nil, recursive: true)
    
    ignore_sets = rule_sets.select { |rs| rs.type == :ignore }
    cracking_sets = rule_sets.select { |rs| rs.type == :cracking }
    
    assert_equal 1, ignore_sets.size
    assert_equal 1, cracking_sets.size
  end

  def test_load_with_max_rules_limit
    # Test loading with maximum rules per file limit
    large_rule_file = create_temp_file('large_rules', (1..1500).map { |i| "rule_pattern_#{i}" })

    rule_set = @rule_loader.load_file(large_rule_file, :ignore, max_rules: 1000)
    
    assert_equal 1000, rule_set.size
  end

  def test_load_empty_file
    # Test loading an empty file
    empty_file = create_temp_file('empty', [])

    rule_set = @rule_loader.load_file(empty_file, :ignore)
    
    assert_not_nil rule_set
    assert_equal 0, rule_set.size
  end

  def test_load_file_with_encoding_issues
    # Test loading file with different encodings
    rule_file = create_temp_file('encoding_test', %w(
                                   ascii_pattern
                                   pattern_with_unicode_äöü
                                 ))

    rule_set = @rule_loader.load_file(rule_file, :ignore)
    
    assert_equal 2, rule_set.size
  end

  private

  def create_temp_file(name, lines)
    file_path = File.join(@temp_dir, name)
    File.write(file_path, lines.join("\n"))
    file_path
  end

  def create_directory_structure
    # Create a nested directory structure with rule files
    sub_dir = File.join(@temp_dir, 'subdir')
    FileUtils.mkdir_p(sub_dir)
    
    # Top-level file
    create_temp_file('top_level', %w(top_rule_1 top_rule_2))
    
    # Sub-directory files
    File.write(File.join(sub_dir, 'sub_file1'), "sub_rule_1\nsub_rule_2")
    File.write(File.join(sub_dir, 'sub_file2'), "sub_rule_3\nsub_rule_4")
  end

  def create_typed_directory_structure
    # Create directory structure with type-specific subdirectories
    ignore_dir = File.join(@temp_dir, 'ignore.d')
    cracking_dir = File.join(@temp_dir, 'cracking.d')
    
    FileUtils.mkdir_p(ignore_dir)
    FileUtils.mkdir_p(cracking_dir)
    
    File.write(File.join(ignore_dir, 'server'), "ignore_rule_1\nignore_rule_2")
    File.write(File.join(cracking_dir, 'ssh'), "cracking_rule_1\ncracking_rule_2")
  end
end
