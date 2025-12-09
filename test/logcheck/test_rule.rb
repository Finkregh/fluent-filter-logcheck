# typed: false
# frozen_string_literal: true

require_relative "../helper"
require "fluent/plugin/logcheck/rule"

class RuleTest < Test::Unit::TestCase
  def setup
    @rule = Fluent::Plugin::Logcheck::Rule.new(
      "^test pattern$",
      :ignore,
      "/test/file",
      42
    )
  end

  def test_initialization
    # Test rule initialization with all parameters
    assert_equal :ignore, @rule.type
    assert_equal "/test/file", @rule.source_file
    assert_equal 42, @rule.line_number
    assert_equal "^test pattern$", @rule.raw_pattern
  end

  def test_pattern_compilation
    # Test lazy pattern compilation
    pattern = @rule.pattern
    assert_instance_of Regexp, pattern
    assert_equal pattern, @rule.pattern # Should return cached version
  end

  def test_match_positive
    # Test positive pattern matching
    assert_true @rule.match?("test pattern")
  end

  def test_match_negative
    # Test negative pattern matching
    assert_false @rule.match?("different pattern")
    assert_false @rule.match?("test pattern extra")
    assert_false @rule.match?("prefix test pattern")
  end

  def test_match_nil_input
    # Test matching against nil input
    assert_false @rule.match?(nil)
  end

  def test_match_empty_input
    # Test matching against empty input
    assert_false @rule.match?("")
  end

  def test_match_non_string_input
    # Test matching against non-string input (should convert to string)
    rule = Fluent::Plugin::Logcheck::Rule.new("123", :ignore, "/test", 1)
    assert_true rule.match?(123)
    assert_false rule.match?(456)
  end

  def test_invalid_pattern
    # Test invalid regex pattern handling
    rule = Fluent::Plugin::Logcheck::Rule.new("[invalid", :ignore, "/test", 1)

    assert_raise(Fluent::Plugin::Logcheck::PatternCompileError) do
      rule.pattern
    end
  end

  def test_invalid_pattern_error_message
    # Test that error message includes useful information
    rule = Fluent::Plugin::Logcheck::Rule.new("[invalid", :ignore, "/test/file", 42)

    error = assert_raise(Fluent::Plugin::Logcheck::PatternCompileError) do
      rule.pattern
    end

    assert_match(/Invalid regex pattern/, error.message)
    assert_match(/\[invalid/, error.message)
    assert_match(%r{/test/file:42}, error.message)
  end

  def test_match_with_invalid_pattern
    # Test matching with invalid pattern should raise PatternCompileError
    rule = Fluent::Plugin::Logcheck::Rule.new("[invalid", :ignore, "/test", 1)

    assert_raise(Fluent::Plugin::Logcheck::PatternCompileError) do
      rule.match?("test")
    end
  end

  def test_metadata
    # Test rule metadata generation
    metadata = @rule.metadata

    assert_equal :ignore, metadata[:type]
    assert_equal "/test/file", metadata[:source_file]
    assert_equal 42, metadata[:line_number]
    assert_equal "^test pattern$", metadata[:pattern]
  end

  def test_complex_pattern_matching
    # Test with more complex logcheck-style patterns
    pattern = '^(\w{3} [ :[:digit:]]{11}|[0-9T:.+-]{32}) [._[:alnum:]-]+ systemd\[[0-9]+\]: (Start|Stopp)ed .+\.$'
    rule = Fluent::Plugin::Logcheck::Rule.new(pattern, :ignore, "/test", 1)

    # Should match systemd messages
    assert_true rule.match?("Dec  8 10:00:00 server systemd[1]: Started nginx.service.")
    assert_true rule.match?("Dec  8 10:00:00 server systemd[1]: Stopped nginx.service.")

    # Should not match other messages
    assert_false rule.match?("Dec  8 10:00:00 server nginx[1234]: Starting up")
    assert_false rule.match?("Dec  8 10:00:00 server systemd[1]: Reached target")
  end

  def test_different_rule_types
    # Test rules with different types
    types = %i(ignore cracking violations)

    types.each do |type|
      rule = Fluent::Plugin::Logcheck::Rule.new("test", type, "/test", 1)
      assert_equal type, rule.type
      assert_equal type, rule.metadata[:type]
    end
  end

  def test_pattern_caching
    # Test that pattern compilation is cached
    # This is a bit tricky to test directly, but we can verify the pattern
    # object is the same on multiple calls
    pattern1 = @rule.pattern
    pattern2 = @rule.pattern

    assert_same pattern1, pattern2
  end

  def test_unicode_pattern
    # Test with unicode characters in pattern
    rule = Fluent::Plugin::Logcheck::Rule.new("café.*résumé", :ignore, "/test", 1)

    assert_true rule.match?("café and résumé")
    assert_false rule.match?("cafe and resume")
  end

  def test_multiline_pattern
    # Test with multiline matching
    rule = Fluent::Plugin::Logcheck::Rule.new("line1.*line2", :ignore, "/test", 1)

    # Should not match across lines by default
    assert_false rule.match?("line1\nline2")

    # Should match within single line
    assert_true rule.match?("line1 something line2")
  end
end
