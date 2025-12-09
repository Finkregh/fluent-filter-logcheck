# typed: false
# frozen_string_literal: true

require_relative "../helper"
require "fluent/plugin/logcheck/rule_engine"
require "fluent/plugin/logcheck/rule"

class RuleEngineTest < Test::Unit::TestCase
  include Fluent::Test::Helpers

  def setup
    @engine = Fluent::Plugin::Logcheck::RuleEngine.new
    @ignore_rule_set = create_rule_set(:ignore, [
      '^.* systemd\\[[0-9]+\\]: Started .*\\.$',
      "^.* kernel: .*$",
    ])
    @cracking_rule_set = create_rule_set(:cracking, [
      '^.* sshd\\[[0-9]+\\]: Failed password .*$',
      '^.* sshd\\[[0-9]+\\]: Invalid user .*$',
    ])
    @violations_rule_set = create_rule_set(:violations, [
      "^.* sudo: .* : command not allowed .*$",
    ])
  end

  sub_test_case "initialization" do
    test "creates engine with empty rule sets" do
      engine = Fluent::Plugin::Logcheck::RuleEngine.new
      assert_equal 0, engine.rule_set_count
      assert_equal 0, engine.total_rule_count
    end

    test "initializes statistics" do
      stats = @engine.statistics
      assert_equal 0, stats[:total_messages]
      assert_equal 0, stats[:ignored_messages]
      assert_equal 0, stats[:alert_messages]
      assert_equal 0, stats[:passed_messages]
      assert_kind_of Hash, stats[:rule_matches]
    end
  end

  sub_test_case "rule set management" do
    test "adds single rule set" do
      @engine.add_rule_set(@ignore_rule_set)
      assert_equal 1, @engine.rule_set_count
      assert_equal 2, @engine.total_rule_count
    end

    test "adds multiple rule sets" do
      @engine.add_rule_sets([@ignore_rule_set, @cracking_rule_set])
      assert_equal 2, @engine.rule_set_count
      assert_equal 4, @engine.total_rule_count
    end

    test "clears all rule sets" do
      @engine.add_rule_sets([@ignore_rule_set, @cracking_rule_set])
      @engine.clear_rule_sets
      assert_equal 0, @engine.rule_set_count
      assert_equal 0, @engine.total_rule_count
    end
  end

  sub_test_case "filtering with no rules" do
    test "passes message through when no rules loaded" do
      message = "Dec  8 20:15:32 hostname test: Some message"
      decision = @engine.filter(message)

      assert_true decision.pass?
      assert_false decision.matched?
      assert_equal message, decision.message
    end

    test "updates statistics for passed messages" do
      message = "Dec  8 20:15:32 hostname test: Some message"
      @engine.filter(message)

      stats = @engine.statistics
      assert_equal 1, stats[:total_messages]
      assert_equal 0, stats[:ignored_messages]
      assert_equal 0, stats[:alert_messages]
      assert_equal 1, stats[:passed_messages]
    end
  end

  sub_test_case "filtering with ignore rules" do
    define_method(:setup) do
      super
      @engine.add_rule_set(@ignore_rule_set)
    end

    test "ignores message matching ignore rule" do
      message = "Dec  8 20:15:32 hostname systemd[1]: Started some service."
      decision = @engine.filter(message)

      assert_true decision.ignore?
      assert_true decision.matched?
      assert_equal :ignore, decision.rule_type
      assert_equal message, decision.message
    end

    test "passes message not matching ignore rule" do
      message = "Dec  8 20:15:32 hostname sshd[1234]: Connection from 192.168.1.1"
      decision = @engine.filter(message)

      assert_true decision.pass?
      assert_false decision.matched?
    end

    test "updates statistics for ignored messages" do
      message = "Dec  8 20:15:32 hostname systemd[1]: Started some service."
      @engine.filter(message)

      stats = @engine.statistics
      assert_equal 1, stats[:total_messages]
      assert_equal 1, stats[:ignored_messages]
      assert_equal 0, stats[:alert_messages]
      assert_equal 0, stats[:passed_messages]
      assert_equal 1, stats[:rule_matches][:ignore]
    end
  end

  sub_test_case "filtering with cracking rules" do
    define_method(:setup) do
      super
      @engine.add_rule_set(@cracking_rule_set)
    end

    test "alerts on message matching cracking rule" do
      message = "Dec  8 20:15:32 hostname sshd[1234]: Failed password for user from 192.168.1.1"
      decision = @engine.filter(message)

      assert_true decision.alert?
      assert_true decision.matched?
      assert_equal :cracking, decision.rule_type
      assert_equal message, decision.message
    end

    test "updates statistics for alert messages" do
      message = "Dec  8 20:15:32 hostname sshd[1234]: Failed password for user from 192.168.1.1"
      @engine.filter(message)

      stats = @engine.statistics
      assert_equal 1, stats[:total_messages]
      assert_equal 0, stats[:ignored_messages]
      assert_equal 1, stats[:alert_messages]
      assert_equal 0, stats[:passed_messages]
      assert_equal 1, stats[:rule_matches][:cracking]
    end
  end

  sub_test_case "filtering with violations rules" do
    define_method(:setup) do
      super
      @engine.add_rule_set(@violations_rule_set)
    end

    test "alerts on message matching violations rule" do
      message = "Dec  8 20:15:32 hostname sudo: user : command not allowed ; TTY=pts/0"
      decision = @engine.filter(message)

      assert_true decision.alert?
      assert_true decision.matched?
      assert_equal :violations, decision.rule_type
    end
  end

  sub_test_case "rule precedence" do
    define_method(:setup) do
      super
      @engine.add_rule_sets([@ignore_rule_set, @cracking_rule_set, @violations_rule_set])
    end

    test "cracking rules take precedence over ignore rules" do
      # Create overlapping rules where both ignore and cracking could match
      ignore_rule_set = create_rule_set(:ignore, ['^.* sshd\\[[0-9]+\\]: .*$'])
      cracking_rule_set = create_rule_set(:cracking, ['^.* sshd\\[[0-9]+\\]: Failed .*$'])

      engine = Fluent::Plugin::Logcheck::RuleEngine.new
      engine.add_rule_sets([ignore_rule_set, cracking_rule_set])

      message = "Dec  8 20:15:32 hostname sshd[1234]: Failed password for user"
      decision = engine.filter(message)

      # Should alert (cracking) not ignore, even though both rules match
      assert_true decision.alert?
      assert_equal :cracking, decision.rule_type
    end

    test "violations rules take precedence over ignore rules" do
      # Create overlapping rules
      ignore_rule_set = create_rule_set(:ignore, ["^.* sudo: .*$"])
      violations_rule_set = create_rule_set(:violations, ["^.* sudo: .* : command not allowed .*$"])

      engine = Fluent::Plugin::Logcheck::RuleEngine.new
      engine.add_rule_sets([ignore_rule_set, violations_rule_set])

      message = "Dec  8 20:15:32 hostname sudo: user : command not allowed ; TTY=pts/0"
      decision = engine.filter(message)

      # Should alert (violations) not ignore
      assert_true decision.alert?
      assert_equal :violations, decision.rule_type
    end

    test "cracking rules take precedence over violations rules" do
      # Create overlapping rules
      violations_rule_set = create_rule_set(:violations, ['^.* sshd\\[[0-9]+\\]: .*$'])
      cracking_rule_set = create_rule_set(:cracking, ['^.* sshd\\[[0-9]+\\]: Failed .*$'])

      engine = Fluent::Plugin::Logcheck::RuleEngine.new
      engine.add_rule_sets([violations_rule_set, cracking_rule_set])

      message = "Dec  8 20:15:32 hostname sshd[1234]: Failed password for user"
      decision = engine.filter(message)

      # Should be cracking alert, not violations alert
      assert_true decision.alert?
      assert_equal :cracking, decision.rule_type
    end
  end

  sub_test_case "statistics" do
    define_method(:setup) do
      super
      @engine.add_rule_sets([@ignore_rule_set, @cracking_rule_set])
    end

    test "tracks multiple message types" do
      messages = [
        "Dec  8 20:15:32 hostname systemd[1]: Started some service.", # ignore
        "Dec  8 20:15:32 hostname sshd[1234]: Failed password for user", # cracking
        "Dec  8 20:15:32 hostname test: Some other message", # pass
      ]

      messages.each { |msg| @engine.filter(msg) }

      stats = @engine.statistics
      assert_equal 3, stats[:total_messages]
      assert_equal 1, stats[:ignored_messages]
      assert_equal 1, stats[:alert_messages]
      assert_equal 1, stats[:passed_messages]
      assert_equal 1, stats[:rule_matches][:ignore]
      assert_equal 1, stats[:rule_matches][:cracking]
    end

    test "resets statistics" do
      @engine.filter("Dec  8 20:15:32 hostname systemd[1]: Started some service.")
      @engine.reset_statistics

      stats = @engine.statistics
      assert_equal 0, stats[:total_messages]
      assert_equal 0, stats[:ignored_messages]
      assert_equal 0, stats[:alert_messages]
      assert_equal 0, stats[:passed_messages]
      assert_equal 0, stats[:rule_matches].size
    end
  end

  sub_test_case "rule precedence constants" do
    test "defines correct precedence values" do
      precedence = Fluent::Plugin::Logcheck::RuleEngine::RULE_PRECEDENCE

      assert_equal 3, precedence[:cracking]
      assert_equal 2, precedence[:violations]
      assert_equal 1, precedence[:ignore]

      # Verify precedence order
      assert_operator precedence[:cracking], :>, precedence[:violations]
      assert_operator precedence[:violations], :>, precedence[:ignore]
    end
  end

  private

  def create_rule_set(type, patterns)
    rule_set = Fluent::Plugin::Logcheck::RuleSet.new(type, "/test/#{type}")
    patterns.each_with_index do |pattern, index|
      rule = Fluent::Plugin::Logcheck::Rule.new(pattern, type, "/test/#{type}", index + 1)
      rule_set.add_rule(rule)
    end
    rule_set
  end
end
