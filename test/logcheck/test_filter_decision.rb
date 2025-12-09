# typed: false
# frozen_string_literal: true

require_relative "../helper"
require "fluent/plugin/logcheck/filter_decision"
require "fluent/plugin/logcheck/rule"

class FilterDecisionTest < Test::Unit::TestCase
  include Fluent::Test::Helpers

  def setup
    @message = "Test log message"
    @rule = Fluent::Plugin::Logcheck::Rule.new("test.*pattern", :ignore, "/test/file", 1)
  end

  sub_test_case "initialization" do
    test "creates ignore decision with rule" do
      decision = Fluent::Plugin::Logcheck::FilterDecision.new(:ignore, @rule, @message)

      assert_equal :ignore, decision.decision
      assert_equal @rule, decision.rule
      assert_equal :ignore, decision.rule_type
      assert_equal @message, decision.message
    end

    test "creates pass decision without rule" do
      decision = Fluent::Plugin::Logcheck::FilterDecision.new(:pass, nil, @message)

      assert_equal :pass, decision.decision
      assert_nil decision.rule
      assert_nil decision.rule_type
      assert_equal @message, decision.message
    end
  end

  sub_test_case "decision type checks" do
    test "ignore? returns true for ignore decision" do
      decision = Fluent::Plugin::Logcheck::FilterDecision.new(:ignore, @rule, @message)
      assert_true decision.ignore?
      assert_false decision.alert?
      assert_false decision.pass?
    end

    test "alert? returns true for alert decision" do
      decision = Fluent::Plugin::Logcheck::FilterDecision.new(:alert, @rule, @message)
      assert_false decision.ignore?
      assert_true decision.alert?
      assert_false decision.pass?
    end

    test "pass? returns true for pass decision" do
      decision = Fluent::Plugin::Logcheck::FilterDecision.new(:pass, nil, @message)
      assert_false decision.ignore?
      assert_false decision.alert?
      assert_true decision.pass?
    end
  end

  sub_test_case "matched? method" do
    test "returns true when rule is present" do
      decision = Fluent::Plugin::Logcheck::FilterDecision.new(:ignore, @rule, @message)
      assert_true decision.matched?
    end

    test "returns false when rule is nil" do
      decision = Fluent::Plugin::Logcheck::FilterDecision.new(:pass, nil, @message)
      assert_false decision.matched?
    end
  end

  sub_test_case "description method" do
    test "returns correct description for ignore decision" do
      decision = Fluent::Plugin::Logcheck::FilterDecision.new(:ignore, @rule, @message)
      expected = "Message ignored by ignore rule: test.*pattern"
      assert_equal expected, decision.description
    end

    test "returns correct description for alert decision" do
      cracking_rule = Fluent::Plugin::Logcheck::Rule.new("attack.*pattern", :cracking, "/test/file", 1)
      decision = Fluent::Plugin::Logcheck::FilterDecision.new(:alert, cracking_rule, @message)
      expected = "Alert triggered by cracking rule: attack.*pattern"
      assert_equal expected, decision.description
    end

    test "returns correct description for pass decision" do
      decision = Fluent::Plugin::Logcheck::FilterDecision.new(:pass, nil, @message)
      expected = "Message passed through (no matching rules)"
      assert_equal expected, decision.description
    end

    test "returns unknown description for invalid decision" do
      decision = Fluent::Plugin::Logcheck::FilterDecision.new(:unknown, nil, @message)
      expected = "Unknown decision: unknown"
      assert_equal expected, decision.description
    end
  end

  sub_test_case "to_h method" do
    test "returns hash with all fields for decision with rule" do
      decision = Fluent::Plugin::Logcheck::FilterDecision.new(:ignore, @rule, @message)
      hash = decision.to_h

      assert_equal :ignore, hash[:decision]
      assert_equal :ignore, hash[:rule_type]
      assert_equal "test.*pattern", hash[:pattern]
      assert_equal "/test/file", hash[:source]
      assert_equal 1, hash[:line]
      assert_equal @message, hash[:message_preview]
    end

    test "returns hash with nil fields for decision without rule" do
      decision = Fluent::Plugin::Logcheck::FilterDecision.new(:pass, nil, @message)
      hash = decision.to_h

      assert_equal :pass, hash[:decision]
      assert_nil hash[:rule_type]
      assert_nil hash[:pattern]
      assert_nil hash[:source]
      assert_nil hash[:line]
      assert_equal @message, hash[:message_preview]
    end

    test "truncates long messages in preview" do
      long_message = "a" * 150
      decision = Fluent::Plugin::Logcheck::FilterDecision.new(:pass, nil, long_message)
      hash = decision.to_h

      assert_equal 101, hash[:message_preview].length
      assert_equal long_message[0..100], hash[:message_preview]
    end
  end

  sub_test_case "factory methods" do
    test "ignore creates ignore decision" do
      decision = Fluent::Plugin::Logcheck::FilterDecision.ignore(@rule, @message)

      assert_equal :ignore, decision.decision
      assert_equal @rule, decision.rule
      assert_equal @message, decision.message
      assert_true decision.ignore?
    end

    test "alert creates alert decision" do
      decision = Fluent::Plugin::Logcheck::FilterDecision.alert(@rule, @message)

      assert_equal :alert, decision.decision
      assert_equal @rule, decision.rule
      assert_equal @message, decision.message
      assert_true decision.alert?
    end

    test "pass creates pass decision" do
      decision = Fluent::Plugin::Logcheck::FilterDecision.pass(@message)

      assert_equal :pass, decision.decision
      assert_nil decision.rule
      assert_equal @message, decision.message
      assert_true decision.pass?
    end
  end

  sub_test_case "constants" do
    test "defines correct decision constants" do
      assert_equal :ignore, Fluent::Plugin::Logcheck::FilterDecision::IGNORE
      assert_equal :alert, Fluent::Plugin::Logcheck::FilterDecision::ALERT
      assert_equal :pass, Fluent::Plugin::Logcheck::FilterDecision::PASS
    end
  end
end
