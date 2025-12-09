# typed: strict
# frozen_string_literal: true

require "sorbet-runtime"

module Fluent
  module Plugin
    module Logcheck
      # FilterDecision represents the result of applying logcheck rules to a log message
      class FilterDecision
        extend T::Sig

        # Decision types
        IGNORE = T.let(:ignore, Symbol)
        ALERT = T.let(:alert, Symbol)
        PASS = T.let(:pass, Symbol)

        sig { returns(Symbol) }
        attr_reader :decision

        sig { returns(T.nilable(T.untyped)) }
        attr_reader :rule

        sig { returns(T.nilable(Symbol)) }
        attr_reader :rule_type

        sig { returns(String) }
        attr_reader :message

        # Create a new filter decision
        # @param decision [Symbol] The decision type (:ignore, :alert, :pass)
        # @param rule [Rule, nil] The rule that matched (if any)
        # @param message [String] The original log message
        sig { params(decision: Symbol, rule: T.nilable(T.untyped), message: String).void }

        def initialize(decision, rule, message)
          @decision = decision
          @rule = rule
          @rule_type = T.let(rule&.type, T.nilable(Symbol))
          @message = message
        end

        # Check if the decision is to ignore the message
        # @return [Boolean] True if message should be ignored
        sig { returns(T::Boolean) }

        def ignore?
          @decision == IGNORE
        end

        # Check if the decision is to alert on the message
        # @return [Boolean] True if message should generate an alert
        sig { returns(T::Boolean) }

        def alert?
          @decision == ALERT
        end

        # Check if the decision is to pass the message through
        # @return [Boolean] True if message should pass through unchanged
        sig { returns(T::Boolean) }

        def pass?
          @decision == PASS
        end

        # Check if a rule matched
        # @return [Boolean] True if a rule matched
        sig { returns(T::Boolean) }

        def matched?
          !@rule.nil?
        end

        # Get a human-readable description of the decision
        # @return [String] Description of the decision
        sig { returns(String) }

        def description
          case @decision
          when IGNORE
            "Message ignored by #{@rule_type} rule: #{T.must(@rule).raw_pattern}"
          when ALERT
            "Alert triggered by #{@rule_type} rule: #{T.must(@rule).raw_pattern}"
          when PASS
            "Message passed through (no matching rules)"
          else
            "Unknown decision: #{@decision}"
          end
        end

        # Convert to hash for logging/debugging
        # @return [Hash] Hash representation of the decision
        sig { returns(T::Hash[Symbol, T.untyped]) }

        def to_h
          {
            decision: @decision,
            rule_type: @rule_type,
            pattern: @rule&.raw_pattern,
            source: @rule&.source_file,
            line: @rule&.line_number,
            message_preview: @message[0..100],
          }
        end

        # Create an ignore decision
        # @param rule [Rule] The rule that matched
        # @param message [String] The log message
        # @return [FilterDecision] New ignore decision
        sig { params(rule: T.untyped, message: String).returns(FilterDecision) }
        def self.ignore(rule, message)
          new(IGNORE, rule, message)
        end

        # Create an alert decision
        # @param rule [Rule] The rule that matched
        # @param message [String] The log message
        # @return [FilterDecision] New alert decision
        sig { params(rule: T.untyped, message: String).returns(FilterDecision) }
        def self.alert(rule, message)
          new(ALERT, rule, message)
        end

        # Create a pass decision (no rules matched)
        # @param message [String] The log message
        # @return [FilterDecision] New pass decision
        sig { params(message: String).returns(FilterDecision) }
        def self.pass(message)
          new(PASS, nil, message)
        end
      end
    end
  end
end
