# frozen_string_literal: true

module Fluent
  module Plugin
    module Logcheck
      # FilterDecision represents the result of applying logcheck rules to a log message
      class FilterDecision
        # Decision types
        IGNORE = :ignore
        ALERT = :alert
        PASS = :pass

        attr_reader :decision, :rule, :rule_type, :message

        # Create a new filter decision
        # @param decision [Symbol] The decision type (:ignore, :alert, :pass)
        # @param rule [Rule, nil] The rule that matched (if any)
        # @param message [String] The original log message
        def initialize(decision, rule, message)
          @decision = decision
          @rule = rule
          @rule_type = rule&.type
          @message = message
        end

        # Check if the decision is to ignore the message
        # @return [Boolean] True if message should be ignored
        def ignore?
          @decision == IGNORE
        end

        # Check if the decision is to alert on the message
        # @return [Boolean] True if message should generate an alert
        def alert?
          @decision == ALERT
        end

        # Check if the decision is to pass the message through
        # @return [Boolean] True if message should pass through unchanged
        def pass?
          @decision == PASS
        end

        # Check if a rule matched
        # @return [Boolean] True if a rule matched
        def matched?
          !@rule.nil?
        end

        # Get a human-readable description of the decision
        # @return [String] Description of the decision
        def description
          case @decision
          when IGNORE
            "Message ignored by #{@rule_type} rule: #{@rule.raw_pattern}"
          when ALERT
            "Alert triggered by #{@rule_type} rule: #{@rule.raw_pattern}"
          when PASS
            "Message passed through (no matching rules)"
          else
            "Unknown decision: #{@decision}"
          end
        end

        # Convert to hash for logging/debugging
        # @return [Hash] Hash representation of the decision
        def to_h
          {
            decision: @decision,
            rule_type: @rule_type,
            pattern: @rule&.raw_pattern,
            source: @rule&.source_file,
            line: @rule&.line_number,
            message_preview: @message[0..100]
          }
        end

        # Create an ignore decision
        # @param rule [Rule] The rule that matched
        # @param message [String] The log message
        # @return [FilterDecision] New ignore decision
        def self.ignore(rule, message)
          new(IGNORE, rule, message)
        end

        # Create an alert decision
        # @param rule [Rule] The rule that matched
        # @param message [String] The log message
        # @return [FilterDecision] New alert decision
        def self.alert(rule, message)
          new(ALERT, rule, message)
        end

        # Create a pass decision (no rules matched)
        # @param message [String] The log message
        # @return [FilterDecision] New pass decision
        def self.pass(message)
          new(PASS, nil, message)
        end
      end
    end
  end
end
