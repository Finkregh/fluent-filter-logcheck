# typed: strict
# frozen_string_literal: true

require 'sorbet-runtime'
require_relative 'filter_decision'

module Fluent
  module Plugin
    module Logcheck
      # RuleEngine handles the core filtering logic with rule type precedence
      class RuleEngine
        extend T::Sig

        # Rule type precedence (higher number = higher precedence)
        RULE_PRECEDENCE = T.let({
          cracking: 3,     # Highest precedence - security alerts
          violations: 2,   # Medium precedence - system violations
          ignore: 1 # Lowest precedence - ignore rules
        }.freeze, T::Hash[Symbol, Integer])

        sig { params(logger: T.untyped).void }
        def initialize(logger: nil)
          @logger = T.let(logger, T.untyped)
          @rule_sets = T.let([], T::Array[T.untyped])
          @stats = T.let({
                           total_messages: 0,
                           ignored_messages: 0,
                           alert_messages: 0,
                           passed_messages: 0,
                           rule_matches: Hash.new(0)
                         }, T::Hash[Symbol, T.untyped])
        end

        # Add a rule set to the engine
        # @param rule_set [RuleSet] Rule set to add
        sig { params(rule_set: T.untyped).void }
        def add_rule_set(rule_set)
          @rule_sets << rule_set
          log_info "Added rule set: #{rule_set.type} with #{rule_set.size} rules from #{rule_set.source_path}"
        end

        # Add multiple rule sets to the engine
        # @param rule_sets [Array<RuleSet>] Rule sets to add
        sig { params(rule_sets: T::Array[T.untyped]).void }
        def add_rule_sets(rule_sets)
          rule_sets.each { |rule_set| add_rule_set(rule_set) }
        end

        # Clear all rule sets from the engine
        sig { void }
        def clear_rule_sets
          @rule_sets.clear
          log_info 'Cleared all rule sets'
        end

        # Get the number of loaded rule sets
        # @return [Integer] Number of rule sets currently loaded
        sig { returns(Integer) }
        def rule_set_count
          @rule_sets.size
        end

        # Get the total number of rules across all rule sets
        # @return [Integer] Total number of rules across all loaded rule sets
        sig { returns(Integer) }
        def total_rule_count
          @rule_sets.sum(&:size)
        end

        # Apply filtering logic to a log message
        # @param message [String] The log message to filter
        # @return [FilterDecision] The filtering decision based on rule matches
        sig { params(message: String).returns(FilterDecision) }
        def filter(message)
          @stats[:total_messages] = T.cast(@stats[:total_messages], Integer) + 1

          # Find all matching rules across all rule sets
          matching_rules = find_matching_rules(message)

          if matching_rules.empty?
            # No rules matched - pass the message through
            decision = FilterDecision.pass(message)
            @stats[:passed_messages] = T.cast(@stats[:passed_messages], Integer) + 1
            log_debug "No rules matched for message: #{message[0..50]}..."
          else
            # Apply rule precedence to determine the final decision
            decision = apply_rule_precedence(matching_rules, message)
            update_stats(decision)
            log_debug "Applied #{decision.decision} decision for message: #{message[0..50]}..."
          end

          decision
        end

        # Get filtering statistics
        # @return [Hash] Statistics about filtering operations including message counts and rule matches
        sig { returns(T::Hash[Symbol, T.untyped]) }
        def statistics
          @stats.dup
        end

        # Reset all filtering statistics to zero
        sig { void }
        def reset_statistics
          @stats = {
            total_messages: 0,
            ignored_messages: 0,
            alert_messages: 0,
            passed_messages: 0,
            rule_matches: Hash.new(0)
          }
        end

        private

        # Find all rules that match the given message
        # @param message [String] The log message to match against
        # @return [Array<Rule>] Array of matching rules from all rule sets
        sig { params(message: String).returns(T::Array[T.untyped]) }
        def find_matching_rules(message)
          matching_rules = T.let([], T::Array[T.untyped])

          @rule_sets.each do |rule_set|
            matched_rule = rule_set.match(message)
            next unless matched_rule

            matching_rules << matched_rule
            rule_matches = T.cast(@stats[:rule_matches], T::Hash[Symbol, Integer])
            rule_matches[matched_rule.type] = T.must(rule_matches[matched_rule.type]) + 1
          end

          matching_rules
        end

        # Apply rule precedence to determine the final decision
        # @param matching_rules [Array<Rule>] Array of matching rules
        # @param message [String] The log message being processed
        # @return [FilterDecision] The final decision based on highest precedence rule
        sig { params(matching_rules: T::Array[T.untyped], message: String).returns(FilterDecision) }
        def apply_rule_precedence(matching_rules, message)
          # Sort rules by precedence (highest first)
          sorted_rules = matching_rules.sort_by { |rule| -(RULE_PRECEDENCE[rule.type] || 0) }
          highest_precedence_rule = sorted_rules.first

          case highest_precedence_rule.type
          when :cracking, :violations
            # Security and violation rules trigger alerts
            FilterDecision.alert(highest_precedence_rule, message)
          when :ignore
            # Ignore rules cause messages to be filtered out
            FilterDecision.ignore(highest_precedence_rule, message)
          else
            # Unknown rule type - default to pass
            log_warning "Unknown rule type: #{highest_precedence_rule.type}"
            FilterDecision.pass(message)
          end
        end

        # Update statistics based on the decision
        # @param decision [FilterDecision] The filtering decision
        sig { params(decision: FilterDecision).void }
        def update_stats(decision)
          case decision.decision
          when FilterDecision::IGNORE
            @stats[:ignored_messages] = T.cast(@stats[:ignored_messages], Integer) + 1
          when FilterDecision::ALERT
            @stats[:alert_messages] = T.cast(@stats[:alert_messages], Integer) + 1
          when FilterDecision::PASS
            @stats[:passed_messages] = T.cast(@stats[:passed_messages], Integer) + 1
          end
        end

        # Logging helpers
        sig { params(message: String).void }
        def log_info(message)
          @logger&.info(message)
        end

        sig { params(message: String).void }
        def log_debug(message)
          @logger&.debug(message)
        end

        sig { params(message: String).void }
        def log_warning(message)
          @logger&.warn(message)
        end
      end
    end
  end
end
