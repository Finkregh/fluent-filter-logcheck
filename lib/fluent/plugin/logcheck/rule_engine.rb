# frozen_string_literal: true

require_relative 'filter_decision'

module Fluent
  module Plugin
    module Logcheck
      # RuleEngine handles the core filtering logic with rule type precedence
      class RuleEngine
        # Rule type precedence (higher number = higher precedence)
        RULE_PRECEDENCE = {
          cracking: 3,     # Highest precedence - security alerts
          violations: 2,   # Medium precedence - system violations
          ignore: 1        # Lowest precedence - ignore rules
        }.freeze

        def initialize(logger: nil)
          @logger = logger
          @rule_sets = []
          @stats = {
            total_messages: 0,
            ignored_messages: 0,
            alert_messages: 0,
            passed_messages: 0,
            rule_matches: Hash.new(0)
          }
        end

        # Add a rule set to the engine
        # @param rule_set [RuleSet] Rule set to add
        def add_rule_set(rule_set)
          @rule_sets << rule_set
          log_info "Added rule set: #{rule_set.type} with #{rule_set.size} rules from #{rule_set.source_path}"
        end

        # Add multiple rule sets to the engine
        # @param rule_sets [Array<RuleSet>] Rule sets to add
        def add_rule_sets(rule_sets)
          rule_sets.each { |rule_set| add_rule_set(rule_set) }
        end

        # Clear all rule sets
        def clear_rule_sets
          @rule_sets.clear
          log_info 'Cleared all rule sets'
        end

        # Get the number of loaded rule sets
        # @return [Integer] Number of rule sets
        def rule_set_count
          @rule_sets.size
        end

        # Get the total number of rules across all rule sets
        # @return [Integer] Total number of rules
        def total_rule_count
          @rule_sets.sum(&:size)
        end

        # Apply filtering logic to a log message
        # @param message [String] The log message to filter
        # @return [FilterDecision] The filtering decision
        def filter(message)
          @stats[:total_messages] += 1

          # Find all matching rules across all rule sets
          matching_rules = find_matching_rules(message)

          if matching_rules.empty?
            # No rules matched - pass the message through
            decision = FilterDecision.pass(message)
            @stats[:passed_messages] += 1
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
        # @return [Hash] Statistics about filtering operations
        def statistics
          @stats.dup
        end

        # Reset statistics
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
        # @param message [String] The log message
        # @return [Array<Rule>] Array of matching rules
        def find_matching_rules(message)
          matching_rules = []

          @rule_sets.each do |rule_set|
            matched_rule = rule_set.match(message)
            if matched_rule
              matching_rules << matched_rule
              @stats[:rule_matches][matched_rule.type] += 1
            end
          end

          matching_rules
        end

        # Apply rule precedence to determine the final decision
        # @param matching_rules [Array<Rule>] Array of matching rules
        # @param message [String] The log message
        # @return [FilterDecision] The final decision
        def apply_rule_precedence(matching_rules, message)
          # Sort rules by precedence (highest first)
          sorted_rules = matching_rules.sort_by { |rule| -RULE_PRECEDENCE[rule.type] }
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
        def update_stats(decision)
          case decision.decision
          when FilterDecision::IGNORE
            @stats[:ignored_messages] += 1
          when FilterDecision::ALERT
            @stats[:alert_messages] += 1
          when FilterDecision::PASS
            @stats[:passed_messages] += 1
          end
        end

        # Logging helpers
        def log_info(message)
          @logger&.info(message)
        end

        def log_debug(message)
          @logger&.debug(message)
        end

        def log_warning(message)
          @logger&.warn(message)
        end
      end
    end
  end
end
