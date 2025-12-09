# frozen_string_literal: true

require_relative 'rule_types'

module Fluent
  module Plugin
    module Logcheck
      # Custom exceptions for logcheck plugin
      class LogcheckError < StandardError; end
      class PatternCompileError < LogcheckError; end
      class RuleLoadError < LogcheckError; end
      class ConfigurationError < LogcheckError; end

      # Represents a single logcheck rule with pattern matching capability
      class Rule
        attr_reader :raw_pattern, :type, :source_file, :line_number

        # Initialize a new rule
        # @param raw_pattern [String] Original regex pattern string
        # @param type [Symbol] Rule type (:ignore, :cracking, :violations)
        # @param source_file [String] Path to source file
        # @param line_number [Integer] Line number in source file
        def initialize(raw_pattern, type, source_file, line_number)
          @raw_pattern = raw_pattern
          @type = type
          @source_file = source_file
          @line_number = line_number
          @compiled_pattern = nil
        end

        # Test if rule matches given text
        # @param text [String] Text to match against
        # @return [Boolean] True if pattern matches
        def match?(text)
          return false if text.nil?

          pattern.match?(text.to_s)
        rescue StandardError => e
          raise PatternCompileError, "Failed to match pattern '#{@raw_pattern}': #{e.message}"
        end

        # Get compiled regex pattern (lazy compilation)
        # @return [Regexp] Compiled regex pattern
        def pattern
          @compiled_pattern ||= compile_pattern
        end

        # Get rule metadata
        # @return [Hash] Rule metadata
        def metadata
          {
            type: @type,
            source_file: @source_file,
            line_number: @line_number,
            pattern: @raw_pattern
          }
        end

        private

        # Compile the regex pattern with error handling
        # @return [Regexp] Compiled regex pattern
        def compile_pattern
          Regexp.new(@raw_pattern)
        rescue RegexpError => e
          raise PatternCompileError,
                "Invalid regex pattern '#{@raw_pattern}' in #{@source_file}:#{@line_number}: #{e.message}"
        end
      end

      # Collection of rules of the same type from a source
      class RuleSet
        attr_reader :rules, :type, :source_path

        # Initialize rule set
        # @param type [Symbol] Rule type
        # @param source_path [String] Source file/directory path
        def initialize(type, source_path)
          @type = type
          @source_path = source_path
          @rules = []
        end

        # Add rule to set
        # @param rule [Rule] Rule to add
        def add_rule(rule)
          @rules << rule
        end

        # Find first matching rule
        # @param text [String] Text to match
        # @return [Rule, nil] First matching rule or nil
        def match(text)
          @rules.find { |rule| rule.match?(text) }
        end

        # Find all matching rules
        # @param text [String] Text to match
        # @return [Array<Rule>] All matching rules
        def match_all(text)
          @rules.select { |rule| rule.match?(text) }
        end

        # Get rule count
        # @return [Integer] Number of rules in set
        def size
          @rules.size
        end

        # Check if rule set is empty
        # @return [Boolean] True if no rules
        def empty?
          @rules.empty?
        end
      end
    end
  end
end
