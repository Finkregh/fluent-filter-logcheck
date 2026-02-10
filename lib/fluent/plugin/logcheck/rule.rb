# typed: strict
# frozen_string_literal: true

require 'sorbet-runtime'
require_relative 'rule_types'

# Fluent namespace for Fluentd plugins
module Fluent
  # Plugin namespace for Fluentd plugins
  module Plugin
    # Logcheck namespace for logcheck-related classes
    module Logcheck
      # Base error class for logcheck plugin
      class LogcheckError < StandardError; end

      # Error raised when regex pattern compilation fails
      class PatternCompileError < LogcheckError; end

      # Error raised when rule loading fails
      class RuleLoadError < LogcheckError; end

      # Error raised when configuration is invalid
      class ConfigurationError < LogcheckError; end

      # Represents a single logcheck rule with pattern matching capability
      class Rule
        extend T::Sig

        sig { returns(String) }
        attr_reader :raw_pattern

        sig { returns(Symbol) }
        attr_reader :type

        sig { returns(String) }
        attr_reader :source_file

        sig { returns(Integer) }
        attr_reader :line_number

        # Initialize a new rule
        # @param raw_pattern [String] Original regex pattern string
        # @param type [Symbol] Rule type (:ignore, :cracking, :violations)
        # @param source_file [String] Path to source file
        # @param line_number [Integer] Line number in source file
        sig { params(raw_pattern: String, type: Symbol, source_file: String, line_number: Integer).void }
        def initialize(raw_pattern, type, source_file, line_number)
          @raw_pattern = raw_pattern
          @type = type
          @source_file = source_file
          @line_number = line_number
          @compiled_pattern = T.let(nil, T.nilable(Regexp))
          @pattern = T.let(nil, T.nilable(Regexp))
        end

        # Test if rule matches given text
        # @param text [String] Text to match against
        # @return [Boolean] True if pattern matches
        sig { params(text: T.untyped).returns(T::Boolean) }
        def match?(text)
          return false if text.nil?

          pattern.match?(text.to_s)
        rescue StandardError => e
          raise PatternCompileError, "Failed to match pattern '#{@raw_pattern}': #{e.message}"
        end

        # Get compiled regex pattern (lazy compilation)
        # @return [Regexp] Compiled regex pattern
        sig { returns(Regexp) }
        def pattern
          @pattern ||= compile_pattern
        end

        # Get rule metadata
        # @return [Hash] Rule metadata including type, source file, line number, and pattern
        sig { returns(T::Hash[Symbol, T.untyped]) }
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
        # @raise [PatternCompileError] If regex compilation fails
        sig { returns(Regexp) }
        def compile_pattern
          # Suppress Ruby 3.3+ warnings about character classes in POSIX bracket expressions
          # These warnings are false positives for valid POSIX patterns like [[:digit:]]
          original_verbosity = $VERBOSE
          $VERBOSE = nil
          result = Regexp.new(@raw_pattern)
          $VERBOSE = original_verbosity
          result
        rescue RegexpError => e
          $VERBOSE = original_verbosity
          raise PatternCompileError,
                "Invalid regex pattern '#{@raw_pattern}' in #{@source_file}:#{@line_number}: #{e.message}"
        end
      end

      # Collection of rules of the same type from a source
      class RuleSet
        extend T::Sig

        sig { returns(T::Array[Rule]) }
        attr_reader :rules

        sig { returns(Symbol) }
        attr_reader :type

        sig { returns(String) }
        attr_reader :source_path

        # Initialize rule set
        # @param type [Symbol] Rule type
        # @param source_path [String] Source file/directory path
        sig { params(type: Symbol, source_path: String).void }
        def initialize(type, source_path)
          @type = type
          @source_path = source_path
          @rules = T.let([], T::Array[Rule])
        end

        # Add rule to set
        # @param rule [Rule] Rule to add
        sig { params(rule: Rule).void }
        def add_rule(rule)
          @rules << rule
        end

        # Find first matching rule
        # @param text [String] Text to match against rules
        # @return [Rule, nil] First matching rule or nil if no match
        sig { params(text: String).returns(T.nilable(Rule)) }
        def match(text)
          @rules.find { |rule| rule.match?(text) }
        end

        # Find all matching rules
        # @param text [String] Text to match against rules
        # @return [Array<Rule>] All matching rules (empty array if no matches)
        sig { params(text: String).returns(T::Array[Rule]) }
        def match_all(text)
          @rules.filter { |rule| rule.match?(text) }
        end

        # Get rule count
        # @return [Integer] Number of rules in this set
        sig { returns(Integer) }
        def size
          @rules.size
        end

        # Check if rule set is empty
        # @return [Boolean] True if no rules are loaded
        sig { returns(T::Boolean) }
        def empty?
          @rules.empty?
        end
      end
    end
  end
end
