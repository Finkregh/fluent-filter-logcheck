# typed: strict
# frozen_string_literal: true

require 'sorbet-runtime'

module Fluent
  module Plugin
    module Logcheck
      # Module defining logcheck rule types and their behavior
      module RuleTypes
        extend T::Sig

        # Rule type for ignore patterns (lowest priority)
        IGNORE = T.let(:ignore, Symbol)

        # Rule type for cracking/security patterns (highest priority)
        CRACKING = T.let(:cracking, Symbol)

        # Rule type for violation patterns (medium priority)
        VIOLATIONS = T.let(:violations, Symbol)

        # Array of all valid rule types
        ALL_TYPES = T.let([IGNORE, CRACKING, VIOLATIONS].freeze, T::Array[Symbol])

        # Default priority order for rule types (highest to lowest priority)
        DEFAULT_PRIORITY = T.let([CRACKING, VIOLATIONS, IGNORE].freeze, T::Array[Symbol])

        # Rule type detection patterns
        PATH_PATTERNS = T.let({
          /ignore\.d/ => IGNORE,
          /cracking\.d/ => CRACKING,
          /violations\.d/ => VIOLATIONS
        }.freeze, T::Hash[Regexp, Symbol])

        # Detect rule type from file path based on directory patterns
        # @param path [String] File or directory path to analyze
        # @return [Symbol, nil] Detected rule type or nil if no pattern matches
        sig { params(path: String).returns(T.nilable(Symbol)) }
        def self.detect_from_path(path)
          PATH_PATTERNS.each do |pattern, type|
            return type if path.match?(pattern)
          end
          nil
        end

        # Validate if a given type is a valid rule type
        # @param type [Object] Rule type to validate
        # @return [Boolean] True if the type is a valid rule type
        sig { params(type: T.untyped).returns(T::Boolean) }
        def self.valid_type?(type)
          return false unless type.is_a?(Symbol)

          ALL_TYPES.include?(type)
        end

        # Get rule type priority (lower number = higher priority)
        # @param type [Object] Rule type to get priority for
        # @return [Integer] Priority value (0-based index, 999 for invalid types)
        sig { params(type: T.untyped).returns(Integer) }
        def self.priority(type)
          return 999 unless type.is_a?(Symbol)

          DEFAULT_PRIORITY.index(type) || 999
        end

        # Check if rule type is security-related (generates alerts)
        # @param type [Object] Rule type to check
        # @return [Boolean] True for cracking and violations types
        sig { params(type: T.untyped).returns(T::Boolean) }
        def self.security_type?(type)
          return false unless type.is_a?(Symbol)

          [CRACKING, VIOLATIONS].include?(type)
        end
      end
    end
  end
end
