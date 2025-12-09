# typed: strict
# frozen_string_literal: true

require 'sorbet-runtime'

module Fluent
  module Plugin
    module Logcheck
      # Module defining logcheck rule types and their behavior
      module RuleTypes
        extend T::Sig

        IGNORE = T.let(:ignore, Symbol)
        CRACKING = T.let(:cracking, Symbol)
        VIOLATIONS = T.let(:violations, Symbol)

        ALL_TYPES = T.let([IGNORE, CRACKING, VIOLATIONS].freeze, T::Array[Symbol])
        DEFAULT_PRIORITY = T.let([CRACKING, VIOLATIONS, IGNORE].freeze, T::Array[Symbol])

        # Rule type detection patterns
        PATH_PATTERNS = T.let({
          /ignore\.d/ => IGNORE,
          /cracking\.d/ => CRACKING,
          /violations\.d/ => VIOLATIONS
        }.freeze, T::Hash[Regexp, Symbol])

        # Detect rule type from file path
        # @param path [String] File or directory path
        # @return [Symbol, nil] Rule type or nil if not detected
        sig { params(path: String).returns(T.nilable(Symbol)) }
        def self.detect_from_path(path)
          PATH_PATTERNS.each do |pattern, type|
            return type if path.match?(pattern)
          end
          nil
        end

        # Validate rule type
        # @param type [Symbol] Rule type to validate
        # @return [Boolean] True if valid rule type
        sig { params(type: Symbol).returns(T::Boolean) }
        def self.valid_type?(type)
          ALL_TYPES.include?(type)
        end

        # Get rule type priority (lower number = higher priority)
        # @param type [Symbol] Rule type
        # @return [Integer] Priority value
        sig { params(type: Symbol).returns(Integer) }
        def self.priority(type)
          DEFAULT_PRIORITY.index(type) || 999
        end

        # Check if rule type is security-related
        # @param type [Symbol] Rule type
        # @return [Boolean] True for cracking and violations
        sig { params(type: Symbol).returns(T::Boolean) }
        def self.security_type?(type)
          [CRACKING, VIOLATIONS].include?(type)
        end
      end
    end
  end
end
