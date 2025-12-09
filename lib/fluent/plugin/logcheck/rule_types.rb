# frozen_string_literal: true

module Fluent
  module Plugin
    module Logcheck
      # Module defining logcheck rule types and their behavior
      module RuleTypes
        IGNORE = :ignore
        CRACKING = :cracking
        VIOLATIONS = :violations

        ALL_TYPES = [IGNORE, CRACKING, VIOLATIONS].freeze
        DEFAULT_PRIORITY = [CRACKING, VIOLATIONS, IGNORE].freeze

        # Rule type detection patterns
        PATH_PATTERNS = {
          /ignore\.d/ => IGNORE,
          /cracking\.d/ => CRACKING,
          /violations\.d/ => VIOLATIONS
        }.freeze

        # Detect rule type from file path
        # @param path [String] File or directory path
        # @return [Symbol, nil] Rule type or nil if not detected
        def self.detect_from_path(path)
          PATH_PATTERNS.each do |pattern, type|
            return type if path.match?(pattern)
          end
          nil
        end

        # Validate rule type
        # @param type [Symbol] Rule type to validate
        # @return [Boolean] True if valid rule type
        def self.valid_type?(type)
          ALL_TYPES.include?(type)
        end

        # Get rule type priority (lower number = higher priority)
        # @param type [Symbol] Rule type
        # @return [Integer] Priority value
        def self.priority(type)
          DEFAULT_PRIORITY.index(type) || 999
        end

        # Check if rule type is security-related
        # @param type [Symbol] Rule type
        # @return [Boolean] True for cracking and violations
        def self.security_type?(type)
          [CRACKING, VIOLATIONS].include?(type)
        end
      end
    end
  end
end
