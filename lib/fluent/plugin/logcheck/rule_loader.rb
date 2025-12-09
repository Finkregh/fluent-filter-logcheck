# typed: strict
# frozen_string_literal: true

require "sorbet-runtime"
require_relative "rule_types"
require_relative "rule"

module Fluent
  module Plugin
    module Logcheck
      # RuleLoader handles loading and parsing logcheck rule files
      class RuleLoader
        extend T::Sig

        # Custom exceptions
        class FileNotFoundError < StandardError; end
        class ParseError < StandardError; end

        sig { params(logger: T.nilable(T.untyped)).void }

        def initialize(logger: nil)
          @logger = T.let(logger, T.nilable(T.untyped))
        end

        # Load rules from a single file
        # @param file_path [String] Path to the rule file
        # @param rule_type [Symbol] Type of rules (:ignore, :cracking, :violations)
        # @param max_rules [Integer] Maximum number of rules to load from file
        # @return [RuleSet] Loaded rule set
        sig { params(file_path: String, rule_type: T.nilable(Symbol), max_rules: T.nilable(Integer)).returns(RuleSet) }

        def load_file(file_path, rule_type, max_rules: nil)
          raise FileNotFoundError, "File not found: #{file_path}" unless File.exist?(file_path)

          # Auto-detect rule type if not provided
          rule_type = detect_rule_type(file_path) if rule_type.nil?
          raise ParseError, "Could not detect rule type for file: #{file_path}" if rule_type.nil?

          log_info "Loading rules from file: #{file_path} (type: #{rule_type})"

          rules = T.let([], T::Array[Rule])
          line_number = 0

          File.foreach(file_path, encoding: "UTF-8") do |line|
            line_number += 1

            # Skip if we've reached the maximum rules limit
            break if max_rules && rules.size >= max_rules

            # Clean and validate line
            cleaned_line = clean_line(line)
            next if cleaned_line.empty?

            # Try to create a rule from the line
            begin
              rule = Rule.new(cleaned_line, T.must(rule_type), file_path, line_number)
              # Test pattern compilation immediately to catch invalid regex
              rule.pattern
              rules << rule
            rescue PatternCompileError => e
              log_warning "Invalid regex pattern at #{file_path}:#{line_number}: #{e.message}"
              # Continue processing other lines
            end
          end

          log_info "Loaded #{rules.size} rules from #{file_path}"
          rule_set = RuleSet.new(T.must(rule_type), file_path)
          rules.each { |rule| rule_set.add_rule(rule) }
          rule_set
        rescue Encoding::InvalidByteSequenceError, Encoding::UndefinedConversionError => e
          log_error "Encoding error reading file #{file_path}: #{e.message}"
          RuleSet.new(T.must(rule_type), file_path)
        end

        # Load rules from a directory
        # @param dir_path [String] Path to the directory
        # @param rule_type [Symbol, nil] Type of rules, or nil for auto-detection
        # @param recursive [Boolean] Whether to scan recursively
        # @param max_rules [Integer] Maximum number of rules per file
        # @return [Array<RuleSet>] Array of loaded rule sets
        sig do
          params(dir_path: String, rule_type: T.nilable(Symbol), recursive: T::Boolean,
                 max_rules: T.nilable(Integer)).returns(T::Array[RuleSet])
        end

        def load_directory(dir_path, rule_type, recursive: true, max_rules: nil)
          raise FileNotFoundError, "Directory not found: #{dir_path}" unless Dir.exist?(dir_path)

          log_info "Loading rules from directory: #{dir_path} (recursive: #{recursive})"

          rule_sets = T.let([], T::Array[RuleSet])
          pattern = recursive ? File.join(dir_path, "**", "*") : File.join(dir_path, "*")

          Dir.glob(pattern).each do |file_path|
            next unless File.file?(file_path)
            next if should_skip_file?(file_path)

            # Determine rule type
            detected_type = rule_type || detect_rule_type(file_path)
            next unless detected_type

            begin
              rule_set = load_file(file_path, detected_type, max_rules: max_rules)
              rule_sets << rule_set unless rule_set.empty?
            rescue FileNotFoundError, ParseError => e
              log_error "Error loading file #{file_path}: #{e.message}"
              # Continue with other files
            end
          end

          log_info "Loaded #{rule_sets.size} rule sets from directory #{dir_path}"
          rule_sets
        end

        private

        # Clean a line by removing comments and whitespace
        # @param line [String] Raw line from file
        # @return [String] Cleaned line
        sig { params(line: String).returns(String) }

        def clean_line(line)
          # Remove comments (lines starting with #)
          line = line.sub(/#.*$/, "")
          # Remove leading and trailing whitespace
          line.strip
        end

        # Detect rule type from file path
        # @param file_path [String] Path to the file
        # @return [Symbol, nil] Detected rule type or nil
        sig { params(file_path: String).returns(T.nilable(Symbol)) }

        def detect_rule_type(file_path)
          RuleTypes.detect_from_path(file_path)
        end

        # Check if a file should be skipped
        # @param file_path [String] Path to the file
        # @return [Boolean] True if file should be skipped
        sig { params(file_path: String).returns(T::Boolean) }

        def should_skip_file?(file_path)
          filename = File.basename(file_path)

          # Skip hidden files, backup files, and common non-rule files
          return true if filename.start_with?(".")
          return true if filename.end_with?("~", ".bak", ".orig", ".tmp")
          return true if filename.match?(/\.(log|txt|md|yml|yaml|json|xml)$/i)

          false
        end

        # Logging helpers
        sig { params(message: String).void }

        def log_info(message)
          @logger&.info(message)
        end

        sig { params(message: String).void }

        def log_warning(message)
          @logger&.warn(message)
        end

        sig { params(message: String).void }

        def log_error(message)
          @logger&.error(message)
        end
      end
    end
  end
end
