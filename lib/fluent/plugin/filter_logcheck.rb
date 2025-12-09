# typed: strict
# frozen_string_literal: true

require 'fluent/plugin/filter'
require 'sorbet-runtime'
require_relative 'logcheck/rule_types'
require_relative 'logcheck/rule'
require_relative 'logcheck/rule_loader'
require_relative 'logcheck/rule_engine'
require_relative 'logcheck/filter_decision'

module Fluent
  module Plugin
    # Fluentd filter plugin that applies logcheck rules for log filtering
    class LogcheckFilter < Filter
      extend T::Sig

      Fluent::Plugin.register_filter('logcheck', self)

      helpers :record_accessor

      # Configuration parameters
      config_param :match_field, :string, default: 'message'
      config_param :default_action, :enum, list: %i(keep drop), default: :keep
      config_param :mark_matches, :bool, default: false
      config_param :mark_field_prefix, :string, default: 'logcheck_'
      config_param :cache_size, :integer, default: 1000
      config_param :recursive_scan, :bool, default: true
      config_param :ignore_parse_errors, :bool, default: true
      config_param :log_rule_errors, :bool, default: true
      config_param :max_rules_per_file, :integer, default: 1000
      config_param :debug_mode, :bool, default: false
      config_param :log_statistics, :bool, default: false
      config_param :statistics_interval, :integer, default: 300

      # Simple rule source configuration
      config_param :rules_file, :string, default: nil
      config_param :rules_dir, :string, default: nil

      # Advanced rule configuration
      config_section :rules, param_name: :rule_configs, multi: true do
        config_param :path, :string
        config_param :type, :enum, list: %i(ignore cracking violations), default: nil
        config_param :recursive, :bool, default: true
      end

      # Rule priority configuration
      config_param :rule_priority, :array, default: %i(cracking violations ignore)

      sig { void }
      def initialize
        super
        @rule_sets = T.let({}, T::Hash[String, T.untyped])
        @rule_engine = T.let(nil, T.nilable(T.untyped))
        @filter_decision = T.let(nil, T.nilable(T.untyped))
        @match_accessor = T.let(nil, T.nilable(T.untyped))
        @statistics = T.let({
                              processed: 0,
                              ignored: 0,
                              alerted: 0,
                              passed: 0,
                              errors: 0,
                              start_time: nil
                            }, T::Hash[Symbol, T.untyped])
        @last_stats_log = T.let(nil, T.nilable(Time))
      end

      sig { params(conf: T.untyped).void }
      def configure(conf)
        super

        # Validate configuration
        validate_configuration

        # Create record accessor for match field
        @match_accessor = record_accessor_create(@match_field)

        # Initialize components (will be implemented later)
        initialize_components
      end

      sig { void }
      def start
        super
        @statistics[:start_time] = Time.now
        @last_stats_log = Time.now

        log.info "Logcheck filter started with #{total_rules} rules"
        log.info "Configuration: match_field=#{@match_field}, default_action=#{@default_action}, mark_matches=#{@mark_matches}"
        log.info "Debug mode: #{@debug_mode ? 'enabled' : 'disabled'}"
        log.info "Statistics logging: #{@log_statistics ? "enabled (interval: #{@statistics_interval}s)" : 'disabled'}"

        return unless @debug_mode

        log_rule_summary
      end

      sig { void }
      def shutdown
        super
        log_final_statistics
        log.info 'Logcheck filter stopped'
      end

      sig { params(_tag: String, _time: T.untyped, record: T::Hash[String, T.untyped]).returns(T.nilable(T::Hash[String, T.untyped])) }
      def filter(_tag, _time, record)
        @statistics[:processed] += 1

        # Extract text to match
        text = extract_match_text(record)
        if text.nil? || text.empty?
          log.debug "No text found in field '#{@match_field}', passing record" if @debug_mode
          @statistics[:passed] += 1
          log_periodic_statistics
          return record
        end

        log.debug "Processing message: #{text[0..100]}#{'...' if text.length > 100}" if @debug_mode

        # Make filtering decision
        decision = make_filter_decision(text)

        log.debug "Filter decision: #{decision.decision} (#{decision.description})" if @debug_mode

        # Apply decision
        result = apply_decision(record, decision)

        # Update statistics
        case decision.decision
        when Logcheck::FilterDecision::IGNORE
          @statistics[:ignored] += 1
        when Logcheck::FilterDecision::ALERT
          @statistics[:alerted] += 1
        when Logcheck::FilterDecision::PASS
          @statistics[:passed] += 1
        end

        log_periodic_statistics
        result
      rescue StandardError => e
        @statistics[:errors] += 1
        log.error "Error processing record: #{e.message}"
        log.error_backtrace e.backtrace if @debug_mode
        log_periodic_statistics
        record # Return original record on error
      end

      private

      def validate_configuration
        # Check that at least one rule source is specified
        if @rules_file.nil? && @rules_dir.nil? && @rule_configs.empty?
          raise Fluent::ConfigError,
                'At least one rule source must be specified (rules_file, rules_dir, or rules section)'
        end

        # Validate match_field is not empty
        raise Fluent::ConfigError, 'match_field cannot be empty' if @match_field.nil? || @match_field.strip.empty?

        # Validate mark_field_prefix when mark_matches is enabled
        raise Fluent::ConfigError, 'mark_field_prefix cannot be empty when mark_matches is true' if @mark_matches && (@mark_field_prefix.nil? || @mark_field_prefix.strip.empty?)

        # Convert rule priority to symbols and validate
        @rule_priority = @rule_priority.map(&:to_sym)

        # Validate rule_priority is not empty
        raise Fluent::ConfigError, 'rule_priority cannot be empty' if @rule_priority.empty?

        # Validate rule_priority contains unique values
        raise Fluent::ConfigError, 'rule_priority must contain unique values' if @rule_priority.uniq.size != @rule_priority.size

        # Validate rule_priority contains only valid types
        invalid_types = @rule_priority - Logcheck::RuleTypes::ALL_TYPES
        raise Fluent::ConfigError, "Invalid rule types in rule_priority: #{invalid_types.join(', ')}" unless invalid_types.empty?

        # Validate cache size
        raise Fluent::ConfigError, 'cache_size must be positive' if @cache_size <= 0

        # Validate max rules per file
        raise Fluent::ConfigError, 'max_rules_per_file must be positive' if @max_rules_per_file <= 0

        # Validate rules section configurations
        validate_rules_sections
      end

      def validate_rules_sections
        @rule_configs.each_with_index do |rule_config, index|
          # Validate path is specified and not empty
          raise Fluent::ConfigError, "rules section #{index + 1}: path cannot be empty" if rule_config.path.nil? || rule_config.path.strip.empty?

          # Validate type if specified
          if rule_config.type && !Logcheck::RuleTypes::ALL_TYPES.include?(rule_config.type)
            raise Fluent::ConfigError,
                  "rules section #{index + 1}: invalid type '#{rule_config.type}'. Valid types: #{Logcheck::RuleTypes::ALL_TYPES.join(', ')}"
          end
        end
      end

      def initialize_components
        log.info 'Initializing logcheck components...'

        # Initialize rule loader
        rule_loader = Logcheck::RuleLoader.new(logger: log)
        @rule_sets = {}

        # Load rules from simple file/directory sources
        load_simple_rule_sources(rule_loader)

        # Load rules from advanced rule configurations
        load_advanced_rule_sources(rule_loader)

        total_rule_count = total_rules
        log.info "Loaded #{total_rule_count} rules from #{@rule_sets.size} rule sets"

        log.warn 'No rules loaded! Check your configuration and rule file paths.' if @debug_mode && total_rule_count.zero?

        # Initialize RuleEngine with loaded rule sets
        @rule_engine = Logcheck::RuleEngine.new(logger: log)
        @rule_engine.add_rule_sets(@rule_sets.values)

        log.debug "RuleEngine initialized with #{@rule_sets.size} rule sets" if @debug_mode
      end

      def load_simple_rule_sources(rule_loader)
        # Load from rules_file
        if @rules_file
          log.debug "Loading rules from file: #{@rules_file}" if @debug_mode
          begin
            rule_set = rule_loader.load_file(@rules_file, :ignore, max_rules: @max_rules_per_file)
            @rule_sets[@rules_file] = rule_set
            log.info "Loaded #{rule_set.size} rules from file: #{@rules_file}"
          rescue Logcheck::RuleLoader::FileNotFoundError => e
            log.warn "Rules file not found: #{e.message}"
          rescue StandardError => e
            log.error "Error loading rules file #{@rules_file}: #{e.message}"
            log.error_backtrace e.backtrace if @debug_mode
          end
        end

        # Load from rules_dir
        return unless @rules_dir

        log.debug "Loading rules from directory: #{@rules_dir} (recursive: #{@recursive_scan})" if @debug_mode
        begin
          rule_sets = rule_loader.load_directory(@rules_dir, nil,
                                                 recursive: @recursive_scan,
                                                 max_rules: @max_rules_per_file)
          rule_sets.each do |rule_set|
            @rule_sets[rule_set.source_path] = rule_set
            log.debug "Loaded #{rule_set.size} rules from: #{rule_set.source_path}" if @debug_mode
          end
          log.info "Loaded #{rule_sets.sum(&:size)} rules from #{rule_sets.size} files in directory: #{@rules_dir}"
        rescue Logcheck::RuleLoader::FileNotFoundError => e
          log.warn "Rules directory not found: #{e.message}"
        rescue StandardError => e
          log.error "Error loading rules directory #{@rules_dir}: #{e.message}"
          log.error_backtrace e.backtrace if @debug_mode
        end
      end

      def load_advanced_rule_sources(rule_loader)
        @rule_configs.each_with_index do |rule_config, index|
          path = rule_config.path
          type = rule_config.type
          recursive = rule_config.recursive

          log.debug "Loading advanced rule source #{index + 1}: #{path} (type: #{type || 'auto'}, recursive: #{recursive})" if @debug_mode

          begin
            if File.file?(path)
              rule_set = rule_loader.load_file(path, type, max_rules: @max_rules_per_file)
              @rule_sets[path] = rule_set
              log.info "Loaded #{rule_set.size} rules from file: #{path} (type: #{rule_set.type})"
            elsif File.directory?(path)
              rule_sets = rule_loader.load_directory(path, type,
                                                     recursive: recursive,
                                                     max_rules: @max_rules_per_file)
              rule_sets.each do |rule_set|
                @rule_sets[rule_set.source_path] = rule_set
                log.debug "Loaded #{rule_set.size} rules from: #{rule_set.source_path} (type: #{rule_set.type})" if @debug_mode
              end
              log.info "Loaded #{rule_sets.sum(&:size)} rules from #{rule_sets.size} files in directory: #{path}"
            else
              log.warn "Rule source not found: #{path}"
            end
          rescue StandardError => e
            log.error "Error loading rule source #{path}: #{e.message}"
            log.error_backtrace e.backtrace if @debug_mode
          end
        end
      end

      def extract_match_text(record)
        @match_accessor.call(record)&.to_s
      end

      def make_filter_decision(text)
        # Use RuleEngine to make filtering decision
        @rule_engine.filter(text)
      end

      def apply_decision(record, decision)
        case decision.decision
        when Logcheck::FilterDecision::IGNORE
          # Drop the record
          if @log_rule_errors || @debug_mode
            log.debug "Ignoring message: #{decision.description}"
            log.debug "  Rule: #{decision.rule.raw_pattern}" if @debug_mode && decision.rule
            log.debug "  Source: #{decision.rule.source_file}" if @debug_mode && decision.rule
          end
          nil
        when Logcheck::FilterDecision::ALERT
          # Keep record and add alert metadata if marking is enabled
          if @log_rule_errors
            log.info "Alert: #{decision.description}"
            if @debug_mode && decision.rule
              log.debug "  Rule: #{decision.rule.raw_pattern}"
              log.debug "  Source: #{decision.rule.source_file}"
            end
          end
          if @mark_matches
            record["#{@mark_field_prefix}alert"] = true
            record["#{@mark_field_prefix}rule_type"] = decision.rule_type.to_s
            record["#{@mark_field_prefix}pattern"] = decision.rule.raw_pattern if decision.rule
            record["#{@mark_field_prefix}source"] = decision.rule.source_file if decision.rule
          end
          record
        when Logcheck::FilterDecision::PASS
          # Keep record unchanged
          log.debug "Passing message: #{decision.description}" if (@log_rule_errors || @debug_mode) && @debug_mode
          record
        else
          # Unknown decision - apply default action
          log.warn "Unknown filter decision: #{decision.decision}"
          case @default_action
          when :drop
            nil
          when :keep
            record
          else
            record
          end
        end
      end

      def log_rule_summary
        log.info '=== Rule Summary ==='
        @rule_sets.each do |source, rule_set|
          log.info "  #{source}: #{rule_set.size} rules (type: #{rule_set.type})"
        end

        rule_counts = @rule_sets.values.group_by(&:type).transform_values { |sets| sets.sum(&:size) }
        log.info "Rule counts by type: #{rule_counts}"
        log.info "Rule priority order: #{@rule_priority}"
        log.info '==================='
      end

      def log_periodic_statistics
        return unless @log_statistics
        return unless Time.now - @last_stats_log >= @statistics_interval

        log_current_statistics
        @last_stats_log = Time.now
      end

      def log_current_statistics
        uptime = Time.now - @statistics[:start_time]
        rate = @statistics[:processed] / uptime if uptime.positive?

        log.info '=== Logcheck Statistics ==='
        log.info "  Uptime: #{uptime.round(1)}s"
        log.info "  Processed: #{@statistics[:processed]} (#{rate&.round(2) || 0}/s)"
        log.info "  Ignored: #{@statistics[:ignored]}"
        log.info "  Alerted: #{@statistics[:alerted]}"
        log.info "  Passed: #{@statistics[:passed]}"
        log.info "  Errors: #{@statistics[:errors]}"
        log.info '=========================='
      end

      def log_final_statistics
        return unless @log_statistics || @debug_mode

        log.info '=== Final Logcheck Statistics ==='
        log_current_statistics

        return unless @rule_engine

        engine_stats = @rule_engine.statistics
        log.info "Rule engine statistics: #{engine_stats}"
      end

      def total_rules
        @rule_sets.values.sum(&:size)
      end
    end
  end
end
