# typed: strict
# frozen_string_literal: true

# RBI definitions for Fluentd plugin framework

module Fluent
  class ConfigError < StandardError; end

  module Plugin
    extend T::Sig

    sig { params(type: String, klass: T.class_of(BasicObject)).void }
    def self.register_filter(type, klass); end

    sig { params(type: String).returns(T.untyped) }
    def self.new_filter(type); end

    class Filter
      extend T::Sig

      # Configuration DSL methods
      sig { params(name: Symbol, type: Symbol, opts: T.untyped).void }
      def self.config_param(name, type, **opts); end

      sig { params(name: Symbol, opts: T.untyped, block: T.proc.void).void }
      def self.config_section(name, **opts, &block); end

      sig { params(helpers: Symbol).void }
      def self.helpers(*helpers); end

      # Instance methods
      sig { returns(T.untyped) }
      def log; end

      sig { params(field: String).returns(T.untyped) }
      def record_accessor_create(field); end

      sig { void }
      def start; end

      sig { void }
      def shutdown; end

      sig { params(conf: T.untyped).void }
      def configure(conf); end

      sig { params(tag: String, time: T.untyped, record: T::Hash[String, T.untyped]).returns(T.nilable(T::Hash[String, T.untyped])) }
      def filter(tag, time, record); end
    end
  end
end
