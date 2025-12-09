# typed: false
# frozen_string_literal: true

require_relative "../helper"
require "fluent/plugin/filter_logcheck"
require "tempfile"
require "fileutils"

class ConfigurationValidationTest < Test::Unit::TestCase
  include Fluent::Test::Helpers

  def setup
    Fluent::Test.setup
    @temp_dir = Dir.mktmpdir("logcheck_config_test")
    create_test_files
  end

  def teardown
    FileUtils.rm_rf(@temp_dir) if @temp_dir && Dir.exist?(@temp_dir)
  end

  sub_test_case "rule source validation" do
    test "raises error when no rule sources specified" do
      config = %()

      assert_raise(Fluent::ConfigError) do
        create_driver(config)
      end
    end

    test "accepts rules_file configuration" do
      config = %(
        rules_file #{@test_file}
      )

      assert_nothing_raised do
        create_driver(config)
      end
    end

    test "accepts rules_dir configuration" do
      config = %(
        rules_dir #{@temp_dir}
      )

      assert_nothing_raised do
        create_driver(config)
      end
    end

    test "accepts rules section configuration" do
      config = %(
        <rules>
          path #{@test_file}
          type ignore
        </rules>
      )

      assert_nothing_raised do
        create_driver(config)
      end
    end

    test "validates rules_file exists during initialization" do
      non_existent_file = File.join(@temp_dir, "non_existent.rules")
      config = %(
        rules_file #{non_existent_file}
      )

      # Should not raise during configure, but should log warning
      d = create_driver(config)
      assert_not_nil d.instance
    end

    test "validates rules_dir exists during initialization" do
      non_existent_dir = File.join(@temp_dir, "non_existent_dir")
      config = %(
        rules_dir #{non_existent_dir}
      )

      # Should not raise during configure, but should log warning
      d = create_driver(config)
      assert_not_nil d.instance
    end
  end

  sub_test_case "parameter validation" do
    test "validates cache_size is positive" do
      config = %(
        rules_file #{@test_file}
        cache_size 0
      )

      assert_raise(Fluent::ConfigError) do
        create_driver(config)
      end
    end

    test "validates cache_size negative value" do
      config = %(
        rules_file #{@test_file}
        cache_size -100
      )

      assert_raise(Fluent::ConfigError) do
        create_driver(config)
      end
    end

    test "validates max_rules_per_file is positive" do
      config = %(
        rules_file #{@test_file}
        max_rules_per_file 0
      )

      assert_raise(Fluent::ConfigError) do
        create_driver(config)
      end
    end

    test "validates max_rules_per_file negative value" do
      config = %(
        rules_file #{@test_file}
        max_rules_per_file -50
      )

      assert_raise(Fluent::ConfigError) do
        create_driver(config)
      end
    end

    test "validates match_field is not empty" do
      config = %(
        rules_file #{@test_file}
        match_field ""
      )

      assert_raise(Fluent::ConfigError) do
        create_driver(config)
      end
    end

    test "validates mark_field_prefix is not empty when mark_matches is true" do
      config = %(
        rules_file #{@test_file}
        mark_matches true
        mark_field_prefix ""
      )

      assert_raise(Fluent::ConfigError) do
        create_driver(config)
      end
    end
  end

  sub_test_case "rule_priority validation" do
    test "validates rule_priority contains valid types" do
      config = %(
        rules_file #{@test_file}
        rule_priority ["invalid_type", "cracking"]
      )

      assert_raise(Fluent::ConfigError) do
        create_driver(config)
      end
    end

    test "accepts valid rule_priority" do
      config = %(
        rules_file #{@test_file}
        rule_priority ["cracking", "violations", "ignore"]
      )

      assert_nothing_raised do
        create_driver(config)
      end
    end

    test "validates rule_priority is not empty" do
      config = %(
        rules_file #{@test_file}
        rule_priority []
      )

      assert_raise(Fluent::ConfigError) do
        create_driver(config)
      end
    end

    test "validates rule_priority contains unique values" do
      config = %(
        rules_file #{@test_file}
        rule_priority ["cracking", "cracking", "ignore"]
      )

      assert_raise(Fluent::ConfigError) do
        create_driver(config)
      end
    end
  end

  sub_test_case "rules section validation" do
    test "validates rules section path is specified" do
      config = %(
        <rules>
          type ignore
        </rules>
      )

      assert_raise(Fluent::ConfigError) do
        create_driver(config)
      end
    end

    test "validates rules section path is not empty" do
      config = %(
        <rules>
          path ""
          type ignore
        </rules>
      )

      assert_raise(Fluent::ConfigError) do
        create_driver(config)
      end
    end

    test "validates rules section type is valid" do
      config = %(
        <rules>
          path #{@test_file}
          type invalid_type
        </rules>
      )

      assert_raise(Fluent::ConfigError) do
        create_driver(config)
      end
    end

    test "accepts rules section with valid configuration" do
      config = %(
        <rules>
          path #{@test_file}
          type cracking
          recursive false
        </rules>
      )

      assert_nothing_raised do
        create_driver(config)
      end
    end
  end

  sub_test_case "enum validation" do
    test "validates default_action enum" do
      config = %(
        rules_file #{@test_file}
        default_action invalid_action
      )

      assert_raise(Fluent::ConfigError) do
        create_driver(config)
      end
    end

    test "accepts valid default_action values" do
      %w(keep drop).each do |action|
        config = %(
          rules_file #{@test_file}
          default_action #{action}
        )

        assert_nothing_raised do
          create_driver(config)
        end
      end
    end
  end

  sub_test_case "path validation" do
    test "validates absolute paths" do
      config = %(
        rules_file /absolute/path/to/rules
      )

      # Should not raise during configure (path validation happens during initialization)
      assert_nothing_raised do
        create_driver(config)
      end
    end

    test "validates relative paths" do
      config = %(
        rules_file ./relative/path/to/rules
      )

      # Should not raise during configure (path validation happens during initialization)
      assert_nothing_raised do
        create_driver(config)
      end
    end

    test "handles special characters in paths" do
      special_file = File.join(@temp_dir, "rules with spaces & symbols.txt")
      File.write(special_file, "test.*pattern")

      config = %(
        rules_file "#{special_file}"
      )

      assert_nothing_raised do
        create_driver(config)
      end
    end
  end

  sub_test_case "configuration combinations" do
    test "allows multiple rule sources" do
      config = %(
        rules_file #{@test_file}
        rules_dir #{@temp_dir}
        <rules>
          path #{@test_file}
          type violations
        </rules>
      )

      assert_nothing_raised do
        create_driver(config)
      end
    end

    test "validates consistent configuration" do
      config = %(
        rules_file #{@test_file}
        mark_matches true
        mark_field_prefix "custom_"
        cache_size 500
        max_rules_per_file 100
      )

      d = create_driver(config)
      assert_equal true, d.instance.mark_matches
      assert_equal "custom_", d.instance.mark_field_prefix
      assert_equal 500, d.instance.cache_size
      assert_equal 100, d.instance.max_rules_per_file
    end
  end

  sub_test_case "error handling during initialization" do
    test "handles file permission errors gracefully" do
      # Create a file and make it unreadable (if possible)
      restricted_file = File.join(@temp_dir, "restricted.rules")
      File.write(restricted_file, "test.*pattern")

      begin
        File.chmod(0o000, restricted_file)

        config = %(
          rules_file #{restricted_file}
        )

        # Should not raise, but should log error
        d = create_driver(config)
        assert_not_nil d.instance
      ensure
        begin
          File.chmod(0o644, restricted_file)
        rescue StandardError
          nil
        end
      end
    end

    test "handles malformed rule files gracefully" do
      malformed_file = File.join(@temp_dir, "malformed.rules")
      File.write(malformed_file, "[invalid_regex")

      config = %(
        rules_file #{malformed_file}
      )

      # Should not raise during configure
      d = create_driver(config)
      assert_not_nil d.instance
    end
  end

  private

  def create_driver(conf)
    Fluent::Test::Driver::Filter.new(Fluent::Plugin::LogcheckFilter).configure(conf)
  end

  def create_test_files
    @test_file = File.join(@temp_dir, "test.rules")
    File.write(@test_file, "^test.*pattern$\n^another.*pattern$")

    # Create a test directory with some rule files
    test_subdir = File.join(@temp_dir, "ignore.d.server")
    FileUtils.mkdir_p(test_subdir)
    File.write(File.join(test_subdir, "systemd"), "^.*systemd.*$")
  end
end
