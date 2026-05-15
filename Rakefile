# frozen_string_literal: true

require 'bundler'
require 'bundler/gem_tasks'
require 'rake/testtask'
require 'rubocop/rake_task'
begin
  require 'yard'
rescue LoadError
  nil
end
Bundler::GemHelper.install_tasks

Rake::TestTask.new(:test) do |test|
  test.libs.push('lib', 'test')
  test.pattern = 'test/**/test_*.rb'
  test.verbose = true
  test.warning = true
  # Suppress warnings during test runs
  test.ruby_opts = ['-W0']
end

task default: :test

desc 'Run RuboCop on all files'
RuboCop::RakeTask.new(:rubocop) do |task|
  task.patterns = ['lib/**/*.rb', 'test/**/*.rb']
  task.options = ['--fail-level', 'I']
  task.fail_on_error = true
end

desc 'Run RuboCop on lib directory'
RuboCop::RakeTask.new('rubocop:lib') do |task|
  task.patterns = ['lib/**/*.rb']
  # only show the files with failures
  task.formatters = ['files']
  # don't abort rake on failure
  task.fail_on_error = false
end

desc 'Run RuboCop on test directory'
RuboCop::RakeTask.new('rubocop:test') do |task|
  task.patterns = ['test/**/*.rb']
  # only show the files with failures
  task.formatters = ['files']
  # don't abort rake on failure
  task.fail_on_error = false
end

desc 'Autocorrect RuboCop offenses'
RuboCop::RakeTask.new('rubocop:autocorrect') do |task|
  task.patterns = ['lib/**/*.rb', 'test/**/*.rb']
  task.options = ['--autocorrect']
  task.fail_on_error = false
end

desc 'Run Brakeman security scan'
task :brakeman do
  sh 'brakeman --force'
end

desc 'Run all security checks'
task security: [:brakeman] do
  sh 'bundle audit --update'
end

desc 'Run tests with coverage'
task :coverage do
  ENV['COVERAGE'] = 'true'
  # Suppress warnings during coverage runs too
  ENV['RUBYOPT'] = '-W0'
  Rake::Task[:test].invoke
end

desc 'Run Sorbet type checker'
task :sorbet do
  sh 'bundle exec srb tc'
end

desc 'Clean up temporary files'
task :clean do
  sh 'rm -rf coverage/'
  sh 'rm -rf pkg/'
  sh 'rm -rf tmp/'
end

if defined?(YARD)
  desc 'Run YARD documentation generation'
  task :yard do
    YARD::Rake::YardocTask.new
  end

  desc 'Check YARD documentation coverage'
  task 'yard:stats' do
    sh 'bundle exec yard stats --list-undoc'
  end
end

desc 'Run integration tests'
task :integration do
  sh 'bundle exec ruby -Itest test/integration/test_*.rb'
end

desc 'Run performance benchmarks'
task :performance do
  sh 'bundle exec ruby -Itest test/integration/test_performance_benchmarks.rb'
end

desc 'Check for frozen string literal warnings'
task :frozen_string_check do
  puts 'Checking for frozen string literal warnings...'
  result = `bundle exec ruby -w -c lib/**/*.rb 2>&1 | grep -i "frozen"`
  if result.empty?
    puts '✅ No frozen string literal warnings found in lib/'
  else
    puts '⚠️  Frozen string literal warnings found:'
    puts result
  end
end

desc 'Run all quality checks, linters, and tests'
task :ci do
  puts '🚀 Running comprehensive CI checks...'

  # Track failures but continue running all checks
  failures = []

  # 1. Clean up first
  puts "\n📁 Cleaning up temporary files..."
  begin
    Rake::Task[:clean].invoke
    puts '✅ Cleanup completed'
  rescue StandardError => e
    puts "⚠️  Cleanup warning: #{e.message}"
  end

  # 2. Run tests
  puts "\n🧪 Running test suite..."
  begin
    Rake::Task[:test].invoke
    puts '✅ Tests passed'
  rescue StandardError => e
    failures << 'Tests'
    puts "❌ Tests failed: #{e.message}"
  end

  # 3. Run RuboCop linting
  puts "\n🔍 Running RuboCop linting..."
  begin
    Rake::Task[:rubocop].invoke
    puts '✅ RuboCop checks passed'
  rescue StandardError => e
    failures << 'RuboCop'
    puts "❌ RuboCop failed: #{e.message}"
  end

  # 4. Run Sorbet type checking
  puts "\n🔬 Running Sorbet type checking..."
  begin
    Rake::Task[:sorbet].invoke
    puts '✅ Sorbet type checking passed'
  rescue StandardError => e
    failures << 'Sorbet'
    puts "❌ Sorbet type checking failed: #{e.message}"
  end

  # 5. Run security checks
  puts "\n🔒 Running security analysis..."
  begin
    Rake::Task[:security].invoke
    puts '✅ Security checks passed'
  rescue StandardError => e
    failures << 'Security'
    puts "❌ Security checks failed: #{e.message}"
  end

  # 6. Run coverage analysis
  puts "\n📊 Running test coverage analysis..."
  begin
    Rake::Task[:coverage].invoke
    puts '✅ Coverage analysis completed'
  rescue StandardError => e
    failures << 'Coverage'
    puts "❌ Coverage analysis failed: #{e.message}"
  end

  # 7. Check frozen string literals
  puts "\n❄️  Checking frozen string literals..."
  begin
    Rake::Task[:frozen_string_check].invoke
    puts '✅ Frozen string literal check completed'
  rescue StandardError => e
    failures << 'Frozen String Check'
    puts "❌ Frozen string literal check failed: #{e.message}"
  end

  # 8. Run integration tests
  puts "\n🔗 Running integration tests..."
  begin
    Rake::Task[:integration].invoke
    puts '✅ Integration tests passed'
  rescue StandardError => e
    failures << 'Integration Tests'
    puts "❌ Integration tests failed: #{e.message}"
  end

  # 9. Generate documentation
  puts "\n📚 Generating documentation..."
  begin
    Rake::Task[:yard].invoke
    puts '✅ Documentation generated'
  rescue StandardError => e
    failures << 'Documentation'
    puts "❌ Documentation generation failed: #{e.message}"
  end

  # 10. Check documentation coverage
  puts "\n📋 Checking documentation coverage..."
  begin
    Rake::Task['yard:stats'].invoke
    puts '✅ Documentation coverage check completed'
  rescue StandardError => e
    failures << 'Documentation Coverage'
    puts "❌ Documentation coverage check failed: #{e.message}"
  end

  # Summary
  puts "\n#{'=' * 60}"
  if failures.empty?
    puts '🎉 ALL CHECKS PASSED! Your code is ready for production.'
  else
    puts "❌ #{failures.length} check(s) failed:"
    failures.each { |failure| puts "   • #{failure}" }
    puts "\nPlease fix the issues above before proceeding."
    exit 1
  end
  puts '=' * 60
end

desc 'Run quick checks (tests, linting, type checking)'
task :quick do
  puts '⚡ Running quick quality checks...'

  failures = []

  # Run essential checks only
  puts "\n🧪 Running tests..."
  begin
    Rake::Task[:test].invoke
    puts '✅ Tests passed'
  rescue StandardError => e
    failures << 'Tests'
    puts "❌ Tests failed: #{e.message}"
  end

  puts "\n🔍 Running RuboCop..."
  begin
    Rake::Task[:rubocop].invoke
    puts '✅ RuboCop passed'
  rescue StandardError => e
    failures << 'RuboCop'
    puts "❌ RuboCop failed: #{e.message}"
  end

  puts "\n🔬 Running Sorbet..."
  begin
    Rake::Task[:sorbet].invoke
    puts '✅ Sorbet passed'
  rescue StandardError => e
    failures << 'Sorbet'
    puts "❌ Sorbet failed: #{e.message}"
  end

  # Summary
  puts "\n#{'=' * 40}"
  if failures.empty?
    puts '✅ Quick checks passed!'
  else
    puts "❌ #{failures.length} check(s) failed:"
    failures.each { |failure| puts "   • #{failure}" }
    exit 1
  end
  puts '=' * 40
end
