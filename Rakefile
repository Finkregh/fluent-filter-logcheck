# frozen_string_literal: true

require 'bundler/gem_tasks'
require 'rake/testtask'

Rake::TestTask.new(:test) do |test|
  test.libs << 'lib' << 'test'
  test.pattern = 'test/**/test_*.rb'
  test.verbose = true
end

task default: :test

desc 'Run RuboCop'
task :rubocop do
  sh 'rubocop'
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
  Rake::Task[:test].invoke
end

desc 'Clean up temporary files'
task :clean do
  sh 'rm -rf coverage/'
  sh 'rm -rf pkg/'
  sh 'rm -rf tmp/'
end
