# frozen_string_literal: true

require 'bundler/gem_tasks'
require 'rake/testtask'
require 'rubocop/rake_task'

Rake::TestTask.new(:test) do |test|
  test.libs << 'lib' << 'test'
  test.pattern = 'test/**/test_*.rb'
  test.verbose = true
end

task default: :test

desc 'Run RuboCop on all files'
RuboCop::RakeTask.new(:rubocop) do |task|
  task.patterns = ['lib/**/*.rb', 'test/**/*.rb']
  # don't abort rake on failure
  task.fail_on_error = false
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
