# frozen_string_literal: true

require 'bundler/gem_tasks'
require 'rspec/core/rake_task'

RSpec::Core::RakeTask.new(:spec)

desc 'steep check'
task :steep do
  sh 'bundle exec steep check'
end

desc 'Run rbs-inline'
task :rbs_inline do
  sh 'bundle exec rbs-inline --output lib/'
end

task default: %i[spec rbs_inline steep]
