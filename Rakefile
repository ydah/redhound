# frozen_string_literal: true

require 'bundler/gem_tasks'

desc "steep check"
task :steep do
  sh "bundle exec steep check"
end

desc "Run rbs-inline"
task :rbs_inline do
  sh "bundle exec rbs-inline --output lib/"
end

task default: %i[rbs_inline steep]
