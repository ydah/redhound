#!/usr/bin/env ruby
# frozen_string_literal: true

version, path = ARGV
abort 'Usage: script/release-notes.rb VERSION [CHANGELOG]' unless version
sections = File.read(path || File.expand_path('../CHANGELOG.md', __dir__)).split(/^## /)
section = sections.find { |entry| entry.lines.first.to_s.strip.match?(/\A#{Regexp.escape(version)}(?:\s|$)/) }
abort "no changelog entry for #{version}" unless section
notes = section.lines.drop(1).join.strip
abort "no user-facing changes for #{version}" unless notes.match?(/^- \S/)
puts notes
