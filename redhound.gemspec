# frozen_string_literal: true

require_relative 'lib/redhound/version'

Gem::Specification.new do |spec|
  spec.name = 'redhound'
  spec.version = Redhound::VERSION
  spec.authors = ['Yudai Takada']
  spec.email = ['t.yudai92@gmail.com']

  spec.summary = 'Pure Ruby packet analyzer'
  spec.description = 'Redhound is a pure Ruby packet analyzer that can be used to capture and analyze network packets.'
  spec.homepage = 'https://github.com/ydah/redhound'
  spec.license = 'MIT'
  spec.required_ruby_version = '>= 3.3'

  spec.metadata['homepage_uri']      = spec.homepage
  spec.metadata['source_code_uri']   = spec.homepage
  spec.metadata['documentation_uri'] = spec.homepage
  spec.metadata['changelog_uri']     = "#{spec.homepage}/releases"
  spec.metadata['bug_tracker_uri']   = "#{spec.homepage}/issues"

  gemspec = File.basename(__FILE__)
  spec.files = IO.popen(%w[git ls-files -z], chdir: __dir__, err: IO::NULL) do |ls|
    ls.readlines("\x0", chomp: true).reject do |f|
      (f == gemspec) ||
        f.start_with?(*%w[bin/ test/ spec/ features/ .git .github appveyor Gemfile])
    end
  end
  spec.bindir = 'exe'
  spec.executables = spec.files.grep(%r{\Aexe/}) { |f| File.basename(f) }
  spec.require_paths = ['lib']
  spec.metadata['rubygems_mfa_required'] = 'true'
end
