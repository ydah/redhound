# frozen_string_literal: true

require 'open3'
require 'tempfile'

RSpec.describe 'release notes' do
  it 'extracts only the selected changelog entry and rejects empty releases' do
    Tempfile.create('redhound-changelog') do |file|
      file.write("# Changelog\n\n## Unreleased\n\n## 2.0.0.rc1 - 2026-10-01\n\n- Read pcapng files.\n\n## 1.0.1 - 2025-01-17\n\n- Old change.\n")
      file.flush
      script = File.expand_path('../../script/release-notes.rb', __dir__)
      out, _, status = Open3.capture3(RbConfig.ruby, script, '2.0.0.rc1', file.path)
      expect(status).to be_success
      expect(out).to include('Read pcapng files.')
      expect(out).not_to include('Old change.')
      _, err, status = Open3.capture3(RbConfig.ruby, script, 'Unreleased', file.path)
      expect(status).not_to be_success
      expect(err).to include('no user-facing changes')
    end
  end
end
