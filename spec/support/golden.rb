# frozen_string_literal: true

module Golden
  def expect_golden(name, actual)
    path = File.expand_path("../golden/#{name}.txt", __dir__)
    File.write(path, actual) if ENV['UPDATE_GOLDEN'] == '1'
    expect(File.exist?(path)).to be(true), "missing #{path}; regenerate with UPDATE_GOLDEN=1 bundle exec rspec spec/golden"
    expect(actual).to eq(File.read(path))
  end
end

RSpec.configure { |config| config.include Golden }
