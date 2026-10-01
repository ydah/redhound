# frozen_string_literal: true

require 'simplecov'
SimpleCov.start do
  add_filter '/spec/'
  add_group 'Protocols', 'lib/redhound/protocols'
  minimum_coverage 90 if ENV['REDHOUND_COVERAGE_GATE'] == '1'
end
SimpleCov.at_exit do
  SimpleCov.result.format!
  if ENV['REDHOUND_COVERAGE_GATE'] == '1' && SimpleCov.result.groups.fetch('Protocols').covered_percent < 95
    abort 'Protocol line coverage is below 95%'
  end
end

require 'redhound'
Dir[File.join(__dir__, 'support/**/*.rb')].each { |f| require f }

RSpec.configure do |config|
  config.include PacketFactory
  config.disable_monkey_patching!
  config.order = :random
  Kernel.srand config.seed
  # ライブキャプチャのテストは root (または CAP_NET_RAW) が必要なので明示した時だけ動かす
  config.filter_run_excluding :live unless ENV['REDHOUND_LIVE']
end
