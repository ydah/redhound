# frozen_string_literal: true

require 'simplecov'
SimpleCov.start do
  add_filter '/spec/'
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
