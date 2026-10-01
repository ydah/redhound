# frozen_string_literal: true

require 'stringio'

RSpec.describe 'captured packet output snapshots' do
  around do |example|
    previous = ENV['TZ']
    ENV['TZ'] = 'UTC'
    example.run
  ensure
    ENV['TZ'] = previous
  end

  %w[network applications].each do |fixture|
    %i[summary tree json hexdump].each do |format|
      it "matches #{fixture} #{format} with fixed timestamps and numeric addresses" do
        io = StringIO.new
        formatter = case format
                    when :summary then Redhound::Output::Summary.new(timestamp: :date, precision: :nano)
                    when :tree then Redhound::Output::Tree.new
                    when :json then Redhound::Output::Json.new
                    when :hexdump then Redhound::Output::Hexdump.new(ascii: true, link_layer: true)
                    end
        path = File.expand_path("../fixtures/pcap/#{fixture}.pcap", __dir__)
        Redhound.open(path) { |reader| reader.each { |packet| formatter.format(packet, io) } }
        formatter.finish(io) if formatter.respond_to?(:finish)
        expect_golden("#{fixture}.#{format}", io.string)
      end
    end
  end
end
