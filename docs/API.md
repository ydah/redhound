# Ruby API

```ruby
require 'redhound'

Redhound.open('trace.pcapng', filter: 'tcp port 443') do |reader|
  reader.each do |packet|
    puts packet.summary
    puts packet['ip.src']
    p packet[:tcp]&.values
    p packet.to_h
  end
end

Redhound.capture(interface: 'lo', count: 10, filter: 'udp') do |packet|
  puts packet.summary
end

packet = Redhound.dissect(frame_bytes, linktype: :ethernet,
                         timestamp_ns: 1_700_000_000_123_456_789)
Redhound::Writer.open('copy.pcapng') { |writer| writer << packet }
```

`Redhound.open` accepts a path, `-`, or a binary IO. Reader is Enumerable,
provides `next_packet`, `stats`, `interfaces`, `stop`, and `close`; a block always
closes it. `Redhound.capture` yields packets and closes the live source even if
the block fails. Capture options include `snaplen`, `promiscuous`, `buffer_size`
(bytes), `direction` (`:in`, `:out`, `:inout`), `backend`, and `filter`.

`next_packet(timeout:)` returns nil at its deadline without discarding a partial
stdin/pipe record. `stop` interrupts a waiting read. `attach_filter(program)`
replaces a source's capture filter; filtering preserves the original wire length.
For pcapng input, retained interface metadata is limited to 4,096 interfaces and
16 MiB across sections, with at most 4,096 options in a block. Excess input raises
`FileFormatError` rather than growing memory without a bound.

`Redhound.dissect` creates an immutable-byte Packet and decodes its layers lazily.
Packet metadata includes `timestamp_ns`, `original_length`, `linktype`,
`interface`, `direction`, and `number`. `caplen`, `truncated?`, and `time` expose
capture properties. A symbol index selects the first Layer; a dotted string
selects a decoded field value. `layers_of`, `innermost`, and `field_values` expose
repeated or tunneled layers. Layer has `values`, `fields`, and `diagnostics`.
`to_h` follows [json-schema.json](json-schema.json); bytes use hexadecimal strings,
addresses use text, booleans remain booleans, repeated fields become arrays.
`timestamp_ns` must be an Integer; calendar output preserves expanded years
outside 0000..9999. `number` is positive, `direction` is `:in`, `:out`, or nil,
and integer link types are restricted to 0..65535. Invalid UTF-8 field text,
interface names, and diagnostic text use hexadecimal strings without discarding
their original bytes.

Each Field exposes its `name`, `type`, `value`, `raw_value`, `offset`, and
`length`. For packet dissection, offsets are absolute captured byte positions;
lengths describe the encoded source span. Complete fixed fields remain available
when the rest of a header or its options are truncated. Derived values such as
`tcp.len`, `data.len`, and `igmp.version` have zero source length. DNS compressed
names refer to their encoded name/pointer span. Concatenated DHCP values and TLS
handshakes crossing records span the first through last source byte, including
intervening TLV/record headers; decoded values need not equal a direct byte slice.
Likewise, chunked HTTP body spans include chunk framing. Stream-reassembled
application fields use offsets in the logical PDU rather than the completing
packet's `data`; `tcp.reassembled_from` identifies the contributing frames.

Writer accepts `format: :pcap|:pcapng`, `linktype`, `snaplen`, `precision`,
`packet_buffered`, `max_bytes`, `interval`, `file_count`, and
`post_rotate_command`. `write`/`<<`, `flush`, `write_stats`, and `close` are
available. Use a block for deterministic closure.

## Custom dissectors

```ruby
class Example < Redhound::Dissector
  protocol :example, name: 'Example protocol', short: 'EXAMPLE'
  dissects_on 'udp.port', 9999
  header do
    uint16 :message_id, 'example.id'
    uint8 :kind, 'example.kind'
  end

  def summary(layer)
    "Example id #{layer[:message_id]}"
  end
end
```

Header fields support unsigned integers, signed `int8`, MAC/IPv4/IPv6 addresses
and bit fields.
Use `dissect(ctx, layer)` for bounded variable-length parsing through
`ctx.cursor`; append fields with `layer.add`. `next_dissector(ctx, layer)` returns
a registered dissector class, or nil. Child cursors cannot escape their packet
bounds. Truncated input creates a diagnostic. `REDHOUND_STRICT=1` re-raises
unexpected implementation errors for tests. Ordinary malformed input remains
safe. Registry copies allow per-session decode-as rules without changing global
registrations.

`Analysis::Session#update(packet)` adds flow/stream analysis and completed
application PDUs. It provides bounded flow/reassembly state and `snapshot`,
`finish`; library users opt into it explicitly. Reassembly does not modify the
packet's captured bytes. `Filter.compile(expression, linktype:)` returns a
validated cBPF Program with `match?`, `evaluate`, `serialize`, and `disassemble`.

Generate reference documentation with `bundle exec yard doc lib/**/*.rb`.
