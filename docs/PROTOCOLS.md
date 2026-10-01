# Supported protocols

Built-in protocol registry (regenerate with `redhound --list-protocols`):

```text
data: Data
eth: Ethernet eth.dst eth.src eth.type
vlan: 802.1Q VLAN vlan.priority vlan.dei vlan.id vlan.etype
llc: Logical Link Control llc.dsap llc.ssap llc.control
sll: Linux cooked capture sll.pkttype sll.hatype sll.halen sll.src sll.etype
sll2: Linux cooked capture v2 sll.etype sll.reserved sll.ifindex sll.hatype sll.pkttype sll.halen sll.src
null: BSD loopback
raw: Raw IP
arp: Address Resolution Protocol arp.hw.type arp.proto.type arp.hw.size arp.proto.size arp.opcode
ipv4: Internet Protocol v4 ip.version ip.hdr_len ip.dsfield.dscp ip.dsfield.ecn ip.len ip.id ip.flags.rb ip.flags.df ip.flags.mf ip.frag_offset ip.ttl ip.proto ip.checksum ip.src ip.dst
ipv6: Internet Protocol v6 ipv6.version ipv6.tclass ipv6.flow ipv6.plen ipv6.nxt ipv6.hlim ipv6.src ipv6.dst
ipv6_ext: IPv6 extension
udp: User Datagram Protocol udp.srcport udp.dstport udp.length udp.checksum
tcp: Transmission Control Protocol tcp.srcport tcp.dstport tcp.seq tcp.ack tcp.hdr_len tcp.reserved tcp.flags tcp.window_size_value tcp.checksum tcp.urgent_pointer
icmp: Internet Control Message Protocol icmp.type icmp.code icmp.checksum
icmpv6: ICMPv6 / Neighbor Discovery icmpv6.type icmpv6.code icmpv6.checksum
igmp: Internet Group Management Protocol igmp.type igmp.max_resp igmp.checksum
gre: Generic Routing Encapsulation gre.flags gre.proto
vxlan: Virtual eXtensible LAN vxlan.flags vxlan.vni_word
dns: Domain Name System
dhcp: Dynamic Host Configuration Protocol dhcp.type dhcp.hw.type dhcp.hw.len dhcp.hops dhcp.id dhcp.secs dhcp.flags dhcp.ip.client dhcp.ip.your dhcp.ip.server dhcp.ip.relay
ntp: Network Time Protocol ntp.flags.li ntp.flags.vn ntp.flags.mode ntp.stratum ntp.ppoll ntp.precision ntp.rootdelay ntp.rootdispersion ntp.refid ntp.reftime ntp.org ntp.rec ntp.xmt
http: Hypertext Transfer Protocol
tls: Transport Layer Security
```

Variable-length fields, including options, resource records, application headers
and stream analysis, are added while parsing and appear in tree/JSON output.
Unknown protocols produce a Data layer; unsupported encrypted TLS content stays
opaque. HTTP is limited to HTTP/1.x. TLS parsing covers record framing and
ClientHello/ServerHello metadata including SNI, ALPN and supported versions.
DNS includes mDNS/LLMNR and TCP framing. IPv6 supports Hop-by-Hop, Routing,
Fragment, Destination and AH headers; ESP stops dissection. GRE and VXLAN
encapsulations decode inner packet layers.
ICMP identifiers/sequences are emitted for echo, timestamp, and address-mask
messages; fragmentation-needed errors expose `icmp.mtu` instead. IGMP reserved
report bytes are not labeled as maximum-response times. NTP timestamps such as
`ntp.xmt` preserve the unsigned 32.32 wire integer; their era-dependent calendar
interpretation is left to the caller.

Dissectors use checked cursors and parent payload boundaries. Truncation,
malformed lengths, checksum failures and reassembly gaps are available as
structured diagnostics. Checksum verification is enabled by `-v` or
`Engine.new(verify_checksums: true)`; outgoing/offloaded packets are marked
unverified.
IPv6 No Next Header terminates the chain, and the 16-extension limit applies
independently to each encapsulated IPv6 header. Variable wire fields carry source
ranges; [API.md](API.md) describes compression, concatenation, and reassembly
span semantics.
