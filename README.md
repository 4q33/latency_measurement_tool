# Latency measurement tool
Small application for measuring latency of network packets by comparing time of packets in pcap files.

According to RFC 1242:
```
Latency = < timestamp of packet in pcap file 1 > minus < timestamp of identical packet in pcap file 2 >
```

Identical packets = TCP packets with identical source IP, destination IP, source port, destination port, sequence number, acknoledgement number. 

## Limitations

- Supports only TCP-packets
- Works only with old pcap (not pcapng) files

## Usage example

### Testing scheme

```
       ┌──────────────────────┐
   if1 │                      │ if2
     ┌─┤         DUT          ├─┐
┌────┤ │ (device under test)  │ ├────┐
│    └─┤                      ├─┘    │
│      │                      │      │
│      └──────────────────────┘      │
│                                    │                        ┼
│                                    │
│      ┌──────────────────────┐      │
│  if1 │                      │ if2  │
│    ┌─┤                      ├─┐    │
└────┤ │  Measurement device  │ ├────┘
     └─┤                      ├─┘
       │                      │
       └──────────────────────┘
```
### Commands to write traffic

Emulate tcp connection on measurement device with netcat.

Start traffic collection on both interfaces with filter "TCP packets, flags ACK and PSH (payload of netcat)"

```
$ tcpdump -i <if1> -w <pcap-1> 'tcp[13]=24' & ; tcpdump -i <if2> -w <pcap-2> 'tcp[13]=24'&
```

Stop collecting traffic:

```
$ killall tcpdump
```

### Start analysis

```
$ ./latency_measurement_tool <pcap-1> <pcap-2>
```
