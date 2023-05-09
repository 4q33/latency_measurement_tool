use clap::Parser;
use pcap_parser::traits::PcapReaderIterator;
use pcap_parser::*;
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::Packet;
use std::collections::HashMap;
use std::fs::File;
use std::net::Ipv4Addr;

#[derive(Parser, Debug)]
#[command(
    about = "Small tool for compare time of identical TCP-packets in pcap-files",
    long_about = r###"Application parses pcap-files:
- inbound = dump of packets which are sent to something
- outbound = dump of packets which are received from something
Identical packets - TCP packets with identical source IP, destination IP, source port, destination port, sequence number and acknoledgement.
Measured latency - difference between timestamp of identical packet in inbound and outbound dumps.
"###
)]

struct Args {
    /// Path for pcap file on inbound interface
    #[arg(name = "PCAP FILE IN")]
    in_interface_pcap_file_path: String,

    /// Path for pcap file on outbound interface
    #[arg(name = "PCAP FILE OUT")]
    out_interface_pcap_file_path: String,
    
    /// Disable output of latency/miss for every packet
    #[arg(short = 'p', long = "disable-printing")]
    disable_printing: bool
}

#[derive(Eq, PartialEq, Hash, Debug)]
struct TcpTupleId {
    ip_src: Ipv4Addr,
    ip_dst: Ipv4Addr,
    port_src: u16,
    port_dst: u16,
    tcp_seq: u32,
    tcp_ack: u32,
}

impl TcpTupleId {
    fn new_from_bytes(bytes: &[u8]) -> Option<Self> {
        let l2 = EthernetPacket::new(bytes)?;
        let l3 = Ipv4Packet::new(l2.payload())?;
        let l4 = TcpPacket::new(l3.payload())?;
        let ip_src = l3.get_source();
        let ip_dst = l3.get_destination();
        let tcp_seq = l4.get_sequence();
        let tcp_ack = l4.get_acknowledgement();
        let port_src = l4.get_source();
        let port_dst = l4.get_destination();
        Some(Self {
            ip_src,
            ip_dst,
            port_src,
            port_dst,
            tcp_seq,
            tcp_ack,
        })
    }
}

#[derive(Eq, PartialEq, Hash, Debug)]
struct PacketTime {
    sec: u32,
    usec: u32,
}

impl PacketTime {
    fn diff(t1: Self, t2: Self) -> i64 {
        t1.sec as i64 * 1_000_000 + t1.usec as i64 - t2.sec as i64 * 1_000_000 - t2.usec as i64
    }
}

struct PcapReader {
    reader: LegacyPcapReader<File>,
}

impl PcapReader {
    fn new_from_path(file_path: &str) -> Self {
        let file = File::open(file_path).expect("Error opening file");
        let reader = LegacyPcapReader::new(1 * 1024 * 1024, file).expect("LegacyPcapReader");
        Self { reader }
    }
}

impl Iterator for PcapReader {
    type Item = (TcpTupleId, PacketTime);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let mut tuple_id: Option<TcpTupleId> = None;
            let mut time: PacketTime = PacketTime { sec: 0, usec: 0 };
            match self.reader.next() {
                Ok((offset, block)) => {
                    match block {
                        PcapBlockOwned::LegacyHeader(_hdr) => {}
                        PcapBlockOwned::Legacy(_b) => {
                            tuple_id = TcpTupleId::new_from_bytes(_b.data);
                            time = PacketTime {
                                sec: _b.ts_sec,
                                usec: _b.ts_usec,
                            };
                        }
                        PcapBlockOwned::NG(_) => unreachable!(),
                    }
                    self.reader.consume(offset);
                    match tuple_id {
                        Some(tuple_id) => return Some((tuple_id, time)),
                        None => continue,
                    }
                }
                Err(PcapError::Eof) => return None,
                Err(PcapError::Incomplete) => {
                    self.reader.refill().unwrap();
                }
                Err(e) => panic!("Error while reading: {:?}", e),
            }
        }
    }
}

fn main() {
    let args = Args::parse();

    let out_interface_reader = PcapReader::new_from_path(&args.out_interface_pcap_file_path);
    let mut out_interface_table: HashMap<TcpTupleId, PacketTime> = HashMap::new();
    for (tuple_id, packet_time) in out_interface_reader.into_iter() {
        out_interface_table.insert(tuple_id, packet_time);
    }

    let in_interface_reader = PcapReader::new_from_path(&args.in_interface_pcap_file_path);

    let mut latency_sum: i64 = 0;
    let mut latency_min: i64 = i64::MAX;
    let mut latency_max: i64 = 0;
    let mut latency_hit_count: i64 = 0;
    let mut miss_count: u64 = 0;
    let mut in_interface_packet_count: u64 = 0;
    for (tuple_id, packet_time) in in_interface_reader.into_iter() {
        in_interface_packet_count += 1;
        if let Some(out_interface_time) = out_interface_table.remove(&tuple_id) {
            let latency = PacketTime::diff(out_interface_time, packet_time);
            if !args.disable_printing { println!("{}", latency) };
            latency_sum += latency.abs();
            latency_hit_count += 1;
            if latency.abs() < latency_min {
                latency_min = latency
            }
            if latency.abs() > latency_max {
                latency_max = latency
            }
            
        } else {
            miss_count += 1;
            if !args.disable_printing { println!("miss") }
        }
    }
    println!(
        "Average latency (usec): {}. Jitter (usec): {}. Packets count: {}. Misses count: {} ({}%)",
        latency_sum / latency_hit_count,
        latency_max - latency_min,
        in_interface_packet_count,
        miss_count,
        miss_count as f64 / in_interface_packet_count as f64 * 100f64
    );
}