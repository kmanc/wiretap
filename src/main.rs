use std::net::Ipv4Addr;
use std::process::Command;
use wiretap::{self, Packet, TcpSegmentCollection};

/*
fn main() {
    // Create a new PacketCapture with the "lo" interface
    let pc = wiretap::PacketCapture::new("lo").unwrap();
    // Start a capture on that interface
    let pc = pc.start_capture();
    // Do something useful, probably
    thread::sleep(time::Duration::from_secs(15));
    // Stop the capture
    let pc = pc.stop_capture();
    // Get the resulting TCP packets
    let output = pc.results_as_tcp(); //.into_iter().filter(|p| !p.is_syn() && !p.is_rst_ack()).collect::<Vec<TcpSegment>>();
                                      // Do something with them
    println!("Captured {} TCP packets", output.len());
    for out in output.into_iter() {
        println!("{:?}", out.payload());
        println!("{:?}", out.is_syn());
        println!("{:?}", out.is_rst_ack());
    }
}
*/

fn main() {
    // Create a new PacketCapture with the "lo" interface
    let pc = wiretap::PacketCapture::new("ens33").unwrap();
    // Start a capture on that interface
    let pc = pc.start_capture();
    // Do something useful, probably
    run_nmap();
    // Stop the capture
    let pc = pc.stop_capture();
    // Get the resulting TCP packets
    let output = pc.results_as_ipv4();
    // Do something with them
    println!("Captured {} IPV4 packets", output.len());
    let to_from_target = output.filter_only_host(Ipv4Addr::new(192, 168, 4, 23));
    println!("IPv4 packets from target: {}", to_from_target.len());
    let tcp_now = TcpSegmentCollection::from(to_from_target);
    println!("TCP segments from target: {}", tcp_now.len());
    let mut non_empty = tcp_now.filter_no_payload();
    println!("Not empty TCP segments: {}", non_empty.len());
    let (m, u) = non_empty.find_challenge_response_pairs();
    println!("Matched (pairs): {} Unmatched: {}", m.len(), u.len());
    for pair in m.iter() {
        println!("{}", pair.response.get_source());
        println!("\t{:?}", pair.challenge.payload());
        println!("\t{:?}", pair.response.payload());
    }
    for other in u.iter() {
        println!("{} --> {:?}", other.get_destination(), other.payload());
    }
}

fn run_nmap() {
    Command::new("nmap")
        .args([
            "-sV",
            "-p139",
            "192.168.4.23",
            "-w",
            "/home/dev/deception_rust/tcpdumped.pcap",
        ])
        .output()
        .unwrap();
}
