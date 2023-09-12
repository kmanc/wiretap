//! # wiretap
//!
//! `wiretap` wraps lower level networking and concurency libraries to make packet capture easier in Rust programs
//!
//! ## Examples
//!
//! ### Capture-then-process
//!
//! This basic example shows how to capture packets and later do something with the TCP ones
//!
//! ```rust,ignore
//! use wiretap;
//! use std::{thread, time};
//!
//! fn main() {
//!     // Create a new PacketCapture with the "lo" interface
//!     let pc = wiretap::PacketCapture::new_from_interface("lo").unwrap();
//!     // Start a capture on that interface
//!     let pc = pc.start_capture();
//!     // Do something useful, probably
//!     thread::sleep(time::Duration::from_secs(15));
//!     // Stop the capture
//!     let pc = pc.stop_capture();
//!     // Get the resulting TCP packets
//!     let output = pc.results_as_tcp();
//!     // Do something with them
//!     println!("Captured {} TCP packets", output.len());
//!     for out in output.iter() {
//!         println!("{:?}", out.payload());
//! }
//! ```
//!
//! ### Process-while-capturing
//!
//! This basic example shows how to process packets with a callback as they are captured
//!
//! ```rust,ignore
//! use wiretap;
//! use std::{thread, time};
//!
//! // Print the SrcIP:SrcPort --> DestIP:DestPort
//! fn print_to_from(bytes: Vec<u8>) {
//!     // Make sure the payload represents an EthernetPacket
//!     if let Some(ethernet_packet) = wiretap::EthernetPacket::new(&bytes) {
//!         // Make sure the EthernetPacket payload represents an Ipv4Packet
//!         if let Some(ipv4_packet) = Ipv4Packet::new(ethernet_packet.payload()) {
//!             // Make sure the Ipv4Packet payload represents an TcpPacket
//!             if let Some(tcp_packet) = TcpPacket::new(ipv4_packet.payload()) {
//!                 // Print out the interesting information
//!                 println!("Packet: {}:{} --> {}:{}", ipv4_packet.get_source(), tcp_packet.get_source(), ipv4_packet.get_destination(), tcp_packet.get_destination() )
//!             }
//!         }
//!     }
//! }
//!
//! fn main() {
//!     // Create a new PacketCapture with the default interface
//!     let pc = wiretap::PacketCapture::new_with_default().unwrap();
//!     // Start a capture on that interface
//!     let pc = pc.start_live_process(print_to_from);
//!     // Stuff happens
//!     thread::sleep(time::Duration::from_secs(15));
//!     // Stop the capture
//!     started.stop_capture();
//! }
//! ```

pub mod ethernet_frame;
pub use ethernet_frame::*;

pub mod ipv4_packet;
pub use ipv4_packet::*;

pub mod tcp_packet;
pub use tcp_packet::*;

pub use pnet::packet::Packet;

use pnet::datalink::Channel::Ethernet;
use pnet::datalink::{self, NetworkInterface};
use pnet::packet::ethernet::EthernetPacket as pnet_EthernetPacket;
use pnet::packet::ipv4::Ipv4Packet as pnet_Ipv4Packet;
use pnet::packet::tcp::TcpPacket as pnet_TcpPacket;
use std::error::Error;
use std::marker::PhantomData;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

/// Marker for PacketCapture struct
pub struct Uninitialized;
/// Marker for PacketCapture struct
#[derive(Debug)]
pub struct Initialized;
/// Marker for PacketCapture struct
pub struct Started;
/// Marker for PacketCapture struct
pub struct Completed;

/// Basic PacketCapture type
///
/// Marker as PhantomData allow compile-time checking of struct use
#[derive(Debug)]
pub struct PacketCapture<State> {
    interface: NetworkInterface,
    packets: Arc<Mutex<Vec<Vec<u8>>>>,
    results: Arc<[Vec<u8>]>,
    state: PhantomData<State>,
    stop_signal: Arc<AtomicBool>,
}

/// Uninitialized PacketCaptures can be created only
impl PacketCapture<Uninitialized> {
    /// Create a PacketCapture
    ///
    /// Takes an interface name and returns an Initialized PacketCapture
    pub fn new_from_interface(
        interface_name: &str,
    ) -> Result<PacketCapture<Initialized>, Box<dyn Error>> {
        let interface = datalink::interfaces()
            .into_iter()
            .find(|iface| iface.name == interface_name)
            .ok_or(format!("Could not find interface '{interface_name}'"))?;

        Ok(PacketCapture {
            interface,
            packets: Arc::new(Mutex::new(vec![])),
            results: Arc::new([]),
            state: PhantomData,
            stop_signal: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Create a PacketCapture
    ///
    /// Returns an Initialized PacketCapture with the default interface
    pub fn new_with_default() -> Result<PacketCapture<Initialized>, Box<dyn Error>> {
        let interface = datalink::interfaces()
            .into_iter()
            .find(|iface| iface.is_up() && !iface.is_loopback() && !iface.ips.is_empty())
            .ok_or("Could not determine defauly interface")?;

        Ok(PacketCapture {
            interface,
            packets: Arc::new(Mutex::new(vec![])),
            results: Arc::new([]),
            state: PhantomData,
            stop_signal: Arc::new(AtomicBool::new(false)),
        })
    }
}

/// Initialized PacketCaptures can start a capture or a live processing callback
impl PacketCapture<Initialized> {
    /// Start capturing
    ///
    /// Stores packets that can be accessed later with the `results` methods
    pub fn start_capture(&self) -> PacketCapture<Started> {
        let stop_signal = Arc::clone(&self.stop_signal);
        let interface = self.interface.clone();
        let mut rx = match datalink::channel(&interface, Default::default()) {
            Ok(Ethernet(_, rx)) => rx,
            Ok(_) => panic!("Non-ethernet channel created"),
            Err(e) => panic!("Could not create channel using interface: {e}"),
        };
        let packets = Arc::clone(&self.packets);

        rayon::spawn(move || {
            while !stop_signal.load(Ordering::Relaxed) {
                match rx.next() {
                    Ok(packet) => {
                        packets.lock().unwrap().push(packet.to_owned());
                    }
                    Err(e) => panic!("Could not read packet: {e}"),
                }
            }
        });

        PacketCapture {
            interface: self.interface.clone(),
            packets: self.packets.clone(),
            results: self.results.clone(),
            state: PhantomData,
            stop_signal: self.stop_signal.clone(),
        }
    }

    /// Start live processing
    ///
    /// Takes (and calls) a callback function on incoming streams of bytes
    pub fn start_live_process(
        &self,
        mut callback: impl FnMut(Vec<u8>) + std::marker::Send + 'static,
    ) -> PacketCapture<Started> {
        let stop_signal = Arc::clone(&self.stop_signal);
        let interface = self.interface.clone();
        let mut rx = match datalink::channel(&interface, Default::default()) {
            Ok(Ethernet(_, rx)) => rx,
            Ok(_) => panic!("Non-ethernet channel created"),
            Err(e) => panic!("Could not create channel: {e}"),
        };

        rayon::spawn(move || {
            while !stop_signal.load(Ordering::Relaxed) {
                match rx.next() {
                    Ok(packet) => {
                        callback(packet.to_vec());
                    }
                    Err(e) => panic!("Could not read packet: {e}"),
                }
            }
        });

        PacketCapture {
            interface: self.interface.clone(),
            packets: self.packets.clone(),
            results: self.results.clone(),
            state: PhantomData,
            stop_signal: self.stop_signal.clone(),
        }
    }
}

/// Started PacketCaptures can stop only
impl PacketCapture<Started> {
    /// Stop capturing
    ///
    /// Not much more to it
    pub fn stop_capture(&self) -> PacketCapture<Completed> {
        self.stop_signal.store(true, Ordering::Relaxed);
        PacketCapture {
            interface: self.interface.clone(),
            packets: self.packets.clone(),
            results: Arc::from(
                self.packets
                    .lock()
                    .unwrap()
                    .clone()
                    .into_iter()
                    .collect::<Vec<_>>(),
            ),
            state: PhantomData,
            stop_signal: self.stop_signal.clone(),
        }
    }
}

/// Completed PacketCaptures return results in various formats
impl PacketCapture<Completed> {
    /// Results returned as raw vectors of bytes
    pub fn results_raw(&self) -> Arc<[Vec<u8>]> {
        self.results.clone()
    }

    /// Results returned as ethernet frames
    pub fn results_as_ethernet(&self) -> EthernetFrameCollection {
        self.results_raw()
            .iter()
            .filter(|buf| pnet_EthernetPacket::new(buf).is_some())
            .map(|buf| EthernetFrame::from(pnet_EthernetPacket::owned(buf.to_vec()).unwrap()))
            .collect::<EthernetFrameCollection>()
    }

    /// Results returned as ipv4 packets
    pub fn results_as_ipv4(&self) -> Ipv4PacketCollection {
        self.results_as_ethernet()
            .iter()
            .filter(|ethernet_frame| pnet_Ipv4Packet::new(ethernet_frame.payload()).is_some())
            .map(|ethernet_frame| {
                Ipv4Packet::from(pnet_Ipv4Packet::owned(ethernet_frame.payload().to_vec()).unwrap())
            })
            .collect::<Ipv4PacketCollection>()
    }

    /// Results returned as tcp segments
    pub fn results_as_tcp(&self) -> TcpSegmentCollection {
        self.results_as_ipv4()
            .iter()
            .filter(|ipv4_packet| pnet_TcpPacket::new(ipv4_packet.payload()).is_some())
            .map(|ipv4_packet| {
                TcpSegment::from(pnet_TcpPacket::owned(ipv4_packet.payload().to_vec()).unwrap())
            })
            .collect::<TcpSegmentCollection>()
    }
}
