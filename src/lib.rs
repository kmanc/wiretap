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
//!     let pc = wiretap::PacketCapture::new("lo").unwrap();
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
//!     for out in output {
//!         println!("{:?}", out.0.payload());
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
//!                 println!("Packet: {}:{} --> {}:{}", ipv4_packet.0.get_source(), tcp_packet.0.get_source(), ipv4_packet.0.get_destination(), tcp_packet.0.get_destination() )
//!             }
//!         }
//!     }
//! }
//!
//! fn main() {
//!     // Create a new PacketCapture with the "lo" interface
//!     let pc = wiretap::PacketCapture::new("lo").unwrap();
//!     // Start a capture on that interface
//!     let pc = pc.start_live_process(print_to_from);
//!     // Stuff happens
//!     thread::sleep(time::Duration::from_secs(15));
//!     // Stop the capture
//!     started.stop_capture();
//! }
//! ```

pub use pnet::packet::Packet;

use pnet::datalink::Channel::Ethernet;
use pnet::datalink::{self, NetworkInterface};
use std::error::Error;
use std::marker::PhantomData;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

#[derive(Debug)]
pub struct EthernetFrame<'a>(pub pnet::packet::ethernet::EthernetPacket<'a>);

impl<'a> From<pnet::packet::ethernet::EthernetPacket<'a>> for EthernetFrame<'a> {
    fn from(ethernet_frame: pnet::packet::ethernet::EthernetPacket<'a>) -> Self {
        EthernetFrame(ethernet_frame)
    }
}

#[derive(Debug)]
pub struct EthernetFrameCollection<'a>(Vec<EthernetFrame<'a>>);

impl<'a> FromIterator<EthernetFrame<'a>> for EthernetFrameCollection<'a> {
    fn from_iter<I: IntoIterator<Item=EthernetFrame<'a>>>(iter: I) -> Self {
        let mut c = EthernetFrameCollection::new();

        for i in iter {
            c.add(i);
        }

        c
    }
}

impl<'a> IntoIterator for EthernetFrameCollection<'a> {
    type Item = EthernetFrame<'a>;
    type IntoIter = ::std::vec::IntoIter<EthernetFrame<'a>>;
    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'a> EthernetFrameCollection<'a> {
    fn new() -> EthernetFrameCollection<'a> {
        EthernetFrameCollection(Vec::new())
    }

    fn add(&mut self, elem: EthernetFrame<'a>) {
        self.0.push(elem);
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }
}

#[derive(Debug)]
pub struct Ipv4Packet<'a>(pub pnet::packet::ipv4::Ipv4Packet<'a>);

impl<'a> From<pnet::packet::ipv4::Ipv4Packet<'a>> for Ipv4Packet<'a> {
    fn from(ipv4_packet: pnet::packet::ipv4::Ipv4Packet<'a>) -> Self {
        Ipv4Packet(ipv4_packet)
    }
}

#[derive(Debug)]
pub struct Ipv4PacketCollection<'a>(Vec<Ipv4Packet<'a>>);

impl<'a> FromIterator<Ipv4Packet<'a>> for Ipv4PacketCollection<'a> {
    fn from_iter<I: IntoIterator<Item=Ipv4Packet<'a>>>(iter: I) -> Self {
        let mut c = Ipv4PacketCollection::new();

        for i in iter {
            c.add(i);
        }

        c
    }
}

impl<'a> IntoIterator for Ipv4PacketCollection<'a> {
    type Item = Ipv4Packet<'a>;
    type IntoIter = ::std::vec::IntoIter<Ipv4Packet<'a>>;
    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'a> Ipv4PacketCollection<'a> {
    fn new() -> Ipv4PacketCollection<'a> {
        Ipv4PacketCollection(Vec::new())
    }

    fn add(&mut self, elem: Ipv4Packet<'a>) {
        self.0.push(elem);
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }
}


//const TCP_FIN: u16 = 1;
const TCP_SYN: u16 = 2;
const TCP_RST: u16 = 4;
//const TCP_PSH: u16 = 8;
const TCP_ACK: u16 = 16;
//const TCP_URG: u16 = 32;

#[derive(Debug)]
pub struct TcpSegment<'a>(pub pnet::packet::tcp::TcpPacket<'a>);

impl<'a> From<pnet::packet::tcp::TcpPacket<'a>> for TcpSegment<'a> {
    fn from(ipv4_packet: pnet::packet::tcp::TcpPacket<'a>) -> Self {
        TcpSegment(ipv4_packet)
    }
}

impl TcpSegment<'_> {
    pub fn has_payload(&self) -> bool {
        !&self.0.payload().is_empty()
    }

    pub fn is_syn(&self) -> bool {
        self.0.get_flags() == TCP_SYN
    }

    pub fn is_rst_ack(&self) -> bool {
        self.0.get_flags() == TCP_RST + TCP_ACK
    }
}

#[derive(Debug)]
pub struct TcpSegmentCollection<'a>(Vec<TcpSegment<'a>>);

impl<'a> FromIterator<TcpSegment<'a>> for TcpSegmentCollection<'a> {
    fn from_iter<I: IntoIterator<Item=TcpSegment<'a>>>(iter: I) -> Self {
        let mut c = TcpSegmentCollection::new();

        for i in iter {
            c.add(i);
        }

        c
    }
}

impl<'a> IntoIterator for TcpSegmentCollection<'a> {
    type Item = TcpSegment<'a>;
    type IntoIter = ::std::vec::IntoIter<TcpSegment<'a>>;
    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'a> TcpSegmentCollection<'a> {
    fn new() -> TcpSegmentCollection<'a> {
        TcpSegmentCollection(Vec::new())
    }

    fn add(&mut self, elem: TcpSegment<'a>) {
        self.0.push(elem);
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }
}

/// Marker for PacketCapture struct
pub struct Uninitialized;
/// Marker for PacketCapture struct
pub struct Initialized;
/// Marker for PacketCapture struct
pub struct Started;
/// Marker for PacketCapture struct
pub struct Completed;

/// Basic PacketCapture type
///
/// Marker as PhantomData allow compile-time checking of struct use
pub struct PacketCapture<State> {
    interface: NetworkInterface,
    results: Arc<Mutex<Vec<Vec<u8>>>>,
    state: PhantomData<State>,
    stop_signal: Arc<AtomicBool>,
}

/// Uninitialized PacketCaptures can be created only
impl PacketCapture<Uninitialized> {
    /// Create a PacketCapture
    ///
    /// Takes an interface name and returns an Initialized PacketCapture
    pub fn new(interface_name: &str) -> Result<PacketCapture<Initialized>, Box<dyn Error>> {
        let interface = datalink::interfaces()
            .into_iter()
            .find(|iface| iface.name == interface_name)
            .ok_or("Could not find interface")?;

        Ok(PacketCapture {
            interface,
            results: Arc::new(Mutex::new(vec![])),
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
        let results = Arc::clone(&self.results);

        rayon::spawn(move || {
            while !stop_signal.load(Ordering::Relaxed) {
                match rx.next() {
                    Ok(packet) => {
                        results.lock().unwrap().push(packet.to_owned());
                    }
                    Err(e) => panic!("Could not read packet: {e}"),
                }
            }
        });

        PacketCapture {
            interface: self.interface.clone(),
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
            results: self.results.clone(),
            state: PhantomData,
            stop_signal: self.stop_signal.clone(),
        }
    }
}

/// Completed PacketCaptures return results in various formats
impl PacketCapture<Completed> {
    /// Results returned as raw vectors of bytes
    pub fn results_raw(&self) -> Vec<Vec<u8>> {
        self.results.lock().unwrap().clone()
    }

    /// Results returned as ethernet frames
    pub fn results_as_ethernet(&self) -> EthernetFrameCollection {
        self.results_raw()
            .into_iter()
            .filter(|v| pnet::packet::ethernet::EthernetPacket::new(v).is_some())
            .map(|v| EthernetFrame::from(pnet::packet::ethernet::EthernetPacket::owned(v).unwrap()))
            .collect::<EthernetFrameCollection>()
    }

    /// Results returned as ipv4 packets
    pub fn results_as_ipv4(&self) -> Ipv4PacketCollection {
        self.results_as_ethernet()
            .into_iter()
            .filter(|ethernet_frame| {
                pnet::packet::ipv4::Ipv4Packet::new(ethernet_frame.0.payload()).is_some()
            })
            .map(|ethernet_frame| {
                Ipv4Packet::from(
                    pnet::packet::ipv4::Ipv4Packet::owned(ethernet_frame.0.payload().to_vec())
                        .unwrap(),
                )
            })
            .collect::<Ipv4PacketCollection>()
    }

    /// Results returned as tcp segments
    pub fn results_as_tcp(&self) -> TcpSegmentCollection {
        self.results_as_ipv4()
            .into_iter()
            .filter(|ipv4_packet| {
                pnet::packet::tcp::TcpPacket::new(ipv4_packet.0.payload()).is_some()
            })
            .map(|ipv4_packet| {
                TcpSegment::from(
                    pnet::packet::tcp::TcpPacket::owned(ipv4_packet.0.payload().to_vec()).unwrap(),
                )
            })
            .collect::<TcpSegmentCollection>()
    }
}
