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
use std::net::Ipv4Addr;
use std::ops::{Deref, DerefMut};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

/// Wrapper around pnet's EthernetPacket for adding additional funcitonality
#[derive(Debug)]
pub struct EthernetFrame<'a>(pnet::packet::ethernet::EthernetPacket<'a>);

impl<'a> From<pnet::packet::ethernet::EthernetPacket<'a>> for EthernetFrame<'a> {
    fn from(ethernet_frame: pnet::packet::ethernet::EthernetPacket<'a>) -> Self {
        EthernetFrame(ethernet_frame)
    }
}

impl<'a> Deref for EthernetFrame<'a> {
    type Target = pnet::packet::ethernet::EthernetPacket<'a>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl EthernetFrame<'_> {
    pub fn create_clone<'a>(&self) -> EthernetFrame<'a> {
        EthernetFrame::from(
            pnet::packet::ethernet::EthernetPacket::owned(self.packet().to_vec()).unwrap(),
        )
    }
}

/// Wrapper around an Arc<[EthernetFrame]> for additional functionality
#[derive(Debug)]
pub struct EthernetFrameCollection<'a>(Arc<[EthernetFrame<'a>]>);

impl<'a> FromIterator<EthernetFrame<'a>> for EthernetFrameCollection<'a> {
    fn from_iter<I: IntoIterator<Item = EthernetFrame<'a>>>(iter: I) -> Self {
        EthernetFrameCollection(iter.into_iter().collect())
    }
}

impl<'a> Deref for EthernetFrameCollection<'a> {
    type Target = Arc<[EthernetFrame<'a>]>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Wrapper around pnet's Ipv4Packet for adding additional funcitonality
#[derive(Debug)]
pub struct Ipv4Packet<'a>(pnet::packet::ipv4::Ipv4Packet<'a>);

impl<'a> From<pnet::packet::ipv4::Ipv4Packet<'a>> for Ipv4Packet<'a> {
    fn from(ipv4_packet: pnet::packet::ipv4::Ipv4Packet<'a>) -> Self {
        Ipv4Packet(ipv4_packet)
    }
}

impl<'a> Deref for Ipv4Packet<'a> {
    type Target = pnet::packet::ipv4::Ipv4Packet<'a>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Ipv4Packet<'_> {
    pub fn create_clone<'a>(&self) -> Ipv4Packet<'a> {
        Ipv4Packet::from(pnet::packet::ipv4::Ipv4Packet::owned(self.packet().to_vec()).unwrap())
    }
}

/// Wrapper around an Arc<[Ipv4Packet]> for additional functionality
#[derive(Debug)]
pub struct Ipv4PacketCollection<'a>(Arc<[Ipv4Packet<'a>]>);

impl<'a> FromIterator<Ipv4Packet<'a>> for Ipv4PacketCollection<'a> {
    fn from_iter<I: IntoIterator<Item = Ipv4Packet<'a>>>(iter: I) -> Self {
        Ipv4PacketCollection(iter.into_iter().collect())
    }
}

impl<'a> Deref for Ipv4PacketCollection<'a> {
    type Target = Arc<[Ipv4Packet<'a>]>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<'a> Ipv4PacketCollection<'a> {
    pub fn filter_only_host(&'a self, host: Ipv4Addr) -> Ipv4PacketCollection<'a> {
        Ipv4PacketCollection(
            self.iter()
                .filter(|p| p.get_source() == host || p.get_destination() == host)
                .map(|p| p.create_clone())
                .collect::<Arc<[Ipv4Packet]>>(),
        )
    }
}

/// Wrapper around pnet's TcpPacket for adding additional funcitonality
#[derive(Debug)]
pub struct TcpSegment<'a>(pnet::packet::tcp::TcpPacket<'a>);

impl<'a> From<pnet::packet::tcp::TcpPacket<'a>> for TcpSegment<'a> {
    fn from(ipv4_packet: pnet::packet::tcp::TcpPacket<'a>) -> Self {
        TcpSegment(ipv4_packet)
    }
}

impl<'a> Deref for TcpSegment<'a> {
    type Target = pnet::packet::tcp::TcpPacket<'a>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl TcpSegment<'_> {
    /// Return true if the TCP segment has a payload
    pub fn has_payload(&self) -> bool {
        !&self.payload().is_empty()
    }

    pub fn create_clone<'a>(&self) -> TcpSegment<'a> {
        TcpSegment::from(pnet::packet::tcp::TcpPacket::owned(self.packet().to_vec()).unwrap())
    }

    fn is_answered_by(&self, other: &TcpSegment<'_>) -> bool {
        self.get_source() == other.get_destination()
            && self.get_destination() == other.get_source()
            && self.get_sequence() as usize + self.payload().len()
                == other.get_acknowledgement() as usize
    }
}

/// Wrapper around an Arc<[TcpSegment]> for additional functionality
#[derive(Debug)]
pub struct TcpSegmentCollection<'a>(Arc<[TcpSegment<'a>]>);

impl<'a> FromIterator<TcpSegment<'a>> for TcpSegmentCollection<'a> {
    fn from_iter<I: IntoIterator<Item = TcpSegment<'a>>>(iter: I) -> Self {
        TcpSegmentCollection(iter.into_iter().collect())
    }
}

impl<'a> Deref for TcpSegmentCollection<'a> {
    type Target = Arc<[TcpSegment<'a>]>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<'a> From<Ipv4PacketCollection<'a>> for TcpSegmentCollection<'a> {
    fn from(ipv4_packet_collection: Ipv4PacketCollection) -> Self {
        ipv4_packet_collection
            .iter()
            .filter(|ipv4_packet| {
                pnet::packet::tcp::TcpPacket::new(ipv4_packet.payload()).is_some()
            })
            .map(|ipv4_packet| {
                TcpSegment::from(
                    pnet::packet::tcp::TcpPacket::owned(ipv4_packet.payload().to_vec()).unwrap(),
                )
            })
            .collect::<TcpSegmentCollection>()
    }
}

impl<'a> TcpSegmentCollection<'a> {
    /// Get a collection of TcpSegment with TCP payloads
    ///
    /// Returns a new TcpSegmentCollection containing only the segments that have a TCP payload
    pub fn filter_no_payload(&'a self) -> TcpSegmentCollection<'a> {
        TcpSegmentCollection(
            self.iter()
                .filter(|s| s.has_payload())
                .map(|s| s.create_clone())
                .collect::<Arc<[TcpSegment]>>(),
        )
    }

    /// Couple the challenge / response pairs in a collection of TCP segments
    ///
    /// Returns a new TcpSegmentCollection containing only the segments that have a TCP payload
    pub fn find_challenge_response_pairs(
        &'a mut self,
    ) -> (TcpChallengeResponseCollection<'a>, TcpSegmentCollection<'a>) {
        let mut matched = Vec::new();
        let mut unmatched = self
            .iter()
            .map(|s| s.create_clone())
            .collect::<Vec<TcpSegment<'a>>>();
        let mut i = 0;
        while i < unmatched.len() {
            let challenge = unmatched[i].create_clone();
            let mut j = 0;
            let mut found_match = false;
            while j < unmatched.len() - 1 {
                j += 1;
                let candidate = unmatched[j].create_clone();
                if challenge.is_answered_by(&candidate) {
                    matched.push(TcpChallengeResponse::new(
                        challenge.create_clone(),
                        candidate.create_clone(),
                    ));
                    unmatched.remove(i);
                    unmatched.remove(j);
                    found_match = true;
                    break;
                }
            }
            if !found_match {
                i += 1;
            }
        }
        (
            TcpChallengeResponseCollection(matched.into()),
            TcpSegmentCollection(unmatched.into()),
        )
    }
}

/// Container for TCP segments where the "challenge" was answered by the "response"
#[derive(Debug)]
pub struct TcpChallengeResponse<'a> {
    pub challenge: TcpSegment<'a>,
    pub response: TcpSegment<'a>,
}

impl<'a> TcpChallengeResponse<'a> {
    fn new(challenge: TcpSegment<'a>, response: TcpSegment<'a>) -> TcpChallengeResponse<'a> {
        TcpChallengeResponse {
            challenge,
            response,
        }
    }
}

/// Wrapper around an Arc<[TcpChallengeResponse]> for additional functionality
#[derive(Debug)]
pub struct TcpChallengeResponseCollection<'a>(Arc<[TcpChallengeResponse<'a>]>);

impl<'a> FromIterator<TcpChallengeResponse<'a>> for TcpChallengeResponseCollection<'a> {
    fn from_iter<I: IntoIterator<Item = TcpChallengeResponse<'a>>>(iter: I) -> Self {
        TcpChallengeResponseCollection(iter.into_iter().collect())
    }
}

impl<'a> Deref for TcpChallengeResponseCollection<'a> {
    type Target = Arc<[TcpChallengeResponse<'a>]>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<'a> DerefMut for TcpChallengeResponseCollection<'a> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
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
    pub fn new(interface_name: &str) -> Result<PacketCapture<Initialized>, Box<dyn Error>> {
        let interface = datalink::interfaces()
            .into_iter()
            .find(|iface| iface.name == interface_name)
            .ok_or("Could not find interface")?;

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
            .filter(|v| pnet::packet::ethernet::EthernetPacket::new(v).is_some())
            .map(|v| {
                EthernetFrame::from(
                    pnet::packet::ethernet::EthernetPacket::owned(v.to_vec()).unwrap(),
                )
            })
            .collect::<EthernetFrameCollection>()
    }

    /// Results returned as ipv4 packets
    pub fn results_as_ipv4(&self) -> Ipv4PacketCollection {
        self.results_as_ethernet()
            .iter()
            .filter(|ethernet_frame| {
                pnet::packet::ipv4::Ipv4Packet::new(ethernet_frame.payload()).is_some()
            })
            .map(|ethernet_frame| {
                Ipv4Packet::from(
                    pnet::packet::ipv4::Ipv4Packet::owned(ethernet_frame.payload().to_vec())
                        .unwrap(),
                )
            })
            .collect::<Ipv4PacketCollection>()
    }

    /// Results returned as tcp segments
    pub fn results_as_tcp(&self) -> TcpSegmentCollection {
        self.results_as_ipv4()
            .iter()
            .filter(|ipv4_packet| {
                pnet::packet::tcp::TcpPacket::new(ipv4_packet.payload()).is_some()
            })
            .map(|ipv4_packet| {
                TcpSegment::from(
                    pnet::packet::tcp::TcpPacket::owned(ipv4_packet.payload().to_vec()).unwrap(),
                )
            })
            .collect::<TcpSegmentCollection>()
    }
}
