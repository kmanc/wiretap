use pnet::packet::ipv4::Ipv4Packet as pnet_Ipv4Packet;
use pnet::packet::Packet;
use std::net::Ipv4Addr;
use std::ops::Deref;
use std::sync::Arc;

/// Wrapper around pnet's Ipv4Packet for adding additional funcitonality
#[derive(Debug)]
pub struct Ipv4Packet<'a>(pnet_Ipv4Packet<'a>);

impl<'a> From<pnet_Ipv4Packet<'a>> for Ipv4Packet<'a> {
    fn from(ipv4_packet: pnet_Ipv4Packet<'a>) -> Self {
        Ipv4Packet(ipv4_packet)
    }
}

impl<'a> Deref for Ipv4Packet<'a> {
    type Target = pnet_Ipv4Packet<'a>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Ipv4Packet<'_> {
    pub fn new<'a>(packet: &'a [u8]) -> Option<Ipv4Packet<'a>>{
        pnet_Ipv4Packet::new(packet).map(Ipv4Packet::from)
    }

    pub fn create_clone<'a>(&self) -> Ipv4Packet<'a> {
        Ipv4Packet::from(pnet_Ipv4Packet::owned(self.packet().to_vec()).unwrap())
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
