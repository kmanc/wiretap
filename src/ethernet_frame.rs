use pnet::packet::ethernet::EthernetPacket as pnet_EthernetPacket;
use pnet::packet::Packet;
use std::ops::Deref;
use std::sync::Arc;

/// Wrapper around pnet's EthernetPacket for adding additional funcitonality
#[derive(Debug)]
pub struct EthernetFrame<'a>(pnet_EthernetPacket<'a>);

impl<'a> From<pnet_EthernetPacket<'a>> for EthernetFrame<'a> {
    fn from(ethernet_frame: pnet_EthernetPacket<'a>) -> Self {
        EthernetFrame(ethernet_frame)
    }
}

impl<'a> Deref for EthernetFrame<'a> {
    type Target = pnet_EthernetPacket<'a>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl EthernetFrame<'_> {
    pub fn new<'a>(packet: &'a [u8]) -> Option<EthernetFrame<'a>>{
        pnet_EthernetPacket::new(packet).map(EthernetFrame::from)
    }
    
    pub fn create_clone<'a>(&self) -> EthernetFrame<'a> {
        EthernetFrame::from(pnet_EthernetPacket::owned(self.packet().to_vec()).unwrap())
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
