use pnet::packet::tcp::TcpPacket as pnet_TcpPacket;
use pnet::packet::Packet;
use std::ops::{Deref, DerefMut};
use std::sync::Arc;

/// Wrapper around pnet's TcpPacket for adding additional funcitonality
#[derive(Debug)]
pub struct TcpSegment<'a>(pnet_TcpPacket<'a>);

impl<'a> From<pnet_TcpPacket<'a>> for TcpSegment<'a> {
    fn from(ipv4_packet: pnet_TcpPacket<'a>) -> Self {
        TcpSegment(ipv4_packet)
    }
}

impl<'a> Deref for TcpSegment<'a> {
    type Target = pnet_TcpPacket<'a>;

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
        TcpSegment::from(pnet_TcpPacket::owned(self.packet().to_vec()).unwrap())
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

impl<'a> From<crate::Ipv4PacketCollection<'a>> for TcpSegmentCollection<'a> {
    fn from(ipv4_packet_collection: crate::Ipv4PacketCollection) -> Self {
        ipv4_packet_collection
            .iter()
            .filter(|ipv4_packet| pnet_TcpPacket::new(ipv4_packet.payload()).is_some())
            .map(|ipv4_packet| {
                TcpSegment::from(pnet_TcpPacket::owned(ipv4_packet.payload().to_vec()).unwrap())
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
                    if j > i {
                        unmatched.remove(j);
                        unmatched.remove(i);
                    } else {
                        unmatched.remove(i);
                        unmatched.remove(j);
                    }
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

impl DerefMut for TcpChallengeResponseCollection<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
