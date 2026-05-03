//! Double Ratchet (Signal spec: https://signal.org/docs/specifications/doubleratchet/)

pub(crate) mod chain;
pub mod state;
pub mod session;

pub use chain::*;
pub use state::*;
pub use session::*;

use x25519_dalek::{PublicKey, StaticSecret};
use std::collections::HashMap;
use crate::error::{ProtocolError, ProtocolResult};
use crate::crypto::constant_time_eq;
use serde::{Serialize, Deserialize};

pub const MAX_SKIPPED_MESSAGES: usize = 2000;
pub const MAX_MESSAGE_KEY_AGE_SECS: u64 = 86400;

/// Wire layout: dh_public(32) || message_number(8) || previous_chain_length(8) || timestamp(8)
pub const HEADER_SIZE: usize = 56;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RatchetHeader {
    pub dh_public: [u8; 32],
    pub message_number: u64,
    pub previous_chain_length: u64,
    pub timestamp: u64,
}

impl RatchetHeader {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_SIZE);
        out.extend_from_slice(&self.dh_public);
        out.extend_from_slice(&self.message_number.to_le_bytes());
        out.extend_from_slice(&self.previous_chain_length.to_le_bytes());
        out.extend_from_slice(&self.timestamp.to_le_bytes());
        out
    }

    pub fn from_bytes(data: &[u8]) -> ProtocolResult<Self> {
        if data.len() < HEADER_SIZE {
            return Err(ProtocolError::InvalidMessage);
        }
        let mut dh_public = [0u8; 32];
        dh_public.copy_from_slice(&data[0..32]);
        Ok(Self {
            dh_public,
            message_number:       u64::from_le_bytes(data[32..40].try_into().map_err(|_| ProtocolError::InvalidMessage)?),
            previous_chain_length: u64::from_le_bytes(data[40..48].try_into().map_err(|_| ProtocolError::InvalidMessage)?),
            timestamp:             u64::from_le_bytes(data[48..56].try_into().map_err(|_| ProtocolError::InvalidMessage)?),
        })
    }

    pub fn validate(&self) -> ProtocolResult<()> {
        if self.dh_public.iter().all(|&b| b == 0) {
            return Err(ProtocolError::InvalidMessage);
        }
        if self.message_number > 1_000_000_000_000 {
            return Err(ProtocolError::InvalidMessage);
        }
        let now = crate::crypto::current_timestamp()?;
        // Reject messages more than 5 minutes in the future.
        if self.timestamp > now + 300 {
            return Err(ProtocolError::InvalidMessage);
        }
        // Reject messages older than 24 hours, including timestamp == 0.
        if now > self.timestamp.saturating_add(86400) {
            return Err(ProtocolError::MessageTooOld);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SkippedMessageKey {
    pub key: [u8; 32],
    pub created_at: u64,
    pub message_number: u64,
}

impl SkippedMessageKey {
    pub fn new(key: [u8; 32], message_number: u64) -> Self {
        Self {
            key,
            message_number,
            created_at: crate::crypto::current_timestamp().unwrap_or(0),
        }
    }

    pub fn is_expired(&self) -> bool {
        crate::crypto::current_timestamp()
            .unwrap_or(self.created_at)
            > self.created_at + MAX_MESSAGE_KEY_AGE_SECS
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RatchetMessage {
    pub header: RatchetHeader,
    pub ciphertext: Vec<u8>,
}

impl RatchetMessage {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = self.header.to_bytes();
        out.extend_from_slice(&self.ciphertext);
        out
    }

    pub fn from_bytes(data: &[u8]) -> ProtocolResult<Self> {
        if data.len() < HEADER_SIZE + 29 {
            return Err(ProtocolError::InvalidMessage);
        }
        Ok(Self {
            header:     RatchetHeader::from_bytes(&data[..HEADER_SIZE])?,
            ciphertext: data[HEADER_SIZE..].to_vec(),
        })
    }

    pub fn size(&self) -> usize { HEADER_SIZE + self.ciphertext.len() }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RatchetStateSummary {
    pub sending_index: u64,
    pub receiving_index: u64,
    pub skipped_keys: usize,
    pub ratchet_count: u64,
}

#[derive(Clone, Debug)]
pub struct StateSummary {
    pub sending_index: u64,
    pub skipped_keys: usize,
}
