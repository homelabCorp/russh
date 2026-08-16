// Copyright 2016 Pierre-Étienne Meunier
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

//! `aes{128,256}-gcm@openssh.com` over RustCrypto primitives.
//!
//! A drop-in alternative to the `ring`/`aws-lc-rs` implementation in `gcm.rs`,
//! for builds that cannot use a C toolchain.
//!
//! Per RFC 5647, SSH's use of GCM leaves the four-byte packet length in the
//! clear and authenticates it as additional data, rather than encrypting it the
//! way the ChaCha20 construction does.
//!
//! The nonce is incremented as a big-endian integer over all twelve bytes after
//! every packet. A repeated nonce under one key destroys GCM entirely, so that
//! counter is deliberately the least clever code here.

use aes_gcm::aead::AeadInPlace;
use aes_gcm::{Aes128Gcm, Aes256Gcm, KeyInit};
use rand_core::Rng;

use super::super::Error;
use crate::keys::key::safe_rng;
use crate::mac::MacAlgorithm;

pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;

/// Which AES-GCM this is. Stands in for the `&'static Algorithm` the C
/// backends pass around.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Size {
    Aes128,
    Aes256,
}

impl Size {
    fn key_len(self) -> usize {
        match self {
            Self::Aes128 => 16,
            Self::Aes256 => 32,
        }
    }
}

pub struct GcmCipher(pub(crate) Size);

impl super::Cipher for GcmCipher {
    fn key_len(&self) -> usize {
        self.0.key_len()
    }

    fn nonce_len(&self) -> usize {
        NONCE_LEN
    }

    fn make_opening_key(
        &self,
        k: &[u8],
        n: &[u8],
        _: &[u8],
        _: &dyn MacAlgorithm,
    ) -> Box<dyn super::OpeningKey + Send> {
        Box::new(OpeningKey(State::new(self.0, k, n)))
    }

    fn make_sealing_key(
        &self,
        k: &[u8],
        n: &[u8],
        _: &[u8],
        _: &dyn MacAlgorithm,
    ) -> Box<dyn super::SealingKey + Send> {
        Box::new(SealingKey(State::new(self.0, k, n)))
    }
}

struct State {
    size: Size,
    key: Vec<u8>,
    nonce: [u8; NONCE_LEN],
}

impl State {
    fn new(size: Size, key: &[u8], nonce: &[u8]) -> Self {
        let mut fixed = [0u8; NONCE_LEN];
        #[allow(clippy::indexing_slicing)] // russh sizes these from the cipher
        fixed.copy_from_slice(&nonce[..NONCE_LEN]);
        Self {
            size,
            key: key.to_vec(),
            nonce: fixed,
        }
    }

    /// This packet's nonce, advancing the counter for the next one.
    fn advance(&mut self) -> [u8; NONCE_LEN] {
        let current = self.nonce;
        let mut carry = 1u16;
        for byte in self.nonce.iter_mut().rev() {
            let sum = u16::from(*byte) + carry;
            *byte = sum as u8;
            carry = sum >> 8;
            if carry == 0 {
                break;
            }
        }
        current
    }

    fn seal(&mut self, packet: &mut [u8], tag_out: &mut [u8]) -> Result<(), Error> {
        if packet.len() < super::PACKET_LENGTH_LEN {
            return Err(Error::DecryptionError);
        }
        let nonce = self.advance();
        #[allow(clippy::indexing_slicing)] // length checked
        let (length, payload) = packet.split_at_mut(super::PACKET_LENGTH_LEN);
        let aad = length.to_vec();

        let tag = match self.size {
            Size::Aes128 => Aes128Gcm::new_from_slice(&self.key)
                .map_err(|_| Error::DecryptionError)?
                .encrypt_in_place_detached(&nonce.into(), &aad, payload)
                .map_err(|_| Error::DecryptionError)?,
            Size::Aes256 => Aes256Gcm::new_from_slice(&self.key)
                .map_err(|_| Error::DecryptionError)?
                .encrypt_in_place_detached(&nonce.into(), &aad, payload)
                .map_err(|_| Error::DecryptionError)?,
        };
        tag_out.copy_from_slice(&tag);
        Ok(())
    }

    fn open<'a>(&mut self, packet: &'a mut [u8]) -> Result<&'a [u8], Error> {
        if packet.len() < super::PACKET_LENGTH_LEN + TAG_LEN {
            return Err(Error::DecryptionError);
        }
        let nonce = self.advance();
        let split = packet.len() - TAG_LEN;
        #[allow(clippy::indexing_slicing)] // length checked
        let (packet, tag) = packet.split_at_mut(split);
        let tag: [u8; TAG_LEN] = tag.try_into().map_err(|_| Error::DecryptionError)?;

        #[allow(clippy::indexing_slicing)] // length checked
        let (length, payload) = packet.split_at_mut(super::PACKET_LENGTH_LEN);
        let aad = length.to_vec();

        match self.size {
            Size::Aes128 => Aes128Gcm::new_from_slice(&self.key)
                .map_err(|_| Error::DecryptionError)?
                .decrypt_in_place_detached(&nonce.into(), &aad, payload, &tag.into())
                .map_err(|_| Error::DecryptionError)?,
            Size::Aes256 => Aes256Gcm::new_from_slice(&self.key)
                .map_err(|_| Error::DecryptionError)?
                .decrypt_in_place_detached(&nonce.into(), &aad, payload, &tag.into())
                .map_err(|_| Error::DecryptionError)?,
        }
        Ok(payload)
    }
}

pub struct OpeningKey(State);

pub struct SealingKey(State);

impl super::OpeningKey for OpeningKey {
    fn decrypt_packet_length(&self, _seqn: u32, encrypted_packet_length: &[u8]) -> [u8; 4] {
        // The length travels in the clear under RFC 5647.
        let mut length = [0u8; 4];
        length.copy_from_slice(encrypted_packet_length);
        length
    }

    fn tag_len(&self) -> usize {
        TAG_LEN
    }

    fn open<'a>(&mut self, _seqn: u32, ciphertext_and_tag: &'a mut [u8]) -> Result<&'a [u8], Error> {
        self.0.open(ciphertext_and_tag)
    }
}

impl super::SealingKey for SealingKey {
    fn padding_length(&self, payload: &[u8]) -> usize {
        let block_size = 16;
        let extra_len = super::PACKET_LENGTH_LEN + super::PADDING_LENGTH_LEN;
        let padding_len = if payload.len() + extra_len <= super::MINIMUM_PACKET_LEN {
            super::MINIMUM_PACKET_LEN - payload.len() - super::PADDING_LENGTH_LEN
        } else {
            block_size - ((super::PADDING_LENGTH_LEN + payload.len()) % block_size)
        };
        if padding_len < super::PACKET_LENGTH_LEN {
            padding_len + block_size
        } else {
            padding_len
        }
    }

    fn fill_padding(&self, padding_out: &mut [u8]) {
        safe_rng().fill_bytes(padding_out);
    }

    fn tag_len(&self) -> usize {
        TAG_LEN
    }

    fn seal(&mut self, _seqn: u32, plaintext_in_ciphertext_out: &mut [u8], tag_out: &mut [u8]) {
        // The trait cannot report a failure here, and the only failure modes
        // are a mis-sized key or buffer, which russh does not produce.
        let _ = self.0.seal(plaintext_in_ciphertext_out, tag_out);
    }
}
