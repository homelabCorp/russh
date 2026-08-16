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

//! `chacha20-poly1305@openssh.com` over RustCrypto primitives.
//!
//! A drop-in alternative to the `ring`/`aws-lc-rs` implementation in
//! `chacha20poly1305.rs`, for builds that cannot use a C toolchain.
//!
//! <http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/usr.bin/ssh/PROTOCOL.chacha20poly1305>
//!
//! The construction is deliberately *not* the RFC 8439 AEAD:
//!
//! - The 512 bits of key material are two independent keys. The first 256 bits
//!   are K_2, which encrypts the payload; the second 256 bits are K_1, which
//!   encrypts the four-byte packet length on its own so a receiver can learn
//!   how much to read before it can authenticate anything.
//! - The nonce is eight zero bytes followed by the big-endian sequence number.
//! - Counter 0 of the K_2 keystream provides the Poly1305 key; the payload is
//!   encrypted from counter 1.
//! - The tag covers the encrypted length and the encrypted payload together,
//!   as one unpadded message.

use chacha20::ChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use poly1305::Poly1305;
use poly1305::universal_hash::KeyInit as _;
use subtle::ConstantTimeEq;

use super::super::Error;
use crate::mac::MacAlgorithm;

pub const KEY_LEN: usize = 64;
pub const TAG_LEN: usize = 16;

/// One ChaCha20 block, which is what separates the Poly1305 key from the
/// payload keystream.
const BLOCK_LEN: u64 = 64;

fn nonce_for(seqn: u32) -> [u8; 12] {
    let [a, b, c, d] = seqn.to_be_bytes();
    [0, 0, 0, 0, 0, 0, 0, 0, a, b, c, d]
}

#[derive(Clone)]
struct Keys {
    payload: [u8; 32],
    length: [u8; 32],
}

impl Keys {
    fn new(material: &[u8]) -> Self {
        let mut payload = [0u8; 32];
        let mut length = [0u8; 32];
        // K_2 first, K_1 second, per the protocol description above.
        payload.copy_from_slice(&material[..32]);
        length.copy_from_slice(&material[32..64]);
        Self { payload, length }
    }

    fn poly_key(&self, seqn: u32) -> [u8; 32] {
        let mut block = [0u8; BLOCK_LEN as usize];
        let mut cipher = ChaCha20::new(&self.payload.into(), &nonce_for(seqn).into());
        cipher.apply_keystream(&mut block);
        let mut key = [0u8; 32];
        key.copy_from_slice(&block[..32]);
        key
    }

    fn apply_length_keystream(&self, seqn: u32, length: &mut [u8]) {
        let mut cipher = ChaCha20::new(&self.length.into(), &nonce_for(seqn).into());
        cipher.apply_keystream(length);
    }

    fn apply_payload_keystream(&self, seqn: u32, payload: &mut [u8]) {
        let mut cipher = ChaCha20::new(&self.payload.into(), &nonce_for(seqn).into());
        cipher.seek(BLOCK_LEN);
        cipher.apply_keystream(payload);
    }
}

pub struct SshChacha20Poly1305Cipher {}

impl super::Cipher for SshChacha20Poly1305Cipher {
    fn key_len(&self) -> usize {
        KEY_LEN
    }

    fn make_opening_key(
        &self,
        k: &[u8],
        _: &[u8],
        _: &[u8],
        _: &dyn MacAlgorithm,
    ) -> Box<dyn super::OpeningKey + Send> {
        Box::new(OpeningKey(Keys::new(k)))
    }

    fn make_sealing_key(
        &self,
        k: &[u8],
        _: &[u8],
        _: &[u8],
        _: &dyn MacAlgorithm,
    ) -> Box<dyn super::SealingKey + Send> {
        Box::new(SealingKey(Keys::new(k)))
    }
}

pub struct OpeningKey(Keys);

pub struct SealingKey(Keys);

impl super::OpeningKey for OpeningKey {
    fn decrypt_packet_length(&self, seqn: u32, encrypted_packet_length: &[u8]) -> [u8; 4] {
        let mut length = [0u8; 4];
        length.copy_from_slice(encrypted_packet_length);
        self.0.apply_length_keystream(seqn, &mut length);
        length
    }

    fn tag_len(&self) -> usize {
        TAG_LEN
    }

    fn open<'a>(&mut self, seqn: u32, ciphertext_and_tag: &'a mut [u8]) -> Result<&'a [u8], Error> {
        if ciphertext_and_tag.len() < super::PACKET_LENGTH_LEN + TAG_LEN {
            return Err(Error::DecryptionError);
        }
        let ciphertext_len = ciphertext_and_tag.len() - TAG_LEN;
        #[allow(clippy::indexing_slicing)] // length checked
        let (ciphertext, tag) = ciphertext_and_tag.split_at_mut(ciphertext_len);

        // Verified before anything is decrypted. Decrypting first and checking
        // afterwards hands a padding oracle to whoever is on the wire.
        let expected = Poly1305::new(&self.0.poly_key(seqn).into()).compute_unpadded(ciphertext);
        if expected.as_slice().ct_eq(tag).unwrap_u8() != 1 {
            return Err(Error::DecryptionError);
        }

        #[allow(clippy::indexing_slicing)] // length checked
        let payload = &mut ciphertext[super::PACKET_LENGTH_LEN..];
        self.0.apply_payload_keystream(seqn, payload);
        Ok(payload)
    }
}

impl super::SealingKey for SealingKey {
    fn padding_length(&self, payload: &[u8]) -> usize {
        let block_size = 8;
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

    // As explained in "SSH via CTR mode with stateful decryption" in
    // https://openvpn.net/papers/ssh-security.pdf, the padding doesn't need to
    // be random because we're doing stateful counter-mode encryption. Use
    // fixed padding to avoid PRNG overhead.
    fn fill_padding(&self, padding_out: &mut [u8]) {
        for padding_byte in padding_out {
            *padding_byte = 0;
        }
    }

    fn tag_len(&self) -> usize {
        TAG_LEN
    }

    fn seal(&mut self, seqn: u32, plaintext_in_ciphertext_out: &mut [u8], tag: &mut [u8]) {
        #[allow(clippy::indexing_slicing)] // caller sizes the buffer
        let (length, payload) = plaintext_in_ciphertext_out.split_at_mut(super::PACKET_LENGTH_LEN);
        self.0.apply_length_keystream(seqn, length);
        self.0.apply_payload_keystream(seqn, payload);

        let computed = Poly1305::new(&self.0.poly_key(seqn).into())
            .compute_unpadded(plaintext_in_ciphertext_out);
        tag.copy_from_slice(&computed);
    }
}

// Enabled only when both this backend and `ring` are compiled in, so a
// reviewer can check the replacement against the implementation it replaces:
//
//     cargo test -p russh --no-default-features --features rustcrypto,ring
//
// The construction is not the RFC 8439 AEAD and published vectors for it are
// scarce, so the reference implementation is the oracle. If these disagree by
// one byte, the replacement is not a replacement.
#[cfg(all(test, feature = "ring"))]
mod matches_ring {
    use super::*;

    fn bytes(seed: u64, n: usize) -> Vec<u8> {
        let mut state = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
        (0..n)
            .map(|_| {
                state = state
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                (state >> 33) as u8
            })
            .collect()
    }

    fn packet(seed: u64, body: usize) -> Vec<u8> {
        let mut p = (body as u32).to_be_bytes().to_vec();
        p.extend(bytes(seed, body));
        p
    }

    #[test]
    fn sealing_produces_the_same_bytes_and_tag_as_ring() {
        for seed in [1u64, 2, 7, 99] {
            let material: [u8; KEY_LEN] = bytes(seed, KEY_LEN).try_into().unwrap();
            let theirs = ring::aead::chacha20_poly1305_openssh::SealingKey::new(&material);

            for body in [0usize, 1, 8, 63, 64, 65, 200, 1024] {
                for seqn in [0u32, 1, 255, 256, 65_535, u32::MAX] {
                    let original = packet(seed.wrapping_add(body as u64), body);

                    let mut mine = original.clone();
                    let mut my_tag = [0u8; TAG_LEN];
                    super::SealingKey(Keys::new(&material)).seal_for_test(
                        seqn,
                        &mut mine,
                        &mut my_tag,
                    );

                    let mut reference = original.clone();
                    let mut their_tag = [0u8; TAG_LEN];
                    theirs.seal_in_place(seqn, &mut reference, &mut their_tag);

                    assert_eq!(mine, reference, "seed={seed} body={body} seqn={seqn}");
                    assert_eq!(my_tag, their_tag, "seed={seed} body={body} seqn={seqn}");
                }
            }
        }
    }

    #[test]
    fn the_packet_length_decrypts_the_same_way_ring_decrypts_it() {
        // The length uses the *other* key; swapping the two produces a client
        // that interoperates with nothing.
        for seed in [3u64, 11, 42] {
            let material: [u8; KEY_LEN] = bytes(seed, KEY_LEN).try_into().unwrap();
            let theirs = ring::aead::chacha20_poly1305_openssh::OpeningKey::new(&material);
            let mine = super::OpeningKey(Keys::new(&material));

            for seqn in [0u32, 5, 70_000] {
                let encrypted: [u8; 4] = bytes(seed + u64::from(seqn), 4).try_into().unwrap();
                assert_eq!(
                    crate::cipher::OpeningKey::decrypt_packet_length(&mine, seqn, &encrypted),
                    theirs.decrypt_packet_length(seqn, encrypted),
                    "seed={seed} seqn={seqn}"
                );
            }
        }
    }

    #[test]
    fn each_opens_what_the_other_sealed() {
        for seed in [5u64, 13] {
            let material: [u8; KEY_LEN] = bytes(seed, KEY_LEN).try_into().unwrap();
            let their_sealer = ring::aead::chacha20_poly1305_openssh::SealingKey::new(&material);
            let their_opener = ring::aead::chacha20_poly1305_openssh::OpeningKey::new(&material);

            for body in [0usize, 16, 100] {
                let original = packet(seed, body);

                let mut sealed = original.clone();
                let mut tag = [0u8; TAG_LEN];
                their_sealer.seal_in_place(7, &mut sealed, &mut tag);
                sealed.extend_from_slice(&tag);
                let mut opener = super::OpeningKey(Keys::new(&material));
                let opened =
                    crate::cipher::OpeningKey::open(&mut opener, 7, &mut sealed).expect("opens");
                assert_eq!(opened, &original[4..]);

                let mut sealed = original.clone();
                let mut tag = [0u8; TAG_LEN];
                super::SealingKey(Keys::new(&material)).seal_for_test(9, &mut sealed, &mut tag);
                let opened = their_opener
                    .open_in_place(9, &mut sealed, &tag)
                    .expect("ring opens");
                assert_eq!(opened, &original[4..]);
            }
        }
    }

    #[test]
    fn a_flipped_bit_anywhere_is_refused() {
        let material: [u8; KEY_LEN] = bytes(21, KEY_LEN).try_into().unwrap();
        let original = packet(21, 64);
        let mut sealed = original.clone();
        let mut tag = [0u8; TAG_LEN];
        super::SealingKey(Keys::new(&material)).seal_for_test(3, &mut sealed, &mut tag);
        sealed.extend_from_slice(&tag);

        for index in 0..sealed.len() {
            let mut tampered = sealed.clone();
            tampered[index] ^= 0x01;
            let mut opener = super::OpeningKey(Keys::new(&material));
            assert!(
                crate::cipher::OpeningKey::open(&mut opener, 3, &mut tampered).is_err(),
                "a flipped bit at {index} was accepted"
            );
        }
    }
}

#[cfg(test)]
impl SealingKey {
    /// `SealingKey::seal` without needing the trait in scope at each call site.
    fn seal_for_test(mut self, seqn: u32, packet: &mut [u8], tag: &mut [u8]) {
        crate::cipher::SealingKey::seal(&mut self, seqn, packet, tag);
    }
}
