// SPDX-License-Identifier: MIT OR Apache-2.0

//! Confiential Nonces

use core::fmt;
use std::io;

use secp256k1_zkp::rand::{CryptoRng, RngCore};
use secp256k1_zkp::{self, PublicKey, Secp256k1, SecretKey, Signing};
#[cfg(feature = "serde")]
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::encode::{self, Decodable, Encodable};
use crate::hashes::sha256d;

type ExplicitInner = [u8; 32];
type ConfInner = PublicKey;

const EXPLICIT_LEN: usize = 32;
const CONFIDENTIAL_LEN: usize = 33;
const CONF_PREFIX_1: u8 = 0x02;
const CONF_PREFIX_2: u8 = 0x03;

/// A CT commitment to an output nonce (i.e. a public key)
#[derive(Copy, Clone, Debug, Default, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub enum Nonce {
    /// No value
    #[default]
    Null,
    /// There should be no such thing as an "explicit nonce", but Elements will deserialize
    /// such a thing (and insists that its size be 32 bytes). So we stick a 32-byte type here
    /// that implements all the traits we need.
    Explicit(ExplicitInner),
    /// Nonce is committed
    Confidential(ConfInner),
}

impl Nonce {
    /// Create nonce commitment.
    pub fn new_confidential<R: RngCore + CryptoRng, C: Signing>(
        rng: &mut R,
        secp: &Secp256k1<C>,
        receiver_blinding_pk: &ConfInner,
    ) -> (Self, SecretKey) {
        let ephemeral_sk = SecretKey::new(rng);
        Self::with_ephemeral_sk(secp, ephemeral_sk, receiver_blinding_pk)
    }

    /// Similar to [`Self::new_confidential`], but with a given `ephemeral_sk`
    /// instead of sampling it from rng.
    pub fn with_ephemeral_sk<C: Signing>(
        secp: &Secp256k1<C>,
        ephemeral_sk: SecretKey,
        receiver_blinding_pk: &ConfInner,
    ) -> (Self, SecretKey) {
        let sender_pk = ConfInner::from_secret_key(secp, &ephemeral_sk);
        let shared_secret = Self::make_shared_secret(receiver_blinding_pk, &ephemeral_sk);
        (Self::Confidential(sender_pk), shared_secret)
    }

    /// Calculate the shared secret.
    pub fn shared_secret(&self, receiver_blinding_sk: &SecretKey) -> Option<SecretKey> {
        match self {
            Self::Confidential(sender_pk) =>
                Some(Self::make_shared_secret(sender_pk, receiver_blinding_sk)),
            _ => None,
        }
    }

    /// Create the shared secret.
    fn make_shared_secret(pk: &ConfInner, sk: &SecretKey) -> SecretKey {
        let xy = secp256k1_zkp::ecdh::shared_secret_point(pk, sk);
        let shared_secret = {
            // Yes, what follows is the compressed representation of a Bitcoin public key.
            // However, this is more by accident then by design, see here: https://github.com/rust-bitcoin/rust-secp256k1/pull/255#issuecomment-744146282

            let mut dh_secret = [0u8; CONFIDENTIAL_LEN];
            dh_secret[0] = if xy.last().unwrap() % 2 == 0 { CONF_PREFIX_1 } else { CONF_PREFIX_2 };
            dh_secret[1..].copy_from_slice(&xy[0..32]);

            sha256d::Hash::hash(&dh_secret).to_byte_array()
        };

        SecretKey::from_slice(&shared_secret[..32]).expect("always has exactly 32 bytes")
    }

    /// Serialized length, in bytes
    pub fn encoded_length(&self) -> usize {
        match *self {
            Self::Null => 1,
            Self::Explicit(..) => 1 + EXPLICIT_LEN,
            Self::Confidential(..) => CONFIDENTIAL_LEN,
        }
    }

    /// Create from commitment.
    pub fn from_commitment(bytes: &[u8]) -> Result<Self, encode::Error> {
        Ok(Self::Confidential(
            ConfInner::from_slice(bytes).map_err(secp256k1_zkp::Error::Upstream)?,
        ))
    }

    /// Check if the object is null.
    pub fn is_null(&self) -> bool { matches!(*self, Self::Null) }

    /// Check if the object is explicit.
    pub fn is_explicit(&self) -> bool { matches!(*self, Self::Explicit(_)) }

    /// Check if the object is confidential.
    pub fn is_confidential(&self) -> bool { matches!(*self, Self::Confidential(_)) }

    /// Returns the explicit inner value.
    /// Returns [None] if [`Self::is_explicit`] returns false.
    pub fn explicit(&self) -> Option<ExplicitInner> {
        match *self {
            Self::Explicit(i) => Some(i),
            _ => None,
        }
    }

    /// Returns the confidential commitment in case of a confidential value.
    /// Returns [None] if [`Self::is_confidential`] returns false.
    pub fn commitment(&self) -> Option<ConfInner> {
        match *self {
            Self::Confidential(i) => Some(i),
            _ => None,
        }
    }
}

impl From<ConfInner> for Nonce {
    fn from(from: ConfInner) -> Self { Self::Confidential(from) }
}

impl fmt::Display for Nonce {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Self::Null => f.write_str("null"),
            Self::Explicit(n) => {
                for b in &n {
                    write!(f, "{:02x}", b)?;
                }
                Ok(())
            }
            Self::Confidential(pk) => write!(f, "{:02x}", pk),
        }
    }
}

impl Encodable for Nonce {
    fn consensus_encode<S: io::Write>(&self, mut s: S) -> Result<usize, encode::Error> {
        match *self {
            Self::Null => 0u8.consensus_encode(s),
            Self::Explicit(n) => {
                1u8.consensus_encode(&mut s)?;
                Ok(1 + n.consensus_encode(&mut s)?)
            }
            Self::Confidential(commitment) => {
                s.write_all(&commitment.serialize())?;
                Ok(CONFIDENTIAL_LEN)
            }
        }
    }
}

impl Decodable for Nonce {
    fn consensus_decode<D: io::Read>(mut d: D) -> Result<Self, encode::Error> {
        let prefix = u8::consensus_decode(&mut d)?;

        match prefix {
            0 => Ok(Self::Null),
            1 => {
                let explicit = Decodable::consensus_decode(&mut d)?;
                Ok(Self::Explicit(explicit))
            }
            p if p == CONF_PREFIX_1 || p == CONF_PREFIX_2 => {
                let mut comm = [0u8; CONFIDENTIAL_LEN];
                comm[0] = p;
                d.read_exact(&mut comm[1..])?;
                Ok(Self::Confidential(ConfInner::from_slice(&comm)?))
            }
            p => Err(encode::Error::InvalidConfidentialPrefix(p)),
        }
    }
}

#[cfg(feature = "serde")]
impl Serialize for Nonce {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeSeq;

        let seq_len = match *self {
            Self::Null => 1,
            Self::Explicit(_) | Self::Confidential(_) => 2,
        };
        let mut seq = s.serialize_seq(Some(seq_len))?;

        match *self {
            Self::Null => seq.serialize_element(&0u8)?,
            Self::Explicit(n) => {
                seq.serialize_element(&1u8)?;
                seq.serialize_element(&n)?;
            }
            Self::Confidential(commitment) => {
                seq.serialize_element(&2u8)?;
                seq.serialize_element(&commitment)?;
            }
        }
        seq.end()
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for Nonce {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        use serde::de::{Error, SeqAccess, Visitor};
        struct CommitVisitor;

        impl<'de> Visitor<'de> for CommitVisitor {
            type Value = Nonce;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a committed value")
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut access: A) -> Result<Nonce, A::Error> {
                let prefix = access.next_element::<u8>()?;
                match prefix {
                    Some(0) => Ok(Self::Value::Null),
                    Some(1) => match access.next_element()? {
                        Some(x) => Ok(Self::Value::Explicit(x)),
                        None => Err(A::Error::custom("missing explicit nonce")),
                    },
                    Some(2) => match access.next_element()? {
                        Some(x) => Ok(Self::Value::Confidential(x)),
                        None => Err(A::Error::custom("missing nonce")),
                    },
                    _ => Err(A::Error::custom("wrong or missing prefix")),
                }
            }
        }

        d.deserialize_seq(CommitVisitor)
    }
}
