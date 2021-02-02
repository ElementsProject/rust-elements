// Rust Elements Library
// Written in 2018 by
//   Andrew Poelstra <apoelstra@blockstream.com>
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

//! # Confidential Commitments
//!
//! Structures representing Pedersen commitments of various types
//!

use secp256k1_zkp::{self, Generator, PedersenCommitment, PublicKey};
#[cfg(feature = "serde")]
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use std::{fmt, io};

use encode::{self, Decodable, Encodable};
use issuance::AssetId;

/// A CT commitment to an amount
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
pub enum Value {
    /// No value
    Null,
    /// Value is explicitly encoded
    Explicit(u64),
    /// Value is committed
    Confidential(PedersenCommitment),
}

impl Value {
    /// Serialized length, in bytes
    pub fn encoded_length(&self) -> usize {
        match *self {
            Value::Null => 1,
            Value::Explicit(..) => 9,
            Value::Confidential(..) => 33,
        }
    }

    /// Create from commitment.
    pub fn from_commitment(bytes: &[u8]) -> Result<Self, encode::Error> {
        Ok(Value::Confidential(PedersenCommitment::from_slice(bytes)?))
    }

    /// Check if the object is null.
    pub fn is_null(&self) -> bool {
        match self {
            Value::Null => true,
            _ => false
        }
    }

    /// Check if the object is explicit.
    pub fn is_explicit(&self) -> bool {
        match self {
            Value::Explicit(_) => true,
            _ => false
        }
    }

    /// Check if the object is confidential.
    pub fn is_confidential(&self) -> bool {
        match self {
            Value::Confidential(_) => true,
            _ => false
        }
    }

    /// Returns the explicit inner value.
    /// Returns [None] if [is_explicit] returns false.
    pub fn explicit(&self) -> Option<u64> {
        match *self {
            Value::Explicit(i) => Some(i),
            _ => None,
        }
    }

    /// Returns the confidential commitment in case of a confidential value.
    /// Returns [None] if [is_confidential] returns false.
    pub fn commitment(&self) -> Option<PedersenCommitment> {
        match *self {
            Value::Confidential(i) => Some(i),
            _ => None,
        }
    }
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Value::Null => f.write_str("null"),
            Value::Explicit(n) => write!(f, "{}", n),
            Value::Confidential(commitment) => write!(f, "{:02x}", commitment),
        }
    }
}

impl Default for Value {
    fn default() -> Self {
        Value::Null
    }
}

impl Encodable for Value {
    fn consensus_encode<S: io::Write>(&self, mut s: S) -> Result<usize, encode::Error> {
        match *self {
            Value::Null => 0u8.consensus_encode(s),
            Value::Explicit(n) => {
                1u8.consensus_encode(&mut s)?;
                Ok(1 + u64::swap_bytes(n).consensus_encode(&mut s)?)
            }
            Value::Confidential(commitment) => {
                s.write_all(&commitment.serialize())?;
                Ok(33)
            }
        }
    }
}

impl Decodable for Value {
    fn consensus_decode<D: io::BufRead>(mut d: D) -> Result<Value, encode::Error> {
        let prefix = {
            let buffer = d.fill_buf()?;

            if buffer.is_empty() {
                return Err(encode::Error::UnexpectedEOF);
            }

            buffer[0]
        };

        match prefix {
            0 => {
                // consume null value prefix
                d.consume(1);
                Ok(Value::Null)
            }
            1 => {
                // ignore prefix when decoding an explicit value
                d.consume(1);
                let explicit = u64::swap_bytes(Decodable::consensus_decode(&mut d)?);
                Ok(Value::Explicit(explicit))
            }
            p if p == 0x08 || p == 0x09 => {
                let bytes = <[u8; 33]>::consensus_decode(&mut d)?;
                Ok(Value::Confidential(PedersenCommitment::from_slice(&bytes)?))
            }
            p => Err(encode::Error::InvalidConfidentialPrefix(p)),
        }
    }
}

#[cfg(feature = "serde")]
impl Serialize for Value {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeSeq;

        let seq_len = if *self == Value::Null { 1 } else { 2 };
        let mut seq = s.serialize_seq(Some(seq_len))?;

        match *self {
            Value::Null => seq.serialize_element(&0u8)?,
            Value::Explicit(n) => {
                seq.serialize_element(&1u8)?;
                seq.serialize_element(&u64::swap_bytes(n))?;
            }
            Value::Confidential(commitment) => {
                seq.serialize_element(&commitment)?;
            }
        }
        seq.end()
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for Value {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        use serde::de::{Error, SeqAccess, Visitor};
        struct CommitVisitor;

        impl<'de> Visitor<'de> for CommitVisitor {
            type Value = Value;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a committed value")
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut access: A) -> Result<Value, A::Error> {
                let prefix: u8 = if let Some(x) = access.next_element()? {
                    x
                } else {
                    return Err(A::Error::custom("missing prefix"));
                };

                match prefix {
                    0 => Ok(Value::Null),
                    1 => match access.next_element()? {
                        Some(x) => Ok(Value::Explicit(u64::swap_bytes(x))),
                        None => Err(A::Error::custom("missing commitment")),
                    },
                    p if p == 0x08 || p == 0x09 => match access.next_element::<[u8; 32]>()? {
                        Some(y) => {
                            y.to_vec().insert(0, p);
                            Ok(Value::Confidential(
                                PedersenCommitment::from_slice(y.as_ref())
                                    .map_err(A::Error::custom)?,
                            ))
                        }
                        None => Err(A::Error::custom("missing commitment")),
                    },
                    p => Err(A::Error::custom(format!(
                        "invalid commitment, invalid prefix: 0x{:02x}",
                        p
                    ))),
                }
            }
        }

        d.deserialize_seq(CommitVisitor)
    }
}

/// A CT commitment to an asset
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
pub enum Asset {
    /// No value
    Null,
    /// Asset entropy is explicitly encoded
    Explicit(AssetId),
    /// Asset is committed
    Confidential(Generator),
}

impl Asset {
    /// Serialized length, in bytes
    pub fn encoded_length(&self) -> usize {
        match *self {
            Asset::Null => 1,
            Asset::Explicit(..) => 33,
            Asset::Confidential(..) => 33,
        }
    }

    /// Create from commitment.
    pub fn from_commitment(bytes: &[u8]) -> Result<Self, encode::Error> {
        Ok(Asset::Confidential(Generator::from_slice(bytes)?))
    }

    /// Check if the object is null.
    pub fn is_null(&self) -> bool {
        match *self {
            Asset::Null => true,
            _ => false
        }
    }

    /// Check if the object is explicit.
    pub fn is_explicit(&self) -> bool {
        match *self {
            Asset::Explicit(_) => true,
            _ => false
        }
    }

    /// Check if the object is confidential.
    pub fn is_confidential(&self) -> bool {
        match *self {
            Asset::Confidential(_) => true,
            _ => false
        }
    }

    /// Returns the explicit inner value.
    /// Returns [None] if [is_explicit] returns false.
    pub fn explicit(&self) -> Option<AssetId> {
        match *self {
            Asset::Explicit(i) => Some(i),
            _ => None,
        }
    }

    /// Returns the confidential commitment in case of a confidential value.
    /// Returns [None] if [is_confidential] returns false.
    pub fn commitment(&self) -> Option<Generator> {
        match *self {
            Asset::Confidential(i) => Some(i),
            _ => None,
        }
    }
}

impl fmt::Display for Asset {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Asset::Null => f.write_str("null"),
            Asset::Explicit(n) => write!(f, "{}", n),
            Asset::Confidential(generator) => write!(f, "{:02x}", generator),
        }
    }
}

impl Default for Asset {
    fn default() -> Self {
        Asset::Null
    }
}

impl Encodable for Asset {
    fn consensus_encode<S: io::Write>(&self, mut s: S) -> Result<usize, encode::Error> {
        match *self {
            Asset::Null => 0u8.consensus_encode(s),
            Asset::Explicit(n) => {
                1u8.consensus_encode(&mut s)?;
                Ok(1 + n.consensus_encode(&mut s)?)
            }
            Asset::Confidential(generator) => {
                s.write_all(&generator.serialize())?;
                Ok(33)
            }
        }
    }
}

impl Decodable for Asset {
    fn consensus_decode<D: io::BufRead>(mut d: D) -> Result<Self, encode::Error> {
        let prefix = {
            let buffer = d.fill_buf()?;

            if buffer.is_empty() {
                return Err(encode::Error::UnexpectedEOF);
            }

            buffer[0]
        };

        match prefix {
            0 => {
                // consume null value prefix
                d.consume(1);
                Ok(Asset::Null)
            }
            1 => {
                // ignore prefix when decoding an explicit asset
                d.consume(1);
                let explicit = Decodable::consensus_decode(&mut d)?;
                Ok(Asset::Explicit(explicit))
            }
            p if p == 0x0a || p == 0x0b => {
                let bytes = <[u8; 33]>::consensus_decode(&mut d)?;
                Ok(Asset::Confidential(Generator::from_slice(&bytes)?))
            }
            p => Err(encode::Error::InvalidConfidentialPrefix(p)),
        }
    }
}

#[cfg(feature = "serde")]
impl Serialize for Asset {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeSeq;

        let seq_len = if *self == Asset::Null { 1 } else { 2 };
        let mut seq = s.serialize_seq(Some(seq_len))?;

        match *self {
            Asset::Null => seq.serialize_element(&0u8)?,
            Asset::Explicit(n) => {
                seq.serialize_element(&1u8)?;
                seq.serialize_element(&n)?;
            }
            Asset::Confidential(commitment) => {
                seq.serialize_element(&commitment)?;
            }
        }
        seq.end()
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for Asset {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        use serde::de::{Error, SeqAccess, Visitor};
        struct CommitVisitor;

        impl<'de> Visitor<'de> for CommitVisitor {
            type Value = Asset;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a committed value")
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut access: A) -> Result<Asset, A::Error> {
                let prefix: u8 = if let Some(x) = access.next_element()? {
                    x
                } else {
                    return Err(A::Error::custom("missing prefix"));
                };

                match prefix {
                    0 => Ok(Asset::Null),
                    1 => match access.next_element()? {
                        Some(x) => Ok(Asset::Explicit(x)),
                        None => Err(A::Error::custom("missing commitment")),
                    },
                    p if p == 0x0a || p == 0x0b => match access.next_element::<[u8; 32]>()? {
                        Some(y) => {
                            y.to_vec().insert(0, p);
                            Ok(Asset::Confidential(
                                Generator::from_slice(y.as_ref()).map_err(A::Error::custom)?,
                            ))
                        }
                        None => Err(A::Error::custom("missing commitment")),
                    },
                    p => Err(A::Error::custom(format!(
                        "invalid commitment, invalid prefix: 0x{:02x}",
                        p
                    ))),
                }
            }
        }

        d.deserialize_seq(CommitVisitor)
    }
}

/// A CT commitment to an output nonce (i.e. a public key)
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub enum Nonce {
    /// No value
    Null,
    /// There should be no such thing as an "explicit nonce", but Elements will deserialize
    /// such a thing (and insists that its size be 32 bytes). So we stick a 32-byte type here
    /// that implements all the traits we need.
    Explicit([u8; 32]),
    /// Nonce is committed
    Confidential(PublicKey),
}

impl Nonce {
    /// Serialized length, in bytes
    pub fn encoded_length(&self) -> usize {
        match *self {
            Nonce::Null => 1,
            Nonce::Explicit(..) => 33,
            Nonce::Confidential(..) => 33,
        }
    }

    /// Create from commitment.
    pub fn from_commitment(bytes: &[u8]) -> Result<Self, encode::Error> {
        Ok(Nonce::Confidential(
            PublicKey::from_slice(bytes).map_err(secp256k1_zkp::Error::Upstream)?,
        ))
    }

    /// Check if the object is null.
    pub fn is_null(&self) -> bool {
        match *self {
            Nonce::Null => true,
            _ => false
        }
    }

    /// Check if the object is explicit.
    pub fn is_explicit(&self) -> bool {
        match *self {
            Nonce::Explicit(_) => true,
            _ => false
        }
    }

    /// Check if the object is confidential.
    pub fn is_confidential(&self) -> bool {
        match *self {
            Nonce::Confidential(_) => true,
            _ => false
        }
    }

    /// Returns the explicit inner value.
    /// Returns [None] if [is_explicit] returns false.
    pub fn explicit(&self) -> Option<[u8; 32]> {
        match *self {
            Nonce::Explicit(i) => Some(i),
            _ => None,
        }
    }

    /// Returns the confidential commitment in case of a confidential value.
    /// Returns [None] if [is_confidential] returns false.
    pub fn commitment(&self) -> Option<PublicKey> {
        match *self {
            Nonce::Confidential(i) => Some(i),
            _ => None,
        }
    }
}

impl fmt::Display for Nonce {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Nonce::Null => f.write_str("null"),
            Nonce::Explicit(n) => {
                for b in n.iter() {
                    write!(f, "{:02x}", b)?;
                }
                Ok(())
            }
            Nonce::Confidential(pk) => write!(f, "{:02x}", pk),
        }
    }
}

impl Default for Nonce {
    fn default() -> Self {
        Nonce::Null
    }
}

impl Encodable for Nonce {
    fn consensus_encode<S: io::Write>(&self, mut s: S) -> Result<usize, encode::Error> {
        match *self {
            Nonce::Null => 0u8.consensus_encode(s),
            Nonce::Explicit(n) => {
                1u8.consensus_encode(&mut s)?;
                Ok(1 + n.consensus_encode(&mut s)?)
            }
            Nonce::Confidential(commitment) => {
                s.write_all(&commitment.serialize())?;
                Ok(33)
            }
        }
    }
}

impl Decodable for Nonce {
    fn consensus_decode<D: io::BufRead>(mut d: D) -> Result<Self, encode::Error> {
        let prefix = {
            let buffer = d.fill_buf()?;

            if buffer.is_empty() {
                return Err(encode::Error::UnexpectedEOF);
            }

            buffer[0]
        };

        match prefix {
            0 => {
                // consume null value prefix
                d.consume(1);
                Ok(Nonce::Null)
            }
            1 => {
                // ignore prefix when decoding an explicit asset
                d.consume(1);
                let explicit = Decodable::consensus_decode(&mut d)?;
                Ok(Nonce::Explicit(explicit))
            }
            p if p == 0x02 || p == 0x03 => {
                let bytes = <[u8; 33]>::consensus_decode(&mut d)?;
                Ok(Nonce::Confidential(
                    PublicKey::from_slice(&bytes).map_err(secp256k1_zkp::Error::Upstream)?,
                ))
            }
            p => Err(encode::Error::InvalidConfidentialPrefix(p)),
        }
    }
}

#[cfg(feature = "serde")]
impl Serialize for Nonce {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeSeq;

        let seq_len = if *self == Nonce::Null { 1 } else { 2 };
        let mut seq = s.serialize_seq(Some(seq_len))?;

        match *self {
            Nonce::Null => seq.serialize_element(&0u8)?,
            Nonce::Explicit(n) => {
                seq.serialize_element(&1u8)?;
                seq.serialize_element(&n)?;
            }
            Nonce::Confidential(commitment) => {
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
                let prefix: u8 = if let Some(x) = access.next_element()? {
                    x
                } else {
                    return Err(A::Error::custom("missing prefix"));
                };

                match prefix {
                    0 => Ok(Nonce::Null),
                    1 => match access.next_element()? {
                        Some(x) => Ok(Nonce::Explicit(x)),
                        None => Err(A::Error::custom("missing commitment")),
                    },
                    p if p == 0x02 || p == 0x03 => match access.next_element::<[u8; 32]>()? {
                        Some(y) => {
                            y.to_vec().insert(0, p);
                            Ok(Nonce::Confidential(
                                PublicKey::from_slice(y.as_ref()).map_err(A::Error::custom)?,
                            ))
                        }
                        None => Err(A::Error::custom("missing commitment")),
                    },
                    p => Err(A::Error::custom(format!(
                        "invalid commitment, invalid prefix: 0x{:02x}",
                        p
                    ))),
                }
            }
        }

        d.deserialize_seq(CommitVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::sha256;

    #[test]
    fn encode_length() {
        let vals = [
            Value::Null,
            Value::Explicit(1000),
            Value::from_commitment(&[
                0x08, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                1, 1, 1, 1, 1, 1,
            ])
            .unwrap(),
        ];
        for v in &vals[..] {
            let mut x = vec![];
            assert_eq!(v.consensus_encode(&mut x).unwrap(), v.encoded_length());
            assert_eq!(x.len(), v.encoded_length());
        }

        let nonces = [
            Nonce::Null,
            Nonce::Explicit([0; 32]),
            Nonce::from_commitment(&[
                0x02, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                1, 1, 1, 1, 1, 1,
            ])
            .unwrap(),
        ];
        for v in &nonces[..] {
            let mut x = vec![];
            assert_eq!(v.consensus_encode(&mut x).unwrap(), v.encoded_length());
            assert_eq!(x.len(), v.encoded_length());
        }

        let assets = [
            Asset::Null,
            Asset::Explicit(AssetId::from_inner(sha256::Midstate::from_inner([0; 32]))),
            Asset::from_commitment(&[
                0x0a, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                1, 1, 1, 1, 1, 1,
            ])
            .unwrap(),
        ];
        for v in &assets[..] {
            let mut x = vec![];
            assert_eq!(v.consensus_encode(&mut x).unwrap(), v.encoded_length());
            assert_eq!(x.len(), v.encoded_length());
        }
    }

    #[test]
    fn commitments() {
        let x = Value::from_commitment(&[
            0x08, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 1, 1, 1,
        ])
        .unwrap();
        let commitment = x.commitment().unwrap();
        let mut commitment = commitment.serialize();
        assert_eq!(x, Value::from_commitment(&commitment[..]).unwrap());
        commitment[0] = 42;
        assert!(Value::from_commitment(&commitment[..]).is_err());

        let x = Asset::from_commitment(&[
            0x0a, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 1, 1, 1,
        ])
        .unwrap();
        let commitment = x.commitment().unwrap();
        let mut commitment = commitment.serialize();
        assert_eq!(x, Asset::from_commitment(&commitment[..]).unwrap());
        commitment[0] = 42;
        assert!(Asset::from_commitment(&commitment[..]).is_err());

        let x = Nonce::from_commitment(&[
            0x02, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 1, 1, 1,
        ])
        .unwrap();
        let commitment = x.commitment().unwrap();
        let mut commitment = commitment.serialize();
        assert_eq!(x, Nonce::from_commitment(&commitment[..]).unwrap());
        commitment[0] = 42;
        assert!(Nonce::from_commitment(&commitment[..]).is_err());
    }
}
