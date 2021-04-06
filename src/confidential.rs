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

#[cfg(feature = "serde")]
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use std::{io, fmt};

use encode::{self, Encodable, Decodable};
use issuance::AssetId;

// Helper macro to implement various things for the various confidential
// commitment types
macro_rules! impl_confidential_commitment {
    ($name:ident, $inner:ty, $prefixA:expr, $prefixB:expr) => (
        impl_confidential_commitment!($name, $inner, $prefixA, $prefixB, |x|x);
    );
    ($name:ident, $inner:ty, $prefixA:expr, $prefixB:expr, $explicit_fn:expr) => (
        impl $name {
            /// Create from commitment.
            pub fn from_commitment(bytes: &[u8]) -> Result<$name, encode::Error> {
                if bytes.len() != 33 {
                    return Err(encode::Error::ParseFailed("commitments must be 33 bytes long"));
                }
                let prefix = bytes[0];
                if prefix != $prefixA && prefix != $prefixB {
                    return Err(encode::Error::InvalidConfidentialPrefix(prefix));
                }
                let mut c = [0; 32];
                c.copy_from_slice(&bytes[1..]);
                Ok($name::Confidential(prefix, c))
            }

            /// Check if the object is null.
            pub fn is_null(&self) -> bool {
                match *self {
                    $name::Null => true,
                    _ => false,
                }
            }

            /// Check if the object is explicit.
            pub fn is_explicit(&self) -> bool {
                match *self {
                    $name::Explicit(_) => true,
                    _ => false,
                }
            }

            /// Check if the object is confidential.
            pub fn is_confidential(&self) -> bool {
                match *self {
                    // Impossible to create an object with invalid prefix.
                    $name::Explicit(_) => true,
                    _ => false,
                }
            }

            /// Returns the explicit inner value.
            /// Returns [None] if [is_explicit] returns false.
            pub fn explicit(&self) -> Option<$inner> {
                match *self {
                    $name::Explicit(i) => Some(i),
                    _ => None,
                }
            }

            /// Returns the confidential commitment in case of a confidential value.
            /// Returns [None] if [is_confidential] returns false.
            pub fn commitment(&self) -> Option<[u8; 33]> {
                match *self {
                    $name::Confidential(p, c) => {
                        let mut res = [0; 33];
                        res[0] = p;
                        res[1..].copy_from_slice(&c[..]);
                        Some(res)
                    }
                    _ => None,
                }
            }
        }

        impl Default for $name {
            fn default() -> Self {
                $name::Null
            }
        }

        impl Encodable for $name {
            fn consensus_encode<S: io::Write>(&self, mut s: S) -> Result<usize, encode::Error> {
                match *self {
                    $name::Null => 0u8.consensus_encode(s),
                    $name::Explicit(n) => {
                        1u8.consensus_encode(&mut s)?;
                        // Apply $explicit_fn to allow `Value` to swap the amount bytes
                        Ok(1 + $explicit_fn(n).consensus_encode(&mut s)?)
                    }
                    $name::Confidential(prefix, bytes) => {
                        Ok(prefix.consensus_encode(&mut s)? + bytes.consensus_encode(&mut s)?)
                    }
                }
            }
        }

        impl Decodable for $name {
            fn consensus_decode<D: io::BufRead>(mut d: D) -> Result<$name, encode::Error> {
                let prefix = u8::consensus_decode(&mut d)?;
                match prefix {
                    0 => Ok($name::Null),
                    1 => {
                        // Apply $explicit_fn to allow `Value` to swap the amount bytes
                        let explicit = $explicit_fn(Decodable::consensus_decode(&mut d)?);
                        Ok($name::Explicit(explicit))
                    }
                    p if p == $prefixA || p == $prefixB => {
                        let commitment = <[u8; 32]>::consensus_decode(&mut d)?;
                        Ok($name::Confidential(p, commitment))
                    }
                    p => return Err(encode::Error::InvalidConfidentialPrefix(p)),
                }
            }
        }

        #[cfg(feature = "serde")]
        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                use serde::ser::SerializeSeq;

                let seq_len = if *self == $name::Null { 1 } else { 2 };
                let mut seq = s.serialize_seq(Some(seq_len))?;

                match *self {
                    $name::Null => seq.serialize_element(&0u8)?,
                    $name::Explicit(n) => {
                        seq.serialize_element(&1u8)?;
                        // Apply $explicit_fn to allow `Value` to swap the amount bytes
                        seq.serialize_element(&$explicit_fn(n))?;
                    }
                    $name::Confidential(prefix, bytes) => {
                        seq.serialize_element(&prefix)?;
                        seq.serialize_element(&bytes)?;
                    }
                }
                seq.end()
            }
        }

        #[cfg(feature = "serde")]
        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                use serde::de::{Error, Visitor, SeqAccess};
                struct CommitVisitor;

                impl <'de> Visitor<'de> for CommitVisitor {
                    type Value = $name;

                    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                        f.write_str("a committed value")
                    }

                    fn visit_seq<A: SeqAccess<'de>>(self, mut access: A) -> Result<Self::Value, A::Error> {
                        let prefix: u8 = if let Some(x) = access.next_element()? {
                            x
                        } else {
                            return Err(A::Error::custom("missing prefix"));
                        };

                        match prefix {
                            0 => Ok($name::Null),
                            1 => {
                                // Apply $explicit_fn to allow `Value` to swap the amount bytes
                                match access.next_element()? {
                                    Some(x) => Ok($name::Explicit($explicit_fn(x))),
                                    None => Err(A::Error::custom("missing commitment")),
                                }
                            }
                            p if p == $prefixA || p == $prefixB => {
                                match access.next_element()? {
                                    Some(y) => Ok($name::Confidential(p, y)),
                                    None => Err(A::Error::custom("missing commitment")),
                                }
                            }
                            p => return Err(A::Error::custom(format!(
                                "invalid commitment, invalid prefix: 0x{:02x}", p
                            ))),
                        }
                    }
                }

                d.deserialize_seq(CommitVisitor)
            }
        }
    );
}

/// A CT commitment to an amount
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub enum Value {
    /// No value
    Null,
    /// Value is explicitly encoded
    Explicit(u64),
    // Split commitments into a 1-byte prefix and 32-byte commitment, because
    // they're easy enough to separate and Rust stdlib treats 32-byte arrays
    // much much better than 33-byte arrays.
    /// Value is committed
    Confidential(u8, [u8; 32]),
}
impl_confidential_commitment!(Value, u64, 0x08, 0x09, u64::swap_bytes);

impl Value {
    /// Serialized length, in bytes
    pub fn encoded_length(&self) -> usize {
        match *self {
            Value::Null => 1,
            Value::Explicit(..) => 9,
            Value::Confidential(..) => 33,
        }
    }
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Value::Null => f.write_str("null"),
            Value::Explicit(n) => write!(f, "{}", n),
            Value::Confidential(prefix, bytes) => {
                write!(f, "{:02x}", prefix)?;
                for b in bytes.iter() {
                    write!(f, "{:02x}", b)?;
                }
                Ok(())
            }
        }
    }
}

/// A CT commitment to an asset
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub enum Asset {
    /// No value
    Null,
    /// Asset entropy is explicitly encoded
    Explicit(AssetId),
    /// Asset is committed
    Confidential(u8, [u8; 32]),
}
impl_confidential_commitment!(Asset, AssetId, 0x0a, 0x0b);

impl Asset {
    /// Serialized length, in bytes
    pub fn encoded_length(&self) -> usize {
        match *self {
            Asset::Null => 1,
            Asset::Explicit(..) => 33,
            Asset::Confidential(..) => 33,
        }
    }
}

impl fmt::Display for Asset {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Asset::Null => f.write_str("null"),
            Asset::Explicit(n) => write!(f, "{}", n),
            Asset::Confidential(prefix, bytes) => {
                write!(f, "{:02x}", prefix)?;
                for b in bytes.iter() {
                    write!(f, "{:02x}", b)?;
                }
                Ok(())
            }
        }
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
    Confidential(u8, [u8; 32]),
}
impl_confidential_commitment!(Nonce, [u8; 32], 0x02, 0x03);

impl Nonce {
    /// Serialized length, in bytes
    pub fn encoded_length(&self) -> usize {
        match *self {
            Nonce::Null => 1,
            Nonce::Explicit(..) => 33,
            Nonce::Confidential(..) => 33,
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
            },
            Nonce::Confidential(prefix, bytes) => {
                write!(f, "{:02x}", prefix)?;
                for b in bytes.iter() {
                    write!(f, "{:02x}", b)?;
                }
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::hashes::sha256;
    use super::*;

    #[test]
    fn encode_length() {
        let vals = [
            Value::Null,
            Value::Explicit(1000),
            Value::Confidential(0x08, [1; 32]),
        ];
        for v in &vals[..] {
            let mut x = vec![];
            assert_eq!(v.consensus_encode(&mut x).unwrap(), v.encoded_length());
            assert_eq!(x.len(), v.encoded_length());
        }

        let nonces = [
            Nonce::Null,
            Nonce::Explicit([0; 32]),
            Nonce::Confidential(0x02, [1; 32]),
        ];
        for v in &nonces[..] {
            let mut x = vec![];
            assert_eq!(v.consensus_encode(&mut x).unwrap(), v.encoded_length());
            assert_eq!(x.len(), v.encoded_length());
        }

        let assets = [
            Asset::Null,
            Asset::Explicit(AssetId::from_inner(sha256::Midstate::from_inner([0; 32]))),
            Asset::Confidential(0x0a, [1; 32]),
        ];
        for v in &assets[..] {
            let mut x = vec![];
            assert_eq!(v.consensus_encode(&mut x).unwrap(), v.encoded_length());
            assert_eq!(x.len(), v.encoded_length());
        }
    }

    #[test]
    fn commitments() {
        let x = Value::Confidential(0x08, [1; 32]);
        let mut commitment = x.commitment().unwrap();
        assert_eq!(x, Value::from_commitment(&commitment[..]).unwrap());
        commitment[0] = 42;
        assert!(Value::from_commitment(&commitment[..]).is_err());

        let x = Asset::Confidential(0x0a, [1; 32]);
        let mut commitment = x.commitment().unwrap();
        assert_eq!(x, Asset::from_commitment(&commitment[..]).unwrap());
        commitment[0] = 42;
        assert!(Asset::from_commitment(&commitment[..]).is_err());

        let x = Nonce::Confidential(0x02, [1; 32]);
        let mut commitment = x.commitment().unwrap();
        assert_eq!(x, Nonce::from_commitment(&commitment[..]).unwrap());
        commitment[0] = 42;
        assert!(Nonce::from_commitment(&commitment[..]).is_err());
    }

    #[cfg(feature = "serde")]
    #[test]
    fn value_serde() {
        use serde_test::{assert_tokens, Token};

        let value = Value::Explicit(100_000_000);
        assert_tokens(
            &value,
            &[
                Token::Seq { len: Some(2) },
                Token::U8(1),
                Token::U64(63601271583539200),
                Token::SeqEnd
            ]
        );

        let value = Value::from_commitment(&[
            0x08,
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        ]).unwrap();

        assert_tokens(
            &value,
            &[
                Token::Seq { len: Some(2) },
                Token::U8(8),
                Token::Tuple { len: 32 },
                Token::U8(1), Token::U8(1), Token::U8(1), Token::U8(1),
                Token::U8(1), Token::U8(1), Token::U8(1), Token::U8(1),
                Token::U8(1), Token::U8(1), Token::U8(1), Token::U8(1),
                Token::U8(1), Token::U8(1), Token::U8(1), Token::U8(1),
                Token::U8(1), Token::U8(1), Token::U8(1), Token::U8(1),
                Token::U8(1), Token::U8(1), Token::U8(1), Token::U8(1),
                Token::U8(1), Token::U8(1), Token::U8(1), Token::U8(1),
                Token::U8(1), Token::U8(1), Token::U8(1), Token::U8(1),
                Token::TupleEnd,
                Token::SeqEnd
            ]
        );

        let value = Value::Null;
        assert_tokens(
            &value,
            &[
                Token::Seq { len: Some(1) },
                Token::U8(0),
                Token::SeqEnd
            ]
        );
    }

    #[cfg(feature = "serde")]
    #[test]
    fn asset_serde() {
        use bitcoin::hashes::hex::FromHex;
        use serde_test::{assert_tokens, Configure, Token};

        let asset_id = AssetId::from_hex(
            "630ed6f9b176af03c0cd3f8aa430f9e7b4d988cf2d0b2f204322488f03b00bf8"
        ).unwrap();
        let asset = Asset::Explicit(asset_id);
        assert_tokens(
            &asset.readable(),
            &[
                Token::Seq { len: Some(2) },
                Token::U8(1),
                Token::Str(
                    "630ed6f9b176af03c0cd3f8aa430f9e7b4d988cf2d0b2f204322488f03b00bf8"
                ),
                Token::SeqEnd
            ]
        );
        assert_tokens(
            &asset.compact(),
            &[
                Token::Seq { len: Some(2) },
                Token::U8(1),
                Token::Bytes(
                    &[
                        248, 11, 176, 3, 143, 72, 34, 67, 32, 47, 11, 45, 207, 136, 217, 180,
                        231, 249, 48, 164, 138, 63, 205, 192, 3, 175, 118, 177, 249, 214, 14, 99
                    ]
                ),
                Token::SeqEnd
            ]
        );

        let asset = Asset::from_commitment(&[
            0x0a,
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        ]).unwrap();
        assert_tokens(
            &asset,
            &[
                Token::Seq { len: Some(2) },
                Token::U8(10),
                Token::Tuple { len: 32 },
                Token::U8(1), Token::U8(1), Token::U8(1), Token::U8(1),
                Token::U8(1), Token::U8(1), Token::U8(1), Token::U8(1),
                Token::U8(1), Token::U8(1), Token::U8(1), Token::U8(1),
                Token::U8(1), Token::U8(1), Token::U8(1), Token::U8(1),
                Token::U8(1), Token::U8(1), Token::U8(1), Token::U8(1),
                Token::U8(1), Token::U8(1), Token::U8(1), Token::U8(1),
                Token::U8(1), Token::U8(1), Token::U8(1), Token::U8(1),
                Token::U8(1), Token::U8(1), Token::U8(1), Token::U8(1),
                Token::TupleEnd,
                Token::SeqEnd
            ]
        );

        let asset = Asset::Null;
        assert_tokens(
            &asset,
            &[
                Token::Seq { len: Some(1) },
                Token::U8(0),
                Token::SeqEnd
            ]
        );
    }

    #[cfg(feature = "serde")]
    #[test]
    fn nonce_serde() {
        use serde_test::{assert_tokens, Token};

        let nonce = Nonce::Explicit([
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        ]);
        assert_tokens(
            &nonce,
            &[
                Token::Seq { len: Some(2) },
                Token::U8(1),
                Token::Tuple { len: 32 },
                Token::U8(1), Token::U8(1), Token::U8(1), Token::U8(1),
                Token::U8(1), Token::U8(1), Token::U8(1), Token::U8(1),
                Token::U8(1), Token::U8(1), Token::U8(1), Token::U8(1),
                Token::U8(1), Token::U8(1), Token::U8(1), Token::U8(1),
                Token::U8(1), Token::U8(1), Token::U8(1), Token::U8(1),
                Token::U8(1), Token::U8(1), Token::U8(1), Token::U8(1),
                Token::U8(1), Token::U8(1), Token::U8(1), Token::U8(1),
                Token::U8(1), Token::U8(1), Token::U8(1), Token::U8(1),
                Token::TupleEnd,
                Token::SeqEnd
            ]
        );

        let nonce = Nonce::from_commitment(&[
            0x02,
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        ]).unwrap();
        assert_tokens(
            &nonce,
            &[
                Token::Seq { len: Some(2) },
                Token::U8(2),
                Token::Tuple { len: 32 },
                Token::U8(1), Token::U8(1), Token::U8(1), Token::U8(1),
                Token::U8(1), Token::U8(1), Token::U8(1), Token::U8(1),
                Token::U8(1), Token::U8(1), Token::U8(1), Token::U8(1),
                Token::U8(1), Token::U8(1), Token::U8(1), Token::U8(1),
                Token::U8(1), Token::U8(1), Token::U8(1), Token::U8(1),
                Token::U8(1), Token::U8(1), Token::U8(1), Token::U8(1),
                Token::U8(1), Token::U8(1), Token::U8(1), Token::U8(1),
                Token::U8(1), Token::U8(1), Token::U8(1), Token::U8(1),
                Token::TupleEnd,
                Token::SeqEnd
            ]
        );

        let nonce = Nonce::Null;
        assert_tokens(
            &nonce,
            &[
                Token::Seq { len: Some(1) },
                Token::U8(0),
                Token::SeqEnd
            ]
        );
    }
}
