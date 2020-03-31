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

use bitcoin::hashes::sha256d;

use encode::{self, Encodable, Decodable};

// Helper macro to implement various things for the various confidential
// commitment types
macro_rules! impl_confidential_commitment {
    ($name:ident, $prefixA:expr, $prefixB:expr) => (
        impl_confidential_commitment!($name, $prefixA, $prefixB, |x|x);
    );
    ($name:ident, $prefixA:expr, $prefixB:expr, $explicit_fn:expr) => (
        impl Default for $name {
            fn default() -> Self {
                $name::Null
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                match *self {
                    $name::Null => f.write_str("null"),
                    $name::Explicit(n) => write!(f, "{}", n),
                    $name::Confidential(prefix, bytes) => {
                        write!(f, "{:02x}", prefix)?;
                        for b in bytes.iter() {
                            write!(f, "{:02x}", b)?;
                        }
                        Ok(())
                    }
                }
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
            fn consensus_decode<D: io::Read>(mut d: D) -> Result<$name, encode::Error> {
                let prefix = u8::consensus_decode(&mut d)?;
                match prefix {
                    0 => Ok($name::Null),
                    1 => {
                        // Apply $explicit_fn to allow `Value` to swap the amount bytes
                        let explicit = $explicit_fn(Decodable::consensus_decode(&mut d)?);
                        Ok($name::Explicit(explicit))
                    }
                    x => {
                        let commitment = <[u8; 32]>::consensus_decode(&mut d)?;
                        Ok($name::Confidential(x, commitment))
                    }
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
                            x => {
                                match access.next_element()? {
                                    Some(y) => Ok($name::Confidential(x, y)),
                                    None => Err(A::Error::custom("missing commitment")),
                                }
                            }
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
impl_confidential_commitment!(Value, 0x08, 0x09, u64::swap_bytes);

impl Value {
    /// Serialized length, in bytes
    pub fn encoded_length(&self) -> usize {
        match *self {
            Value::Null => 1,
            Value::Explicit(..) => 9,
            Value::Confidential(..) => 33,
        }
    }

    /// Check if the value is explicit.
    pub fn is_explicit(&self) -> bool {
        match *self {
            Value::Explicit(_) => true,
            _ => false,
        }
    }

    /// Returns the explicit value.
    /// Returns [None] if [is_explicit] returns false.
    pub fn explicit(&self) -> Option<u64> {
        match *self {
            Value::Explicit(v) => Some(v),
            _ => None,
        }
    }
}

/// A CT commitment to an asset
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub enum Asset {
    /// No value
    Null,
    /// Asset entropy is explicitly encoded
    Explicit(sha256d::Hash),
    /// Asset is committed
    Confidential(u8, [u8; 32]),
}
impl_confidential_commitment!(Asset, 0x0a, 0x0b);

impl Asset {
    /// Serialized length, in bytes
    pub fn encoded_length(&self) -> usize {
        match *self {
            Asset::Null => 1,
            Asset::Explicit(..) => 33,
            Asset::Confidential(..) => 33,
        }
    }

    /// Check if the asset is explicit.
    pub fn is_explicit(&self) -> bool {
        match *self {
            Asset::Explicit(_) => true,
            _ => false,
        }
    }

    /// Unwrap the explicit value of this type.
    /// Panics if [is_explicit] returns false.
    pub fn unwrap_explicit(&self) -> sha256d::Hash {
        match *self {
            Asset::Explicit(v) => v,
            _ => panic!("Called unwrap_explicit on non-explicit asset: {:?}", self),
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
    Explicit(sha256d::Hash),
    /// Nonce is committed
    Confidential(u8, [u8; 32]),
}
impl_confidential_commitment!(Nonce, 0x02, 0x03);

impl Nonce {
    /// Serialized length, in bytes
    pub fn encoded_length(&self) -> usize {
        match *self {
            Nonce::Null => 1,
            Nonce::Explicit(..) => 33,
            Nonce::Confidential(..) => 33,
        }
    }

    /// Check if the nonce is explicit.
    pub fn is_explicit(&self) -> bool {
        match *self {
            Nonce::Explicit(_) => true,
            _ => false,
        }
    }

    /// Unwrap the explicit value of this type.
    /// Panics if [is_explicit] returns false.
    pub fn unwrap_explicit(&self) -> sha256d::Hash {
        match *self {
            Nonce::Explicit(v) => v,
            _ => panic!("Called unwrap_explicit on non-explicit nonce: {:?}", self),
        }
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::hashes::Hash;
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
            Nonce::Explicit(sha256d::Hash::from_inner([0; 32])),
            Nonce::Confidential(0x02, [1; 32]),
        ];
        for v in &nonces[..] {
            let mut x = vec![];
            assert_eq!(v.consensus_encode(&mut x).unwrap(), v.encoded_length());
            assert_eq!(x.len(), v.encoded_length());
        }

        let assets = [
            Asset::Null,
            Asset::Explicit(sha256d::Hash::from_inner([0; 32])),
            Asset::Confidential(0x0a, [1; 32]),
        ];
        for v in &assets[..] {
            let mut x = vec![];
            assert_eq!(v.consensus_encode(&mut x).unwrap(), v.encoded_length());
            assert_eq!(x.len(), v.encoded_length());
        }
    }
}

