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

use std::fmt;

use bitcoin::network::encodable::{ConsensusEncodable, ConsensusDecodable};
use bitcoin::network::serialize::{self, SimpleEncoder, SimpleDecoder};
use bitcoin::util::hash::Sha256dHash;

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

        impl<S: SimpleEncoder> ConsensusEncodable<S> for $name {
            fn consensus_encode(&self, s: &mut S) -> Result<(), serialize::Error> {
                match *self {
                    $name::Null => 0u8.consensus_encode(s),
                    $name::Explicit(n) => {
                        1u8.consensus_encode(s)?;
                        // Apply $explicit_fn to allow `Value` to swap the amount bytes
                        $explicit_fn(n).consensus_encode(s)
                    }
                    $name::Confidential(prefix, bytes) => {
                        prefix.consensus_encode(s)?;
                        bytes.consensus_encode(s)
                    }
                }
            }
        }

        impl<D: SimpleDecoder> ConsensusDecodable<D> for $name {
            fn consensus_decode(d: &mut D) -> Result<$name, serialize::Error> {
                let prefix = u8::consensus_decode(d)?;
                match prefix {
                    0 => Ok($name::Null),
                    1 => {
                        // Apply $explicit_fn to allow `Value` to swap the amount bytes
                        let explicit = $explicit_fn(ConsensusDecodable::consensus_decode(d)?);
                        Ok($name::Explicit(explicit))
                    }
                    x => {
                        let commitment = <[u8; 32]>::consensus_decode(d)?;
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
}

/// A CT commitment to an asset
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub enum Asset {
    /// No value
    Null,
    /// Asset entropy is explicitly encoded
    Explicit(Sha256dHash),
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
}


/// A CT commitment to an output nonce (i.e. a public key)
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub enum Nonce {
    /// No value
    Null,
    /// There should be no such thing as an "explicit nonce", but Elements will deserialize
    /// such a thing (and insists that its size be 32 bytes). So we stick a 32-byte type here
    /// that implements all the traits we need.
    Explicit(Sha256dHash),
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
}

