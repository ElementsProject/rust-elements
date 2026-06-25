// SPDX-License-Identifier: MIT OR Apache-2.0

//! Confiential Assets

use core::{fmt, str};
use std::io;

use secp256k1_zkp::{self, Generator, Secp256k1, Signing, Tweak, ZERO_TWEAK};
use secp256k1_zkp::rand::Rng;
#[cfg(feature = "serde")]
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::encode::{self, Decodable, Encodable};
use crate::issuance::AssetId;

/// A CT commitment to an asset
#[derive(Copy, Clone, Debug, Default, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub enum Asset {
    /// No value
    #[default]
    Null,
    /// Asset entropy is explicitly encoded
    Explicit(AssetId),
    /// Asset is committed
    Confidential(Generator),
}

impl Asset {
    /// Create asset commitment.
    pub fn new_confidential<C: Signing>(
        secp: &Secp256k1<C>,
        asset: AssetId,
        bf: AssetBlindingFactor,
    ) -> Self {
        Asset::Confidential(Generator::new_blinded(
            secp,
            asset.into_tag(),
            bf.into_inner(),
        ))
    }

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
        matches!(*self, Asset::Null)
    }

    /// Check if the object is explicit.
    pub fn is_explicit(&self) -> bool {
        matches!(*self, Asset::Explicit(_))
    }

    /// Check if the object is confidential.
    pub fn is_confidential(&self) -> bool {
        matches!(*self, Asset::Confidential(_))
    }

    /// Returns the explicit inner value.
    /// Returns [None] if [`Asset::is_explicit`] returns false.
    pub fn explicit(&self) -> Option<AssetId> {
        match *self {
            Asset::Explicit(i) => Some(i),
            _ => None,
        }
    }

    /// Returns the confidential commitment in case of a confidential value.
    /// Returns [None] if [`Asset::is_confidential`] returns false.
    pub fn commitment(&self) -> Option<Generator> {
        match *self {
            Asset::Confidential(i) => Some(i),
            _ => None,
        }
    }

    /// Internally used function for getting the generator from asset
    /// Used in the amount verification check
    /// Returns [`None`] is the asset is [`Asset::Null`]
    /// Converts a explicit asset into a generator and returns the confidential
    /// generator as is.
    pub fn into_asset_gen<C: secp256k1_zkp::Signing> (
        self,
        secp: &Secp256k1<C>,
    ) -> Option<Generator> {
        match self {
            // Only error is Null error which is dealt with later
            // when we have more context information about it.
            Asset::Null => None,
            Asset::Explicit(x) => {
                Some(Generator::new_unblinded(secp, x.into_tag()))
            }
            Asset::Confidential(gen) => Some(gen),
        }
    }
}

impl From<Generator> for Asset {
    fn from(from: Generator) -> Self {
        Asset::Confidential(from)
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
    fn consensus_decode<D: io::Read>(mut d: D) -> Result<Self, encode::Error> {
        let prefix = u8::consensus_decode(&mut d)?;

        match prefix {
            0 => Ok(Asset::Null),
            1 => {
                let explicit = Decodable::consensus_decode(&mut d)?;
                Ok(Asset::Explicit(explicit))
            }
            p if p == 0x0a || p == 0x0b => {
                let mut comm = [0u8; 33];
                comm[0] = p;
                d.read_exact(&mut comm[1..])?;
                Ok(Asset::Confidential(Generator::from_slice(&comm[..])?))
            }
            p => Err(encode::Error::InvalidConfidentialPrefix(p)),
        }
    }
}

#[cfg(feature = "serde")]
impl Serialize for Asset {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeSeq;

        let seq_len = match *self {
            Asset::Null => 1,
            Asset::Explicit(_) | Asset::Confidential(_) => 2
        };
        let mut seq = s.serialize_seq(Some(seq_len))?;

        match *self {
            Asset::Null => seq.serialize_element(&0u8)?,
            Asset::Explicit(n) => {
                seq.serialize_element(&1u8)?;
                seq.serialize_element(&n)?;
            }
            Asset::Confidential(commitment) => {
                seq.serialize_element(&2u8)?;
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
                let prefix = access.next_element::<u8>()?;
                match prefix {
                    Some(0) => Ok(Asset::Null),
                    Some(1) => {
                        match access.next_element()? {
                            Some(x) => Ok(Asset::Explicit(x)),
                            None => Err(A::Error::custom("missing explicit asset")),
                        }
                    }
                    Some(2) => {
                        match access.next_element()? {
                            Some(x) => Ok(Asset::Confidential(x)),
                            None => Err(A::Error::custom("missing generator")),
                        }
                    }
                    _ => Err(A::Error::custom("wrong or missing prefix")),
                }
            }
        }

        d.deserialize_seq(CommitVisitor)
    }
}


/// Blinding factor used for asset commitments.
#[derive(Copy, Clone, Eq, PartialEq, PartialOrd, Ord, Hash)]
pub struct AssetBlindingFactor(pub(crate) Tweak);

impl AssetBlindingFactor {
    /// Generate random asset blinding factor.
    pub fn new<R: Rng>(rng: &mut R) -> Self {
        AssetBlindingFactor(Tweak::new(rng))
    }

    /// Parse a blinding factor from a 64-character hex string.
    #[deprecated(since = "0.27.0", note = "use s.parse() instead")]
    pub fn from_hex(s: &str) -> Result<Self, encode::Error> {
        s.parse()
    }

    /// Create from bytes.
    pub fn from_byte_array(bytes: [u8; 32]) -> Result<Self, secp256k1_zkp::Error> {
        Ok(AssetBlindingFactor(Tweak::from_inner(bytes)?))
    }

    /// Create from bytes.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, secp256k1_zkp::Error> {
        Ok(AssetBlindingFactor(Tweak::from_slice(bytes)?))
    }

    /// Returns the inner value.
    pub fn into_inner(self) -> Tweak {
        self.0
    }

    /// Get a unblinded/zero `AssetBlinding` factor
    pub fn zero() -> Self {
        AssetBlindingFactor(ZERO_TWEAK)
    }
}

impl core::borrow::Borrow<[u8]> for AssetBlindingFactor {
    fn borrow(&self) -> &[u8] { &self.0[..] }
}

hex::impl_fmt_traits! {
    #[display_backward(true)]
    impl fmt_traits for AssetBlindingFactor {
        const LENGTH: usize = 32;
    }
}

impl str::FromStr for AssetBlindingFactor {
    type Err = encode::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut slice: [u8; 32] = hex::decode_to_array(s)?;
        slice.reverse();

        let inner = Tweak::from_inner(slice)?;
        Ok(AssetBlindingFactor(inner))
    }
}

#[cfg(feature = "serde")]
impl Serialize for AssetBlindingFactor {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            s.collect_str(&self)
        } else {
            s.serialize_bytes(&self.0[..])
        }
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for AssetBlindingFactor {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<AssetBlindingFactor, D::Error> {
        if d.is_human_readable() {
            struct HexVisitor;

            impl ::serde::de::Visitor<'_> for HexVisitor {
                type Value = AssetBlindingFactor;

                fn expecting(&self, formatter: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
                    formatter.write_str("an ASCII hex string")
                }

                fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
                where
                    E: ::serde::de::Error,
                {
                    if let Ok(hex) = ::std::str::from_utf8(v) {
                        hex.parse().map_err(E::custom)
                    } else {
                        Err(E::invalid_value(::serde::de::Unexpected::Bytes(v), &self))
                    }
                }

                fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
                where
                    E: ::serde::de::Error,
                {
                    v.parse().map_err(E::custom)
                }
            }

            d.deserialize_str(HexVisitor)
        } else {
            struct BytesVisitor;

            impl ::serde::de::Visitor<'_> for BytesVisitor {
                type Value = AssetBlindingFactor;

                fn expecting(&self, formatter: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
                    formatter.write_str("a bytestring")
                }

                fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
                where
                    E: ::serde::de::Error,
                {
                    use core::convert::TryFrom;

                    match <[u8; 32]>::try_from(v) {
                        Ok(ret) => {
                            let inner = Tweak::from_inner(ret).map_err(E::custom)?;
                            Ok(AssetBlindingFactor(inner))
                        }
                        Err(_) => Err(E::invalid_length(v.len(), &stringify!($len))),
                    }
                }
            }

            d.deserialize_bytes(BytesVisitor)
        }
    }
}

