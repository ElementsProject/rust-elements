// SPDX-License-Identifier: MIT OR Apache-2.0

//! Confiential Values

use core::ops::{AddAssign, Neg};
use core::{fmt, str};
use std::io;

use secp256k1_zkp::rand::Rng;
use secp256k1_zkp::{
    self, compute_adaptive_blinding_factor, CommitmentSecrets, Generator, PedersenCommitment,
    Secp256k1, SecretKey, Signing, Tweak, ZERO_TWEAK,
};
#[cfg(feature = "serde")]
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::confidential::AssetBlindingFactor;
use crate::encode::{self, Decodable, Encodable};
use crate::issuance::AssetId;

type ExplicitInner = u64;
type ConfInner = PedersenCommitment;

const EXPLICIT_LEN: usize = 8;
const CONFIDENTIAL_LEN: usize = 33;
const CONF_PREFIX_1: u8 = 0x08;
const CONF_PREFIX_2: u8 = 0x09;

/// A CT commitment to an amount
#[derive(Copy, Clone, Debug, Default, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub enum Value {
    /// No value
    #[default]
    Null,
    /// Value is explicitly encoded
    Explicit(ExplicitInner),
    /// Value is committed
    Confidential(ConfInner),
}

impl Value {
    /// Create value commitment.
    pub fn new_confidential<C: Signing>(
        secp: &Secp256k1<C>,
        value: u64,
        asset: Generator,
        bf: BlindingFactor,
    ) -> Self {
        Self::Confidential(ConfInner::new(secp, value, bf.0, asset))
    }

    /// Create value commitment from assetID, asset blinding factor,
    /// value and value blinding factor
    pub fn new_confidential_from_assetid<C: Signing>(
        secp: &Secp256k1<C>,
        value: u64,
        asset: AssetId,
        v_bf: BlindingFactor,
        a_bf: AssetBlindingFactor,
    ) -> Self {
        let generator = Generator::new_blinded(secp, asset.into_tag(), a_bf.0);
        let comm = ConfInner::new(secp, value, v_bf.0, generator);

        Self::Confidential(comm)
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
        Ok(Self::Confidential(ConfInner::from_slice(bytes)?))
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

impl From<ConfInner> for Value {
    fn from(from: ConfInner) -> Self { Self::Confidential(from) }
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Self::Null => f.write_str("null"),
            Self::Explicit(n) => write!(f, "{}", n),
            Self::Confidential(commitment) => write!(f, "{:02x}", commitment),
        }
    }
}

impl Encodable for Value {
    fn consensus_encode<S: io::Write>(&self, mut s: S) -> Result<usize, encode::Error> {
        match *self {
            Self::Null => {
                s.write_all(&[0u8])?;
                Ok(1)
            }
            Self::Explicit(n) => {
                s.write_all(&[1u8])?;
                s.write_all(&n.to_be_bytes())?;
                Ok(1 + EXPLICIT_LEN)
            }
            Self::Confidential(commitment) => {
                s.write_all(&commitment.serialize())?;
                Ok(CONFIDENTIAL_LEN)
            }
        }
    }
}

impl Decodable for Value {
    fn consensus_decode<D: io::Read>(mut d: D) -> Result<Self, encode::Error> {
        let mut buf = [0u8; CONFIDENTIAL_LEN];
        d.read_exact(&mut buf[0..1])?;

        match buf[0] {
            0 => Ok(Self::Null),
            1 => {
                let mut buf = [0; EXPLICIT_LEN];
                d.read_exact(&mut buf)?;
                Ok(Self::Explicit(u64::from_be_bytes(buf)))
            }
            p if p == CONF_PREFIX_1 || p == CONF_PREFIX_2 => {
                d.read_exact(&mut buf[1..])?;
                Ok(Self::Confidential(ConfInner::from_slice(&buf)?))
            }
            p => Err(encode::Error::InvalidConfidentialPrefix(p)),
        }
    }
}

#[cfg(feature = "serde")]
impl Serialize for Value {
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
                seq.serialize_element(&u64::swap_bytes(n))?;
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
impl<'de> Deserialize<'de> for Value {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        use serde::de::{Error, SeqAccess, Visitor};
        struct CommitVisitor;

        impl<'de> Visitor<'de> for CommitVisitor {
            type Value = Value;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a committed value")
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut access: A) -> Result<Self::Value, A::Error> {
                let prefix = access.next_element::<u8>()?;
                match prefix {
                    Some(0) => Ok(Self::Value::Null),
                    Some(1) => match access.next_element()? {
                        Some(x) => Ok(Self::Value::Explicit(u64::swap_bytes(x))),
                        None => Err(A::Error::custom("missing explicit value")),
                    },
                    Some(2) => match access.next_element()? {
                        Some(x) => Ok(Self::Value::Confidential(x)),
                        None => Err(A::Error::custom("missing pedersen commitment")),
                    },
                    _ => Err(A::Error::custom("wrong or missing prefix")),
                }
            }
        }

        d.deserialize_seq(CommitVisitor)
    }
}

/// Blinding factor used for value commitments.
#[derive(Copy, Clone, Eq, PartialEq, PartialOrd, Ord, Hash)]
pub struct BlindingFactor(pub(crate) Tweak);

impl BlindingFactor {
    /// Generate random value blinding factor.
    pub fn new<R: Rng>(rng: &mut R) -> Self { Self(Tweak::new(rng)) }

    /// Parse a blinding factor from a 64-character hex string.
    #[deprecated(since = "0.27.0", note = "use s.parse() instead")]
    pub fn from_hex(s: &str) -> Result<Self, encode::Error> { s.parse() }

    /// Create the value blinding factor of the last output of a transaction.
    pub fn last<C: Signing>(
        secp: &Secp256k1<C>,
        value: u64,
        abf: AssetBlindingFactor,
        inputs: &[(u64, AssetBlindingFactor, Self)],
        outputs: &[(u64, AssetBlindingFactor, Self)],
    ) -> Self {
        let set_a = inputs
            .iter()
            .map(|(value, abf, vbf)| CommitmentSecrets {
                value: *value,
                value_blinding_factor: vbf.0,
                generator_blinding_factor: abf.into_inner(),
            })
            .collect::<Vec<_>>();
        let set_b = outputs
            .iter()
            .map(|(value, abf, vbf)| CommitmentSecrets {
                value: *value,
                value_blinding_factor: vbf.0,
                generator_blinding_factor: abf.into_inner(),
            })
            .collect::<Vec<_>>();

        Self(compute_adaptive_blinding_factor(secp, value, abf.0, &set_a, &set_b))
    }

    /// Create from bytes.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, secp256k1_zkp::Error> {
        Ok(Self(Tweak::from_slice(bytes)?))
    }

    /// Returns the inner value.
    pub fn into_inner(self) -> Tweak { self.0 }

    /// Get a unblinded/zero `AssetBlinding` factor
    pub fn zero() -> Self { Self(ZERO_TWEAK) }
}

impl AddAssign for BlindingFactor {
    fn add_assign(&mut self, other: Self) {
        if self.0.as_ref() == &[0u8; 32] {
            *self = other;
        } else if other.0.as_ref() == &[0u8; 32] {
            // nothing to do
        } else {
            // Since libsecp does not expose low level APIs
            // for scalar arethematic, we need to abuse secret key
            // operations for this
            let sk2 = SecretKey::from_slice(self.into_inner().as_ref()).expect("Valid key");
            let sk = SecretKey::from_slice(other.into_inner().as_ref()).expect("Valid key");
            // The only reason that secret key addition can fail
            // is when the keys add up to zero since we have already checked
            // keys are in valid secret keys
            match sk.add_tweak(&sk2.into()) {
                Ok(sk_tweaked) =>
                    *self = Self::from_slice(sk_tweaked.as_ref()).expect("Valid Tweak"),
                Err(_) => *self = Self::zero(),
            }
        }
    }
}

impl Neg for BlindingFactor {
    type Output = Self;

    fn neg(self) -> Self::Output {
        if self.0.as_ref() == &[0u8; 32] {
            self
        } else {
            let sk = SecretKey::from_slice(self.into_inner().as_ref()).expect("Valid key").negate();
            Self::from_slice(sk.as_ref()).expect("Valid Tweak")
        }
    }
}

impl core::borrow::Borrow<[u8]> for BlindingFactor {
    fn borrow(&self) -> &[u8] { &self.0[..] }
}

hex::impl_fmt_traits! {
    #[display_backward(true)]
    impl fmt_traits for BlindingFactor {
        const LENGTH: usize = 32;
    }
}

impl str::FromStr for BlindingFactor {
    type Err = encode::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut slice: [u8; 32] = hex::decode_to_array(s)?;
        slice.reverse();

        let inner = Tweak::from_inner(slice)?;
        Ok(Self(inner))
    }
}

#[cfg(feature = "serde")]
impl Serialize for BlindingFactor {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            s.collect_str(&self)
        } else {
            s.serialize_bytes(&self.0[..])
        }
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for BlindingFactor {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        if d.is_human_readable() {
            struct HexVisitor;

            impl ::serde::de::Visitor<'_> for HexVisitor {
                type Value = BlindingFactor;

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
                type Value = BlindingFactor;

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
                            Ok(BlindingFactor(inner))
                        }
                        Err(_) => Err(E::invalid_length(v.len(), &stringify!($len))),
                    }
                }
            }

            d.deserialize_bytes(BytesVisitor)
        }
    }
}
