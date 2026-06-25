// SPDX-License-Identifier: MIT OR Apache-2.0

//! Confiential Values

use core::{fmt, ops::{AddAssign, Neg}, str};
use std::io;

use secp256k1_zkp::{self, CommitmentSecrets, PedersenCommitment, Generator, Secp256k1, SecretKey, Signing, Tweak, ZERO_TWEAK};
use secp256k1_zkp::compute_adaptive_blinding_factor;
use secp256k1_zkp::rand::Rng;
#[cfg(feature = "serde")]
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::confidential::{AssetBlindingFactor};
use crate::encode::{self, Decodable, Encodable};
use crate::issuance::AssetId;

/// A CT commitment to an amount
#[derive(Copy, Clone, Debug, Default, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub enum Value {
    /// No value
    #[default]
    Null,
    /// Value is explicitly encoded
    Explicit(u64),
    /// Value is committed
    Confidential(PedersenCommitment),
}

impl Value {
    /// Create value commitment.
    pub fn new_confidential<C: Signing>(
        secp: &Secp256k1<C>,
        value: u64,
        asset: Generator,
        bf: ValueBlindingFactor,
    ) -> Self {
        Value::Confidential(PedersenCommitment::new(secp, value, bf.0, asset))
    }

    /// Create value commitment from assetID, asset blinding factor,
    /// value and value blinding factor
    pub fn new_confidential_from_assetid<C: Signing>(
        secp: &Secp256k1<C>,
        value: u64,
        asset: AssetId,
        v_bf: ValueBlindingFactor,
        a_bf: AssetBlindingFactor,
    ) -> Self {
        let generator = Generator::new_blinded(secp, asset.into_tag(), a_bf.0);
        let comm = PedersenCommitment::new(secp, value, v_bf.0, generator);

        Value::Confidential(comm)
    }

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
        matches!(*self, Value::Null)
    }

    /// Check if the object is explicit.
    pub fn is_explicit(&self) -> bool {
        matches!(*self, Value::Explicit(_))
    }

    /// Check if the object is confidential.
    pub fn is_confidential(&self) -> bool {
        matches!(*self, Value::Confidential(_))
    }

    /// Returns the explicit inner value.
    /// Returns [None] if [`Value::is_explicit`] returns false.
    pub fn explicit(&self) -> Option<u64> {
        match *self {
            Value::Explicit(i) => Some(i),
            _ => None,
        }
    }

    /// Returns the confidential commitment in case of a confidential value.
    /// Returns [None] if [`Value::is_confidential`] returns false.
    pub fn commitment(&self) -> Option<PedersenCommitment> {
        match *self {
            Value::Confidential(i) => Some(i),
            _ => None,
        }
    }
}

impl From<PedersenCommitment> for Value {
    fn from(from: PedersenCommitment) -> Self {
        Value::Confidential(from)
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
    fn consensus_decode<D: io::Read>(mut d: D) -> Result<Value, encode::Error> {
        let prefix = u8::consensus_decode(&mut d)?;

        match prefix {
            0 => Ok(Value::Null),
            1 => {
                let explicit = u64::swap_bytes(Decodable::consensus_decode(&mut d)?);
                Ok(Value::Explicit(explicit))
            }
            p if p == 0x08 || p == 0x09 => {
                let mut comm = [0u8; 33];
                comm[0] = p;
                d.read_exact(&mut comm[1..])?;
                Ok(Value::Confidential(PedersenCommitment::from_slice(&comm)?))
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
            Value::Null => 1,
            Value::Explicit(_) | Value::Confidential(_) => 2
        };
        let mut seq = s.serialize_seq(Some(seq_len))?;

        match *self {
            Value::Null => seq.serialize_element(&0u8)?,
            Value::Explicit(n) => {
                seq.serialize_element(&1u8)?;
                seq.serialize_element(&u64::swap_bytes(n))?;
            }
            Value::Confidential(commitment) => {
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
                    Some(0) => Ok(Value::Null),
                    Some(1) => {
                        match access.next_element()? {
                            Some(x) => Ok(Value::Explicit(u64::swap_bytes(x))),
                            None => Err(A::Error::custom("missing explicit value")),
                        }
                    }
                    Some(2) => {
                        match access.next_element()? {
                            Some(x) => Ok(Value::Confidential(x)),
                            None => Err(A::Error::custom("missing pedersen commitment")),
                        }
                    }
                    _ => Err(A::Error::custom("wrong or missing prefix")),
                }
            }
        }

        d.deserialize_seq(CommitVisitor)
    }
}

/// Blinding factor used for value commitments.
#[derive(Copy, Clone, Eq, PartialEq, PartialOrd, Ord, Hash)]
pub struct ValueBlindingFactor(pub(crate) Tweak);

impl ValueBlindingFactor {
    /// Generate random value blinding factor.
    pub fn new<R: Rng>(rng: &mut R) -> Self {
        ValueBlindingFactor(Tweak::new(rng))
    }

    /// Parse a blinding factor from a 64-character hex string.
    #[deprecated(since = "0.27.0", note = "use s.parse() instead")]
    pub fn from_hex(s: &str) -> Result<Self, encode::Error> {
        s.parse()
    }

    /// Create the value blinding factor of the last output of a transaction.
    pub fn last<C: Signing>(
        secp: &Secp256k1<C>,
        value: u64,
        abf: AssetBlindingFactor,
        inputs: &[(u64, AssetBlindingFactor, ValueBlindingFactor)],
        outputs: &[(u64, AssetBlindingFactor, ValueBlindingFactor)],
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

        ValueBlindingFactor(compute_adaptive_blinding_factor(
            secp, value, abf.0, &set_a, &set_b,
        ))
    }

    /// Create from bytes.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, secp256k1_zkp::Error> {
        Ok(ValueBlindingFactor(Tweak::from_slice(bytes)?))
    }

    /// Returns the inner value.
    pub fn into_inner(self) -> Tweak {
        self.0
    }

    /// Get a unblinded/zero `AssetBlinding` factor
    pub fn zero() -> Self {
        ValueBlindingFactor(ZERO_TWEAK)
    }
}

impl AddAssign for ValueBlindingFactor {
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
                Ok(sk_tweaked) => *self = ValueBlindingFactor::from_slice(sk_tweaked.as_ref()).expect("Valid Tweak"),
                Err(_) =>  *self = Self::zero(),
            }
        }
    }
}

impl Neg for ValueBlindingFactor {
    type Output = Self;

    fn neg(self) -> Self::Output {
        if self.0.as_ref() == &[0u8; 32] {
            self
        } else {
            let sk = SecretKey::from_slice(self.into_inner().as_ref()).expect("Valid key").negate();
            ValueBlindingFactor::from_slice(sk.as_ref()).expect("Valid Tweak")
        }
    }
}

impl core::borrow::Borrow<[u8]> for ValueBlindingFactor {
    fn borrow(&self) -> &[u8] { &self.0[..] }
}

hex::impl_fmt_traits! {
    #[display_backward(true)]
    impl fmt_traits for ValueBlindingFactor {
        const LENGTH: usize = 32;
    }
}

impl str::FromStr for ValueBlindingFactor {
    type Err = encode::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut slice: [u8; 32] = hex::decode_to_array(s)?;
        slice.reverse();

        let inner = Tweak::from_inner(slice)?;
        Ok(ValueBlindingFactor(inner))
    }
}

#[cfg(feature = "serde")]
impl Serialize for ValueBlindingFactor {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            s.collect_str(&self)
        } else {
            s.serialize_bytes(&self.0[..])
        }
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for ValueBlindingFactor {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<ValueBlindingFactor, D::Error> {
        if d.is_human_readable() {
            struct HexVisitor;

            impl ::serde::de::Visitor<'_> for HexVisitor {
                type Value = ValueBlindingFactor;

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
                type Value = ValueBlindingFactor;

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
                            Ok(ValueBlindingFactor(inner))
                        }
                        Err(_) => Err(E::invalid_length(v.len(), &stringify!($len))),
                    }
                }
            }

            d.deserialize_bytes(BytesVisitor)
        }
    }
}

