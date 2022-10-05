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

use crate::hashes::{sha256d, Hash, hex};
use secp256k1_zkp::{self, CommitmentSecrets, Generator, PedersenCommitment,
    PublicKey, Secp256k1, SecretKey, Signing, Tweak, ZERO_TWEAK,
    compute_adaptive_blinding_factor,
    rand::{CryptoRng, Rng, RngCore}
};
#[cfg(feature = "serde")]
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use std::{fmt, io, ops::{AddAssign, Neg}, str};

use crate::encode::{self, Decodable, Encodable};
use crate::issuance::AssetId;

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
            Value::Confidential(commitment) => commitment.consensus_encode(&mut s),
        }
    }
}

impl Encodable for PedersenCommitment {
    fn consensus_encode<W: io::Write>(&self, mut e: W) -> Result<usize, encode::Error> {
        e.write_all(&self.serialize())?;
        Ok(33)
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

impl Decodable for PedersenCommitment {
    fn consensus_decode<D: io::Read>(d: D) -> Result<Self, encode::Error> {
        let bytes = <[u8; 33]>::consensus_decode(d)?;
        Ok(PedersenCommitment::from_slice(&bytes)?)
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
            Asset::Null => return None,
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
            Asset::Confidential(generator) => generator.consensus_encode(&mut s)
        }
    }
}

impl Encodable for Generator {
    fn consensus_encode<W: io::Write>(&self, mut e: W) -> Result<usize, encode::Error> {
        e.write_all(&self.serialize())?;
        Ok(33)
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

impl Decodable for Generator {
    fn consensus_decode<D: io::Read>(d: D) -> Result<Self, encode::Error> {
        let bytes = <[u8; 33]>::consensus_decode(d)?;
        Ok(Generator::from_slice(&bytes)?)
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
    /// Create nonce commitment.
    pub fn new_confidential<R: RngCore + CryptoRng, C: Signing>(
        rng: &mut R,
        secp: &Secp256k1<C>,
        receiver_blinding_pk: &PublicKey,
    ) -> (Self, SecretKey) {
        let ephemeral_sk = SecretKey::new(rng);
        Self::with_ephemeral_sk(secp, ephemeral_sk, receiver_blinding_pk)
    }

    /// Similar to [Nonce::new_confidential], but with a given `ephemeral_sk`
    /// instead of sampling it from rng.
    pub fn with_ephemeral_sk<C: Signing>(
        secp: &Secp256k1<C>,
        ephemeral_sk: SecretKey,
        receiver_blinding_pk: &PublicKey
    ) -> (Self, SecretKey) {
        let sender_pk = PublicKey::from_secret_key(&secp, &ephemeral_sk);
        let shared_secret = Self::make_shared_secret(receiver_blinding_pk, &ephemeral_sk);
        (Nonce::Confidential(sender_pk), shared_secret)
    }

    /// Calculate the shared secret.
    pub fn shared_secret(&self, receiver_blinding_sk: &SecretKey) -> Option<SecretKey> {
        match self {
            Nonce::Confidential(sender_pk) => {
                Some(Self::make_shared_secret(&sender_pk, receiver_blinding_sk))
            }
            _ => None,
        }
    }

    /// Create the shared secret.
    fn make_shared_secret(pk: &PublicKey, sk: &SecretKey) -> SecretKey {
        let xy = secp256k1_zkp::ecdh::shared_secret_point(pk, sk);
        let shared_secret = {
            // Yes, what follows is the compressed representation of a Bitcoin public key.
            // However, this is more by accident then by design, see here: https://github.com/rust-bitcoin/rust-secp256k1/pull/255#issuecomment-744146282

            let mut dh_secret = [0u8; 33];
            dh_secret[0] = if xy.last().unwrap() % 2 == 0 {
                0x02
            } else {
                0x03
            };
            dh_secret[1..].copy_from_slice(&xy[0..32]);

            sha256d::Hash::hash(&dh_secret).into_inner()
        };

        SecretKey::from_slice(&shared_secret.as_ref()[..32]).expect("always has exactly 32 bytes")
    }

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

impl From<PublicKey> for Nonce {
    fn from(from: PublicKey) -> Self {
        Nonce::Confidential(from)
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
            Nonce::Confidential(commitment) => commitment.consensus_encode(&mut s),
        }
    }
}

impl Encodable for PublicKey {
    fn consensus_encode<W: io::Write>(&self, mut e: W) -> Result<usize, encode::Error> {
        e.write_all(&self.serialize())?;
        Ok(33)
    }
}

impl Decodable for Nonce {
    fn consensus_decode<D: io::Read>(mut d: D) -> Result<Self, encode::Error> {
        let prefix = u8::consensus_decode(&mut d)?;

        match prefix {
            0 => Ok(Nonce::Null),
            1 => {
                let explicit = Decodable::consensus_decode(&mut d)?;
                Ok(Nonce::Explicit(explicit))
            }
            p if p == 0x02 || p == 0x03 => {
                let mut comm = [0u8; 33];
                comm[0] = p;
                d.read_exact(&mut comm[1..])?;
                Ok(Nonce::Confidential(PublicKey::from_slice(&comm)?))
            }
            p => Err(encode::Error::InvalidConfidentialPrefix(p)),
        }
    }
}

impl Decodable for PublicKey {
    fn consensus_decode<D: io::Read>(d: D) -> Result<Self, encode::Error> {
        let bytes = <[u8; 33]>::consensus_decode(d)?;
        Ok(PublicKey::from_slice(&bytes)?)
    }
}

#[cfg(feature = "serde")]
impl Serialize for Nonce {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeSeq;

        let seq_len = match *self {
            Nonce::Null => 1,
            Nonce::Explicit(_) | Nonce::Confidential(_) => 2
        };
        let mut seq = s.serialize_seq(Some(seq_len))?;

        match *self {
            Nonce::Null => seq.serialize_element(&0u8)?,
            Nonce::Explicit(n) => {
                seq.serialize_element(&1u8)?;
                seq.serialize_element(&n)?;
            }
            Nonce::Confidential(commitment) => {
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
                    Some(0) => Ok(Nonce::Null),
                    Some(1) => {
                        match access.next_element()? {
                            Some(x) => Ok(Nonce::Explicit(x)),
                            None => Err(A::Error::custom("missing explicit nonce")),
                        }
                    }
                    Some(2) => {
                        match access.next_element()? {
                            Some(x) => Ok(Nonce::Confidential(x)),
                            None => Err(A::Error::custom("missing nonce")),
                        }
                    }
                    _ => Err(A::Error::custom("wrong or missing prefix"))
                }
            }
        }

        d.deserialize_seq(CommitVisitor)
    }
}

/// Blinding factor used for asset commitments.
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord, Hash)]
pub struct AssetBlindingFactor(pub(crate) Tweak);

impl AssetBlindingFactor {
    /// Generate random asset blinding factor.
    pub fn new<R: Rng>(rng: &mut R) -> Self {
        AssetBlindingFactor(Tweak::new(rng))
    }

    /// Create from bytes.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, secp256k1_zkp::Error> {
        Ok(AssetBlindingFactor(Tweak::from_slice(bytes)?))
    }

    /// Returns the inner value.
    pub fn into_inner(self) -> Tweak {
        self.0
    }

    /// Get a unblinded/zero AssetBlinding factor
    pub fn zero() -> Self {
        AssetBlindingFactor(ZERO_TWEAK)
    }
}

impl hex::FromHex for AssetBlindingFactor {
    fn from_byte_iter<I>(iter: I) -> Result<Self, hex::Error>
        where I: Iterator<Item=Result<u8, hex::Error>> +
            ExactSizeIterator +
            DoubleEndedIterator
    {
        let slice = <[u8; 32]>::from_byte_iter(iter.rev())?;
        // Incorrect Return Error
        // See: https://github.com/rust-bitcoin/bitcoin_hashes/issues/124
        let inner = Tweak::from_inner(slice)
            .map_err(|_e| hex::Error::InvalidChar(0))?;
        Ok(AssetBlindingFactor(inner))
    }
}

impl fmt::Display for AssetBlindingFactor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        hex::format_hex_reverse(self.0.as_ref(), f)
    }
}

impl fmt::LowerHex for AssetBlindingFactor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        hex::format_hex_reverse(self.0.as_ref(), f)
    }
}

impl str::FromStr for AssetBlindingFactor {
    type Err = encode::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(hex::FromHex::from_hex(s)?)
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
        use bitcoin::hashes::hex::FromHex;

        if d.is_human_readable() {
            struct HexVisitor;

            impl<'de> ::serde::de::Visitor<'de> for HexVisitor {
                type Value = AssetBlindingFactor;

                fn expecting(&self, formatter: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
                    formatter.write_str("an ASCII hex string")
                }

                fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
                where
                    E: ::serde::de::Error,
                {
                    if let Ok(hex) = ::std::str::from_utf8(v) {
                        AssetBlindingFactor::from_hex(hex).map_err(E::custom)
                    } else {
                        return Err(E::invalid_value(::serde::de::Unexpected::Bytes(v), &self));
                    }
                }

                fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
                where
                    E: ::serde::de::Error,
                {
                    AssetBlindingFactor::from_hex(v).map_err(E::custom)
                }
            }

            d.deserialize_str(HexVisitor)
        } else {
            struct BytesVisitor;

            impl<'de> ::serde::de::Visitor<'de> for BytesVisitor {
                type Value = AssetBlindingFactor;

                fn expecting(&self, formatter: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
                    formatter.write_str("a bytestring")
                }

                fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
                where
                    E: ::serde::de::Error,
                {
                    if v.len() != 32 {
                        Err(E::invalid_length(v.len(), &stringify!($len)))
                    } else {
                        let mut ret = [0; 32];
                        ret.copy_from_slice(v);
                        let inner = Tweak::from_inner(ret).map_err(E::custom)?;
                        Ok(AssetBlindingFactor(inner))
                    }
                }
            }

            d.deserialize_bytes(BytesVisitor)
        }
    }
}

/// Blinding factor used for value commitments.
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord, Hash)]
pub struct ValueBlindingFactor(pub(crate) Tweak);

impl ValueBlindingFactor {
    /// Generate random value blinding factor.
    pub fn new<R: Rng>(rng: &mut R) -> Self {
        ValueBlindingFactor(Tweak::new(rng))
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

    /// Get a unblinded/zero AssetBlinding factor
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

impl hex::FromHex for ValueBlindingFactor {
    fn from_byte_iter<I>(iter: I) -> Result<Self, hex::Error>
        where I: Iterator<Item=Result<u8, hex::Error>> +
            ExactSizeIterator +
            DoubleEndedIterator
    {
        let slice = <[u8; 32]>::from_byte_iter(iter.rev())?;
        // Incorrect Return Error
        // See: https://github.com/rust-bitcoin/bitcoin_hashes/issues/124
        let inner = Tweak::from_inner(slice)
            .map_err(|_e| hex::Error::InvalidChar(0))?;
        Ok(ValueBlindingFactor(inner))
    }
}

impl fmt::Display for ValueBlindingFactor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        hex::format_hex_reverse(self.0.as_ref(), f)
    }
}

impl fmt::LowerHex for ValueBlindingFactor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        hex::format_hex_reverse(self.0.as_ref(), f)
    }
}

impl str::FromStr for ValueBlindingFactor {
    type Err = encode::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(hex::FromHex::from_hex(s)?)
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
        use bitcoin::hashes::hex::FromHex;

        if d.is_human_readable() {
            struct HexVisitor;

            impl<'de> ::serde::de::Visitor<'de> for HexVisitor {
                type Value = ValueBlindingFactor;

                fn expecting(&self, formatter: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
                    formatter.write_str("an ASCII hex string")
                }

                fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
                where
                    E: ::serde::de::Error,
                {
                    if let Ok(hex) = ::std::str::from_utf8(v) {
                        ValueBlindingFactor::from_hex(hex).map_err(E::custom)
                    } else {
                        return Err(E::invalid_value(::serde::de::Unexpected::Bytes(v), &self));
                    }
                }

                fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
                where
                    E: ::serde::de::Error,
                {
                    ValueBlindingFactor::from_hex(v).map_err(E::custom)
                }
            }

            d.deserialize_str(HexVisitor)
        } else {
            struct BytesVisitor;

            impl<'de> ::serde::de::Visitor<'de> for BytesVisitor {
                type Value = ValueBlindingFactor;

                fn expecting(&self, formatter: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
                    formatter.write_str("a bytestring")
                }

                fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
                where
                    E: ::serde::de::Error,
                {
                    if v.len() != 32 {
                        Err(E::invalid_length(v.len(), &stringify!($len)))
                    } else {
                        let mut ret = [0; 32];
                        ret.copy_from_slice(v);
                        let inner = Tweak::from_inner(ret).map_err(E::custom)?;
                        Ok(ValueBlindingFactor(inner))
                    }
                }
            }

            d.deserialize_bytes(BytesVisitor)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::sha256;

    #[cfg(feature = "serde")]
    use bincode;

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

    #[cfg(feature = "serde")]
    #[test]
    fn value_serde() {
        use serde_test::{assert_tokens, Configure, Token};

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
            &value.readable(),
            &[
                Token::Seq { len: Some(2) },
                Token::U8(2),
                Token::Str(
                    "080101010101010101010101010101010101010101010101010101010101010101"
                ),
                Token::SeqEnd
            ]
        );
        assert_tokens(
            &value.compact(),
            &[
                Token::Seq { len: Some(2) },
                Token::U8(2),
                Token::Bytes(
                    &[
                        8,
                        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1
                    ]
                ),
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
            &asset.readable(),
            &[
                Token::Seq { len: Some(2) },
                Token::U8(2),
                Token::Str(
                    "0a0101010101010101010101010101010101010101010101010101010101010101"
                ),
                Token::SeqEnd
            ]
        );
        assert_tokens(
            &asset.compact(),
            &[
                Token::Seq { len: Some(2) },
                Token::U8(2),
                Token::Bytes(
                    &[
                        10,
                        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1
                    ]
                ),
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
        use serde_test::{assert_tokens, Configure, Token};

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
            &nonce.readable(),
            &[
                Token::Seq { len: Some(2) },
                Token::U8(2),
                Token::Str(
                    "020101010101010101010101010101010101010101010101010101010101010101"
                ),
                Token::SeqEnd
            ]
        );
        assert_tokens(
            &nonce.compact(),
            &[
                Token::Seq { len: Some(2) },
                Token::U8(2),
                Token::Tuple { len: 33 },
                Token::U8(2), Token::U8(1), Token::U8(1), Token::U8(1),
                Token::U8(1), Token::U8(1), Token::U8(1), Token::U8(1),
                Token::U8(1), Token::U8(1), Token::U8(1), Token::U8(1),
                Token::U8(1), Token::U8(1), Token::U8(1), Token::U8(1),
                Token::U8(1), Token::U8(1), Token::U8(1), Token::U8(1),
                Token::U8(1), Token::U8(1), Token::U8(1), Token::U8(1),
                Token::U8(1), Token::U8(1), Token::U8(1), Token::U8(1),
                Token::U8(1), Token::U8(1), Token::U8(1), Token::U8(1),
                Token::U8(1),
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

    #[cfg(feature = "serde")]
    #[test]
    fn bf_serde() {
        use serde_json;
        use std::str::FromStr;

        let abf_str = "a5b3d111cdaa5fc111e2723df4caf315864f25fb4610cc737f10d5a55cd4096f";
        let abf_str_quoted = format!("\"{}\"", abf_str);
        let abf_from_serde: AssetBlindingFactor = serde_json::from_str(&abf_str_quoted).unwrap();
        let abf_from_str = AssetBlindingFactor::from_str(abf_str).unwrap();
        assert_eq!(abf_from_serde, abf_from_str);
        assert_eq!(abf_str_quoted, serde_json::to_string(&abf_from_serde).unwrap());

        let vbf_str = "e36a4de359469f547571d117bc5509fb74fba73c84b0cdd6f4edfa7ff7fa457d";
        let vbf_str_quoted = format!("\"{}\"", vbf_str);
        let vbf_from_serde: ValueBlindingFactor = serde_json::from_str(&vbf_str_quoted).unwrap();
        let vbf_from_str = ValueBlindingFactor::from_str(vbf_str).unwrap();
        assert_eq!(vbf_from_serde, vbf_from_str);
        assert_eq!(vbf_str_quoted, serde_json::to_string(&vbf_from_serde).unwrap());
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_value_bincode_be() {
        let value = Value::Explicit(500);
        let bytes = bincode::serialize(&value).unwrap();
        let decoded: Value = bincode::deserialize(&bytes).unwrap();
        assert_eq!(value, decoded);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_value_bincode_le() {
        use bincode::Options;
        let value = Value::Explicit(500);
        let bytes = bincode::DefaultOptions::default()
            .with_little_endian()
            .serialize(&value)
            .unwrap();
        let decoded: Value = bincode::DefaultOptions::default()
            .with_little_endian()
            .deserialize(&bytes)
            .unwrap();
        assert_eq!(value, decoded);
    }
}
