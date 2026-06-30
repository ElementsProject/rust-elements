// SPDX-License-Identifier: MIT OR Apache-2.0

//! Range Proofs

use core::convert::TryInto;
use std::io;

use secp256k1_zkp::rand::{CryptoRng, RngCore};
use secp256k1_zkp::{self, Generator, PedersenCommitment, Secp256k1, SecretKey, Signing, Tweak};
#[cfg(feature = "serde")]
use serde::{Deserializer, Serializer};

use crate::confidential::ValueBlindingFactor;
use crate::encode;

/// A range proof, which represents a proof that a confidential value lies within
/// some range (typically `[0, 2^64)`).
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub struct RangeProof {
    inner: Option<Box<secp256k1_zkp::RangeProof>>,
}

impl RangeProof {
    /// No range proof.
    pub const EMPTY: Self = Self { inner: None };

    /// Constructs a new [`RangeProof`].
    #[allow(clippy::too_many_arguments)]
    pub fn new<C: Signing>(
        secp: &Secp256k1<C>,
        min_value: u64,
        commitment: PedersenCommitment,
        value: u64,
        commitment_blinding: Tweak,
        message: &[u8],
        additional_commitment: &[u8],
        sk: SecretKey,
        exp: i32,
        min_bits: u8,
        additional_generator: Generator,
    ) -> Result<Self, secp256k1_zkp::Error> {
        secp256k1_zkp::RangeProof::new(
            secp,
            min_value,
            commitment,
            value,
            commitment_blinding,
            message,
            additional_commitment,
            sk,
            exp,
            min_bits,
            additional_generator,
        )
        .map(|inner| Self { inner: Some(Box::new(inner)) })
    }

    /// Parses a [`RangeProof`] from a byte slice (with no length prefix).
    pub fn from_slice(sl: &[u8]) -> Result<Self, secp256k1_zkp::Error> {
        if sl.is_empty() {
            Ok(Self { inner: None })
        } else {
            secp256k1_zkp::RangeProof::from_slice(sl)
                .map(|inner| Self { inner: Some(Box::new(inner)) })
        }
    }

    /// Outputs a [`RangeProof`] proving that a commitment matches an exact value.
    pub fn blind_value_proof<C: secp256k1_zkp::Signing, R: RngCore + CryptoRng>(
        rng: &mut R,
        secp: &Secp256k1<C>,
        explicit_val: u64,
        value_commit: PedersenCommitment,
        asset_gen: Generator,
        vbf: ValueBlindingFactor,
    ) -> Result<Self, secp256k1_zkp::Error> {
        secp256k1_zkp::RangeProof::new(
            secp,
            explicit_val,        // min_value
            value_commit,        // value_commit
            explicit_val,        // value
            vbf.into_inner(),    // blinding factor
            &[],                 // message
            &[],                 // add commitment
            SecretKey::new(rng), // nonce
            -1,                  // exp
            0,                   // min bits
            asset_gen,           // additional gen
        )
        .map(|inner| Self { inner: Some(Box::new(inner)) })
    }

    /// Verifies a [`RangeProof`] proving that a commitment matches an exact value.
    pub fn blind_value_proof_verify<C: secp256k1_zkp::Verification>(
        &self,
        secp: &Secp256k1<C>,
        explicit_val: u64,
        asset_gen: Generator,
        value_commit: PedersenCommitment,
    ) -> bool {
        let Some(inner) = self.inner.as_deref() else {
            return false;
        };
        if explicit_val == u64::MAX {
            // FIXME upstream will panic on this input; we should be able to validate
            //  proofs with this value.
            return false;
        }

        let Ok(range) = inner.verify(secp, value_commit, &[], asset_gen) else {
            return false;
        };
        range == (explicit_val..explicit_val + 1)
    }

    /// The length of the range proof (zero if it is empty/absent).
    pub fn len(&self) -> usize { self.inner.as_deref().map_or(0, secp256k1_zkp::RangeProof::len) }

    /// Whether the range proof is absent.
    pub fn is_empty(&self) -> bool { self.inner.is_none() }

    /// Serializes the range proof as a byte vector.
    pub fn to_vec(&self) -> Vec<u8> {
        match self.inner.as_deref() {
            Some(prf) => secp256k1_zkp::RangeProof::serialize(prf),
            None => Vec::new(),
        }
    }

    /// Extracts the minimum value encoded in the range proof.
    pub fn minimim_value(&self) -> Option<u64> {
        // inefficient, consider implementing index on rangeproof
        let prf = self.to_vec();
        let byte0 = prf.first()?;

        let has_nonzero_range = byte0 & 64 == 64;
        let has_min = byte0 & 32 == 32;

        if !has_min {
            None
        } else if has_nonzero_range {
            let bytes: [u8; 8] = prf.get(2..10)?.try_into().ok()?;
            Some(u64::from_be_bytes(bytes))
        } else {
            let bytes: [u8; 8] = prf.get(1..9)?.try_into().ok()?;
            Some(u64::from_be_bytes(bytes))
        }
    }

    /// Obtains a reference to the underlying secp256k1-zkp object.
    pub fn as_ref(&self) -> Option<&secp256k1_zkp::RangeProof> { self.inner.as_deref() }
}

impl crate::encode::Encodable for RangeProof {
    fn consensus_encode<W: io::Write>(&self, e: W) -> Result<usize, encode::Error> {
        self.to_vec().consensus_encode(e)
    }
}

impl crate::encode::Decodable for RangeProof {
    fn consensus_decode<D: io::Read>(d: D) -> Result<Self, encode::Error> {
        let v = Vec::<u8>::consensus_decode(d)?;
        if v.is_empty() {
            Ok(Self { inner: None })
        } else {
            secp256k1_zkp::RangeProof::from_slice(&v)
                .map(|inner| Self { inner: Some(Box::new(inner)) })
                .map_err(encode::Error::Secp256k1zkp)
        }
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for RangeProof {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.inner.serialize(serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for RangeProof {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Option::<secp256k1_zkp::RangeProof>::deserialize(deserializer)
            .map(|inner| Self { inner: inner.map(Box::new) })
    }
}
