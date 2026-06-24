// SPDX-License-Identifier: MIT OR Apache-2.0

//! Surjection Proofs

use std::io;

use secp256k1_zkp::rand::{CryptoRng, RngCore};
use secp256k1_zkp::{self, Generator, Secp256k1, Signing, Tweak, ZERO_TWEAK};
#[cfg(feature = "serde")]
use serde::{Deserializer, Serializer};

use crate::confidential::{AssetBlindingFactor, AssetId};
use crate::encode;

/// A surjection proof, proving that an asset commitment commits to the same asset ID
/// as a commitment from a given set.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub struct SurjectionProof {
    inner: Option<Box<secp256k1_zkp::SurjectionProof>>,
}

impl SurjectionProof {
    /// No surjection proof.
    pub const EMPTY: Self = Self { inner: None };

    /// Constructs a new [`SurjectionProof`].
    pub fn new<R, C, S>(
        secp: &Secp256k1<C>,
        rng: &mut R,
        asset: AssetId,
        asset_bf: AssetBlindingFactor,
        inputs: S,
    ) -> Result<Self, secp256k1_zkp::Error>
    where
        R: RngCore + CryptoRng,
        C: Signing,
        S: AsRef<[(Generator, secp256k1_zkp::Tag, Tweak)]>,
    {
        secp256k1_zkp::SurjectionProof::new(
            secp,
            rng,
            asset.into_tag(),
            asset_bf.into_inner(),
            inputs.as_ref(),
        )
        .map(|inner| Self { inner: Some(Box::new(inner)) })
    }

    /// Parses a [`SurjectionProof`] from a byte slice (with no length prefix).
    pub fn from_slice(sl: &[u8]) -> Result<Self, secp256k1_zkp::Error> {
        if sl.is_empty() {
            Ok(Self { inner: None })
        } else {
            secp256k1_zkp::SurjectionProof::from_slice(sl)
                .map(|inner| Self { inner: Some(Box::new(inner)) })
        }
    }

    /// Serializes the surjection proof as a byte vector.
    pub fn to_vec(&self) -> Vec<u8> {
        match self.inner.as_deref() {
            Some(prf) => secp256k1_zkp::SurjectionProof::serialize(prf),
            None => Vec::new(),
        }
    }

    /// Outputs a [`SurjectionProof`] proving that an asset matches an exact asset ID.
    pub fn blind_asset_proof<C: secp256k1_zkp::Signing, R: RngCore + CryptoRng>(
        rng: &mut R,
        secp: &Secp256k1<C>,
        asset: AssetId,
        abf: AssetBlindingFactor,
    ) -> Result<Self, secp256k1_zkp::Error> {
        let gen = Generator::new_unblinded(secp, asset.into_tag());
        SurjectionProof::new(secp, rng, asset, abf, [(gen, asset.into_tag(), ZERO_TWEAK)])
    }

    /// Verifies a [`SurjectionProof`] proving that an asset matches an exact asset ID.
    pub fn blind_asset_proof_verify(
        &self,
        secp: &Secp256k1<secp256k1_zkp::All>,
        asset: AssetId,
        asset_commit: Generator,
    ) -> bool {
        let gen = Generator::new_unblinded(secp, asset.into_tag());
        match self.inner.as_deref() {
            Some(inner) => inner.verify(secp, asset_commit, &[gen]),
            None => false,
        }
    }

    /// The length of the range proof (zero if it is empty/absent).
    pub fn len(&self) -> usize {
        self.inner.as_deref().map_or(0, secp256k1_zkp::SurjectionProof::len)
    }

    /// Whether the surjectionproof is absent.
    pub fn is_empty(&self) -> bool { self.inner.is_none() }

    /// Obtains a reference to the underlying secp256k1-zkp object.
    pub fn as_ref(&self) -> Option<&secp256k1_zkp::SurjectionProof> { self.inner.as_deref() }
}

impl crate::encode::Encodable for SurjectionProof {
    fn consensus_encode<W: io::Write>(&self, e: W) -> Result<usize, encode::Error> {
        match self.inner.as_ref() {
            Some(prf) => secp256k1_zkp::SurjectionProof::serialize(prf).consensus_encode(e),
            None => <[u8]>::consensus_encode(&[], e),
        }
    }
}

impl crate::encode::Decodable for SurjectionProof {
    fn consensus_decode<D: io::Read>(d: D) -> Result<Self, encode::Error> {
        let v = Vec::<u8>::consensus_decode(d)?;
        if v.is_empty() {
            Ok(Self { inner: None })
        } else {
            secp256k1_zkp::SurjectionProof::from_slice(&v)
                .map(|inner| Self { inner: Some(Box::new(inner)) })
                .map_err(encode::Error::Secp256k1zkp)
        }
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for SurjectionProof {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.inner.serialize(serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for SurjectionProof {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Option::<secp256k1_zkp::SurjectionProof>::deserialize(deserializer)
            .map(|inner| Self { inner: inner.map(Box::new) })
    }
}
