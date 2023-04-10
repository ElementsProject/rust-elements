// Rust Bitcoin Library
// Written in 2014 by
//     Andrew Poelstra <apoelstra@wpsoftware.net>
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

//! Schnorr Bitcoin keys.
//!
//! This module provides Schnorr keys used in Bitcoin, reexporting Secp256k1
//! Schnorr key types.
//!

use std::fmt;

use crate::taproot::{TapBranchHash, TapTweakHash};
use crate::SchnorrSigHashType;
use secp256k1_zkp::{self, constants::SCHNORR_SIGNATURE_SIZE, Secp256k1, Verification};
pub use secp256k1_zkp::{KeyPair, XOnlyPublicKey};

/// Untweaked Schnorr public key
pub type UntweakedPublicKey = XOnlyPublicKey;

/// Tweaked Schnorr public key
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct TweakedPublicKey(XOnlyPublicKey);

/// A trait for tweaking Schnorr key types (x-only public keys and key pairs).
pub trait TapTweak {
    /// Tweaked key type with optional auxiliary information
    type TweakedAux;
    /// Tweaked key type
    type TweakedKey;

    /// Tweaks an untweaked key with corresponding public key value and optional script tree merkle
    /// root. For the [`KeyPair`] type this also tweaks the private key in the pair.
    ///
    /// This is done by using the equation Q = P + H(P|c)G, where
    ///  * Q is the tweaked public key
    ///  * P is the internal public key
    ///  * H is the hash function
    ///  * c is the commitment data
    ///  * G is the generator point
    ///
    /// # Returns
    /// The tweaked key and its parity.
    fn tap_tweak<C: Verification>(
        self,
        secp: &Secp256k1<C>,
        merkle_root: Option<TapBranchHash>,
    ) -> Self::TweakedAux;

    /// Directly converts to a `TweakedKey`
    ///
    /// This method is dangerous and can lead to loss of funds if used incorrectly.
    /// Specifically, in multi-party protocols a peer can provide a value that allows them to steal.
    fn dangerous_assume_tweaked(self) -> Self::TweakedKey;
}

impl TapTweak for UntweakedPublicKey {
    type TweakedAux = (TweakedPublicKey, secp256k1_zkp::Parity);
    type TweakedKey = TweakedPublicKey;

    /// Tweaks an untweaked public key with corresponding public key value and optional script tree
    /// merkle root.
    ///
    /// This is done by using the equation Q = P + H(P|c)G, where
    ///  * Q is the tweaked public key
    ///  * P is the internal public key
    ///  * H is the hash function
    ///  * c is the commitment data
    ///  * G is the generator point
    ///
    /// # Returns
    /// The tweaked key and its parity.
    fn tap_tweak<C: Verification>(
        self,
        secp: &Secp256k1<C>,
        merkle_root: Option<TapBranchHash>,
    ) -> (TweakedPublicKey, secp256k1_zkp::Parity) {
        let tweak = TapTweakHash::from_key_and_tweak(self, merkle_root).to_scalar();
        let (output_key, parity) = self.add_tweak(secp, &tweak).expect("Tap tweak failed");

        debug_assert!(self.tweak_add_check(secp, &output_key, parity, tweak));
        (TweakedPublicKey(output_key), parity)
    }


    fn dangerous_assume_tweaked(self) -> TweakedPublicKey {
        TweakedPublicKey(self)
    }
}


impl TweakedPublicKey {
    /// Create a new [TweakedPublicKey] from a [PublicKey]. No tweak is applied.
    pub fn new(key: XOnlyPublicKey) -> TweakedPublicKey {
        TweakedPublicKey(key)
    }

    /// Returns the underlying public key
    pub fn into_inner(self) -> XOnlyPublicKey {
        self.0
    }

    /// Returns a reference to underlying public key
    pub fn as_inner(&self) -> &XOnlyPublicKey {
        &self.0
    }
}

/// A BIP340-341 serialized schnorr signature with the corresponding hash type.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(crate = "actual_serde"))]
pub struct SchnorrSig {
    /// The underlying schnorr signature
    pub sig: secp256k1_zkp::schnorr::Signature,
    /// The corresponding hash type
    pub hash_ty: SchnorrSigHashType,
}

impl SchnorrSig {

    /// Deserialize from slice
    pub fn from_slice(sl: &[u8]) -> Result<Self, SchnorrSigError> {
        if sl.len() == SCHNORR_SIGNATURE_SIZE {
            // default type
            let sig = secp256k1_zkp::schnorr::Signature::from_slice(sl)
                .map_err(|_| SchnorrSigError::InvalidSchnorrSig)?;
            return Ok( SchnorrSig { sig, hash_ty : SchnorrSigHashType::Default });
        }
        let (hash_ty, sig) = sl.split_last()
            .ok_or_else(|| SchnorrSigError::InvalidSchnorrSig)?;
        let hash_ty = SchnorrSigHashType::from_u8(*hash_ty)
            .ok_or_else(|| SchnorrSigError::InvalidSighashType(*hash_ty))?;
        let sig = secp256k1_zkp::schnorr::Signature::from_slice(sig)
            .map_err(|_| SchnorrSigError::InvalidSchnorrSig)?;
        Ok(SchnorrSig { sig, hash_ty })
    }

    /// Serialize SchnorrSig
    pub fn to_vec(&self) -> Vec<u8> {
        // TODO: add support to serialize to a writer to SerializedSig
        let mut ser_sig = self.sig.as_ref().to_vec();
        if let SchnorrSigHashType::Default = self.hash_ty {
            // default sighash type, don't add extra sighash byte
        } else {
            ser_sig.push(self.hash_ty as u8);
        }
        ser_sig
    }

}

/// A schnorr sig related error.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum SchnorrSigError {
    /// Base58 encoding error
    InvalidSighashType(u8),
    /// secp256k1-related error
    InvalidSchnorrSig,
}


impl fmt::Display for SchnorrSigError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            SchnorrSigError::InvalidSighashType(hash_ty) =>
                write!(f, "Invalid signature hash type {}", hash_ty),
            SchnorrSigError::InvalidSchnorrSig => write!(f, "Cannot parse Schnorr Signature"),
        }
    }
}

impl ::std::error::Error for SchnorrSigError {}
