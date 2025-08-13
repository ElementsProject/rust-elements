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

//! # Rust Elements Library
//!
//! Extensions to `rust-bitcoin` to support deserialization and serialization
//! of Elements transactions and blocks.
//!

// Coding conventions
#![deny(non_upper_case_globals)]
#![deny(non_camel_case_types)]
#![deny(non_snake_case)]
#![deny(unused_mut)]
#![deny(missing_docs)]
#![allow(clippy::manual_range_contains)] // this lint is bullshit

/// Re-export of bitcoin crate
pub extern crate bitcoin;
/// Re-export of secp256k1-zkp crate
pub extern crate secp256k1_zkp;
/// Re-export of serde crate
#[cfg(feature = "serde")]
pub extern crate serde;
#[cfg(all(test, feature = "serde"))]
extern crate serde_test;

#[cfg(test)]
extern crate bincode;
#[cfg(test)]
extern crate rand;
#[cfg(any(test, feature = "serde_json"))]
extern crate serde_json;

#[macro_use]
mod internal_macros;
pub mod address;
pub mod blech32;
mod blind;
mod block;
pub mod confidential;
pub mod dynafed;
pub mod encode;
mod error;
mod ext;
mod fast_merkle_root;
pub mod hash_types;
pub mod hex;
pub mod issuance;
pub mod locktime;
pub mod opcodes;
mod parse;
pub mod pset;
pub mod schnorr;
pub mod script;
pub mod sighash;
pub mod taproot;
mod transaction;
// consider making upstream public
mod endian;
// re-export bitcoin deps which we re-use
pub use bitcoin::hashes;
// Re-export units which are identical in Bitcoin and Elements
pub use bitcoin_units::{
    BlockHeight, BlockHeightInterval, BlockMtp, BlockMtpInterval, BlockTime,
    MathOp, NumOpError, NumOpResult,
    Weight,
};
// export everything at the top level so it can be used as `elements::Transaction` etc.
pub use crate::address::{Address, AddressError, AddressParams};
pub use crate::blind::{
    BlindAssetProofs, BlindError, BlindValueProofs, ConfidentialTxOutError, RangeProofMessage,
    SurjectionInput, TxOutError, TxOutSecrets, UnblindError, VerificationError,
};
pub use crate::block::ExtData as BlockExtData;
pub use crate::block::{Block, BlockHeader};
pub use crate::ext::{ReadExt, WriteExt};
pub use crate::fast_merkle_root::fast_merkle_root;
pub use crate::hash_types::*;
pub use crate::issuance::{AssetId, ContractHash};
pub use crate::locktime::LockTime;
pub use crate::schnorr::{SchnorrSig, SchnorrSigError};
pub use crate::script::Script;
pub use crate::sighash::SchnorrSighashType;
pub use crate::transaction::Sequence;
pub use crate::transaction::{
    AssetIssuance, EcdsaSighashType, OutPoint, PeginData, PegoutData, Transaction, TxIn,
    TxInWitness, TxOut, TxOutWitness,
};

/// Utility trait for producing lengths in u64, for use in weight computations.
trait Len64 {
    fn len64(&self) -> u64;
}

impl<T> Len64 for [T] {
    fn len64(&self) -> u64 { self.len() as u64 }
}
impl<T> Len64 for &[T] {
    fn len64(&self) -> u64 { (*self).len64() }
}
impl<T> Len64 for Vec<T> {
    fn len64(&self) -> u64 { self[..].len64() }
}
impl Len64 for crate::script::Script {
    fn len64(&self) -> u64 { self[..].len64() }
}
impl Len64 for secp256k1_zkp::RangeProof {
    fn len64(&self) -> u64 { self.serialize().len64() }
}
impl Len64 for secp256k1_zkp::SurjectionProof {
    fn len64(&self) -> u64 { self.serialize().len64() }
}
impl Len64 for bitcoin::VarInt {
    fn len64(&self) -> u64 { self.size() as u64 }
}
impl Len64 for crate::encode::VarInt {
    fn len64(&self) -> u64 { self.size() as u64 }
}
impl<T: Len64> Len64 for Option<T> {
    fn len64(&self) -> u64 { self.as_ref().map_or(0, T::len64) }
}
impl<T: Len64> Len64 for Box<T> {
    fn len64(&self) -> u64 { (**self).len64() }
}
