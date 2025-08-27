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
#[macro_use]
pub extern crate actual_serde as serde;
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

mod blind;
mod block;
mod endian;
pub mod pset;
#[cfg(feature = "serde")]
mod serde_utils;
pub mod sighash;
mod transaction;

pub use elements26::{address, blech32, confidential, dynafed, encode, hex, issuance, locktime, opcodes};
pub use elements26::{schnorr, script, taproot};
// re-export bitcoin deps which we re-use
pub use bitcoin::hashes;
// export everything at the top level so it can be used as `elements::Transaction` etc.
pub use elements26::{Address, AddressError, AddressParams};
pub use elements26::{
    BlindAssetProofs, BlindError, BlindValueProofs, ConfidentialTxOutError, RangeProofMessage,
    SurjectionInput, TxOutError, TxOutSecrets, UnblindError, VerificationError,
};
pub use elements26::{ReadExt, WriteExt};
pub use elements26::fast_merkle_root;
pub use elements26::hash_types::{self, *};
pub use elements26::{AssetId, ContractHash};
pub use elements26::LockTime;
pub use elements26::{SchnorrSig, SchnorrSigError};
pub use elements26::Script;
pub use elements26::Sequence;
pub use elements26::{
    AssetIssuance, EcdsaSighashType, OutPoint, PeginData, PegoutData, TxIn,
    TxInWitness, TxOutWitness,
};

pub use crate::block::ExtData as BlockExtData;
pub use crate::block::{Block, BlockHeader};
pub use crate::sighash::SchnorrSighashType;
pub use crate::transaction::{TxOut, Transaction};

