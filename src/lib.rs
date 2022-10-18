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

pub extern crate bitcoin;
#[macro_use]
extern crate bitcoin_hashes as just_imported_for_the_macros;
extern crate slip21;
pub extern crate secp256k1_zkp;
#[cfg(feature = "serde")] #[macro_use] extern crate actual_serde as serde;
#[cfg(all(test, feature = "serde"))] extern crate serde_test;

#[cfg(test)] extern crate rand;
#[cfg(test)] extern crate bincode;
#[cfg(any(test, feature = "serde_json"))] extern crate serde_json;

#[macro_use] mod internal_macros;
pub mod address;
pub mod blech32;
mod block;
pub mod confidential;
pub mod dynafed;
pub mod encode;
mod error;
mod fast_merkle_root;
pub mod hash_types;
pub mod locktime;
pub mod issuance;
pub mod opcodes;
pub mod script;
mod transaction;
mod blind;
mod parse;
pub mod slip77;
pub mod sighash;
pub mod pset;
pub mod taproot;
pub mod schnorr;
#[cfg(feature = "serde")]
mod serde_utils;
// consider making upstream public
mod endian;
// re-export bitcoin deps which we re-use
pub use bitcoin::{bech32, hashes};
// export everything at the top level so it can be used as `elements::Transaction` etc.
pub use crate::address::{Address, AddressParams, AddressError};
pub use crate::transaction::{OutPoint, PeginData, PegoutData, EcdsaSigHashType, TxIn, TxOut, TxInWitness, TxOutWitness, Transaction, AssetIssuance};
pub use crate::transaction::Sequence;
pub use crate::blind::{ConfidentialTxOutError, TxOutSecrets, SurjectionInput, TxOutError, VerificationError, BlindError, UnblindError, BlindValueProofs, BlindAssetProofs};
pub use crate::block::{BlockHeader, Block};
pub use crate::block::ExtData as BlockExtData;
pub use ::bitcoin::consensus::encode::VarInt;
pub use crate::fast_merkle_root::fast_merkle_root;
pub use crate::hash_types::*;
pub use crate::issuance::{AssetId, ContractHash};
pub use crate::locktime::{LockTime, PackedLockTime};
pub use crate::script::Script;
pub use crate::sighash::SchnorrSigHashType;
pub use crate::schnorr::{SchnorrSig, SchnorrSigError};
