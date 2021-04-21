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
extern crate secp256k1_zkp;
#[cfg(feature = "serde")]
extern crate serde;
#[cfg(all(test, feature = "serde"))]
extern crate serde_test;
extern crate slip21;

#[cfg(test)]
extern crate rand;
#[cfg(any(test, feature = "serde_json"))]
extern crate serde_json;

#[macro_use]
mod internal_macros;
pub mod address;
pub mod blech32;
mod block;
pub mod confidential;
pub mod dynafed;
pub mod encode;
mod fast_merkle_root;
pub mod hash_types;
pub mod issuance;
pub mod opcodes;
pub mod script;
pub mod sighash;
pub mod slip77;
mod transaction;

// consider making upstream public
mod endian;
// re-export bitcoin deps which we re-use
pub use bitcoin::{bech32, hashes, secp256k1};
// export everything at the top level so it can be used as `elements::Transaction` etc.
pub use address::{Address, AddressError, AddressParams};
pub use bitcoin::consensus::encode::VarInt;
pub use block::ExtData as BlockExtData;
pub use block::{Block, BlockHeader};
pub use fast_merkle_root::fast_merkle_root;
pub use hash_types::*;
pub use issuance::{AssetId, ContractHash};
pub use script::Script;
pub use transaction::{
    AssetIssuance, ConfidentialTxOutError, OutPoint, PeginData, PegoutData, SigHashType,
    Transaction, TxIn, TxInWitness, TxOut, TxOutWitness,
};
