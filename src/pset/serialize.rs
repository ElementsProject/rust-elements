// Rust Bitcoin Library
// Written by
//   The Rust Bitcoin developers
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

//! # PSET Serialization
//!
//! Defines traits used for (de)serializing PSET values into/from raw
//! bytes in PSET key-value pairs.

use crate::{Transaction, TxOut};

pub use elements26::pset::serialize::{Deserialize, Serialize, serialize_hex};

impl_pset_de_serialize!(Transaction);
impl_pset_de_serialize!(TxOut);

