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

use encode;
use pset::{self, raw};

/// A trait that describes a PSET key-value map.
pub(crate) trait Map {
    /// Attempt to insert a key-value pair.
    fn insert_pair(&mut self, pair: raw::Pair) -> Result<(), encode::Error>;

    /// Attempt to get all key-value pairs.
    fn get_pairs(&self) -> Result<Vec<raw::Pair>, encode::Error>;

    /// Attempt to merge with another key-value map of the same type.
    fn merge(&mut self, other: Self) -> Result<(), pset::Error>;
}

// place at end to pick up macros
mod global;
mod input;
mod output;

pub use self::global::Global;
pub use self::global::TxData as GlobalTxData;
pub use self::input::Input;
pub use self::output::Output;
