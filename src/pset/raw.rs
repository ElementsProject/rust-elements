//! # Raw PSET Key-Value Pairs


pub use bitcoin::util::psbt::raw::{Key, Pair};

/// A borrowed variant of raw::Key.
#[derive(Debug, PartialEq, Hash, Eq, Clone, Ord, PartialOrd)]
pub struct BorrowedKey<'a> {
    /// The type of this PSBT key.
    pub type_value: u8,
    /// The key itself in raw byte form.
    pub key: &'a [u8],
}

impl<'a> Into<Key> for BorrowedKey<'a> {
    fn into(self) -> Key {
        Key {
            type_value: self.type_value,
            key: self.key.to_vec(),
        }
    }
}
