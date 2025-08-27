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

//! # Raw PSET Key-Value Pairs
//!
//! Raw PSET key-value pairs as defined at
//! <https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki>.

use std::io;

use super::Error;
use crate::encode::{self, deserialize, serialize, Decodable, Encodable};

pub use elements26::pset::raw::{Key, Pair, ProprietaryType};

/// Proprietary keys (i.e. keys starting with 0xFC byte) with their internal
/// structure according to BIP 174.
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "actual_serde")
)]
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct ProprietaryKey<Subtype = ProprietaryType>
where
    Subtype: Copy + From<u8> + Into<u8>,
{
    /// Proprietary type prefix used for grouping together keys under some
    /// application and avoid namespace collision
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::hex_bytes"))]
    pub prefix: Vec<u8>,
    /// Custom proprietary subtype
    pub subtype: Subtype,
    /// Additional key bytes (like serialized public key data etc)
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::hex_bytes"))]
    pub key: Vec<u8>,
}

impl ProprietaryKey {
    /// Check if the proprietary key is a "pset key"
    /// starts with prefix pset
    pub fn is_pset_key(&self) -> bool {
        // TODO: precompute this
        self.prefix == "pset".as_bytes().to_vec()
    }

    /// Create a pset prop key
    pub fn from_pset_pair(subtype: ProprietaryType, key: Vec<u8>) -> Self {
        Self {
            // TODO: precompute this
            prefix: String::from("pset").into_bytes(),
            subtype,
            key,
        }
    }
}

impl<Subtype> Encodable for ProprietaryKey<Subtype>
where
    Subtype: Copy + From<u8> + Into<u8>,
{
    fn consensus_encode<W: crate::WriteExt>(&self, mut e: W) -> Result<usize, encode::Error> {
        let mut len = self.prefix.consensus_encode(&mut e)? + 1;
        e.emit_u8(self.subtype.into())?;
        len += e.write(&self.key)?;
        Ok(len)
    }
}

impl<Subtype> Decodable for ProprietaryKey<Subtype>
where
    Subtype: Copy + From<u8> + Into<u8>,
{
    fn consensus_decode<D: io::Read>(mut d: D) -> Result<Self, encode::Error> {
        let prefix = Vec::<u8>::consensus_decode(&mut d)?;
        let mut key = vec![];

        let subtype = Subtype::from(u8::consensus_decode(&mut d)?);
        d.read_to_end(&mut key)?;

        Ok(ProprietaryKey {
            prefix,
            subtype,
            key,
        })
    }
}

impl<Subtype> ProprietaryKey<Subtype>
where
    Subtype: Copy + From<u8> + Into<u8>,
{
    /// Constructs [ProprietaryKey] from [Key]; returns
    /// [Error::InvalidProprietaryKey] if `key` do not starts with 0xFC byte
    pub fn from_key(key: Key) -> Result<Self, Error> {
        if key.type_value != 0xFC {
            return Err(Error::InvalidProprietaryKey);
        }

        Ok(deserialize(&key.key)?)
    }

    /// Constructs full [Key] corresponding to this proprietary key type
    pub fn to_key(&self) -> Key {
        Key {
            type_value: 0xFC,
            key: serialize(self),
        }
    }
}
