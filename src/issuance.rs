// Rust Elements Library
// Written in 2019 by
//   The Elements developers
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

//! Asset Issuance

use bitcoin::util::hash::BitcoinHash;
use bitcoin::hashes::{hex, sha256, Hash};
use fast_merkle_root::fast_merkle_root;
use transaction::OutPoint;

/// The zero hash.
const ZERO32: [u8; 32] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];
/// The one hash.
const ONE32: [u8; 32] = [
    1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];
/// The two hash.
const TWO32: [u8; 32] = [
    2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

/// An issued asset ID.
#[derive(Copy, Clone, PartialEq, Eq, Default, PartialOrd, Ord, Hash)]
pub struct AssetId(sha256::Midstate);

impl AssetId {
    /// Create an [AssetId] from its inner type.
    pub fn from_inner(midstate: sha256::Midstate) -> AssetId {
        AssetId(midstate)
    }

    /// Convert the [AssetId] into its inner type.
    pub fn into_inner(self) -> sha256::Midstate {
        self.0
    }

    /// Generate the asset entropy from the issuance prevout and the contract hash.
    pub fn generate_asset_entropy(
        prevout: OutPoint,
        contract_hash: sha256::Hash,
    ) -> sha256::Midstate {
        // E : entropy
        // I : prevout
        // C : contract
        // E = H( H(I) || H(C) )
        fast_merkle_root(&[prevout.bitcoin_hash().into_inner(), contract_hash.into_inner()])
    }

    /// Calculate the asset ID from the asset entropy.
    pub fn from_entropy(entropy: sha256::Midstate) -> AssetId {
        // H_a : asset tag
        // E   : entropy
        // H_a = H( E || 0 )
        AssetId(fast_merkle_root(&[entropy.into_inner(), ZERO32]))
    }

    /// Calculate the reissuance token asset ID from the asset entropy.
    pub fn reissuance_token_from_entropy(entropy: sha256::Midstate, confidential: bool) -> AssetId {
        // H_a : asset reissuance tag
        // E   : entropy
        // if not fConfidential:
        //     H_a = H( E || 1 )
        // else
        //     H_a = H( E || 2 )
        let second = match confidential {
            false => ONE32,
            true => TWO32,
        };
        AssetId(fast_merkle_root(&[entropy.into_inner(), second]))
    }
}

impl hex::FromHex for AssetId {
    fn from_byte_iter<I>(iter: I) -> Result<Self, hex::Error>
    where
        I: Iterator<Item = Result<u8, hex::Error>> + ExactSizeIterator + DoubleEndedIterator,
    {
        sha256::Midstate::from_byte_iter(iter).map(AssetId)
    }
}

impl ::std::fmt::Display for AssetId {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        ::std::fmt::Display::fmt(&self.0, f)
    }
}

impl ::std::fmt::Debug for AssetId {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        ::std::fmt::Display::fmt(&self, f)
    }
}

impl ::std::fmt::LowerHex for AssetId {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        ::std::fmt::LowerHex::fmt(&self.0, f)
    }
}

#[cfg(feature = "serde")]
impl ::serde::Serialize for AssetId {
    fn serialize<S: ::serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use bitcoin::hashes::hex::ToHex;
        if s.is_human_readable() {
            s.serialize_str(&self.to_hex())
        } else {
            s.serialize_bytes(&self.0[..])
        }
    }
}

#[cfg(feature = "serde")]
impl<'de> ::serde::Deserialize<'de> for AssetId {
    fn deserialize<D: ::serde::Deserializer<'de>>(d: D) -> Result<AssetId, D::Error> {
        use bitcoin::hashes::hex::FromHex;

        if d.is_human_readable() {
            struct HexVisitor;

            impl<'de> ::serde::de::Visitor<'de> for HexVisitor {
                type Value = AssetId;

                fn expecting(&self, formatter: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
                    formatter.write_str("an ASCII hex string")
                }

                fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
                where
                    E: ::serde::de::Error,
                {
                    if let Ok(hex) = ::std::str::from_utf8(v) {
                        AssetId::from_hex(hex).map_err(E::custom)
                    } else {
                        return Err(E::invalid_value(::serde::de::Unexpected::Bytes(v), &self));
                    }
                }

                fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
                where
                    E: ::serde::de::Error,
                {
                    AssetId::from_hex(v).map_err(E::custom)
                }
            }

            d.deserialize_str(HexVisitor)
        } else {
            struct BytesVisitor;

            impl<'de> ::serde::de::Visitor<'de> for BytesVisitor {
                type Value = AssetId;

                fn expecting(&self, formatter: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
                    formatter.write_str("a bytestring")
                }

                fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
                where
                    E: ::serde::de::Error,
                {
                    if v.len() != 32 {
                        Err(E::invalid_length(v.len(), &stringify!($len)))
                    } else {
                        let mut ret = [0; 32];
                        ret.copy_from_slice(v);
                        Ok(AssetId(sha256::Midstate::from_inner(ret)))
                    }
                }
            }

            d.deserialize_bytes(BytesVisitor)
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::str::FromStr;

    use bitcoin::hashes::hex::FromHex;
    use bitcoin::hashes::sha256;

    #[test]
    fn example_elements_core() {
        // example test data from Elements Core 0.17
        let prevout_str = "05a047c98e82a848dee94efcf32462b065198bebf2404d201ba2e06db30b28f4:0";
        let entropy_hex = "746f447f691323502cad2ef646f932613d37a83aeaa2133185b316648df4b70a";
        let asset_id_hex = "dcd60818d863b5c026c40b2bc3ba6fdaf5018bcc8606c18adf7db4da0bcd8533";
        let token_id_hex = "c1adb114f4f87d33bf9ce90dd4f9ca523dd414d6cd010a7917903e2009689530";

        let contract_hash = sha256::Hash::from_inner(ZERO32);
        let prevout = OutPoint::from_str(prevout_str).unwrap();
        let entropy = sha256::Midstate::from_hex(entropy_hex).unwrap();
        assert_eq!(AssetId::generate_asset_entropy(prevout, contract_hash), entropy);
        let asset_id = AssetId::from_hex(asset_id_hex).unwrap();
        assert_eq!(AssetId::from_entropy(entropy), asset_id);
        let token_id = AssetId::from_hex(token_id_hex).unwrap();
        assert_eq!(AssetId::reissuance_token_from_entropy(entropy, false), token_id);
    }
}
