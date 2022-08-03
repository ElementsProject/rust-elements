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

use std::io;
use std::str::FromStr;

use bitcoin::hashes::{self, hex, sha256, sha256d, Hash};

use crate::encode::{self, Encodable, Decodable};
use crate::fast_merkle_root::fast_merkle_root;
use secp256k1_zkp::Tag;
use crate::transaction::OutPoint;

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

hash_newtype!(ContractHash, sha256::Hash, 32, doc="The hash of an asset contract.", true);

impl ContractHash {
    /// Calculate the contract hash of a JSON contract object.
    ///
    /// This method does not perform any validation of the contents of the contract.
    /// After basic JSON syntax validation, the object is formatted in a standard way to calculate
    /// the hash.
    #[cfg(feature = "json-contract")]
    pub fn from_json_contract(json: &str) -> Result<ContractHash, ::serde_json::Error> {
        // Parsing the JSON into a BTreeMap will recursively order object keys
        // lexicographically. This order is respected when we later serialize
        // it again.
        let ordered: ::std::collections::BTreeMap<String, ::serde_json::Value> =
            ::serde_json::from_str(json)?;

        let mut engine = ContractHash::engine();
        ::serde_json::to_writer(&mut engine, &ordered).expect("engines don't error");
        Ok(ContractHash::from_engine(engine))
    }
}

/// An issued asset ID.
#[derive(Copy, Clone, PartialEq, Eq, Default, PartialOrd, Ord, Hash)]
pub struct AssetId(sha256::Midstate);

impl AssetId {
    /// The asset ID for L-BTC, Bitcoin on the Liquid network.
    pub const LIQUID_BTC: AssetId = AssetId(sha256::Midstate([
        0x6d, 0x52, 0x1c, 0x38, 0xec, 0x1e, 0xa1, 0x57,
        0x34, 0xae, 0x22, 0xb7, 0xc4, 0x60, 0x64, 0x41,
        0x28, 0x29, 0xc0, 0xd0, 0x57, 0x9f, 0x0a, 0x71,
        0x3d, 0x1c, 0x04, 0xed, 0xe9, 0x79, 0x02, 0x6f,
    ]));

    /// Create an [AssetId] from its inner type.
    pub fn from_inner(midstate: sha256::Midstate) -> AssetId {
        AssetId(midstate)
    }

    /// Convert the [AssetId] into its inner type.
    pub fn into_inner(self) -> sha256::Midstate {
        self.0
    }

    /// Copies a byte slice into an AssetId object
    pub fn from_slice(sl: &[u8]) -> Result<AssetId, hashes::Error> {
        sha256::Midstate::from_slice(sl).map(AssetId)
    }

    /// Generate the asset entropy from the issuance prevout and the contract hash.
    pub fn generate_asset_entropy(
        prevout: OutPoint,
        contract_hash: ContractHash,
    ) -> sha256::Midstate {
        // E : entropy
        // I : prevout
        // C : contract
        // E = H( H(I) || H(C) )
        let prevout_hash = {
            let mut enc = sha256d::Hash::engine();
            prevout.consensus_encode(&mut enc).unwrap();
            sha256d::Hash::from_engine(enc)
        };
        fast_merkle_root(&[prevout_hash.into_inner(), contract_hash.into_inner()])
    }

    /// Calculate the asset ID from the asset entropy.
    pub fn from_entropy(entropy: sha256::Midstate) -> AssetId {
        // H_a : asset tag
        // E   : entropy
        // H_a = H( E || 0 )
        AssetId(fast_merkle_root(&[entropy.into_inner(), ZERO32]))
    }

    /// Computes the asset ID when issuing asset from issuing input and contract hash
    pub fn new_issuance(prevout: OutPoint, contract_hash: ContractHash) -> Self {
        let entropy = AssetId::generate_asset_entropy(prevout, contract_hash);
        AssetId::from_entropy(entropy)
    }

    /// Computes the re-issuance token from input and contract hash
    pub fn new_reissuance_token(prevout: OutPoint, contract_hash: ContractHash, confidential: bool) -> Self {
        let entropy = AssetId::generate_asset_entropy(prevout, contract_hash);
        AssetId::reissuance_token_from_entropy(entropy, confidential)
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

    /// Convert an asset into [Tag]
    pub fn into_tag(self) -> Tag {
        self.0.into_inner().into()
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

impl FromStr for AssetId {
    type Err = hex::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        hex::FromHex::from_hex(s)
    }
}

impl Encodable for AssetId {
    fn consensus_encode<W: io::Write>(&self, e: W) -> Result<usize, encode::Error> {
        self.0.consensus_encode(e)
    }
}

impl Decodable for AssetId {
    fn consensus_decode<D: io::Read>(d: D) -> Result<Self, encode::Error> {
        Ok(Self::from_inner(sha256::Midstate::consensus_decode(d)?))
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

        let contract_hash = ContractHash::from_inner(ZERO32);
        let prevout = OutPoint::from_str(prevout_str).unwrap();
        let entropy = sha256::Midstate::from_hex(entropy_hex).unwrap();
        assert_eq!(AssetId::generate_asset_entropy(prevout, contract_hash), entropy);
        let asset_id = AssetId::from_hex(asset_id_hex).unwrap();
        assert_eq!(AssetId::from_entropy(entropy), asset_id);
        let token_id = AssetId::from_hex(token_id_hex).unwrap();
        assert_eq!(AssetId::reissuance_token_from_entropy(entropy, false), token_id);

        // example test data from Elements Core 0.21 with prevout vout = 1
        let prevout_str = "c76664aa4be760056dcc39b59637eeea8f3c3c3b2aeefb9f23a7b99945a2931e:1";
        let entropy_hex = "bc67a13736341d8ad19e558433483a38cae48a44a5a8b5598ca0b01b5f9f9f41";
        let asset_id_hex = "2ec6c1a06e895b06fffb8dc36084255f890467fb906565b0c048d4c807b4a129";
        let token_id_hex = "d09d205ff7c626ca98c91fed24787ff747fec62194ed1b7e6ef6cc775a1a1fdc";

        let contract_hash = ContractHash::from_inner(ZERO32);
        let prevout = OutPoint::from_str(prevout_str).unwrap();
        let entropy = sha256::Midstate::from_hex(entropy_hex).unwrap();
        assert_eq!(AssetId::generate_asset_entropy(prevout, contract_hash), entropy);
        let asset_id = AssetId::from_hex(asset_id_hex).unwrap();
        assert_eq!(AssetId::from_entropy(entropy), asset_id);
        let token_id = AssetId::from_hex(token_id_hex).unwrap();
        assert_eq!(AssetId::reissuance_token_from_entropy(entropy, true), token_id);


        // example test data from Elements Core 0.21 with a given contract hash and non-blinded issuance
        let prevout_str = "ee45365ddb62e8822182fbdd132fb156b4991e0b7411cff4aab576fd964f2edb:0"; // txid parsed reverse
        let contract_hash_hex = "e06e6d4933e76afd7b9cc6a013e0855aa60bbe6d2fca1c27ec6951ff5f1a20c9"; // parsed reverse
        let entropy_hex = "1922da340705eef526640b49d28b08928630d1ad52db0f945f3c389267e292c9"; // parsed reverse
        let asset_id_hex = "8eebf6109bca0331fe559f0cbd1ef846a2bbb6812f3ae3d8b0b610170cc21a4e"; // parsed reverse
        let token_id_hex = "eb02cbc591c9ede071625c129f0a1fab386202cb27a894a45be0d564e961d6bc"; // parsed reverse

        let contract_hash = ContractHash::from_hex(contract_hash_hex).unwrap();
        let prevout = OutPoint::from_str(prevout_str).unwrap();
        let entropy = sha256::Midstate::from_hex(entropy_hex).unwrap();
        assert_eq!(AssetId::generate_asset_entropy(prevout, contract_hash), entropy);
        let asset_id = AssetId::from_hex(asset_id_hex).unwrap();
        assert_eq!(AssetId::from_entropy(entropy), asset_id);
        let token_id = AssetId::from_hex(token_id_hex).unwrap();
        assert_eq!(AssetId::reissuance_token_from_entropy(entropy, false), token_id);

        // example test data from Elements Core 0.21
        // with confidential re-issuance
        let prevout_str = "8903ee739b52859877fbfedc58194c2d59d0f5a4ea3c2774dc3cba3031cec757:0";
        let entropy_hex = "b9789de8589dc1b664e4f2bda4d04af9d4d2180394a8c47b1f889acfb5e0acc4";
        let asset_id_hex = "bdab916e8cda17781bcdb84505452e44d0ab2f080e9e5dd7765ffd5ce0c07cd9";
        let token_id_hex = "f144868169dfc7afc024c4d8f55607ac8dfe925e67688650a9cdc54c3cfa5b1c";

        let contract_hash = ContractHash::from_inner(ZERO32);
        let prevout = OutPoint::from_str(prevout_str).unwrap();
        let entropy = sha256::Midstate::from_hex(entropy_hex).unwrap();
        assert_eq!(AssetId::generate_asset_entropy(prevout, contract_hash), entropy);
        let asset_id = AssetId::from_hex(asset_id_hex).unwrap();
        assert_eq!(AssetId::from_entropy(entropy), asset_id);
        let token_id = AssetId::from_hex(token_id_hex).unwrap();
        assert_eq!(AssetId::reissuance_token_from_entropy(entropy, true), token_id);
    }

    #[cfg(feature = "json-contract")]
    #[test]
    fn test_json_contract() {
        let tether = ContractHash::from_hex("3c7f0a53c2ff5b99590620d7f6604a7a3a7bfbaaa6aa61f7bfc7833ca03cde82").unwrap();

        let correct = r#"{"entity":{"domain":"tether.to"},"issuer_pubkey":"0337cceec0beea0232ebe14cba0197a9fbd45fcf2ec946749de920e71434c2b904","name":"Tether USD","precision":8,"ticker":"USDt","version":0}"#;
        let expected = ContractHash::hash(correct.as_bytes());
        assert_eq!(tether, expected);
        assert_eq!(expected, ContractHash::from_json_contract(&correct).unwrap());

        let invalid_json = r#"{"entity":{"domain":"tether.to"},"issuer_pubkey:"#;
        assert!(ContractHash::from_json_contract(&invalid_json).is_err());

        let unordered = r#"{"precision":8,"ticker":"USDt","entity":{"domain":"tether.to"},"issuer_pubkey":"0337cceec0beea0232ebe14cba0197a9fbd45fcf2ec946749de920e71434c2b904","name":"Tether USD","version":0}"#;
        assert_eq!(expected, ContractHash::from_json_contract(&unordered).unwrap());

        let unordered = r#"{"precision":8,"name":"Tether USD","ticker":"USDt","entity":{"domain":"tether.to"},"issuer_pubkey":"0337cceec0beea0232ebe14cba0197a9fbd45fcf2ec946749de920e71434c2b904","version":0}"#;
        assert_eq!(expected, ContractHash::from_json_contract(&unordered).unwrap());

        let spaces = r#"{"precision":8, "name" : "Tether USD", "ticker":"USDt",  "entity":{"domain":"tether.to" }, "issuer_pubkey" :"0337cceec0beea0232ebe14cba0197a9fbd45fcf2ec946749de920e71434c2b904","version":0} "#;
        assert_eq!(expected, ContractHash::from_json_contract(&spaces).unwrap());

        let nested_correct = r#"{"entity":{"author":"Tether Inc","copyright":2020,"domain":"tether.to","hq":"Mars"},"issuer_pubkey":"0337cceec0beea0232ebe14cba0197a9fbd45fcf2ec946749de920e71434c2b904","name":"Tether USD","precision":8,"ticker":"USDt","version":0}"#;
        let nested_expected = ContractHash::hash(nested_correct.as_bytes());
        assert_eq!(nested_expected, ContractHash::from_json_contract(&nested_correct).unwrap());

        let nested_unordered = r#"{"ticker":"USDt","entity":{"domain":"tether.to","hq":"Mars","author":"Tether Inc","copyright":2020},"issuer_pubkey":"0337cceec0beea0232ebe14cba0197a9fbd45fcf2ec946749de920e71434c2b904","name":"Tether USD","precision":8,"version":0}"#;
        assert_eq!(nested_expected, ContractHash::from_json_contract(&nested_unordered).unwrap());
    }

    #[test]
    fn liquid() {
        assert_eq!(
            AssetId::LIQUID_BTC.to_string(),
            "6f0279e9ed041c3d710a9f57d0c02928416460c4b722ae3457a11eec381c526d",
        );
    }
}
