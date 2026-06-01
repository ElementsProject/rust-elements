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

use crate::encode::{self, Encodable, Decodable};
use crate::hashes::{hash_newtype, sha256, sha256d};
use crate::fast_merkle_root::fast_merkle_root;
use secp256k1_zkp::Tag;
use crate::genesis::{commit_to_custom_network_parameters, NetworkParams};
use crate::transaction::OutPoint;
use crate::Txid;

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

hash_newtype!(
    /// The hash of an asset contract.
    #[hash_newtype(backward)]
    pub struct ContractHash(sha256::Hash);
);
hashes::impl_hex_for_newtype!(ContractHash);
#[cfg(feature = "serde")]
hashes::impl_serde_for_newtype!(ContractHash);

impl_sha256_midstate_wrapper! {
    /// A hash of some data used as "asset entropy" to seed the ID of a new asset.
    pub struct AssetEntropy([u8; 32]);
}

impl_sha256_midstate_wrapper! {
    /// An issued asset ID.
    pub struct AssetId([u8; 32]);
}

impl ContractHash {
    /// Calculate the contract hash of a JSON contract object.
    ///
    /// This method does not perform any validation of the contents of the contract.
    /// After basic JSON syntax validation, the object is formatted in a standard way to calculate
    /// the hash.
    #[cfg(feature = "json-contract")]
    pub fn from_json_contract(json: &str) -> Result<ContractHash, ::serde_json::Error> {
        use crate::hashes::HashEngine as _;
        
        // Parsing the JSON into a BTreeMap will recursively order object keys
        // lexicographically. This order is respected when we later serialize
        // it again.
        let ordered: ::std::collections::BTreeMap<String, ::serde_json::Value> =
            ::serde_json::from_str(json)?;

        let mut engine = sha256::Hash::engine();
        ::serde_json::to_writer(&mut engine, &ordered).expect("engines don't error");
        Ok(ContractHash(engine.finalize()))
    }
}

impl AssetId {
    /// The asset ID for L-BTC, Bitcoin on the Liquid network.
    pub const LIQUID_BTC: AssetId = AssetId([
        0x6d, 0x52, 0x1c, 0x38, 0xec, 0x1e, 0xa1, 0x57,
        0x34, 0xae, 0x22, 0xb7, 0xc4, 0x60, 0x64, 0x41,
        0x28, 0x29, 0xc0, 0xd0, 0x57, 0x9f, 0x0a, 0x71,
        0x3d, 0x1c, 0x04, 0xed, 0xe9, 0x79, 0x02, 0x6f,
    ]);

    /// The asset ID for L-BTC, Bitcoin on the Liquidtestnet network.
    pub const LIQUIDTESTNET_BTC: AssetId = AssetId([
        0x49, 0x9a, 0x81, 0x85, 0x45, 0xf6, 0xba, 0xe3,
        0x9f, 0xc0, 0x3b, 0x63, 0x7f, 0x2a, 0x4e, 0x1e,
        0x64, 0xe5, 0x90, 0xca, 0xc1, 0xbc, 0x3a, 0x6f,
        0x6d, 0x71, 0xaa, 0x44, 0x43, 0x65, 0x4c, 0x14,
    ]);

    /// Generate the asset entropy from the issuance prevout and the contract hash.
    pub fn generate_asset_entropy(
        prevout: OutPoint,
        contract_hash: ContractHash,
    ) -> AssetEntropy {
        // E : entropy
        // I : prevout
        // C : contract
        // E = H( H(I) || H(C) )
        let prevout_hash = {
            let mut enc = sha256d::Hash::engine();
            prevout.consensus_encode(&mut enc).unwrap();
            sha256d::Hash::from_engine(enc)
        };
        AssetEntropy::from_midstate(fast_merkle_root(&[prevout_hash.to_byte_array(), contract_hash.to_byte_array()]))
    }

    /// Calculate the asset ID from the asset entropy.
    pub fn from_entropy(entropy: AssetEntropy) -> AssetId {
        // H_a : asset tag
        // E   : entropy
        // H_a = H( E || 0 )
        AssetId::from_midstate(fast_merkle_root(&[entropy.to_byte_array(), ZERO32]))
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
    pub fn reissuance_token_from_entropy(entropy: AssetEntropy, confidential: bool) -> AssetId {
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
        AssetId::from_midstate(fast_merkle_root(&[entropy.to_byte_array(), second]))
    }

    /// Convert an asset into [Tag]
    pub fn into_tag(self) -> Tag {
        self.0.into()
    }

    /// Pegged asset id for given network parameters
    pub fn pegged_asset_id_for_network_params(params: &NetworkParams) -> AssetId {
        match params.network_id.as_str() {
            "liquidv1" => Self::LIQUID_BTC,
            "liquidtestnet" => Self::LIQUIDTESTNET_BTC,
            _ => {
                // Else calculate the asset_id
                Self::pegged_asset_id_for_params_and_parent_chain_hash(
                    params,
                    bitcoin::Network::Regtest.chain_hash(),
                )
            }
        }
    }

    /// Calculate the `AssetId` for the pegged asset for a given set of network parameters assuming
    /// a Regtest parent network
    fn pegged_asset_id_for_params_and_parent_chain_hash(params: &NetworkParams, parent_chainhash: bitcoin::blockdata::constants::ChainHash) -> AssetId {
        let commit = commit_to_custom_network_parameters(params);
        let asset_outpoint = OutPoint::new(Txid::from_byte_array(commit.to_byte_array()), 0);
        let asset_entropy = AssetId::generate_asset_entropy(asset_outpoint, ContractHash::from_byte_array(*parent_chainhash.as_ref()));
        AssetId::from_entropy(asset_entropy)
    }
}

impl Encodable for AssetId {
    fn consensus_encode<W: io::Write>(&self, e: W) -> Result<usize, encode::Error> {
        self.0.consensus_encode(e)
    }
}

impl Decodable for AssetId {
    fn consensus_decode<D: io::Read>(d: D) -> Result<Self, encode::Error> {
        Decodable::consensus_decode(d).map(Self)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::str::FromStr;
    use bitcoin::constants::ChainHash;

    #[test]
    fn example_elements_core() {
        // example test data from Elements Core 0.17
        let prevout_str = "05a047c98e82a848dee94efcf32462b065198bebf2404d201ba2e06db30b28f4:0";
        let entropy_hex = "746f447f691323502cad2ef646f932613d37a83aeaa2133185b316648df4b70a";
        let asset_id_hex = "dcd60818d863b5c026c40b2bc3ba6fdaf5018bcc8606c18adf7db4da0bcd8533";
        let token_id_hex = "c1adb114f4f87d33bf9ce90dd4f9ca523dd414d6cd010a7917903e2009689530";

        let contract_hash = ContractHash::from_byte_array(ZERO32);
        let prevout = OutPoint::from_str(prevout_str).unwrap();
        let entropy = AssetEntropy::from_str(entropy_hex).unwrap();
        assert_eq!(AssetId::generate_asset_entropy(prevout, contract_hash), entropy);
        let asset_id = AssetId::from_str(asset_id_hex).unwrap();
        assert_eq!(AssetId::from_entropy(entropy), asset_id);
        let token_id = AssetId::from_str(token_id_hex).unwrap();
        assert_eq!(AssetId::reissuance_token_from_entropy(entropy, false), token_id);

        // example test data from Elements Core 0.21 with prevout vout = 1
        let prevout_str = "c76664aa4be760056dcc39b59637eeea8f3c3c3b2aeefb9f23a7b99945a2931e:1";
        let entropy_hex = "bc67a13736341d8ad19e558433483a38cae48a44a5a8b5598ca0b01b5f9f9f41";
        let asset_id_hex = "2ec6c1a06e895b06fffb8dc36084255f890467fb906565b0c048d4c807b4a129";
        let token_id_hex = "d09d205ff7c626ca98c91fed24787ff747fec62194ed1b7e6ef6cc775a1a1fdc";

        let contract_hash = ContractHash::from_byte_array(ZERO32);
        let prevout = OutPoint::from_str(prevout_str).unwrap();
        let entropy = AssetEntropy::from_str(entropy_hex).unwrap();
        assert_eq!(AssetId::generate_asset_entropy(prevout, contract_hash), entropy);
        let asset_id = AssetId::from_str(asset_id_hex).unwrap();
        assert_eq!(AssetId::from_entropy(entropy), asset_id);
        let token_id = AssetId::from_str(token_id_hex).unwrap();
        assert_eq!(AssetId::reissuance_token_from_entropy(entropy, true), token_id);


        // example test data from Elements Core 0.21 with a given contract hash and non-blinded issuance
        let prevout_str = "ee45365ddb62e8822182fbdd132fb156b4991e0b7411cff4aab576fd964f2edb:0"; // txid parsed reverse
        let contract_hash_hex = "e06e6d4933e76afd7b9cc6a013e0855aa60bbe6d2fca1c27ec6951ff5f1a20c9"; // parsed reverse
        let entropy_hex = "1922da340705eef526640b49d28b08928630d1ad52db0f945f3c389267e292c9"; // parsed reverse
        let asset_id_hex = "8eebf6109bca0331fe559f0cbd1ef846a2bbb6812f3ae3d8b0b610170cc21a4e"; // parsed reverse
        let token_id_hex = "eb02cbc591c9ede071625c129f0a1fab386202cb27a894a45be0d564e961d6bc"; // parsed reverse

        let contract_hash = ContractHash::from_str(contract_hash_hex).unwrap();
        let prevout = OutPoint::from_str(prevout_str).unwrap();
        let entropy = AssetEntropy::from_str(entropy_hex).unwrap();
        assert_eq!(AssetId::generate_asset_entropy(prevout, contract_hash), entropy);
        let asset_id = AssetId::from_str(asset_id_hex).unwrap();
        assert_eq!(AssetId::from_entropy(entropy), asset_id);
        let token_id = AssetId::from_str(token_id_hex).unwrap();
        assert_eq!(AssetId::reissuance_token_from_entropy(entropy, false), token_id);

        // example test data from Elements Core 0.21
        // with confidential re-issuance
        let prevout_str = "8903ee739b52859877fbfedc58194c2d59d0f5a4ea3c2774dc3cba3031cec757:0";
        let entropy_hex = "b9789de8589dc1b664e4f2bda4d04af9d4d2180394a8c47b1f889acfb5e0acc4";
        let asset_id_hex = "bdab916e8cda17781bcdb84505452e44d0ab2f080e9e5dd7765ffd5ce0c07cd9";
        let token_id_hex = "f144868169dfc7afc024c4d8f55607ac8dfe925e67688650a9cdc54c3cfa5b1c";

        let contract_hash = ContractHash::from_byte_array(ZERO32);
        let prevout = OutPoint::from_str(prevout_str).unwrap();
        let entropy = AssetEntropy::from_str(entropy_hex).unwrap();
        assert_eq!(AssetId::generate_asset_entropy(prevout, contract_hash), entropy);
        let asset_id = AssetId::from_str(asset_id_hex).unwrap();
        assert_eq!(AssetId::from_entropy(entropy), asset_id);
        let token_id = AssetId::from_str(token_id_hex).unwrap();
        assert_eq!(AssetId::reissuance_token_from_entropy(entropy, true), token_id);
    }

    #[cfg(feature = "json-contract")]
    #[test]
    fn test_json_contract() {
        let tether = ContractHash::from_str("3c7f0a53c2ff5b99590620d7f6604a7a3a7bfbaaa6aa61f7bfc7833ca03cde82").unwrap();

        let correct = r#"{"entity":{"domain":"tether.to"},"issuer_pubkey":"0337cceec0beea0232ebe14cba0197a9fbd45fcf2ec946749de920e71434c2b904","name":"Tether USD","precision":8,"ticker":"USDt","version":0}"#;
        let expected = sha256::Hash::hash(correct.as_bytes()).to_byte_array();
        assert_eq!(tether.to_byte_array(), expected);
        assert_eq!(expected, ContractHash::from_json_contract(correct).unwrap().to_byte_array());

        let invalid_json = r#"{"entity":{"domain":"tether.to"},"issuer_pubkey:"#;
        assert!(ContractHash::from_json_contract(invalid_json).is_err());

        let unordered = r#"{"precision":8,"ticker":"USDt","entity":{"domain":"tether.to"},"issuer_pubkey":"0337cceec0beea0232ebe14cba0197a9fbd45fcf2ec946749de920e71434c2b904","name":"Tether USD","version":0}"#;
        assert_eq!(expected, ContractHash::from_json_contract(unordered).unwrap().to_byte_array());

        let unordered = r#"{"precision":8,"name":"Tether USD","ticker":"USDt","entity":{"domain":"tether.to"},"issuer_pubkey":"0337cceec0beea0232ebe14cba0197a9fbd45fcf2ec946749de920e71434c2b904","version":0}"#;
        assert_eq!(expected, ContractHash::from_json_contract(unordered).unwrap().to_byte_array());

        let spaces = r#"{"precision":8, "name" : "Tether USD", "ticker":"USDt",  "entity":{"domain":"tether.to" }, "issuer_pubkey" :"0337cceec0beea0232ebe14cba0197a9fbd45fcf2ec946749de920e71434c2b904","version":0} "#;
        assert_eq!(expected, ContractHash::from_json_contract(spaces).unwrap().to_byte_array());

        let nested_correct = r#"{"entity":{"author":"Tether Inc","copyright":2020,"domain":"tether.to","hq":"Mars"},"issuer_pubkey":"0337cceec0beea0232ebe14cba0197a9fbd45fcf2ec946749de920e71434c2b904","name":"Tether USD","precision":8,"ticker":"USDt","version":0}"#;
        let nested_expected = sha256::Hash::hash(nested_correct.as_bytes()).to_byte_array();
        assert_eq!(nested_expected, ContractHash::from_json_contract(nested_correct).unwrap().to_byte_array());

        let nested_unordered = r#"{"ticker":"USDt","entity":{"domain":"tether.to","hq":"Mars","author":"Tether Inc","copyright":2020},"issuer_pubkey":"0337cceec0beea0232ebe14cba0197a9fbd45fcf2ec946749de920e71434c2b904","name":"Tether USD","precision":8,"version":0}"#;
        assert_eq!(nested_expected, ContractHash::from_json_contract(nested_unordered).unwrap().to_byte_array());
    }

    #[test]
    fn liquid() {
        assert_eq!(
            AssetId::LIQUID_BTC.to_string(),
            "6f0279e9ed041c3d710a9f57d0c02928416460c4b722ae3457a11eec381c526d",
        );
    }

    #[test]
    fn liquid_asset_ids() {
        // Testing the two most common Regtest networks using in Liquid and CLN codebases
        let network_params = NetworkParams::custom_network("elementsregtest".to_string(), None, None, None);
        let asset_id = AssetId::pegged_asset_id_for_params_and_parent_chain_hash(
            &network_params,
            bitcoin::Network::Regtest.chain_hash(),
        );

        let elementsregtest_asset_id = AssetId([
            0x23, 0x0f, 0x4f, 0x5d, 0x4b, 0x7c, 0x6f, 0xa8, 0x45, 0x80, 0x6e, 0xe4,
            0xf6, 0x77, 0x13, 0x45, 0x9e, 0x1b, 0x69, 0xe8, 0xe6, 0x0f, 0xce, 0xe2,
            0xe4, 0x94, 0x0c, 0x7a, 0x0d, 0x5d, 0xe1, 0xb2,
        ]);

        assert_eq!(asset_id, elementsregtest_asset_id);

        let network_params = NetworkParams::custom_network("liquid-regtest".to_string(), None, None, None);
        let asset_id = AssetId::pegged_asset_id_for_params_and_parent_chain_hash(
            &network_params,
            bitcoin::Network::Regtest.chain_hash(),
        );

        let liquid_regtest_assetid = AssetId([
            0x5c, 0xe7, 0xb9, 0x63, 0xd3, 0x7f, 0x8f, 0x2d, 0x51, 0xca, 0xfb, 0xba,
            0x92, 0x8a, 0xaa, 0x9e, 0x22, 0x0b, 0x8b, 0xbc, 0x66, 0x05, 0x71, 0x49,
            0x9c, 0x03, 0x62, 0x8a, 0x38, 0x51, 0xb8, 0xce,
        ]);

        assert_eq!(asset_id, liquid_regtest_assetid);

        let liquidv1_params = NetworkParams::liquidv1();
        let asset_id = AssetId::pegged_asset_id_for_params_and_parent_chain_hash(
            &liquidv1_params,
            bitcoin::Network::Bitcoin.chain_hash(),
        );

        assert_eq!(asset_id, AssetId::LIQUID_BTC);

        let liquidtestnet_params = NetworkParams::liquidtestnet();
        let asset_id = AssetId::pegged_asset_id_for_params_and_parent_chain_hash(
            &liquidtestnet_params,
            ChainHash::from([0u8; 32]),
        );

        assert_eq!(asset_id, AssetId::LIQUIDTESTNET_BTC);
    }
}
