//!
//! An implementation of ELIP0100 as defined in
//! <https://github.com/ElementsProject/ELIPs/blob/main/elip-0100.mediawiki>
//! but excluding contract validation.
//!
//! ELIP0100 defines how to inlcude assets metadata, such as the contract defining the asset and
//! the issuance prevout inside a PSET
//!
//! To use check [`PartiallySignedTransaction::add_asset_metadata`] and
//! [`PartiallySignedTransaction::get_asset_metadata`]
//!

use std::io::Cursor;

use super::{raw::ProprietaryKey, PartiallySignedTransaction};
use crate::{
    encode::{self, Decodable, Encodable},
    AssetId, OutPoint,
};

/// keytype as defined in ELIP0100
pub const PSBT_ELEMENTS_HWW_GLOBAL_ASSET_METADATA: u8 = 0x00u8;

/// Prefix for PSET hardware wallet extension as defined in ELIP0100
pub const PSET_HWW_PREFIX: &[u8] = b"pset_hww";

/// Contains extension to add and retrieve from the PSET contract informations related to an asset
impl PartiallySignedTransaction {
    /// Add contract information to the PSET, returns None if it wasn't present or Some with the old
    /// data if already in the PSET
    pub fn add_asset_metadata(
        &mut self,
        asset_id: AssetId,
        asset_meta: &AssetMetadata,
    ) -> Option<Result<AssetMetadata, encode::Error>> {
        let key = prop_key(&asset_id);
        self.global
            .proprietary
            .insert(key, asset_meta.serialize())
            .map(|old| AssetMetadata::deserialize(&old))
    }

    /// Get contract information from the PSET, returns None if there are no information regarding
    /// the given `asset_id`` in the PSET
    pub fn get_asset_metadata(
        &self,
        asset_id: AssetId,
    ) -> Option<Result<AssetMetadata, encode::Error>> {
        let key = prop_key(&asset_id);

        self.global
            .proprietary
            .get(&key)
            .map(|data| AssetMetadata::deserialize(data))
    }
}

/// Asset metadata, the contract and the outpoint used to issue the asset
#[derive(Debug, PartialEq, Eq)]
pub struct AssetMetadata {
    contract: String,
    issuance_prevout: OutPoint,
}

fn prop_key(asset_id: &AssetId) -> ProprietaryKey {
    let mut key = Vec::with_capacity(32);
    asset_id
        .consensus_encode(&mut key)
        .expect("vec doesn't err"); // equivalent to asset_tag

    ProprietaryKey {
        prefix: PSET_HWW_PREFIX.to_vec(),
        subtype: 0x00,
        key,
    }
}

impl AssetMetadata {
    /// Returns the contract as string containing a json
    pub fn contract(&self) -> &str {
        &self.contract
    }

    /// Returns the issuance prevout where the asset has been issued
    pub fn issuance_prevout(&self) -> OutPoint {
        self.issuance_prevout
    }

    /// Serialize this metadata as defined by ELIP0100
    ///
    /// `<compact size uint contractLen><contract><32-byte prevoutTxid><32-bit little endian uint prevoutIndex>`
    pub fn serialize(&self) -> Vec<u8> {
        let mut result = vec![];

        encode::consensus_encode_with_size(self.contract.as_bytes(), &mut result)
            .expect("vec doesn't err");

        self.issuance_prevout
            .consensus_encode(&mut result)
            .expect("vec doesn't err");

        result
    }

    /// Deserialize this metadata as defined by ELIP0100
    pub fn deserialize(data: &[u8]) -> Result<AssetMetadata, encode::Error> {
        let mut cursor = Cursor::new(data);
        let str_bytes = Vec::<u8>::consensus_decode(&mut cursor)?;

        let contract = String::from_utf8(str_bytes).map_err(|_| {
            encode::Error::ParseFailed("utf8 conversion fail on the contract string")
        })?;

        let issuance_prevout = OutPoint::consensus_decode(&mut cursor)?;

        Ok(AssetMetadata {
            contract,
            issuance_prevout,
        })
    }
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use crate::encode::serialize;
    use crate::{OutPoint, Txid};
    use bitcoin::hashes::hex::FromHex;
    use bitcoin::hashes::Hash;

    use crate::{
        encode::{serialize_hex, Encodable},
        hex::ToHex,
        pset::{elip100::PSET_HWW_PREFIX, map::Map, PartiallySignedTransaction},
        AssetId,
    };

    use super::{prop_key, AssetMetadata};

    #[cfg(feature = "json-contract")]
    const CONTRACT_HASH: &str = "3c7f0a53c2ff5b99590620d7f6604a7a3a7bfbaaa6aa61f7bfc7833ca03cde82";

    const VALID_CONTRACT: &str = r#"{"entity":{"domain":"tether.to"},"issuer_pubkey":"0337cceec0beea0232ebe14cba0197a9fbd45fcf2ec946749de920e71434c2b904","name":"Tether USD","precision":8,"ticker":"USDt","version":0}"#;
    const ISSUANCE_PREVOUT: &str =
        "9596d259270ef5bac0020435e6d859aea633409483ba64e232b8ba04ce288668:0";
    const ASSET_ID: &str = "ce091c998b83c78bb71a632313ba3760f1763d9cfcffae02258ffa9865a37bd2";

    const ELIP0100_IDENTIFIER: &str = "fc08707365745f68777700";
    const ELIP0100_ASSET_TAG: &str =
        "48f835622f34e8fdc313c90d4a8659aa4afe993e32dcb03ae6ec9ccdc6fcbe18";

    const ELIP0100_CONTRACT: &str = r#"{"entity":{"domain":"example.com"},"issuer_pubkey":"03455ee7cedc97b0ba435b80066fc92c963a34c600317981d135330c4ee43ac7a3","name":"Testcoin","precision":2,"ticker":"TEST","version":0}"#;
    const ELIP0100_PREVOUT_TXID: &str =
        "3514a07cf4812272c24a898c482f587a51126beef8c9b76a9e30bf41b0cbe53c";

    const ELIP0100_PREVOUT_VOUT: u32 = 1;
    const ELIP0100_ASSET_METADATA_RECORD_KEY: &str =
        "fc08707365745f6877770018befcc6cd9cece63ab0dc323e99fe4aaa59864a0dc913c3fde8342f6235f848";
    const ELIP0100_ASSET_METADATA_RECORD_VALUE_WRONG: &str = "b47b22656e74697479223a7b22646f6d61696e223a226578616d706c652e636f6d227d2c226973737565725f7075626b6579223a22303334353565653763656463393762306261343335623830303636666339326339363361333463363030333137393831643133353333306334656534336163376133222c226e616d65223a2254657374636f696e222c22707265636973696f6e223a322c227469636b6572223a2254455354222c2276657273696f6e223a307d3514a07cf4812272c24a898c482f587a51126beef8c9b76a9e30bf41b0cbe53c01000000";

    const ELIP0100_ASSET_METADATA_RECORD_VALUE: &str = "b47b22656e74697479223a7b22646f6d61696e223a226578616d706c652e636f6d227d2c226973737565725f7075626b6579223a22303334353565653763656463393762306261343335623830303636666339326339363361333463363030333137393831643133353333306334656534336163376133222c226e616d65223a2254657374636f696e222c22707265636973696f6e223a322c227469636b6572223a2254455354222c2276657273696f6e223a307d3ce5cbb041bf309e6ab7c9f8ee6b12517a582f488c894ac2722281f47ca0143501000000";
    fn mockup_asset_metadata() -> (AssetId, AssetMetadata) {
        (
            AssetId::from_str(ASSET_ID).unwrap(),
            AssetMetadata {
                contract: VALID_CONTRACT.to_string(),
                issuance_prevout: ISSUANCE_PREVOUT.parse().unwrap(),
            },
        )
    }

    #[cfg(feature = "json-contract")]
    #[test]
    fn asset_metadata_roundtrip() {
        let (_, asset_metadata) = mockup_asset_metadata();
        let contract_hash = crate::ContractHash::from_str(CONTRACT_HASH).unwrap();
        assert_eq!(
            crate::ContractHash::from_json_contract(VALID_CONTRACT).unwrap(),
            contract_hash
        );
        assert_eq!(asset_metadata.serialize().to_hex(),"b47b22656e74697479223a7b22646f6d61696e223a227465746865722e746f227d2c226973737565725f7075626b6579223a22303333376363656563306265656130323332656265313463626130313937613966626434356663663265633934363734396465393230653731343334633262393034222c226e616d65223a2254657468657220555344222c22707265636973696f6e223a382c227469636b6572223a2255534474222c2276657273696f6e223a307d688628ce04bab832e264ba83944033a6ae59d8e6350402c0baf50e2759d2969500000000");

        assert_eq!(
            AssetMetadata::deserialize(&asset_metadata.serialize()).unwrap(),
            asset_metadata
        );
    }

    #[test]
    fn prop_key_serialize() {
        let asset_id = AssetId::from_str(ASSET_ID).unwrap();

        let key = prop_key(&asset_id);
        let mut vec = vec![];
        key.consensus_encode(&mut vec).unwrap();

        assert_eq!(
            vec.to_hex(),
            format!("08{}00{}", PSET_HWW_PREFIX.to_hex(), asset_id.into_tag())
        );

        assert!(vec.to_hex().starts_with(&ELIP0100_IDENTIFIER[2..])); // cut prefix "fc: which is PSET_GLOBAL_PROPRIETARY serialized one level up
    }

    #[test]
    fn set_get_asset_metadata() {
        let mut pset = PartiallySignedTransaction::new_v2();
        let (asset_id, asset_meta) = mockup_asset_metadata();

        let old = pset.add_asset_metadata(asset_id, &asset_meta);
        assert!(old.is_none());
        let old = pset
            .add_asset_metadata(asset_id, &asset_meta)
            .unwrap()
            .unwrap();
        assert_eq!(old, asset_meta);

        assert!(serialize_hex(&pset).contains(ELIP0100_IDENTIFIER));

        let get = pset.get_asset_metadata(asset_id).unwrap().unwrap();
        assert_eq!(get, asset_meta);
    }

    #[test]
    fn elip0100_test_vector() {
        let mut pset = PartiallySignedTransaction::new_v2();

        let asset_id = AssetId::from_str(ELIP0100_ASSET_TAG).unwrap();
        let txid = Txid::from_str(ELIP0100_PREVOUT_TXID).unwrap();

        let asset_meta = AssetMetadata {
            contract: ELIP0100_CONTRACT.to_string(),
            issuance_prevout: OutPoint {
                txid,
                vout: ELIP0100_PREVOUT_VOUT,
            },
        };

        pset.add_asset_metadata(asset_id, &asset_meta);

        let expected_key = Vec::<u8>::from_hex(ELIP0100_ASSET_METADATA_RECORD_KEY).unwrap();

        let values: Vec<Vec<u8>> = pset
            .global
            .get_pairs()
            .unwrap()
            .into_iter()
            .filter(|p| serialize(&p.key)[1..] == expected_key[..]) // NOTE key serialization contains an initial varint with the lenght of the key which is not present in the test vector
            .map(|p| p.value)
            .collect();
        assert_eq!(values.len(), 1);
        assert_eq!(values[0].to_hex(), ELIP0100_ASSET_METADATA_RECORD_VALUE);

        let txid_hex_non_convention = txid.as_byte_array().to_vec().to_hex();
        assert_eq!(
            ELIP0100_ASSET_METADATA_RECORD_VALUE,
            ELIP0100_ASSET_METADATA_RECORD_VALUE_WRONG
                .replace(ELIP0100_PREVOUT_TXID, &txid_hex_non_convention),
            "only change in the value is the txid"
        );
    }

    #[cfg(feature = "json-contract")]
    #[test]
    fn elip0100_contract() {
        let txid = Txid::from_str(ELIP0100_PREVOUT_TXID).unwrap();
        let prevout = OutPoint {
            txid,
            vout: ELIP0100_PREVOUT_VOUT,
        };

        let contract_hash = crate::ContractHash::from_json_contract(ELIP0100_CONTRACT).unwrap();
        let entropy = AssetId::generate_asset_entropy(prevout, contract_hash);
        let asset_id = AssetId::from_entropy(entropy);

        let expected = AssetId::from_str(ELIP0100_ASSET_TAG).unwrap();

        assert_eq!(asset_id.to_hex(), expected.to_hex());
    }
}
