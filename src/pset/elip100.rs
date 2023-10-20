//! 
//! An implementation of ELIP0100 as defined in 
//! https://github.com/ElementsProject/ELIPs/blob/main/elip-0100.mediawiki
//! 
//! ELIP0100 defines how to inlcude assets metadata, such as the contract defining the asset and 
//! the issuance prevout inside a PSET
//! 

use crate::{AssetId, OutPoint, encode::Encodable};
use super::{PartiallySignedTransaction, raw::ProprietaryKey};

/// keytype as defined in ELIP0100
pub const PSBT_ELEMENTS_HWW_GLOBAL_ASSET_METADATA: [u8; 2] = [0x01, 0x00];

/// Contains extension to add and retrieve from the PSET contract informations related to an asset 
pub trait ContractExt {

    /// Add contract information to the PSET, returns None if it wasn't present or Some with the old
    /// data if already in the PSET
    fn add_contract(&mut self, asset_id: AssetId, contract: &str, prevout: OutPoint)-> Option<AssetMetadata>;

    /// Get contract information from the PSET, returns None if there are no information regarding
    /// the given asset_id in the PSET
    fn get_contract(&self, asset_id: AssetId) -> Option<AssetMetadata>;
}

/// Asset metadata, the contract and the outpoint used to issue the asset
pub struct AssetMetadata {
    contract: String,
    issuance_prevout: OutPoint
}

impl ContractExt for PartiallySignedTransaction {
    fn add_contract(&mut self, _asset_id: AssetId, _contract: &str, _prevout: OutPoint)-> Option<AssetMetadata> {


        // let existing = self.global.proprietary.insert(key, value);
        todo!()
    }

    fn get_contract(&self, _asset_id: AssetId) -> Option<AssetMetadata> {
        todo!()
    }
}

fn prop_key(asset_id: &AssetId) -> ProprietaryKey {
    let mut vec = Vec::with_capacity(32);
    asset_id.consensus_encode(&mut vec).expect("vec doesn't err"); // equivalent to asset_tag
    
    ProprietaryKey::from_pset_pair(0x00, vec)
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
    /// <compact size uint contractLen><contract><32-byte prevoutTxid><32-bit little endian uint prevoutIndex>
    pub fn serialize(&self) -> Vec<u8> {
        let mut result = vec![];


        self.contract.as_bytes().to_vec().consensus_encode(&mut result).expect("vec doesn't err"); // TODO improve efficiency avoding to_vec

        self.issuance_prevout.consensus_encode(&mut result).expect("vec doesn't err");

        result
    }
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use crate::{OutPoint, hex::ToHex, ContractHash, AssetId, encode::Encodable};

    use super::{AssetMetadata, prop_key};

    const CONTRACT_HASH: &str = "3c7f0a53c2ff5b99590620d7f6604a7a3a7bfbaaa6aa61f7bfc7833ca03cde82";
    const VALID_CONTRACT: &str = r#"{"entity":{"domain":"tether.to"},"issuer_pubkey":"0337cceec0beea0232ebe14cba0197a9fbd45fcf2ec946749de920e71434c2b904","name":"Tether USD","precision":8,"ticker":"USDt","version":0}"#;
    const ISSUANCE_PREVOUT: &str = "9596d259270ef5bac0020435e6d859aea633409483ba64e232b8ba04ce288668:0";
    const ASSET_ID: &str = "ce091c998b83c78bb71a632313ba3760f1763d9cfcffae02258ffa9865a37bd2";

    // TODO At the moment (23 Oct 2023) there are no official test vectors in the ELIP0100 so don't 
    // base anything on this value yet
    #[test]
    fn asset_metadata_serialize() {
        let issuance_prevout: OutPoint = ISSUANCE_PREVOUT.parse().unwrap(); 
        let a = AssetMetadata {
            contract: VALID_CONTRACT.to_string(),
            issuance_prevout,

        };
        let contract_hash = ContractHash::from_str(CONTRACT_HASH).unwrap();
        assert_eq!(ContractHash::from_json_contract(&VALID_CONTRACT).unwrap(), contract_hash);
        assert_eq!(a.serialize().to_hex(),"b47b22656e74697479223a7b22646f6d61696e223a227465746865722e746f227d2c226973737565725f7075626b6579223a22303333376363656563306265656130323332656265313463626130313937613966626434356663663265633934363734396465393230653731343334633262393034222c226e616d65223a2254657468657220555344222c22707265636973696f6e223a382c227469636b6572223a2255534474222c2276657273696f6e223a307d688628ce04bab832e264ba83944033a6ae59d8e6350402c0baf50e2759d2969500000000");
    }


    // TODO At the moment (23 Oct 2023) there are no official test vectors in the ELIP0100 so don't 
    // base anything on this value yet
    #[test]
    fn prop_key_serialize() {
        let asset_id = AssetId::from_str(ASSET_ID).unwrap();
        
        let key = prop_key(&asset_id);
        let mut vec = vec![];
        key.consensus_encode(&mut vec).unwrap();
        assert_eq!(vec.to_hex(), format!("04{}00{}", b"pset".to_hex(), asset_id.into_tag()));
        // 0xfc0470736574fd0100
    }
}