//!
//! An implementation of ELIP0100 as defined in
//! <https://github.com/ElementsProject/ELIPs/blob/main/elip-0100.mediawiki>
//! but excluding contract validation.
//!
//! ELIP0100 defines how to include assets metadata, such as the contract defining the asset and
//! the issuance prevout inside a PSET
//!
//! To use check [`PartiallySignedTransaction::add_asset_metadata`] and
//! [`PartiallySignedTransaction::get_asset_metadata`]
//!

use super::{PartiallySignedTransaction, raw::ProprietaryKey};
use crate::{encode::{self, Encodable}, AssetId};

pub use elements26::pset::elip100::{PSBT_ELEMENTS_HWW_GLOBAL_ASSET_METADATA, PSBT_ELEMENTS_HWW_GLOBAL_REISSUANCE_TOKEN, PSET_HWW_PREFIX};
pub use elements26::pset::elip100::{AssetMetadata, TokenMetadata};

/// Contains extension to add and retrieve from the PSET contract informations related to an asset
impl PartiallySignedTransaction {
    /// Add contract information to the PSET, returns None if it wasn't present or Some with the old
    /// data if already in the PSET
    pub fn add_asset_metadata(
        &mut self,
        asset_id: AssetId,
        asset_meta: &AssetMetadata,
    ) -> Option<Result<AssetMetadata, encode::Error>> {
        let key = prop_key(&asset_id, PSBT_ELEMENTS_HWW_GLOBAL_ASSET_METADATA);
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
        let key = prop_key(&asset_id, PSBT_ELEMENTS_HWW_GLOBAL_ASSET_METADATA);

        self.global
            .proprietary
            .get(&key)
            .map(|data| AssetMetadata::deserialize(data))
    }

    /// Add token information to the PSET, returns None if it wasn't present or Some with the old
    /// data if already in the PSET
    pub fn add_token_metadata(
        &mut self,
        token_id: AssetId,
        token_meta: &TokenMetadata
    ) -> Option<Result<TokenMetadata, encode::Error>> {
        let key = prop_key(&token_id, PSBT_ELEMENTS_HWW_GLOBAL_REISSUANCE_TOKEN);
        self.global
            .proprietary
            .insert(key, token_meta.serialize())
            .map(|old| TokenMetadata::deserialize(&old))
    }

    /// Get token information from the PSET, returns None if there are no information regarding
    /// the given `token_id`` in the PSET
    pub fn get_token_metadata(
        &self,
        token_id: AssetId
    ) -> Option<Result<TokenMetadata, encode::Error>> {
        let key = prop_key(&token_id, PSBT_ELEMENTS_HWW_GLOBAL_REISSUANCE_TOKEN);

        self.global
            .proprietary
            .get(&key)
            .map(|data| TokenMetadata::deserialize(data))
    }
}

fn prop_key(asset_id: &AssetId, keytype: u8) -> ProprietaryKey {
    let mut key = Vec::with_capacity(32);
    asset_id
        .consensus_encode(&mut key)
        .expect("vec doesn't err"); // equivalent to asset_tag

    ProprietaryKey {
        prefix: PSET_HWW_PREFIX.to_vec(),
        subtype: keytype,
        key,
    }
}

