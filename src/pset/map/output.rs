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

use std::{collections::BTreeMap, io};
use std::collections::btree_map::Entry;

use {Script, encode};
use bitcoin::util::bip32::KeySource;
use bitcoin::{self, PublicKey};
use {pset, confidential};
use encode::Decodable;
use pset::map::Map;
use pset::raw;
use pset::Error;
use secp256k1_zkp::{RangeProof, SurjectionProof};

use {TxOut};

/// Type: Redeem Script PSET_OUT_REDEEM_SCRIPT = 0x00
const PSET_OUT_REDEEM_SCRIPT: u8 = 0x00;
/// Type: Witness Script PSET_OUT_WITNESS_SCRIPT = 0x01
const PSET_OUT_WITNESS_SCRIPT: u8 = 0x01;
/// Type: BIP 32 Derivation Path PSET_OUT_BIP32_DERIVATION = 0x02
const PSET_OUT_BIP32_DERIVATION: u8 = 0x02;
/// Type: Output Amount PSET_OUT_AMOUNT = 0x03
const PSET_OUT_AMOUNT: u8 = 0x03;
/// Type: Output Script PSET_OUT_SCRIPT = 0x04
const PSET_OUT_SCRIPT: u8 = 0x04;
/// Type: Proprietary Use Type PSET_IN_PROPRIETARY = 0xFC
const PSET_OUT_PROPRIETARY: u8 = 0xFC;

/// Elements
/// The 33 byte Value Commitment for this output. This is mutually
/// exclusive with PSBT_OUT_VALUE.
const PSBT_ELEMENTS_OUT_VALUE_COMMITMENT: u8 = 0x01;
/// The explicit 32 byte asset tag for this output. This is mutually
/// exclusive with PSBT_ELEMENTS_OUT_ASSET_COMMITMENT.
const PSBT_ELEMENTS_OUT_ASSET: u8 = 0x02;
/// The 33 byte Asset Commitment for this output. This is mutually
/// exclusive with PSBT_ELEMENTS_OUT_ASSET.
const PSBT_ELEMENTS_OUT_ASSET_COMMITMENT: u8 = 0x03;
/// The rangeproof for the value of this output.
const PSBT_ELEMENTS_OUT_VALUE_RANGEPROOF: u8 = 0x04;
/// The asset surjection proof for this output's asset.
const PSBT_ELEMENTS_OUT_ASSET_SURJECTION_PROOF: u8 = 0x05;
/// The 33 byte blinding pubkey to be used when blinding this output.
const PSBT_ELEMENTS_OUT_BLINDING_PUBKEY: u8 = 0x06;
/// The 33 byte ephemeral pubkey used for ECDH in the blinding of this output.
const PSBT_ELEMENTS_OUT_ECDH_PUBKEY: u8 = 0x07;
/// The unsigned 32-bit little endian integer index of the input
/// whose owner should blind this output.
const PSBT_ELEMENTS_OUT_BLINDER_INDEX: u8 = 0x08;

/// A key-value map for an output of the corresponding index in the unsigned
/// transaction.
#[derive(Clone, Default, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Output {
    /// The redeem script for this output.
    pub redeem_script: Option<Script>,
    /// The witness script for this output.
    pub witness_script: Option<Script>,
    /// A map from public keys needed to spend this output to their
    /// corresponding master key fingerprints and derivation paths.
    #[cfg_attr(feature = "serde", serde(with = "::serde_utils::btreemap_as_seq"))]
    pub bip32_derivation: BTreeMap<PublicKey, KeySource>,
    /// (PSET2) The amount of the output
    pub amount: confidential::Value,
    /// (PSET2) The script pubkey of the output
    pub script_pubkey: Script,
    /// The output asset (mandatory for each output)
    pub asset: confidential::Asset,
    // Proprietary key-value pairs for this output.
    /// Output value rangeproof
    pub value_rangeproof: Option<RangeProof>,
    /// Output Asset surjection proof
    pub asset_surjection_proof: Option<SurjectionProof>,
    /// Blinding pubkey which is used in receiving address
    pub blinding_key: Option<bitcoin::PublicKey>,
    /// The ephermal pk sampled by sender
    pub ecdh_pubkey: Option<bitcoin::PublicKey>,
    /// The index of the input whose owner should blind this output
    pub blinder_index: Option<u32>,
    /// Other fields
    #[cfg_attr(feature = "serde", serde(with = "::serde_utils::btreemap_as_seq_byte_values"))]
    pub proprietary: BTreeMap<raw::ProprietaryKey, Vec<u8>>,
    /// Unknown key-value pairs for this output.
    #[cfg_attr(feature = "serde", serde(with = "::serde_utils::btreemap_as_seq_byte_values"))]
    pub unknown: BTreeMap<raw::Key, Vec<u8>>,
}

impl Output{

    /// Create a output from mandatory fields
    pub fn from_txout(txout: TxOut) -> Self {
        let mut rv = Self::default();
        rv.amount = txout.value;
        rv.script_pubkey = txout.script_pubkey;
        rv.asset = txout.asset;
        rv.ecdh_pubkey = txout.nonce.commitment().map(|pk| bitcoin::PublicKey {
            key: pk,
            compressed: true, // always serialize none as compressed pk
        });
        rv.value_rangeproof = txout.witness.rangeproof;
        rv.asset_surjection_proof = txout.witness.surjection_proof;
        rv
    }
}

impl Map for Output {
    fn insert_pair(&mut self, pair: raw::Pair) -> Result<(), encode::Error> {
        let raw::Pair {
            key: raw_key,
            value: raw_value,
        } = pair;

        match raw_key.type_value {
            PSET_OUT_REDEEM_SCRIPT => {
                impl_pset_insert_pair! {
                    self.redeem_script <= <raw_key: _>|<raw_value: Script>
                }
            }
            PSET_OUT_WITNESS_SCRIPT => {
                impl_pset_insert_pair! {
                    self.witness_script <= <raw_key: _>|<raw_value: Script>
                }
            }
            PSET_OUT_BIP32_DERIVATION => {
                impl_pset_insert_pair! {
                    self.bip32_derivation <= <raw_key: PublicKey>|<raw_value: KeySource>
                }
            }
            PSET_OUT_AMOUNT |
            PSET_OUT_SCRIPT => return Err(Error::DuplicateKey(raw_key).into()),

            PSET_OUT_PROPRIETARY => {
                let prop_key = raw::ProprietaryKey::from_key(raw_key.clone())?;
                if prop_key.is_pset_key() {
                    match prop_key.subtype {
                        PSBT_ELEMENTS_OUT_VALUE_COMMITMENT |
                        PSBT_ELEMENTS_OUT_ASSET |
                        PSBT_ELEMENTS_OUT_ASSET_COMMITMENT => return Err(Error::DuplicateKey(raw_key).into()),
                        PSBT_ELEMENTS_OUT_VALUE_RANGEPROOF => {
                            impl_pset_prop_insert_pair!(self.value_rangeproof <= <raw_key: _> | <raw_value : RangeProof>)
                        }
                        PSBT_ELEMENTS_OUT_ASSET_SURJECTION_PROOF => {
                            impl_pset_prop_insert_pair!(self.asset_surjection_proof <= <raw_key: _> | <raw_value : SurjectionProof>)
                        }
                        PSBT_ELEMENTS_OUT_BLINDING_PUBKEY => {
                            impl_pset_prop_insert_pair!(self.blinding_key <= <raw_key: _> | <raw_value : bitcoin::PublicKey>)
                        }
                        PSBT_ELEMENTS_OUT_ECDH_PUBKEY => {
                            impl_pset_prop_insert_pair!(self.ecdh_pubkey <= <raw_key: _> | <raw_value : bitcoin::PublicKey>)
                        }
                        PSBT_ELEMENTS_OUT_BLINDER_INDEX => {
                            impl_pset_prop_insert_pair!(self.blinder_index <= <raw_key: _> | <raw_value : u32>)
                        }
                        _ => {
                            match self.proprietary.entry(prop_key) {
                                Entry::Vacant(empty_key) => {empty_key.insert(raw_value);},
                                Entry::Occupied(_) => return Err(Error::DuplicateKey(raw_key.clone()).into()),
                            }
                        }
                    }
                } else {
                    match self.proprietary.entry(prop_key) {
                        Entry::Vacant(empty_key) => {empty_key.insert(raw_value);},
                        Entry::Occupied(_) => return Err(Error::DuplicateKey(raw_key.clone()).into()),
                    }
                }
            }

            _ => match self.unknown.entry(raw_key) {
                    Entry::Vacant(empty_key) => {empty_key.insert(raw_value);},
                    Entry::Occupied(k) => return Err(Error::DuplicateKey(k.key().clone()).into()),
            }
        }

        Ok(())
    }

    fn get_pairs(&self) -> Result<Vec<raw::Pair>, encode::Error> {
        let mut rv: Vec<raw::Pair> = Default::default();

        impl_pset_get_pair! {
            rv.push(self.redeem_script as <PSET_OUT_REDEEM_SCRIPT, _>)
        }

        impl_pset_get_pair! {
            rv.push(self.witness_script as <PSET_OUT_WITNESS_SCRIPT, _>)
        }

        impl_pset_get_pair! {
            rv.push(self.bip32_derivation as <PSET_OUT_BIP32_DERIVATION, PublicKey>)
        }

        match self.amount {
            confidential::Value::Null => {},
            confidential::Value::Explicit(x) => {
                impl_pset_get_pair! {
                    rv.push_mandatory(x as <PSET_OUT_AMOUNT, _>)
                }
            }
            // confidential value
            comm => {
                let key = raw::ProprietaryKey::from_pset_pair(PSBT_ELEMENTS_OUT_VALUE_COMMITMENT, vec![]);
                rv.push(raw::Pair {
                    key: key.to_key(),
                    value: pset::serialize::Serialize::serialize(&comm),
                });
            }
        }

        match self.asset {
            confidential::Asset::Null => {},
            confidential::Asset::Explicit(x) => {
                let key = raw::ProprietaryKey::from_pset_pair(PSBT_ELEMENTS_OUT_ASSET, vec![]);
                rv.push(raw::Pair {
                    key: key.to_key(),
                    value: pset::serialize::Serialize::serialize(&x),
                });
            }
            // confidential asset
            comm => {
                let key = raw::ProprietaryKey::from_pset_pair(PSBT_ELEMENTS_OUT_ASSET_COMMITMENT, vec![]);
                rv.push(raw::Pair {
                    key: key.to_key(),
                    value: pset::serialize::Serialize::serialize(&comm),
                });
            }
        }
        // Mandatory field: Script
        rv.push(raw::Pair {
            key: raw::Key { type_value: PSET_OUT_SCRIPT, key: vec![]},
            value: pset::serialize::Serialize::serialize(&self.script_pubkey)
        });

        // Prop Output fields
        impl_pset_get_pair! {
            rv.push_prop(self.value_rangeproof as <PSBT_ELEMENTS_OUT_VALUE_RANGEPROOF, _>)
        }

        impl_pset_get_pair! {
            rv.push_prop(self.asset_surjection_proof as <PSBT_ELEMENTS_OUT_ASSET_SURJECTION_PROOF, _>)
        }

        impl_pset_get_pair! {
            rv.push_prop(self.blinding_key as <PSBT_ELEMENTS_OUT_BLINDING_PUBKEY, _>)
        }

        impl_pset_get_pair! {
            rv.push_prop(self.ecdh_pubkey as <PSBT_ELEMENTS_OUT_ECDH_PUBKEY, _>)
        }

        impl_pset_get_pair! {
            rv.push_prop(self.blinder_index as <PSBT_ELEMENTS_OUT_BLINDER_INDEX, _>)
        }

        for (key, value) in self.proprietary.iter() {
            rv.push(raw::Pair {
                key: key.to_key(),
                value: value.clone(),
            });
        }

        for (key, value) in self.unknown.iter() {
            rv.push(raw::Pair {
                key: key.clone(),
                value: value.clone(),
            });
        }

        Ok(rv)
    }

    fn merge(&mut self, other: Self) -> Result<(), pset::Error> {
        // Out amount and out script will be the same
        self.bip32_derivation.extend(other.bip32_derivation);
        self.proprietary.extend(other.proprietary);
        self.unknown.extend(other.unknown);

        merge!(redeem_script, self, other);
        merge!(witness_script, self, other);

        // elements
        merge!(value_rangeproof, self, other);
        merge!(asset_surjection_proof, self, other);
        merge!(blinding_key, self, other);
        merge!(ecdh_pubkey, self, other);
        merge!(blinder_index, self, other);
        Ok(())
    }
}

impl_psetmap_consensus_encoding!(Output);
// Implement decodable by hand. This is required
// because some fields like txid and outpoint are
// not optional and cannot by set by insert_pair
impl Decodable for Output {
    fn consensus_decode<D: io::BufRead>(mut d: D) -> Result<Self, encode::Error> {

        // Sets the default to [0;32] and [0;4]
        let mut rv = Self::default();
        let mut out_value: Option<confidential::Value> = None;
        let mut out_asset: Option<confidential::Asset> = None;
        let mut out_spk: Option<Script> = None;

        loop {
            match raw::Pair::consensus_decode(&mut d) {
                Ok(pair) => {
                    let raw::Pair {
                        key: raw_key,
                        value: raw_value,
                    } = pair;
                    match raw_key.type_value {
                        PSET_OUT_SCRIPT => {
                            impl_pset_insert_pair! {
                                out_spk <= <raw_key: _>|<raw_value: Script>
                            }
                        }
                        PSET_OUT_AMOUNT => {
                            impl_pset_insert_pair! {
                                out_value <= <raw_key: _>|<raw_value: confidential::Value>
                            }
                        }
                        PSET_OUT_PROPRIETARY => {
                            let prop_key = raw::ProprietaryKey::from_key(raw_key.clone())?;
                            if prop_key.is_pset_key() && prop_key.subtype == PSBT_ELEMENTS_OUT_VALUE_COMMITMENT {
                                impl_pset_prop_insert_pair!(
                                    out_value <= <raw_key: _> | <raw_value : confidential::Value>
                                )
                            } else if prop_key.is_pset_key() && prop_key.subtype == PSBT_ELEMENTS_OUT_ASSET {
                                impl_pset_prop_insert_pair!(
                                    out_asset <= <raw_key: _> | <raw_value : confidential::Asset>
                                )
                            } else if prop_key.is_pset_key() && prop_key.subtype == PSBT_ELEMENTS_OUT_ASSET_COMMITMENT {
                                impl_pset_prop_insert_pair!(
                                    out_asset <= <raw_key: _> | <raw_value : confidential::Asset>
                                )
                            } else {
                                rv.insert_pair(raw::Pair { key: raw_key, value: raw_value })?;
                            }
                        }
                        _ =>  rv.insert_pair(raw::Pair { key: raw_key, value: raw_value })?,
                    }
                }
                Err(::encode::Error::PsetError(::pset::Error::NoMorePairs)) => break,
                Err(e) => return Err(e),
            }
        }

        // Mandatory fields
        // Override the default values
        let value = out_value.ok_or(Error::MissingOutputValue)?;
        let asset = out_asset.ok_or(Error::MissingOutputAsset)?;
        let spk = out_spk.ok_or(Error::MissingOutputSpk)?;

        rv.asset = asset;
        rv.amount = value;
        rv.script_pubkey = spk;

        Ok(rv)
    }
}
