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

use std::collections::btree_map::Entry;
use std::{collections::BTreeMap, io};

use crate::taproot::TapLeafHash;
use crate::taproot::{NodeInfo, TaprootBuilder};

use crate::encode::Decodable;
use crate::pset::map::Map;
use crate::pset::raw;
use crate::pset::Error;
use crate::{confidential, pset};
use crate::{encode, Script, TxOutWitness};
use bitcoin::util::bip32::KeySource;
use bitcoin::{self, PublicKey};
use secp256k1_zkp::{self, Generator, RangeProof, SurjectionProof};

use crate::issuance;

use crate::AssetId;
use crate::TxOut;

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
/// Type: Taproot Internal Key PSBT_OUT_TAP_INTERNAL_KEY = 0x05
const PSBT_OUT_TAP_INTERNAL_KEY: u8 = 0x05;
/// Type: Taproot Tree PSBT_OUT_TAP_TREE = 0x06
const PSBT_OUT_TAP_TREE: u8 = 0x06;
/// Type: Taproot Key BIP 32 Derivation Path PSBT_OUT_TAP_BIP32_DERIVATION = 0x07
const PSBT_OUT_TAP_BIP32_DERIVATION: u8 = 0x07;
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
/// An explicit value rangeproof that proves that the value commitment in
/// PSBT_ELEMENTS_OUT_VALUE_COMMITMENT matches the explicit value in PSBT_OUT_VALUE.
/// If provided, PSBT_ELEMENTS_OUT_VALUE_COMMITMENT must be provided too.
const PSBT_ELEMENTS_OUT_BLIND_VALUE_PROOF: u8 = 0x09;
/// An asset surjection proof with this output's asset as the only asset in the
/// input set in order to prove that the asset commitment in
/// PSBT_ELEMENTS_OUT_ASSET_COMMITMENT matches the explicit asset in
/// PSBT_ELEMENTS_OUT_ASSET. If provided, PSBT_ELEMENTS_OUT_ASSET_COMMITMENT must
/// be provided too.
const PSBT_ELEMENTS_OUT_BLIND_ASSET_PROOF: u8 = 0x0a;

/// A key-value map for an output of the corresponding index in the unsigned
/// transaction.
#[derive(Clone, Default, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(crate = "actual_serde"))]
pub struct Output {
    /// The redeem script for this output.
    pub redeem_script: Option<Script>,
    /// The witness script for this output.
    pub witness_script: Option<Script>,
    /// A map from public keys needed to spend this output to their
    /// corresponding master key fingerprints and derivation paths.
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::btreemap_as_seq"))]
    pub bip32_derivation: BTreeMap<PublicKey, KeySource>,
    /// The internal pubkey
    pub tap_internal_key: Option<bitcoin::XOnlyPublicKey>,
    /// Taproot Output tree
    pub tap_tree: Option<TapTree>,
    /// Map of tap root x only keys to origin info and leaf hashes contained in it
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::btreemap_as_seq"))]
    pub tap_key_origins: BTreeMap<bitcoin::XOnlyPublicKey, (Vec<TapLeafHash>, KeySource)>,
    /// (PSET) The explicit amount of the output
    pub amount: Option<u64>,
    /// (PSET) The out amount commitment
    pub amount_comm: Option<secp256k1_zkp::PedersenCommitment>,
    /// (PSET) The script pubkey of the output
    pub script_pubkey: Script,
    /// The output explicit asset
    pub asset: Option<issuance::AssetId>,
    /// The output explicit asset
    pub asset_comm: Option<secp256k1_zkp::Generator>,
    // Proprietary key-value pairs for this output.
    /// Output value rangeproof
    pub value_rangeproof: Option<Box<RangeProof>>,
    /// Output Asset surjection proof
    pub asset_surjection_proof: Option<Box<SurjectionProof>>,
    /// Blinding pubkey which is used in receiving address
    pub blinding_key: Option<bitcoin::PublicKey>,
    /// The ephermal pk sampled by sender
    pub ecdh_pubkey: Option<bitcoin::PublicKey>,
    /// The index of the input whose owner should blind this output
    pub blinder_index: Option<u32>,
    /// The blind value rangeproof
    pub blind_value_proof: Option<Box<RangeProof>>,
    /// The blind asset surjection proof
    pub blind_asset_proof: Option<Box<SurjectionProof>>,
    /// Pset
    /// Other fields
    #[cfg_attr(
        feature = "serde",
        serde(with = "crate::serde_utils::btreemap_as_seq_byte_values")
    )]
    pub proprietary: BTreeMap<raw::ProprietaryKey, Vec<u8>>,
    /// Unknown key-value pairs for this output.
    #[cfg_attr(
        feature = "serde",
        serde(with = "crate::serde_utils::btreemap_as_seq_byte_values")
    )]
    pub unknown: BTreeMap<raw::Key, Vec<u8>>,
}

/// Taproot Tree representing a finalized [`TaprootBuilder`] (a complete binary tree)
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(crate = "actual_serde"))]
pub struct TapTree(pub(crate) TaprootBuilder);

impl PartialEq for TapTree {
    fn eq(&self, other: &Self) -> bool {
        self.node_info().hash.eq(&other.node_info().hash)
    }
}

impl Eq for TapTree {}

impl TapTree {
    // get the inner node info as the builder is finalized
    fn node_info(&self) -> &NodeInfo {
        // The builder algorithm invariant guarantees that is_complete builder
        // have only 1 element in branch and that is not None.
        // We make sure that we only allow is_complete builders via the from_inner
        // constructor
        self.0.branch()[0]
            .as_ref()
            .expect("from_inner only parses is_complete builders")
    }

    /// Convert a [`TaprootBuilder`] into a tree if it is complete binary tree.
    /// Returns the inner as Err if it is not a complete tree
    pub fn from_inner(inner: TaprootBuilder) -> Result<Self, TaprootBuilder> {
        if inner.is_complete() {
            Ok(TapTree(inner))
        } else {
            Err(inner)
        }
    }

    /// Convert self into builder [`TaprootBuilder`]. The builder is guaranteed to
    /// be finalized.
    pub fn into_inner(self) -> TaprootBuilder {
        self.0
    }
}

impl Output {
    /// Create a new explicit pset output
    pub fn new_explicit(
        script: Script,
        amount: u64,
        asset: AssetId,
        blinding_key: Option<bitcoin::PublicKey>,
    ) -> Self {
        let mut res = pset::Output::default();
        // set the respective values
        res.script_pubkey = script;
        res.amount = Some(amount);
        res.blinding_key = blinding_key;
        res.asset = Some(asset);
        res
    }

    /// Create a output from txout
    /// If the txout it [TxOut::is_partially_blinded], then nonce of the txout
    /// is treated as ecdh pubkey, otherwise the nonce of the txout is assumed to
    /// be receiver blinding key.
    /// This is to be used when the txout is not blinded. This sets
    /// the blinding key from the txout nonce
    pub fn from_txout(txout: TxOut) -> Self {
        let mut rv = Self::default();
        match txout.value {
            confidential::Value::Null => {}
            confidential::Value::Explicit(x) => rv.amount = Some(x),
            confidential::Value::Confidential(comm) => rv.amount_comm = Some(comm),
        }
        match txout.asset {
            confidential::Asset::Null => {}
            confidential::Asset::Explicit(x) => rv.asset = Some(x),
            confidential::Asset::Confidential(comm) => rv.asset_comm = Some(comm),
        }
        if txout.is_partially_blinded() {
            rv.ecdh_pubkey = txout.nonce.commitment().map(|pk| bitcoin::PublicKey {
                inner: pk,
                compressed: true, // always serialize none as compressed pk
            });
        } else {
            rv.blinding_key = txout.nonce.commitment().map(|pk| bitcoin::PublicKey {
                inner: pk,
                compressed: true, // always serialize none as compressed pk
            });
        }
        rv.script_pubkey = txout.script_pubkey;
        rv.value_rangeproof = txout.witness.rangeproof;
        rv.asset_surjection_proof = txout.witness.surjection_proof;
        rv
    }

    /// Create a txout from self
    pub fn to_txout(&self) -> TxOut {
        TxOut {
            asset: match (self.asset_comm, self.asset) {
                (Some(gen), _) => confidential::Asset::Confidential(gen),
                (None, Some(id)) => confidential::Asset::Explicit(id),
                (None, None) => confidential::Asset::Null,
            },
            value: match (self.amount_comm, self.amount) {
                (Some(comm), _) => confidential::Value::Confidential(comm),
                (None, Some(x)) => confidential::Value::Explicit(x),
                (None, None) => confidential::Value::Null,
            },
            nonce: if self.is_partially_blinded() {
                self.ecdh_pubkey
                    .map(|pk| confidential::Nonce::from(pk.inner))
            } else {
                self.blinding_key
                    .map(|pk| confidential::Nonce::from(pk.inner))
            }
            .unwrap_or_default(),
            script_pubkey: self.script_pubkey.clone(),
            witness: TxOutWitness {
                surjection_proof: self.asset_surjection_proof.clone(),
                rangeproof: self.value_rangeproof.clone(),
            },
        }
    }

    /// IsBlinded from elements core
    /// This indicates whether the output is marked for blinding
    pub fn is_marked_for_blinding(&self) -> bool {
        self.blinding_key.is_some()
    }

    /// IsPartiallyBlinded from elements core
    pub fn is_partially_blinded(&self) -> bool {
        self.is_marked_for_blinding()
            && (self.amount_comm.is_some()
                || self.asset_comm.is_some()
                || self.value_rangeproof.is_some()
                || self.asset_surjection_proof.is_some()
                || self.ecdh_pubkey.is_some())
    }

    /// IsFullyBlinded from elements core
    pub fn is_fully_blinded(&self) -> bool {
        self.is_marked_for_blinding()
            && self.amount_comm.is_some()
            && self.asset_comm.is_some()
            && self.value_rangeproof.is_some()
            && self.asset_surjection_proof.is_some()
            && self.ecdh_pubkey.is_some()
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
            PSET_OUT_AMOUNT => {
                impl_pset_insert_pair! {
                    self.amount <= <raw_key: _>|<raw_value: u64>
                }
            }
            PSET_OUT_SCRIPT => return Err(Error::DuplicateKey(raw_key).into()),

            PSBT_OUT_TAP_INTERNAL_KEY => {
                impl_pset_insert_pair! {
                    self.tap_internal_key <= <raw_key: _>|<raw_value: bitcoin::XOnlyPublicKey>
                }
            }
            PSBT_OUT_TAP_TREE => {
                impl_pset_insert_pair! {
                    self.tap_tree <= <raw_key: _>|<raw_value: TapTree>
                }
            }
            PSBT_OUT_TAP_BIP32_DERIVATION => {
                impl_pset_insert_pair! {
                    self.tap_key_origins <= <raw_key: bitcoin::XOnlyPublicKey>|< raw_value: (Vec<TapLeafHash>, KeySource)>
                }
            }

            PSET_OUT_PROPRIETARY => {
                let prop_key = raw::ProprietaryKey::from_key(raw_key.clone())?;
                if prop_key.is_pset_key() {
                    match prop_key.subtype {
                        PSBT_ELEMENTS_OUT_VALUE_COMMITMENT => {
                            impl_pset_prop_insert_pair!(self.amount_comm <= <raw_key: _> | <raw_value : secp256k1_zkp::PedersenCommitment>)
                        }
                        PSBT_ELEMENTS_OUT_ASSET => {
                            impl_pset_prop_insert_pair!(self.asset <= <raw_key: _> | <raw_value : AssetId>)
                        }
                        PSBT_ELEMENTS_OUT_ASSET_COMMITMENT => {
                            impl_pset_prop_insert_pair!(self.asset_comm <= <raw_key: _> | <raw_value : Generator>)
                        }
                        PSBT_ELEMENTS_OUT_VALUE_RANGEPROOF => {
                            impl_pset_prop_insert_pair!(self.value_rangeproof <= <raw_key: _> | <raw_value : Box<RangeProof>>)
                        }
                        PSBT_ELEMENTS_OUT_ASSET_SURJECTION_PROOF => {
                            impl_pset_prop_insert_pair!(self.asset_surjection_proof <= <raw_key: _> | <raw_value : Box<SurjectionProof>>)
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
                        PSBT_ELEMENTS_OUT_BLIND_VALUE_PROOF => {
                            impl_pset_prop_insert_pair!(self.blind_value_proof <= <raw_key: _> | <raw_value : Box<RangeProof>>)
                        }
                        PSBT_ELEMENTS_OUT_BLIND_ASSET_PROOF => {
                            impl_pset_prop_insert_pair!(self.blind_asset_proof <= <raw_key: _> | <raw_value : Box<SurjectionProof>>)
                        }
                        _ => match self.proprietary.entry(prop_key) {
                            Entry::Vacant(empty_key) => {
                                empty_key.insert(raw_value);
                            }
                            Entry::Occupied(_) => {
                                return Err(Error::DuplicateKey(raw_key.clone()).into())
                            }
                        },
                    }
                } else {
                    match self.proprietary.entry(prop_key) {
                        Entry::Vacant(empty_key) => {
                            empty_key.insert(raw_value);
                        }
                        Entry::Occupied(_) => {
                            return Err(Error::DuplicateKey(raw_key.clone()).into())
                        }
                    }
                }
            }

            _ => match self.unknown.entry(raw_key) {
                Entry::Vacant(empty_key) => {
                    empty_key.insert(raw_value);
                }
                Entry::Occupied(k) => return Err(Error::DuplicateKey(k.key().clone()).into()),
            },
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

        impl_pset_get_pair! {
            rv.push(self.tap_internal_key as <PSBT_OUT_TAP_INTERNAL_KEY, _>)
        }

        impl_pset_get_pair! {
            rv.push(self.tap_tree as <PSBT_OUT_TAP_TREE, _>)
        }

        impl_pset_get_pair! {
            rv.push(self.tap_key_origins as <PSBT_OUT_TAP_BIP32_DERIVATION,
                    schnorr::PublicKey>)
        }

        impl_pset_get_pair! {
            rv.push(self.amount as <PSET_OUT_AMOUNT, _>)
        }

        impl_pset_get_pair! {
            rv.push_prop(self.amount_comm as <PSBT_ELEMENTS_OUT_VALUE_COMMITMENT, _>)
        }

        impl_pset_get_pair! {
            rv.push_prop(self.asset as <PSBT_ELEMENTS_OUT_ASSET, _>)
        }

        impl_pset_get_pair! {
            rv.push_prop(self.asset_comm as <PSBT_ELEMENTS_OUT_ASSET_COMMITMENT, _>)
        }

        // Mandatory field: Script
        rv.push(raw::Pair {
            key: raw::Key {
                type_value: PSET_OUT_SCRIPT,
                key: vec![],
            },
            value: pset::serialize::Serialize::serialize(&self.script_pubkey),
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

        impl_pset_get_pair! {
            rv.push_prop(self.blind_value_proof as <PSBT_ELEMENTS_OUT_BLIND_VALUE_PROOF, _>)
        }

        impl_pset_get_pair! {
            rv.push_prop(self.blind_asset_proof as <PSBT_ELEMENTS_OUT_BLIND_ASSET_PROOF, _>)
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
        self.tap_key_origins.extend(other.tap_key_origins);

        merge!(redeem_script, self, other);
        merge!(witness_script, self, other);
        merge!(tap_internal_key, self, other);
        merge!(tap_tree, self, other);

        // elements
        merge!(value_rangeproof, self, other);
        merge!(asset_surjection_proof, self, other);
        merge!(blinding_key, self, other);
        merge!(ecdh_pubkey, self, other);
        merge!(blinder_index, self, other);
        merge!(blind_value_proof, self, other);
        merge!(blind_asset_proof, self, other);
        Ok(())
    }
}

impl_psetmap_consensus_encoding!(Output);
// Implement decodable by hand. This is required
// because some fields like txid and outpoint are
// not optional and cannot by set by insert_pair
impl Decodable for Output {
    fn consensus_decode<D: io::Read>(mut d: D) -> Result<Self, encode::Error> {
        // Sets the default to [0;32] and [0;4]
        let mut rv = Self::default();
        // let mut out_value: Option<confidential::Value> = None;
        // let mut out_asset: Option<confidential::Asset> = None;
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
                        _ => rv.insert_pair(raw::Pair {
                            key: raw_key,
                            value: raw_value,
                        })?,
                    }
                }
                Err(crate::encode::Error::PsetError(crate::pset::Error::NoMorePairs)) => break,
                Err(e) => return Err(e),
            }
        }

        // Mandatory fields
        let spk = out_spk.ok_or(Error::MissingOutputSpk)?;

        rv.script_pubkey = spk;
        if let (None, None) = (rv.amount, rv.amount_comm) {
            return Err(encode::Error::PsetError(Error::MissingOutputValue));
        }
        if let (None, None) = (rv.asset, rv.asset_comm) {
            return Err(encode::Error::PsetError(Error::MissingOutputAsset));
        }
        if let (Some(_), None) = (rv.blinding_key, rv.blinder_index) {
            return Err(encode::Error::PsetError(Error::MissingBlinderIndex));
        }
        if rv.is_marked_for_blinding() && rv.is_partially_blinded() && !rv.is_fully_blinded() {
            return Err(encode::Error::PsetError(Error::MissingBlindingInfo));
        }
        Ok(rv)
    }
}
