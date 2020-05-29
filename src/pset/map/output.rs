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

use std::collections::BTreeMap;
use std::collections::btree_map::Entry;

use bitcoin::blockdata::script::Script;
use bitcoin::secp256k1::SecretKey;
use bitcoin::util::bip32::{DerivationPath, Fingerprint};
use bitcoin::util::key::PublicKey;

use confidential;
use encode;
use pset::map::Map;
use pset::{self, raw, Error, ELEMENTS_PROP_KEY};

/// A key-value map for an output of the corresponding index in the unsigned
/// transaction.
#[derive(Clone, Default, Debug, PartialEq)]
pub struct Output {
    /// The redeem script for this output.
    pub redeem_script: Option<Script>,
    /// The witness script for this output.
    pub witness_script: Option<Script>,
    /// A map from public keys needed to spend this output to their
    /// corresponding master key fingerprints and derivation paths.
    pub hd_keypaths: BTreeMap<PublicKey, (Fingerprint, DerivationPath)>,
    /// Unknown key-value pairs for this output.
    pub unknown: BTreeMap<raw::Key, Vec<u8>>,

    // Elements fields:
    /// The blinding pubkey for the blinding commitments for this output.
    pub blinding_pubkey: Option<PublicKey>,
    /// The value commitment for this output.
    pub value_commitment: Option<confidential::Value>,
    /// The blinding factor for the value commitment of this output.
    pub value_blinding_factor: Option<SecretKey>,
    /// The asset commitment for this output.
    pub asset_commitment: Option<confidential::Asset>,
    /// The blinding factor for the asset commitment of this output.
    pub asset_blinding_factor: Option<SecretKey>,
    /// The nonce commitment for this output.
    pub nonce_commitment: Option<confidential::Nonce>,
    /// The value range proof for this output.
    pub range_proof: Option<Vec<u8>>,
    /// The asset surjection proof for this output.
    pub surjection_proof: Option<Vec<u8>>,
}

impl Map for Output {
    fn insert_pair(&mut self, pair: raw::Pair) -> Result<(), encode::Error> {
        let raw::Pair {
            key: raw_key,
            value: raw_value,
        } = pair;

        match raw_key.type_value {
            0u8 => {
                impl_psbt_insert_pair! {
                    self.redeem_script <= <raw_key: _>|<raw_value: Script>
                }
            }
            1u8 => {
                impl_psbt_insert_pair! {
                    self.witness_script <= <raw_key: _>|<raw_value: Script>
                }
            }
            2u8 => {
                impl_psbt_insert_pair! {
                    self.hd_keypaths <= <raw_key: PublicKey>|<raw_value: (Fingerprint, DerivationPath)>
                }
            }
            0xfc_u8 => {
                match impl_psbt_extract_prop!(ELEMENTS_PROP_KEY, raw_key, raw_value) {
                    None => {},
                    Some((raw_key, raw_value)) if raw_key.type_value == 0u8 => {
                        impl_psbt_insert_pair! {
                            self.value_commitment <= <raw_key: _>|<raw_value: confidential::Value>
                        }
                    }
                    Some((raw_key, raw_value)) if raw_key.type_value == 1u8 => {
                        impl_psbt_insert_pair! {
                            self.value_blinding_factor <= <raw_key: _>|<raw_value: SecretKey>
                        }
                    }
                    Some((raw_key, raw_value)) if raw_key.type_value == 2u8 => {
                        impl_psbt_insert_pair! {
                            self.asset_commitment <= <raw_key: _>|<raw_value: confidential::Asset>
                        }
                    }
                    Some((raw_key, raw_value)) if raw_key.type_value == 3u8 => {
                        impl_psbt_insert_pair! {
                            self.asset_blinding_factor <= <raw_key: _>|<raw_value: SecretKey>
                        }
                    }
                    Some((raw_key, raw_value)) if raw_key.type_value == 4u8 => {
                        impl_psbt_insert_pair! {
                            self.range_proof <= <raw_key: _>|<raw_value: Vec<u8>>
                        }
                    }
                    Some((raw_key, raw_value)) if raw_key.type_value == 5u8 => {
                        impl_psbt_insert_pair! {
                            self.surjection_proof <= <raw_key: _>|<raw_value: Vec<u8>>
                        }
                    }
                    Some((raw_key, raw_value)) if raw_key.type_value == 6u8 => {
                        impl_psbt_insert_pair! {
                            self.blinding_pubkey <= <raw_key: _>|<raw_value: PublicKey>
                        }
                    }
                    Some((raw_key, raw_value)) if raw_key.type_value == 7u8 => {
                        impl_psbt_insert_pair! {
                            self.nonce_commitment <= <raw_key: _>|<raw_value: confidential::Nonce>
                        }
                    }
                    Some((_, raw_value)) => match self.unknown.entry(raw_key) {
                        Entry::Vacant(empty_key) => {empty_key.insert(raw_value);},
                        Entry::Occupied(k) => return Err(Error::DuplicateKey(k.key().clone()).into()),
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

        impl_psbt_get_pair! {
            rv.push(self.redeem_script as <0u8, _>|<Script>)
        }

        impl_psbt_get_pair! {
            rv.push(self.witness_script as <1u8, _>|<Script>)
        }

        impl_psbt_get_pair! {
            rv.push(self.hd_keypaths as <2u8, PublicKey>|<(Fingerprint, DerivationPath)>)
        }

        impl_psbt_get_prop_pair! {
            rv.push(self.value_commitment as <ELEMENTS_PROP_KEY, 0u8, _>|<confidential::Value>)
        }

        impl_psbt_get_prop_pair! {
            rv.push(self.value_blinding_factor as <ELEMENTS_PROP_KEY, 1u8, _>|<confidential::SecretKey>)
        }

        impl_psbt_get_prop_pair! {
            rv.push(self.asset_commitment as <ELEMENTS_PROP_KEY, 2u8, _>|<confidential::Asset>)
        }

        impl_psbt_get_prop_pair! {
            rv.push(self.asset_blinding_factor as <ELEMENTS_PROP_KEY, 3u8, _>|<confidential::SecretKey>)
        }

        impl_psbt_get_prop_pair! {
            rv.push(self.range_proof as <ELEMENTS_PROP_KEY, 4u8, _>|<Vec<u8>>)
        }

        impl_psbt_get_prop_pair! {
            rv.push(self.surjection_proof as <ELEMENTS_PROP_KEY, 5u8, _>|<Vec<u8>>)
        }

        impl_psbt_get_prop_pair! {
            rv.push(self.blinding_pubkey as <ELEMENTS_PROP_KEY, 6u8, _>|<PublicKey>)
        }

        impl_psbt_get_prop_pair! {
            rv.push(self.nonce_commitment as <ELEMENTS_PROP_KEY, 7u8, _>|<confidential::Nonce>)
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
        self.hd_keypaths.extend(other.hd_keypaths);
        self.unknown.extend(other.unknown);

        merge!(redeem_script, self, other);
        merge!(witness_script, self, other);

        merge!(blinding_pubkey, self, other);
        merge!(value_commitment, self, other);
        merge!(value_blinding_factor, self, other);
        merge!(asset_commitment, self, other);
        merge!(asset_blinding_factor, self, other);
        merge!(nonce_commitment, self, other);
        merge!(range_proof, self, other);
        merge!(surjection_proof, self, other);

        Ok(())
    }
}

impl_psbtmap_consensus_enc_dec_oding!(Output);
