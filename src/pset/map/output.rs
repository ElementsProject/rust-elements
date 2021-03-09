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

use {Script, encode};
use bitcoin::util::bip32::KeySource;
use bitcoin::PublicKey;
use pset;
use pset::map::Map;
use pset::raw;
use pset::Error;

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
    pub amount: Option<u64>,
    /// (PSET2) The script pubkey of the output
    pub script: Option<Script>,
    /// Proprietary key-value pairs for this output.
    #[cfg_attr(feature = "serde", serde(with = "::serde_utils::btreemap_as_seq_byte_values"))]
    pub proprietary: BTreeMap<raw::ProprietaryKey, Vec<u8>>,
    /// Unknown key-value pairs for this output.
    #[cfg_attr(feature = "serde", serde(with = "::serde_utils::btreemap_as_seq_byte_values"))]
    pub unknown: BTreeMap<raw::Key, Vec<u8>>,
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
            PSET_OUT_SCRIPT => {
                impl_pset_insert_pair! {
                    self.script <= <raw_key: _>|<raw_value: Script>
                }
            }
            PSET_OUT_PROPRIETARY => match self.proprietary.entry(raw::ProprietaryKey::from_key(raw_key.clone())?) {
                Entry::Vacant(empty_key) => {empty_key.insert(raw_value);},
                Entry::Occupied(_) => return Err(Error::DuplicateKey(raw_key.clone()).into()),
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
            rv.push(self.redeem_script as <PSET_OUT_REDEEM_SCRIPT, _>|<Script>)
        }

        impl_pset_get_pair! {
            rv.push(self.witness_script as <PSET_OUT_WITNESS_SCRIPT, _>|<Script>)
        }

        impl_pset_get_pair! {
            rv.push(self.bip32_derivation as <PSET_OUT_BIP32_DERIVATION, PublicKey>|<KeySource>)
        }

        impl_pset_get_pair! {
            rv.push(self.amount as <PSET_OUT_AMOUNT, _>|<u64>)
        }

        impl_pset_get_pair! {
            rv.push(self.script as <PSET_OUT_SCRIPT, _>|<Script>)
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
        self.bip32_derivation.extend(other.bip32_derivation);
        self.proprietary.extend(other.proprietary);
        self.unknown.extend(other.unknown);

        merge!(redeem_script, self, other);
        merge!(witness_script, self, other);

        Ok(())
    }
}

impl_psetmap_consensus_enc_dec_oding!(Output);
