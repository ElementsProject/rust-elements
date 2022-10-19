// Rust Bitcoin Library
// Written by
//   The Rust Bitcoin developers
//   The Rust Elements developers
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

use std::cmp;
use std::collections::btree_map::Entry;
use std::{
    collections::BTreeMap,
    io::{self, Cursor, Read},
};

use crate::encode;
use crate::encode::Decodable;
use crate::endian::u32_to_array_le;
use crate::pset::{self, map::Map, raw, Error};
use crate::{PackedLockTime, VarInt};
use bitcoin::util::bip32::{ChildNumber, DerivationPath, ExtendedPubKey, Fingerprint, KeySource};
use secp256k1_zkp::Tweak;

// (Not used in pset) Type: Unsigned Transaction PSET_GLOBAL_UNSIGNED_TX = 0x00
const PSET_GLOBAL_UNSIGNED_TX: u8 = 0x00;
//
/// Type: Extended Public Key PSET_GLOBAL_XPUB = 0x01
const PSET_GLOBAL_XPUB: u8 = 0x01;

/// Type: Tx Version PSET_GLOBAL_TX_VERSION = 0x02
const PSET_GLOBAL_TX_VERSION: u8 = 0x02;
/// Type: Fallback Locktime PSET_GLOBAL_FALLBACK_LOCKTIME = 0x03
const PSET_GLOBAL_FALLBACK_LOCKTIME: u8 = 0x03;
/// Type: Tx Input Count PSET_GLOBAL_INPUT_COUNT = 0x04
const PSET_GLOBAL_INPUT_COUNT: u8 = 0x04;
/// Type: Tx Output Count PSET_GLOBAL_OUTPUT_COUNT = 0x05
const PSET_GLOBAL_OUTPUT_COUNT: u8 = 0x05;
/// Type: Transaction Modifiable Flags PSET_GLOBAL_TX_MODIFIABLE = 0x06
const PSET_GLOBAL_TX_MODIFIABLE: u8 = 0x06;

/// Type: Version Number PSET_GLOBAL_VERSION = 0xFB
const PSET_GLOBAL_VERSION: u8 = 0xFB;
/// Type: Proprietary Use Type PSET_GLOBAL_PROPRIETARY = 0xFC
const PSET_GLOBAL_PROPRIETARY: u8 = 0xFC;

/// Proprietary fields in elements
/// Type: Global Scalars used in range proofs = 0x00
const PSBT_ELEMENTS_GLOBAL_SCALAR: u8 = 0x00;
/// Type: Global Flag used in elements for Blinding signalling
const PSBT_ELEMENTS_GLOBAL_TX_MODIFIABLE: u8 = 0x01;

/// Global transaction data
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(crate = "actual_serde"))]
pub struct TxData {
    /// Transaction version. Must be 2.
    pub version: u32,
    /// Locktime to use if no inputs specify a minimum locktime to use.
    /// May be omitted in which case it is interpreted as 0.
    pub fallback_locktime: Option<crate::PackedLockTime>,
    /// Number of inputs in the transaction
    /// Not public. Users should not be able to mutate this directly
    /// This will be automatically whenever pset inputs are added
    pub(crate) input_count: usize,
    /// Number of outputs in the transaction
    /// Not public. Users should not be able to mutate this directly
    /// This will be automatically whenever pset inputs are added
    pub(crate) output_count: usize,
    /// Flags indicating that the transaction may be modified.
    /// May be omitted in which case it is interpreted as 0.
    pub tx_modifiable: Option<u8>,
}

impl Default for TxData {
    fn default() -> Self {
        Self {
            // tx version must be 2
            version: 2,
            fallback_locktime: None,
            input_count: 0,
            output_count: 0,
            tx_modifiable: None,
        }
    }
}

/// A key-value map for global data.
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(crate = "actual_serde"))]
pub struct Global {
    /// Global transaction data
    #[cfg_attr(feature = "serde", serde(flatten))]
    pub tx_data: TxData,
    /// The version number of this PSET. Must be present.
    pub version: u32,
    /// A global map from extended public keys to the used key fingerprint and
    /// derivation path as defined by BIP 32
    pub xpub: BTreeMap<ExtendedPubKey, KeySource>,
    // Global proprietary key-value pairs.
    /// Scalars used for blinding
    pub scalars: Vec<Tweak>,
    /// Elements tx modifiable flag
    pub elements_tx_modifiable_flag: Option<u8>,
    /// Other Proprietary fields
    #[cfg_attr(
        feature = "serde",
        serde(with = "crate::serde_utils::btreemap_as_seq_byte_values")
    )]
    pub proprietary: BTreeMap<raw::ProprietaryKey, Vec<u8>>,
    /// Unknown global key-value pairs.
    #[cfg_attr(
        feature = "serde",
        serde(with = "crate::serde_utils::btreemap_as_seq_byte_values")
    )]
    pub unknown: BTreeMap<raw::Key, Vec<u8>>,
}

impl Default for Global {
    fn default() -> Self {
        Self {
            tx_data: TxData::default(),
            version: 2,
            xpub: BTreeMap::new(),
            scalars: Vec::new(),
            elements_tx_modifiable_flag: None,
            proprietary: BTreeMap::new(),
            unknown: BTreeMap::new(),
        }
    }
}

impl Global {
    /// Accessor for the number of inputs currently in the PSET
    pub fn n_inputs(&self) -> usize {
        self.tx_data.input_count
    }

    /// Accessor for the number of outputs currently in the PSET
    pub fn n_outputs(&self) -> usize {
        self.tx_data.output_count
    }
}

impl Map for Global {
    fn insert_pair(&mut self, pair: raw::Pair) -> Result<(), encode::Error> {
        let raw::Pair {
            key: raw_key,
            value: raw_value,
        } = pair;

        match raw_key.type_value {
            PSET_GLOBAL_UNSIGNED_TX => return Err(Error::ExpiredPsbtv0Field)?,
            // Can't set the mandatory non-optional fields via insert_pair
            PSET_GLOBAL_VERSION
            | PSET_GLOBAL_FALLBACK_LOCKTIME
            | PSET_GLOBAL_INPUT_COUNT
            | PSET_GLOBAL_OUTPUT_COUNT
            | PSET_GLOBAL_TX_MODIFIABLE
            | PSET_GLOBAL_TX_VERSION => return Err(Error::DuplicateKey(raw_key).into()),
            PSET_GLOBAL_PROPRIETARY => {
                let prop_key = raw::ProprietaryKey::from_key(raw_key.clone())?;
                if prop_key.is_pset_key() && prop_key.subtype == PSBT_ELEMENTS_GLOBAL_SCALAR {
                    if raw_value.is_empty() && prop_key.key.len() == 32 {
                        let scalar = Tweak::from_slice(&prop_key.key)?;
                        if !self.scalars.contains(&scalar) {
                            self.scalars.push(scalar);
                        } else {
                            return Err(Error::DuplicateKey(raw_key).into());
                        }
                    } else {
                        return Err(Error::InvalidKey(raw_key.into()))?;
                    }
                } else if prop_key.is_pset_key()
                    && prop_key.subtype == PSBT_ELEMENTS_GLOBAL_TX_MODIFIABLE
                {
                    if prop_key.key.is_empty() && raw_value.len() == 1 {
                        self.elements_tx_modifiable_flag = Some(raw_value[0]);
                    } else {
                        return Err(Error::InvalidKey(raw_key.into()))?;
                    }
                } else {
                    match self.proprietary.entry(prop_key) {
                        Entry::Vacant(empty_key) => {
                            empty_key.insert(raw_value);
                        }
                        Entry::Occupied(_) => return Err(Error::DuplicateKey(raw_key).into()),
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

        let TxData {
            version,
            fallback_locktime,
            input_count,
            output_count,
            tx_modifiable,
        } = self.tx_data;
        let input_count_vint = VarInt(input_count as u64);
        let output_count_vint = VarInt(output_count as u64);

        impl_pset_get_pair! {
            rv.push_mandatory(version as <PSET_GLOBAL_TX_VERSION, _>)
        }

        impl_pset_get_pair! {
            rv.push(fallback_locktime as <PSET_GLOBAL_FALLBACK_LOCKTIME, _>)
        }

        impl_pset_get_pair! {
            rv.push_mandatory(input_count_vint as <PSET_GLOBAL_INPUT_COUNT, _>)
        }

        impl_pset_get_pair! {
            rv.push_mandatory(output_count_vint as <PSET_GLOBAL_OUTPUT_COUNT, _>)
        }

        impl_pset_get_pair! {
            rv.push(tx_modifiable as <PSET_GLOBAL_TX_MODIFIABLE, _>)
        }

        for (xpub, (fingerprint, derivation)) in &self.xpub {
            rv.push(raw::Pair {
                key: raw::Key {
                    type_value: PSET_GLOBAL_XPUB,
                    key: xpub.encode().to_vec(),
                },
                value: {
                    let mut ret = Vec::with_capacity(4 + derivation.len() * 4);
                    ret.extend(fingerprint.as_bytes());
                    derivation
                        .into_iter()
                        .for_each(|n| ret.extend(&u32_to_array_le((*n).into())));
                    ret
                },
            });
        }

        let ver = self.version; //hack to use macro
        impl_pset_get_pair!(
            rv.push_mandatory(ver as <PSET_GLOBAL_VERSION, _>)
        );

        // Serialize scalars and elements tx modifiable
        for scalar in &self.scalars {
            let key = raw::ProprietaryKey::from_pset_pair(
                PSBT_ELEMENTS_GLOBAL_SCALAR,
                scalar.as_ref().to_vec(),
            );
            rv.push(raw::Pair {
                key: key.to_key(),
                value: vec![], // This is a bug in elements core c++, parses this value as vec![0]
            })
        }

        impl_pset_get_pair! {
            rv.push_prop(self.elements_tx_modifiable_flag as <PSBT_ELEMENTS_GLOBAL_TX_MODIFIABLE, _>)
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

    // Keep in mind that according to BIP 174 this function must be commutative, i.e.
    // A.merge(B) == B.merge(A)
    fn merge(&mut self, other: Self) -> Result<(), pset::Error> {
        // BIP 174: The Combiner must remove any duplicate key-value pairs, in accordance with
        //          the specification. It can pick arbitrarily when conflicts occur.

        // Does not specify, how to resolve conflicts
        // But since unique ids must be the same, all fields of
        // tx_data but tx modifiable must be the same
        // Keep flags from both psets
        self.tx_data.tx_modifiable = Some(
            self.tx_data.tx_modifiable.unwrap_or(0) | other.tx_data.tx_modifiable.unwrap_or(0),
        );

        // Keeping the highest version
        self.version = cmp::max(self.version, other.version);

        // Merging xpubs
        for (xpub, (fingerprint1, derivation1)) in other.xpub {
            match self.xpub.entry(xpub) {
                Entry::Vacant(entry) => {
                    entry.insert((fingerprint1, derivation1));
                }
                Entry::Occupied(mut entry) => {
                    // Here in case of the conflict we select the version with algorithm:
                    // 1) if everything is equal we do nothing
                    // 2) report an error if
                    //    - derivation paths are equal and fingerprints are not
                    //    - derivation paths are of the same length, but not equal
                    //    - derivation paths has different length, but the shorter one
                    //      is not the strict suffix of the longer one
                    // 3) choose longest derivation otherwise

                    let (fingerprint2, derivation2) = entry.get().clone();

                    if derivation1 == derivation2 && fingerprint1 == fingerprint2 {
                        continue;
                    } else if derivation1.len() < derivation2.len()
                        && derivation1[..] == derivation2[derivation2.len() - derivation1.len()..]
                    {
                        continue;
                    } else if derivation2[..]
                        == derivation1[derivation1.len() - derivation2.len()..]
                    {
                        entry.insert((fingerprint1, derivation1));
                        continue;
                    }
                    return Err(pset::Error::MergeConflict(
                        format!("global xpub {} has inconsistent key sources", xpub).to_owned(),
                    ));
                }
            }
        }

        // TODO: Use hashset for efficiency
        self.scalars.extend(other.scalars);
        self.scalars.sort();
        self.scalars.dedup();
        merge!(elements_tx_modifiable_flag, self, other);
        self.proprietary.extend(other.proprietary);
        self.unknown.extend(other.unknown);
        Ok(())
    }
}

impl_psetmap_consensus_encoding!(Global);
// It is possible to get invalid Global structures(e.g: psbt version 0) if
// you try to use this API directly on Global structure
// Users should always use the deserialize on the upper level
// PSET data structure.

impl Decodable for Global {
    fn consensus_decode<D: io::Read>(mut d: D) -> Result<Self, encode::Error> {
        let mut version: Option<u32> = None;
        let mut unknowns: BTreeMap<raw::Key, Vec<u8>> = Default::default();
        let mut xpub_map: BTreeMap<ExtendedPubKey, (Fingerprint, DerivationPath)> =
            Default::default();
        let mut proprietary = BTreeMap::new();
        let mut scalars = Vec::new();

        let mut tx_version: Option<u32> = None;
        let mut input_count: Option<VarInt> = None;
        let mut output_count: Option<VarInt> = None;
        let mut fallback_locktime: Option<PackedLockTime> = None;
        let mut tx_modifiable: Option<u8> = None;
        let mut elements_tx_modifiable_flag: Option<u8> = None;

        loop {
            match raw::Pair::consensus_decode(&mut d) {
                Ok(pair) => {
                    let raw::Pair {
                        key: raw_key,
                        value: raw_value,
                    } = pair;
                    match raw_key.type_value {
                        PSET_GLOBAL_TX_VERSION => {
                            impl_pset_insert_pair! {
                                tx_version <= <raw_key: _>|<raw_value: u32>
                            }
                        }
                        PSET_GLOBAL_FALLBACK_LOCKTIME => {
                            impl_pset_insert_pair! {
                                fallback_locktime <= <raw_key: _>|<raw_value: PackedLockTime>
                            }
                        }
                        PSET_GLOBAL_INPUT_COUNT => {
                            impl_pset_insert_pair! {
                                input_count <= <raw_key: _>|<raw_value: VarInt>
                            }
                        }
                        PSET_GLOBAL_OUTPUT_COUNT => {
                            impl_pset_insert_pair! {
                                output_count <= <raw_key: _>|<raw_value: VarInt>
                            }
                        }
                        PSET_GLOBAL_TX_MODIFIABLE => {
                            impl_pset_insert_pair! {
                                tx_modifiable <= <raw_key: _>|<raw_value: u8>
                            }
                        }
                        PSET_GLOBAL_XPUB => {
                            if !raw_key.key.is_empty() {
                                let xpub = ExtendedPubKey::decode(&raw_key.key)
                                    .map_err(|_| encode::Error::ParseFailed(
                                        "Can't deserialize ExtendedPublicKey from global XPUB key data"
                                    ))?;

                                if raw_value.is_empty() || raw_value.len() % 4 != 0 {
                                    return Err(encode::Error::ParseFailed(
                                        "Incorrect length of global xpub derivation data",
                                    ));
                                }

                                let child_count = raw_value.len() / 4 - 1;
                                let mut decoder = Cursor::new(raw_value);
                                let mut fingerprint = [0u8; 4];
                                decoder.read_exact(&mut fingerprint[..])?;
                                let mut path = Vec::<ChildNumber>::with_capacity(child_count);
                                while let Ok(index) = u32::consensus_decode(&mut decoder) {
                                    path.push(ChildNumber::from(index))
                                }
                                let derivation = DerivationPath::from(path);
                                // Keys, according to BIP-174, must be unique
                                if xpub_map
                                    .insert(xpub, (Fingerprint::from(&fingerprint[..]), derivation))
                                    .is_some()
                                {
                                    return Err(encode::Error::ParseFailed(
                                        "Repeated global xpub key",
                                    ));
                                }
                            } else {
                                return Err(encode::Error::ParseFailed(
                                    "Xpub global key must contain serialized Xpub data",
                                ));
                            }
                        }
                        PSET_GLOBAL_VERSION => {
                            impl_pset_insert_pair! {
                                version <= <raw_key: _>|<raw_value: u32>
                            }
                        }
                        PSET_GLOBAL_PROPRIETARY => {
                            let prop_key = raw::ProprietaryKey::from_key(raw_key.clone())?;
                            if prop_key.is_pset_key()
                                && prop_key.subtype == PSBT_ELEMENTS_GLOBAL_SCALAR
                            {
                                if raw_value.is_empty() && prop_key.key.len() == 32 {
                                    let scalar = Tweak::from_slice(&prop_key.key)?;
                                    if !scalars.contains(&scalar) {
                                        scalars.push(scalar);
                                    } else {
                                        return Err(Error::DuplicateKey(raw_key).into());
                                    }
                                } else {
                                    return Err(Error::InvalidKey(raw_key.into()))?;
                                }
                            } else if prop_key.is_pset_key()
                                && prop_key.subtype == PSBT_ELEMENTS_GLOBAL_TX_MODIFIABLE
                            {
                                if prop_key.key.is_empty() && raw_value.len() == 1 {
                                    elements_tx_modifiable_flag = Some(raw_value[0]);
                                } else {
                                    return Err(Error::InvalidKey(raw_key.into()))?;
                                }
                            } else {
                                match proprietary.entry(prop_key) {
                                    Entry::Vacant(empty_key) => {
                                        empty_key.insert(raw_value);
                                    }
                                    Entry::Occupied(_) => {
                                        return Err(Error::DuplicateKey(raw_key).into())
                                    }
                                }
                            }
                        }
                        _ => match unknowns.entry(raw_key) {
                            Entry::Vacant(empty_key) => {
                                empty_key.insert(raw_value);
                            }
                            Entry::Occupied(k) => {
                                return Err(Error::DuplicateKey(k.key().clone()).into())
                            }
                        },
                    }
                }
                Err(crate::encode::Error::PsetError(crate::pset::Error::NoMorePairs)) => break,
                Err(e) => return Err(e),
            }
        }

        // Mandatory fields
        let version = version.ok_or(Error::IncorrectPsetVersion)?;
        if version != 2 {
            return Err(Error::IncorrectPsetVersion)?;
        }
        let tx_version = tx_version.ok_or(Error::MissingTxVersion)?;
        let input_count = input_count.ok_or(Error::MissingInputCount)?.0 as usize;
        let output_count = output_count.ok_or(Error::MissingOutputCount)?.0 as usize;

        let global = Global {
            tx_data: TxData {
                version: tx_version,
                fallback_locktime,
                input_count,
                output_count,
                tx_modifiable,
            },
            version: version,
            xpub: xpub_map,
            proprietary: proprietary,
            unknown: unknowns,
            scalars: scalars,
            elements_tx_modifiable_flag: elements_tx_modifiable_flag,
        };
        Ok(global)
    }
}
