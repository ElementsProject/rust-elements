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

use std::collections::BTreeMap;
use std::collections::btree_map::Entry;
use std::io::{self, Cursor, Read};
use std::cmp;

use {Transaction, VarInt};
use encode::{serialize, Encodable, Decodable};
use pset::{self, map::Map, raw, Error};
use endian::u32_to_array_le;
use bitcoin::util::bip32::{ExtendedPubKey, KeySource, Fingerprint, DerivationPath, ChildNumber};
use encode;

/// Type: Unsigned Transaction PSET_GLOBAL_UNSIGNED_TX = 0x00
const PSET_GLOBAL_UNSIGNED_TX: u8 = 0x00;
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

/// Global transaction data
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(untagged))]
pub enum TxData {
    /// BIP-174 PSET v0
    V0 {
        /// The complete unsigned transaction in the PSET
        unsigned_tx: Transaction,
    },
    /// BIP-370 PSET v2
    V2 {
        /// Transaction version. Must be 2.
        version: u32,
        /// Locktime to use if no inputs specify a minimum locktime to use.
        /// May be omitted in which case it is interpreted as 0.
        fallback_locktime: u32,
        /// Number of inputs in the transaction
        input_count: usize,
        /// Number of outputs in the transaction
        output_count: usize,
        /// Flags indicating that the transaction may be modified.
        /// May be omitted in which case it is interpreted as 0.
        tx_modifiable: u8,
    },
}

/// A key-value map for global data.
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Global {
    /// Global transaction data
    #[cfg_attr(feature = "serde", serde(flatten))]
    pub tx_data: TxData,
    /// The version number of this PSET. If omitted, the version number is 0.
    pub version: u32,
    /// A global map from extended public keys to the used key fingerprint and
    /// derivation path as defined by BIP 32
    pub xpub: BTreeMap<ExtendedPubKey, KeySource>,
    /// Global proprietary key-value pairs.
    #[cfg_attr(feature = "serde", serde(with = "::serde_utils::btreemap_as_seq_byte_values"))]
    pub proprietary: BTreeMap<raw::ProprietaryKey, Vec<u8>>,
    /// Unknown global key-value pairs.
    #[cfg_attr(feature = "serde", serde(with = "::serde_utils::btreemap_as_seq_byte_values"))]
    pub unknown: BTreeMap<raw::Key, Vec<u8>>,
}

impl Global {
    /// Create a Global from an unsigned transaction, error if not unsigned
    pub fn from_unsigned_tx(tx: Transaction) -> Result<Self, pset::Error> {
        for txin in &tx.input {
            if !txin.script_sig.is_empty() {
                return Err(Error::UnsignedTxHasScriptSigs);
            }

            if !txin.witness.is_empty() {
                return Err(Error::UnsignedTxHasScriptWitnesses);
            }
        }

        Ok(Global {
            tx_data: TxData::V0 { unsigned_tx: tx },
            xpub: Default::default(),
            version: 0,
            proprietary: Default::default(),
            unknown: Default::default(),
        })
    }

    /// Accessor for the number of inputs currently in the PSET
    pub fn n_inputs(&self) -> usize {
        match self.tx_data {
            TxData::V0 { ref unsigned_tx } => unsigned_tx.input.len(),
            TxData::V2 { input_count, .. } => input_count,
        }
    }

    /// Accessor for the number of outputs currently in the PSET
    pub fn n_outputs(&self) -> usize {
        match self.tx_data {
            TxData::V0 { ref unsigned_tx } => unsigned_tx.output.len(),
            TxData::V2 { output_count, .. } => output_count,
        }
    }
}

impl Map for Global {
    fn insert_pair(&mut self, pair: raw::Pair) -> Result<(), encode::Error> {
        let raw::Pair {
            key: raw_key,
            value: raw_value,
        } = pair;

        match raw_key.type_value {
            PSET_GLOBAL_UNSIGNED_TX => return Err(Error::DuplicateKey(raw_key).into()),
            PSET_GLOBAL_PROPRIETARY => match self.proprietary.entry(raw::ProprietaryKey::from_key(raw_key.clone())?) {
                Entry::Vacant(empty_key) => {empty_key.insert(raw_value);},
                Entry::Occupied(_) => return Err(Error::DuplicateKey(raw_key).into()),
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

        match self.tx_data {
            TxData::V0 { ref unsigned_tx } => {
                rv.push(raw::Pair {
                    key: raw::Key {
                        type_value: PSET_GLOBAL_UNSIGNED_TX,
                        key: vec![],
                    },
                    value: {
                        // Manually serialized to ensure 0-input txs are serialized
                        // without witnesses.
                        let mut ret = Vec::new();
                        unsigned_tx.version.consensus_encode(&mut ret)?;
                        unsigned_tx.input.consensus_encode(&mut ret)?;
                        unsigned_tx.output.consensus_encode(&mut ret)?;
                        unsigned_tx.lock_time.consensus_encode(&mut ret)?;
                        ret
                    },
                });
            },
            TxData::V2 { version, fallback_locktime, input_count, output_count, tx_modifiable } => {
                rv.push(raw::Pair {
                    key: raw::Key {
                        type_value: PSET_GLOBAL_TX_VERSION,
                        key: vec![],
                    },
                    value: u32_to_array_le(version).to_vec(),
                });
                if fallback_locktime > 0 {
                    rv.push(raw::Pair {
                        key: raw::Key {
                            type_value: PSET_GLOBAL_FALLBACK_LOCKTIME,
                            key: vec![],
                        },
                        value: u32_to_array_le(fallback_locktime).to_vec(),
                    });
                }
                rv.push(raw::Pair {
                    key: raw::Key {
                        type_value: PSET_GLOBAL_INPUT_COUNT,
                        key: vec![],
                    },
                    value: serialize(&VarInt(input_count as u64)),
                });
                rv.push(raw::Pair {
                    key: raw::Key {
                        type_value: PSET_GLOBAL_OUTPUT_COUNT,
                        key: vec![],
                    },
                    value: serialize(&VarInt(output_count as u64)),
                });
                if tx_modifiable != 0 {
                    rv.push(raw::Pair {
                        key: raw::Key {
                            type_value: PSET_GLOBAL_TX_MODIFIABLE,
                            key: vec![],
                        },
                        value: vec![tx_modifiable],
                    });
                }
            },
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
                    derivation.into_iter().for_each(|n| ret.extend(&u32_to_array_le((*n).into())));
                    ret
                }
            });
        }

        // Serializing version only for non-default value; otherwise test vectors fail
        if self.version > 0 {
            rv.push(raw::Pair {
                key: raw::Key {
                    type_value: PSET_GLOBAL_VERSION,
                    key: vec![],
                },
                value: u32_to_array_le(self.version).to_vec()
            });
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

        // Keeping the highest version
        self.version = cmp::max(self.version, other.version);

        // Merging xpubs
        for (xpub, (fingerprint1, derivation1)) in other.xpub {
            match self.xpub.entry(xpub) {
                Entry::Vacant(entry) => {
                    entry.insert((fingerprint1, derivation1));
                },
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

                    if derivation1 == derivation2 && fingerprint1 == fingerprint2
                    {
                        continue
                    }
                    else if
                        derivation1.len() < derivation2.len() &&
                        derivation1[..] == derivation2[derivation2.len() - derivation1.len()..]
                    {
                        continue
                    }
                    else if derivation2[..] == derivation1[derivation1.len() - derivation2.len()..]
                    {
                        entry.insert((fingerprint1, derivation1));
                        continue
                    }
                    return Err(pset::Error::MergeConflict(format!(
                        "global xpub {} has inconsistent key sources", xpub
                    ).to_owned()));
                }
            }
        }

        self.proprietary.extend(other.proprietary);
        self.unknown.extend(other.unknown);
        Ok(())
    }
}

impl_psetmap_consensus_encoding!(Global);

impl Decodable for Global {
    fn consensus_decode<D: io::BufRead>(mut d: D) -> Result<Self, encode::Error> {

        let mut tx: Option<Transaction> = None;
        let mut version: Option<u32> = None;
        let mut unknowns: BTreeMap<raw::Key, Vec<u8>> = Default::default();
        let mut xpub_map: BTreeMap<ExtendedPubKey, (Fingerprint, DerivationPath)> = Default::default();
        let mut proprietary: BTreeMap<raw::ProprietaryKey, Vec<u8>> = Default::default();

        loop {
            match raw::Pair::consensus_decode(&mut d) {
                Ok(pair) => {
                    match pair.key.type_value {
                        PSET_GLOBAL_UNSIGNED_TX => {
                            // key has to be empty
                            if pair.key.key.is_empty() {
                                // there can only be one unsigned transaction
                                if tx.is_none() {
                                    let vlen: usize = pair.value.len();
                                    let mut decoder = Cursor::new(pair.value);

                                    // Manually deserialized to ensure 0-input
                                    // txs without witnesses are deserialized
                                    // properly.
                                    tx = Some(Transaction {
                                        version: Decodable::consensus_decode(&mut decoder)?,
                                        input: Decodable::consensus_decode(&mut decoder)?,
                                        output: Decodable::consensus_decode(&mut decoder)?,
                                        lock_time: Decodable::consensus_decode(&mut decoder)?,
                                    });

                                    if decoder.position() != vlen as u64 {
                                        return Err(encode::Error::ParseFailed("data not consumed entirely when explicitly deserializing"))
                                    }
                                } else {
                                    return Err(Error::DuplicateKey(pair.key).into())
                                }
                            } else {
                                return Err(Error::InvalidKey(pair.key).into())
                            }
                        }
                        PSET_GLOBAL_XPUB => {
                            if !pair.key.key.is_empty() {
                                let xpub = ExtendedPubKey::decode(&pair.key.key)
                                    .map_err(|_| encode::Error::ParseFailed(
                                        "Can't deserialize ExtendedPublicKey from global XPUB key data"
                                    ))?;

                                if pair.value.is_empty() || pair.value.len() % 4 != 0 {
                                    return Err(encode::Error::ParseFailed("Incorrect length of global xpub derivation data"))
                                }

                                let child_count = pair.value.len() / 4 - 1;
                                let mut decoder = Cursor::new(pair.value);
                                let mut fingerprint = [0u8; 4];
                                decoder.read_exact(&mut fingerprint[..])?;
                                let mut path = Vec::<ChildNumber>::with_capacity(child_count);
                                while let Ok(index) = u32::consensus_decode(&mut decoder) {
                                    path.push(ChildNumber::from(index))
                                }
                                let derivation = DerivationPath::from(path);
                                // Keys, according to BIP-174, must be unique
                                if xpub_map.insert(xpub, (Fingerprint::from(&fingerprint[..]), derivation)).is_some() {
                                    return Err(encode::Error::ParseFailed("Repeated global xpub key"))
                                }
                            } else {
                                return Err(encode::Error::ParseFailed("Xpub global key must contain serialized Xpub data"))
                            }
                        }
                        PSET_GLOBAL_VERSION => {
                            // key has to be empty
                            if pair.key.key.is_empty() {
                                // there can only be one version
                                if version.is_none() {
                                    let vlen: usize = pair.value.len();
                                    let mut decoder = Cursor::new(pair.value);
                                    if vlen != 4 {
                                        return Err(encode::Error::ParseFailed("Wrong global version value length (must be 4 bytes)"))
                                    }
                                    version = Some(Decodable::consensus_decode(&mut decoder)?);
                                    // We only understand version 0 PSETs. According to BIP-174 we
                                    // should throw an error if we see anything other than version 0.
                                    if version != Some(0) {
                                        return Err(encode::Error::ParseFailed("PSET versions greater than 0 are not supported"))
                                    }
                                } else {
                                    return Err(Error::DuplicateKey(pair.key).into())
                                }
                            } else {
                                return Err(Error::InvalidKey(pair.key).into())
                            }
                        }
                        PSET_GLOBAL_PROPRIETARY => match proprietary.entry(raw::ProprietaryKey::from_key(pair.key.clone())?) {
                            Entry::Vacant(empty_key) => {empty_key.insert(pair.value);},
                            Entry::Occupied(_) => return Err(Error::DuplicateKey(pair.key).into()),
                        }
                        _ => match unknowns.entry(pair.key) {
                            Entry::Vacant(empty_key) => {empty_key.insert(pair.value);},
                            Entry::Occupied(k) => return Err(Error::DuplicateKey(k.key().clone()).into()),
                        }
                    }
                }
                Err(::encode::Error::PsetError(::pset::Error::NoMorePairs)) => break,
                Err(e) => return Err(e),
            }
        }

        if let Some(tx) = tx {
            let mut rv: Global = Global::from_unsigned_tx(tx)?;
            rv.version = version.unwrap_or(0);
            rv.xpub = xpub_map;
            rv.unknown = unknowns;
            Ok(rv)
        } else {
            Err(Error::MustHaveUnsignedTx.into())
        }
    }
}
