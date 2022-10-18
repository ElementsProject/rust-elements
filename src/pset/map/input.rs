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

use std::fmt;
use std::{
    cmp,
    collections::btree_map::{BTreeMap, Entry},
    io,
    str::FromStr,
};

use crate::taproot::{ControlBlock, LeafVersion, TapBranchHash, TapLeafHash};
use crate::{schnorr, AssetId, ContractHash};

use crate::{confidential, locktime};
use crate::encode::{self, Decodable};
use crate::hashes::{self, hash160, ripemd160, sha256, sha256d};
use crate::pset::map::Map;
use crate::pset::raw;
use crate::pset::serialize;
use crate::pset::{self, error, Error};
use crate::{transaction::SighashTypeParseError, SchnorrSigHashType};
use crate::{AssetIssuance, BlockHash, EcdsaSigHashType, Script, Transaction, TxIn, TxOut, Txid};
use bitcoin::util::bip32::KeySource;
use bitcoin::{self, PublicKey};
use hashes::Hash;
use secp256k1_zkp::{self, RangeProof, Tweak, ZERO_TWEAK};

use crate::{OutPoint, Sequence};

/// Type: Non-Witness UTXO PSET_IN_NON_WITNESS_UTXO = 0x00
const PSET_IN_NON_WITNESS_UTXO: u8 = 0x00;
/// Type: Witness UTXO PSET_IN_WITNESS_UTXO = 0x01
const PSET_IN_WITNESS_UTXO: u8 = 0x01;
/// Type: Partial Signature PSET_IN_PARTIAL_SIG = 0x02
const PSET_IN_PARTIAL_SIG: u8 = 0x02;
/// Type: Sighash Type PSET_IN_SIGHASH_TYPE = 0x03
const PSET_IN_SIGHASH_TYPE: u8 = 0x03;
/// Type: Redeem Script PSET_IN_REDEEM_SCRIPT = 0x04
const PSET_IN_REDEEM_SCRIPT: u8 = 0x04;
/// Type: Witness Script PSET_IN_WITNESS_SCRIPT = 0x05
const PSET_IN_WITNESS_SCRIPT: u8 = 0x05;
/// Type: BIP 32 Derivation Path PSET_IN_BIP32_DERIVATION = 0x06
const PSET_IN_BIP32_DERIVATION: u8 = 0x06;
/// Type: Finalized scriptSig PSET_IN_FINAL_SCRIPTSIG = 0x07
const PSET_IN_FINAL_SCRIPTSIG: u8 = 0x07;
/// Type: Finalized scriptWitness PSET_IN_FINAL_SCRIPTWITNESS = 0x08
const PSET_IN_FINAL_SCRIPTWITNESS: u8 = 0x08;
/// Type: RIPEMD160 preimage PSET_IN_RIPEMD160 = 0x0a
const PSET_IN_RIPEMD160: u8 = 0x0a;
/// Type: SHA256 preimage PSET_IN_SHA256 = 0x0b
const PSET_IN_SHA256: u8 = 0x0b;
/// Type: HASH160 preimage PSET_IN_HASH160 = 0x0c
const PSET_IN_HASH160: u8 = 0x0c;
/// Type: HASH256 preimage PSET_IN_HASH256 = 0x0d
const PSET_IN_HASH256: u8 = 0x0d;
/// Type: (Mandatory) Previous TXID PSET_IN_PREVIOUS_TXID = 0x0e
const PSET_IN_PREVIOUS_TXID: u8 = 0x0e;
/// Type: (Mandatory) Spent Output Index PSET_IN_OUTPUT_INDEX = 0x0f
const PSET_IN_OUTPUT_INDEX: u8 = 0x0f;
/// Type: Sequence Number PSET_IN_SEQUENCE = 0x10
const PSET_IN_SEQUENCE: u8 = 0x10;
/// Type: Required Time-based Locktime PSET_IN_REQUIRED_TIME_LOCKTIME = 0x11
const PSET_IN_REQUIRED_TIME_LOCKTIME: u8 = 0x11;
/// Type: Required Height-based Locktime PSET_IN_REQUIRED_HEIGHT_LOCKTIME = 0x12
const PSET_IN_REQUIRED_HEIGHT_LOCKTIME: u8 = 0x12;
/// Type: Schnorr Signature in Key Spend PSBT_IN_TAP_KEY_SIG = 0x13
const PSBT_IN_TAP_KEY_SIG: u8 = 0x13;
/// Type: Schnorr Signature in Script Spend PSBT_IN_TAP_SCRIPT_SIG = 0x14
const PSBT_IN_TAP_SCRIPT_SIG: u8 = 0x14;
/// Type: Taproot Leaf Script PSBT_IN_TAP_LEAF_SCRIPT = 0x14
const PSBT_IN_TAP_LEAF_SCRIPT: u8 = 0x15;
/// Type: Taproot Key BIP 32 Derivation Path PSBT_IN_TAP_BIP32_DERIVATION = 0x16
const PSBT_IN_TAP_BIP32_DERIVATION: u8 = 0x16;
/// Type: Taproot Internal Key PSBT_IN_TAP_INTERNAL_KEY = 0x17
const PSBT_IN_TAP_INTERNAL_KEY: u8 = 0x17;
/// Type: Taproot Merkle Root PSBT_IN_TAP_MERKLE_ROOT = 0x18
const PSBT_IN_TAP_MERKLE_ROOT: u8 = 0x18;
/// Type: Proprietary Use Type PSET_IN_PROPRIETARY = 0xFC
const PSET_IN_PROPRIETARY: u8 = 0xFC;

// Elements Proprietary types:
/// Issuance Value: The explicit little endian 64-bit integer
/// for the value of this issuance. This is mutually exclusive with
/// PSBT_ELEMENTS_IN_ISSUANCE_VALUE_COMMITMENT
const PSBT_ELEMENTS_IN_ISSUANCE_VALUE: u8 = 0x00;
/// Issuance Value Commitment: The 33 byte Value Commitment.
/// This is mutually exclusive with PSBT_IN_ISSUANCE_VALUE.
const PSBT_ELEMENTS_IN_ISSUANCE_VALUE_COMMITMENT: u8 = 0x01;
/// Issuance Value Rangeproof: The rangeproof
const PSBT_ELEMENTS_IN_ISSUANCE_VALUE_RANGEPROOF: u8 = 0x02;
/// Issuance Inflation Keys Rangeproof: The rangeproof
const PSBT_ELEMENTS_IN_ISSUANCE_KEYS_RANGEPROOF: u8 = 0x03;
/// Peg-in Transaction: The Peg-in Transaction serialized without witnesses.
const PSBT_ELEMENTS_IN_PEG_IN_TX: u8 = 0x04;
/// Peg-in Transaction Output Proof: The transaction output proof for the
/// Peg-in Transaction.
const PSBT_ELEMENTS_IN_PEG_IN_TXOUT_PROOF: u8 = 0x05;
/// Peg-in Genesis Hash: The 32 byte genesis hash for the Peg-in Transaction.
const PSBT_ELEMENTS_IN_PEG_IN_GENESIS: u8 = 0x06;
/// Peg-in Claim Script: The claim script for the Peg-in Transaction.
const PSBT_ELEMENTS_IN_PEG_IN_CLAIM_SCRIPT: u8 = 0x07;
/// Peg-in Value: The little endian 64-bit value of the peg-in for
/// the Peg-in Transaction.
const PSBT_ELEMENTS_IN_PEG_IN_VALUE: u8 = 0x08;
/// Peg-in Witness: The Peg-in witness for the Peg-in Transaction.
const PSBT_ELEMENTS_IN_PEG_IN_WITNESS: u8 = 0x09;
/// Issuance Inflation Keys Amount: The value for the inflation keys output to
/// set in this issuance. This is mutually exclusive with
/// PSBT_ELEMENTS_IN_ISSUANCE_INFLATION_KEYS_COMMITMENT.
const PSBT_ELEMENTS_IN_ISSUANCE_INFLATION_KEYS: u8 = 0x0a;
/// Issuance Inflation Keys Amount Commitment: The 33 byte commitment to the
/// inflation keys output value in this issuance. This is mutually exclusive
/// with PSBT_ELEMENTS_IN_ISSUANCE_INFLATION_KEYS
const PSBT_ELEMENTS_IN_ISSUANCE_INFLATION_KEYS_COMMITMENT: u8 = 0x0b;
/// Issuance Blinding Nonce: The 32 byte asset blinding nonce. For new assets,
/// must be 0. For reissuances, this is a revelation of the blinding factor for
/// the input.
const PSBT_ELEMENTS_IN_ISSUANCE_BLINDING_NONCE: u8 = 0x0c;
/// Issuance Asset Entropy: The 32 byte asset entropy. For new issuances, an
/// arbitrary and optional 32 bytes of no consensus meaning combined used as
/// additional entropy in the asset tag calculation. For reissuances, the
/// original, final entropy used for the asset tag calculation.
const PSBT_ELEMENTS_IN_ISSUANCE_ASSET_ENTROPY: u8 = 0x0d;
/// The rangeproof for the UTXO for this input. This rangeproof is found in
/// the output witness data for the transaction and thus is not included as part
/// of either of the UTXOs (as witness data is not included in either case).
/// However the rangeproof is needed in order for stateless blinders to learn
/// the blinding factors for the UTXOs that they are involved in.
const PSBT_ELEMENTS_IN_UTXO_RANGEPROOF: u8 = 0x0e;
/// An explicit value rangeproof that proves that the value commitment in
/// PSBT_ELEMENTS_IN_ISSUANCE_VALUE_COMMITMENT matches the explicit value in
/// PSBT_ELEMENTS_IN_ISSUANCE_VALUE. If provided, PSBT_ELEMENTS_IN_ISSUANCE_VALUE_COMMITMENT
/// must be provided too.
const PSBT_ELEMENTS_IN_ISSUANCE_BLIND_VALUE_PROOF: u8 = 0x0f;
/// An explicit value rangeproof that proves that the value commitment in
/// PSBT_ELEMENTS_IN_ISSUANCE_INFLATION_KEYS_COMMITMENT matches the explicit value
/// in PSBT_ELEMENTS_IN_ISSUANCE_INFLATION_KEYS. If provided,
/// PSBT_ELEMENTS_IN_ISSUANCE_INFLATION_KEYS_COMMITMENT must be provided too.
const PSBT_ELEMENTS_IN_ISSUANCE_BLIND_INFLATION_KEYS_PROOF: u8 = 0x10;
/// A key-value map for an input of the corresponding index in the unsigned
/// transaction.
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(crate = "actual_serde"))]
pub struct Input {
    /// The non-witness transaction this input spends from. Should only be
    /// [std::option::Option::Some] for inputs which spend non-segwit outputs or
    /// if it is unknown whether an input spends a segwit output.
    pub non_witness_utxo: Option<Transaction>,
    /// The transaction output this input spends from. Should only be
    /// [std::option::Option::Some] for inputs which spend segwit outputs,
    /// including P2SH embedded ones.
    pub witness_utxo: Option<TxOut>,
    /// A map from public keys to their corresponding signature as would be
    /// pushed to the stack from a scriptSig or witness.
    #[cfg_attr(
        feature = "serde",
        serde(with = "crate::serde_utils::btreemap_byte_values")
    )]
    pub partial_sigs: BTreeMap<PublicKey, Vec<u8>>,
    /// The sighash type to be used for this input. Signatures for this input
    /// must use the sighash type.
    pub sighash_type: Option<PsbtSighashType>,
    /// The redeem script for this input.
    pub redeem_script: Option<Script>,
    /// The witness script for this input.
    pub witness_script: Option<Script>,
    /// A map from public keys needed to sign this input to their corresponding
    /// master key fingerprints and derivation paths.
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::btreemap_as_seq"))]
    pub bip32_derivation: BTreeMap<PublicKey, KeySource>,
    /// The finalized, fully-constructed scriptSig with signatures and any other
    /// scripts necessary for this input to pass validation.
    pub final_script_sig: Option<Script>,
    /// The finalized, fully-constructed scriptWitness with signatures and any
    /// other scripts necessary for this input to pass validation.
    pub final_script_witness: Option<Vec<Vec<u8>>>,
    /// TODO: Proof of reserves commitment
    /// RIPEMD160 hash to preimage map
    #[cfg_attr(
        feature = "serde",
        serde(with = "crate::serde_utils::btreemap_byte_values")
    )]
    pub ripemd160_preimages: BTreeMap<ripemd160::Hash, Vec<u8>>,
    /// SHA256 hash to preimage map
    #[cfg_attr(
        feature = "serde",
        serde(with = "crate::serde_utils::btreemap_byte_values")
    )]
    pub sha256_preimages: BTreeMap<sha256::Hash, Vec<u8>>,
    /// HSAH160 hash to preimage map
    #[cfg_attr(
        feature = "serde",
        serde(with = "crate::serde_utils::btreemap_byte_values")
    )]
    pub hash160_preimages: BTreeMap<hash160::Hash, Vec<u8>>,
    /// HAS256 hash to preimage map
    #[cfg_attr(
        feature = "serde",
        serde(with = "crate::serde_utils::btreemap_byte_values")
    )]
    pub hash256_preimages: BTreeMap<sha256d::Hash, Vec<u8>>,
    /// (PSET) Prevout TXID of the input
    pub previous_txid: Txid,
    /// (PSET) Prevout vout of the input
    pub previous_output_index: u32,
    /// (PSET) Sequence number. If omitted, defaults to 0xffffffff
    pub sequence: Option<Sequence>,
    /// (PSET) Minimum required locktime, as a UNIX timestamp. If present, must be greater than or equal to 500000000
    pub required_time_locktime: Option<locktime::Time>,
    /// (PSET) Minimum required locktime, as a blockheight. If present, must be less than 500000000
    pub required_height_locktime: Option<locktime::Height>,
    /// Serialized schnorr signature with sighash type for key spend
    pub tap_key_sig: Option<schnorr::SchnorrSig>,
    /// Map of <xonlypubkey>|<leafhash> with signature
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::btreemap_as_seq"))]
    pub tap_script_sigs: BTreeMap<(bitcoin::XOnlyPublicKey, TapLeafHash), schnorr::SchnorrSig>,
    /// Map of Control blocks to Script version pair
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::btreemap_as_seq"))]
    pub tap_scripts: BTreeMap<ControlBlock, (Script, LeafVersion)>,
    /// Map of tap root x only keys to origin info and leaf hashes contained in it
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::btreemap_as_seq"))]
    pub tap_key_origins: BTreeMap<bitcoin::XOnlyPublicKey, (Vec<TapLeafHash>, KeySource)>,
    /// Taproot Internal key
    pub tap_internal_key: Option<bitcoin::XOnlyPublicKey>,
    /// Taproot Merkle root
    pub tap_merkle_root: Option<TapBranchHash>,
    // Proprietary key-value pairs for this input.
    /// The issuance value
    pub issuance_value_amount: Option<u64>,
    /// The issuance value commitment
    pub issuance_value_comm: Option<secp256k1_zkp::PedersenCommitment>,
    /// Issuance value rangeproof
    pub issuance_value_rangeproof: Option<Box<RangeProof>>,
    /// Issuance keys rangeproof
    pub issuance_keys_rangeproof: Option<Box<RangeProof>>,
    /// Pegin Transaction. Should be a bitcoin::Transaction
    pub pegin_tx: Option<bitcoin::Transaction>,
    /// Pegin Transaction proof
    // TODO: Look for Merkle proof structs
    pub pegin_txout_proof: Option<Vec<u8>>,
    /// Pegin genesis hash
    pub pegin_genesis_hash: Option<BlockHash>,
    /// Claim script
    pub pegin_claim_script: Option<Script>,
    /// Pegin Value
    pub pegin_value: Option<u64>,
    /// Pegin Witness
    pub pegin_witness: Option<Vec<Vec<u8>>>,
    /// Issuance inflation keys
    pub issuance_inflation_keys: Option<u64>,
    /// Issuance inflation keys commitment
    pub issuance_inflation_keys_comm: Option<secp256k1_zkp::PedersenCommitment>,
    /// Issuance blinding nonce
    pub issuance_blinding_nonce: Option<Tweak>,
    /// Issuance asset entropy
    pub issuance_asset_entropy: Option<[u8; 32]>,
    /// input utxo rangeproof
    pub in_utxo_rangeproof: Option<Box<RangeProof>>,
    /// Proof that blinded issuance matches the commitment
    pub in_issuance_blind_value_proof: Option<Box<RangeProof>>,
    /// Proof that blinded inflation keys matches the corresponding commitment
    pub in_issuance_blind_inflation_keys_proof: Option<Box<RangeProof>>,
    /// Other fields
    #[cfg_attr(
        feature = "serde",
        serde(with = "crate::serde_utils::btreemap_as_seq_byte_values")
    )]
    pub proprietary: BTreeMap<raw::ProprietaryKey, Vec<u8>>,
    /// Unknown key-value pairs for this input.
    #[cfg_attr(
        feature = "serde",
        serde(with = "crate::serde_utils::btreemap_as_seq_byte_values")
    )]
    pub unknown: BTreeMap<raw::Key, Vec<u8>>,
}

impl Default for Input {
    fn default() -> Self {
        Self { non_witness_utxo: Default::default(), witness_utxo: Default::default(), partial_sigs: Default::default(), sighash_type: Default::default(), redeem_script: Default::default(), witness_script: Default::default(), bip32_derivation: Default::default(), final_script_sig: Default::default(), final_script_witness: Default::default(), ripemd160_preimages: Default::default(), sha256_preimages: Default::default(), hash160_preimages: Default::default(), hash256_preimages: Default::default(), previous_txid: Txid::all_zeros(), previous_output_index: Default::default(), sequence: Default::default(), required_time_locktime: Default::default(), required_height_locktime: Default::default(), tap_key_sig: Default::default(), tap_script_sigs: Default::default(), tap_scripts: Default::default(), tap_key_origins: Default::default(), tap_internal_key: Default::default(), tap_merkle_root: Default::default(), issuance_value_amount: Default::default(), issuance_value_comm: Default::default(), issuance_value_rangeproof: Default::default(), issuance_keys_rangeproof: Default::default(), pegin_tx: Default::default(), pegin_txout_proof: Default::default(), pegin_genesis_hash: Default::default(), pegin_claim_script: Default::default(), pegin_value: Default::default(), pegin_witness: Default::default(), issuance_inflation_keys: Default::default(), issuance_inflation_keys_comm: Default::default(), issuance_blinding_nonce: Default::default(), issuance_asset_entropy: Default::default(), in_utxo_rangeproof: Default::default(), in_issuance_blind_value_proof: Default::default(), in_issuance_blind_inflation_keys_proof: Default::default(), proprietary: Default::default(), unknown: Default::default() }
    }
}

/// A Signature hash type for the corresponding input. As of taproot upgrade, the signature hash
/// type can be either [`SigHashType`] or [`SchnorrSigHashType`] but it is not possible to know
/// directly which signature hash type the user is dealing with. Therefore, the user is responsible
/// for converting to/from [`PsbtSighashType`] from/to the desired signature hash type they need.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PsbtSighashType {
    pub(crate) inner: u32,
}

serde_string_impl!(PsbtSighashType, "a PsbtSighashType data");

impl fmt::Display for PsbtSighashType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.schnorr_hash_ty() {
            Some(SchnorrSigHashType::Reserved) | None => write!(f, "{:#x}", self.inner),
            Some(schnorr_hash_ty) => fmt::Display::fmt(&schnorr_hash_ty, f),
        }
    }
}

impl FromStr for PsbtSighashType {
    type Err = SighashTypeParseError;

    #[inline]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // We accept strings of form: "SIGHASH_ALL" etc.
        //
        // NB: some of Schnorr sighash types are non-standard for pre-taproot
        // inputs. We also do not support SIGHASH_RESERVED in verbatim form
        // ("0xFF" string should be used instead).
        match SchnorrSigHashType::from_str(s) {
            Ok(SchnorrSigHashType::Reserved) => {
                return Err(SighashTypeParseError {
                    unrecognized: s.to_owned(),
                })
            }
            Ok(ty) => return Ok(ty.into()),
            Err(_) => {}
        }

        // We accept non-standard sighash values.
        if let Ok(inner) = u32::from_str_radix(s.trim_start_matches("0x"), 16) {
            return Ok(PsbtSighashType { inner });
        }

        Err(SighashTypeParseError {
            unrecognized: s.to_owned(),
        })
    }
}
impl From<EcdsaSigHashType> for PsbtSighashType {
    fn from(ecdsa_hash_ty: EcdsaSigHashType) -> Self {
        PsbtSighashType {
            inner: ecdsa_hash_ty as u32,
        }
    }
}

impl From<SchnorrSigHashType> for PsbtSighashType {
    fn from(schnorr_hash_ty: SchnorrSigHashType) -> Self {
        PsbtSighashType {
            inner: schnorr_hash_ty as u32,
        }
    }
}

impl PsbtSighashType {
    /// Returns the [`SigHashType`] if the [`PsbtSighashType`] can be
    /// converted to one.
    pub fn ecdsa_hash_ty(self) -> Option<EcdsaSigHashType> {
        EcdsaSigHashType::from_standard(self.inner).ok()
    }

    /// Returns the [`SchnorrSigHashType`] if the [`PsbtSighashType`] can be
    /// converted to one.
    pub fn schnorr_hash_ty(self) -> Option<SchnorrSigHashType> {
        if self.inner > 0xffu32 {
            None
        } else {
            SchnorrSigHashType::from_u8(self.inner as u8)
        }
    }

    /// Creates a [`PsbtSighashType`] from a raw `u32`.
    ///
    /// Allows construction of a non-standard or non-valid sighash flag
    /// ([`SigHashType`], [`SchnorrSigHashType`] respectively).
    pub fn from_u32(n: u32) -> PsbtSighashType {
        PsbtSighashType { inner: n }
    }

    /// Converts [`PsbtSighashType`] to a raw `u32` sighash flag.
    ///
    /// No guarantees are made as to the standardness or validity of the returned value.
    pub fn to_u32(self) -> u32 {
        self.inner
    }
}

impl Input {
    /// Obtains the [`EcdsaSigHashType`] for this input if one is specified. If no sighash type is
    /// specified, returns [`EcdsaSigHashType::All`].
    ///
    /// # Errors
    ///
    /// If the `sighash_type` field is set to a non-standard ECDSA sighash value.
    pub fn ecdsa_hash_ty(&self) -> Option<EcdsaSigHashType> {
        self.sighash_type
            .map(|sighash_type| sighash_type.ecdsa_hash_ty())
            .unwrap_or(Some(EcdsaSigHashType::All))
    }

    /// Obtains the [`SchnorrSigHashType`] for this input if one is specified. If no sighash type is
    /// specified, returns [`SchnorrSigHashType::Default`].
    ///
    /// # Errors
    ///
    /// If the `sighash_type` field is set to a invalid Schnorr sighash value.
    pub fn schnorr_hash_ty(&self) -> Option<SchnorrSigHashType> {
        self.sighash_type
            .map(|sighash_type| sighash_type.schnorr_hash_ty())
            .unwrap_or(Some(SchnorrSigHashType::Default))
    }

    /// Create a psbt input from prevout
    /// without any issuance or pegins
    pub fn from_prevout(outpoint: OutPoint) -> Self {
        let mut ret = Self::default();
        ret.previous_output_index = outpoint.vout;
        ret.previous_txid = outpoint.txid;
        ret
    }

    /// Create a pset input from TxIn
    pub fn from_txin(txin: TxIn) -> Self {
        let mut ret = Self::from_prevout(txin.previous_output);
        let has_issuance = txin.has_issuance();
        ret.sequence = Some(txin.sequence);
        ret.final_script_sig = Some(txin.script_sig);
        ret.final_script_witness = Some(txin.witness.script_witness);

        if txin.is_pegin {
            ret.previous_output_index |= 1 << 30;
            ret.pegin_witness = Some(txin.witness.pegin_witness);
        }
        if has_issuance {
            ret.previous_output_index |= 1 << 31;
            ret.issuance_blinding_nonce = Some(txin.asset_issuance.asset_blinding_nonce);
            ret.issuance_asset_entropy = Some(txin.asset_issuance.asset_entropy);
            match txin.asset_issuance.amount {
                confidential::Value::Null => {}
                confidential::Value::Explicit(x) => ret.issuance_value_amount = Some(x),
                confidential::Value::Confidential(comm) => ret.issuance_value_comm = Some(comm),
            }
            match txin.asset_issuance.inflation_keys {
                confidential::Value::Null => {}
                confidential::Value::Explicit(x) => ret.issuance_inflation_keys = Some(x),
                confidential::Value::Confidential(comm) => {
                    ret.issuance_inflation_keys_comm = Some(comm)
                }
            }

            // Witness
            ret.issuance_keys_rangeproof = txin.witness.inflation_keys_rangeproof;
            ret.issuance_value_rangeproof = txin.witness.amount_rangeproof;
        }
        ret
    }

    /// Compute the issuance asset ids from pset. This function does not check
    /// whether there is an issuance in this input. Returns (asset_id, token_id)
    pub fn issuance_ids(&self) -> (AssetId, AssetId) {
        let issue_nonce = self.issuance_blinding_nonce.unwrap_or(ZERO_TWEAK);
        let entropy = if issue_nonce == ZERO_TWEAK {
            // new issuance
            let prevout = OutPoint {
                txid: self.previous_txid,
                vout: self.previous_output_index,
            };
            let contract_hash =
                ContractHash::from_inner(self.issuance_asset_entropy.unwrap_or_default());
            AssetId::generate_asset_entropy(prevout, contract_hash)
        } else {
            // re-issuance
            sha256::Midstate::from_inner(self.issuance_asset_entropy.unwrap_or_default())
        };
        let asset_id = AssetId::from_entropy(entropy);
        let token_id =
            AssetId::reissuance_token_from_entropy(entropy, self.issuance_value_comm.is_some());

        (asset_id, token_id)
    }

    /// If the pset input has issuance
    pub fn has_issuance(&self) -> bool {
        !self.asset_issuance().is_null()
    }

    /// If the Pset Input is pegin
    pub fn is_pegin(&self) -> bool {
        self.previous_output_index & (1 << 30) != 0
    }

    /// Get the issuance for this tx input
    pub fn asset_issuance(&self) -> AssetIssuance {
        AssetIssuance {
            asset_blinding_nonce: *self.issuance_blinding_nonce.as_ref().unwrap_or(&ZERO_TWEAK),
            asset_entropy: self.issuance_asset_entropy.unwrap_or_default(),
            amount: match (self.issuance_value_amount, self.issuance_value_comm) {
                (None, None) => confidential::Value::Null,
                (_, Some(comm)) => confidential::Value::Confidential(comm),
                (Some(x), None) => confidential::Value::Explicit(x),
            },
            inflation_keys: match (
                self.issuance_inflation_keys,
                self.issuance_inflation_keys_comm,
            ) {
                (None, None) => confidential::Value::Null,
                (_, Some(comm)) => confidential::Value::Confidential(comm),
                (Some(x), None) => confidential::Value::Explicit(x),
            },
        }
    }
}

impl Map for Input {
    fn insert_pair(&mut self, pair: raw::Pair) -> Result<(), encode::Error> {
        let raw::Pair {
            key: raw_key,
            value: raw_value,
        } = pair;

        match raw_key.type_value {
            PSET_IN_NON_WITNESS_UTXO => {
                impl_pset_insert_pair! {
                    self.non_witness_utxo <= <raw_key: _>|<raw_value: Transaction>
                }
            }
            PSET_IN_WITNESS_UTXO => {
                impl_pset_insert_pair! {
                    self.witness_utxo <= <raw_key: _>|<raw_value: TxOut>
                }
            }
            PSET_IN_PARTIAL_SIG => {
                impl_pset_insert_pair! {
                    self.partial_sigs <= <raw_key: PublicKey>|<raw_value: Vec<u8>>
                }
            }
            PSET_IN_SIGHASH_TYPE => {
                impl_pset_insert_pair! {
                    self.sighash_type <= <raw_key: _>|<raw_value: PsbtSighashType>
                }
            }
            PSET_IN_REDEEM_SCRIPT => {
                impl_pset_insert_pair! {
                    self.redeem_script <= <raw_key: _>|<raw_value: Script>
                }
            }
            PSET_IN_WITNESS_SCRIPT => {
                impl_pset_insert_pair! {
                    self.witness_script <= <raw_key: _>|<raw_value: Script>
                }
            }
            PSET_IN_BIP32_DERIVATION => {
                impl_pset_insert_pair! {
                    self.bip32_derivation <= <raw_key: PublicKey>|<raw_value: KeySource>
                }
            }
            PSET_IN_FINAL_SCRIPTSIG => {
                impl_pset_insert_pair! {
                    self.final_script_sig <= <raw_key: _>|<raw_value: Script>
                }
            }
            PSET_IN_FINAL_SCRIPTWITNESS => {
                impl_pset_insert_pair! {
                    self.final_script_witness <= <raw_key: _>|<raw_value: Vec<Vec<u8>>>
                }
            }
            PSET_IN_RIPEMD160 => {
                pset_insert_hash_pair(
                    &mut self.ripemd160_preimages,
                    raw_key,
                    raw_value,
                    error::PsetHash::Ripemd,
                )?;
            }
            PSET_IN_SHA256 => {
                pset_insert_hash_pair(
                    &mut self.sha256_preimages,
                    raw_key,
                    raw_value,
                    error::PsetHash::Sha256,
                )?;
            }
            PSET_IN_HASH160 => {
                pset_insert_hash_pair(
                    &mut self.hash160_preimages,
                    raw_key,
                    raw_value,
                    error::PsetHash::Hash160,
                )?;
            }
            PSET_IN_HASH256 => {
                pset_insert_hash_pair(
                    &mut self.hash256_preimages,
                    raw_key,
                    raw_value,
                    error::PsetHash::Hash256,
                )?;
            }
            PSET_IN_PREVIOUS_TXID | PSET_IN_OUTPUT_INDEX => {
                return Err(Error::DuplicateKey(raw_key))?;
            }
            PSET_IN_SEQUENCE => {
                impl_pset_insert_pair! {
                    self.sequence <= <raw_key: _>|<raw_value: Sequence>
                }
            }
            PSET_IN_REQUIRED_TIME_LOCKTIME => {
                impl_pset_insert_pair! {
                    self.required_time_locktime <= <raw_key: _>|<raw_value: locktime::Time>
                }
            }
            PSET_IN_REQUIRED_HEIGHT_LOCKTIME => {
                impl_pset_insert_pair! {
                    self.required_height_locktime <= <raw_key: _>|<raw_value: locktime::Height>
                }
            }
            PSBT_IN_TAP_KEY_SIG => {
                impl_pset_insert_pair! {
                    self.tap_key_sig <= <raw_key: _>|<raw_value: schnorr::SchnorrSig>
                }
            }
            PSBT_IN_TAP_SCRIPT_SIG => {
                impl_pset_insert_pair! {
                    self.tap_script_sigs <= <raw_key: (bitcoin::XOnlyPublicKey, TapLeafHash)>|<raw_value: schnorr::SchnorrSig>
                }
            }
            PSBT_IN_TAP_LEAF_SCRIPT => {
                impl_pset_insert_pair! {
                    self.tap_scripts <= <raw_key: ControlBlock>|< raw_value: (Script, LeafVersion)>
                }
            }
            PSBT_IN_TAP_BIP32_DERIVATION => {
                impl_pset_insert_pair! {
                    self.tap_key_origins <= <raw_key: bitcoin::XOnlyPublicKey>|< raw_value: (Vec<TapLeafHash>, KeySource)>
                }
            }
            PSBT_IN_TAP_INTERNAL_KEY => {
                impl_pset_insert_pair! {
                    self.tap_internal_key <= <raw_key: _>|< raw_value: bitcoin::XOnlyPublicKey>
                }
            }
            PSBT_IN_TAP_MERKLE_ROOT => {
                impl_pset_insert_pair! {
                    self.tap_merkle_root <= <raw_key: _>|< raw_value: TapBranchHash>
                }
            }
            PSET_IN_PROPRIETARY => {
                let prop_key = raw::ProprietaryKey::from_key(raw_key.clone())?;
                if prop_key.is_pset_key() {
                    match prop_key.subtype {
                        PSBT_ELEMENTS_IN_ISSUANCE_VALUE => {
                            impl_pset_prop_insert_pair!(self.issuance_value_amount <= <raw_key: _> | <raw_value : u64>)
                        }
                        PSBT_ELEMENTS_IN_ISSUANCE_VALUE_COMMITMENT => {
                            impl_pset_prop_insert_pair!(self.issuance_value_comm <= <raw_key: _> | <raw_value : secp256k1_zkp::PedersenCommitment>)
                        }
                        PSBT_ELEMENTS_IN_ISSUANCE_VALUE_RANGEPROOF => {
                            impl_pset_prop_insert_pair!(self.issuance_value_rangeproof <= <raw_key: _> | <raw_value : Box<RangeProof>>)
                        }
                        PSBT_ELEMENTS_IN_ISSUANCE_KEYS_RANGEPROOF => {
                            impl_pset_prop_insert_pair!(self.issuance_keys_rangeproof <= <raw_key: _> | <raw_value : Box<RangeProof>>)
                        }
                        PSBT_ELEMENTS_IN_PEG_IN_TX => {
                            impl_pset_prop_insert_pair!(self.pegin_tx <= <raw_key: _> | <raw_value : bitcoin::Transaction>)
                        }
                        // No support for TxOutProof struct yet
                        PSBT_ELEMENTS_IN_PEG_IN_TXOUT_PROOF => {
                            impl_pset_prop_insert_pair!(self.pegin_txout_proof <= <raw_key: _> | <raw_value : Vec<u8>>)
                        }
                        PSBT_ELEMENTS_IN_PEG_IN_GENESIS => {
                            impl_pset_prop_insert_pair!(self.pegin_genesis_hash <= <raw_key: _> | <raw_value : BlockHash>)
                        }
                        PSBT_ELEMENTS_IN_PEG_IN_CLAIM_SCRIPT => {
                            impl_pset_prop_insert_pair!(self.pegin_claim_script <= <raw_key: _> | <raw_value : Script>)
                        }
                        PSBT_ELEMENTS_IN_PEG_IN_VALUE => {
                            impl_pset_prop_insert_pair!(self.pegin_value <= <raw_key: _> | <raw_value : u64>)
                        }
                        PSBT_ELEMENTS_IN_PEG_IN_WITNESS => {
                            impl_pset_prop_insert_pair!(self.pegin_witness <= <raw_key: _> | <raw_value : Vec<Vec<u8>>>)
                        }
                        PSBT_ELEMENTS_IN_ISSUANCE_INFLATION_KEYS => {
                            impl_pset_prop_insert_pair!(self.issuance_inflation_keys <= <raw_key: _> | <raw_value : u64>)
                        }
                        PSBT_ELEMENTS_IN_ISSUANCE_INFLATION_KEYS_COMMITMENT => {
                            impl_pset_prop_insert_pair!(self.issuance_inflation_keys_comm <= <raw_key: _> | <raw_value : secp256k1_zkp::PedersenCommitment>)
                        }
                        PSBT_ELEMENTS_IN_ISSUANCE_BLINDING_NONCE => {
                            impl_pset_prop_insert_pair!(self.issuance_blinding_nonce <= <raw_key: _> | <raw_value : Tweak>)
                        }
                        PSBT_ELEMENTS_IN_ISSUANCE_ASSET_ENTROPY => {
                            impl_pset_prop_insert_pair!(self.issuance_asset_entropy <= <raw_key: _> | <raw_value : [u8;32]>)
                        }
                        PSBT_ELEMENTS_IN_UTXO_RANGEPROOF => {
                            impl_pset_prop_insert_pair!(self.in_utxo_rangeproof <= <raw_key: _> | <raw_value : Box<RangeProof>>)
                        }
                        PSBT_ELEMENTS_IN_ISSUANCE_BLIND_VALUE_PROOF => {
                            impl_pset_prop_insert_pair!(self.in_issuance_blind_value_proof <= <raw_key: _> | <raw_value : Box<RangeProof>>)
                        }
                        PSBT_ELEMENTS_IN_ISSUANCE_BLIND_INFLATION_KEYS_PROOF => {
                            impl_pset_prop_insert_pair!(self.in_issuance_blind_inflation_keys_proof <= <raw_key: _> | <raw_value : Box<RangeProof>>)
                        }
                        _ => match self.proprietary.entry(prop_key) {
                            Entry::Vacant(empty_key) => {
                                empty_key.insert(raw_value);
                            }
                            Entry::Occupied(_) => return Err(Error::DuplicateKey(raw_key).into()),
                        },
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
            rv.push(self.non_witness_utxo as <PSET_IN_NON_WITNESS_UTXO, _>)
        }

        impl_pset_get_pair! {
            rv.push(self.witness_utxo as <PSET_IN_WITNESS_UTXO, _>)
        }

        impl_pset_get_pair! {
            rv.push(self.partial_sigs as <PSET_IN_PARTIAL_SIG, PublicKey>)
        }

        impl_pset_get_pair! {
            rv.push(self.sighash_type as <PSET_IN_SIGHASH_TYPE, _>)
        }

        impl_pset_get_pair! {
            rv.push(self.redeem_script as <PSET_IN_REDEEM_SCRIPT, _>)
        }

        impl_pset_get_pair! {
            rv.push(self.witness_script as <PSET_IN_WITNESS_SCRIPT, _>)
        }

        impl_pset_get_pair! {
            rv.push(self.bip32_derivation as <PSET_IN_BIP32_DERIVATION, PublicKey>)
        }

        impl_pset_get_pair! {
            rv.push(self.final_script_sig as <PSET_IN_FINAL_SCRIPTSIG, _>)
        }

        impl_pset_get_pair! {
            rv.push(self.final_script_witness as <PSET_IN_FINAL_SCRIPTWITNESS, _>)
        }

        impl_pset_get_pair! {
            rv.push(self.ripemd160_preimages as <PSET_IN_RIPEMD160, ripemd160::Hash>)
        }

        impl_pset_get_pair! {
            rv.push(self.sha256_preimages as <PSET_IN_SHA256, sha256::Hash>)
        }

        impl_pset_get_pair! {
            rv.push(self.hash160_preimages as <PSET_IN_HASH160, hash160::Hash>)
        }

        impl_pset_get_pair! {
            rv.push(self.hash256_preimages as <PSET_IN_HASH256, sha256d::Hash>)
        }

        // Mandatory field: Prev Txid
        rv.push(raw::Pair {
            key: raw::Key {
                type_value: PSET_IN_PREVIOUS_TXID,
                key: vec![],
            },
            value: serialize::Serialize::serialize(&self.previous_txid),
        });

        // Mandatory field: prev out index
        rv.push(raw::Pair {
            key: raw::Key {
                type_value: PSET_IN_OUTPUT_INDEX,
                key: vec![],
            },
            value: serialize::Serialize::serialize(&self.previous_output_index),
        });

        impl_pset_get_pair! {
            rv.push(self.sequence as <PSET_IN_SEQUENCE, _>)
        }

        impl_pset_get_pair! {
            rv.push(self.required_time_locktime as <PSET_IN_REQUIRED_TIME_LOCKTIME, _>)
        }

        impl_pset_get_pair! {
            rv.push(self.required_height_locktime as <PSET_IN_REQUIRED_HEIGHT_LOCKTIME, _>)
        }

        impl_pset_get_pair! {
            rv.push(self.tap_key_sig as <PSBT_IN_TAP_KEY_SIG, _>)
        }

        impl_pset_get_pair! {
            rv.push(self.tap_script_sigs as <PSBT_IN_TAP_SCRIPT_SIG, (schnorr::PublicKey, TapLeafHash)>)
        }

        impl_pset_get_pair! {
            rv.push(self.tap_scripts as <PSBT_IN_TAP_LEAF_SCRIPT, ControlBlock>)
        }

        impl_pset_get_pair! {
            rv.push(self.tap_key_origins as <PSBT_IN_TAP_BIP32_DERIVATION,
                schnorr::PublicKey>)
        }

        impl_pset_get_pair! {
            rv.push(self.tap_internal_key as <PSBT_IN_TAP_INTERNAL_KEY, _>)
        }

        impl_pset_get_pair! {
            rv.push(self.tap_merkle_root as <PSBT_IN_TAP_MERKLE_ROOT, _>)
        }

        impl_pset_get_pair! {
            rv.push_prop(self.issuance_value_amount as <PSBT_ELEMENTS_IN_ISSUANCE_VALUE, _>)
        }

        impl_pset_get_pair! {
            rv.push_prop(self.issuance_value_comm as <PSBT_ELEMENTS_IN_ISSUANCE_VALUE_COMMITMENT, _>)
        }

        impl_pset_get_pair! {
            rv.push_prop(self.issuance_value_rangeproof as <PSBT_ELEMENTS_IN_ISSUANCE_VALUE_RANGEPROOF, _>)
        }

        impl_pset_get_pair! {
            rv.push_prop(self.issuance_keys_rangeproof as <PSBT_ELEMENTS_IN_ISSUANCE_KEYS_RANGEPROOF, _>)
        }

        impl_pset_get_pair! {
            rv.push_prop(self.pegin_tx as <PSBT_ELEMENTS_IN_PEG_IN_TX, _>)
        }

        impl_pset_get_pair! {
            rv.push_prop(self.pegin_txout_proof as <PSBT_ELEMENTS_IN_PEG_IN_TXOUT_PROOF, _>)
        }

        impl_pset_get_pair! {
            rv.push_prop(self.pegin_genesis_hash as <PSBT_ELEMENTS_IN_PEG_IN_GENESIS, _>)
        }

        impl_pset_get_pair! {
            rv.push_prop(self.pegin_claim_script as <PSBT_ELEMENTS_IN_PEG_IN_CLAIM_SCRIPT, _>)
        }

        impl_pset_get_pair! {
            rv.push_prop(self.pegin_value as <PSBT_ELEMENTS_IN_PEG_IN_VALUE, _>)
        }

        impl_pset_get_pair! {
            rv.push_prop(self.pegin_witness as <PSBT_ELEMENTS_IN_PEG_IN_WITNESS, _>)
        }

        impl_pset_get_pair! {
            rv.push_prop(self.issuance_inflation_keys as <PSBT_ELEMENTS_IN_ISSUANCE_INFLATION_KEYS, _>)
        }

        impl_pset_get_pair! {
            rv.push_prop(self.issuance_inflation_keys_comm as <PSBT_ELEMENTS_IN_ISSUANCE_INFLATION_KEYS_COMMITMENT, _>)
        }

        impl_pset_get_pair! {
            rv.push_prop(self.issuance_blinding_nonce as <PSBT_ELEMENTS_IN_ISSUANCE_BLINDING_NONCE, _>)
        }

        impl_pset_get_pair! {
            rv.push_prop(self.issuance_asset_entropy as <PSBT_ELEMENTS_IN_ISSUANCE_ASSET_ENTROPY, _>)
        }

        impl_pset_get_pair! {
            rv.push_prop(self.in_utxo_rangeproof as <PSBT_ELEMENTS_IN_UTXO_RANGEPROOF, _>)
        }

        impl_pset_get_pair! {
            rv.push_prop(self.in_issuance_blind_value_proof as <PSBT_ELEMENTS_IN_ISSUANCE_BLIND_VALUE_PROOF, _>)
        }

        impl_pset_get_pair! {
            rv.push_prop(self.in_issuance_blind_inflation_keys_proof as <PSBT_ELEMENTS_IN_ISSUANCE_BLIND_INFLATION_KEYS_PROOF, _>)
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
        // The prev txids and output must be the same.
        // because unique ids are the same

        merge!(non_witness_utxo, self, other);

        if let (&None, Some(witness_utxo)) = (&self.witness_utxo, other.witness_utxo) {
            self.witness_utxo = Some(witness_utxo);
            self.non_witness_utxo = None; // Clear out any non-witness UTXO when we set a witness one
        }

        self.partial_sigs.extend(other.partial_sigs);
        self.bip32_derivation.extend(other.bip32_derivation);
        self.ripemd160_preimages.extend(other.ripemd160_preimages);
        self.sha256_preimages.extend(other.sha256_preimages);
        self.hash160_preimages.extend(other.hash160_preimages);
        self.hash256_preimages.extend(other.hash256_preimages);
        self.tap_script_sigs.extend(other.tap_script_sigs);
        self.tap_scripts.extend(other.tap_scripts);
        self.tap_key_origins.extend(other.tap_key_origins);
        self.proprietary.extend(other.proprietary);
        self.unknown.extend(other.unknown);

        merge!(redeem_script, self, other);
        merge!(witness_script, self, other);
        merge!(final_script_sig, self, other);
        merge!(final_script_witness, self, other);
        merge!(tap_key_sig, self, other);
        merge!(tap_internal_key, self, other);
        merge!(tap_merkle_root, self, other);

        // Should we do this?
        self.required_time_locktime =
            cmp::max(self.required_time_locktime, other.required_time_locktime);
        self.required_height_locktime = cmp::max(
            self.required_height_locktime,
            other.required_height_locktime,
        );

        // elements
        merge!(issuance_value_amount, self, other);
        merge!(issuance_value_comm, self, other);
        merge!(issuance_value_rangeproof, self, other);
        merge!(issuance_keys_rangeproof, self, other);
        merge!(pegin_tx, self, other);
        merge!(pegin_txout_proof, self, other);
        merge!(pegin_genesis_hash, self, other);
        merge!(pegin_claim_script, self, other);
        merge!(pegin_value, self, other);
        merge!(pegin_witness, self, other);
        merge!(issuance_inflation_keys, self, other);
        merge!(issuance_inflation_keys_comm, self, other);
        merge!(issuance_blinding_nonce, self, other);
        merge!(issuance_asset_entropy, self, other);
        merge!(in_utxo_rangeproof, self, other);
        merge!(in_issuance_blind_value_proof, self, other);
        merge!(in_issuance_blind_inflation_keys_proof, self, other);
        Ok(())
    }
}

impl_psetmap_consensus_encoding!(Input);

// Implement decodable by hand. This is required
// because some fields like txid and outpoint are
// not optional and cannot by set by insert_pair
impl Decodable for Input {
    fn consensus_decode<D: io::Read>(mut d: D) -> Result<Self, encode::Error> {
        // Sets the default to [0;32] and [0;4]
        let mut rv = Self::default();
        let mut prev_vout: Option<u32> = None;
        let mut prev_txid: Option<Txid> = None;

        loop {
            match raw::Pair::consensus_decode(&mut d) {
                Ok(pair) => {
                    let raw::Pair {
                        key: raw_key,
                        value: raw_value,
                    } = pair;
                    match raw_key.type_value {
                        PSET_IN_PREVIOUS_TXID => {
                            impl_pset_insert_pair! {
                                prev_txid <= <raw_key: _>|<raw_value: Txid>
                            }
                        }
                        PSET_IN_OUTPUT_INDEX => {
                            impl_pset_insert_pair! {
                                prev_vout <= <raw_key: _>|<raw_value: u32>
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
        // Override the default values
        let prev_txid = prev_txid.ok_or(Error::MissingInputPrevTxId)?;
        let prev_vout = prev_vout.ok_or(Error::MissingInputPrevVout)?;

        // Other checks for pset

        rv.previous_txid = prev_txid;
        rv.previous_output_index = prev_vout;
        Ok(rv)
    }
}

fn pset_insert_hash_pair<H>(
    map: &mut BTreeMap<H, Vec<u8>>,
    raw_key: raw::Key,
    raw_value: Vec<u8>,
    hash_type: error::PsetHash,
) -> Result<(), encode::Error>
where
    H: hashes::Hash + serialize::Deserialize,
{
    if raw_key.key.is_empty() {
        return Err(pset::Error::InvalidKey(raw_key).into());
    }
    let key_val: H = serialize::Deserialize::deserialize(&raw_key.key)?;
    match map.entry(key_val) {
        Entry::Vacant(empty_key) => {
            let val: Vec<u8> = serialize::Deserialize::deserialize(&raw_value)?;
            if <H as hashes::Hash>::hash(&val) != key_val {
                return Err(pset::Error::InvalidPreimageHashPair {
                    preimage: val,
                    hash: Vec::from(key_val.borrow()),
                    hash_type: hash_type,
                }
                .into());
            }
            empty_key.insert(val);
            Ok(())
        }
        Entry::Occupied(_) => return Err(pset::Error::DuplicateKey(raw_key).into()),
    }
}
