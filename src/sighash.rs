// Rust Bitcoin Library
// Written in 2018 by
//     Andrew Poelstra <apoelstra@wpsoftware.net>
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

//! BIP143 Implementation
//!
//! Implementation of BIP143 Segwit-style signatures. Should be sufficient
//! to create signatures for Segwit transactions (which should be pushed into
//! the appropriate place in the `Transaction::witness` array) or bcash
//! signatures, which are placed in the scriptSig.
//!

use crate::encode::{self, Encodable};
use crate::hash_types::SigHash;
use crate::hashes::{sha256d, Hash, sha256};
use crate::script::Script;
use std::ops::{Deref, DerefMut};
use std::io;
use crate::endian;
use crate::transaction::{EcdsaSigHashType, Transaction, TxIn, TxOut, TxInWitness};
use crate::confidential;
use crate::Sequence;
use std::fmt;
use crate::taproot::{TapSighashHash, TapLeafHash};

use crate::BlockHash;

use crate::transaction::SighashTypeParseError;
/// Efficiently calculates signature hash message for legacy, segwit and taproot inputs.
#[derive(Debug)]
pub struct SigHashCache<T: Deref<Target = Transaction>> {
    /// Access to transaction required for various introspection, moreover type
    /// `T: Deref<Target=Transaction>` allows to accept borrow and mutable borrow, the
    /// latter in particular is necessary for [`SigHashCache::witness_mut`]
    tx: T,

    /// Common cache for taproot and segwit inputs. It's an option because it's not needed for legacy inputs
    common_cache: Option<CommonCache>,

    /// Cache for segwit v0 inputs, it's the result of another round of sha256 on `common_cache`
    segwit_cache: Option<SegwitCache>,

    /// Cache for taproot v1 inputs
    taproot_cache: Option<TaprootCache>,
}

/// Values cached common between segwit and taproot inputs
#[derive(Debug)]
struct CommonCache {
    prevouts: sha256::Hash,
    sequences: sha256::Hash,

    /// in theory, `outputs` could be `Option` since `NONE` and `SINGLE` doesn't need it, but since
    /// `ALL` is the mostly used variant by large, we don't bother
    outputs: sha256::Hash,
    issuances: sha256::Hash,
}

/// Values cached for segwit inputs, it's equal to [`CommonCache`] plus another round of `sha256`
#[derive(Debug)]
struct SegwitCache {
    prevouts: sha256d::Hash,
    sequences: sha256d::Hash,
    issuances: sha256d::Hash,
    outputs: sha256d::Hash,
}

/// Values cached for taproot inputs
#[derive(Debug)]
struct TaprootCache {
    script_pubkeys: sha256::Hash,
    outpoint_flags: sha256::Hash,
    asset_amounts: sha256::Hash,
    issuance_rangeproofs: sha256::Hash,
    output_witnesses: sha256::Hash,
}

/// Contains outputs of previous transactions.
/// In the case [`SchnorrSigHashType`] variant is `ANYONECANPAY`, [`Prevouts::One`] may be provided
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub enum Prevouts<'u> {
    /// `One` variant allows to provide the single Prevout needed. It's useful for example
    /// when modifier `ANYONECANPAY` is provided, only prevout of the current input is needed.
    /// The first `usize` argument is the input index this [`TxOut`] is referring to.
    One(usize, &'u TxOut),
    /// When `ANYONECANPAY` is not provided, or the caller is handy giving all prevouts so the same
    /// variable can be used for multiple inputs.
    All(&'u [TxOut]),
}

const KEY_VERSION_0: u8 = 0u8;

/// Information related to the script path spending
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct ScriptPath<'s> {
    script: &'s Script,
    code_separator_pos: u32,
    leaf_version: u8,
}

/// Possible errors in computing the signature message
#[derive(Debug)]
pub enum Error {
    /// Could happen only by using `*_encode_signing_*` methods with custom writers, engines writers
    /// like the ones used in methods `*_signature_hash` don't error
    Encode(encode::Error),

    /// Requested index is greater or equal than the number of inputs in the transaction
    IndexOutOfInputsBounds {
        /// Requested index
        index: usize,
        /// Number of transaction inputs
        inputs_size: usize,
    },

    /// Using SIGHASH_SINGLE without a "corresponding output" (an output with the same index as the
    /// input being verified) is a validation failure
    SingleWithoutCorrespondingOutput {
        /// Requested index
        index: usize,
        /// Number of transaction outputs
        outputs_size: usize,
    },

    /// There are mismatches in the number of prevouts provided compared with the number of
    /// inputs in the transaction
    PrevoutsSize,

    /// Requested a prevout index which is greater than the number of prevouts provided or a
    /// [`Prevouts::One`] with different index
    PrevoutIndex,

    /// A single prevout has been provided but all prevouts are needed without `ANYONECANPAY`
    PrevoutKind,

    /// Annex must be at least one byte long and the first bytes must be `0x50`
    WrongAnnex,

    /// Invalid Sighash type
    InvalidSigHashType(u8),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Encode(ref e) => write!(f, "Writer errored: {:?}", e),
            Error::IndexOutOfInputsBounds { index, inputs_size } => write!(f, "Requested index ({}) is greater or equal than the number of transaction inputs ({})", index, inputs_size),
            Error::SingleWithoutCorrespondingOutput { index, outputs_size } => write!(f, "SIGHASH_SINGLE for input ({}) haven't a corresponding output (#outputs:{})", index, outputs_size),
            Error::PrevoutsSize => write!(f, "Number of supplied prevouts differs from the number of inputs in transaction"),
            Error::PrevoutIndex => write!(f, "The index requested is greater than available prevouts or different from the provided [Provided::Anyone] index"),
            Error::PrevoutKind => write!(f, "A single prevout has been provided but all prevouts are needed without `ANYONECANPAY`"),
            Error::WrongAnnex => write!(f, "Annex must be at least one byte long and the first bytes must be `0x50`"),
            Error::InvalidSigHashType(hash_ty) => write!(f, "Invalid schnorr Signature hash type : {} ", hash_ty),
        }
    }
}

impl ::std::error::Error for Error {}

impl<'u> Prevouts<'u> {
    fn check_all(&self, tx: &Transaction) -> Result<(), Error> {
        if let Prevouts::All(prevouts) = self {
            if prevouts.len() != tx.input.len() {
                return Err(Error::PrevoutsSize);
            }
        }
        Ok(())
    }

    fn get_all(&self) -> Result<&[TxOut], Error> {
        match self {
            Prevouts::All(prevouts) => Ok(prevouts),
            _ => Err(Error::PrevoutKind),
        }
    }

    fn get(&self, input_index: usize) -> Result<&TxOut, Error> {
        match self {
            Prevouts::One(index, prevout) => {
                if input_index == *index {
                    Ok(prevout)
                } else {
                    Err(Error::PrevoutIndex)
                }
            }
            Prevouts::All(prevouts) => prevouts.get(input_index).ok_or(Error::PrevoutIndex),
        }
    }
}

impl<'s> ScriptPath<'s> {
    /// Create a new ScriptPath structure
    pub fn new(script: &'s Script, code_separator_pos: u32, leaf_version: u8) -> Self {
        ScriptPath {
            script,
            code_separator_pos,
            leaf_version,
        }
    }
    /// Create a new ScriptPath structure using default values for `code_separator_pos` and `leaf_version`
    pub fn with_defaults(script: &'s Script) -> Self {
        Self::new(script, 0xFFFFFFFFu32, 0xc4)
    }

    /// Compute the leaf hash
    pub fn leaf_hash(&self) -> TapLeafHash {
        let mut enc = TapLeafHash::engine();

        self.leaf_version.consensus_encode(&mut enc).expect("Writing to hash enging should never fail");
        self.script.consensus_encode(&mut enc).expect("Writing to hash enging should never fail");

        TapLeafHash::from_engine(enc)
    }
}

impl<'s> From<ScriptPath<'s>> for TapLeafHash {
    fn from(script_path: ScriptPath<'s>) -> TapLeafHash {
        script_path.leaf_hash()
    }
}

impl<R: Deref<Target = Transaction>> SigHashCache<R> {
    /// Compute the sighash components from an unsigned transaction and auxiliary
    /// in a lazy manner when required.
    /// For the generated sighashes to be valid, no fields in the transaction may change except for
    /// script_sig and witnesses.
    pub fn new(tx: R) -> Self {
        SigHashCache {
            tx,
            common_cache: None,
            taproot_cache: None,
            segwit_cache: None,
        }
    }

    /// Encode the BIP341 signing data for any flag type into a given object implementing a
    /// io::Write trait.
    pub fn taproot_encode_signing_data_to<Write: io::Write>(
        &mut self,
        mut writer: Write,
        input_index: usize,
        prevouts: &Prevouts,
        annex: Option<Annex>,
        leaf_hash_code_separator: Option<(TapLeafHash, u32)>,
        sighash_type: SchnorrSigHashType,
        genesis_hash: BlockHash,
    ) -> Result<(), Error> {
        prevouts.check_all(&self.tx)?;

        let (sighash, anyone_can_pay) = sighash_type.split_anyonecanpay_flag();

        // Genesis hash twice
        genesis_hash.consensus_encode(&mut writer)?;
        genesis_hash.consensus_encode(&mut writer)?;

        // No epoch in elements

        // * Control:
        // hash_type (1).
        (sighash_type as u8).consensus_encode(&mut writer)?;

        // * Transaction Data:
        // nVersion (4): the nVersion of the transaction.
        self.tx.version.consensus_encode(&mut writer)?;

        // nLockTime (4): the nLockTime of the transaction.
        self.tx.lock_time.consensus_encode(&mut writer)?;

        // If the hash_type & 0x80 does not equal SIGHASH_ANYONECANPAY:
        //     sha_outpoint_flags (32): (ELEMENTS) the SHA256 of outpoint flags
        //     sha_prevouts (32): the SHA256 of the serialization of all input outpoints.
        //     sha_asset_amounts (32): (ELEMENTS) the SHA256 of the serialization of all spent output asset followed by amounts.
        //     sha_scriptpubkeys (32): the SHA256 of the serialization of all spent output scriptPubKeys.
        //     sha_sequences (32): the SHA256 of the serialization of all input nSequence.
        //     sha_issuances (32): (ELEMENTS) the SHA256 of the serialization of the concatenation of asset issuance data
        //     sha_issuance_rangeproofs (32): (ELEMENTS) the sha256 of issuance amount rangeproof followed by inflation keys rangeproof
        if !anyone_can_pay {
            self.taproot_cache(prevouts.get_all()?)
                .outpoint_flags
                .consensus_encode(&mut writer)?;
            self.common_cache().prevouts.consensus_encode(&mut writer)?;
            self.taproot_cache(prevouts.get_all()?)
                .asset_amounts
                .consensus_encode(&mut writer)?;
            self.taproot_cache(prevouts.get_all()?)
                .script_pubkeys
                .consensus_encode(&mut writer)?;
            self.common_cache()
                .sequences
                .consensus_encode(&mut writer)?;
            self.common_cache()
                .issuances
                .consensus_encode(&mut writer)?;
            self.taproot_cache(prevouts.get_all()?)
                .issuance_rangeproofs
                .consensus_encode(&mut writer)?;
        }

        // If hash_type & 3 does not equal SIGHASH_NONE or SIGHASH_SINGLE:
        //     sha_outputs (32): the SHA256 of the serialization of all outputs in CTxOut format.
        //     sha_output_witnesses (32): (ELEMENTS) the SHA256 of the serialization of all output witnesses
        if sighash != SchnorrSigHashType::None && sighash != SchnorrSigHashType::Single {
            self.common_cache().outputs.consensus_encode(&mut writer)?;
            self.taproot_cache(prevouts.get_all()?)
                .output_witnesses
                .consensus_encode(&mut writer)?;
        }

        // * Data about this input:
        // spend_type (1): equal to (ext_flag * 2) + annex_present, where annex_present is 0
        // if no annex is present, or 1 otherwise
        let mut spend_type = 0u8;
        if annex.is_some() {
            spend_type |= 1u8;
        }
        if leaf_hash_code_separator.is_some() {
            spend_type |= 2u8;
        }
        spend_type.consensus_encode(&mut writer)?;

        // If hash_type & 0x80 equals SIGHASH_ANYONECANPAY:
        //      outpoint_flag(1) : (ELEMENTS) the outpoint flag of this input
        //      outpoint (36): the COutPoint of this input (32-byte hash + 4-byte little-endian).
        //      asset (33): (ELEMENTS) the asset of the previous output
        //      value (9-33): (modified in ELEMENTS) value of the previous output spent by this input.
        //      scriptPubKey (35): scriptPubKey of the previous output spent by this input, serialized as script inside CTxOut. Its size is always 35 bytes.
        //      nSequence (4): nSequence of this input.
        //      asset_issuance (1-130): (ELEMENTS) asset issuance data if present; otherwise 0x00
        //      asset_issuance_rangeproofs (0-32) : (ELEMENTS) the sha256 of serialization of issuance proofs for this input
        if anyone_can_pay {
            let txin =
                &self
                    .tx
                    .input
                    .get(input_index)
                    .ok_or_else(|| Error::IndexOutOfInputsBounds {
                        index: input_index,
                        inputs_size: self.tx.input.len(),
                    })?;
            let previous_output = prevouts.get(input_index)?;
            txin.outpoint_flag().consensus_encode(&mut writer)?;
            txin.previous_output.consensus_encode(&mut writer)?;
            previous_output.asset.consensus_encode(&mut writer)?;
            previous_output.value.consensus_encode(&mut writer)?;
            previous_output
                .script_pubkey
                .consensus_encode(&mut writer)?;
            txin.sequence.consensus_encode(&mut writer)?;
            if txin.has_issuance(){
                txin.asset_issuance.consensus_encode(&mut writer)?;
                let mut eng = sha256::Hash::engine();
                txin.witness.amount_rangeproof.consensus_encode(&mut eng)?;
                txin.witness.inflation_keys_rangeproof.consensus_encode(&mut eng)?;
                let sha_single_issuance_rangeproofs = sha256::Hash::from_engine(eng);
                sha_single_issuance_rangeproofs.consensus_encode(&mut writer)?;
            } else {
                0u8.consensus_encode(&mut writer)?;
            }
        } else {
            (input_index as u32).consensus_encode(&mut writer)?;
        }

        // If an annex is present (the lowest bit of spend_type is set):
        //      sha_annex (32): the SHA256 of (compact_size(size of annex) || annex), where annex
        //      includes the mandatory 0x50 prefix.
        if let Some(annex) = annex {
            let mut enc = sha256::Hash::engine();
            annex.consensus_encode(&mut enc)?;
            let hash = sha256::Hash::from_engine(enc);
            hash.consensus_encode(&mut writer)?;
        }

        // * Data about this output:
        // If hash_type & 3 equals SIGHASH_SINGLE:
        //      sha_single_output (32): the SHA256 of the corresponding output in CTxOut format.
        //      sha_single_output_witness (32): the sha256 serialization of output witnesses
        if sighash == SchnorrSigHashType::Single {
            let mut enc = sha256::Hash::engine();
            let out = self.tx
                .output
                .get(input_index)
                .ok_or_else(|| Error::SingleWithoutCorrespondingOutput {
                    index: input_index,
                    outputs_size: self.tx.output.len(),
                })?;
            out.consensus_encode(&mut enc)?;
            let hash = sha256::Hash::from_engine(enc);
            hash.consensus_encode(&mut writer)?;

            // Witness serialization
            let mut eng = sha256::Hash::engine();
            out.witness.consensus_encode(&mut eng)?;
            let sha_single_output_witness = sha256::Hash::from_engine(eng);
            sha_single_output_witness.consensus_encode(&mut writer)?;
        }

        //     if (scriptpath):
        //         ss += TaggedHash("TapLeaf", bytes([leaf_ver]) + ser_string(script))
        //         ss += bytes([0])
        //         ss += struct.pack("<i", codeseparator_pos)
        if let Some((hash, code_separator_pos)) = leaf_hash_code_separator {
            hash.into_inner().consensus_encode(&mut writer)?;
            KEY_VERSION_0.consensus_encode(&mut writer)?;
            code_separator_pos.consensus_encode(&mut writer)?;
        }

        Ok(())
    }

    /// Compute the BIP341 sighash for any flag type.
    pub fn taproot_sighash(
        &mut self,
        input_index: usize,
        prevouts: &Prevouts,
        annex: Option<Annex>,
        leaf_hash_code_separator: Option<(TapLeafHash, u32)>,
        sighash_type: SchnorrSigHashType,
        genesis_hash: BlockHash,
    ) -> Result<TapSighashHash, Error> {
        let mut enc = TapSighashHash::engine();
        self.taproot_encode_signing_data_to(
            &mut enc,
            input_index,
            prevouts,
            annex,
            leaf_hash_code_separator,
            sighash_type,
            genesis_hash,
        )?;
        Ok(TapSighashHash::from_engine(enc))
    }

    /// Compute the BIP341 sighash for a key spend
    pub fn taproot_key_spend_signature_hash(
        &mut self,
        input_index: usize,
        prevouts: &Prevouts,
        sighash_type: SchnorrSigHashType,
        genesis_hash: BlockHash,
    ) -> Result<TapSighashHash, Error> {
        let mut enc = TapSighashHash::engine();
        self.taproot_encode_signing_data_to(
            &mut enc,
            input_index,
            prevouts,
            None,
            None,
            sighash_type,
            genesis_hash,
        )?;
        Ok(TapSighashHash::from_engine(enc))
    }

    /// Compute the BIP341 sighash for a script spend
    ///
    /// Assumes the default `OP_CODESEPARATOR` position of `0xFFFFFFFF`. Custom values can be
    /// provided through the more fine-grained API of [`SighashCache::taproot_encode_signing_data_to`].
    pub fn taproot_script_spend_signature_hash<S: Into<TapLeafHash>>(
        &mut self,
        input_index: usize,
        prevouts: &Prevouts,
        leaf_hash: S,
        sighash_type: SchnorrSigHashType,
        genesis_hash: BlockHash,
    ) -> Result<TapSighashHash, Error> {
        let mut enc = TapSighashHash::engine();
        self.taproot_encode_signing_data_to(
            &mut enc,
            input_index,
            prevouts,
            None,
            Some((leaf_hash.into(), 0xFFFFFFFF)),
            sighash_type,
            genesis_hash
        )?;
        Ok(TapSighashHash::from_engine(enc))
    }

    /// Encode the BIP143 signing data for any flag type into a given object implementing a
    /// std::io::Write trait.
    ///
    /// *Warning* This does NOT attempt to support OP_CODESEPARATOR. In general
    /// this would require evaluating `script_pubkey` to determine which separators
    /// get evaluated and which don't, which we don't have the information to
    /// determine.
    ///
    /// # Panics
    /// Panics if `input_index` is greater than or equal to `self.input.len()`
    ///
    pub fn encode_segwitv0_signing_data_to<Write: io::Write>(
        &mut self,
        mut writer: Write,
        input_index: usize,
        script_code: &Script,
        value: confidential::Value,
        sighash_type: EcdsaSigHashType,
    ) -> Result<(), encode::Error> {
        let zero_hash = sha256d::Hash::all_zeros();

        let (sighash, anyone_can_pay) = sighash_type.split_anyonecanpay_flag();

        self.tx.version.consensus_encode(&mut writer)?;

        if !anyone_can_pay {
            self.segwit_cache().prevouts.consensus_encode(&mut writer)?;
        } else {
            zero_hash.consensus_encode(&mut writer)?;
        }

        if !anyone_can_pay && sighash != EcdsaSigHashType::Single && sighash != EcdsaSigHashType::None {
            self.segwit_cache().sequences.consensus_encode(&mut writer)?;
        } else {
            zero_hash.consensus_encode(&mut writer)?;
        }

        // Elements: Push the hash issuance zero hash as required
        // If required implement for issuance, but not necessary as of now
        if !anyone_can_pay {
            self.segwit_cache().issuances.consensus_encode(&mut writer)?;
        } else {
            zero_hash.consensus_encode(&mut writer)?;
        }

        // input specific values
        {
            let txin = &self.tx.input[input_index];

            txin.previous_output.consensus_encode(&mut writer)?;
            script_code.consensus_encode(&mut writer)?;
            value.consensus_encode(&mut writer)?;
            txin.sequence.consensus_encode(&mut writer)?;
            if txin.has_issuance(){
                txin.asset_issuance.consensus_encode(&mut writer)?;
            }
        }

        // hashoutputs
        if sighash != EcdsaSigHashType::Single && sighash != EcdsaSigHashType::None {
            self.segwit_cache().outputs.consensus_encode(&mut writer)?;
        } else if sighash == EcdsaSigHashType::Single && input_index < self.tx.output.len() {
            let mut single_enc = SigHash::engine();
            self.tx.output[input_index].consensus_encode(&mut single_enc)?;
            SigHash::from_engine(single_enc).consensus_encode(&mut writer)?;
        } else {
            zero_hash.consensus_encode(&mut writer)?;
        }

        self.tx.lock_time.consensus_encode(&mut writer)?;
        sighash_type.as_u32().consensus_encode(&mut writer)?;
        Ok(())
    }

    /// Compute the segwitv0(BIP143) style sighash for any flag type.
    /// *Warning* This does NOT attempt to support OP_CODESEPARATOR. In general
    /// this would require evaluating `script_pubkey` to determine which separators
    /// get evaluated and which don't, which we don't have the information to
    /// determine.
    ///
    /// # Panics
    /// Panics if `input_index` is greater than or equal to `self.input.len()`
    ///
    pub fn segwitv0_sighash(
        &mut self,
        input_index: usize,
        script_code: &Script,
        value: confidential::Value,
        sighash_type: EcdsaSigHashType
    ) -> SigHash {
        let mut enc = SigHash::engine();
        self.encode_segwitv0_signing_data_to(&mut enc, input_index, script_code, value, sighash_type)
            .expect("engines don't error");
        SigHash::from_engine(enc)
    }

    /// Encodes the signing data from which a signature hash for a given input index with a given
    /// sighash flag can be computed.  To actually produce a scriptSig, this hash needs to be run
    /// through an ECDSA signer, the SigHashType appended to the resulting sig, and a script
    /// written around this, but this is the general (and hard) part.
    ///
    /// *Warning* This does NOT attempt to support OP_CODESEPARATOR. In general this would require
    /// evaluating `script_pubkey` to determine which separators get evaluated and which don't,
    /// which we don't have the information to determine.
    ///
    /// # Panics Panics if `input_index` is greater than or equal to `self.input.len()`
    ///
    pub fn encode_legacy_signing_data_to<Write: io::Write>(
        &self,
        mut writer: Write,
        input_index: usize,
        script_pubkey: &Script,
        sighash_type: EcdsaSigHashType,
    ) -> Result<(), encode::Error> {
        assert!(input_index < self.tx.input.len());  // Panic on OOB

        let (sighash, anyone_can_pay) = sighash_type.split_anyonecanpay_flag();

        // Special-case sighash_single bug because this is easy enough.
        if sighash == EcdsaSigHashType::Single && input_index >= self.tx.output.len() {
            writer.write_all(&[1, 0, 0, 0, 0, 0, 0, 0,
                               0, 0, 0, 0, 0, 0, 0, 0,
                               0, 0, 0, 0, 0, 0, 0, 0,
                               0, 0, 0, 0, 0, 0, 0, 0])?;
            return Ok(());
        }

        // Build tx to sign
        let mut tx = Transaction {
            version: self.tx.version,
            lock_time: self.tx.lock_time,
            input: vec![],
            output: vec![],
        };
        // Add all inputs necessary..
        if anyone_can_pay {
            tx.input = vec![TxIn {
                previous_output: self.tx.input[input_index].previous_output,
                is_pegin: self.tx.input[input_index].is_pegin,
                script_sig: script_pubkey.clone(),
                sequence: self.tx.input[input_index].sequence,
                asset_issuance: self.tx.input[input_index].asset_issuance,
                witness: TxInWitness::default(),
            }];
        } else {
            tx.input = Vec::with_capacity(self.tx.input.len());
            for (n, input) in self.tx.input.iter().enumerate() {
                tx.input.push(TxIn {
                    previous_output: input.previous_output,
                    is_pegin: input.is_pegin,
                    script_sig: if n == input_index { script_pubkey.clone() } else { Script::new() },
                    sequence: if n != input_index && (sighash == EcdsaSigHashType::Single || sighash == EcdsaSigHashType::None) { Sequence::ZERO } else { input.sequence },
                    asset_issuance: input.asset_issuance,
                    witness: TxInWitness::default(),
                });
            }
        }
        // ..then all outputs
        tx.output = match sighash {
            EcdsaSigHashType::All => self.tx.output.clone(),
            EcdsaSigHashType::Single => {
                let output_iter = self.tx.output.iter()
                                      .take(input_index + 1)  // sign all outputs up to and including this one, but erase
                                      .enumerate()            // all of them except for this one
                                      .map(|(n, out)| if n == input_index { out.clone() } else { TxOut::default() });
                output_iter.collect()
            }
            EcdsaSigHashType::None => vec![],
            _ => unreachable!()
        };
        // hash the result
        // cannot encode tx directly because of different consensus encoding
        // of elements tx(they include witness flag even for non-witness transactions)
        tx.version.consensus_encode(&mut writer)?;
        tx.input.consensus_encode(&mut writer)?;
        tx.output.consensus_encode(&mut writer)?;
        tx.lock_time.consensus_encode(&mut writer)?;

        let sighash_arr = endian::u32_to_array_le(sighash_type.as_u32());
        sighash_arr.consensus_encode(&mut writer)?;
        Ok(())
    }

    /// Computes a signature hash for a given input index with a given sighash flag.
    /// To actually produce a scriptSig, this hash needs to be run through an
    /// ECDSA signer, the SigHashType appended to the resulting sig, and a
    /// script written around this, but this is the general (and hard) part.
    /// Does not take a mutable reference because it does not do any caching.
    ///
    /// *Warning* This does NOT attempt to support OP_CODESEPARATOR. In general
    /// this would require evaluating `script_pubkey` to determine which separators
    /// get evaluated and which don't, which we don't have the information to
    /// determine.
    ///
    /// # Panics
    /// Panics if `input_index` is greater than or equal to `self.input.len()`
    ///
    pub fn legacy_sighash(
        &self,
        input_index: usize,
        script_pubkey: &Script,
        sighash_type: EcdsaSigHashType,
    ) -> SigHash {
        let mut engine = SigHash::engine();
        self.encode_legacy_signing_data_to(&mut engine, input_index, script_pubkey, sighash_type)
            .expect("engines don't error");
        SigHash::from_engine(engine)
    }

    #[inline]
    fn common_cache(&mut self) -> &CommonCache {
        Self::common_cache_minimal_borrow(&mut self.common_cache, &self.tx)
    }

    fn common_cache_minimal_borrow<'a>(
        common_cache: &'a mut Option<CommonCache>,
        tx: &R,
    ) -> &'a CommonCache {
        common_cache.get_or_insert_with(|| {
            let mut enc_prevouts = sha256::Hash::engine();
            let mut enc_sequences = sha256::Hash::engine();
            for txin in tx.input.iter() {
                txin.previous_output
                    .consensus_encode(&mut enc_prevouts)
                    .unwrap();
                txin.sequence.consensus_encode(&mut enc_sequences).unwrap();
            }
            CommonCache {
                prevouts: sha256::Hash::from_engine(enc_prevouts),
                sequences: sha256::Hash::from_engine(enc_sequences),
                outputs: {
                    let mut enc = sha256::Hash::engine();
                    for txout in tx.output.iter() {
                        txout.consensus_encode(&mut enc).unwrap();
                    }
                    sha256::Hash::from_engine(enc)
                },
                issuances: {
                    let mut enc = sha256::Hash::engine();
                    for txin in tx.input.iter() {
                        if txin.has_issuance() {
                            txin.asset_issuance.consensus_encode(&mut enc).unwrap();
                        } else {
                            0u8.consensus_encode(&mut enc).unwrap();
                        }
                    }
                    sha256::Hash::from_engine(enc)
                },
            }
        })
    }

    fn segwit_cache(&mut self) -> &SegwitCache {
        let common_cache = &mut self.common_cache;
        let tx = &self.tx;
        self.segwit_cache.get_or_insert_with(|| {
            let common_cache = Self::common_cache_minimal_borrow(common_cache, tx);
            SegwitCache {
                prevouts: sha256d::Hash::from_inner(
                    sha256::Hash::hash(&common_cache.prevouts).into_inner(),
                ),
                sequences: sha256d::Hash::from_inner(
                    sha256::Hash::hash(&common_cache.sequences).into_inner(),
                ),
                outputs: sha256d::Hash::from_inner(
                    sha256::Hash::hash(&common_cache.outputs).into_inner(),
                ),
                issuances: sha256d::Hash::from_inner(
                    sha256::Hash::hash(&common_cache.issuances).into_inner(),
                ),
            }
        })
    }

    #[inline]
    fn taproot_cache(&mut self, prevouts: &[TxOut]) -> &TaprootCache {
        Self::taproot_cache_minimal_borrow(&mut self.taproot_cache, &self.tx, prevouts)
    }

    fn taproot_cache_minimal_borrow<'a>(
        taproot_cache: &'a mut Option<TaprootCache>,
        tx: &R,
        prevouts: &[TxOut],
    ) -> &'a TaprootCache {
        taproot_cache.get_or_insert_with(|| {
            let mut enc_asset_amounts = sha256::Hash::engine();
            let mut enc_script_pubkeys = sha256::Hash::engine();
            let mut enc_outpoint_flags = sha256::Hash::engine();
            let mut enc_issuance_rangeproofs = sha256::Hash::engine();
            let mut enc_output_witnesses = sha256::Hash::engine();
            for prevout in prevouts {
                prevout.asset.consensus_encode(&mut enc_asset_amounts).unwrap();
                prevout.value.consensus_encode(&mut enc_asset_amounts).unwrap();
                prevout
                    .script_pubkey
                    .consensus_encode(&mut enc_script_pubkeys)
                    .unwrap();
            }
            for inp in tx.input.iter() {
                inp.outpoint_flag()
                    .consensus_encode(&mut enc_outpoint_flags).unwrap();
                inp.witness.amount_rangeproof
                    .consensus_encode(&mut enc_issuance_rangeproofs).unwrap();
                inp.witness.inflation_keys_rangeproof
                    .consensus_encode(&mut enc_issuance_rangeproofs).unwrap();
            }

            for out in tx.output.iter() {
                out.witness.surjection_proof.consensus_encode(&mut enc_output_witnesses).unwrap();
                out.witness.rangeproof.consensus_encode(&mut enc_output_witnesses).unwrap();
            }
            TaprootCache {
                asset_amounts: sha256::Hash::from_engine(enc_asset_amounts),
                script_pubkeys: sha256::Hash::from_engine(enc_script_pubkeys),
                outpoint_flags: sha256::Hash::from_engine(enc_outpoint_flags),
                issuance_rangeproofs: sha256::Hash::from_engine(enc_issuance_rangeproofs),
                output_witnesses: sha256::Hash::from_engine(enc_output_witnesses),
            }
        })
    }
}

impl<R: DerefMut<Target = Transaction>> SigHashCache<R> {
    /// When the SigHashCache is initialized with a mutable reference to a transaction instead of a
    /// regular reference, this method is available to allow modification to the witnesses.
    ///
    /// This allows in-line signing such as
    /// ```
    /// use elements::{PackedLockTime, Transaction, EcdsaSigHashType};
    /// use elements::sighash::SigHashCache;
    /// use elements::Script;
    /// use elements::confidential;
    ///
    /// let mut tx_to_sign = Transaction { version: 2, lock_time: PackedLockTime::ZERO, input: Vec::new(), output: Vec::new() };
    /// let input_count = tx_to_sign.input.len();
    ///
    /// let mut sig_hasher = SigHashCache::new(&mut tx_to_sign);
    /// for inp in 0..input_count {
    ///     let prevout_script = Script::new();
    ///     let _sighash = sig_hasher.segwitv0_sighash(inp, &prevout_script, confidential::Value::Explicit(42), EcdsaSigHashType::All);
    ///     // ... sign the sighash
    ///     sig_hasher.witness_mut(inp).unwrap().push(Vec::new());
    /// }
    /// ```
    pub fn witness_mut(&mut self, input_index: usize) -> Option<&mut Vec<Vec<u8>>> {
        self.tx.input.get_mut(input_index).map(|i| &mut i.witness.script_witness)
    }
}

impl From<encode::Error> for Error {
    fn from(e: encode::Error) -> Self {
        Error::Encode(e)
    }
}

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
/// The `Annex` struct is a slice wrapper enforcing first byte to be `0x50`
pub struct Annex<'a>(&'a [u8]);

impl<'a> Annex<'a> {
    /// Creates a new `Annex` struct checking the first byte is `0x50`
    pub fn new(annex_bytes: &'a [u8]) -> Result<Self, Error> {
        if annex_bytes.first() == Some(&0x50) {
            Ok(Annex(annex_bytes))
        } else {
            Err(Error::WrongAnnex)
        }
    }

    /// Returns the Annex bytes data (including first byte `0x50`)
    pub fn as_bytes(&self) -> &[u8] {
        &*self.0
    }
}

impl<'a> Encodable for Annex<'a> {
    fn consensus_encode<W: io::Write>(&self, writer: W) -> Result<usize, encode::Error> {
        encode::consensus_encode_with_size(&self.0, writer)
    }
}

/// Hashtype of an input's signature, encoded in the last byte of the signature
/// Fixed values so they can be casted as integer types for encoding
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum SchnorrSigHashType {
    /// 0x0: Used when not explicitly specified, defaulting to [`SchnorrSigHashType::All`]
    Default = 0x00,
    /// 0x1: Sign all outputs
    All = 0x01,
    /// 0x2: Sign no outputs --- anyone can choose the destination
    None = 0x02,
    /// 0x3: Sign the output whose index matches this input's index. If none exists,
    /// sign the hash `0000000000000000000000000000000000000000000000000000000000000001`.
    /// (This rule is probably an unintentional C++ism, but it's consensus so we have
    /// to follow it.)
    Single = 0x03,
    /// 0x81: Sign all outputs but only this input
    AllPlusAnyoneCanPay = 0x81,
    /// 0x82: Sign no outputs and only this input
    NonePlusAnyoneCanPay = 0x82,
    /// 0x83: Sign one output and only this input (see `Single` for what "one output" means)
    SinglePlusAnyoneCanPay = 0x83,

    /// Reserved for future use, `#[non_exhaustive]` is not available with current MSRV
    Reserved = 0xFF,
}

serde_string_impl!(SchnorrSigHashType, "a SchnorrSigHashType data");

impl SchnorrSigHashType {
    /// Break the sighash flag into the "real" sighash flag and the ANYONECANPAY boolean
    pub fn split_anyonecanpay_flag(self) -> (SchnorrSigHashType, bool) {
        match self {
            SchnorrSigHashType::Default => (SchnorrSigHashType::Default, false),
            SchnorrSigHashType::All => (SchnorrSigHashType::All, false),
            SchnorrSigHashType::None => (SchnorrSigHashType::None, false),
            SchnorrSigHashType::Single => (SchnorrSigHashType::Single, false),
            SchnorrSigHashType::AllPlusAnyoneCanPay => (SchnorrSigHashType::All, true),
            SchnorrSigHashType::NonePlusAnyoneCanPay => (SchnorrSigHashType::None, true),
            SchnorrSigHashType::SinglePlusAnyoneCanPay => (SchnorrSigHashType::Single, true),
            SchnorrSigHashType::Reserved => (SchnorrSigHashType::Reserved, false),
        }
    }

    /// Create a [`SchnorrSigHashType`] from raw u8
    pub fn from_u8(hash_ty: u8) -> Option<Self> {
        match hash_ty {
            0x00 => Some(SchnorrSigHashType::Default),
            0x01 => Some(SchnorrSigHashType::All),
            0x02 => Some(SchnorrSigHashType::None),
            0x03 => Some(SchnorrSigHashType::Single),
            0x81 => Some(SchnorrSigHashType::AllPlusAnyoneCanPay),
            0x82 => Some(SchnorrSigHashType::NonePlusAnyoneCanPay),
            0x83 => Some(SchnorrSigHashType::SinglePlusAnyoneCanPay),
            _x => None,
        }
    }
}

impl fmt::Display for SchnorrSigHashType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            SchnorrSigHashType::Default => "SIGHASH_DEFAULT",
            SchnorrSigHashType::All => "SIGHASH_ALL",
            SchnorrSigHashType::None => "SIGHASH_NONE",
            SchnorrSigHashType::Single => "SIGHASH_SINGLE",
            SchnorrSigHashType::AllPlusAnyoneCanPay => "SIGHASH_ALL|SIGHASH_ANYONECANPAY",
            SchnorrSigHashType::NonePlusAnyoneCanPay => "SIGHASH_NONE|SIGHASH_ANYONECANPAY",
            SchnorrSigHashType::SinglePlusAnyoneCanPay => "SIGHASH_SINGLE|SIGHASH_ANYONECANPAY",
            SchnorrSigHashType::Reserved => "SIGHASH_RESERVED",
        };
        f.write_str(s)
    }
}

impl std::str::FromStr for SchnorrSigHashType {
    type Err = SighashTypeParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "SIGHASH_DEFAULT" => Ok(SchnorrSigHashType::Default),
            "SIGHASH_ALL" => Ok(SchnorrSigHashType::All),
            "SIGHASH_NONE" => Ok(SchnorrSigHashType::None),
            "SIGHASH_SINGLE" => Ok(SchnorrSigHashType::Single),
            "SIGHASH_ALL|SIGHASH_ANYONECANPAY" => Ok(SchnorrSigHashType::AllPlusAnyoneCanPay),
            "SIGHASH_NONE|SIGHASH_ANYONECANPAY" => Ok(SchnorrSigHashType::NonePlusAnyoneCanPay),
            "SIGHASH_SINGLE|SIGHASH_ANYONECANPAY" => Ok(SchnorrSigHashType::SinglePlusAnyoneCanPay),
            "SIGHASH_RESERVED" => Ok(SchnorrSigHashType::Reserved),
            _ => Err(SighashTypeParseError{ unrecognized: s.to_owned() }),
        }
    }
}


#[cfg(test)]
mod tests{
    use super::*;
    use crate::encode::deserialize;
    use bitcoin::hashes::hex::FromHex;
    use bitcoin;

    fn test_segwit_sighash(tx: &str, script: &str, input_index: usize, value: &str, hash_type: EcdsaSigHashType, expected_result: &str) {
        let tx: Transaction = deserialize(&Vec::<u8>::from_hex(tx).unwrap()[..]).unwrap();
        let script = Script::from(Vec::<u8>::from_hex(script).unwrap());
        // A hack to parse sha256d strings are sha256 so that we don't reverse them...
        let raw_expected = bitcoin::hashes::sha256::Hash::from_hex(expected_result).unwrap();
        let expected_result = SigHash::from_slice(&raw_expected[..]).unwrap();

        let mut cache = SigHashCache::new(&tx);
        let value : confidential::Value = deserialize(&Vec::<u8>::from_hex(value).unwrap()[..]).unwrap();
        let actual_result = cache.segwitv0_sighash(input_index, &script, value, hash_type);
        assert_eq!(actual_result, expected_result);
    }

    #[test]
    fn test_segwit_sighashes(){
        // generated by script(example_test.py) at https://github.com/sanket1729/elements/commit/8fb4eb9e6020adaf20f3ec25055ffa905ba5b5c4
        test_segwit_sighash("010000000001715df5ccebaf02ff18d6fae7263fa69fed5de59c900f4749556eba41bc7bf2af0000000000000000000201230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b2010000000124101100001f5175517551755175517551755175517551755175517551755175517551755101230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b2010000000005f5e100000000000000", "76a914f54a5851e9372b87810a8e60cdd2e7cfd80b6e3188ac", 0, "0850863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352", EcdsaSigHashType::All, "e201b4019129a03ca0304989731c6dccde232c854d86fce999b7411da1e90048");
        test_segwit_sighash("010000000001715df5ccebaf02ff18d6fae7263fa69fed5de59c900f4749556eba41bc7bf2af0000000000000000000201230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b2010000000124101100001f5175517551755175517551755175517551755175517551755175517551755101230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b2010000000005f5e100000000000000", "76a914f54a5851e9372b87810a8e60cdd2e7cfd80b6e3188ac", 0, "0850863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352", EcdsaSigHashType::None, "bfc6599816673083334ae82ac3459a2d0fef478d3e580e3ae203a28347502cb4");
        test_segwit_sighash("010000000001715df5ccebaf02ff18d6fae7263fa69fed5de59c900f4749556eba41bc7bf2af0000000000000000000201230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b2010000000124101100001f5175517551755175517551755175517551755175517551755175517551755101230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b2010000000005f5e100000000000000", "76a914f54a5851e9372b87810a8e60cdd2e7cfd80b6e3188ac", 0, "0850863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352", EcdsaSigHashType::Single, "4bc8546e32d31c5415444138184696e80f49e537a083bfcc89be2ab41d962e76");
        test_segwit_sighash("010000000001715df5ccebaf02ff18d6fae7263fa69fed5de59c900f4749556eba41bc7bf2af0000000000000000000201230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b2010000000124101100001f5175517551755175517551755175517551755175517551755175517551755101230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b2010000000005f5e100000000000000", "76a914f54a5851e9372b87810a8e60cdd2e7cfd80b6e3188ac", 0, "0850863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352", EcdsaSigHashType::AllPlusAnyoneCanPay, "b70ba5f4a1c2c48cd7f2104b2baa6a5c97987eb560916d39a5d427deb8b1dc2a");
        test_segwit_sighash("010000000001715df5ccebaf02ff18d6fae7263fa69fed5de59c900f4749556eba41bc7bf2af0000000000000000000201230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b2010000000124101100001f5175517551755175517551755175517551755175517551755175517551755101230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b2010000000005f5e100000000000000", "76a914f54a5851e9372b87810a8e60cdd2e7cfd80b6e3188ac", 0, "0850863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352", EcdsaSigHashType::NonePlusAnyoneCanPay, "6d6a4749c09ffd9a8df4c5de5d939325d896009e18f94bb095c9d7d695a8465e");
        test_segwit_sighash("010000000001715df5ccebaf02ff18d6fae7263fa69fed5de59c900f4749556eba41bc7bf2af0000000000000000000201230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b2010000000124101100001f5175517551755175517551755175517551755175517551755175517551755101230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b2010000000005f5e100000000000000", "76a914f54a5851e9372b87810a8e60cdd2e7cfd80b6e3188ac", 0, "0850863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352", EcdsaSigHashType::SinglePlusAnyoneCanPay, "7fc34367b42bf0e2bb78d8c20f45a64b81b2d4fbb59cbff8649322f619e88a0f");
        test_segwit_sighash("010000000001715df5ccebaf02ff18d6fae7263fa69fed5de59c900f4749556eba41bc7bf2af0000000000000000000201230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b2010000000124101100001f5175517551755175517551755175517551755175517551755175517551755101230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b2010000000005f5e100000000000000", "76a914f54a5851e9372b87810a8e60cdd2e7cfd80b6e3188ac", 0, "010000000005f5e100", EcdsaSigHashType::All, "71141639d982f1a1a8901e32fb1a9e15a0ea168b37d33300a3c9619fc3767388");
        test_segwit_sighash("010000000001715df5ccebaf02ff18d6fae7263fa69fed5de59c900f4749556eba41bc7bf2af0000000000000000000201230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b2010000000124101100001f5175517551755175517551755175517551755175517551755175517551755101230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b2010000000005f5e100000000000000", "76a914f54a5851e9372b87810a8e60cdd2e7cfd80b6e3188ac", 0, "010000000005f5e100", EcdsaSigHashType::None, "00730922d0e1d55b4b5fffafd087b06aeb44c4cedb58d8e182cbb9b87382cddb");
        test_segwit_sighash("010000000001715df5ccebaf02ff18d6fae7263fa69fed5de59c900f4749556eba41bc7bf2af0000000000000000000201230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b2010000000124101100001f5175517551755175517551755175517551755175517551755175517551755101230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b2010000000005f5e100000000000000", "76a914f54a5851e9372b87810a8e60cdd2e7cfd80b6e3188ac", 0, "010000000005f5e100", EcdsaSigHashType::Single, "100063ea0923ef4432dd51c5756383530f28b31ffe9d50b59a11b94a63c84c78");
        test_segwit_sighash("010000000001715df5ccebaf02ff18d6fae7263fa69fed5de59c900f4749556eba41bc7bf2af0000000000000000000201230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b2010000000124101100001f5175517551755175517551755175517551755175517551755175517551755101230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b2010000000005f5e100000000000000", "76a914f54a5851e9372b87810a8e60cdd2e7cfd80b6e3188ac", 0, "010000000005f5e100", EcdsaSigHashType::AllPlusAnyoneCanPay, "e1c4ddf5f723759f7d99d4f162155119160b1c6b765fdbdb25aedb2059769b74");
        test_segwit_sighash("010000000001715df5ccebaf02ff18d6fae7263fa69fed5de59c900f4749556eba41bc7bf2af0000000000000000000201230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b2010000000124101100001f5175517551755175517551755175517551755175517551755175517551755101230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b2010000000005f5e100000000000000", "76a914f54a5851e9372b87810a8e60cdd2e7cfd80b6e3188ac", 0, "010000000005f5e100", EcdsaSigHashType::NonePlusAnyoneCanPay, "b0be275e0c69e89ef5c482fdf330038c3b2994ebce3e3639bb81456d15a95a7a");
        test_segwit_sighash("010000000001715df5ccebaf02ff18d6fae7263fa69fed5de59c900f4749556eba41bc7bf2af0000000000000000000201230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b2010000000124101100001f5175517551755175517551755175517551755175517551755175517551755101230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b2010000000005f5e100000000000000", "76a914f54a5851e9372b87810a8e60cdd2e7cfd80b6e3188ac", 0, "010000000005f5e100", EcdsaSigHashType::SinglePlusAnyoneCanPay, "27c293da7a0f08e161fa2a77aeefa6743c929905597b5bcb28f2015fe648aa0c");

        // Test a issuance test with only sighash all
        test_segwit_sighash("010000000001715df5ccebaf02ff18d6fae7263fa69fed5de59c900f4749556eba41bc7bf2af000000800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000003e801000000000000000a0201230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b2010000000124101100001f5175517551755175517551755175517551755175517551755175517551755101230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b2010000000005f5e100000000000000", "76a914f54a5851e9372b87810a8e60cdd2e7cfd80b6e3188ac", 0, "0850863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352", EcdsaSigHashType::All, "ea946ee417d5a16a1038b2c3b54d1b7b12a9f98c0dcb4684bf005eb1c27d0c92");
    }


    fn test_legacy_sighash(tx: &str, script: &str, input_index: usize, hash_type: EcdsaSigHashType, expected_result: &str) {
        let tx: Transaction = deserialize(&Vec::<u8>::from_hex(tx).unwrap()[..]).unwrap();
        let script = Script::from(Vec::<u8>::from_hex(script).unwrap());
        // A hack to parse sha256d strings are sha256 so that we don't reverse them...
        let raw_expected = bitcoin::hashes::sha256::Hash::from_hex(expected_result).unwrap();
        let expected_result = SigHash::from_slice(&raw_expected[..]).unwrap();
        let sighash_cache = SigHashCache::new(&tx);
        let actual_result = sighash_cache.legacy_sighash(input_index, &script, hash_type);
        assert_eq!(actual_result, expected_result);
    }

    #[test]
    fn test_legacy_sighashes(){
        // generated by script(example_test.py) at https://github.com/sanket1729/elements/commit/5ddfb5a749e85b71c961d29d5689d692ef7cee4b
        test_legacy_sighash("010000000001715df5ccebaf02ff18d6fae7263fa69fed5de59c900f4749556eba41bc7bf2af0000000000000000000201230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b2010000000124101100001f5175517551755175517551755175517551755175517551755175517551755101230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b2010000000005f5e100000000000000", "76a914f54a5851e9372b87810a8e60cdd2e7cfd80b6e3188ac", 0, EcdsaSigHashType::All, "769ad754a77282712895475eb17251bcb8f3cc35dc13406fa1188ef2707556cf");
        test_legacy_sighash("010000000001715df5ccebaf02ff18d6fae7263fa69fed5de59c900f4749556eba41bc7bf2af0000000000000000000201230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b2010000000124101100001f5175517551755175517551755175517551755175517551755175517551755101230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b2010000000005f5e100000000000000", "76a914f54a5851e9372b87810a8e60cdd2e7cfd80b6e3188ac", 0, EcdsaSigHashType::None, "b399ca018b4fec7d94e47092b72d25983db2d0d16eaa6a672050add66077ef40");
        test_legacy_sighash("010000000001715df5ccebaf02ff18d6fae7263fa69fed5de59c900f4749556eba41bc7bf2af0000000000000000000201230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b2010000000124101100001f5175517551755175517551755175517551755175517551755175517551755101230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b2010000000005f5e100000000000000", "76a914f54a5851e9372b87810a8e60cdd2e7cfd80b6e3188ac", 0, EcdsaSigHashType::Single, "4efef74996f840ed104c0b69461f33da2e364288f3015c55b2516a68e3ee60bc");
        test_legacy_sighash("010000000001715df5ccebaf02ff18d6fae7263fa69fed5de59c900f4749556eba41bc7bf2af0000000000000000000201230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b2010000000124101100001f5175517551755175517551755175517551755175517551755175517551755101230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b2010000000005f5e100000000000000", "76a914f54a5851e9372b87810a8e60cdd2e7cfd80b6e3188ac", 0, EcdsaSigHashType::AllPlusAnyoneCanPay, "a70a59ae29f1d9f4461f12e730e5cb75d3a75312666e8d911584aebb8e4afc5c");
        test_legacy_sighash("010000000001715df5ccebaf02ff18d6fae7263fa69fed5de59c900f4749556eba41bc7bf2af0000000000000000000201230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b2010000000124101100001f5175517551755175517551755175517551755175517551755175517551755101230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b2010000000005f5e100000000000000", "76a914f54a5851e9372b87810a8e60cdd2e7cfd80b6e3188ac", 0, EcdsaSigHashType::NonePlusAnyoneCanPay, "5f3694a35f3b994639d3fb1f6214ec166f9e0721c7ab3f216e465b9b2728d834");
        test_legacy_sighash("010000000001715df5ccebaf02ff18d6fae7263fa69fed5de59c900f4749556eba41bc7bf2af0000000000000000000201230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b2010000000124101100001f5175517551755175517551755175517551755175517551755175517551755101230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b2010000000005f5e100000000000000", "76a914f54a5851e9372b87810a8e60cdd2e7cfd80b6e3188ac", 0, EcdsaSigHashType::SinglePlusAnyoneCanPay, "4c18486c473dc31c264c477c55e9c17d70fddb9f567c7d411ce922261577167c");

        // Test a issuance test with only sighash all
        test_legacy_sighash("010000000001715df5ccebaf02ff18d6fae7263fa69fed5de59c900f4749556eba41bc7bf2af000000800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000003e801000000000000000a0201230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b2010000000124101100001f5175517551755175517551755175517551755175517551755175517551755101230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b2010000000005f5e100000000000000", "76a914f54a5851e9372b87810a8e60cdd2e7cfd80b6e3188ac", 0, EcdsaSigHashType::All, "9f00e1758a230aaf6c9bce777701a604f50b2ac5f2a07e1cd478d8a0e70fc195");
    }
}
