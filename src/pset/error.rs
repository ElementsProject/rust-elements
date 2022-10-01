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

use std::{error, fmt};

use crate::encode;
use crate::Txid;

use super::raw;

use crate::blind::ConfidentialTxOutError;
use crate::hashes;
use secp256k1_zkp;

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
/// Enum for marking pset hash error
pub enum PsetHash {
    Ripemd,
    Sha256,
    Hash160,
    Hash256,
}
/// Ways that a Partially Signed Transaction might fail.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Error {
    /// Magic bytes for a PSET must be the ASCII for "pset" serialized in most
    /// significant byte order.
    InvalidMagic,
    /// The separator for a PSET must be `0xff`.
    InvalidSeparator,
    /// Known keys must be according to spec.
    InvalidKey(raw::Key),
    /// Non-proprietary key type found when proprietary key was expected
    InvalidProprietaryKey,
    /// Keys within key-value map should never be duplicated.
    DuplicateKey(raw::Key),
    /// PSET has an input exclusively requiring a height-based locktime and also
    /// an input requiring a time-based locktime
    LocktimeConflict,
    /// The scriptSigs for the unsigned transaction must be empty.
    UnsignedTxHasScriptSigs,
    /// The scriptWitnesses for the unsigned transaction must be empty.
    UnsignedTxHasScriptWitnesses,
    /// A PSET must have an unsigned transaction.
    MustHaveUnsignedTx,
    /// Signals that there are no more key-value pairs in a key-value map.
    NoMorePairs,
    /// Attempting to merge with a PSET describing a different unsigned
    /// transaction.
    UniqueIdMismatch {
        /// Expected
        expected: Txid,
        /// Actual
        actual: Txid,
    },
    /// Unable to parse as a standard SigHash type.
    NonStandardSigHashType(u32),
    /// Parsing errors from bitcoin_hashes
    HashParseError(hashes::Error),
    /// The pre-image must hash to the correponding pset hash
    InvalidPreimageHashPair {
        /// Hash-type
        hash_type: PsetHash,
        /// Pre-image
        preimage: Vec<u8>,
        /// Hash value
        hash: Vec<u8>,
    },
    /// Data inconsistency/conflicting data during merge procedure
    MergeConflict(String),
    /// Serialization error in bitcoin consensus-encoded structures
    ConsensusEncoding,
    /// Too Large Pset
    TooLargePset,
    /// Specified a feild in from psbt v0. Disallowed in psbtv2(pset)
    ExpiredPsbtv0Field,
    /// Cannot change pset version
    IncorrectPsetVersion,
    /// Missing Pset transaction global version
    MissingTxVersion,
    /// Missing Pset input count
    MissingInputCount,
    /// Missing Pset output count
    MissingOutputCount,
    /// Missing Pset Input Prev Txid
    MissingInputPrevTxId,
    /// Missing Input Prev Out
    MissingInputPrevVout,
    /// Global scalar must be 32 bytes
    SecpScalarSizeError(usize),
    /// Missing Output Value
    MissingOutputValue,
    /// Missing Output Asset
    MissingOutputAsset,
    /// Missing output Script Pubkey
    MissingOutputSpk,
    /// Blinded Output requires Blinded index
    MissingBlinderIndex,
    /// Output marked for blinding, but missing blinding information
    MissingBlindingInfo,
    /// Input Count Mismatch
    InputCountMismatch,
    /// Output Count Mismatch
    OutputCountMismatch,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::InvalidKey(ref rkey) => write!(f, "invalid key: {}", rkey),
            Error::InvalidProprietaryKey => write!(
                f,
                "non-proprietary key type found when proprietary key was expected"
            ),
            Error::DuplicateKey(ref rkey) => write!(f, "duplicate key: {}", rkey),
            Error::LocktimeConflict => write!(f, "conflicting locktime requirements"),
            Error::UniqueIdMismatch {
                expected: ref e,
                actual: ref a,
            } => write!(f, "different id: expected {}, actual {}", e, a),
            Error::NonStandardSigHashType(ref sht) => {
                write!(f, "non-standard sighash type: {}", sht)
            }
            Error::InvalidMagic => f.write_str("invalid magic"),
            Error::InvalidSeparator => f.write_str("invalid separator"),
            Error::UnsignedTxHasScriptSigs => {
                f.write_str("the unsigned transaction has script sigs")
            }
            Error::UnsignedTxHasScriptWitnesses => {
                f.write_str("the unsigned transaction has script witnesses")
            }
            Error::MustHaveUnsignedTx => {
                f.write_str("partially signed transactions must have an unsigned transaction")
            }
            Error::NoMorePairs => f.write_str("no more key-value pairs for this pset map"),
            Error::HashParseError(e) => write!(f, "Hash Parse Error: {}", e),
            Error::InvalidPreimageHashPair {
                ref preimage,
                ref hash,
                ref hash_type,
            } => {
                // directly using debug forms of psethash enums
                write!(
                    f,
                    "Preimage {:?} does not match {:?} hash {:?}",
                    preimage, hash_type, hash
                )
            }
            Error::MergeConflict(ref s) => {
                write!(f, "Merge conflict: {}", s)
            }
            Error::ConsensusEncoding => f.write_str("bitcoin consensus encoding error"),
            Error::TooLargePset => {
                write!(f, "Psets with 10_000 or more inputs/outputs unsupported")
            }
            Error::ExpiredPsbtv0Field => {
                f.write_str("psbt v0 field specified in pset(based on pset)")
            }
            Error::IncorrectPsetVersion => f.write_str("Pset version must be 2"),
            Error::MissingTxVersion => f.write_str("PSET missing global transaction version"),
            Error::MissingInputCount => f.write_str("PSET missing input count"),
            Error::MissingOutputCount => f.write_str("PSET missing output count"),
            Error::MissingInputPrevTxId => f.write_str("PSET input missing previous txid"),
            Error::MissingInputPrevVout => f.write_str("PSET input missing previous output index"),
            Error::SecpScalarSizeError(actual) => {
                write!(
                    f,
                    "PSET blinding scalars must be 32 bytes. Found {} bytes",
                    actual
                )
            }
            Error::MissingOutputValue => f.write_str(
                "PSET output missing value. Must have \
                at least one of explicit/confidential value set",
            ),
            Error::MissingOutputAsset => f.write_str(
                "PSET output missing asset. Must have \
                at least one of explicit/confidential asset set",
            ),
            Error::MissingBlinderIndex => {
                f.write_str("Output is blinded but does not have a blinder index")
            }
            Error::MissingBlindingInfo => f.write_str(
                "Output marked for blinding, but missing \
                some blinding information",
            ),
            Error::MissingOutputSpk => f.write_str(
                "PSET output missing script pubkey. Must have \
                exactly one of explicit/confidential script pubkey set",
            ),
            Error::InputCountMismatch => f.write_str(
                "PSET input count global field must \
                match the number of inputs",
            ),
            Error::OutputCountMismatch => f.write_str(
                "PSET output count global field must \
                match the number of outputs",
            ),
        }
    }
}

impl error::Error for Error {}

#[doc(hidden)]
impl From<hashes::Error> for Error {
    fn from(e: hashes::Error) -> Error {
        Error::HashParseError(e)
    }
}

impl From<encode::Error> for Error {
    fn from(err: encode::Error) -> Self {
        match err {
            encode::Error::PsetError(err) => err,
            _ => Error::ConsensusEncoding,
        }
    }
}

/// Ways that blinding a Partially Signed Transaction might fail.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum PsetBlindError {
    /// Input TxOut len mismatch
    InputTxOutSecretLen,
    /// Output TxOut len mismatch
    OutputTxOutSecretLen,
    /// Blinder index out of range
    BlinderIndexOutOfBounds(usize, usize),
    /// Missing Input Blind Secrets
    MissingInputBlinds(usize, usize),
    /// Atleast one output should be blinded
    AtleastOneOutputBlind,
    /// must have explicit asset/values for blinding
    MustHaveExplicitTxOut(usize),
    /// Missing witness utxo
    MissingWitnessUtxo(usize),
    /// Confidential txout error
    ConfidentialTxOutError(usize, ConfidentialTxOutError),
    /// Blinding proof creation error
    BlindingProofsCreationError(usize, secp256k1_zkp::Error),
}

impl fmt::Display for PsetBlindError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            PsetBlindError::InputTxOutSecretLen => {
                write!(f, "Input Secret Count must match pset input count")
            }
            PsetBlindError::OutputTxOutSecretLen => {
                write!(f, "Output Secret Count must match pset output count")
            }
            PsetBlindError::AtleastOneOutputBlind => {
                write!(f, "Atleast one output secrets should be provided")
            }
            PsetBlindError::BlinderIndexOutOfBounds(i, bl) => {
                write!(
                    f,
                    "Blinder index {} for output index {} must be less \
                    than total input count",
                    bl, i
                )
            }
            PsetBlindError::MissingInputBlinds(i, bl) => {
                write!(f, "Output index {} expects blinding input index {}", i, bl)
            }
            PsetBlindError::MustHaveExplicitTxOut(i) => {
                write!(f, "Output index {} must be a explicit txout", i)
            }
            PsetBlindError::MissingWitnessUtxo(i) => {
                write!(f, "Input index {} must have witness utxo", i)
            }
            PsetBlindError::ConfidentialTxOutError(i, e) => {
                write!(f, "Blinding error {} at output index {}", e, i)
            }
            PsetBlindError::BlindingProofsCreationError(i, e) => {
                write!(
                    f,
                    "Blinding proof creation error {} at output index {}",
                    e, i
                )
            }
        }
    }
}
impl error::Error for PsetBlindError {}
