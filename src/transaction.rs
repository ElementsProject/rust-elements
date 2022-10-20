// Rust Elements Library
// Written in 2018 by
//   Andrew Poelstra <apoelstra@blockstream.com>
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

//! # Transactions
//!

use std::{io, fmt, str};
use std::collections::HashMap;
use std::convert::TryFrom;

use bitcoin::{self, VarInt};
use crate::hashes::{Hash, sha256};

use crate::{confidential, ContractHash};
use crate::encode::{self, Encodable, Decodable};
use crate::issuance::AssetId;
use crate::opcodes;
use crate::parse::impl_parse_str_through_int;
use crate::script::Instruction;
use crate::{PackedLockTime, Script, Txid, Wtxid};
use secp256k1_zkp::{
    RangeProof, SurjectionProof, Tweak, ZERO_TWEAK,
};

/// Description of an asset issuance in a transaction input
#[derive(Copy, Clone, Debug, Default, Eq, Hash, PartialEq)]
pub struct AssetIssuance {
    /// Zero for a new asset issuance; otherwise a blinding factor for the input
    pub asset_blinding_nonce: Tweak,
    /// Freeform entropy field
    pub asset_entropy: [u8; 32],
    /// Amount of asset to issue
    pub amount: confidential::Value,
    /// Amount of inflation keys to issue
    pub inflation_keys: confidential::Value,
}

impl AssetIssuance {

    /// Checks whether the [`AssetIssuance`] is null
    pub fn is_null(&self) -> bool {
        self.amount.is_null() && self.inflation_keys.is_null()
    }
}
serde_struct_impl!(AssetIssuance, asset_blinding_nonce, asset_entropy, amount, inflation_keys);
impl_consensus_encoding!(AssetIssuance, asset_blinding_nonce, asset_entropy, amount, inflation_keys);

/// A reference to a transaction output
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub struct OutPoint {
    /// The referenced transaction's txid
    pub txid: Txid,
    /// The index of the referenced output in its transaction's vout
    pub vout: u32,
}
serde_struct_human_string_impl!(OutPoint, "an Elements OutPoint", txid, vout);

impl OutPoint {
    /// Create a new outpoint.
    #[inline]
    pub fn new(txid: Txid, vout: u32) -> OutPoint {
        OutPoint {
            txid,
            vout,
        }
    }

    /// Creates a "null" `OutPoint`.
    ///
    /// This value is used for coinbase transactions because they don't have
    /// any previous outputs.
    #[inline]
    pub fn null() -> OutPoint {
        OutPoint {
            txid: Txid::all_zeros(),
            vout: u32::max_value(),
        }
    }

    /// Checks if an `OutPoint` is "null".
    #[inline]
    pub fn is_null(&self) -> bool {
        *self == OutPoint::null()
    }
}

impl Default for OutPoint {
    /// Coinbase outpoint
    fn default() -> OutPoint {
        OutPoint::null()
    }
}

impl Encodable for OutPoint {
    fn consensus_encode<S: io::Write>(&self, mut s: S) -> Result<usize, encode::Error> {
        Ok(self.txid.consensus_encode(&mut s)? +
        self.vout.consensus_encode(&mut s)?)
    }
}

impl Decodable for OutPoint {
    fn consensus_decode<D: io::Read>(mut d: D) -> Result<OutPoint, encode::Error> {
        let txid = Txid::consensus_decode(&mut d)?;
        let vout = u32::consensus_decode(&mut d)?;
        Ok(OutPoint {
            txid,
            vout,
        })
    }
}

impl fmt::Display for OutPoint {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("[elements]")?;
        write!(f, "{}:{}", self.txid, self.vout)
    }
}

impl ::std::str::FromStr for OutPoint {
    type Err = bitcoin::blockdata::transaction::ParseOutPointError;
    fn from_str(mut s: &str) -> Result<Self, Self::Err> {
        if s.starts_with("[elements]") {
            s = &s[10..];
        }
        let bitcoin_outpoint = bitcoin::OutPoint::from_str(s)?;
        Ok(OutPoint {
            txid: Txid::from(bitcoin_outpoint.txid.as_hash()),
            vout: bitcoin_outpoint.vout,
        })
    }
}

/// Bitcoin transaction input sequence number.
///
/// The sequence field is used for:
/// - Indicating whether absolute lock-time (specified in `lock_time` field of [`Transaction`])
///   is enabled.
/// - Indicating and encoding [BIP-68] relative lock-times.
/// - Indicating whether a transcation opts-in to [BIP-125] replace-by-fee.
///
/// Note that transactions spending an output with `OP_CHECKLOCKTIMEVERIFY`MUST NOT use
/// `Sequence::MAX` for the corresponding input. [BIP-65]
///
/// [BIP-65]: <https://github.com/bitcoin/bips/blob/master/bip-0065.mediawiki>
/// [BIP-68]: <https://github.com/bitcoin/bips/blob/master/bip-0068.mediawiki>
/// [BIP-125]: <https://github.com/bitcoin/bips/blob/master/bip-0125.mediawiki>
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub struct Sequence(pub u32);

#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
/// An error in creating relative lock-times.
pub enum RelativeLockTimeError {
    /// The input was too large
    IntegerOverflow(u32)
}

impl Sequence {
    /// The maximum allowable sequence number.
    ///
    /// This sequence number disables lock-time and replace-by-fee.
    pub const MAX: Self = Sequence(0xFFFFFFFF);
    /// Zero value sequence.
    ///
    /// This sequence number enables replace-by-fee and lock-time.
    pub const ZERO: Self = Sequence(0);
    /// The sequence number that enables absolute lock-time but disables replace-by-fee
    /// and relative lock-time.
    pub const ENABLE_LOCKTIME_NO_RBF: Self = Sequence::MIN_NO_RBF;
    /// The sequence number that enables replace-by-fee and absolute lock-time but
    /// disables relative lock-time.
    pub const ENABLE_RBF_NO_LOCKTIME: Self = Sequence(0xFFFFFFFD);

    /// The lowest sequence number that does not opt-in for replace-by-fee.
    ///
    /// A transaction is considered to have opted in to replacement of itself
    /// if any of it's inputs have a `Sequence` number less than this value
    /// (Explicit Signalling [BIP-125]).
    ///
    /// [BIP-125]: <https://github.com/bitcoin/bips/blob/master/bip-0125.mediawiki]>
    const MIN_NO_RBF: Self = Sequence(0xFFFFFFFE);
    /// BIP-68 relative lock-time disable flag mask
    const LOCK_TIME_DISABLE_FLAG_MASK: u32 = 0x80000000;
    /// BIP-68 relative lock-time type flag mask
    const LOCK_TYPE_MASK: u32 = 0x00400000;

    /// Retuns `true` if the sequence number indicates that the transaction is finalised.
    ///
    /// The sequence number being equal to 0xffffffff on all txin sequences indicates
    /// that the transaction is finalised.
    #[inline]
    pub fn is_final(&self) -> bool {
        *self == Sequence::MAX
    }

    /// Returns true if the transaction opted-in to BIP125 replace-by-fee.
    ///
    /// Replace by fee is signaled by the sequence being less than 0xfffffffe which is checked by this method.
    #[inline]
    pub fn is_rbf(&self) -> bool {
        *self < Sequence::MIN_NO_RBF
    }

    /// Returns `true` if the sequence has a relative lock-time.
    #[inline]
    pub fn is_relative_lock_time(&self) -> bool {
        self.0 & Sequence::LOCK_TIME_DISABLE_FLAG_MASK == 0
    }

    /// Returns `true` if the sequence number encodes a block based relative lock-time.
    #[inline]
    pub fn is_height_locked(&self) -> bool {
        self.is_relative_lock_time() & (self.0 & Sequence::LOCK_TYPE_MASK == 0)
    }

    /// Returns `true` if the sequene number encodes a time interval based relative lock-time.
    #[inline]
    pub fn is_time_locked(&self) -> bool {
        self.is_relative_lock_time() & (self.0 & Sequence::LOCK_TYPE_MASK > 0)
    }

    /// Create a relative lock-time using block height.
    #[inline]
    pub fn from_height(height: u16) -> Self {
        Sequence(u32::from(height))
    }

    /// Create a relative lock-time using time intervals where each interval is equivalent
    /// to 512 seconds.
    ///
    /// Encoding finer granularity of time for relative lock-times is not supported in Bitcoin
    #[inline]
    pub fn from_512_second_intervals(intervals: u16) -> Self {
        Sequence(u32::from(intervals) | Sequence::LOCK_TYPE_MASK)
    }

    /// Create a relative lock-time from seconds, converting the seconds into 512 second
    /// interval with floor division.
    ///
    /// Will return an error if the input cannot be encoded in 16 bits.
    #[inline]
    pub fn from_seconds_floor(seconds: u32) -> Result<Self, RelativeLockTimeError> {
        if let Ok(interval) = u16::try_from(seconds / 512) {
            Ok(Sequence::from_512_second_intervals(interval))
        } else {
            Err(RelativeLockTimeError::IntegerOverflow(seconds))
        }
    }

    /// Create a relative lock-time from seconds, converting the seconds into 512 second
    /// interval with ceiling division.
    ///
    /// Will return an error if the input cannot be encoded in 16 bits.
    #[inline]
    pub fn from_seconds_ceil(seconds: u32) -> Result<Self, RelativeLockTimeError> {
        if let Ok(interval) = u16::try_from((seconds + 511) / 512) {
            Ok(Sequence::from_512_second_intervals(interval))
        } else {
            Err(RelativeLockTimeError::IntegerOverflow(seconds))
        }
    }

    /// Returns `true` if the sequence number enables absolute lock-time ([`Transaction::lock_time`]).
    #[inline]
    pub fn enables_absolute_lock_time(&self) -> bool {
        !self.is_final()
    }

    /// Create a sequence from a u32 value.
    #[inline]
    pub fn from_consensus(n: u32) -> Self {
        Sequence(n)
    }

    /// Returns the inner 32bit integer value of Sequence.
    #[inline]
    pub fn to_consensus_u32(self) -> u32 {
        self.0
    }
}

impl Default for Sequence {
    /// The default value of sequence is 0xffffffff.
    fn default() -> Self {
        Sequence::MAX
    }
}

impl From<Sequence> for u32 {
    fn from(sequence: Sequence) -> u32 {
        sequence.0
    }
}

impl fmt::Display for Sequence {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl fmt::LowerHex for Sequence {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::LowerHex::fmt(&self.0, f)
    }
}

impl fmt::UpperHex for Sequence {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::UpperHex::fmt(&self.0, f)
    }
}

impl fmt::Display for RelativeLockTimeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Self::IntegerOverflow(val) => write!(f, "input of {} was too large", val)
        }
    }
}

impl_parse_str_through_int!(Sequence);

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
impl std::error::Error for RelativeLockTimeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::IntegerOverflow(_) => None
        }
    }
}


/// Transaction input witness
#[derive(Clone, Default, PartialEq, Eq, Debug, Hash)]
pub struct TxInWitness {
    /// Amount rangeproof
    pub amount_rangeproof: Option<Box<RangeProof>>,
    /// Rangeproof for inflation keys
    pub inflation_keys_rangeproof: Option<Box<RangeProof>>,
    /// Traditional script witness
    pub script_witness: Vec<Vec<u8>>,
    /// Pegin witness, basically the same thing
    pub pegin_witness: Vec<Vec<u8>>,
}
serde_struct_impl!(TxInWitness, amount_rangeproof, inflation_keys_rangeproof, script_witness, pegin_witness);
impl_consensus_encoding!(TxInWitness, amount_rangeproof, inflation_keys_rangeproof, script_witness, pegin_witness);

impl TxInWitness {
    /// Whether this witness is null
    pub fn is_empty(&self) -> bool {
        self.amount_rangeproof.is_none() &&
            self.inflation_keys_rangeproof.is_none() &&
            self.script_witness.is_empty() &&
            self.pegin_witness.is_empty()
    }
}


/// Parsed data from a transaction input's pegin witness
#[derive(Copy, Clone, PartialEq, Eq, Debug, Hash)]
pub struct PeginData<'tx> {
    /// Reference to the pegin output on the mainchain
    pub outpoint: bitcoin::OutPoint,
    /// The value, in satoshis, of the pegin
    pub value: u64,
    /// Asset type being pegged in
    pub asset: AssetId,
    /// Hash of genesis block of originating blockchain
    pub genesis_hash: bitcoin::BlockHash,
    /// The claim script that we should hash to tweak our address. Unparsed
    /// to avoid unnecessary allocation and copying. Typical use is simply
    /// to feed it raw into a hash function.
    pub claim_script: &'tx [u8],
    /// Mainchain transaction; not parsed to save time/memory since the
    /// parsed transaction is typically not useful without auxillary
    /// data (e.g. knowing how to compute pegin addresses for the
    /// sidechain).
    pub tx: &'tx [u8],
    /// Merkle proof of transaction inclusion; also not parsed
    pub merkle_proof: &'tx [u8],
    /// The Bitcoin block that the pegin output appears in; scraped
    /// from the transaction inclusion proof
    pub referenced_block: bitcoin::BlockHash,
}

impl<'tx> PeginData<'tx> {
    /// Construct the pegin data from a pegin witness.
    /// Returns None if not a valid pegin witness.
    pub fn from_pegin_witness(
        pegin_witness: &'tx [Vec<u8>],
        prevout: bitcoin::OutPoint,
    ) -> Result<PeginData<'tx>, &'static str> {
        if pegin_witness.len() != 6 {
            return Err("size not 6");
        }

        Ok(PeginData {
            outpoint: prevout,
            value: bitcoin::consensus::deserialize(&pegin_witness[0]).map_err(|_| "invalid value")?,
            asset: encode::deserialize(&pegin_witness[1]).map_err(|_| "invalid asset")?,
            genesis_hash: bitcoin::consensus::deserialize(&pegin_witness[2])
                .map_err(|_| "invalid genesis hash")?,
            claim_script: &pegin_witness[3],
            tx: &pegin_witness[4],
            merkle_proof: &pegin_witness[5],
            referenced_block: bitcoin::BlockHash::hash(&pegin_witness[5][0..80]),
        })
    }

    /// Construct a pegin witness from the pegin data.
    pub fn to_pegin_witness(&self) -> Vec<Vec<u8>> {
        vec![
            bitcoin::consensus::serialize(&self.value),
            encode::serialize(&self.asset),
            bitcoin::consensus::serialize(&self.genesis_hash),
            self.claim_script.to_vec(),
            self.tx.to_vec(),
            self.merkle_proof.to_vec(),
        ]
    }

    /// Parse the mainchain tx provided as pegin data.
    pub fn parse_tx(&self) -> Result<bitcoin::Transaction, bitcoin::consensus::encode::Error> {
        bitcoin::consensus::encode::deserialize(self.tx)
    }

    /// Parse the merkle inclusion proof provided as pegin data.
    pub fn parse_merkle_proof(&self) -> Result<bitcoin::MerkleBlock, bitcoin::consensus::encode::Error> {
        bitcoin::consensus::encode::deserialize(self.merkle_proof)
    }
}

/// A transaction input, which defines old coins to be consumed
#[derive(Clone, PartialEq, Eq, Debug, Hash)]
pub struct TxIn {
    /// The reference to the previous output that is being used an an input
    pub previous_output: OutPoint,
    /// Flag indicating that `previous_outpoint` refers to something on the main chain
    pub is_pegin: bool,
    /// The script which pushes values on the stack which will cause
    /// the referenced output's script to accept
    pub script_sig: Script,
    /// The sequence number, which suggests to miners which of two
    /// conflicting transactions should be preferred, or 0xFFFFFFFF
    /// to ignore this feature. This is generally never used since
    /// the miner behaviour cannot be enforced.
    pub sequence: Sequence,
    /// Asset issuance data
    pub asset_issuance: AssetIssuance,
    /// Witness data - not deserialized/serialized as part of a `TxIn` object
    /// (rather as part of its containing transaction, if any) but is logically
    /// part of the txin.
    pub witness: TxInWitness,
}

impl Default for TxIn {
    fn default() -> Self {
        Self {
            previous_output: Default::default(), // same as in rust-bitcoin
            is_pegin: false,
            script_sig: Script::new(),
            sequence: Sequence::MAX, // same as in rust-bitcoin
            asset_issuance: Default::default(),
            witness: Default::default()
        }
    }
}

serde_struct_impl!(TxIn, previous_output, is_pegin, script_sig, sequence, asset_issuance, witness);

impl Encodable for TxIn {
    fn consensus_encode<S: io::Write>(&self, mut s: S) -> Result<usize, encode::Error> {
        let mut ret = 0;
        let mut vout = self.previous_output.vout;
        if self.is_pegin {
            vout |= 1 << 30;
        }
        if self.has_issuance() {
            vout |= 1 << 31;
        }
        ret += self.previous_output.txid.consensus_encode(&mut s)?;
        ret += vout.consensus_encode(&mut s)?;
        ret += self.script_sig.consensus_encode(&mut s)?;
        ret += self.sequence.consensus_encode(&mut s)?;
        if self.has_issuance() {
            ret += self.asset_issuance.consensus_encode(&mut s)?;
        }
        Ok(ret)
    }
}

impl Decodable for TxIn {
    fn consensus_decode<D: io::Read>(mut d: D) -> Result<TxIn, encode::Error> {
        let mut outp = OutPoint::consensus_decode(&mut d)?;
        let script_sig = Script::consensus_decode(&mut d)?;
        let sequence = Sequence::consensus_decode(&mut d)?;
        let issuance;
        let is_pegin;
        let has_issuance;
        // Pegin/issuance flags are encoded into the high bits of `vout`, *except*
        // if vout is all 1's; this indicates a coinbase transaction
        if outp.vout == 0xffffffff {
            is_pegin = false;
            has_issuance = false;
        } else {
            is_pegin = outp.vout & (1 << 30) != 0;
            has_issuance = outp.vout & (1 << 31) != 0;
            outp.vout &= !((1 << 30) | (1 << 31));
        }
        if has_issuance {
            issuance = AssetIssuance::consensus_decode(&mut d)?;
        } else {
            issuance = AssetIssuance::default();
        }
        Ok(TxIn {
            previous_output: outp,
            is_pegin,
            script_sig,
            sequence,
            asset_issuance: issuance,
            witness: TxInWitness::default(),
        })
    }
}


impl TxIn {
    /// Whether the input is a coinbase
    pub fn is_coinbase(&self) -> bool {
        self.previous_output == OutPoint::default()
    }

    /// Whether the input is a pegin
    pub fn is_pegin(&self) -> bool {
        self.is_pegin
    }

    /// In case of a pegin input, returns the Bitcoin prevout.
    pub fn pegin_prevout(&self) -> Option<bitcoin::OutPoint> {
        if self.is_pegin {
            // here we have to cast the previous_output to a bitcoin one
            Some(bitcoin::OutPoint {
                txid: bitcoin::Txid::from(self.previous_output.txid.as_hash()),
                vout: self.previous_output.vout,
            })
        } else {
            None
        }
    }

    /// Extracts witness data from a pegin. Will return `None` if any data
    /// cannot be parsed. The combination of `is_pegin()` returning `true`
    /// and `pegin_data()` returning `None` indicates an invalid transaction.
    pub fn pegin_data(&self) -> Option<PeginData> {
        self.pegin_prevout().and_then(|p| {
            PeginData::from_pegin_witness(&self.witness.pegin_witness, p).ok()
        })
    }

    /// Helper to determine whether an input has an asset issuance attached
    pub fn has_issuance(&self) -> bool {
        !&self.asset_issuance.is_null()
    }

    /// Obtain the outpoint flag corresponding to this input
    pub fn outpoint_flag(&self) -> u8 {
        ((self.is_pegin as u8) << 6 ) | ((self.has_issuance() as u8) << 7)
    }

    /// Compute the issuance asset ids from this [`TxIn`]. This function does not check
    /// whether there is an issuance in this input. Returns (asset_id, token_id)
    pub fn issuance_ids(&self) -> (AssetId, AssetId) {
        let entropy = if self.asset_issuance.asset_blinding_nonce == ZERO_TWEAK {
            let contract_hash =
                ContractHash::from_inner(self.asset_issuance.asset_entropy);
            AssetId::generate_asset_entropy(self.previous_output, contract_hash)
        } else {
            // re-issuance
            sha256::Midstate::from_inner(self.asset_issuance.asset_entropy)
        };
        let asset_id = AssetId::from_entropy(entropy);
        let token_id =
            AssetId::reissuance_token_from_entropy(entropy, self.asset_issuance.amount.is_confidential());

        (asset_id, token_id)
    }
}

/// Transaction output witness
#[derive(Clone, Default, PartialEq, Eq, Debug, Hash)]
pub struct TxOutWitness {
    /// Surjection proof showing that the asset commitment is legitimate
    // We Box it because surjection proof internally is an array [u8; N] that
    // allocates on stack even when the surjection proof is empty
    pub surjection_proof: Option<Box<SurjectionProof>>,
    /// Rangeproof showing that the value commitment is legitimate
    // We Box it because range proof internally is an array [u8; N] that
    // allocates on stack even when the range proof is empty
    pub rangeproof: Option<Box<RangeProof>>,
}
serde_struct_impl!(TxOutWitness, surjection_proof, rangeproof);
impl_consensus_encoding!(TxOutWitness, surjection_proof, rangeproof);

impl TxOutWitness {
    /// Whether this witness is null
    pub fn is_empty(&self) -> bool {
        self.surjection_proof.is_none() && self.rangeproof.is_none()
    }

    /// The rangeproof len if is present, otherwise 0
    pub fn rangeproof_len(&self) -> usize {
        self.rangeproof.as_ref().map(|prf| prf.len()).unwrap_or(0)
    }

    /// The surjection proof len if is present, otherwise 0
    pub fn surjectionproof_len(&self) -> usize {
        self.surjection_proof.as_ref().map(|prf| prf.len()).unwrap_or(0)
    }
}

/// Information about a pegout
#[derive(Clone, PartialEq, Eq, Debug, Hash)]
pub struct PegoutData<'txo> {
    /// Amount to peg out
    pub value: u64,
    /// Asset of pegout
    pub asset: confidential::Asset,
    /// Genesis hash of the target blockchain
    pub genesis_hash: bitcoin::BlockHash,
    /// Scriptpubkey to create on the target blockchain
    pub script_pubkey: bitcoin::Script,
    /// Remaining pegout data used by some forks of Elements
    pub extra_data: Vec<&'txo [u8]>,
}

/// Transaction output
#[derive(Clone, Default, PartialEq, Eq, Debug, Hash)]
pub struct TxOut {
    /// Committed asset
    pub asset: confidential::Asset,
    /// Committed amount
    pub value: confidential::Value,
    /// Nonce (ECDH key passed to recipient)
    pub nonce: confidential::Nonce,
    /// Scriptpubkey
    pub script_pubkey: Script,
    /// Witness data - not deserialized/serialized as part of a `TxIn` object
    /// (rather as part of its containing transaction, if any) but is logically
    /// part of the txin.
    pub witness: TxOutWitness,
}
serde_struct_impl!(TxOut, asset, value, nonce, script_pubkey, witness);

impl Encodable for TxOut {
    fn consensus_encode<S: io::Write>(&self, mut s: S) -> Result<usize, encode::Error> {
        Ok(self.asset.consensus_encode(&mut s)? +
        self.value.consensus_encode(&mut s)? +
        self.nonce.consensus_encode(&mut s)? +
        self.script_pubkey.consensus_encode(&mut s)?)
    }
}

impl Decodable for TxOut {
    fn consensus_decode<D: io::Read>(mut d: D) -> Result<TxOut, encode::Error> {
        Ok(TxOut {
            asset: Decodable::consensus_decode(&mut d)?,
            value: Decodable::consensus_decode(&mut d)?,
            nonce: Decodable::consensus_decode(&mut d)?,
            script_pubkey: Decodable::consensus_decode(&mut d)?,
            witness: TxOutWitness::default(),
        })
    }
}

impl TxOut {

    /// Create a new fee output.
    pub fn new_fee(amount: u64, asset: AssetId) -> TxOut {
        TxOut {
            asset: confidential::Asset::Explicit(asset),
            value: confidential::Value::Explicit(amount),
            nonce: confidential::Nonce::Null,
            script_pubkey: Script::new(),
            witness: TxOutWitness::default(),
        }
    }

    /// Whether this data represents nulldata (OP_RETURN followed by pushes,
    /// not necessarily minimal)
    pub fn is_null_data(&self) -> bool {
        let mut iter = self.script_pubkey.instructions();
        if iter.next() == Some(Ok(Instruction::Op(opcodes::all::OP_RETURN))) {
            for push in iter {
                match push {
                    Ok(Instruction::Op(op)) if op.into_u8() > opcodes::all::OP_PUSHNUM_16.into_u8() => return false,
                    Err(_) => return false,
                    _ => {}
                }
            }
            true
        } else {
            false
        }
    }

    /// Whether this output is a pegout, which is a subset of nulldata with the
    /// following extra rules: (a) there must be at least 2 pushes, the first of
    /// which must be 32 bytes and the second of which must be nonempty; (b) all
    /// pushes must use a push opcode rather than a numeric or reserved opcode
    pub fn is_pegout(&self) -> bool {
        self.pegout_data().is_some()
    }

    /// If this output is a pegout, returns the destination genesis block,
    /// the destination script pubkey, and any additional data
    pub fn pegout_data(&self) -> Option<PegoutData> {
        // Must be NULLDATA
        if !self.is_null_data() {
            return None;
        }

        // Must have an explicit value
        let value = self.value.explicit()?;

        let mut iter = self.script_pubkey.instructions();

        iter.next(); // Skip OP_RETURN

        // Parse destination chain's genesis block
        let genesis_hash = bitcoin::BlockHash::from_slice(iter.next()?.ok()?.push_bytes()?).ok()?;

        // Parse destination scriptpubkey
        let script_pubkey = bitcoin::Script::from(iter.next()?.ok()?.push_bytes()?.to_owned());
        if script_pubkey.len() == 0 {
            return None;
        }

        // Return everything
        let mut found_non_data_push = false;
        let remainder = iter
            .filter_map(|x| if let Ok(Instruction::PushBytes(data)) = x {
                Some(data)
            } else {
                found_non_data_push = true;
                None
            })
            .collect();

        if found_non_data_push {
            None
        } else {
            Some(PegoutData {
                value,
                asset: self.asset,
                genesis_hash,
                script_pubkey,
                extra_data: remainder,
            })
        }
    }

    /// Whether or not this output is a fee output
    pub fn is_fee(&self) -> bool {
        self.script_pubkey.is_empty() && self.value.is_explicit() && self.asset.is_explicit()
    }

    /// Extracts the minimum value from the rangeproof, if there is one, or returns 0.
    pub fn minimum_value(&self) -> u64 {
        let min_value = if self.script_pubkey.is_op_return() { 0 } else { 1 };

        match self.value {
            confidential::Value::Null => min_value,
            confidential::Value::Explicit(n) => n,
            confidential::Value::Confidential(..) => {
                match &self.witness.rangeproof {
                    None => min_value,
                    Some(prf) => {
                        // inefficient, consider implementing index on rangeproof
                        let prf = prf.serialize();
                        debug_assert!(prf.len() > 10);

                        let has_nonzero_range = prf[0] & 64 == 64;
                        let has_min = prf[0] & 32 == 32;

                        if !has_min {
                            min_value
                        } else if has_nonzero_range {
                            bitcoin::consensus::deserialize::<u64>(&prf[2..10])
                                .expect("any 8 bytes is a u64")
                                .swap_bytes()  // min-value is BE
                        } else {
                            bitcoin::consensus::deserialize::<u64>(&prf[1..9])
                                .expect("any 8 bytes is a u64")
                                .swap_bytes()  // min-value is BE
                        }
                    }
                }
            }
        }
    }

    /// Returns if at least some part of this output are blinded
    pub fn is_partially_blinded(&self) -> bool {
        self.asset.is_confidential() || self.value.is_confidential() || !self.witness.is_empty()
    }
}

/// Elements transaction
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Transaction {
    /// Transaction version field (should always be 2)
    pub version: u32,
    /// Transaction locktime
    pub lock_time: PackedLockTime,
    /// Vector of inputs
    pub input: Vec<TxIn>,
    /// Vector of outputs
    pub output: Vec<TxOut>,
}
serde_struct_impl!(Transaction, version, lock_time, input, output);

impl Transaction {
    /// Whether the transaction is a coinbase tx
    pub fn is_coinbase(&self) -> bool {
        self.input.len() == 1 && self.input[0].is_coinbase()
    }

    /// Determines whether a transaction has any non-null witnesses
    pub fn has_witness(&self) -> bool {
        self.input.iter().any(|i| !i.witness.is_empty()) ||
            self.output.iter().any(|o| !o.witness.is_empty())
    }

    /// Get the "weight" of this transaction; roughly equivalent to BIP141, in that witness data is
    /// counted as 1 while non-witness data is counted as 4.
    #[deprecated(since = "0.19.1", note = "Please use `Transaction::weight` instead.")]
    pub fn get_weight(&self) -> usize {
        self.weight()
    }

    /// Get the "weight" of this transaction; roughly equivalent to BIP141, in that witness data is
    /// counted as 1 while non-witness data is counted as 4.
    pub fn weight(&self) -> usize {
        self.scaled_size(4)
    }

    /// Gets the regular byte-wise consensus-serialized size of this transaction.
    #[deprecated(since = "0.19.1", note = "Please use `Transaction::size` instead.")]
    pub fn get_size(&self) -> usize {
        self.size()
    }

    /// Gets the regular byte-wise consensus-serialized size of this transaction.
    pub fn size(&self) -> usize {
        self.scaled_size(1)
    }

    fn scaled_size(&self, scale_factor: usize) -> usize {
        let witness_flag = self.has_witness();

        let input_weight = self.input.iter().map(|input| {
            scale_factor * (
                32 + 4 + 4 + // output + nSequence
                VarInt(input.script_sig.len() as u64).len() as usize +
                input.script_sig.len() + if input.has_issuance() {
                    64 +
                    input.asset_issuance.amount.encoded_length() +
                    input.asset_issuance.inflation_keys.encoded_length()
                } else {
                    0
                }
            ) + if witness_flag {
                let amt_prf_len = input.witness.amount_rangeproof.as_ref()
                    .map(|x| x.len()).unwrap_or(0);
                let keys_prf_len = input.witness.inflation_keys_rangeproof.as_ref()
                    .map(|x| x.len()).unwrap_or(0);

                VarInt(amt_prf_len as u64).len() as usize +
                amt_prf_len +
                VarInt(keys_prf_len as u64).len() as usize +
                keys_prf_len +
                VarInt(input.witness.script_witness.len() as u64).len() as usize +
                input.witness.script_witness.iter().map(|wit|
                    VarInt(wit.len() as u64).len() as usize +
                    wit.len()
                ).sum::<usize>() +
                VarInt(input.witness.pegin_witness.len() as u64).len() as usize +
                input.witness.pegin_witness.iter().map(|wit|
                    VarInt(wit.len() as u64).len() as usize +
                    wit.len()
                ).sum::<usize>()
            } else {
                0
            }
        }).sum::<usize>();

        let output_weight = self.output.iter().map(|output| {
            scale_factor * (
                output.asset.encoded_length() +
                output.value.encoded_length() +
                output.nonce.encoded_length() +
                VarInt(output.script_pubkey.len() as u64).len() as usize +
                output.script_pubkey.len()
            ) + if witness_flag {
                let range_prf_len = output.witness.rangeproof_len();
                let surj_prf_len = output.witness.surjectionproof_len();
                VarInt(surj_prf_len as u64).len() as usize +
                surj_prf_len +
                VarInt(range_prf_len as u64).len() as usize +
                range_prf_len
            } else {
                0
            }
        }).sum::<usize>();

        scale_factor * (
            4 + // version
            4 + // locktime
            VarInt(self.input.len() as u64).len() as usize +
            VarInt(self.output.len() as u64).len() as usize +
            1 // segwit flag byte (note this is *not* witness data in Elements)
        ) + input_weight + output_weight
    }

    /// The txid of the transaction.
    pub fn txid(&self) -> Txid {
        let mut enc = Txid::engine();
        self.version.consensus_encode(&mut enc).unwrap();
        0u8.consensus_encode(&mut enc).unwrap();
        self.input.consensus_encode(&mut enc).unwrap();
        self.output.consensus_encode(&mut enc).unwrap();
        self.lock_time.consensus_encode(&mut enc).unwrap();
        Txid::from_engine(enc)
    }

    /// Get the witness txid of the transaction.
    pub fn wtxid(&self) -> Wtxid {
        let mut enc = Txid::engine();
        self.consensus_encode(&mut enc).unwrap();
        Wtxid::from_engine(enc)
    }

    /// Get the total transaction fee in the given asset.
    pub fn fee_in(&self, asset: AssetId) -> u64 {
        // is_fee checks for explicit asset and value, so we can unwrap them here.
        self.output.iter()
            .filter(|o| o.is_fee() && o.asset.explicit().expect("is_fee") == asset)
            .map(|o| o.value.explicit().expect("is_fee"))
            .sum()
    }

    /// Get all fees in all assets.
    pub fn all_fees(&self) -> HashMap<AssetId, u64> {
        let mut fees = HashMap::new();
        for out in self.output.iter().filter(|o| o.is_fee()) {
            // is_fee checks for explicit asset and value, so we can unwrap them here.
            let asset = out.asset.explicit().expect("is_fee");
            let entry = fees.entry(asset).or_insert(0);
            *entry += out.value.explicit().expect("is_fee");
        }
        fees
    }
}

impl Encodable for Sequence {
    fn consensus_encode<W: io::Write>(&self, w: W) -> Result<usize, encode::Error> {
        self.0.consensus_encode(w)
    }
}

impl Decodable for Sequence {
    fn consensus_decode<R: io::Read>(r: R) -> Result<Self, encode::Error> {
        Decodable::consensus_decode(r).map(Sequence)
    }
}

impl Encodable for Transaction {
    fn consensus_encode<S: io::Write>(&self, mut s: S) -> Result<usize, encode::Error> {
        let mut ret = 0;
        ret += self.version.consensus_encode(&mut s)?;

        let wit_flag = self.has_witness();
        if wit_flag {
            ret += 1u8.consensus_encode(&mut s)?;
        } else {
            ret += 0u8.consensus_encode(&mut s)?;
        }
        ret += self.input.consensus_encode(&mut s)?;
        ret += self.output.consensus_encode(&mut s)?;
        ret += self.lock_time.consensus_encode(&mut s)?;

        if wit_flag {
            for i in &self.input {
                ret += i.witness.consensus_encode(&mut s)?;
            }
            for o in &self.output {
                ret += o.witness.consensus_encode(&mut s)?;
            }
        }
        Ok(ret)
    }
}

impl Decodable for Transaction {
    fn consensus_decode<D: io::Read>(mut d: D) -> Result<Transaction, encode::Error> {
        let version = u32::consensus_decode(&mut d)?;
        let wit_flag = u8::consensus_decode(&mut d)?;
        let mut input = Vec::<TxIn>::consensus_decode(&mut d)?;
        let mut output = Vec::<TxOut>::consensus_decode(&mut d)?;
        let lock_time = PackedLockTime::consensus_decode(&mut d)?;

        match wit_flag {
            0 => Ok(Transaction {
                version,
                lock_time,
                input,
                output,
            }),
            1 => {
                for i in &mut input {
                    i.witness = Decodable::consensus_decode(&mut d)?;
                }
                for o in &mut output {
                    o.witness = Decodable::consensus_decode(&mut d)?;
                }
                if input.iter().all(|input| input.witness.is_empty()) &&
                    output.iter().all(|output| output.witness.is_empty()) {
                    Err(encode::Error::ParseFailed("witness flag set but no witnesses were given"))
                } else {
                    Ok(Transaction {
                        version,
                        lock_time,
                        input,
                        output,
                    })
                }
            }
            _ => Err(encode::Error::ParseFailed("bad witness flag in tx")),
        }
    }
}
/// Hashtype of a transaction, encoded in the last byte of a signature
/// Fixed values so they can be casted as integer types for encoding
#[derive(PartialEq, Eq, Debug, Copy, Clone)]
pub enum EcdsaSigHashType {
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
}

serde_string_impl!(EcdsaSigHashType, "a EcdsaSigHashType data");

impl fmt::Display for EcdsaSigHashType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            EcdsaSigHashType::All => "SIGHASH_ALL",
            EcdsaSigHashType::None => "SIGHASH_NONE",
            EcdsaSigHashType::Single => "SIGHASH_SINGLE",
            EcdsaSigHashType::AllPlusAnyoneCanPay => "SIGHASH_ALL|SIGHASH_ANYONECANPAY",
            EcdsaSigHashType::NonePlusAnyoneCanPay => "SIGHASH_NONE|SIGHASH_ANYONECANPAY",
            EcdsaSigHashType::SinglePlusAnyoneCanPay => "SIGHASH_SINGLE|SIGHASH_ANYONECANPAY",
        };
        f.write_str(s)
    }
}

impl str::FromStr for EcdsaSigHashType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.as_ref() {
            "SIGHASH_ALL" => Ok(EcdsaSigHashType::All),
            "SIGHASH_NONE" => Ok(EcdsaSigHashType::None),
            "SIGHASH_SINGLE" => Ok(EcdsaSigHashType::Single),
            "SIGHASH_ALL|SIGHASH_ANYONECANPAY" => Ok(EcdsaSigHashType::AllPlusAnyoneCanPay),
            "SIGHASH_NONE|SIGHASH_ANYONECANPAY" => Ok(EcdsaSigHashType::NonePlusAnyoneCanPay),
            "SIGHASH_SINGLE|SIGHASH_ANYONECANPAY" => Ok(EcdsaSigHashType::SinglePlusAnyoneCanPay),
            _ => Err("can't recognize SIGHASH string".to_string())
        }
    }
}

impl EcdsaSigHashType {
    /// Break the sighash flag into the "real" sighash flag and the ANYONECANPAY boolean
    pub(crate) fn split_anyonecanpay_flag(self) -> (EcdsaSigHashType, bool) {
        match self {
            EcdsaSigHashType::All => (EcdsaSigHashType::All, false),
            EcdsaSigHashType::None => (EcdsaSigHashType::None, false),
            EcdsaSigHashType::Single => (EcdsaSigHashType::Single, false),
            EcdsaSigHashType::AllPlusAnyoneCanPay => (EcdsaSigHashType::All, true),
            EcdsaSigHashType::NonePlusAnyoneCanPay => (EcdsaSigHashType::None, true),
            EcdsaSigHashType::SinglePlusAnyoneCanPay => (EcdsaSigHashType::Single, true),
        }
    }

    /// Reads a 4-byte uint32 as a sighash type
    pub fn from_u32(n: u32) -> EcdsaSigHashType {
        match n & 0x9f {
            // "real" sighashes
            0x01 => EcdsaSigHashType::All,
            0x02 => EcdsaSigHashType::None,
            0x03 => EcdsaSigHashType::Single,
            0x81 => EcdsaSigHashType::AllPlusAnyoneCanPay,
            0x82 => EcdsaSigHashType::NonePlusAnyoneCanPay,
            0x83 => EcdsaSigHashType::SinglePlusAnyoneCanPay,
            // catchalls
            x if x & 0x80 == 0x80 => EcdsaSigHashType::AllPlusAnyoneCanPay,
            _ => EcdsaSigHashType::All,
        }
    }

    /// Converts to a u32
    pub fn as_u32(self) -> u32 {
        self as u32
    }

    /// Creates a [`SigHashType`] from a raw `u32`.
    ///
    /// # Errors
    ///
    /// If `n` is a non-standard sighash value.
    pub fn from_standard(n: u32) -> Result<EcdsaSigHashType, NonStandardSighashType> {
        match n {
            // Standard sighashes, see https://github.com/bitcoin/bitcoin/blob/b805dbb0b9c90dadef0424e5b3bf86ac308e103e/src/script/interpreter.cpp#L189-L198
            0x01 => Ok(EcdsaSigHashType::All),
            0x02 => Ok(EcdsaSigHashType::None),
            0x03 => Ok(EcdsaSigHashType::Single),
            0x81 => Ok(EcdsaSigHashType::AllPlusAnyoneCanPay),
            0x82 => Ok(EcdsaSigHashType::NonePlusAnyoneCanPay),
            0x83 => Ok(EcdsaSigHashType::SinglePlusAnyoneCanPay),
            non_standard => Err(NonStandardSighashType(non_standard))
        }
    }
}

/// This type is consensus valid but an input including it would prevent the transaction from
/// being relayed on today's Bitcoin network.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NonStandardSighashType(pub u32);

impl fmt::Display for NonStandardSighashType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Non standard sighash type {}", self.0)
    }
}

impl std::error::Error for NonStandardSighashType {}

/// Error returned for failure during parsing one of the sighash types.
///
/// This is currently returned for unrecognized sighash strings.
#[derive(Debug, Clone)]
pub struct SighashTypeParseError {
    /// The unrecognized string we attempted to parse.
    pub unrecognized: String,
}

impl fmt::Display for SighashTypeParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Unrecognized SIGHASH string '{}'", self.unrecognized)
    }
}

impl ::std::error::Error for SighashTypeParseError {}

#[cfg(test)]
mod tests {
    use bitcoin;
    use bitcoin::hashes::hex::FromHex;

    use crate::encode::serialize;
    use crate::confidential;
    use secp256k1_zkp::{self, ZERO_TWEAK};
    use crate::script;

    use super::*;

    #[test]
    fn outpoint() {
        let txid = "d0a5c455ea7221dead9513596d2f97c09943bad81a386fe61a14a6cda060e422";
        let s = format!("{}:42", txid);
        let expected = OutPoint::new(Txid::from_hex(&txid).unwrap(), 42);
        let op = ::std::str::FromStr::from_str(&s).ok();
        assert_eq!(op, Some(expected));
        // roundtrip with elements prefix
        let op = ::std::str::FromStr::from_str(&expected.to_string()).ok();
        assert_eq!(op, Some(expected));
    }

    #[test]
    fn test_fees() {
        let asset1: AssetId = "0000000000000000000000000000000000000000000000000000000000000011".parse().unwrap();
        let asset2: AssetId = "0000000000000000000000000000000000000000000000000000000000000022".parse().unwrap();

        let fee1 = TxOut::new_fee(42, asset1);
        assert!(fee1.is_fee());
        let fee2 = TxOut::new_fee(24, asset2);
        assert!(fee2.is_fee());

        let tx = Transaction {
            version: 0,
            lock_time: PackedLockTime::ZERO,
            input: vec![],
            output: vec![fee1, fee2],
        };

        assert_eq!(tx.fee_in(asset1), 42);
        assert_eq!(tx.fee_in(asset2), 24);
        let all_fees = tx.all_fees();
        assert_eq!(all_fees.len(), 2);
        assert_eq!(all_fees[&asset1], 42);
        assert_eq!(all_fees[&asset2], 24);
    }

    #[test]
    fn transaction() {
        // Simple transaction with explicit input (no scriptsig/witness) and explicit outputs
        let tx: Transaction = hex_deserialize!(
            "020000000001eb04b68e9a26d116046c76e8ff47332fb71dda90ff4bef5370f2\
             5226d3bc09fc0000000000feffffff0201230f4f5d4b7c6fa845806ee4f67713\
             459e1b69e8e60fcee2e4940c7a0d5de1b20100000002540bd71c001976a91448\
             633e2c0ee9495dd3f9c43732c47f4702a362c888ac01230f4f5d4b7c6fa84580\
             6ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b2010000000000000ce400\
             0000000000"
        );

        assert_eq!(
            tx.wtxid().to_string(),
            "758f784bdfa89b62c8b882542afb46074d3851a6da997199bcfb7cc6daed3cf2"
        );
        assert_eq!(
            tx.txid().to_string(),
            "758f784bdfa89b62c8b882542afb46074d3851a6da997199bcfb7cc6daed3cf2"
        );
        assert_eq!(tx.input.len(), 1);
        assert_eq!(tx.output.len(), 2);
        assert_eq!(tx.size(), serialize(&tx).len());
        assert_eq!(tx.weight(), tx.size() * 4);
        assert_eq!(tx.output[0].is_fee(), false);
        assert_eq!(tx.output[1].is_fee(), true);
        assert_eq!(tx.output[0].value, confidential::Value::Explicit(9999996700));
        assert_eq!(tx.output[1].value, confidential::Value::Explicit(      3300));
        assert_eq!(tx.output[0].minimum_value(), 9999996700);
        assert_eq!(tx.output[1].minimum_value(),       3300);
        let fee_asset = "b2e15d0d7a0c94e4e2ce0fe6e8691b9e451377f6e46e8045a86f7c4b5d4f0f23".parse().unwrap();
        assert_eq!(tx.fee_in(fee_asset), 3300);
        assert_eq!(tx.all_fees()[&fee_asset], 3300);

        // CT transaction with explicit input (with script witness) and confidential outputs
        let tx: Transaction = hex_deserialize!(
            "020000000101f23ceddac67cfbbc997199daa651384d0746fb2a5482b8c8629b\
             a8df4b788f75000000006b483045022100e0feb3e2f292000d67e24b821d87c9\
             532230dac1de428d6a0068c9f416583abf02200e76f072788dd411b2327267cd\
             91c6b1659809598cd4fae35be475efe1e4bbad01210201e15c23c021652d07c1\
             557b607ea0379fca0462aca840d6c33c4d4927524547feffffff030b60424a42\
             3335923c15ae387d95d4f80d944722020bfa55b9f0a0e67579e3c13c081c4f21\
             5239c77456d121eb73bd9914a9a6398fe369b4eb8f88a5f78e257fcaa303301e\
             e46349950886ae115c9556607fcda9381c2f72368f4b5286488c62aa0b081976\
             a9148bb6c4d5814d43fefb9e330575e326632136389c88ac0bd436b0539f5497\
             af792d7cb281f09b73d8a5abc198b3ce6239d79e68893e5e5d0923899fd35071\
             ba8a209d85b556d5747b6c35539c3b2f8631a27c0d477a1f45a603d1d350b8cb\
             f900f7666da66541bf6252fc4c162141ad49c670884c93c57db6ba1976a9148c\
             7ab6e0fca387d03643d4846f708bf39d47c1e988ac01230f4f5d4b7c6fa84580\
             6ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b2010000000000008e8000\
             00000000000000000043010001dc65ae13f76fde4a7172e0fb380b1a5cc8dc88\
             eaa0659e638a25eac8ae30d79bf93eb7e487eeee323e4ac8e3a2fe6523bdeba6\
             acce32b9b085f2286174c04655fd6c0a6020000000000000000178ad016b3e5d\
             8165423e56d8b37e3eaee96009b2f970043ccf65d61b5c3c1e1ef343e0c479bd\
             ba442717dc861c9591566010240b9d4607efb9252a5fcef05edf640e0bb6b606\
             729246ad07baa49d0d3b52042c65a03ca737744e45b2d2d6d177c36569ae9d6e\
             b4437305b169bbc59f85cabff3bc49a2d6d08c177cce3121a509d3c47961bd22\
             e35c932b79d4ec5ccaf913fac04034bfebdadbc4ff3127af96344b02ee6b967b\
             b08326cbe6a4e1c924485e64a8c0fdf70b98c99f38acaa15aa0adb2b5b7335ed\
             5502443891bcd657310347cbd928f40f38f1dec087a2b947c9cf7d304798f77b\
             bc4a2c843796b2d49acce91de4e88a0a9c261277df28ffc3320d7f7d64790f59\
             2ddded48a1068ef88271395fa5606389ef90856ddd6bd6710a8d27e0147983b5\
             dde2a7efae44e83ad02a3c3da04be43d5f2c05c205f1e17b48554c2177670f46\
             dbb6600bd2e6c75dd5ea2e1072c5f22483dcf05d8124e3f9063a5ddb179a29c2\
             3a2d15d6e89f2192f03dae5938f66fcdcff000c5a96ffd2920f23881880af721\
             53c96a56dd80c218bb48b44a18e54a8050ff32c869c1264ee574cdb4002f86e0\
             779c724d11dc4a768dbec1bd22054886f1fdf2e7347e4c247b829159d1375f88\
             1c6ce0a5c4da8534000e7fec3a980afb1edc99b725c29de80f260dcf144c873b\
             f589ae1812ef6cb05f2234f9c66c23e874a0d5d0dc52f2209e015bbcf74ee449\
             a397f6b0318c915b7e58dea5904abbe35285e90ccf548ad1f3f52f60c3b19b3c\
             d67644d633e68aef42d8ef1782f22a8edd0620f55f29070720ca7a078ac83e87\
             b9ebd2783ecad17dd854ef1bbd319f1a6d3a1e4931f9097422f5a3c4af037b99\
             e06c7610ee61102c6eea763af108e9a16b93b2dc0891658d5c6a197df6aae9b3\
             06b2c895d21c79cb6cb6dd85b4018b0a9fe7468336e3907eb4adcaf930cacc97\
             e8e951d2d6b25744a4143679bad1f31b210c9a2ed54b80d8f5d7dc1f1c985681\
             534c1926920cd683d95dca7e8ea285f9906d2e89cd8bfa76a98e38ee4b515252\
             2d55f79610fe8d5278fe6ed5866b5da4dcf330ea84307c34f30e1a66eb1934da\
             febb0074fc27c2ff73d8c0bae8416cc87bf611f81119aba9e2a911beaf3ac950\
             7e621fc1ed1cf15dfb31408cf55e2bfdd2880db2d3489a336d6f8348347648d8\
             82f9f376331e469e809115c6cc82468f363c910673e9ded172ded90a369e1cdd\
             135676f623e11a1531ed221177812b1ef0c65e5ca92c0df8de7fe664710f3228\
             a226e019c99607fe1395ecd5643e1c7ad8a132bf5131737cb970a7f0dabc0002\
             9755bf71b3f47bd69ba39b3ab104c74f04239f4919dca1dfce7c9c41cba9d449\
             073e106ebabe3c313b598ee8b11702ec46e9ee53fb9422f0326371898b8fa4c2\
             1a951684c687398e0bebd6f6fd91b829e8666b9a19a4273cfda0f34b8ecb902f\
             7adc6539fb9a0cba6f87a63a957acfb2dfa18973f4a3063668767b2be7803115\
             13c63f1814f082176f6a953f2ffaa49ec9b39fecc2eab603be7a969bb4c1dbeb\
             f8d39fa90f802d5ea52378b5025a19b64a8c2c2dd6a6133bd8d29730bd5724b5\
             bf50c158b238d1137082937ad91a176aaf91577868db7581b457c917e612b242\
             ce0065ad47e11dcdc1fc6158687142249bcf312497a547b6f43e795af7d4ae8c\
             d022e44e417987e35e83de21e39dcdf86b97bd421e6e61881a432fa2284f20be\
             80e32459443736b875d9036468ceb881589394441e2d10aa10b6c93332951e8b\
             a56f89fac70baf415b4511873c0f3e418ca4fe8954a28f1f7b5f590d34470119\
             f694e2712f184882d90396c8e6aa850eaa3c2ae51990543638c46c59512167a2\
             c5ad593532dc2142ffb6560476e4159213b9ef017ec75310d2e4624a405bb26f\
             7192a485a94890674928c9caa4a5819ca4ddcba8fa71afc1a6baf63f039452c8\
             fe994f8b63d58c876dfddd61a476345eaed4f66bdc0fcfc38d485c6a5b0e27d0\
             fbc50427ff591ba38d63445c01642cfbd7d4c032f2546a6fe80bc3b598362502\
             c552049523fe360c3bcf1cc572feb04386f97d55871dd8cea0393cdd964e7240\
             82adc98126e6f2fe1d576be4bf911e9aca70e35538175f8382bbcd614bbecc97\
             c9607ef25da2ff08a6e5b6f76cbe9ccb0e0fdc3528e3e2c3675a5c897d295bb7\
             6524ec8a73a70b97909368f44d92f9aceaef0b03f3dafa1faa89fc663a92da3c\
             19b4952463fac0e825e78cf046e266cfb9975af72e9d50d2c2cafee88fe2ceca\
             e2b1465fc07b280d83b66062dc9e7a372f81aec8e0bb9e97877814a5a6813c67\
             746e35cd068d45d8664528bd00d5a306a5319e1bea7f38345da92d3a10d91476\
             a26aed6b8441f0f72fbbad5d5e0f8ae5cabc9f4f08e6be7902b5c53632db5264\
             afee7422c87b3237a32d5213ad0eb807b61977d9d90666cbb0c70500526b0eb7\
             62c99351796db41166b0aa2f221b5607e0d629fac4e938488245c11557381a4f\
             8addcc49913b11d42481cf8668e37bacbad4a20509e4fe4ccbcee7aea2909a2a\
             be59052f7f28b9340cd92f69729d615b8d3b530941c0b30506498cd4e561a9c8\
             2d915266bb7115967bc76c5593c06d094bdf4294b868afc5fa52742d3bdbd593\
             2df599f0e1187c49f0dba8679c771a514cc9da75e03506957800bf470d4a07c4\
             bb8918d6085499bb8ceeaba23c0b465863327e9ab8b6b8cf8b3ca530ca7b02cf\
             adf85437b750f305e8fbc8855c95bee8595a7e9e1f0993a03adbadc68665a189\
             36cc99b6530b4518c0754990d7bfdfdac76f88cfcbcb7b3d9a71ee10cbd3a1bd\
             bc2e50b642c1fef56511962f845bbec6eab727b1d4add335db8d80c4c07e8356\
             ad05adad68b012489fa5bb5d9019a667778ddf7f5edd80f1d3c4abd64397a89e\
             554c8007809336ddc2b2e7d5219c39fdf39aad33b9350f6b18fe3b98c690b906\
             8f36d4b7669530fd216373842fbf70fe9bbe80854b31eed4bd515d6caeb065d6\
             c609846c9bfae1b3fce3db70b5bfb448ec69512e7f25019c789301b77a75f2a0\
             f81c65ec29f41bf96d597a00c310e8ba4b48ac82b5a735c1e83f22394eb2fc9b\
             35d42a35533c938f26290a5860175637982f1733c99be39c44ac4a0918740630\
             6bde2fd3d28e4e7bda73719912c338804dea03987757dac4d73def665e11da12\
             6f9414f71624a3b753797eb0472bd334094515c4f9fe57fdd8d185f22b4bf82e\
             4b5f6b800870cce19a0c8174dc11ee9f1cb9ffe0ac6f6fff1ebf7c915c7ae201\
             72bb70390e3759912e0e0a4e83a0a2d2318f4386314a89f6438ccb331f89377f\
             f7947fe4b24f788aef85c1656ca87ee41c959f1b09bde09f20c2a51ac481646b\
             28e9b0fc2ff49cfe8cf28577bf5bf6f261f54f97fcd2875da4210c6dfe685450\
             280b68e378d9a486243cc682ed4ec747c37de1fde848e4a8f70498d22e40c462\
             c469c884cd67330e77b694e759232313f31a1624e0e1960f23ddae47b68ff553\
             d0de0910c8abe2e8e5fb063aa744ff77465fc731c7af79a84dcaa9b3f741a46d\
             d3c932877d49242c6d883e14392b8c4530986605812b636a73590ef437f27e40\
             d1af37ed1cbd68fb4e9ca5b0b41e5daee0142c1bf59c9d71f6c19b25e6148dfb\
             b9fb142107aabe3701e36611a7e0b13ea32d3c5f8a51f63c5f34415baa15f6ca\
             77300eb323241ffe73c5acd97fcb682c21dc8911392979e9cb81be5218acf452\
             b5b93f6681d323b7989fdd10efe6fe9e2ac88d0d76a4cf3ee45e3b5c43010001\
             4142c1fc7e8a658eff437594a25cf34d269556d8511918f27fdc7e9d6dd73f0e\
             4790b91f225e9d131e6abb3dbfb66549a9aa57948fbd2f183fcd951b1d2305bf\
             fd6c0a602000000000000000016f5cdf9fb6c1b5e98a36befdc2c55bd4fd8793\
             d554b2506f51c909362495e1216ee83cd270ddb0a00785600ba23bd3363f0798\
             e3a7a117990415adec88e61be65170bd587ab4d2ee38edb22a91e5c29afa397d\
             d5a73465c51c6263f5fbde47fa801ce84464acc32589acaafadfe44d6558774b\
             7085612a88f3424b6dca3c6f07217d1cbd5c41bda46a6a492a0119c1de4d25b5\
             8c94250bee3fba6b8223777535673a2f4da6af27598030f88144f408120f07ca\
             9c98d5d9edcdf6cdc9073f118fce55e6c9d0be80b5e87992ddaa9c22053b3a00\
             d42bdedc9768de25c0b37a5c4fb4e86710b33cebed5588d88adde607f6bca14f\
             0279ce35126d403ffa50f288c87f528c19749ed43bd846c513fcd92c173fe76d\
             8f2e69770439d3d075cb19b1094a42ee07ae1de197e8c136e2bc688a75a74db2\
             4adb0fbb73872dc80074f61c9cce9bd33861bdd921ee3edacab1d6e7cec325c1\
             72b6b6e82ada11687e4fc931225074dd1f20a0f9342dbce1fc3fdbf5bb6cb74a\
             b6475e574e9f5f247a2f7e4fcfcc354d4da8c8066e574642c7fccbbb9ef0aa59\
             2ecab5366fe87eb8e14cd64aee34578aa48f68f8f4c5372df2c3fc429f5a3e39\
             ef6c034c87f9c52b2ea35e28c7bf3be737c3817efd6569466dc859e8ff8965c5\
             249b6f045934d3d08b0ffd388aec58df8194ac2c4fec2152942d2626595e6566\
             4b1fa33b5dae8ee796a840a56d885cbf7ae6483fad05e507ada3f075ebce0d79\
             1b626c6dfe93f8492c4dd3b34aafc33d7644c5c8e38bfd8c19194f65be88fcb4\
             538778632e489a626896372fdd2498b16e64daa7d3c5cfac688d6f9cdf371726\
             1b0a1f25be1bdd6be6558ddb826fa04b5f668810a291aea51a6f05ff7c34dcf8\
             1c74849a8015bad5e4e416989b10ef01de304775db725fa0b665f4330dc9c540\
             dc29aab144837362a97d6bb0165cb3272338c2d32386cd95ee3e66d876b591a2\
             5a6907237523cf908f736d2fdc8e54ea8d9c7562697161d1f72fc4d7b7750524\
             15cd0e5ae5bdf6edfab5776b6ff75ce5e1f8f2beea6ec74252b63966cca58abd\
             638279dc5c998a1068079f3e5dcc8a69165c304c3d8c362ccfadab05ad12208a\
             5655ab389eb727e8ed5f86b300331a13be26e2fbabf89fbfd2b98481dd5edb52\
             ed456a0e03a84b6f89761f91ff251412f5cfa286e35fb9f48ef0e044c4742b6e\
             860a08767ecb80548c2f3df3b371cdb40e86dbe118f64e84faf45ecb78d73364\
             e9e31e3412ca2a3fad0a35983370ea9e6264a222edd1fd4aca30e3c169d7ca2d\
             07609262e786ecd019c1417a06b7dfa32a54e0897afdc6492f26611555cbff47\
             dba3b76381f239d597a8f687669333e0b47b53d5bcc4fea1919490bad3c6f0b6\
             a58a50aca7ddeb9745ead454e0a38d9486fb52aefe0dbb92bf7fd6c215078aba\
             3482b11274ec8cddff92c359bbc6d20bd823ad0bbf859cfaadf8e775b3d37b30\
             78319f46c6d2a112cf60a673fee467538c70f1687d97fbe9d9f8a0856061592a\
             4e00b6d10e979e674dd2cd0ba8b853f733877cd508062d5f723d58d215ad69c2\
             be6be742496aef54eb87338622eb36a9bbc5a7a602d280a45e095b1e078dab54\
             479e783a513c722066acaae44ccc15f9560da91ed053ec05c36d82f680976687\
             6c45c4fbeb2321d50f48f7995437d0c5fc365974a571fb0352d28cb1cdbd21d6\
             9fab576a2e68d6b881776027bcdb7f01be22b1c847d91f26e680ef6ab2c128a8\
             9b59432383d9bd661b0b01432cf8a25319426d38ac2e2114825f59b4250569c7\
             98b1094920bb31130728313ff56a6eef2e6c4b275215dce3786d0f9024952b5f\
             572566c53597e7ef4ab1f75743e605a564054d667f48906b5481d924769ef657\
             51e349891d725a2c1bf8b102fea4c25c874d2fc2ce1bfec4b39bea76fbf7a288\
             55725d52b595a4fc96892c3f1f961d46310ebd5221df729c02060035c559baf0\
             fd7efa73a2213ca29642857aeb8ebf7efdf9d2f5c84746b6fc35ab355a8dca56\
             e7dde4831e47ca1be6b62af30cfcf807c384e56ab84ff03bbe786251e6c4b932\
             c9217bf671046217bd0511fdc06aa69050c1480281e4843eb73d80095a2fb8e6\
             8a2c0c98c9aea637b99d87ad847a3a76d59ea308c751f9cb4a4fce2989822bd6\
             ba2f901f09df647536dc30730ea3160dd35b8c6dcc9aa815b79ed492a8a299a2\
             98ccdf784b9b0211ca877ec1723817c98529acaa4d3727162b5740b0fc9b498d\
             fb2212a3cbf0c63dc4f7663fafad7905643a792862b651e8497b0f0da632b897\
             ecf9ee63f2b20b54fa5eb2f2e424dcce5a075f50b856af266655be3a815fc83e\
             d8027508b2536976982196b160e2219ffdb5c7a56dd3e6b700860c711f4439db\
             f72973f4f26fe3260ec43a3446fe14444b9787d877e107be610147eec4a35747\
             45e95a1f424aff062f84c559d13b1e6b59e8dc2221515c229f07db8eb39c515a\
             321d8bd07b1bd6c9a79dac6d951c04415553c7a2ce1eb77495c7f89c4d5b4cff\
             d289435b69bc53585095083cc5a1b191781342266e204e1566aca8175e2ae84a\
             8bd711d188b666dfb65a6442776d3e23c1b5192af09ec712537f2157d0ccbc1b\
             b3b3a1969d9705671f16bdc266e615ad2e50a8cbd666f3ee7465cc430c6cd69d\
             30c91e717b12f7094b6f0ef89134d6c1620d28d8f238c181146448b348e4ca2e\
             93c737210350f18fb878fb91b70ecc5689e5b6101ecfc545f6a1c903115b0c64\
             19c91a50fb2dbe2edd362f2815f0c75070974507c34130ac9b29747ff7efbe6e\
             37ee4c62be3ecfedfa817fdf3309163aaff677775b77f0d288c9858cfe59cb0f\
             a18afa591e7d574eaef43c82e79d71542c4177de4e5bd724b18cfd33c6853066\
             5728a9d5ef192772094acbf3d885d5146c1634e74754e3fbcb94fa349eac8280\
             cfd7d1f46a0813b57a83bd078b1f7cb5a60a59b59380fe04e1c600c33b33d1ad\
             d69a9ff1be546f0ec5c0083979fce940b23711f382ac0d011c1103f02cb6082c\
             18e39cf7a9c3bf4c081f905ae7b87951a7880b57e934465ccd634e5a17fd8d88\
             66abfdfebd33b2c3d2c5be58144900c04e9c18de0c80270660e62a3c18527755\
             5f89da4c41bd33cec1359f4ed21abdb586e1d97f720a92d16014d7f1822f1836\
             f74c97cb7f7b38e073477c6ab064fde835916c1e624de81f2ad90f6260073c5e\
             1848582860f033630bde225821b39c2572b30c36adf8fdb8317c33df05f64134\
             47f4985d12e9012629df09dc8f43373a6d0db4b0048453a6f1ec662472c77a30\
             d5cf4ac7084f736d0d598c251f2aefc986052fbf12a657885d7140ad36b07c63\
             ab86388a2be12d943747f3f29ef9f2e11e1444cc873df0ed7826eef675389a0d\
             5a0388a8504fe89c4791ea4a572bfd406d5f01418b4f888c9a7a566e32811936\
             bf6950bbf786b86c41c28f2045d31953fcd15f179e7bc00c72870890537921f7\
             deff82270b0e44b88720aa738f60a85567deb7c90b0c2444467621e53e1c0794\
             36d31d3d0b34dd237fc281eb9d87175237a9a433142db4bb7f8c4cb6a34e2dc7\
             3f074045d216695ce88ef68e18564c935c9cbd902e939655c258de2ab78def87\
             46bffd972083afce3b6881b7147262e1a44e0224689fafa1a3cb823c8da6eb7d\
             f091bec0638bf728b7b10aa95f2bce512ec8d3252938d2eb77b44ace7a2f9765\
             88032cac5af670f9e5ca25cb0721bc1baec26f9c3a9f41b02fb62997d6cb0a01\
             314845e9d0e78139ea49f2ead8736e0000"
        );

        assert_eq!(
            tx.wtxid().to_string(),
            "7ac6c1400003162ab667406221656f06dad902c70f96ee703f3f5f9f09df4bb9"
        );
        assert_eq!(
            tx.txid().to_string(),
            "d606b563122409191e3b114a41d5611332dc58237ad5d2dccded302664fd56c4"
        );
        assert_eq!(tx.size(), serialize(&tx).len());
        assert_eq!(tx.weight(), 7296);
        assert_eq!(tx.input.len(), 1);
        assert_eq!(tx.input[0].is_coinbase(), false);
        assert_eq!(tx.is_coinbase(), false);

        assert_eq!(tx.output.len(), 3);
        assert_eq!(tx.output[0].is_fee(), false);
        assert_eq!(tx.output[1].is_fee(), false);
        assert_eq!(tx.output[2].is_fee(), true);

        assert_eq!(tx.output[0].minimum_value(), 1);
        assert_eq!(tx.output[1].minimum_value(), 1);
        assert_eq!(tx.output[2].minimum_value(), 36480);

        assert_eq!(tx.output[0].is_null_data(), false);
        assert_eq!(tx.output[1].is_null_data(), false);
        assert_eq!(tx.output[2].is_null_data(), false);

        let fee_asset = "b2e15d0d7a0c94e4e2ce0fe6e8691b9e451377f6e46e8045a86f7c4b5d4f0f23".parse().unwrap();
        assert_eq!(tx.fee_in(fee_asset), 36480);
        assert_eq!(tx.all_fees()[&fee_asset], 36480);

        // Coinbase tx
        let tx: Transaction = hex_deserialize!(
            "0200000001010000000000000000000000000000000000000000000000000000\
             000000000000ffffffff03520101ffffffff0201230f4f5d4b7c6fa845806ee4\
             f67713459e1b69e8e60fcee2e4940c7a0d5de1b201000000000000000000016a\
             01230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1\
             b201000000000000000000266a24aa21a9ed94f15ed3a62165e4a0b99699cc28\
             b48e19cb5bc1b1f47155db62d63f1e047d450000000000000120000000000000\
             00000000000000000000000000000000000000000000000000000000000000"
        );

        assert_eq!(
            tx.wtxid().to_string(),
            "69e214ecad13b954208084572a6dedc264a016b953d71901f5aa1706d5f4916a"
        );
        assert_eq!(
            tx.txid().to_string(),
            "cc1f895908af2509e55719e662acf4a50ca4dcf0454edd718459241745e2b0aa"
        );
        assert_eq!(tx.input.len(), 1);
        assert_eq!(tx.size(), serialize(&tx).len());
        assert_eq!(tx.weight(), 769);
        assert_eq!(tx.input[0].is_coinbase(), true);
        assert_eq!(!tx.input[0].is_pegin(), true);
        assert_eq!(tx.input[0].pegin_data(), None);
        assert_eq!(tx.is_coinbase(), true);

        assert_eq!(tx.output.len(), 2);
        assert_eq!(tx.output[0].is_null_data(), true);
        assert_eq!(tx.output[1].is_null_data(), true);
        assert_eq!(tx.output[0].is_pegout(), false);
        assert_eq!(tx.output[1].is_pegout(), false);
        assert_eq!(tx.output[0].pegout_data(), None);
        assert_eq!(tx.output[1].pegout_data(), None);
        let fee_asset = "b2e15d0d7a0c94e4e2ce0fe6e8691b9e451377f6e46e8045a86f7c4b5d4f0f23".parse().unwrap();
        assert_eq!(tx.fee_in(fee_asset), 0);
        assert!(tx.all_fees().is_empty());
    }

    #[test]
    fn pegin() {
        // Pegin tx from Liquid integration tests
        let tx: Transaction = hex_deserialize!(
            "0200000001013fe9fcf1d5eae66a152efa45ad32baa5eed3cf11ab5e04edde65\
             0313b58ed8c90000004000ffffffff0201f80bb0038f482243202f0b2dcf88d9\
             b4e7f930a48a3fcdc003af76b1f9d60e63010000000005f5c88c001976a914d7\
             cc0ea6d5e53af78c7802101519cc100692668e88ac01f80bb0038f482243202f\
             0b2dcf88d9b4e7f930a48a3fcdc003af76b1f9d60e6301000000000000187400\
             0000000000000002473044022048cf10f12a31cb0ec36ba3a6f79fad7e0dea3f\
             1aa790a5aed02f8e8455c8cb1502201a2624089ce70c893dfd07a156ba91223e\
             dd5680cbd93d3336285ceefcb3dc1401210205914becd15ac5d2f72ad0aa42e8\
             4349c825a544d8c16e78ecc21534ef561fd4060800e1f5050000000020f80bb0\
             038f482243202f0b2dcf88d9b4e7f930a48a3fcdc003af76b1f9d60e63200622\
             6e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f1600\
             141ab7f5995cf0dfcb90cbb02b63397e5326eae6febe020000000113244fa59f\
             cb407124038ff9121ed546f6dc217571cb366a50d3193f2c80298c0000000049\
             483045022100d1e212715d2dcbc1c66d76f43d9f326f54ff339b565c68f046ed\
             74040730433b02201d9ccbad57566100a06b4be47a4c777cbd7c99e0a08e17f7\
             bf10458117426cd801feffffff0200e1f5050000000017a914774b87be1ef871\
             d82a01edbb89a70bf4bb59310387a88c8b44000000001976a914b14b73956239\
             21dbbce438f4fc1fc8f1a495affa88acf4010000b700000020a060086af92ac3\
             4dbbc8bd89bbbe03ef7e0016930f7fdc806ff15d163b5fda5e32105949c74822\
             2d3e1c5b6e0a4d47f8de45b25d63f145c4056682a7b15cc3da56a2815bffff7f\
             20000000000300000003946c969d81a3b0ca473ab54c11fa665234d6ce1ad09e\
             87a1dbc56eb6de4002b83fe9fcf1d5eae66a152efa45ad32baa5eed3cf11ab5e\
             04edde650313b58ed8c9fccdc0d07eaf48f928fecfc07707b95769704d25f855\
             529711ed6450cc9b3c95010b00000000"
        );

        assert_eq!(
            tx.txid().to_string(),
            "d1402017060761d77ee516f388134660d31ce9a72e546676303ac2fc3400656f"
        );
        assert_eq!(tx.input.len(), 1);
        assert_eq!(tx.input[0].is_coinbase(), false);
        assert_eq!(tx.input[0].is_pegin(), true);
        assert_eq!(tx.input[0].witness.pegin_witness.len(), 6);
        assert_eq!(
            tx.input[0].pegin_data(),
            Some(super::PeginData {
                outpoint: bitcoin::OutPoint {
                    txid: bitcoin::Txid::from_hex(
                        "c9d88eb5130365deed045eab11cfd3eea5ba32ad45fa2e156ae6ead5f1fce93f",
                    ).unwrap(),
                    vout: 0,
                },
                value: 100000000,
                asset: tx.output[0].asset.explicit().unwrap(),
                genesis_hash: bitcoin::BlockHash::from_hex(
                    "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"
                ).unwrap(),
                claim_script: &[
                    0x00, 0x14, 0x1a, 0xb7, 0xf5, 0x99, 0x5c, 0xf0,
                    0xdf, 0xcb, 0x90, 0xcb, 0xb0, 0x2b, 0x63, 0x39,
                    0x7e, 0x53, 0x26, 0xea, 0xe6, 0xfe,
                ],
                tx: &[
                    0x02, 0x00, 0x00, 0x00, 0x01, 0x13, 0x24, 0x4f,
                    0xa5, 0x9f, 0xcb, 0x40, 0x71, 0x24, 0x03, 0x8f,
                    0xf9, 0x12, 0x1e, 0xd5, 0x46, 0xf6, 0xdc, 0x21,
                    0x75, 0x71, 0xcb, 0x36, 0x6a, 0x50, 0xd3, 0x19,
                    0x3f, 0x2c, 0x80, 0x29, 0x8c, 0x00, 0x00, 0x00,
                    0x00, 0x49, 0x48, 0x30, 0x45, 0x02, 0x21, 0x00,
                    0xd1, 0xe2, 0x12, 0x71, 0x5d, 0x2d, 0xcb, 0xc1,
                    0xc6, 0x6d, 0x76, 0xf4, 0x3d, 0x9f, 0x32, 0x6f,
                    0x54, 0xff, 0x33, 0x9b, 0x56, 0x5c, 0x68, 0xf0,
                    0x46, 0xed, 0x74, 0x04, 0x07, 0x30, 0x43, 0x3b,
                    0x02, 0x20, 0x1d, 0x9c, 0xcb, 0xad, 0x57, 0x56,
                    0x61, 0x00, 0xa0, 0x6b, 0x4b, 0xe4, 0x7a, 0x4c,
                    0x77, 0x7c, 0xbd, 0x7c, 0x99, 0xe0, 0xa0, 0x8e,
                    0x17, 0xf7, 0xbf, 0x10, 0x45, 0x81, 0x17, 0x42,
                    0x6c, 0xd8, 0x01, 0xfe, 0xff, 0xff, 0xff, 0x02,
                    0x00, 0xe1, 0xf5, 0x05, 0x00, 0x00, 0x00, 0x00,
                    0x17, 0xa9, 0x14, 0x77, 0x4b, 0x87, 0xbe, 0x1e,
                    0xf8, 0x71, 0xd8, 0x2a, 0x01, 0xed, 0xbb, 0x89,
                    0xa7, 0x0b, 0xf4, 0xbb, 0x59, 0x31, 0x03, 0x87,
                    0xa8, 0x8c, 0x8b, 0x44, 0x00, 0x00, 0x00, 0x00,
                    0x19, 0x76, 0xa9, 0x14, 0xb1, 0x4b, 0x73, 0x95,
                    0x62, 0x39, 0x21, 0xdb, 0xbc, 0xe4, 0x38, 0xf4,
                    0xfc, 0x1f, 0xc8, 0xf1, 0xa4, 0x95, 0xaf, 0xfa,
                    0x88, 0xac, 0xf4, 0x01, 0x00, 0x00,
                ],
                merkle_proof: &[
                    0x00, 0x00, 0x00, 0x20, 0xa0, 0x60, 0x08, 0x6a,
                    0xf9, 0x2a, 0xc3, 0x4d, 0xbb, 0xc8, 0xbd, 0x89,
                    0xbb, 0xbe, 0x03, 0xef, 0x7e, 0x00, 0x16, 0x93,
                    0x0f, 0x7f, 0xdc, 0x80, 0x6f, 0xf1, 0x5d, 0x16,
                    0x3b, 0x5f, 0xda, 0x5e, 0x32, 0x10, 0x59, 0x49,
                    0xc7, 0x48, 0x22, 0x2d, 0x3e, 0x1c, 0x5b, 0x6e,
                    0x0a, 0x4d, 0x47, 0xf8, 0xde, 0x45, 0xb2, 0x5d,
                    0x63, 0xf1, 0x45, 0xc4, 0x05, 0x66, 0x82, 0xa7,
                    0xb1, 0x5c, 0xc3, 0xda, 0x56, 0xa2, 0x81, 0x5b,
                    0xff, 0xff, 0x7f, 0x20, 0x00, 0x00, 0x00, 0x00,
                    0x03, 0x00, 0x00, 0x00, 0x03, 0x94, 0x6c, 0x96,
                    0x9d, 0x81, 0xa3, 0xb0, 0xca, 0x47, 0x3a, 0xb5,
                    0x4c, 0x11, 0xfa, 0x66, 0x52, 0x34, 0xd6, 0xce,
                    0x1a, 0xd0, 0x9e, 0x87, 0xa1, 0xdb, 0xc5, 0x6e,
                    0xb6, 0xde, 0x40, 0x02, 0xb8, 0x3f, 0xe9, 0xfc,
                    0xf1, 0xd5, 0xea, 0xe6, 0x6a, 0x15, 0x2e, 0xfa,
                    0x45, 0xad, 0x32, 0xba, 0xa5, 0xee, 0xd3, 0xcf,
                    0x11, 0xab, 0x5e, 0x04, 0xed, 0xde, 0x65, 0x03,
                    0x13, 0xb5, 0x8e, 0xd8, 0xc9, 0xfc, 0xcd, 0xc0,
                    0xd0, 0x7e, 0xaf, 0x48, 0xf9, 0x28, 0xfe, 0xcf,
                    0xc0, 0x77, 0x07, 0xb9, 0x57, 0x69, 0x70, 0x4d,
                    0x25, 0xf8, 0x55, 0x52, 0x97, 0x11, 0xed, 0x64,
                    0x50, 0xcc, 0x9b, 0x3c, 0x95, 0x01, 0x0b,
                ],
                referenced_block: bitcoin::BlockHash::from_hex(
                    "297852caf43464d8f13a3847bd602184c21474cd06760dbf9fc5e87bade234f1"
                ).unwrap(),
            })
        );
        assert_eq!(
            tx.input[0].witness.pegin_witness,
            tx.input[0].pegin_data().unwrap().to_pegin_witness(),
        );

        assert_eq!(tx.output.len(), 2);
        assert!(!tx.output[0].is_null_data());
        assert!(!tx.output[1].is_null_data());
        assert_eq!(tx.output[0].is_pegout(), false);
        assert_eq!(tx.output[1].is_pegout(), false);
        assert_eq!(tx.output[0].pegout_data(), None);
        assert_eq!(tx.output[1].pegout_data(), None);
        let fee_asset = "630ed6f9b176af03c0cd3f8aa430f9e7b4d988cf2d0b2f204322488f03b00bf8".parse().unwrap();
        assert_eq!(tx.fee_in(fee_asset), 6260);
        assert_eq!(tx.all_fees()[&fee_asset], 6260);
    }

    #[test]
    fn pegout() {
        let tx: Transaction = hex_deserialize!(
            "020000000001f6d59ba2e098a2a2eaecf06b02aa0773773449caf62bd4e9f17c\
             db9b0d679954000000006b483045022100c74ee0dd8f3f6c909635f7a2bb8dd2\
             052e3547f94a520cdba2aa12668059dae302204306e11033f18f65560a52a860\
             b098e7df0fa7d35350d16f1c5a86e2da2ae37e012102b672f428ad984563c0de\
             c80b3912fcad871338545df1538fe26c390826fbb4b2000000000101f80bb003\
             8f482243202f0b2dcf88d9b4e7f930a48a3fcdc003af76b1f9d60e6301000000\
             0005f5c92c00a06a2006226e46111a0b59caaf126043eb5bbf28c34f3a5e332a\
             1fc7b2b73cf188910f1976a914bedb324be05d1a1254afeb3e7ef40fea0368bc\
             1e88ac2102e25e582ac1adc69f168aa7dbf0a97341421e10b22c659927de24fd\
             ac6e9f1fae4101a48fe52775701556a4a2dbf3d95c0c13845bbf87271e745b1c\
             454f8ebcb5cd4792a4139f419f192ca6e389531d46fa5857f2c109dfe4003ad8\
             b2ce504b488bed00000000"
        );

        assert_eq!(
            tx.txid().to_string(),
            "aeb921c251c466d36f58677e0ade3b7229c525bc2859f683f33c4428d1b5d83f"
        );
        assert_eq!(tx.input.len(), 1);
        assert_eq!(tx.output.len(), 1);
        assert_eq!(tx.output[0].is_null_data(), true);
        assert_eq!(tx.output[0].is_pegout(), true);
        let fee_asset = "b2e15d0d7a0c94e4e2ce0fe6e8691b9e451377f6e46e8045a86f7c4b5d4f0f23".parse().unwrap();
        assert_eq!(tx.fee_in(fee_asset), 0);
        assert!(tx.all_fees().is_empty());
        assert_eq!(
            tx.output[0].pegout_data(),
            Some(super::PegoutData {
                asset: tx.output[0].asset,
                value: 99993900,
                genesis_hash: bitcoin::BlockHash::from_hex(
                    "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"
                ).unwrap(),
                script_pubkey: bitcoin::Script::from_hex(
                    "76a914bedb324be05d1a1254afeb3e7ef40fea0368bc1e88ac"
                ).unwrap(),
                extra_data: vec![
                    &[
                        0x02,
                        0xe2, 0x5e, 0x58, 0x2a, 0xc1, 0xad, 0xc6, 0x9f,
                        0x16, 0x8a, 0xa7, 0xdb, 0xf0, 0xa9, 0x73, 0x41,
                        0x42, 0x1e, 0x10, 0xb2, 0x2c, 0x65, 0x99, 0x27,
                        0xde, 0x24, 0xfd, 0xac, 0x6e, 0x9f, 0x1f, 0xae,
                    ],
                    &[
                        0x01, 0xa4, 0x8f, 0xe5, 0x27, 0x75, 0x70, 0x15,
                        0x56, 0xa4, 0xa2, 0xdb, 0xf3, 0xd9, 0x5c, 0x0c,
                        0x13, 0x84, 0x5b, 0xbf, 0x87, 0x27, 0x1e, 0x74,
                        0x5b, 0x1c, 0x45, 0x4f, 0x8e, 0xbc, 0xb5, 0xcd,
                        0x47, 0x92, 0xa4, 0x13, 0x9f, 0x41, 0x9f, 0x19,
                        0x2c, 0xa6, 0xe3, 0x89, 0x53, 0x1d, 0x46, 0xfa,
                        0x58, 0x57, 0xf2, 0xc1, 0x09, 0xdf, 0xe4, 0x00,
                        0x3a, 0xd8, 0xb2, 0xce, 0x50, 0x4b, 0x48, 0x8b,
                        0xed,
                    ]
                ],
            })
        );

        let expected_asset_id = AssetId::from_hex("630ed6f9b176af03c0cd3f8aa430f9e7b4d988cf2d0b2f204322488f03b00bf8").unwrap();
        if let confidential::Asset::Explicit(asset_id) = tx.output[0].asset {
            assert_eq!(expected_asset_id, asset_id);
        } else {
            panic!("Bad asset tag {}", tx.output[0].asset);
        }
    }

    #[test]
    fn issuance() {
        let tx: Transaction = hex_deserialize!("\
            02000000010173828cbc65fd68ab78dc86992b76ae50ae2bf8ceedbe8de048317\
            2f0886219f7000000806b483045022100a21a578a7f2f98ca65115488facb62d7\
            c196d2df14213aed986cfdbdfd05647402204197c1fd1d9e94a14535e0918cd3c\
            a5932f6c086ac49136f255fd72ba7651d4801210211dd65ff387faf9bd658527c\
            b79d2b91cc7b691b0b5273b1a50d43104ea50f0dfeffffff00000000000000000\
            00000000000000000000000000000000000000000000000000000000000000000\
            00000000000000000000000000000000000000000000000981654eb5ccd9927b8\
            bea94997dce4ae85b3d95a20700384f0b8c1fe99518063800030a1f491e09f485\
            e018ec05dfa75239207546d19339b23e074dad183d788f81e7a708ce96a4dbcf0\
            9acde1fee82af501c9846ee59c51e77813feb3dff8d199195ee6303ed14decec9\
            a849df2449da03ab2d9ee717e03878226220612d790e7dec08f1e81976a914d7f\
            8ae92f7a073586c318b10db200db2ce831a1e88ac0a6c90cc7e0028e021801e68\
            d3a6db206598985e4cb954d09bcdbb64312a4024d308c2740f3fe59958d51bcf8\
            ccc863a2212c07313effa4a887814fb217b511ea27802759443a36a675dc6671e\
            d02fefecc127a8dafb9894d2ff44a74c5e8aae3dc2e91976a914904d0f751d7aa\
            301c724899be86224034758cc7988ac01230f4f5d4b7c6fa845806ee4f6771345\
            9e1b69e8e60fcee2e4940c7a0d5de1b201000000000000dc50000097010000fd4\
            50c40264c7003daed6754f258faa19bf81c8d94532cd8ec023420ed4e7e102259\
            93508c96f319d07b8cd89b4d1818c446e3599347482a767c7dd3b2fb5030b7eaf\
            62bc439875f020a6b400a29deedc363f9daed32a081a5ef6295b7c4e2a9db31a6\
            ed1a6d290d5a354f71aae49db8a34fbff22ca1e897a73984805705a0787c23d5d\
            c8973aeaf4f431febe5e1feec2c4eb31a1ad74ff01a0536e2fffe081b554f8b44\
            88e152fa98b2cb06a2ed6e793352e76b81896db6911416b458d42f2e6cdc6a67d\
            7e522cd51af9a1004ad7329ed86811adafde53caa97d4100ef5e2dcd63e956999\
            2716691eab34e7adc87bcb94c9fd983d265079bb0f9179cd089de335cf6da676e\
            822f81e46cfcb2271390efa383944b99682927fec879380c23f6484939d7320ea\
            d9690d90855ea2f27c8dbac965e64ab5e004c96a4a09e590cb012a2297231fc52\
            f7720cce1dba52e0448e05fa86cfd94561f09cd702aefae25bdb15c8903512577\
            565019bf7372ba40f61efd922bf5f34878ee2501de84935512b5908cac697e0e0\
            cb917c24315290735210a47e861a7340e540540f4b2fb92f54f2540dd98b25122\
            80eb2db08f52f6ab4544fb7377b9424c050afa126412eb80e20611432528ed386\
            0c2e27eab18a0bb8568c76df5c9a3de777c0ae69dd8a71e81df3fac8eeb31da8a\
            ea467eca0f2b32bd416c5adf106b7d18b6de9fbd4348d45c517f2bc369e0504ae\
            267f16d5e34225cb0100090c75c27f67eda8dd1986a6bf29b0488a115abd33f0c\
            19e75dc8622302b50e1b67b1e6074893b411251b0f40327b9a135f93b926ecc7a\
            91da9dea77fccb234d90735235d7196dbdcc3cc542f11faafd54341c380f7bcf6\
            faf9757460951ccaa9533a9c4bafbd61cb8260f916bdcf25c3d12885fbc48b74d\
            865888823240f780ed8c924f9f60a1dd9125391a43e66dc65d7b5fa82b8eb5ea2\
            a200fbcf37cba4c3fb31015c0cbd17b16a50ca8416e312254b87ce083abccdadc\
            bde4b4cfa99b01b989819c6fd40d140493e0795015457befbc52654070dfba568\
            77987502dda25b5eba2a6b1374dc4dd19c607811f3a1deb8de67cd17b1d6fe2ec\
            3ffac884325d61d95f881194ee5577ebc338d9809be55c12bfac4d69e596bc416\
            186f2d76a1dc1dd8fe787cd0012639f7da04b3c193403d6a55c1ee8c05a3b1a0f\
            a65d3a5b86b9398999a9a448d8c34dba35731d542d5e99a21ae63bd30f0ed9f1e\
            c12cbb6e812766689981fa5d6ecd6d9972e0423cb6cabfcc0fb333ae21dd61327\
            ebd511528df5d758e2a73b7ccb839ac5bc6aa51b58c8f6e09be27e51e8071c17a\
            d899d2b08ba6b7443fff03ad6fe943efebef8e35f3873cd54941d90b44529b115\
            af8367af9bdb605193ec4353d5fd65bc148f3f76afe7815ace18ac6c2c70c8a91\
            27ace4ef0f0344ae9367db15a5a1d87b8719bbce43c37581488202051838cbaa1\
            39bbb7f6c85b9a7dc5090bdec1168c6defb6eb5e9c2f3841c1e53c4a5b40d51c3\
            40e309c8db21f2ff4667e928e71eadc5a462d715116001d6822dcb012d6bf4e94\
            e07d625786e290f2c32e55a8fd0b13aa2776130c842db34eac5358733f54b8efe\
            f2803c98d0d20467ae116d983bc2e75b2ec83e6a8a9562b29b77f1c497422cceb\
            d7df4f05d4c2fe403d57ed37239b974339d0a7b536ecea53e391a70c181603814\
            18b3d7de2da0abd5743186c7361d7f398d719e7c4945f06f4e74c95ae07023a15\
            3c1f5dfe152f914af504e8067f87bee54d92493162b8e09d4fa18e8722863b084\
            c9a19b5a3893dbbb1d456efaf17581538becf64ea8d63c6bc87fa87f6a71c0650\
            e307a080dc9b335f4baffc350725583367021fb4b77c2e1e05d339e1ae7832eb2\
            d46ac036bf951798bb7b236d9ac73df5c59639b8159a07890d5bc6134d08c10f3\
            f5b271d63a735700ae3690939ac74912c4b6c3f197fc0ef9a41961b4adcf0c052\
            0288f2073be175a15db0f2f6a79ba2db0ccd3e2486129827f90e9b9f8e814ce23\
            b151d93b35854bdfaa0ec0e2f3d992ffa9561648aa831edfd7f356602366ae9d1\
            252fb3196bf5844b376fa7c6f8cdda0210b60c97ac896638688632b8f33554ad2\
            71140c29e4a1f43e5c8f266b88eefdb01d583c27c98c8084edc8034ae51dd4a6d\
            ca1b9e311662685e53c509fe61c9583acb5693c598edfc33c2bd039a7121cef3a\
            49ac135089ace29485b2cc4ff9402935e4dd42753955a69d981debe35eddb9eeb\
            ffbe6f6027e39cb74bd7e88ef384c7e7cdf8d2e3224cc9e9f49b72b1978db7c30\
            bdf1824edb67cab8b7c6e8633e7d14d261fba0fbc6811209f73adfe8a2c485970\
            000526536395f7312347582aa2a49f3935acc1db33c555002653a46a9635a4bf6\
            7caa700f685f2291eebd7bd59c72e98ea0cd24a14aab5b288f8f40f87cac409af\
            fb5a7e43a306df831a1106c54ee330f04df833dab8f5171e5f4f3087b5b82bc02\
            d91c71363db7eebec29bd4ec6f32e6afc1a07635f1c07f8aa15643f06108326e9\
            e29df1c93f6321868144dc84719c1031b7f81e5ed49eb9f8b4b6f863b21084a57\
            bede3a7ee9640a91f6091ef584eebb4e3fef49c03ed703c8d869f18f90777e65c\
            6270f33e371b01efacee44a15346ba29fc7d6bd7c2217cc399de615d41e4006df\
            808c63e3cb986845cc52c2fda7072d88aff90b54a29c787f5aef0a4b96ea6f971\
            7f3bc8df1e5bef6ec73f51705b5133621460d1fab14a420fd4dcd8019c0588d7d\
            85104b88ea04d9139ce2e31d5756928af8b6a3202e4ecf00686dc292ad752ec0d\
            a61b3308ac9e8f7ca159962f54f284116511a7b53519dde7d7b5f92c41a9e31d6\
            a006117c91fc078c8bf437f5e735c8698094674c6795df6479fad8f352602a148\
            27d57afef36d059dd185fd141f498306a44806120ae1966aaa4c64b99c2515459\
            5460d179f4042cf0abc6a0b277757b3fc5368366df8ea3fcde280961e5663290f\
            2e2af37a6e9963c58ba7b68f9b63c16bd7d22a9303cb69ff529544d4a82540503\
            63a074e3f6703dbe403406dca15086d3312a86d3f3f119628b214fda41fe28416\
            e0d7670e0ad567f2a66d2331788037c1748e00e110d15bf105b0002eff2d8aa4e\
            2902addda34c82af7149978f1c924fc5fa6189068d09dde69f2b1a91fe96587eb\
            7929cb9e30c7a6e9ac8ab353509cdfa7d7f1f7bb2cd8bef944532a3d085fd609f\
            96d35d5eb41627dacba7b8ae6c30b9e8ae40684d1c0890a59e98c4b6de684e155\
            59be97f382161aff01b28aa21786e71edf458d852b6482d1ae20a25f130a110fe\
            8812d79e19dbec32be5a7bf495f5a264bd64f62a2646b8ea37e6fd36c280197e4\
            e141c29ec7a7aa25581e08673dd713bfa81d77e0c9855964b33dae6dbf0953cdb\
            1d42307ea5f7eb49bdb341b6be3f9f2a029e5a656dc614a6c6d69681167b607b9\
            0bde3f5cbdce734bfa7f76b0297c2462b47caae4e371cf258b7ce897ccaaa3f99\
            15de94a150764791ef9cea89716b6bfe7fc8ca502a947e211432794c9d415a32b\
            a7e822d071d3fd61a53c26cf1beb6fa8811249e0f2482aca9d1c7365d99e655e7\
            22c8aa38d8f14b101f18b047263f1ab95f6bbeb2c03ab6b64cce35687ab76e0c1\
            79997516b947b2b9f1857a354a33e763a0ff5fb90b55cbbfb1b56d5114fe33295\
            55550ec7fc8de5f6797bb53129a1887a1c3e47b7c53c2f224fd1cb5df02cc6ba4\
            ce7dea93379f6cdd06475e7ab51453781bb2605debe86519497609ee4644224ab\
            84ce896fabec46b81dfdab035942de9f160829c1f8e7beccc02d659c7e09d2807\
            4bb1fe24100cf61799ecf8306c2685ca24a22a17de2dc1a78599a524afb76fb96\
            1a093b8f35da2c04cbae86ba793320312f63d479d36c9b5984364b508ae8d8120\
            ae14e3c8641591b320e314b36db6bc9aa5f548b91953fac433f0efd94bcbf660e\
            b560db5fa4af31320cf254d675d97b7fde1b8551b85087b6e7818deb66a75125a\
            3d2040a03e1c2bc4add8f2f6cb636237136fe9ae879fa18e12282cd1cc5d0d84a\
            ecd8ad56da49ac0150fe7dd4710fadd580f39a49e427b42f980ca343b68e73b1b\
            34b838e125bc0b3a6eaa038bbacab6f06558f6ace4c416cd1ecf6818cffd8690a\
            319fc2ae2c4a8eb10e602ce3f0a464f7b920d68846113d8389c292601ec112338\
            fa2de3a5a0bd1847f54a04bfac1a93bc5e7c1a5ac2a76fbf5fd0d2ccf1934a1e1\
            438ec9e3e1fe6b943d1a72037c70a4dcec983bf828b11be1488cf7b1ff84725d1\
            e7aac6ca2807bd520936db6730ca23fd298e93c88c15647eba71bf39bfd4515b4\
            df1cd8c2bc0b4db11d9912295af18a8521862952cc1f6f08da8cca0d967ca7b7e\
            e0690a6558e328ad08a056e3d65adcde079404f03d18f540615a322cab285ea15\
            6790305066fb26fc1ab57a09279f5ffff4edffc6137a900000063020003e6847a\
            3cd9b5eba65bd81056ba707f19961ac3d0a26cc63ed8e433d44b1c9c4c82be685\
            7f9f85ecbe7db17fd4693c31ee1f8b9247eb43ad3f4c6ad81e5829723de029baf\
            6b65c9201bd065ad569d4eba4736145c4d005922968ebedf9deba2f5fd0c0a601\
            f00000000000000013566ebac06d73056cf8d5f565ac1aa83889dafc5dd367978\
            10823b909ef66724e21827d0670561dfbe1982788483b9be05b7729275a44c439\
            77df9cbab97c553475d2228379892be237d42b252057daf29b72fd7111b672830\
            69d410b68d54f8e0da92bf0b3598ef7ce1cfd313c9a9c06b0ea313935929e1cd1\
            287d412814c0232caa165c467ab0eb3ade399ab2abb7f92a8abf970adddf989a8\
            fbaaa360fcad2990dc845b9d83a1d536669ace9a498d83043238df074d7030bf2\
            caf6548d439ba7533285fb25679b44fa4ded2f0a157d59d95c8821a36c6c80168\
            0cfb1c74db08aee75eada227f0e45ebcf0d7640471d45fe56d108360d3a7f640d\
            662f19a1c96de625db64ed1bdb4afd0a1d6241538e7ababcb7ecc27c8873fc9e6\
            3b029af9ea142e80d2dda2c45214ef21800fea9dfaed833d35f17eff9ccca4648\
            c961c4e1d2cd97962fe6b69935036aba9c89ba13f84aa6630b580aabd3efdb0d0\
            3db8bda63b0a69157d00c7834582722a3bd696f174175bac95e74a1b3cc5a0983\
            1e2be6409412544d35833afeff6b88f76954ed9c0019c75701622fabcd6c8b4ac\
            cbd1f3551c7f39a51ed58c773449cba2afef7b7fbf55bcba1f4f845cbeca662b2\
            fb95ab84e275bf9d0dedd96ee32eb2ea71e9b133e6060d19707a4b63734fdfa37\
            b507ca2bb4056c8786f687c50ca58ef07a3d27f337f80b6a66073baff2adbf5ba\
            03726fa2c84ab7b6be243fb56add0e313be4eddd6af55b42f85472074f440470f\
            01a2fa1db1c33e4b686c631e7bc09d92ce0c057ab372d5caeb549b6ddbc374017\
            740debe825cbe35d51b269ddc58fb1b2f389f2d179b97aaa5779374f5db737798\
            905ba48002e3125a831c844ac1558ce197e5a2f66901a5933ff3da7b99faf3634\
            e5ce532765b3477756080fe9952bdced8f1fe61073b99604526c18b93a1dae6d0\
            78745db84ee658e83a02ec0b041027c25a5fa9f3d2e069fe1155579ef5fe9a694\
            8cfbc8444f99372fc615864d5bc0261fdc4e96f36827d5a2b3cd61f94dc213c7d\
            83666f4bb464e33826454d75675e7a6d320d16ab240d0efc04744327ce830d4cf\
            221352729786dd4a1ef180aa529526a5f044636582419f173e49e4f189106a64f\
            181e03c7860a7cc26d9e84e401210cb564f81c26e5409f161d1c5683820f3e307\
            315d5a56dbe6a4bf41e60a6a7f66b28f6c353b174f6a84d0a3d040cd687f8e830\
            98e1d76e85d3193d65cd2114659d42a92499e250d38630a3166cc4f5f2aaa1207\
            b9147c4ee54977fb4211b8336348cb950e845f4b39aaabda3343a2871daf89229\
            c3504f70a8fbe2de524ac352dc5b042b4d5171f51c021f626f640c8f08fab5092\
            44000877e1dd383a01e2639938011ab5c10a103dc843296dabbb9fe984fff7d26\
            9cf4f96a14907701c078e405340a468eb1f493c4dcbcbb851c09ecfe3b108d864\
            e6125047fa7b1f71182524dd6f60f43542e09ec291fa03a200975a85cf38f7f11\
            4eed2408a6e757f6bd6435d9afe8cbfa159941a7eb85b3c5b68b242c7ae0e2066\
            54c9ff6a0669754f34c022fb940bf7ba91b6a03ad20276162dbe1dac433b41b72\
            f3d96cdddc975ba64ff23556f6dde4f8152bf1b615459d6bb245daeb14bd38201\
            f6a89e996ad39e277bf59dab63e34f509f44a3f1fe187815c9a1ba4849ca64859\
            c91aeadb15842ddccdce7d1ded68b4e28b7988104dd1b0887425910d71b7e170d\
            67275f605da7e7b7fa270cca7a50e052fd771e241c50473d6f8e697f7669f16cc\
            62697c921fea92d8c69957c612ad9d3faab0c6260483a0f274a32b62723e85056\
            f87b536830410464e4fccb47d6ad2e5270d370efd1847dc07f3492d5a1244bf42\
            56bb6f029a209bbdff10275e19a6bd15c6eb0f14ab81eb2d5d56fbfa4ae2e36a0\
            b1ce36c68300d5e8909e1a209358d155dc8d948dddeac9483bceced7a5e3da1b4\
            203b476e9c81c908a74bac120825efb711d83105f8aee9258fe2cf86138a4409e\
            508aeb6d252be80f240887407667fd62dcb029ee8c8e1ef5d613e19dfed38a065\
            03fcacb2e590706fc024a9f3f859edaf48b9fb3f65c70f0555f0651ea2b0fa28e\
            c5739b94054a082d55e2ce0a3dded2906fc327f97145f3987b39621c231df9b17\
            69f0a28c7152881ead2f67bf7a2438e7858f6d2d3a1b72da0f65edc1e4acc12b9\
            eec264f69f7b50b44fee7ad80d3d3029bdc7704c2836164d901392aadc5903c3d\
            bb789ac14e2a6a79dbee1796ce2bcd0f39d72a298696f22c5bc84ac4e719148f7\
            7e87a8d747ff08698544ba7e9b0ad9c2b209e2df9ce00905a19a510086ae6d32b\
            c2a8ece3f63ac2dfb19868f4e4c4d8bcb7d1ccbd2a9a91d80314fb2e89f91693c\
            36851ba27ea1fdc118b6aad0b8be4f02d7bf7c7051905461ad0c7cb1cfd520e32\
            03c4ad20248a2afb3ae7dca2f27992e0f233826acd487524c7b019c08c5ecc00b\
            ae8c42b0c43a3e9cce3a8c44a3017ec1b10c0813aff22bb7902c9c61e16a57bfc\
            cb98e4112a15fe5623035f28d75104c302c1b8cab77a70cdca9c239e869cb42da\
            d98bd2d656e608023a325abe007c6875329824e571d5c8ea370078aac6ac75829\
            3e4c30729db81e0c8f962753b9007a4c486a7a31f6581160803e95ae6e4f5228b\
            0860489041490e51e88dedc874a49d18abcbda88bc3d80406e70d8701aa86b26e\
            594139c2f27eb838fd6d73ba0f58cce118c2f9f98539cbaeb82e8a5507ebe49a7\
            67fbf04096434ae276e67bb48eee2c9e0bc06616acc8d705cae5ab408bf2046db\
            bf96d79b470b90ed1d7cfb1fd9d7b77148177971032af58b5bb772c823cf91f21\
            b341495dba5d7bbb2408574aa59d3fe29e30019fa00769b7f1864781a037cae0d\
            120261eac8f772d01f7e49ef75c8eabea1ae41dd8b5a89473d2559dd0fadc9162\
            561316b318eedec0acdcb64258288bea986bceaf944a27a2fa8ad311c72ac9d75\
            d2800a065680cc2832d509087c5b156006762894be62164d72dfda3756833f33f\
            5793ba545c9660df3485f90aca88fedc2bc1d931e03afd97118dbe0fc7af09ab2\
            307f930e9737b6c4bc8a7d4ab0202c68277a5fc5eb32c787e728ed6075c622f18\
            dd83925ce04f4204993b3483ffd5046491a772ac4e1cc11c64a19210bd8d1820c\
            b246ca40ad22a068086590beb06898dc9818c1539100e912fab4a364274d62122\
            23388934a2f564ed37a1353cb41954e1c6e1f59495a07b101016dadd680708d41\
            5ac504e3968f693fcad1128ba263b69e1693c4144875232eb0e60815210aa2ce2\
            43b5bb988d7dfa6e04212d43b09bc8efe52765bfe903b4a0c5f49ed9add4d6bbc\
            5aebe0b286512054a4bd5655d07a988b62385152310c0a1ce2881b0aa8fb93ce2\
            565a519e2d056d7f44830baba1be2a22adf85064c57e30a1898e23d6ca37a59d9\
            096986bda40f192c72eb82332a8c149176ec49cd24d7443471b8793288ff90c08\
            95e47fd53ad5600df5d484a2c275fbb7f2b55d712cfe530ddc3ff3d2e02eb7f73\
            de7a9f6968f0e85d62043a6eb9cd3e7c8c5e61948df226433173708f0ae410abd\
            13c4bab8d89c2f131097a84f9e8bacf5241b01f56153cc76e29fb2d86f193e49a\
            47df80630200030f87ce27f7a6eba73a6f5b454b1b4103493c5aeb8a6a8dff8df\
            ac8b40f212fe13e01edc26bf19ae317b8c16641b371c1cdae9dd7fa2d7debcdce\
            376c95d0097068d0408461b786331ccf5d5dbb6306cfd25b6b86447a56881cf65\
            8cabe49e645fd4d0c6026000000000000000143eb0463e272209bffaf9e7cbb1a\
            e2fd6f960049f3ab0be423764c25e0785d71b3cee4ba5bde841d9f66f054289fa\
            d5109a5c2c4311d590ef67901a8b0de798834ce87ecb885c6aec7a8fc90ac8cab\
            b2ff43ba8206a6647e9b3aafcfa7d316c023b957ef7e641e2e5bea2710a2fae80\
            d271b4c34445717c98baddc7a54abeaac1a4ef58a6af74b345e445e23c948a418\
            2e6d0eae3183d3afba58422a069df4d3d06da04cca199c9eb2419c552ae429e58\
            a245539540d80191dff862e62374bf181ba81af14be1275231b9af1a5d2e70a62\
            e21a63cb14dd7579e50e47f2423449267a693620d95ffa1b6c01d6ccd82c90c02\
            a58647b61f31835ac22254bdd40a069f0ba807fd70418d4b99bdf4526ae1059a2\
            7acc82c10238e9d8b51b0a67370bb6007512670a882cd4ecb1625ef21297ad984\
            0baf7eeb1aff4515228ad63cb06c5821741551cccfbd533d56e2007c7d6f5a867\
            944d25654d007d3aadd8a037ad0b44f3988c290b4df68c471ba154546b931d2cc\
            65c38fd72bc98856a73fe04d6492496ea834f3b81813149fd8d80c3bf75cec495\
            7c78a9b1754b4d1f63786e75aecd7d3e327d4e4e59fa2bf75d95a1fe53294fb33\
            7e26178b784c88342f5eab473cc1b4bb77a91e3240eff123e1a0a5cafe2909ca3\
            843de72023bc739539bfe6ba05f6c078e4ed6f85e8cb1212a6f3d0c0d2e77db1e\
            2a3c832fe20f5d681dd3cc3f672d76cf162890d2736023b09086400e15eb1356c\
            ddd39d78d59fa8b44247153d486e8b8ddf2a3e730603c14690cb871afd3e3d13e\
            d4b36ce7a4b88b14f2be96caae4296f810ef269d8c02ed691cb5895a06716e160\
            1a9bf87ebcf8b5bda02343f2eac3dfa5fc6fc4c8c855fbf70af37da99231f160b\
            b99717a32f4cd17a213aac1cfc39fa80badc7a9125477374c441468c594c1e751\
            104e01f65a47e6039d804fa8550a8800a52f3b087e714acff868b62ceb123319a\
            fb65020309116dcea3742157dce1d0b85b8f7c0a3ca0c54147c9a17bd15c06630\
            f55666012d7b29ab5147c3b2c7aefb821562516ad902785983e1330c489929ccc\
            f806810327538ff30fb3a690f9751200e67be85d6220e8b01dae3efc86b7b4340\
            68873583c4c0ca1744575be08dcef90211bd26b812858d077ca4dda520080b8cd\
            001d9ef9d8d5085e33911de7e3c4bb2580ee9ac5c3833a0c3ea0a1ec473f417fa\
            4b85f6e66d0ff4182c528b711b505f320a5d42cbc39b08808137cbb9290b7549a\
            e61465c9dac0d0be6d6eefffffacc8e4d527d346209bd14911453e397d9a5e414\
            d32ce5be5895ca737712281d39f94a7e67c2243f95b07ea257d3df7fffa71e0bc\
            169ea6b8e1981c2ac6b3ea14458dfc9166ce57db3fa1a99c6fd1c9973965637a9\
            e7a31e4c6c27486e3667bd69049ff3040aff40c560f3c15e3df870dfb0596e262\
            3495e08dccc003113983bf8f2dca02ea7af5b2de2f093aac789a5582026eda1d4\
            038d32947016b21bea05d1276100c7a3262654bc48b6187ee4d2bae5bb5383d67\
            1c59f41981c3d966cd9eb12ac107f3f14e8920f0f25113d92203cae3734e9f704\
            22e5e833b9011073bc691f79419b720470b9b895353a005c4356cb8c950fe5a83\
            e2efb461eb7d5887977638b40937b73f5e67861aaf0741506c24cf33c8ce68a63\
            350c90e69e022e09efe5d6cfe15e4bbe0674c1f4608e0396c281b3453efbba5c4\
            0d03962abd55dc9e63532255754a263db4e7e1d4984496c7c0048d54442698585\
            a276ddb1bbafa17390f143717fba16b5705b71127c6d615f9a4302c0b67ae633d\
            21c38a31c7e68a702a55163ed926093c0857e1902e336dffafc108711b1ac0cc4\
            50a774006680c2569a42e5d20f8172bde00bfdea57097c7a377442d47354bf44e\
            eec6320013ef954ca79bfd714f61aca47826990c91d607257d4f69986a0a6750b\
            00c0dad72e665584059f589c428e09c4f71cc8148ae8c739f89ea848aeda489c8\
            00316154cc338a0c6ec82a317cc09c880d6dbe093f579aa56826249359edd6555\
            4ece318eee4211cf6ab34e2f4fd690352863abfab7d4db199bed131ba14206b57\
            7b890178fbe7126ab9bf0af0fd959526c1ccb4808b37a9db4c2312c3b2f7292f3\
            5c4d7ad150e997cb93b39176af7da6a4540e37efb0a4540f536ee3bb96b68ac57\
            f43755b02f0e1e5ed4bcb5063c97efead2457405b0b578663a12b8a5623168638\
            a8a76c1eae249f6716aea4b1259e2e4023ba8d23eb4ece7961400bf962dcbcb03\
            858a92b56731f482d83baa715de969f82ae22bc7647fa17cae7ca9113977b3f1a\
            f766eedb5e96e481ba319eb12044af64b971aeb054bde5e0440e6c9c5f5eb1aa5\
            bdfe702fef1f983aaab12cb666a2ba87f9d7d7a00f1bed5f455d3748600ec7f28\
            a781868e1896617cf0bbdb81a33dadca46df29554db003ded2c228c660e97d265\
            46e58dba32fb48e1a8091c1442e6291c915a412074af0b5bb28e9a00eda57bfa6\
            c1974f7f41a8680a31ebfa34ae7f98bf39d657fd80776f03b5bf1ecff9edaeb66\
            e938987056d2a47c246d47d91b74616345c827792311be6524e285b1db60a7fc2\
            7bf3d5c5c31d34f072595b61f1c35fb26312ce337598376b81b93c3a1d6095922\
            4bb32807f9c37c3227c23c0120e07e15f46d87ea017175f2f7105e08325054eb1\
            3efe3330fbef7eec8d0c9a598ce327046372e37a6871abd2bb164441dad8e9d31\
            fc3009a3cbc87b0a43abb1ddbfbe311028e747bc8caa9ea8d45d37a6c2a0a9ba9\
            5190e0399b9449d06fa78c455c1c5ee47c0b7f3e01d1d4d1370a7377757e3e02d\
            d6e495996fbcefab719939490279f0847102c0a697b65bd420512fb9af201a796\
            a0164b798dac45c8752078dc20b7123e033d01eb6f089d78627ac54271f1f7de9\
            8564d2860da314ce69b882e7f03db8f1b3f630c808c2fa047eb3a1b39c48154bd\
            54e6be5259364ad7cb82178fccd42fd8819370d1c93d29eaad58d0398de41e55d\
            3394fc444a9f8b6a923e70caea1a77fbe4e1560a7bf5d4b953ba6175faa13eee9\
            a92a9e6d7148c1198ffadaf72db1e64a066bc0d82e77a067b66eea0f4f4f9f75f\
            cd27fe5038942054b85325f2f6e003aa6b1c27580d95d030b63f706dfdd2b8e89\
            c5ce80f2c54cfebe8433469fd90ce9bff1462571af7c2eef3a266f5c8f875e3bc\
            197c09d5476de7214a004673857d6080d57e31b19954a3ca8f45601bfe30c54dd\
            51cc22a5b17517868c95b868e96a9c14520dfbeb926030a9b213e9087973328b7\
            2d16035cb22e9835d74a9e8107f883d45f303b6e8d50721888c325b857f041c7f\
            2fe9260b64d04440bcbc2757504c1539c31632e65bb06f386aad9c65cd33c893c\
            95d9470b9d7474d5582a29a0146d35ce27b534f29eb161d73e3baa18638d7077b\
            e55251b3c321f0987ce59c53ac25eff5fb16df2009bd33a01cca1f16af5b78eb6\
            3ae751c89f42b7b411b3d4787b7c7090f8f069f90b1b492926f4813e2a9e1c073\
            9c073bea3ec2983ef713a880e33f5fa0b2f203f03fc6d9670bd44f6a27168fcdb\
            9c538b2d8800b2f5d8f50b1b282d139a24f49d17942d1305042e2fc26116d6808\
            16721cb2a6ecf0c7e68f85464766e832a0ac65601da66f00ca270b8db5d7f1d78\
            9b518a5d2d27027be5d685b6df86c8e2ac7ec2f1b191c75bdfc0dc2b4b22c14bc\
            3d828809adead46542c90cc3a0febd4391fd12cba8625de98d0b709b5d56efbd5\
            80a0442687d0e677b8515fe7a47e2c002d1ee16c157c0d3f09b9ed14b948413d1\
            b88056874395c24c9694781c108ce8aa6b0ac7889c977f030270985fa68be1d27\
            74f4c7b9c06f1aab326301a56d424f5300c2c60c8220150f85192cde412823660\
            66e87fe26d6ee5b7d284537d62dc698b5913f57c72b95c6ec43291274acb2c8f3\
            109b82fad4b8a135b12163102f317b409a04f57e93ebe311d89a31cb17d338171\
            45548c92a6339c988d1eee7d9d57475709c29f829ebb8ad5fe6113498b9ce6eb3\
            91aa806d45fdcfac594b93b12c1e1635a6469248af357891c6bb24fee7cb38b65\
            35af8462f90405e0f21ce4db4b20cb8c033c039c4e3561c3de87cc1687e0a6944\
            ce9475179956392cbf2aa5c0ca9d487fbbb77d9a0856e1cc5b131b37f2e337a97\
            e18b761c1fa5cb1a40845b5e2a12a7240ba050762e79aa754992218b092dfb22d\
            a3fdaf9573589e767f12fdbe567593c581e9482209ee8c25258ee540b55e90c89\
            8e7c834676db7b9b8e11b74049a4447d4267adddcaa85926a9ff56c128b29b895\
            6423fc994355e90fb48caa17d4156b80bfe668cda0a0ec108a487f4a7193e25cb\
            78fea170dc6956487744de0c263bd0c1847c5df09fad541b2be2d557896b566ae\
            50186f922528705e5d8e7785f8ef9568f5edbb36e2d46ffc89b1b83439ff07ba4\
            5c3d8f741d0000\
        ");

        assert_eq!(
            tx.txid().to_string(),
            "eda1d7c0f47fe209c3b5e98ec4bf48fc03f78ce8dcb9742683751fac42f7e4ed"
        );
        assert_eq!(tx.input.len(), 1);
        assert_eq!(tx.output.len(), 3);
        assert_eq!(tx.input[0].has_issuance(), true);
        let fee_asset = "b2e15d0d7a0c94e4e2ce0fe6e8691b9e451377f6e46e8045a86f7c4b5d4f0f23".parse().unwrap();
        assert_eq!(tx.fee_in(fee_asset), 56400);
        assert_eq!(tx.all_fees()[&fee_asset], 56400);
        assert_eq!(
            tx.input[0].asset_issuance,
            AssetIssuance {
                asset_blinding_nonce: ZERO_TWEAK,
                asset_entropy: [0; 32],
                amount: confidential::Value::from_commitment(
                    &[  0x09, 0x81, 0x65, 0x4e, 0xb5, 0xcc, 0xd9, 0x92,
                        0x7b, 0x8b, 0xea, 0x94, 0x99, 0x7d, 0xce, 0x4a,
                        0xe8, 0x5b, 0x3d, 0x95, 0xa2, 0x07, 0x00, 0x38,
                        0x4f, 0x0b, 0x8c, 0x1f, 0xe9, 0x95, 0x18, 0x06,
                        0x38
                    ],
                ).unwrap(),
                inflation_keys: confidential::Value::Null,
            }
        );
    }

    #[test]
    fn txout_null_data() {
        // Output with high opcodes should not be considered nulldata
        let output: TxOut = hex_deserialize!("\
            0a319c0000000000d3d3d3d3d3d3d3d3d3d3d3d3fdfdfd0101010101010101010\
            101010101010101010101010101012e010101010101010101fdfdfdfdfdfdfdfd\
            fdfdfdfdfdfdfdfdfdfdfdfd006a209f6a6a6a6a6a6a806a6afdfdfdfd17fdfdf\
            dfdfdfdfdfdfdfdddfdfdfdfdfdfdfdfdfddedededededededededededededede\
            dedededededededededededededededededededededededededededededededed\
            edededededededededededededededededededededededededededededededede\
            dededededea7dedededededededededededededededededfdedededededededed\
            edededededededede9edededede00000000000001000000000000050000ff0000\
            000000000000000000ff000000000000000000000000200000000000011c00000\
            000d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3f3d3d3d3d3d3d3d3d3d3d3d3d3\
            d3d3d3d3d3d3\
        ");

        assert!(!output.is_null_data());
        assert!(!output.is_pegout());

        // Output with pushes that are e.g. OP_1 are nulldata but not pegouts
        let output: TxOut = hex_deserialize!("\
            0a319c0000000000d3d3d3d3d3d3d3d3d3d3d3d3fdfdfd0101010101010101010\
            1010101010101010101010101010101010101016a01010101fdfdfdfdfdfdfdfd\
            fdfdfdfdfd3ca059fdfdfb6a2000002323232323232323232323232323232\
            3232323232323232321232323010151232323232323232323232323232323\
            23232323232323232323233323232323332323232323232323232323232323232\
            32323232323232323232423232323232323232323232323232323232323232323\
            2323232323232323232323232323232323232323232321230d000000232323232\
            323232323a2232323232323222303233323232323332323232323232323232323\
            23232324232123232323232323232423232323232323232323232323232323232\
            3232323232323232323232323232323232323232323232323232321230d000000\
            2323232323d3\
        ");

        assert!(output.is_null_data());
        assert!(!output.is_pegout());

        // Output with just one push and nothing else should be nulldata but not pegout
        let output: TxOut = hex_deserialize!("\
            0a319c0000000000d3d3d3d3d3d3d3d3d3d3d3d3fdfdfd0101010101010101010\
            1010101010101010101010101010101010101016a01010101fdfdfdfdfdfdfdfd\
            fdfdfdfdfd3ca059fdf2226a20000000000000000000000000000000000000000\
            0000000000000000000000000\
        ");

        assert!(output.is_null_data());
        assert!(!output.is_pegout());
    }

    #[test]
    fn pegout_tx_vector_1() {
        let tx: Transaction = hex_deserialize!("\
            0200000000021c39a226160dd8962eb273772950f0b603c319a8e4aa9912c9e8e\
            36b5bdf71a2000000006a473044022071212fcde89d1055d5b74f17a162b3dbe5\
            348ac8527a131dab5dcf8a97d67d2f02202edf12f3c69fed1fa0c23da608e6ade\
            d86dd5c7b09da42f61b453c3a838e8cab012103557f25ff40f976670ddf59c719\
            38bade91684b76ad69dfed27049de2afec59e5feffffff853db31f986dd89c81f\
            e87a84f385d7099c5ea841d762b26b03166e5e798dfbe000000006a4730440220\
            42c70729fb50930179a9d76f5febbda5b0ee50e62febf92de4dd10b9393554d80\
            2203140b107519243e4110c065017c8ae1ac04843f94b3f20a1e5faf7343dd761\
            59012102797ffcf7ccc8e2012a90e71962901a1ad740f2a28f2f563c76f9eb42a\
            8100f5efeffffff03016d521c38ec1ea15734ae22b7c46064412829c0d0579f0a\
            713d1c04ede979026f0100000000000f7869001976a914216d878ebff0c623909\
            889265d8dc1ab26e2ff4388ac016d521c38ec1ea15734ae22b7c46064412829c0\
            d0579f0a713d1c04ede979026f0100000000000186a000fd02026a206fe28c0ab\
            6f1b372c1a6a246ae63f74f931e8365e15a089c68d61900000000001976a914df\
            662e2dd70fd82acba2d252cc897cb6e618093288ac21025f756509f5dbac47d54\
            c9ef5ccf49895a4dbac4759005a74375f66c480e6c0864da1010ce552be292c37\
            e7242d7e58e678a19349021d22f2712ea68de397b66167d141b09f98e3294e05b\
            51c1469bab3ddb7096f5aa2817e218d137879fb54dbe1659353e6e64add9cb2d6\
            f9e8647bd1ca94d9a6a80d193d76f115596f7bcc8a07eaf85c738f31f4fb192b7\
            85aa2934bcb5e4f6a7b444da2bc64da3527a33cc7f0792630f57b92ba07dd0e47\
            2d5e2e08b2bca8f1c06e18a07f226dac8acbcc1dfafe8be893d9c5092808b1dec\
            fbb955c5f82968bed609b0b2e2c55abe4b0c12bc0c7ea3976e0af2c6aadab3c90\
            ed862a9846fc1a1c20ef220a050538d3c9ff12669653f9b055606dd45fe66f18a\
            a819c8cda5c1b224dc19c0fbf028133d1256588834ea14cb44a84da3af8344365\
            7f9ff3eaa14216dc4ed06a92c0ce19be4fe066c9d830ee3acdd3062b9336ace12\
            cc5935953284946bf6bc5c89f9a13d37dddd63e85173174a164f4b68cbc94d347\
            b3d4a7e4ec79044b049375cc7b43b7657123b80f5834afca696b6bc7bf47fa677\
            42e1caa609424cba3ec9d9d156b5909debd0475d91d31134acce50420c2ea694e\
            2c2ea477a0bd14e670bccb42a0fb7009b41ee86a016d521c38ec1ea15734ae22b\
            7c46064412829c0d0579f0a713d1c04ede979026f0100000000000006fc000054\
            840300\
        ");

        assert_eq!(tx.input.len(), 2);
        assert_eq!(tx.output.len(), 3);
        assert!(!tx.output[0].is_null_data());
        assert!(!tx.output[0].is_pegout());
        assert!(!tx.output[0].is_fee());

        assert!(tx.output[1].is_null_data());
        assert!(tx.output[1].is_pegout());
        assert!(tx.output[1].pegout_data().is_some());
        assert!(!tx.output[1].is_fee());

        assert!(!tx.output[2].is_null_data());
        assert!(!tx.output[2].is_pegout());
        assert!(tx.output[2].is_fee());

        assert_eq!(tx.output[0].asset, tx.output[1].asset);
        assert_eq!(tx.output[2].asset, tx.output[1].asset);
        let fee_asset = "6f0279e9ed041c3d710a9f57d0c02928416460c4b722ae3457a11eec381c526d".parse().unwrap();
        assert_eq!(tx.fee_in(fee_asset), 1788);
        assert_eq!(tx.all_fees()[&fee_asset], 1788);
    }

    #[test]
    fn pegout_with_numeric_pak() {
        let tx: Transaction = hex_deserialize!("\
            0200000000021c39a226160dd8962eb273772950f0b603c319a8e4aa9912c9e8\
            e36b5bdf71a2000000006a473044022071212fcde89d1055d5b74f17a162b3db\
            e5348ac8527a131dab5dcf8a97d67d2f02202edf12f3c69fed1fa0c23da608e6\
            aded86dd5c7b09da42f61b453c3a838e8cab012103557f25ff40f976670ddf59\
            c71938bade91684b76ad69dfed27049de2afec59e5feffffff853db31f986dd8\
            9c81fe87a84f385d7099c5ea841d762b26b03166e5e798dfbe000000006a4730\
            44022042c70729fb50930179a9d76f5febbda5b0ee50e62febf92de4dd10b939\
            3554d802203140b107519243e4110c065017c8ae1ac04843f94b3f20a1e5faf7\
            343dd76159012102797ffcf7ccc8e2012a90e71962901a1ad740f2a28f2f563c\
            76f9eb42a8100f5efeffffff03016d521c38ec1ea15734ae22b7c46064412829\
            c0d0579f0a713d1c04ede979026f0100000000000f7869001976a914216d878e\
            bff0c623909889265d8dc1ab26e2ff4388ac016d521c38ec1ea15734ae22b7c4\
            6064412829c0d0579f0a713d1c04ede979026f0100000000000186a0005f6a20\
            6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000\
            1976a914df662e2dd70fd82acba2d252cc897cb6e618093288ac21025f756509\
            f5dbac47d54c9ef5ccf49895a4dbac4759005a74375f66c480e6c08651016d52\
            1c38ec1ea15734ae22b7c46064412829c0d0579f0a713d1c04ede979026f0100\
            000000000006fc000054840300\
        ");

        assert_eq!(tx.input.len(), 2);
        assert_eq!(tx.output.len(), 3);
        assert!(!tx.output[0].is_null_data());
        assert!(!tx.output[0].is_pegout());
        assert!(!tx.output[0].is_fee());

        assert!(tx.output[1].is_null_data());
        assert!(!tx.output[1].is_pegout());
        assert!(!tx.output[1].is_fee());

        assert!(!tx.output[2].is_null_data());
        assert!(!tx.output[2].is_pegout());
        assert!(tx.output[2].is_fee());

        assert_eq!(tx.output[0].asset, tx.output[1].asset);
        assert_eq!(tx.output[2].asset, tx.output[1].asset);
        let fee_asset = "6f0279e9ed041c3d710a9f57d0c02928416460c4b722ae3457a11eec381c526d".parse().unwrap();
        assert_eq!(tx.fee_in(fee_asset), 1788);
        assert_eq!(tx.all_fees()[&fee_asset], 1788);
    }

    #[test]
    fn pegout_with_null_scriptpubkey() {
        let tx: Transaction = hex_deserialize!("\
            0200000000021c39a226160dd8962eb273772950f0b603c319a8e4aa9912c9e8\
            e36b5bdf71a2000000006a473044022071212fcde89d1055d5b74f17a162b3db\
            e5348ac8527a131dab5dcf8a97d67d2f02202edf12f3c69fed1fa0c23da608e6\
            aded86dd5c7b09da42f61b453c3a838e8cab012103557f25ff40f976670ddf59\
            c71938bade91684b76ad69dfed27049de2afec59e5feffffff853db31f986dd8\
            9c81fe87a84f385d7099c5ea841d762b26b03166e5e798dfbe000000006a4730\
            44022042c70729fb50930179a9d76f5febbda5b0ee50e62febf92de4dd10b939\
            3554d802203140b107519243e4110c065017c8ae1ac04843f94b3f20a1e5faf7\
            343dd76159012102797ffcf7ccc8e2012a90e71962901a1ad740f2a28f2f563c\
            76f9eb42a8100f5efeffffff03016d521c38ec1ea15734ae22b7c46064412829\
            c0d0579f0a713d1c04ede979026f0100000000000f7869001976a914216d878e\
            bff0c623909889265d8dc1ab26e2ff4388ac016d521c38ec1ea15734ae22b7c4\
            6064412829c0d0579f0a713d1c04ede979026f0100000000000186a000466a20\
            6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000\
            0021025f756509f5dbac47d54c9ef5ccf49895a4dbac4759005a74375f66c480\
            e6c08600016d521c38ec1ea15734ae22b7c46064412829c0d0579f0a713d1c04\
            ede979026f0100000000000006fc000054840300\
        ");

        assert_eq!(tx.input.len(), 2);
        assert_eq!(tx.output.len(), 3);
        assert!(!tx.output[0].is_null_data());
        assert!(!tx.output[0].is_pegout());
        assert!(!tx.output[0].is_fee());

        assert!(tx.output[1].is_null_data());
        assert!(!tx.output[1].is_pegout());
        assert!(!tx.output[1].is_fee());

        assert!(!tx.output[2].is_null_data());
        assert!(!tx.output[2].is_pegout());
        assert!(tx.output[2].is_fee());

        assert_eq!(tx.output[0].asset, tx.output[1].asset);
        assert_eq!(tx.output[2].asset, tx.output[1].asset);
        let fee_asset = "6f0279e9ed041c3d710a9f57d0c02928416460c4b722ae3457a11eec381c526d".parse().unwrap();
        assert_eq!(tx.fee_in(fee_asset), 1788);
        assert_eq!(tx.all_fees()[&fee_asset], 1788);
    }

    #[test]
    fn verify_ct() {
        let secp = secp256k1_zkp::Secp256k1::new();
        let tx: Transaction = hex_deserialize!(
            "0200000001014166d8bc73e9f6bf833f6372b021d6e412ae773cdd722467db163ff06d1e1fcb0100000000fdffffff030bbc8258e21ddcfa93f8b13e26675ce0696bab13e48b6e570087d27b8c2e58229108a6dd1a702dc30f897e040004def8dd2e67b7c6567a77b7c4d88e71d837531d76021d91021fab6f42fbae69c1ef0fe51ed088f08f69f9e658c5f702ab8a512334cb160014bea76c13404321e84760d712218e455b559f2ea20b637f6c0c63b8403cb889ee0502f2b4d8f391b8230798e938ea0aff882758f5fc09674f64e8313722b6fda15d4e3be5845a2c8fd7a243312413f026f6dc9541bb6e031465dee3abbf0059ebabf7933cd5bc8725a8e284f9f2868df84dcd78af6e15741600149928d95e500cf680ab923370529b5110b4c6b35501230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b20100000000000000f900006f000000000002473044022018a96048b7b3d732fe44421655a26c076a84adc9b0d210856734ef52093b0ba8022045f3645b9d9f40a47963f56c5fe599a23079bd14fceaa2432750a235c623485e01210232edc2082acf05281c9ddb1d8e024de805ae65f6547848ea34441c09173bee3000430100012bfbd82937b25fc506c0b016d904d63eb15301c8fabc6e796549f0383cc08c7effd3d398b04e4feb1279f90f7c32d9a87907155514d69f9612b059f6fdf2a62ffd4e10603300000000000000013f2817003c824b0c690dbde0739e2e1263411a92287701d3bcb9917b2562397755e3945a5f0e917e4eb71b9245d225abcb97a43c7c8bae23fe9b389991db5e693937b2dc225072e5177673ba18545a9dcafd1f550501543ca45d11eaabd2769e49bc5a26fbe64eedaf38d56ef5f6d5cbac587c97c9846a6472a0525104dbabf24d34fb3db29244ef5dce6c9b71a12d9bd48bb796f6b4f89c1130e767ea70842402a1d1c1e4fa2ab18db1f407587e2b5ecbfc34c05b5fe5d10ab43fc9fda482ae7b08eb0115e9758b9d14de8f8d567133779a6153411e32456241f149e0731dbc263a5831317bb394a0efbed52cbf121abafce5dcde0949b619dffea3a942e0ce237a4725a865f4d3a7dd18f6c3baceefd2504fe03d898687ed44237e6105a237621a71f68a22d43ade7c59e14ebc5ea93e236f29b7d8cdaf933c8dc2df72dfd4b74c4469ce34a263373c7154ee89a66387bda99794ecfda0ac03298f1be66f60a67202053fcc98eea44839f8f6e5e0aa3657b72bd54a236362222ab91b5bc0abc7bf1b19138dbead02f904e0417b45699fa3699f7c8af319db491b7c0990a119ae0fbb0591e5c1185c50aa6b8a6ee85cbb841bc4fb99164e0b4d0e18fd8f61d41e05af83c4e94091256f27fe2838d8b44c657f0035c11c3c7636f62e0e3b2188faed87daa23b01f690a0712a06f06f464be8b5ae955f3f880f750d01d23c3f6ee7472b1a8508b0b7a200675dd347c14d520e77f7d61dc28e87f63129aeeb15c32fce6fc109ea7582bedef9594685b8290ead0fec8f7a0477babf661c61d7e651b19b46a59b06d92472ff1e30033534acfdc6a23bdd287e0582d3ca45be95436120ebae081c0c81da96d60db6870d02e386e5cf0ceeb0d5d746ab7178f9297c47be7d9fae7b73eda435319ed7865fd3357120645cc46bbb8ab4ff58fbffc3252888ac7e1bf6f61ef113c1823e38494c2344897f31f65374b13b677656b37386d95a66089b2d1c557b6f70d0354fb71a903c530ead4a0199d71052f589be243ccbc890537b9412f2d70a4d9585c8af6af9844f403acc40ff8633bd2232c032fff6538aa45218ecac24eb62a48f852b91dab12efea26f2b96f368fd850da25ba319d09289df0ee8052ebc0e39bb006966cc51757a3bc3da2a7483ccc7b82f4b13fdc5222a72f60bb750ffb469fa1821cff233ce8078676a9c8dc4cbdd89337275af2e51fe5351d7ed81ef62dcd944022da3ae3cc501e777d567217b21e13d8f1cc2cfac2d8494343e3b6ae80cff461ea20a3604bd41b42d2ead953bdbd75170c7129139724a6669ae77ac234370625a9533168bc1cad48839ef2abe517d2955d75b5d573e6b6e52e5342d9b6d9e2ed5413bd2cb8190fbbfa22a090da3eb462a886e2c2fbc076fc47c8778d3d10b15b7afdc2fd8886b4f85a565c2f517005b125df57a444a4d2528b7d3ac67a56454fdb2fc764f29d6e9fa8ec0bfb78f562ed9331d24f541c03a51628a932457e0287189ea36a35be4d01577e7a2a766f2081366840780abfd2aff20a9d4cc826fd751fbb0e7b353d518a3cd90bd61e694a7645a7859e21532d8f9759d32804c3341e41164f8815a38411484f4b394db6a8150591faa9d37cc76e812fc2b6cfb1e605d91552a31fe88b9d18cbbc7d2e558db74987564209ce126241c38a80da1df34db585a9d7a1330080cb16fdaf9ec1c37f309a8a0e2e7748ede59e7910b8b6b5caee51532ee6c5bd851db455c150b8d90445a36fbac9858798d73abf605dd0f515c23a0f975d50d09e6d7f541f0250c23c414219c87b15929ada1974a71709809db49ad8cab72958c31b1ddd0064d264641327a433d748713c57bc0063ec45b852a9beb2cc2be7465bd48b3d113ecf3d4981f2e3ddc7494714d21b860eb336ab91e894af0a5ff727f2b8d85c12f7ed321c90038e8f26f544c4918562b7c65e7cc1cecd5c6961ea2d1f806268d1dca92337f127a03c2626fcac5b8caf0a7abc3a6cc4d362f040572b56c5ad09e0dfd92235dbb2c1a8fbccdee13b2cf55681ec8f053575214c9200bee18428b25440b220079ca8708d23c84927103a8afac4bee58b95cce012ea23b175bd2a12636afc07e649675568ef945d352402f222fa62dcbad7f9f0dae132c089aea82d4c8b905655943e8b61f55475b3c3755d5967b01236e2c4b833ff6945031b50f0a68f0ec7130055761f8e9c2ebb2c9462d0b8aa9e99c7ebed1d3213abc471bbd49f44e78e057c750590f3ac02d3baa776d9f9ef39bc1a166dd7cb1cc3e63d94d7bb51544b9b02ad1278f7691973030612534ff513d2cf7988b3235b4449976b90fa5932639bafb7d0d33b58a167617ab4a46189e251bd488cc36a4b40968aa34c20a80f3ee5380152b7dd62de83c1e2a07307861b3713506115c1021880c19f89f45e40a16cebfc1980ebbab7bb9288eb33d4696c39bedada35a41f9e6832a0f5e12f2968303533c8186cc09da7c3ce4e96410f7a9bc5941706fd513a908ace16cd3605c5d0f4b872e931d79361134371285b6d223e1601ad129daa776ab58cb4dc7eaddd45cbf722d4cc4229d75a52e18c7470ed1a7a84671bd8bca4b9bdb0d7b0a34779d1a538fad3b6e2d7cc2972ab1bb98613b8ecc27f9fc25fd797aca4e5d0de4aa6df7f6607ad268baea41f3c1f9afc9dc5da929b29e4ac203a7476fe2c185ac25b835b6f2037c3f540852bfd2d643c179e0951cebc35743f6315a56d2965de934695ef5dbae70924f8548a858518340d7add64f45d2c7b69bfdbb8fb640a2284619fa857d2f5f8bbf615822e45b924622d32e78caedead8ab69fdfe142c97d7fb61af8cd32767d1006c6331d316e0e66b112a765388ff027eecd1181913ef9c701f2a46d0bf35abcaa3fe0cd26863e3d65ded79b262d1e914c538ae7d05ab30390465ba25a73a6ab53ce4296a3f5cbfd3901cca44bdd6818fa8d427ab2ceddc315f0adcd3fcae63074ea9e42f15fa02f1e3ec6276adc953beaadbce84ca6ef04966c882e3e7802436e4042fa5be4c3773d685bed66eec0c5a6cc463770c00740fef403badedadd28984e22027b38a0c66b7a409080adea574cb95ca236d701751056f7ea1e1b3082f0a26acbc630526053be88bd88267e23c2787daef884d709a5ac2c118c8c8b4b1eb6cd9d829ec42d9f249f754cf93b6c4cfdcf99cec0f9d742af36300274df095a35efa8ba95d412d2e61db8776660882519d4500f615e6a3e88640e93e921dc1fc4b74b5776cfdd47eb8b00d422fb0ee5c889c419bd352cef4573dab05fe44abd39bb7014e4ad0af6e5c9ed8236edb16d05057a6794ee76e923b6d1bef5e17e7078f6696af0f23064b1a592e89ff7073f040e9ea236450fa8d8fad6d04606b1a1a407ea14868b0c81c76c0f5fe9047e9c60dd150f9164533a7e4cbcc87f5c58e9e9ce317ce694cdd816b45fc497ec5c66736050ba925fa7ec598274f23a4ff022e7970dc520e4baefb30a26a5464fd5c75906e88a2c245cfcf00807c3b5e0deeb463886d606bfe7f30b73a512c5488f7c586dbcecd03ecc6cfc3caef921930aa01d2ca21ae3acfe5af26003acd436c344f80a4a9d9371a51b5b19b984d12b2a134f2ed89a6c5cf9905b2626d926bee7fd39988282411a0ea0ec1b61c22eceee21cd264c1fede96d9460cddc0624c9e22ccf42ff18bb13f8686bd6ef528aeda6181647a1c6c6ebd90fe05a69cbf169a971ae616d9d74840f1a7a3cc48c7a27b07a14e58bace67aa61dc594f0dc909283fc39c77a5dfadd50a358fc2c05118cb6197f3aba31d75fe2681219bff02e70f6d968f99d59a6c80a2af8bc09c21a2874ecfa47850844221fe066a1e6b40c0c5c4b59f8a8c22b78419c77be2306a9e085a76dbf9552ac9a575b872df0f9834f7aa8d89d585ec34ddb7c1d76c6d132356679263c8458a288c95f36631ca460ef925fdd9801154f886beae75dfb5e794ee58813cd1748e932e279ad65a3e2e894d190e221f07207d6ab5d2c7e328661746bc12e72d6075eb2a4e1f91a3b27d3309f9825d2467aef6f5236c38b071e5a6d17e3a7a88033a3ddb756e7aceb2c7d4fcca92a077a110684337fd8222f9c38e806554d30d9c3fcb647faa000f72adcc8e1d6c811634757a74b4d52f9e47826319f3954756d0623149a9f62f838feb135b1d26fe00e299a96dd94106fd39c9aa14360792870f33b8cde870e98353b27c1bbff569b79ef1d5f0161a4b585f4002b42c970b3e84912bf707c8d49fe56adfca407f8a039314a5c0720060061ace5a8144224bf52d5458e1fff84306c2c88b86061e18116a8b46cfb2adb6b33f704ae6d83aa2aac13bcd61b64c93cb6d2d5c3acc990626f891f9b7befa0f25c1a2665290309add936ff62d4fd182d68adeafb49f75fea798d8572444253886bc936589bda972b5e5625db267de1b30a8501ef215ab8a320574ce27a33fe603a67656ed8744f048b022cd61c132ece087fa0d94c2d4dfbb92a46ea5403341df3896ac49932955c6b3d700bc475c9d173c6173c8d883bd9499aede17e7840294334f1b0585b66f00e121ca298933703951801584c5db57854ef87802d254fc75d31319b8560f5ebee2ea80ffefa63e2a4c4e3d53b007ca18f83539f3078b2736f4fb4f8fff41823912227b04bab8aeeb7d95eb0db3dda58a98077f25e1db6dd454cfcd41068dcfb54f1d1e0b478013e58ca7efe874e98205d7c59ceeeb28cdd55cab4fa3a01ebaa957effe330364f75c0d6728b769dad34e58e9f217d1e8e96d79d896c193b425236ef2303eed072d114c06c198fd6a12a28f4d436dd126d1ab98c7e1621e0f59cc7276dbe7cf267ce2c6c0ed164deb57039fc5be8ae4e72efe26115e0fd59ae6fed9743eebbea873fca30c9d7eda201e73fe22e509b11c19580d368bca3f4cc59b949c8d03fa63e7b2b79f39983235d7ea3fc6fc92fab4c66a7680ec57f998fd818db6fa88ac2913f4a48a4cfbf68f1f565f799a6a95a22c8f6a4d6ba2a5307e51c99d22bcdb399520306446a6804f7cccff394986341187c4a72813392984e57ce3cab06c540722e25be50ba138ca0a54686c8960e2f6118380b3b9255d14071b1e2131d6cda16eb463bc4642cc11391a7c8a75a6da8c5f1424f7752ca3dbd37f2d9a2a3855f3b3aa7104c7a5be0c334df618dd478c43b9bb0fe7d774e93cbc8323816e1f0e1290e52079009150761207d99b1ec995ec7897a0385513abb96ec5f9d2c757662cd946d8e340646944b5fc6cf92f606ed2bd6872fe89c1cdabfa7f755b27dadce1337a18ecad4b78c0291f34e1cf0577eab17c70b05eea58bfb7bb3cdb46d46507db8fe8cbe3dca07d92d1ea2c5a6e354cabba8d532a47f6d9ba6ca48add4df8bf8ebbf3ccf8b0417f4b90756faf134ee210511d40314f218f9902897390fb0f405eabfc4a7ed4467e4fd14edd3ce4ee0337a5f0c21590816126768d5a85d67c8a7ef6b07c8d40dd13978cecbbfff0507d6030167e01bfbcb3557610ebad49f2f98cd9e003d3fe0a4dbc64d4202d4260ece552b7f7dad2be1dc61e3e7fbd5ae5be1f9bc0599807727c1e30eaa6d80ce79bc6d5a28c5c3efb8c1e99ffadde8ba7f42c2f27e3fbadec5b13e8673256b2aea4ea1a7b92d909ac4fd06fc3f03098cff0667224949eb1fc242ee42da5a9a06d93c5c4896e3c54e8815602d2a42c4bcad7a597e9261d24a404ba0f4645eb68f0521b7eb73d7b26ce2f802ba54674d011c07c485c1f7b6e31197c40a39c53e94cbd0b3de605c76ec9d7272a53ea5547b2131da2b51b2b0c099bc93214f02c2469c396dbc6fda284126d7d069fc3d51750037e545cf2ffe35b308d1c515870bf0fb062c2c666367061430100011850912d035bb6962d10e126e5a9666eb4128d7fefc4a0633ba0f388c5f28302a7a2e02653aebda6a6bad0cbdd972b57201a14a7f879c480fe5e1c36db90f749fd4e1060330000000000000001bdbe9301cb099b5fb8baac78310a3529d6677700658a6a87eb00a5f66dceb0862dc11cdcf845e07ba63ea84308200d309ffc3211996c507208560b7f65fa70f0a176dd0cb179ca911797c66d6fb56d27728a4fcc9998919a89c52d8bded3f732a5360861a6639c839f39503ea1457ae5d4ff7e1811ac2d33047823c5c118768343620abe7fd8cf459e5fca0f490ed91d9c09b37303662c201fff61247e8fefed8ffb29f999cddf601670469de151617021352c0dfe54512bc44c3b8e1a4ece73d2eaa727b28093d4741bd01dba0d9c7a4cb69e8a63bf6e887fcf6a57812ae40fd829dcfb6bab3a2a4ac678418e15179613f2436f53ae806ecb8f44115847b16cf935efadee467aa6de4a0cccaf8e4b1835b8dd1f9d04f0bbd4b3164dbc58a3a10db4537c94bafeb0289c6a192b28d5ba48df580a44a0d044ba82140295bfae70214127b73c7efac419bccaa75716867bc0bc75171e54dc3c439635d832cd052c4e9fa7370b1794b3da8a1a740b50cbcc605dc840f4d996f1283018a6356c437e79218a191ec68a48b193d3560b690d44741b354b13320ea16286405dc6476e8e8231d667978ef9c36e84f09e74387b4d557e39a40f51a62f70b5be58415c256f262486fd144489de4b8605a0d53945ed08daf543f3fac38888dcd4650903b95ebfcb4e0f57ca89b3f0132400e4012e00854c41b2788bd7c0d5d40845f48571d954e12013f6cf7ece536f32ff9a3c94ed10f1a2fd50b3f38a0f1272489d583deec9da33d9ac46914efea240aa004a8f17e1e168136b4ada57309b91e10c716eae0a5789c64747c0e09a696b67e8c7bba12c2b8d80248da93acfc7c1455a33b40f8761fd37812e74e572a9a21b0e2d7bc37ccad146d847a53d7a650122d96d00b179e353db2864e5ec929173550e0edf2c02b2ccb595b326582758d700009f4c433cf86837d1070686a6eeee6f4ab1e6ffc44bda783d7e2ff81f289991cdf982b61a73660020e544e5897c3021a446c8a4966ca625bbd6bfdc505e85d1f5acc663607cc2ba18945b74662be550b215878b35d9932f11cbe509456461ffa2b3bad33405f51c5b17b5081bbb4874c2656e0efecb2647d22028e53f263401e779e92ea3f70c860b0405e8109e10e27c2f4986e66965f4ddb895b943ba4dd0315372ac0460f78ec408cd562c21537d7f0f5e12c95e3d86066db77390b02e9073e241aa97af7588bbd6fa967a6776a3e226c0e56936fccae5ecd8aa20af1cc9b74a4579d8bd4fba988438fe455da8261f9aa96bf222e5af2fe297ce1901f0845334e856fa928119e23cc64f5ac541c699befad140a3e2cf53f591112d1ae57391eecf6fb729654fa98ba946ba8a532c3cb8b0dad5f08e3158f128cb065379b2ffc78d8394e5d2f1c7f4fa7b8a5031a7053f0144835e7ef53f4d60c8953bfde31e75fa3ab6bab86bc37617585db21f16318902138c1a7c25db16c212bef0de8aed1575e1c8e1064755b4b493adaec2dd320f8f8b9a240352f7a8a409ff3ac3beaf08114ba7294502f8f0f529e039ac7cda8a9d8e45b9aeb4e7a83d2de5a4edcb363a15020a5d285cf6acc3f43dfa724fd6c8ce76c33d485db88cdf379faaa7a0eb65f52c99daf2fb0edd8eed2e38e2990b044bb4ab7cda75d23b04fb72e842b54d88ed8a7ed236f61ce58e7a7fc34aa94e9100157cda06dcf81722058369df2b912442ea0768383b7c673f239a7f56dd4ec8739cd14698000747b979f22852e72352b0287fe7c0bddb68bd494341a0cbbd0df4fec1d613f7160f8fae32b9009c4d7146a8004a158763efea270c6724d022bd3d5954789e2ebcb50663b98a619182d800263485faee5e621d99f6819068f6d032aba95f7294aa6bb297f93fbd0e1def781351fe5ed7330ffb203d48aef9c6e6af244cca568dd164226131343f37977f11a770bea7f40e8b0593f5efd23ca0ff18594512004a9a34582de5ecfe06519f6223b5576ba1492d817e6da30791abfd2f4e85d235fc16f43ffa1879afd6f3c3aa252a232d567502dbdd70005997da48f8a0c64911af8ba5e8c123a3e81247de4a536ef41330d345c2681e1a508e4accee45140a194a1eedbe6559e67a9daa34580f00166db39d3f6e92d0b996754bb1d8cd3d68d692b872a0e9b086c14c1d143e03ffe5279a6687e5fe139534e59d43e2204ad9794a38a3d9cc9e63245c89123977e66dde7e33800f62a9ab3aa725b09670cbd58890056d62b459473ecdcca375d4784f278042fecd626c635414ed1ed1a1e2cec075d1a495004debb13df0c61e0bfc2f10ac84d94c404400559c6b4209fcc4fd0f4e041fc5101fa8265478fb794e7c008af8172d267e495d314d65b9dc1dc3ede3be27e4c80840ee7b75c31355bb4c940049bb0e02234370a2cd009753983409d87604ff5bd2d179061f9629be6663ffad62e3aed59de373892140475cf491a6482da6d9a1cc1031b4fce7737accce613a01fccaf36f0ac6fe1323828f3cf2a3e8c64cd0f95916c3db7176200e8f6384e6527f8020a761c0e46d388c4c1424118a69afc6bc5884d9ca3a19b5a65f95d3cc476b1f8e1c7bd41969b0f42d6b121816c1f3ebcff888c0c93d582d6f9b1bb5acc1cbdef4db323585ee059b4a68b37dd6ec85fa3a7bdc0ff7cd5e903cc76bc6a30b7965132e551bd5ac1c11ef069da69064086baa14435a9492444619dc3df5466bfb2cda341ff630d767ab55ec2bec5f92fa0e23cd8b4a5386c85cf540fdc4a15e9a27f7ea48c29d92a58c738eb2133005ab4b787d849acca740d58d258e5fe32dac3f2499773ffe3b362cb384632a8f24b9380c1ec1566108052ac157691ccdfe8ee497c57fcb8db7799ff2688288f07dcd7af020e3b21ce8ce9a730fa23f88fe2ade8291a439fd3b5769ff98284e042a1d795b1920b10cf755d3073a7a8e7f9b78b62baea353b77fc4be39caf38c709ad8c548432a7ed102e114f44b0ff22c7c04d4299f9d47bd81172385ddb1e5c9019809968a7638bde0b766d63514f85b22b1a795fb97b9c367b9693299c7447630e333265faf35ea516247d1d1ef7f9ded1219f9cba746100cbf6470becbe5e73fb817e7979bd1d502e9b7ab62bd70a70115cf3f9eee4e7ba131040a4baf9139e7bc6968b0053075f75afc787e2a083caff88d5b627d81d5e8584bb30334211866dceb96a2f03db6734e5a8cd28d4000119a55e32ac45dc38080c5fa05200e0054bea35713648f17634b6954b7be38e38fb29c3f5251f33c3f6531855f393fad9568b3f3ee02fdcf02f2172de1f8007a479d235091c4c39b76941bcf563b46e32248f9adbbb247bc62d552c5444ffdbd0cebf3e5a08212400cd7155236c21a410bb1dc9aca0f82b438c5e1d2c1632c577801ca18d30371e39efd3135092d008e290dba376f799a85dbfa317e9490bf2ee52444567ef8f74c5350e69331c03d51ddc8151822656cf7bbc054dcf9a5166a2bc72b01c5778c4c8f3076343ec1a6f7f3380d3e19bde7c248b23789bc724af6fe17c2173b0c204ff8b6342e5c9bd8f652ff0c80077fce0ce258b0879c74986f5d51e59eae4b946de1e2b785f039ef9bde314753011e35dd9ab9278fd95e4b10f04b4a157a16a6de9ba5a1793a4be0f2e2fd3cf2fd9366b2b7cd358f7a9a9397899833839c8bc968c5c37660488cf391637702de780b5ac526ab11fc895a5c783931dd0d486cc7672f417ceb30914b8f6fc51d270c932c81c7fda22b2b88ff14f7c9285f6341053fc529aefc97755fc5962a5e094b10291b98c991b0bee8c28b639f642bbcbd7c27d9217c19e11a94ecd58bc79c220feb9f1799f952e8a31b9607bb9fc4ababb8515aed1112050e0a75cb5c7811a63b90eafe411e92f2864fdbc4f23ac3c335d300440f9b6c0e7402a825fd5f4eb32ccb76ae4ef43441282356cac29b0147f780252427c9d21abdf7306c9f2836f599cef0a2c2eb4596df9498d661bcf8bcc88d5a7f0779489f9423ad045b735e421ba0f861744beecb7c1efcb5989386e9c2e4e07ef033ce75d5e3ae6b78775cbb3d5ad8fa5b29ee2137f6b59f865c71af63ac98c2f0cecaec428c773a747ba188f8f3dc30ede05077b422a920a313b885c31d247328c691f66a7440bb27581baea7d9365f8da23bf71a7cbbca02c74391928daf1f6b2b0f74acd3b89ad53e3dc87aa2716a25c89c4a6f1a363cbd97745910e399cfa766ddc5b25fe4f40412690316acab688493a1c882ccabf7ba2b1496f77ba6a34133b3a6d9f5c6526309f1d2e14c261959dae012420bf9fa0aa2b3e3862308f6c6f65e7f0660eed3b5fbf3278eb5b2893b1c8dbef827e7bee0fa92fad9393f037c4b90babf62a159e2637f22a46a18bee1baf9c4c3344186083b167de5936437a5fb379ae305e8a502fc22f849398daa9547c8f6c2554d231daba90a5f729069c24bdb2b749cd1a16489f7c0940a59ba7f324dcb2c42e47652179208bfff6d64a1ac5e557a34321a4c3bda6eae6f461e1a6ecc9cee9fbf36e2b6c504ae2e0a3bd03235fb6032725280d64fa1a33f58a7196b56c0a65dc7bbf0a429889d0ee2467796515f857800c78fe21bd17f65807342a7f4a0a7926d064f073d1a7dc76295b9e35195b7880fd83db7e2335709179cca4f285b0b14693fd0b6cef9958cc6906adacdf1ad1b572eaf9e6ef42b574d75a1f58927d49113726572b40bd792b6ca621daa7c5f56645b1f8ed5b0a7ac26f71c4c665b89b975b3c38ed6949271df097c8018e772b2a3f8bba41424bd9c1b06e111cfdedbac883dbdc5345e5a6aec531c722c94b0c6b072288b706afe77a6e179fd38c7f6a0051246f0b161d0a5c696374755b01822181bd843ee8d4f476ef5bf3efbf9cae0f3162ee5de88c0aeafcb3b5fb34a7edaad5292428a612eeea80a54c0dc3ac1ac7b00f103aa39015a038d4537271bdc277e4a8f8648797b6a67cebb7485625406f9963d17b51d1f4706674e58da1b5e4c415eb403791c72a62a2e6a5a4cf50d26fe78d7e9620c50f718dbd0d075efccbeb8b731f8b1ecc988f2b38dce9cda9a644441391728a47ccd8975dac442c39f59726802474ec44a45afb5e545512e8f069e139da079c6e0bafce31f30bef474bb2deeeb6a035ab37757b02d6f4de3ff85a0cd5109290259c1be2a8288a33dcad5518d9d0413a393f659095beef0572193af15d909acbff828b56adba008a3fdb653ee5fcb5653884ef69d8f8f6588b2b46a3dd361dd4983d205d22f9351f4ebc049f867832b35181a70f390158a2960fc9bc2551e23925f2c9a262b7b9e9da6c97f35e5ba21986f5cface9e8d829751921a9e6fdfbe084197a97a778c795c0a9e293c7a07033ac2a34e0f27ca53b4cc7833fc7682c0da1f5784e812e4223933dc2b4b20f77c4d01c40c4f7db5a556ad3de59605e45c02928f5b8a7720eb83f750c9789b062826bfc895ee526f0c813d3a3bdc3a6a03c27c9f3eeaec747bfa72c19da03af860ea21986df7c0509575c2b7f47f036758d9777e6843f620084bafac9c6a2f7910f703c8dff42c9f160a15d852cc4bf2f33b1b53c392959e804d34a3b56c1bf47a4813c7d67d36e66859b1eeb8f105c79aadab1cd2ea927cb9cc48a70da61241b5e3d3a5802c3ba003e7d318628f6a6a37725b6fc721899b30c9dd2b3d6f18d70df0f363ddac2fd3cc79fdde2ac26ccf16462534ba1a8d1baea51b789bc00226febe51678af19898e4f4456f072e5d79345323f8231b085b94419dd812bfae12c4defd363fa4baf09c4ceac1d543365ab52f230925f56840efff264b3b8e961c8aa8e62a8f3df6f204331a1dc08375c6521ebede7a0eaa92d378830d11a989681bd6e07b7a870195f4c2fb579a800000"
        );
        // let asset_id : hashes::sha256d::Hash = hex_deserialize!("b2e15d0d7a0c94e4e2ce0fe6e8691b9e451377f6e46e8045a86f7c4b5d4f0f23");
        let btc_asset : confidential::Asset = hex_deserialize!("0b37d4818b8ce1df5d3d0b88d140c6848029d6d85fb0f6ee270865caf53d0b82d4");
        let btc_value : confidential::Value = hex_deserialize!("094e2cceeb8005ac14b611821c37fca757b47426afb0bb4eabe41c275d3997c046");
        let spk : script::Script = hex_deserialize!("16001475f578ed4f7a0103182a6e92942c66350dd949dc");

        let txout = TxOut {
            asset: btc_asset,
            value: btc_value,
            nonce: confidential::Nonce::Null,
            script_pubkey: spk,
            witness: TxOutWitness:: default(),
            // We don't care about witness here since all the blinding
            // factors/explicit values are already known.
        };

        tx.verify_tx_amt_proofs(&secp, &[txout]).expect("Verification");
    }

    #[test]
    fn genesis_tx() {
        let tx: Transaction = hex_deserialize!("\
            0100000000010000000000000000000000000000000000000000000000000000\
            000000000000ffffffff2120961454ea0955421873d61bab197d814b3386fde2\
            433c90bc1621ca1ef5462fc2ffffffff01010000000000000000000000000000\
            00000000000000000000000000000000000001000000000000000000016a0000\
            0000\
        ");
        assert!(tx.input[0].previous_output.is_null());
    }
}
