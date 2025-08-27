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

use std::{io, cmp};
use std::collections::HashMap;

use bitcoin::{self, VarInt};
use crate::hashes::Hash;

use crate::confidential;
use crate::encode::{self, Encodable, Decodable};
use crate::issuance::AssetId;
use crate::opcodes;
use crate::script::Instruction;
use crate::{LockTime, Script, Txid, Wtxid};

use crate::{PegoutData, TxIn, TxOutWitness};


/// Transaction output
#[derive(Clone, Default, PartialEq, Eq, Debug, Hash, PartialOrd, Ord)]
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
    pub fn pegout_data(&self) -> Option<PegoutData<'_>> {
        // Must be NULLDATA
        if !self.is_null_data() {
            return None;
        }

        // Must have an explicit value
        let value = self.value.explicit()?;

        let mut iter = self.script_pubkey.instructions();

        iter.next(); // Skip OP_RETURN

        // Parse destination chain's genesis block
        let genesis_hash = bitcoin::BlockHash::from_raw_hash(
            crate::hashes::Hash::from_slice(iter.next()?.ok()?.push_bytes()?).ok()?
        );

        // Parse destination scriptpubkey
        let script_pubkey = bitcoin::ScriptBuf::from(iter.next()?.ok()?.push_bytes()?.to_owned());
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
    pub lock_time: LockTime,
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

    /// Returns the "virtual size" (vsize) of this transaction.
    ///
    /// Will be `ceil(weight / 4.0)`.
    #[inline]
    pub fn vsize(&self) -> usize {
        let weight = self.weight();
        (weight + 4 - 1) / 4
    }

    /// Get the "discount weight" of this transaction; this is the weight minus the output witnesses and minus the
    /// differences between asset and nonce commitments from their explicit values (weighted as part of the base transaction).
    pub fn discount_weight(&self) -> usize {
        let mut weight = self.scaled_size(4);

        for out in self.output.iter() {
            let rp_len = out.witness.rangeproof_len();
            let sp_len = out.witness.surjectionproof_len();
            let witness_weight = VarInt(sp_len as u64).size() + sp_len + VarInt(rp_len as u64).size() + rp_len;
            weight -= witness_weight.saturating_sub(2); // explicit transactions have 1 byte for each empty proof
            if out.value.is_confidential() {
                weight -= (33 - 9) * 4;
            }
            if out.nonce.is_confidential() {
                weight -= (33 - 1) * 4;
            }
        }

        weight
    }

    /// Returns the "discount virtual size" (discountvsize) of this transaction.
    ///
    /// Will be `ceil(discount weight / 4.0)`.
    pub fn discount_vsize(&self) -> usize {
        (self.discount_weight() + 4 - 1) / 4
    }

    fn scaled_size(&self, scale_factor: usize) -> usize {
        let witness_flag = self.has_witness();

        let input_weight = self.input.iter().map(|input| {
            scale_factor * (
                32 + 4 + 4 + // output + nSequence
                VarInt(input.script_sig.len() as u64).size() +
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

                VarInt(amt_prf_len as u64).size() +
                amt_prf_len +
                VarInt(keys_prf_len as u64).size() +
                keys_prf_len +
                VarInt(input.witness.script_witness.len() as u64).size() +
                input.witness.script_witness.iter().map(|wit|
                    VarInt(wit.len() as u64).size() +
                    wit.len()
                ).sum::<usize>() +
                VarInt(input.witness.pegin_witness.len() as u64).size() +
                input.witness.pegin_witness.iter().map(|wit|
                    VarInt(wit.len() as u64).size() +
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
                VarInt(output.script_pubkey.len() as u64).size() +
                output.script_pubkey.len()
            ) + if witness_flag {
                let range_prf_len = output.witness.rangeproof_len();
                let surj_prf_len = output.witness.surjectionproof_len();
                VarInt(surj_prf_len as u64).size() +
                surj_prf_len +
                VarInt(range_prf_len as u64).size() +
                range_prf_len
            } else {
                0
            }
        }).sum::<usize>();

        scale_factor * (
            4 + // version
            4 + // locktime
            VarInt(self.input.len() as u64).size() +
            VarInt(self.output.len() as u64).size() +
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
        let lock_time = LockTime::consensus_decode(&mut d)?;

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

impl cmp::PartialOrd for Transaction {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl cmp::Ord for Transaction {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        self.version
            .cmp(&other.version)
            .then(
                self.lock_time
                    .to_consensus_u32()
                    .cmp(&other.lock_time.to_consensus_u32()),
            )
            .then(self.input.cmp(&other.input))
            .then(self.output.cmp(&other.output))
    }
}

