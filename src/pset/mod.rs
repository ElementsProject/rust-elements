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

//! # Partially Signed Elements Transactions (PSET)
//!
//! Implementation of BIP174 Partially Signed Bitcoin Transaction Format as
//! defined at https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki
//! except we define PSETs containing non-standard SigHash types as invalid.
//! Extension for PSET is based on PSET2 defined in BIP370.
//! https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki

use std::{cmp, io};

mod error;
#[macro_use]
mod macros;
mod map;
pub mod raw;
pub mod serialize;

use {Transaction, Txid, TxIn, OutPoint, Script, AssetIssuance, TxInWitness, TxOut, TxOutWitness};
use encode::{self, Encodable, Decodable};
use confidential;
pub use self::error::Error;
pub use self::map::{Global, GlobalTxData, Input, Output};
use self::map::Map;
use secp256k1_zkp::ZERO_TWEAK;

/// A Partially Signed Transaction.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PartiallySignedTransaction {
    /// The key-value pairs for all global data.
    pub global: Global,
    /// The corresponding key-value map for each input in the unsigned
    /// transaction.
    pub inputs: Vec<Input>,
    /// The corresponding key-value map for each output in the unsigned
    /// transaction.
    pub outputs: Vec<Output>,
}

impl PartiallySignedTransaction {

    /// Create a new PSET from a raw transaction
    pub fn from_tx(tx: Transaction) -> Self {
        let mut global = Global::default();
        global.tx_data.output_count = tx.output.len();
        global.tx_data.input_count = tx.input.len();
        global.tx_data.fallback_locktime = Some(tx.lock_time);
        global.tx_data.version = tx.version;

        let inputs = tx.input.into_iter().map(Input::from_txin).collect();
        let outputs = tx.output.into_iter().map(Output::from_txout).collect();
        Self {
            global: global,
            inputs: inputs,
            outputs: outputs,
        }
    }
    /// Create a PartiallySignedTransaction with zero inputs
    /// zero outputs with a version 2 and tx version 2
    pub fn new_v2() -> Self {
        PartiallySignedTransaction {
            inputs: vec![],
            outputs: vec![],
            global: Global::default(),
        }
    }

    /// Add an input to pset. This also updates the
    /// pset global input count
    pub fn add_input(&mut self, inp: Input) {
        self.global.tx_data.input_count += 1;
        self.inputs.push(inp);
    }

    /// Add an output to pset. This also updates the
    /// pset global output count
    pub fn add_output(&mut self, out: Output) {
        self.global.tx_data.output_count += 1;
        self.outputs.push(out);
    }

    /// Accessor for the number of inputs currently in the PSET
    pub fn n_inputs(&self) -> usize {
        self.global.n_inputs()
    }

    /// Accessor for the number of outputs currently in the PSET
    pub fn n_outputs(&self) -> usize {
        self.global.n_outputs()
    }

    /// Accessor for the locktime to be used in the final transaction
    pub fn locktime(&self) -> Result<u32, Error> {
        match self.global.tx_data {
            GlobalTxData{ fallback_locktime, .. } => {
                #[derive(PartialEq, Eq, PartialOrd, Ord)]
                enum Locktime {
                    /// No inputs have specified this type of locktime
                    Unconstrained,
                    /// The locktime must be at least this much
                    Minimum(u32),
                    /// Some input exclusively requires the other type of locktime
                    Disallowed,
                }

                let mut time_locktime = Locktime::Unconstrained;
                let mut height_locktime = Locktime::Unconstrained;
                for inp in &self.inputs {
                    match (inp.required_time_locktime, inp.required_height_locktime) {
                        (Some(rt), Some(rh)) => {
                            time_locktime = cmp::max(time_locktime, Locktime::Minimum(rt));
                            height_locktime = cmp::max(height_locktime, Locktime::Minimum(rh));
                        },
                        (Some(rt), None) => {
                            time_locktime = cmp::max(time_locktime, Locktime::Minimum(rt));
                            height_locktime = Locktime::Disallowed;
                        },
                        (None, Some(rh)) => {
                            time_locktime = Locktime::Disallowed;
                            height_locktime = cmp::max(height_locktime, Locktime::Minimum(rh));
                        },
                        (None, None) => {}
                    }
                }

                match (time_locktime, height_locktime) {
                    (Locktime::Unconstrained, Locktime::Unconstrained) => Ok(fallback_locktime.unwrap_or(0)),
                    (Locktime::Minimum(x), _) => Ok(x),
                    (_, Locktime::Minimum(x)) => Ok(x),
                    (Locktime::Disallowed, Locktime::Disallowed) => Err(Error::LocktimeConflict),
                    (Locktime::Unconstrained, Locktime::Disallowed) => unreachable!(),
                    (Locktime::Disallowed, Locktime::Unconstrained) => unreachable!(),
                }
            },
        }
    }

    /// Accessor for the "unique identifier" of this PSET, to be used when merging
    pub fn unique_id(&self) -> Result<Txid, Error> {
        let mut tx = self.extract_tx()?;
        // PSBTv2s can be uniquely identified by constructing an unsigned
        // transaction given the information provided in the PSBT and computing
        // the transaction ID of that transaction. Since PSBT_IN_SEQUENCE can be
        // changed by Updaters and Combiners, the sequence number in this unsigned
        // transaction must be set to 0 (not final, nor the sequence in PSBT_IN_SEQUENCE).
        // The lock time in this unsigned transaction must be computed as described previously.
        for inp in tx.input.iter_mut() {
            inp.sequence = 0;
        }
        Ok(tx.txid())
    }

    /// Sanity check input and output count
    pub fn sanity_check(&self) -> Result<(), Error> {
        if self.n_inputs() != self.inputs.len() {
            Err(Error::InputCountMismatch)
        } else if self.n_outputs() != self.outputs.len() {
            Err(Error::OutputCountMismatch)
        } else {
            Ok(())
        }
    }


    /// Extract the Transaction from a PartiallySignedTransaction by filling in
    /// the available signature information in place.
    pub fn extract_tx(&self) -> Result<Transaction, Error> {
        // This should never trigger any error, should be panic here?
        self.sanity_check()?;
        let locktime = self.locktime()?;
        let mut inputs = vec![];
        let mut outputs = vec![];

        for psetin in self.inputs.iter() {
            let txin = TxIn {
                previous_output: OutPoint::new(psetin.previous_txid, psetin.previous_output_index),
                is_pegin: psetin.previous_output_index & (1 << 30) != 0,
                has_issuance: psetin.previous_output_index & (1 << 31) != 0,
                script_sig: psetin.final_script_sig.clone().unwrap_or(Script::new()),
                sequence: psetin.sequence.unwrap_or(0xffffffff),
                asset_issuance: AssetIssuance {
                    asset_blinding_nonce: psetin.issuance_blinding_nonce.as_ref()
                        .unwrap_or_else(|| &ZERO_TWEAK).to_owned(),
                    asset_entropy: psetin.issuance_asset_entropy.unwrap_or([0u8; 32]),
                    amount: psetin.issuance_value.unwrap_or(confidential::Value::Null),
                    inflation_keys: psetin.issuance_inflation_keys.unwrap_or(confidential::Value::Null),
                },
                witness: TxInWitness {
                    amount_rangeproof: psetin.issuance_value_rangeproof.clone(),
                    inflation_keys_rangeproof: psetin.issuance_keys_rangeproof.clone(),
                    script_witness: psetin.final_script_witness.as_ref()
                        .map(|x| x.to_owned()).unwrap_or(Vec::new()),
                    pegin_witness: psetin.pegin_witness.as_ref()
                        .map(|x| x.to_owned()).unwrap_or(Vec::new()),
                },
            };
            inputs.push(txin);
        }

        for out in self.outputs.iter() {
            let txout = TxOut {
                asset: out.asset,
                value: out.amount,
                nonce: out.blinding_key
                    .map(|x| confidential::Nonce::from(x.key))
                    .unwrap_or(confidential::Nonce::Null),
                script_pubkey: out.script_pubkey.clone(),
                witness: TxOutWitness {
                    surjection_proof: out.asset_surjection_proof.clone(),
                    rangeproof: out.value_rangeproof.clone(),
                },
            };
            outputs.push(txout);
        }
        Ok(Transaction {
            version: self.global.tx_data.version,
            lock_time: locktime,
            input: inputs,
            output: outputs,
        })
    }

    /// Attempt to merge with another `PartiallySignedTransaction`.
    pub fn merge(&mut self, other: Self) -> Result<(), self::Error> {
        if self.unique_id() != other.unique_id() {
            return Err(Error::UniqueIdMismatch {
                expected: self.unique_id()?,
                actual: other.unique_id()?,
            });
        }

        self.global.merge(other.global)?;

        for (self_input, other_input) in self.inputs.iter_mut().zip(other.inputs.into_iter()) {
            self_input.merge(other_input)?;
        }

        for (self_output, other_output) in self.outputs.iter_mut().zip(other.outputs.into_iter()) {
            self_output.merge(other_output)?;
        }

        Ok(())
    }
}

impl Encodable for PartiallySignedTransaction {
    fn consensus_encode<S: io::Write>(
        &self,
        mut s: S,
    ) -> Result<usize, encode::Error> {
        let mut len = 0;
        len += b"pset".consensus_encode(&mut s)?;

        len += 0xff_u8.consensus_encode(&mut s)?;

        len += self.global.consensus_encode(&mut s)?;

        for i in &self.inputs {
            len += i.consensus_encode(&mut s)?;
        }

        for i in &self.outputs {
            len += i.consensus_encode(&mut s)?;
        }

        Ok(len)
    }
}

impl Decodable for PartiallySignedTransaction {
    fn consensus_decode<D: io::BufRead>(mut d: D) -> Result<Self, encode::Error> {
        let magic: [u8; 4] = Decodable::consensus_decode(&mut d)?;

        if *b"pset" != magic {
            return Err(Error::InvalidMagic.into());
        }

        if 0xff_u8 != u8::consensus_decode(&mut d)? {
            return Err(Error::InvalidSeparator.into());
        }

        let global: Global = Decodable::consensus_decode(&mut d)?;

        let inputs: Vec<Input> = {
            let inputs_len = global.n_inputs();

            // Maximum pset input size supported
            if inputs_len > 10_000 {
                return Err(Error::TooLargePset)?;
            }

            let mut inputs: Vec<Input> = Vec::with_capacity(inputs_len);

            for _ in 0..inputs_len {
                inputs.push(Decodable::consensus_decode(&mut d)?);
            }

            inputs
        };

        let outputs: Vec<Output> = {
            let outputs_len = global.n_outputs();

            // Maximum pset input size supported
            if outputs_len > 10_000 {
                return Err(Error::TooLargePset)?;
            }

            let mut outputs: Vec<Output> = Vec::with_capacity(outputs_len);

            for _ in 0..outputs_len {
                outputs.push(Decodable::consensus_decode(&mut d)?);
            }

            outputs
        };

        let pset = PartiallySignedTransaction {
            global: global,
            inputs: inputs,
            outputs: outputs,
        };
        pset.sanity_check()?;
        Ok(pset)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::hex::FromHex;

    fn tx_pset_rtt(tx_hex: &str) {
        let tx: Transaction = encode::deserialize(&Vec::<u8>::from_hex(tx_hex).unwrap()[..]).unwrap();
        let pset= PartiallySignedTransaction::from_tx(tx);
        let rtt_tx_hex = encode::serialize_hex(&pset.extract_tx().unwrap());
        assert_eq!(tx_hex, rtt_tx_hex);
        let pset_rtt_hex = encode::serialize_hex(&pset);
        let pset2 : PartiallySignedTransaction = encode::deserialize(&Vec::<u8>::from_hex(&pset_rtt_hex).unwrap()[..]).unwrap();
        assert_eq!(pset, pset2);
    }

    #[test]
    fn test_pset(){

        tx_pset_rtt("010000000001715df5ccebaf02ff18d6fae7263fa69fed5de59c900f4749556eba41bc7bf2af0000000000000000000201230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b2010000000124101100001f5175517551755175517551755175517551755175517551755175517551755101230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b2010000000005f5e100000000000000");

        // Test a issuance test with only sighash all
        tx_pset_rtt("010000000001715df5ccebaf02ff18d6fae7263fa69fed5de59c900f4749556eba41bc7bf2af000000800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000003e801000000000000000a0201230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b2010000000124101100001f5175517551755175517551755175517551755175517551755175517551755101230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b2010000000005f5e100000000000000");
    }

    #[test]
    fn invalid_pset() {
        // Check Global must have
        let pset_str = "70736574ff010401000105010001fb040200000000";
        let pset = encode::deserialize::<PartiallySignedTransaction>(&Vec::<u8>::from_hex(pset_str).unwrap()[..]);
        pset.expect_err("Missing tx version");

        // Check input must have
        let pset_str = "70736574ff010204020000000104010001fb040200000000";
        let pset = encode::deserialize::<PartiallySignedTransaction>(&Vec::<u8>::from_hex(pset_str).unwrap()[..]);
        pset.expect_err("Missing inp count");

        let pset_str = "70736574ff010204020000000105010001fb040200000000";
        let pset = encode::deserialize::<PartiallySignedTransaction>(&Vec::<u8>::from_hex(pset_str).unwrap()[..]);
        pset.expect_err("Missing out count");

        let pset_str = "70736574ff01020402000000010401000105010000";
        let pset = encode::deserialize::<PartiallySignedTransaction>(&Vec::<u8>::from_hex(pset_str).unwrap()[..]);
        pset.expect_err("Missing pset version");
        // Check inp/out count mismatch
        let pset_str = "70736574ff01020402000000010401000105010001fb04020000000001017a0ad92644e9bf6cb8d0856a8ca713c8a212d3a62142e85454b7865217890e52ec3108a469a9811ec1c1df7a98dbc3a7f71860293e98c6fad8a7ef6828344e9172547302217d344513f0a5ed1a60ebeba01460c505ad63d95b3542fb303aca8f9382777d160014bd5c31aaea2ddc585f317ee589bc6800bc95e7e6010e208965573f41392a88d8bb106cf13a7bdc69f1ab914cd5e8de11235467b514e5a9010f040100000000";
        let pset = encode::deserialize::<PartiallySignedTransaction>(&Vec::<u8>::from_hex(pset_str).unwrap()[..]);
        pset.expect_err("Input count mismatch");

        // input must have
        let pset_str = "70736574ff01020402000000010401010105010001fb04020000000001017a0ad92644e9bf6cb8d0856a8ca713c8a212d3a62142e85454b7865217890e52ec3108a469a9811ec1c1df7a98dbc3a7f71860293e98c6fad8a7ef6828344e9172547302217d344513f0a5ed1a60ebeba01460c505ad63d95b3542fb303aca8f9382777d160014bd5c31aaea2ddc585f317ee589bc6800bc95e7e601010f040100000000";
        let pset = encode::deserialize::<PartiallySignedTransaction>(&Vec::<u8>::from_hex(pset_str).unwrap()[..]);
        pset.expect_err("Input must have prevtxid");

        // output must have
        let pset_str = "70736574ff01020402000000010401000105010101fb04020000000007fc04707365740220010101010101010101010101010101010101010101010101010101010101010101040000";
        let pset = encode::deserialize::<PartiallySignedTransaction>(&Vec::<u8>::from_hex(pset_str).unwrap()[..]);
        pset.expect_err("Output must have");

        let pset_str = "70736574ff01020402000000010401000105010101fb040200000000010308170000000000000007fc0470736574022009090909090909090909090909090909090909090909090909090909090909090100";
        let pset = encode::deserialize::<PartiallySignedTransaction>(&Vec::<u8>::from_hex(pset_str).unwrap()[..]);
        pset.expect_err("Output must have script pubkey");


        // Check only one possible value for pset conf/value
        let pset_str = "70736574ff01020402000000010401000105010101fb040200000000010308170000000000000007fc0470736574012109090909090909090909090909090909090909090909090909090909090909090907fc04707365740220090909090909090909090909090909090909090909090909090909090909090901040000";
        let pset = encode::deserialize::<PartiallySignedTransaction>(&Vec::<u8>::from_hex(pset_str).unwrap()[..]);
        pset.expect_err("Only one type of conf/explicit value should be present in map");

        // Commented code for quick test vector generation
        // let mut pset = PartiallySignedTransaction::new_v2();
        // use AssetId;
        // let txout = TxOut {
        //     asset: confidential::Asset::Explicit(AssetId::from_slice(&[9u8;32]).unwrap()),
        //     value: confidential::Value::Explicit(23),
        //     nonce: confidential::Nonce::Null,
        //     script_pubkey: Script::new(),
        //     witness: TxOutWitness::default(),
        // };
        // pset.add_output(Output::from_txout(txout));
        // println!("{}", encode::serialize_hex(&pset));


        // // Commit an asset
        // let mut pset = PartiallySignedTransaction::new_v2();
        // // use AssetId;
        // let txout = TxOut {
        //     asset: confidential::Asset::Explicit(AssetId::from_slice(&[9u8;32]).unwrap()),
        //     value: confidential::Value::from_commitment(&[09;33]).unwrap(),
        //     nonce: confidential::Nonce::Null,
        //     script_pubkey: Script::new(),
        //     witness: TxOutWitness::default(),
        // };
        // pset.add_output(Output::from_txout(txout));
        // println!("{}", encode::serialize_hex(&pset));
    }
}