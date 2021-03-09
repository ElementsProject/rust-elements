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

use {Script, Transaction, Txid};
use encode::{self, Encodable, Decodable};
pub use self::error::Error;
pub use self::map::{Map, Global, GlobalTxData, Input, Output};

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
    /// Create a PartiallySignedTransaction from an unsigned transaction, error
    /// if not unsigned
    pub fn from_unsigned_tx(tx: Transaction) -> Result<Self, self::Error> {
        Ok(PartiallySignedTransaction {
            inputs: vec![Default::default(); tx.input.len()],
            outputs: vec![Default::default(); tx.output.len()],
            global: Global::from_unsigned_tx(tx)?,
        })
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
            GlobalTxData::V0 { ref unsigned_tx } => Ok(unsigned_tx.lock_time),
            GlobalTxData::V2 { fallback_locktime, .. } => {
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
                    (Locktime::Unconstrained, Locktime::Unconstrained) => Ok(fallback_locktime),
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
    pub fn unique_id(&self) -> Txid {
        match self.global.tx_data {
            // v0 PSETs are easy because they have an explicit transaction
            GlobalTxData::V0 { ref unsigned_tx } => unsigned_tx.txid(),
            GlobalTxData::V2 { .. } => unimplemented!(),
        }
    }

    /// Extract the Transaction from a PartiallySignedTransaction by filling in
    /// the available signature information in place.
    pub fn extract_tx(self) -> Transaction {
        let mut tx = match self.global.tx_data {
            // v0 PSETs are easy because they have an explicit transaction
            GlobalTxData::V0 { unsigned_tx } => unsigned_tx,
            GlobalTxData::V2 { .. } => unimplemented!(),
        };

        for (vin, psetin) in tx.input.iter_mut().zip(self.inputs.into_iter()) {
            vin.script_sig = psetin.final_script_sig.unwrap_or_else(Script::new);
            vin.witness.script_witness = psetin.final_script_witness.unwrap_or_else(Vec::new);
        }

        tx
    }

    /// Attempt to merge with another `PartiallySignedTransaction`.
    pub fn merge(&mut self, other: Self) -> Result<(), self::Error> {
        if self.unique_id() != other.unique_id() {
            return Err(Error::UniqueIdMismatch {
                expected: self.unique_id(),
                actual: other.unique_id(),
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

        Ok(PartiallySignedTransaction {
            global: global,
            inputs: inputs,
            outputs: outputs,
        })
    }
}