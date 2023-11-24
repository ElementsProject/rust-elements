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
//! defined at <https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki>
//! except we define PSETs containing non-standard Sighash types as invalid.
//! Extension for PSET is based on PSET defined in BIP370.
//! <https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki>

use std::collections::HashMap;
use std::{cmp, io};

mod error;
#[macro_use]
mod macros;
mod map;
pub mod raw;
pub mod serialize;
pub mod elip100;

#[cfg(feature = "base64")]
mod str;

#[cfg(feature = "base64")]
pub use self::str::ParseError;

use crate::blind::{BlindAssetProofs, BlindValueProofs};
use crate::confidential;
use crate::encode::{self, Decodable, Encodable};
use crate::{
    blind::RangeProofMessage,
    confidential::{AssetBlindingFactor, ValueBlindingFactor},
    TxOutSecrets,
};
use crate::{OutPoint, LockTime, Sequence, SurjectionInput, Transaction, TxIn, TxInWitness, TxOut, TxOutWitness, Txid};
use secp256k1_zkp::rand::{CryptoRng, RngCore};
use secp256k1_zkp::{self, RangeProof, SecretKey, SurjectionProof};

pub use self::error::{Error, PsetBlindError};
use self::map::Map;
pub use self::map::{Global, GlobalTxData, Input, Output, PsbtSighashType, TapTree};

/// A Partially Signed Transaction.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(crate = "actual_serde"))]
pub struct PartiallySignedTransaction {
    /// The key-value pairs for all global data.
    pub global: Global,
    /// The corresponding key-value map for each input in the unsigned
    /// transaction.
    inputs: Vec<Input>,
    /// The corresponding key-value map for each output in the unsigned
    /// transaction.
    outputs: Vec<Output>,
}

impl Default for PartiallySignedTransaction {
    fn default() -> Self {
        Self::new_v2()
    }
}

impl PartiallySignedTransaction {
    /// Create a new PSET from a raw transaction
    pub fn from_tx(tx: Transaction) -> Self {
        let global = Global {
            tx_data: GlobalTxData {
                output_count: tx.output.len(),
                input_count: tx.input.len(),
                fallback_locktime: Some(tx.lock_time),
                version: tx.version,
                ..Default::default()
            },
            ..Default::default()
        };

        let inputs = tx.input.into_iter().map(Input::from_txin).collect();
        let outputs = tx
            .output
            .into_iter()
            .map(Output::from_txout)
            .collect();
        Self { global, inputs, outputs }
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

    /// Add an input to pset at position i. This also updates the
    /// pset global input count and the blinder index that might have shifted.
    ///
    /// See also: [`PartiallySignedTransaction::add_input`]
    /// Panics if index is more than length.
    pub fn insert_input(&mut self, inp: Input, pos: usize) {
        self.global.tx_data.input_count += 1;
        self.inputs.insert(pos, inp);

        for out in self.outputs_mut() {
            match out.blinder_index {
                Some(i) if i >= pos as u32 => {
                    out.blinder_index = Some(i + 1);
                }
                _ => {}
            }
        }
    }

    /// Read accessor to inputs
    pub fn inputs(&self) -> &[Input] {
        &self.inputs
    }

    /// Mutable accessor to inputs
    pub fn inputs_mut(&mut self) -> &mut [Input] {
        &mut self.inputs
    }

    /// Remove the input at `index` and return it if any, otherwise returns None
    /// This also updates the pset global input count
    pub fn remove_input(&mut self, index: usize) -> Option<Input> {
        if self.inputs.get(index).is_some() {
            self.global.tx_data.input_count -= 1;
            return Some(self.inputs.remove(index));
        }
        None
    }

    /// Add an output to pset. This also updates the
    /// pset global output count
    pub fn add_output(&mut self, out: Output) {
        self.global.tx_data.output_count += 1;
        self.outputs.push(out);
    }

    /// Add an output to pset at position i. This also updates the
    /// pset global output count
    /// Panics if index is more than length.
    pub fn insert_output(&mut self, out: Output, pos: usize) {
        self.global.tx_data.output_count += 1;
        self.outputs.insert(pos, out);
    }

    /// read accessor to outputs
    pub fn outputs(&self) -> &[Output] {
        &self.outputs
    }

    /// mutable accessor to outputs
    pub fn outputs_mut(&mut self) -> &mut [Output] {
        &mut self.outputs
    }

    /// Remove the output at `index` and return it if any, otherwise returns None
    /// This also updates the pset global output count
    pub fn remove_output(&mut self, index: usize) -> Option<Output> {
        if self.outputs.get(index).is_some() {
            self.global.tx_data.output_count -= 1;
            return Some(self.outputs.remove(index));
        }
        None
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
    #[allow(clippy::match_single_binding)]
    pub fn locktime(&self) -> Result<LockTime, Error> {
        match self.global.tx_data {
            GlobalTxData {
                fallback_locktime, ..
            } => {
                #[derive(PartialEq, Eq, PartialOrd, Ord)]
                enum Locktime<T: Ord> {
                    /// No inputs have specified this type of locktime
                    Unconstrained,
                    /// The locktime must be at least this much
                    Minimum(T),
                    /// Some input exclusively requires the other type of locktime
                    Disallowed,
                }

                let mut time_locktime = Locktime::<crate::locktime::Time>::Unconstrained;
                let mut height_locktime = Locktime::<crate::locktime::Height>::Unconstrained;
                for inp in &self.inputs {
                    match (inp.required_time_locktime, inp.required_height_locktime) {
                        (Some(rt), Some(rh)) => {
                            time_locktime = cmp::max(time_locktime, Locktime::Minimum(rt));
                            height_locktime = cmp::max(height_locktime, Locktime::Minimum(rh));
                        }
                        (Some(rt), None) => {
                            time_locktime = cmp::max(time_locktime, Locktime::Minimum(rt));
                            height_locktime = Locktime::Disallowed;
                        }
                        (None, Some(rh)) => {
                            time_locktime = Locktime::Disallowed;
                            height_locktime = cmp::max(height_locktime, Locktime::Minimum(rh));
                        }
                        (None, None) => {}
                    }
                }

                match (time_locktime, height_locktime) {
                    (Locktime::Unconstrained, Locktime::Unconstrained) => {
                        Ok(fallback_locktime.map(LockTime::from).unwrap_or(LockTime::ZERO))
                    }
                    (Locktime::Minimum(x), _) => Ok(x.into()),
                    (_, Locktime::Minimum(x)) => Ok(x.into()),
                    (Locktime::Disallowed, Locktime::Disallowed) => Err(Error::LocktimeConflict),
                    (Locktime::Unconstrained, Locktime::Disallowed) => unreachable!(),
                    (Locktime::Disallowed, Locktime::Unconstrained) => unreachable!(),
                }
            }
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
            inp.sequence = Sequence::from_height(0);
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
                is_pegin: psetin.is_pegin(),
                script_sig: psetin.final_script_sig.clone().unwrap_or_default(),
                sequence: psetin.sequence.unwrap_or(Sequence::MAX),
                asset_issuance: psetin.asset_issuance(),
                witness: TxInWitness {
                    amount_rangeproof: psetin.issuance_value_rangeproof.clone(),
                    inflation_keys_rangeproof: psetin.issuance_keys_rangeproof.clone(),
                    script_witness: psetin
                        .final_script_witness
                        .as_ref()
                        .map(|x| x.to_owned())
                        .unwrap_or_default(),
                    pegin_witness: psetin
                        .pegin_witness
                        .as_ref()
                        .map(|x| x.to_owned())
                        .unwrap_or_default(),
                },
            };
            inputs.push(txin);
        }

        for out in self.outputs.iter() {
            let txout = TxOut {
                asset: match (out.asset_comm, out.asset) {
                    (Some(gen), _) => confidential::Asset::Confidential(gen),
                    (None, Some(asset)) => confidential::Asset::Explicit(asset),
                    (None, None) => return Err(Error::MissingOutputValue),
                },
                value: match (out.amount_comm, out.amount) {
                    (Some(comm), _) => confidential::Value::Confidential(comm),
                    (None, Some(x)) => confidential::Value::Explicit(x),
                    (None, None) => return Err(Error::MissingOutputAsset),
                },
                nonce: out
                    .ecdh_pubkey
                    .map(|x| confidential::Nonce::from(x.inner))
                    .unwrap_or_default(),
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

    // Common pset blinding checks
    #[allow(clippy::type_complexity)] // FIXME we probably should actually factor out this return type
    fn blind_checks(
        &self,
        inp_txout_sec: &HashMap<usize, TxOutSecrets>,
    ) -> Result<
        (
            Vec<(u64, AssetBlindingFactor, ValueBlindingFactor)>,
            Vec<usize>,
        ),
        PsetBlindError,
    > {
        let mut blind_out_indices = Vec::new();
        for (i, out) in self.outputs.iter().enumerate() {
            if out.blinding_key.is_none() {
                // skip checks on non-blinding outputs
                continue;
            }
            if let Some(blind_index) = self.outputs[i].blinder_index {
                if blind_index as usize >= self.inputs.len() {
                    return Err(PsetBlindError::BlinderIndexOutOfBounds(
                        i,
                        blind_index as usize,
                    ));
                } else if inp_txout_sec.get(&(blind_index as usize)).is_none() {
                    //nothing
                } else {
                    // Output has corresponding input blinders
                    blind_out_indices.push(i);
                }
            }
        }

        // collect input factors
        let inp_secrets = inp_txout_sec
            .iter()
            .map(|(_i, sec)| (sec.value, sec.asset_bf, sec.value_bf))
            .collect::<Vec<_>>();

        Ok((inp_secrets, blind_out_indices))
    }

    /// Obtains the surjection inputs for this pset. This servers as the domain
    /// when creating a new [`SurjectionProof`]. Informally, the domain refers to the
    /// set of inputs assets. For inputs whose [`TxOutSecrets`] is supplied,
    /// [`SurjectionInput::Known`] variant is created. For confidential inputs whose secrets
    /// are not supplied [`SurjectionInput::Unknown`] variant is created.
    /// For non-confidential inputs, [`SurjectionInput::Known`] variant is created with zero
    /// blinding factors.
    pub fn surjection_inputs(
        &self,
        inp_txout_sec: &HashMap<usize, TxOutSecrets>,
    ) -> Result<Vec<SurjectionInput>, PsetBlindError> {
        let mut ret = vec![];
        for (i, inp) in self.inputs().iter().enumerate() {
            let utxo = inp
                .witness_utxo
                .as_ref()
                .ok_or(PsetBlindError::MissingWitnessUtxo(i))?;
            let surject_target = match inp_txout_sec.get(&i) {
                Some(sec) => SurjectionInput::from_txout_secrets(*sec),
                None => SurjectionInput::Unknown(utxo.asset),
            };
            ret.push(surject_target);

            if inp.has_issuance() {
                let (asset_id, token_id) = inp.issuance_ids();
                if inp.issuance_value_amount.is_some() || inp.issuance_value_comm.is_some() {
                    let secrets = TxOutSecrets {
                        asset: asset_id,
                        asset_bf: AssetBlindingFactor::zero(),
                        value: 0, // This value really does not matter in surjection proofs
                        value_bf: ValueBlindingFactor::zero(),
                    };
                    ret.push(SurjectionInput::from_txout_secrets(secrets))
                }
                if inp.issuance_inflation_keys.is_some()
                    || inp.issuance_inflation_keys_comm.is_some()
                {
                    let secrets = TxOutSecrets {
                        asset: token_id,
                        asset_bf: AssetBlindingFactor::zero(),
                        value: 0, // This value really does not matter in surjection proofs
                        value_bf: ValueBlindingFactor::zero(),
                    };
                    ret.push(SurjectionInput::from_txout_secrets(secrets))
                }
            }
        }
        Ok(ret)
    }

    /// Blind the pset as the non-last blinder role. The last blinder of pset
    /// should call the `blind_last` function which balances the blinding factors
    /// `inp_secrets` and must be consistent by [`Output`] `blinder_index` field
    /// For each output that is to be blinded, the following must be true
    /// 1. The blinder_index must be set in pset output field
    /// 2. the corresponding inp_secrets\[out.blinder_index\] must be present
    ///
    /// Issuances and re-issuance inputs are not blinded.
    /// # Parameters
    ///
    /// * `inp_secrets`: [`TxOutSecrets`] corresponding to owned inputs. Use [`None`] for non-owned outputs
    ///
    // Blinding issuances is not currently supported. We have no way in pset to specify
    // which issuances we want to blind
    pub fn blind_non_last<C: secp256k1_zkp::Signing, R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        secp: &secp256k1_zkp::Secp256k1<C>,
        inp_txout_sec: &HashMap<usize, TxOutSecrets>,
    ) -> Result<Vec<(AssetBlindingFactor, ValueBlindingFactor)>, PsetBlindError> {
        let (inp_secrets, outs_to_blind) = self.blind_checks(inp_txout_sec)?;

        if outs_to_blind.is_empty() {
            // Return empty values if no outputs are marked for blinding
            return Ok(Vec::new());
        }
        // Blind each output as non-last and save the secrets
        let surject_inputs = self.surjection_inputs(inp_txout_sec)?;
        let mut out_secrets = vec![];
        let mut ret = vec![]; // return all the random values used
        for i in outs_to_blind {
            let txout = self.outputs[i].to_txout();
            let (txout, abf, vbf, _) = txout
                .to_non_last_confidential(
                    rng,
                    secp,
                    self.outputs[i]
                        .blinding_key
                        .map(|x| x.inner)
                        .ok_or(PsetBlindError::MustHaveExplicitTxOut(i))?,
                    &surject_inputs,
                )
                .map_err(|e| PsetBlindError::ConfidentialTxOutError(i, e))?;
            let value = self.outputs[i]
                .amount
                .ok_or(PsetBlindError::MustHaveExplicitTxOut(i))?;
            out_secrets.push((value, abf, vbf));

            // mutate the pset
            {
                self.outputs[i].value_rangeproof = txout.witness.rangeproof;
                self.outputs[i].asset_surjection_proof = txout.witness.surjection_proof;
                self.outputs[i].amount_comm = txout.value.commitment();
                self.outputs[i].asset_comm = txout.asset.commitment();
                self.outputs[i].ecdh_pubkey =
                    txout.nonce.commitment().map(|pk| bitcoin::PublicKey {
                        inner: pk,
                        compressed: true,
                    });
                let asset_id = self.outputs[i]
                    .asset
                    .ok_or(PsetBlindError::MustHaveExplicitTxOut(i))?;
                self.outputs[i].blind_asset_proof = Some(Box::new(
                    SurjectionProof::blind_asset_proof(rng, secp, asset_id, abf)
                        .map_err(|e| PsetBlindError::BlindingProofsCreationError(i, e))?,
                ));

                let asset_gen = self.outputs[i]
                    .asset_comm
                    .expect("Blinding proof creation error");
                let value_comm = self.outputs[i]
                    .amount_comm
                    .expect("Blinding proof successful");
                self.outputs[i].blind_value_proof = Some(Box::new(
                    RangeProof::blind_value_proof(rng, secp, value, value_comm, asset_gen, vbf)
                        .map_err(|e| PsetBlindError::BlindingProofsCreationError(i, e))?,
                ));
            }
            // return blinding factors used
            ret.push((abf, vbf));
        }

        // safe to unwrap because we have checked that there is atleast one output to blind
        let (value, abf, vbf) = out_secrets.pop().unwrap();

        // Calculate what should have been the last vbf if the txout
        // had to be balanced
        let mut vbf2 = ValueBlindingFactor::last(
            secp,
            value,
            abf,
            &inp_secrets,
            &out_secrets[..out_secrets.len()],
        );

        // Since the txout is not balanced, calculate the last scalar
        vbf2 += -vbf;
        // Push the scalar
        // BUG in pset
        // Bug in Pset, scalars can be the same value, but there is no place
        // in pset to place them as it would break the uniqueness constriant.
        self.global.scalars.push(vbf2.into_inner());
        Ok(ret)
    }

    /// Blind the pset as the last blinder role. The non-last blinder of pset
    /// should call the [`Self::blind_non_last`] function.
    /// This function balances the blinding factors with partial information about
    /// blinding inputs and scalars from [`Global`] scalars field.
    /// `inp_secrets` and `out_secrets` must be consistent by [`Output`] `blinder_index` field
    /// For each output, the corresponding inp_secrets\[out.blinder_index\] must be present
    /// # Parameters
    ///
    /// * `inp_secrets`: [`TxOutSecrets`] corresponding to owned inputs. Use [`None`] for non-owned outputs
    ///
    pub fn blind_last<C: secp256k1_zkp::Signing, R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        secp: &secp256k1_zkp::Secp256k1<C>,
        inp_txout_sec: &HashMap<usize, TxOutSecrets>,
    ) -> Result<(), PsetBlindError> {
        let (mut inp_secrets, mut outs_to_blind) = self.blind_checks(inp_txout_sec)?;

        if outs_to_blind.is_empty() {
            // Atleast one output must be marked for blinding for pset blind_last
            return Err(PsetBlindError::AtleastOneOutputBlind);
        }
        // If there are more than 1 outs to blind
        // blind all outs but the last one
        let last_out_index = outs_to_blind.pop().unwrap();
        if !outs_to_blind.is_empty() {
            // Don't blind the last output
            let ind = self.outputs[last_out_index].blinder_index;
            self.outputs[last_out_index].blinder_index = None;
            // Blind normally without the last index
            self.blind_non_last(rng, secp, inp_txout_sec)?;
            // Restore who blinded the last output
            self.outputs[last_out_index].blinder_index = ind;
            // inp_secrets contributed to self.global.scalars, unset it so we don't count them
            // twice when computing the last vbf.
            inp_secrets = vec![];
        }
        // blind the last txout

        let surject_inputs = self.surjection_inputs(inp_txout_sec)?;
        let asset_id = self.outputs[last_out_index]
            .asset
            .ok_or(PsetBlindError::MustHaveExplicitTxOut(last_out_index))?;
        let out_abf = AssetBlindingFactor::new(rng);
        let exp_asset = confidential::Asset::Explicit(asset_id);
        let blind_res = exp_asset.blind(rng, secp, out_abf, &surject_inputs);

        let (out_asset_commitment, surjection_proof) =
            blind_res.map_err(|e| PsetBlindError::ConfidentialTxOutError(last_out_index, e))?;

        let value = self.outputs[last_out_index]
            .amount
            .ok_or(PsetBlindError::MustHaveExplicitTxOut(last_out_index))?;
        let exp_value = confidential::Value::Explicit(value);
        // Get all the explicit outputs
        let mut exp_out_secrets = vec![];
        for (i, out) in self.outputs.iter().enumerate() {
            if out.blinding_key.is_none() {
                let amt = out.amount.ok_or(PsetBlindError::MustHaveExplicitTxOut(i))?;
                exp_out_secrets.push((
                    amt,
                    AssetBlindingFactor::zero(),
                    ValueBlindingFactor::zero(),
                ));
            }
        }
        let mut final_vbf =
            ValueBlindingFactor::last(secp, value, out_abf, &inp_secrets, &exp_out_secrets);

        // Add all the scalars
        for value_diff in self.global.scalars.iter() {
            final_vbf += ValueBlindingFactor(*value_diff);
        }

        let receiver_blinding_pk = &self.outputs[last_out_index]
            .blinding_key
            .ok_or(PsetBlindError::MustHaveExplicitTxOut(last_out_index))?;
        let ephemeral_sk = SecretKey::new(rng);
        let spk = &self.outputs[last_out_index].script_pubkey;
        let msg = RangeProofMessage {
            asset: asset_id,
            bf: out_abf,
        };
        let blind_res = exp_value.blind(
            secp,
            final_vbf,
            receiver_blinding_pk.inner,
            ephemeral_sk,
            spk,
            &msg,
        );
        let (value_commitment, nonce, rangeproof) =
            blind_res.map_err(|e| PsetBlindError::ConfidentialTxOutError(last_out_index, e))?;

        // mutate the pset
        {
            self.outputs[last_out_index].value_rangeproof = Some(Box::new(rangeproof));
            self.outputs[last_out_index].asset_surjection_proof = Some(Box::new(surjection_proof));
            self.outputs[last_out_index].amount_comm = value_commitment.commitment();
            self.outputs[last_out_index].asset_comm = out_asset_commitment.commitment();
            self.outputs[last_out_index].ecdh_pubkey =
                nonce.commitment().map(|pk| bitcoin::PublicKey {
                    inner: pk,
                    compressed: true,
                });
            let asset_id = self.outputs[last_out_index]
                .asset
                .ok_or(PsetBlindError::MustHaveExplicitTxOut(last_out_index))?;
            self.outputs[last_out_index].blind_asset_proof = Some(Box::new(
                SurjectionProof::blind_asset_proof(rng, secp, asset_id, out_abf)
                    .map_err(|e| PsetBlindError::BlindingProofsCreationError(last_out_index, e))?,
            ));

            let asset_gen = self.outputs[last_out_index]
                .asset_comm
                .expect("Blinding proof creation error");
            let value_comm = self.outputs[last_out_index]
                .amount_comm
                .expect("Blinding proof successful");
            self.outputs[last_out_index].blind_value_proof = Some(Box::new(
                RangeProof::blind_value_proof(rng, secp, value, value_comm, asset_gen, final_vbf)
                    .map_err(|e| PsetBlindError::BlindingProofsCreationError(last_out_index, e))?,
            ));

            self.global.scalars.clear()
        }
        Ok(())
    }
}

impl Encodable for PartiallySignedTransaction {
    fn consensus_encode<S: io::Write>(&self, mut s: S) -> Result<usize, encode::Error> {
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
    fn consensus_decode<D: io::Read>(mut d: D) -> Result<Self, encode::Error> {
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

        let pset = PartiallySignedTransaction { global, inputs, outputs };
        pset.sanity_check()?;
        Ok(pset)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hex::{FromHex, ToHex};

    fn tx_pset_rtt(tx_hex: &str) {
        let tx: Transaction =
            encode::deserialize(&Vec::<u8>::from_hex(tx_hex).unwrap()[..]).unwrap();
        let pset = PartiallySignedTransaction::from_tx(tx);
        let rtt_tx_hex = encode::serialize_hex(&pset.extract_tx().unwrap());
        assert_eq!(tx_hex, rtt_tx_hex);
        let pset_rtt_hex = encode::serialize_hex(&pset);
        let pset2: PartiallySignedTransaction =
            encode::deserialize(&Vec::<u8>::from_hex(&pset_rtt_hex).unwrap()[..]).unwrap();
        assert_eq!(pset, pset2);
    }

    fn pset_rtt(pset_hex: &str) {
        let pset: PartiallySignedTransaction =
            encode::deserialize(&Vec::<u8>::from_hex(pset_hex).unwrap()[..]).unwrap();

        assert_eq!(encode::serialize_hex(&pset), pset_hex);
    }

    #[test]
    fn test_pset() {
        tx_pset_rtt("010000000001715df5ccebaf02ff18d6fae7263fa69fed5de59c900f4749556eba41bc7bf2af0000000000000000000201230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b2010000000124101100001f5175517551755175517551755175517551755175517551755175517551755101230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b2010000000005f5e100000000000000");

        // Test a issuance test with only sighash all
        tx_pset_rtt("010000000001715df5ccebaf02ff18d6fae7263fa69fed5de59c900f4749556eba41bc7bf2af000000800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000003e801000000000000000a0201230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b2010000000124101100001f5175517551755175517551755175517551755175517551755175517551755101230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b2010000000005f5e100000000000000");
        tx_pset_rtt(include_str!("../../tests/data/pset1.hex"));

        pset_rtt("70736574ff01020402000000010401000105010001fb040200000000");
        pset_rtt("70736574ff01020402000000010401010105010001fb04020000000001017a0ad92644e9bf6cb8d0856a8ca713c8a212d3a62142e85454b7865217890e52ec3108a469a9811ec1c1df7a98dbc3a7f71860293e98c6fad8a7ef6828344e9172547302217d344513f0a5ed1a60ebeba01460c505ad63d95b3542fb303aca8f9382777d160014bd5c31aaea2ddc585f317ee589bc6800bc95e7e6010e208965573f41392a88d8bb106cf13a7bdc69f1ab914cd5e8de11235467b514e5a9010f040100000000");
        pset_rtt("70736574ff01020402000000010401020105010001fb04020000000001017a0ad92644e9bf6cb8d0856a8ca713c8a212d3a62142e85454b7865217890e52ec3108a469a9811ec1c1df7a98dbc3a7f71860293e98c6fad8a7ef6828344e9172547302217d344513f0a5ed1a60ebeba01460c505ad63d95b3542fb303aca8f9382777d160014bd5c31aaea2ddc585f317ee589bc6800bc95e7e6010e208965573f41392a88d8bb106cf13a7bdc69f1ab914cd5e8de11235467b514e5a9010f04010000000001017a0af0b70a2237872fb9e84fbc002358469c51f85bcb6215930df63dd29953bbf5cf090e6df3e3b4e589ce447d3deb7cd4fa7a3c264a3d18b5e245a60add9f01137a4b0365026bb845d512434305eb2309656cd0701de8adfdcc84dd8b05d9e240ee55e6160014adf9a42f6d4643f7ae69d94114cfebc3824209ae010e208965573f41392a88d8bb106cf13a7bdc69f1ab914cd5e8de11235467b514e5a9010f040000000000");
        pset_rtt(include_str!("../../tests/data/pset2.hex"));
        pset_rtt(include_str!("../../tests/data/pset3.hex"));
        pset_rtt(include_str!("../../tests/data/pset4.hex"));
        pset_rtt(include_str!("../../tests/data/pset5.hex"));
        pset_rtt(include_str!("../../tests/data/pset6.hex"));
    }

    #[test]
    fn single_blinded_output_pset() {
        use crate::AssetId;
        use rand::{self, SeedableRng};
        use serde_json;
        use std::str::FromStr;

        // Initially secp context and rng global state
        let secp = secp256k1_zkp::Secp256k1::new();
        #[allow(deprecated)]
        let mut rng = rand::rngs::StdRng::seed_from_u64(0);

        let pset_hex = "70736574ff01020402000000010401010105010201fb04020000000001017a0bb9325c276764451bbc2eb82a4c8c4bb6f4007ba803e5a5ba72d0cd7c09848e1a091622d935953bf06e0b7393239c68c6f810a00fe19d11c6ae343cffd3037077da02535fe4ad0fcd675cd0f62bf73b60a554dc1569b80f1f76a2bbfc9f00d439bf4b160014d2cbec8783bd01c9f178348b08500a830a89a7f9010e20805131ba6b37165c026eed9325ac56059ba872fd569e3ed462734098688b4770010f0400000000000103088c83b50d0000000007fc04707365740220230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b20104220020e5793ad956ee91ebf3543b37d110701118ed4078ffa0d477eacb8885e486ad8507fc047073657406210212bf0ea45b733dfde8ecb5e896306c4165c666c99fc5d1ab887f71393a975cea07fc047073657408040000000000010308f40100000000000007fc04707365740220230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b201040000";
        let mut pset: PartiallySignedTransaction =
            encode::deserialize(&Vec::<u8>::from_hex(pset_hex).unwrap()[..]).unwrap();

        let btc_txout_secrets_str = r#"
        {
            "amount": "2.30000000",
            "asset": "b2e15d0d7a0c94e4e2ce0fe6e8691b9e451377f6e46e8045a86f7c4b5d4f0f23",
            "amountblinder": "0f155ac96c49e39c0501e3448e9aac89f5b43c16bf9156e6c1694e310c80f374",
            "assetblinder": "de6ecd62ab6fc66597b2144f38c3be873ba583970aacdfcc8978a1a0b6cb872c"
        }"#;
        let v: serde_json::Value = serde_json::from_str(btc_txout_secrets_str).unwrap();
        let btc_txout_secrets = TxOutSecrets {
            asset_bf: AssetBlindingFactor::from_str(v["assetblinder"].as_str().unwrap()).unwrap(),
            value_bf: ValueBlindingFactor::from_str(v["amountblinder"].as_str().unwrap()).unwrap(),
            value: bitcoin::Amount::from_str_in(
                v["amount"].as_str().unwrap(),
                bitcoin::Denomination::Bitcoin,
            )
            .unwrap()
            .to_sat(),
            asset: AssetId::from_str(v["asset"].as_str().unwrap()).unwrap(),
        };

        let mut inp_txout_sec = HashMap::new();
        inp_txout_sec.insert(0, btc_txout_secrets);
        pset.blind_last(&mut rng, &secp, &inp_txout_sec).unwrap();

        let tx = pset.extract_tx().unwrap();
        let btc_txout = pset.inputs[0].witness_utxo.clone().unwrap();
        tx.verify_tx_amt_proofs(&secp, &[btc_txout]).unwrap();
    }

    #[test]
    fn basic_pset() {
        // Invalid psets
        // Check Global mandatory field
        let pset_str = "70736574ff010401000105010001fb040200000000";
        let pset = encode::deserialize::<PartiallySignedTransaction>(
            &Vec::<u8>::from_hex(pset_str).unwrap()[..],
        );
        pset.expect_err("Missing tx version");

        // Check input mandatory field
        let pset_str = "70736574ff010204020000000104010001fb040200000000";
        let pset = encode::deserialize::<PartiallySignedTransaction>(
            &Vec::<u8>::from_hex(pset_str).unwrap()[..],
        );
        pset.expect_err("Missing inp count");

        let pset_str = "70736574ff010204020000000105010001fb040200000000";
        let pset = encode::deserialize::<PartiallySignedTransaction>(
            &Vec::<u8>::from_hex(pset_str).unwrap()[..],
        );
        pset.expect_err("Missing out count");

        let pset_str = "70736574ff01020402000000010401000105010000";
        let pset = encode::deserialize::<PartiallySignedTransaction>(
            &Vec::<u8>::from_hex(pset_str).unwrap()[..],
        );
        pset.expect_err("Missing pset version");
        // Check inp/out count mismatch
        let pset_str = "70736574ff01020402000000010401000105010001fb04020000000001017a0ad92644e9bf6cb8d0856a8ca713c8a212d3a62142e85454b7865217890e52ec3108a469a9811ec1c1df7a98dbc3a7f71860293e98c6fad8a7ef6828344e9172547302217d344513f0a5ed1a60ebeba01460c505ad63d95b3542fb303aca8f9382777d160014bd5c31aaea2ddc585f317ee589bc6800bc95e7e6010e208965573f41392a88d8bb106cf13a7bdc69f1ab914cd5e8de11235467b514e5a9010f040100000000";
        let pset = encode::deserialize::<PartiallySignedTransaction>(
            &Vec::<u8>::from_hex(pset_str).unwrap()[..],
        );
        pset.expect_err("Input count mismatch");

        // input mandatory field
        let pset_str = "70736574ff01020402000000010401010105010001fb04020000000001017a0ad92644e9bf6cb8d0856a8ca713c8a212d3a62142e85454b7865217890e52ec3108a469a9811ec1c1df7a98dbc3a7f71860293e98c6fad8a7ef6828344e9172547302217d344513f0a5ed1a60ebeba01460c505ad63d95b3542fb303aca8f9382777d160014bd5c31aaea2ddc585f317ee589bc6800bc95e7e601010f040100000000";
        let pset = encode::deserialize::<PartiallySignedTransaction>(
            &Vec::<u8>::from_hex(pset_str).unwrap()[..],
        );
        pset.expect_err("Input mandatory field prevtxid");

        // output mandatory amount field
        let pset_str = "70736574ff01020402000000010401000105010101fb04020000000007fc04707365740220010101010101010101010101010101010101010101010101010101010101010101040000";
        let pset = encode::deserialize::<PartiallySignedTransaction>(
            &Vec::<u8>::from_hex(pset_str).unwrap()[..],
        );
        pset.expect_err("Output non-mandatory field");

        let pset_str = "70736574ff01020402000000010401000105010101fb040200000000010308170000000000000007fc0470736574022009090909090909090909090909090909090909090909090909090909090909090100";
        let pset = encode::deserialize::<PartiallySignedTransaction>(
            &Vec::<u8>::from_hex(pset_str).unwrap()[..],
        );
        pset.expect_err("Output mandatory field script pubkey");

        // Valid Psets

        // Check both possible conf/explicit values are allowed for pset
        let pset_str = "70736574ff01020402000000010401000105010101fb040200000000010308170000000000000007fc0470736574012109090909090909090909090909090909090909090909090909090909090909090907fc04707365740220090909090909090909090909090909090909090909090909090909090909090901040000";
        let pset = encode::deserialize::<PartiallySignedTransaction>(
            &Vec::<u8>::from_hex(pset_str).unwrap()[..],
        );
        pset.expect("Both conf/explicit value are allowed be present in map");

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

    #[test]
    fn pset_from_elements() {
        let pset_str = include_str!("../../tests/data/pset_swap_tutorial.hex");

        let bytes = Vec::<u8>::from_hex(pset_str).unwrap();
        let pset = encode::deserialize::<PartiallySignedTransaction>(&bytes).unwrap();

        assert_eq!(pset_str.len(), encode::serialize(&pset).to_hex().len());
        let back_hex = encode::serialize(&pset).to_hex();
        //assert_eq!(pset_str, &back_hex);  //TODO this fails, field ordering?

        let bytes = Vec::<u8>::from_hex(&back_hex).unwrap();
        let pset = encode::deserialize::<PartiallySignedTransaction>(&bytes).unwrap();
        assert_eq!(&back_hex, &encode::serialize(&pset).to_hex());
    }

    #[test]
    fn pset_remove_in_out() {
        let pset_str = include_str!("../../tests/data/pset_swap_tutorial.hex");

        let bytes = Vec::<u8>::from_hex(pset_str).unwrap();
        let mut pset = encode::deserialize::<PartiallySignedTransaction>(&bytes).unwrap();

        let n_inputs = pset.n_inputs();
        let n_outputs = pset.n_outputs();
        pset.remove_input(n_inputs - 1).unwrap();
        pset.remove_output(n_outputs - 1).unwrap();
        assert_eq!(pset.n_inputs(), n_inputs - 1);
        assert_eq!(pset.n_outputs(), n_outputs - 1);
    }
}
