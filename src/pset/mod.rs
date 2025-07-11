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
pub mod elip102;

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
    /// Create a `PartiallySignedTransaction` with zero inputs
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
                        Ok(fallback_locktime.unwrap_or(LockTime::ZERO))
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
        for inp in &mut tx.input {
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

    /// Extract the Transaction from a `PartiallySignedTransaction` by filling in
    /// the available signature information in place.
    pub fn extract_tx(&self) -> Result<Transaction, Error> {
        // This should never trigger any error, should be panic here?
        self.sanity_check()?;
        let locktime = self.locktime()?;
        let mut inputs = vec![];
        let mut outputs = vec![];

        for psetin in &self.inputs {
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
                        .map(Vec::to_owned)
                        .unwrap_or_default(),
                    pegin_witness: psetin
                        .pegin_witness
                        .as_ref()
                        .map(Vec::to_owned)
                        .unwrap_or_default(),
                },
            };
            inputs.push(txin);
        }

        for out in &self.outputs {
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
        for (i, inp) in self.inputs.iter().enumerate() {
            if inp.has_issuance() && inp.blinded_issuance.unwrap_or(1) == 1 {
                return Err(PsetBlindError::BlindingIssuanceUnsupported(i));
            }
        }
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
            .values()
            .map(|sec| (sec.value, sec.asset_bf, sec.value_bf))
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
                    ret.push(SurjectionInput::from_txout_secrets(secrets));
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
                    ret.push(SurjectionInput::from_txout_secrets(secrets));
                }
            }
        }
        Ok(ret)
    }

    /// Blind the pset as the non-last blinder role. The last blinder of pset
    /// should call the `blind_last` function which balances the blinding factors
    /// `inp_secrets` and must be consistent by [`Output`] `blinder_index` field
    /// For each output that is to be blinded, the following must be true
    /// 1. The `blinder_index` must be set in pset output field
    /// 2. the corresponding `inp_secrets`\[`out.blinder_index`\] must be present
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
        // in pset to place them as it would break the uniqueness constraint.
        self.global.scalars.push(vbf2.into_inner());
        Ok(ret)
    }

    /// Blind the pset as the last blinder role. The non-last blinder of pset
    /// should call the [`Self::blind_non_last`] function.
    /// This function balances the blinding factors with partial information about
    /// blinding inputs and scalars from [`Global`] scalars field.
    /// `inp_secrets` and `out_secrets` must be consistent by [`Output`] `blinder_index` field
    /// For each output, the corresponding `inp_secrets`\[`out.blinder_index`\] must be present
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
        for value_diff in &self.global.scalars {
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

            self.global.scalars.clear();
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
        tx_pset_rtt("0200000001028965573f41392a88d8bb106cf13a7bdc69f1ab914cd5e8de11235467b514e5a90100000000ffffffff8965573f41392a88d8bb106cf13a7bdc69f1ab914cd5e8de11235467b514e5a90000000000ffffffff040a1862832b5a1ff4c222398ab482534c75decc4176450df7c78280b4dd90062da708378fd3af2f7af7009fcf06b5ecae126d5446b134c6763d0a2c103b61ec348c5000220020c731ad44c00a2928d508ad82b05868cb42733a5b0d0b208f483307ce8c328d930bc57b6abf30fcb84f8660771267bb93a6e72de69165ecc9e462d6fff5153d6296090b81ada05aaa354e5c62732358c8a2395dd9576631d9377844935cac78d3b4e80022002058037c2d81d3122185c8704d4276e2629122c95b8ea68575c451628d37eea84501230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b20100000000000001f400000b9991881df2ec384ff5616f6c03d45cf033ee64536297c3557f9fffec716c1fbe09870d0ad593316a7ff67dee90f2c2d8e305cfcdc4619fe0922c706560eac5d8f500220020cd4ed5f0db8c450e8b0be595b6410c1759c19f1f6926279095c83dade9862b6d000000000000024730440220330e4801f9d385f6e7a59b1fbd782357d44578ee95b59cb4030bfbeab44e43c5022037cf1eb808ee08b3ff929caa631f58a689cdf15e1540c965358419ad3cf6337d012103f73515486481e116a5c2cb6fb4c5ee7a518523f878a1570b83e7989222d0236f00000002473044022070679d770419120e2380c6611f7a78b21f64fe88f015646ced3b6cf5e843807402201360c9015b4867e7f771a2f6059dceee13295a3529bc6a56769a3902c32f6b3d0121032e7429173d6c0a555e9389dc90df48c5248af4b73384159c37d533a2aa79753a006302000385eaed68d747a689f194dd86d5da452bf2f327d795d5d504e1a59b038ec702d9ad78f74c269b6c97c8b2b6496bafcf9790dc9c608304da86ca5edaafbd62dc960bfe5c8bf1b4833e5b5177e26bb83bbd28415ff617db4e3c3c33b03f10427bbbfd4e1060330000000000000001e772fd0127f16a4db9c194d7a039b46117fb73586a2826f59597af6eceb7a1762ffd8a88d62d846f2f64698505c921ac735fd08d784e833d930c8127fd8e2439e1d4541db5170e5aba306fbaac4c28ee6a30ad6e12886418dac926f46113c8ed01d146a9ca2b98171b63bfa0629ea26d256e8c9f7d6d936945e568dbc707be87439b65cdbd9bafbd3da43475bef08dda59fe1a7f661626e23da0ed70e5b2901f5a34790ceadb3dfed265e003143993b2674fa12f2188d88a1ec03c6767028d774b495a132f89b9404ff9b9772b92f22a75f5af5c5f4ae3ed213881d247141fe061f96fd7d619a657238c960b52cfd836e1255469eb787f1472d19091473fd26dc86f6f7ed613ac985b2c1716ea53b2cefdd0facd69b8428336d516de195422cea82842270a8b20f9ebb44b9492243430943540c5a82c17e6ec53e3ccb386925d2675d03d9a157757c60aa611dbb43873e89d8501d3a09aa7a38f606ab7e58a4d9aa456a125c502b9f5c0963b71348d71fd0db9aa7f9d4e6acf245a77c7701d4a5f58b876b154ba44cc2988024d81aa882b7babb80f0dde1b3468e9e575265c35d979910b8aa2cbd639db98268d9c58efcd12f9cb0ce2d13019866741b2efd0410d0129a6d06f0e95065ba7c41bddb6f1ede6e61a3016f9a5b53a7ceaa7f5d3b653c8603a50581e99c98e4d6bebbc914ed675efd060a8d9e8d796d1d5de0714014dcfd489a4810296092ead5009643fc93579e089fe2cf5e09889001714b12b550a4d7a85fb3538c58526f00075b2de37f4fae993c2493725911cef68cfeae49705844e16614944a9cb5e45784da4d1d4ac73b62340c175813aea49d1052f81cd7e2dcbb00f38473075d238bfe5dfd4f44863ddb2680e3859bdeb94044a4c469e55823d9502df43adbb60868d8240ec0bfc8f617a81e8d967710cb5971ad55b1069efe4b066c2e6efe4aaeccf786e5fe01f43a66ee8a2d0e6f360bf3fd8f98253d487c3f413a60945b6294b38eb9e67aa7fff203bce2f8e88e3530615ea44d8b058c92e4724821159e83baef0c17bb7bce9503bdc217758e2013b76028fde49121a4e9fa9219a9bd340a6feae9d0b4ced850f82d73f029e8fadb622e6b21e6829288054dd1e7bf5239f5750d97fbafba6753ca1fad8c2091a6a822f156e9d1667490fa0e6bd2668003f23382c651334882400adc52dae8bc4162cfabffb71dd89f3ffce25086455eca92ddfa2186fc8ab9cafb260e9a553125ec7636b0132f2cf4adc66f2d9f23d5bd4d2e36b1338bc103b59733f745e5d8f90d99bb04ac330224b9d609f695cc0aa93cd7c358c79d579f4f556bfc0bb42134ecf82876dfcbe22f487fe19cfa59457a3d3eb9846a99345ecdba7ab4e962456ccc1dad26baf9717e9982578296befd71d046eff05ddaed84cffb8d7b40cc264e59e43ceeafcb26c5bfaa5f0771d6e50b2874cfbc4a42bbd1866d19bf069ef65aed77952414de74096796388b2b2646a570dd6cdfffba2ea2531b8048d1d7a6cdeb53acb96be25d3206a8829b4ac683dafaa3aafb91778ef900eb3635afdb7a9ccda84a711c21018317cfca7101f35d34bdfe7d20198a3b7909c1dcd40d6e83043c246841b989166e85b77dfc849420da0a509256ea5dbc8ed088a73309df5a1340accc50f56fad29e37f3703a5116e6167b337d5a6787f2bb976055e124ada49fe0782836943b7013c026828c8566c75cdc55becbcd2011f10c110b0c388b0fe683b1eec3e8ebc2b3dddff465a8c13aa5b40222ffc0beb32edc9c6c80f08d93cf3209d4bb1b34279319526f186e0250536a3e8a5361fb034122d70e3d0a9bd4d3c62452aaf55d0c86648eb8a9324138f3b83e7b6e77b9ee70239e1b1c81c953f53a5524e0033b51a840caf171584137d46111fdf4e5041f560d2bb715c3f8a0892f4d65d65a7dc8e5130d444bdfd5af8c657eb7c6705950c9be7013bec799aaaae7b081b9f88f8d50cd92ec4d57ea980b5722c71cad6c75aef5fb2ce6c38c9ef53b580c49406e0dc4a85438651e79760670061b94a33cbeee90ad92954544e9c63086571980adc9072e54ffda0377e9771bc212734ba71ccfe5d433eda4909dd806c669283ae08ff35f4a6f768aa4aaf4e7fdd4d5614585d1269a3486971376db161df03118d02b0da31ed2e6fca2904a4b4be9f6578a7ef4545a2534923e4b3864a27612501fbc35e76bbeebe8488b222c99cc508db29d48aa335b4d2a0974f948c3207c92eec89716239dc6ec857776ac61ebe485c29e64ed8d1bf0acb547515c79a3dacb2316dcb5979d23df154e1fafa827f9011e43c5323478f9f48a89913bedbe4dc9b0c8535f8e82fe64179cd74d7fb37d7ad587b65af57b3784810c7b6ee412b6eaf5d1500082fc208a921bf94ae5329016645967c568874abb19a3ee9f752e7b17f35d49b73a66b62e5c41fe0f0683824123e3f0b6b5d3a9b47d2b5eae10913b08cb4370c754d769d6cfb4e4f30fabb38dcf243009bb8f36b6e2e086d70d3286b5633c23559190a5b0107c85474e9e3e87c7110271705e6944dfb232d6a9624d114baa3fa91108d3ba429381aacc0ca9ff188dde3c8836565b4d858fd0cf99c1f14dbf563128d0525c67b1e8014f1a88511d16cbd41046f2c13fc972797b65f3a8ab4407f317b64f4a458b7bd778349d602becad67df6d15793878f4403e1af6f4f54509a85e32e72eab2cedac74da77031908b3f358ff750140ed750267cdcc7e32e8ed32e461bf0aa7d8173e20f4352719a9297f1811e05f691421141eb7fb9d1997b596c629f89b96c08abd77f12f0ad8e76122a17c707e159f590ffec5947392d76ccb5ffb6d4311baa6a00957d185df86166a58ecd9956606ee147229ab58c3664d4c4a260a04558de5442afca4f1301bfea71b327238061f69f78f6154f684f590475bdcc6748775c3275023092f1347eac859b0073bc94e9722aeb4435d816778aba600b33ccc86d7ff502ffd3b5e5228294337c32c0b8aaf95a82cd920e095d0fbf93707be62fe12a27ab2f6c9fb07207787af7c50a4f61e1d860a510726125b0fccc8420ac41897d90f6a8790e984cb9f89e3ab1885e2ccbb3b17253f35336f423e7e04f31305330f27fac32b056117db89ddaa2a0657054e9ad0853ae6f62aedf30196f9b94152c7f7bbf88a83f2f58fe5cdb0d75f56e6050fca4047ad11042e0fd4b2951da3892b66a7674be99d1e82debd98493d80d857d943def54e7acfe405d2672f582bb64924c25495f2dc338735ae0d2b159fc52b26364375630c72cca71bda7b01dfabf4822037ee44f95e934321d853a87bcef2963382b6de64082ab9b3a0c91433c1a87a45c6290a804a34fce3b86e761c58896d0c9f3708661cc61aac282619cd96c60713dffbec7b357fdf51279d50365e008eed72c32f34003b2fc76089238d434d5d912135a553f543b6befec4f7a9496c90ba236eafc7953f4a081de67e2dc549ff15c7734bf12b184670d0424bf20f53662983749aa91a65651d899fb4858abc55282552d22be27f697a7d89cf548591d7d5e7a16a2211c8ff09792e81a9c9042e58a5e76ee678580d3680840465a10692d45ce84faf5cd7fcc9aca49aceee374814110abdda662f4955d99bb27ad310d47e6fb735ce5008fa374d72924f707dff39233bd4109839c3bc61054f7e6715d27e55bcc3464c5c31d109102b95480a0a77e69a2e2cec60c0ce5b0511e8b54445c6eb2086aaa9f47a7130b28fea6fbe2fc26d68fe52d14193d4498f5164f652e8c0259f34956331526acda2611357cc259835351b250137ae3ed44a0d2d25796a8c0cd5d84a0753444509fc0682ea0aa232f6937054864493acf2317c626d36bf13251a92fdae72e7a184e32745343d2b968f2497e79d859059ce132bd898a84c989e5687537caddd4d2f8206e5e10f2f44ee6864baf71ed219c294a7373c5730323b19893b9fdbcb6137d0a5045c3be8bf837c6f5747ab0d91d8db1f17fdee9860e3123fec121148266e8579570bde602ef156ae16ad75fbb31db0e451e06299924ccf2963f600756a47ffe688ad700ce4e1bff02f37f9029a799fc53133b1df2841622981cbe9a1e2753e0db6ecc35fc2beebce4a28c47f6f1ad4bd972befc6fd606f83dc4d319b4935c65709e1e16e97c893ae007634b0883bc2b8a4e2174bcf6bd485c47b9c96c0b11939c4f5edd3db999124d46a4ce4c2564a535406430aa679b2f850272dda5b282b3f9a2431470765e00eec90b310800ee317c2a6aae192552b9e85adafddc556458b6bd5b5e76e770998a2a29b1fdbb37b2f57aba1360f912273134e540ee68c097b8f11275c30171ffa1875a8aaa45106758429061c20330a80f1928c2a9d16e33ded189ac103fb021ffdde726e9eeea1e03a3fdd9f34d9e52b4c5be2d3855e9b60150f7acc909a5d011a3f98cade7eb101abe935372bc81f4b5f18c806de51ebec0a8e032c0e4bdbdbf56429aa1996ede1bd98c7263896f81471f41cbff7311b17b42905d802a6460668a773ee1ef426785f866318f129e2cea728a7f127cd0433879f48812f5ab56fafd270b2cd5186f199d3b875ff5c3c20983e4acd2e8fdeddbb3ca68021bcbb9f9f31b3aa4a07d365b1c72e6b7096241e07e441a5e5314afff8b6285f04eedd74eeb20a41b329dc448ccb8161244711b34982dfd42f66da04e132757c16e54bbfa0d479ff8983eedddefca29a53c588db5e6d0f1e5f4a3f51f766dc3076ef722885844d8655301de79a24b484e1759708f1ebf2716b9688314217b5874bd64d2204efa872283ba9c47d85a0ceb5e5e1fa1cd2eff888a74c10a6a3075fcfae2353154cedb9418f9937a06b02c198e608017895a02c65039195e4c91b2dafefc1e238c069d887d450ef3cb2f786f59bb2e9e4caf743382d7aa665b8b32f484dd44fc9000f86ca3ef57c6a39ba31790f3e12c402d1e3a09a892923e3cef063ea8c29559fb2f3dbd6a4e019f037ed89475dbd825962f360e396646f8ffa00c479f9e8460127b728c543117dce38ae17cfb36b109110cf44f2a712b6cc6b2220db93ca7ef58b5fa163559d10d80aea598afc1221290237172692b418ce4267824dbd237ed2143de7a9d73125f8c682a2a2fd42d537bf8fea48336aa508247814875ad24c541386133d8fcbf28ebd0451a67e7d69ef9018609dc09a4f36dc93953006a82c39d601022bc425dedc2edd6bebabe78fd8ba17ae2b3c4fd657e6b9fbc887e5ad442326cc872075cd960b615fb36b18d140735830da257a4d42f2732d501b21cc883d8beb61ea72961864affff658129f91a59bfaf9dd38ae0cc92c7d8f68d531cdd5e06fd115ed9b4e3b24350882c3914c5f8d2df77e8bf615c6d7427665e395cb5487e13c8df9d3935a8431d95d02a26373dbe4f66a71b31100516596175b17fc6d0fa0c5f0d20bb121ec8fd43567721ffe0e1fdc38d20cf3adcf5004784edbcfadbf60d0d1703012ffcdf918b091a4d2807d896aa463a8f037dddbc01024fa34fbb93a06fd3ea23bacab8fb53937425fa14d6b819d50f91a4cc75689e05e988b8dda6ca89a78acd8eb68457c6dfed5f08aff4523f4695e79c315390f829f1241eb78d6f618c6508e15d3cb6ef70f0c4fcb69ca0e90e1186caa9de5b0553729af8c795db4578e061748fc25851e607dcaffd274e3a6e2d561ca4a55684065e1cacbdb5cd75fadd71ce5bc107365e6fb9dbf778248261613d49c36d1dd1b3403580ff4e6494291690c4508a8defac836876a25a4e9054ecad77937cf9df6f22282ed5f0a7778b4affcaf09f103464864c8c1fcbae97d9e4db03750213eb0a78475b45caef4a477f1c73dc8f9e39dd7d4dd5039606302000381eb5d013a1bbdfc28e27c272822893a4b674355a29a306afa132cf3fe9dc2955ab2375883d5f7e42ada61971ea91f8af2f106402c5592e676a32e3313d03af9eba6e1185d722a0b726da16714e13cd416c8e99f1b7f0aa44b721c483fdf593bfd4e10603300000000000000017823c100e4cb4ea3cd1380fc7986f67a937b71320ac40fcbbcd3fbd3f37dfbb8c4ac0eecc7c8b91d14c7148d2e162d1c4dea595dd8dfb80c0e064b926ef679d2eae0973773f44dcf8cbe7a6e53035366c0c9131cf991bf8eedd5a759ed33baa868e6e3849c93c40bbfdd6d485ce31941d09f9ca07c7d3a3b724760e637191c5344fc7812976c541de2005ef96fc57d8645bfe6e9cf5824a0e084df078006f11dc485c39ee1d196d793a544d458358e4d949c5449a63875196328fda3b29ee227add62fc36f3898512ff596272ea40d79f376a890c806fcbb33d8e7d1552e9aa3dd14420342039157cb991401faf3dcbadace85d5d093ef744462079028c9e68c9aa48b921be8f809b950517af97da5d0e994d1c68a1a9969972a541e3111b0710e552ab40927c165192e263fd00af1b1f0d7eacaef63c52852336c0293b0d0a381b0cd90864240dbb2f6cb61c7149f432a11f62080f7d47d9a04b854b4490eb7a53b4fe33e146db108d235f6b164d22a4a9cab38f5501f4e2bff1963a327f757b8df26d2f65d2d1b933fe6cf8d12c4c7cd8c2f5dd7a69c989516e729b52b6688a4c29333f21a84247e52b152c455d45f582fca280bf818f7c0d8967a43b5d38465922e4de8d2eff49971d28980793eb41a5885cdb4f32e528edf4de6939239ff1c678160b51a1fc5d6e83f3c6cbab2aa88d3e1ab8911779026ede67a6a7b85a57b8a09665150e0cbc3dc615e1d5e39279c2eb24c80423b0568b481b5a37fac1d88b8f686b149c9404b399148aac35515150fbccb29018ddef5c9d219231672ba884020e50ef3e11e29a50a3677fbb427174e2730b1a5293ba9d2f448ae6070294a59de9f0a174273d580af7c87c07acb27962588de2d69c9adf01ab86065f180daef68c9e3399aeb1c290622412484bc88d182ebd19833e6476e24a70a0d1964e61a9258346fa8237b9940612ddb90d91779c5ca2e294679d0ca15367b5db571b81fa0c7e9871147ce9d2729dc3168296d13ee2dbde145ad9bcfb0e24e2542c8a2e06424c5ccf3beb23be0b57acee847f579c1d548306e6fb2fd7bc42c529415002b292d9ce82883d627625a76299f3d055a031be110bcadb95eadffbc6a5a14c97d1a6169dd3ca058e0ee997cefd94f2595e39c06ebebd2862edf7242adabc9716c28555f5ac93ee2609d75c4a852d788eff783c3bcac47b8f7330d2359f004879df8a475ba381c32379d3787761fbbba34a8e9a59fe736bc489562e2ddf71bc9cddf3ee0015857939b6d1af58d3a7fdabd925c8b2e724f0b6a80e7c5c1e7d04bfcb8cc44ecc172f3c18cd73d226f62f4a1fbab7cc6367088f61ec3e562989e01ebba29f8b7f6a94c0c7b32fdcabfc2dbe4ecf404f5fc7d5f05d8694f95c735849ad1e32a44810da350c4cf08c61d8693f468578d09fdb924278add9d261daba0ed187210f239bb4a97763313f2e006ddc202d4550412f68c5be848e1d34a55cce1b894ebc9dce7e9cc16859d940bfad3dd848afb99e2868a92b1d9da7a022ea7405abd42a79995f7351627ced6250f5fcd4f0d179e0101ada67ee8f96e4bd0d7afc1da123616d7a588e07ba84fe948c8ce1e7b51f88d8be970a706c9175d9e46c23388cfff0609533283ab8d2282487f0181d45274ace8a92a8a0eff3d52aba9732a64d787d0effeaa58d03c9df620a43afd2de9607783069ba61e2c583b576150baf140ee48468afe18ffd9da3eecca84b0aa3b7a7af17ef69d77d6f0d99f0e83d9a30652b3487aba49537381ae0afc2885c70ed1fae6dc5cca933d92b8c089bae4855477584e32331623c0369f500d4b36d62d15a81a4d7c197584aa30db415d9197d9cb7ef641cac840a023fdee46c66e3176bae974cdd58ab5ae2c7346390dc696a2208ca7a18c8cf671962791f4e827420e6ceb6cbb58b07054a2355dcd30c2edb64f536860515d515521031f63f9c2a8442694746e9b4ebbf5b85afd96d4e6c25a50013e363681f229645455892f1a1cb8b2a8073a925ecc3832c339d97e9249a8bdd695616cb2818a26bebef23bc94a58a411be30683bcd16a4b6472ba04fc401ecb59f0486dc5b01ac1e0ae57a132c768e4c7fe27dc9b4c422fa647953ba9bec22cf8ad5669c913e0731b03468ebd6009c14283fa1f195fc6636eb30e12cde2c263ae984980a3cd8aacf424e0ebb68c4e9521e2b61c2b39d7ede48d7e98837c7d840455a5525b98f7bf79fd6258059e4e6925db4577eb62b5263d91b7f17a24d3b0ac1163e42d9c367a363034b5c03062c4706885770a5fe3af5ed1ec6e2fa2d3ef23a33acd2fbc30bf436999be36ec7cc9cde96a96bc34d0e0edee7b0ad98a35d8bb1699312d3c1b4966003a054a9bebd8815ca947205fcbfc3dd2c6240a6b911ded609d2c2cbef2fb151d80305615d60ce8fbf4089946780d10523ac165ea7bc38c3a2e6bf800b38d47ca603dcb20bd4dfb40d0c02cf2f3d2727e8995203296b06f2c353f327b2ec1d9503b1060b57144ca9b648c1c87ae982e38ebdd961e3beef4e198eefb1b944f79cc136d38ba449e9800cd2897a2f0e15856883a839fa7f89220c02703f704d1761d8391a183a98e6fc0d9bea48440eed02c84e5e4b70c202c2dfea04047085763766e28e3d4b174ccb7727b05d74c55f7a91de3599834697ba0ce4692a14f966c53fb735109e20599741df2a6ed21d67076dc078b8e565f3afd95e7762bdc3d9818cd69109f59c45aff6088ce3a5ecadf3ba2e10960b115d39d02b559b16488fc7b8a23cbe534311baf5731576c5ed93bfb838edfe4c7c2eeddc2405e8cc4c741f1e6e562592be7f95ecbc26251edbec6b35581738b44673e8295494f804e6ecae2b23527946956f68546fe01b38ff1fd0e8f3090916a0e421d804da219bdac63410d62749b429f82c9c2463c52aa29aa3dc0359051cb5666c6be81a5e7bb85f62be8ec4dd10f2948f82ec66ef4e0471fef64efa4cce7232923b19c72862c674250316448e201abb5fddf248a747689daf8f04343f1e695d3fd045f5e32e98462c0d65d0ff4d751c03826ce02c7513c3c56776325d4566afcf780876ce17fea8450e48d8a36f22879d83014dc6fb7e7ec0ea5fe309723862bb5e2cc1a4899e18583c8ceae1246ba8f12b357dbd91e51718486777b192ac97de65a35a40655b25426a30373278e897a2b99658ad27277ed32e7eac3b7c5d5c775110b5327dac2f3d92125ab3b3bcbc383afd93e795764bf2632c7b4c98876c95e41b7c3fe2952db073cd4ad219ab3aa5d0901cd53b8acd8e2fd92f93d7e5ff0eb5ad97a2240764fc40e8683a1cc28484fb3b1027059a53ffa5552406e9bd7c3d28dc0b081a37cd5a13af22288d39975018984c084cadfaf5ae4c91d8b00a6466ab7cd50f1f143f11ce8ecaf39809a3c4833b5e11945564f1f0d025a07427100e60bc40e065bfe938246b3345fa8fa4a8ee9bb50a5152c90f43d239401ef79894b5f2db6e8f2e98663d6497dabd94f13d9cec86bd2707cf32df56f5a6693ffe9be7ec362c0bc03b6816269dd2b72f5638209dbc1afc97eed232f2916f19d4ccabc55a6cc0a48ebdcbd59ce0404ebb47740a0d802f057116714ddab4aa3bcb5d8ca20069af51e09f941b9efd73e8515aed1db7ba79137146e5c14262dff94a885cfdf435d60d91bf2f508c110106fe4a0eb4c32ca382825ca6a65aa2749a224a62d8a1dbdffc5b53bb4cf2315e9d107a73721cb3ddd111c723cacecbc219ae5c850beae3b3b6a5577222af1706a625965b7c7c7f13f01cbfa9c6f1cf406fd177433b9ad4213fdb30abe01cbe931cde34de1650e69d348d25b6128a26ff8b0a73947399b4162bb6513043167a3871960f0dcd5dce5b6ad680ec782ca48515010244d5692ce8e6a56c291c3512e7ef91680769be39530839adb5a8898d83834d398e63ebb2ad00d42d414233a070dd6bbdd6093c96eb8478953fb04c3e82a7c84a798d7bde36547bdf4486e8bb3a6fddcd9d7ae1b007e61e4da3b85ea327c1ab8f40a66b36190eb3bee753bf1043335ce82cb31751b7e89b84fa9ccec5427b28c161512a963f80bdc72c38fae1b32b4d7900f983b51f42144a82514b535d71f3dc80c0b28f49c20b346d344ed9c81b556ddc49263ddc687e64daa55d659d0a806709a62065e1eb1c694a6e46f6c8b10bd47e76664c42b9d992c23999ce516a5cb6d68a4748957c63b2db6939b86adad8fcdcfb5bb643b08e156d61e5bc4c5810802d5afc1c0e3b160b01d6e5675e5172253d1d943b96a6a6c940925a4f6850612b8c57ddca11e893fcb5e5e791a6749f75969b49c684aca0399bb322b9a72997e204b649c3d26f726ea0a49920ebf4b533bd4b38e1cba3a2422e37c3e259dddd8ec10afce3f1baf2bee470eb752c5721aa49a3b8b4bee25a9f6aa626ade570864246ca2a5c6f0d183ab2d909ebc336db2126a4fd24de704befbd2f07c7cd6c0169a07777e5a583fd3a9a9ff1241fea91c504fd5e4d6c6e636a9a5c3fa56824e74c68c1ebb8c4afa90ff2364acfd4547fff73f94f133d63bef1ddae0a8a338ee8e50777d1b7907f4871bc4efaf746ec2c7b9fadd717bec888026e32e5e26bb0101a269816b9046c29a42b35ee15e203fa26d321fe03f042a8f21cbd62e1bb0bb371d00e46492bd655d0261129393c023d20ce9ddf0f0687820e563d3688cf1e7946a0cdf09737c3715dfa8a6777bf94ddd2d127bb5ad942dd07738eac8b6955019799ce77cc42136dc9aa822470ac56efcd359bf180e95f3fb312cd0ba9ee9bab99560d0b41ea7831bebcf20f27e17303208ef66d5c0f82d26d8093f002418267115e10331646fd87ba1f1a42f72fb45d2a4a4e4353698863e65a7cd4f6f3cd0dea28dbaf5794de216afe202b679899518a3dee9d4024afa3dc9d8d4eaf0179b05ceb22d1e60bd941d44c3866362a92a7951d9de36e4e7d1a681fb2d9420e0fbffe795e9683857846ae0e834d818f990e575a7fa7efe7638fad98fc5b680abbb58cb8da78d783a7ca16fb7521b4be25d4fded9417cc7fd9525c79df7e52bb83894dd905794282a7413bca79bb653afce07cc433e49ffc38d16b7be05c1c9ad05988ed672e1b4dcac2a5d211d7ad1b790e4ec0761533925f528a21305b942e0dd10efdb99bf1fd6d6b906ea0d21ea7bcbb4116490d97246458fe29644f149122586b6f16df620ab1480b55f27f3e8bf32c2c094bece34cce03c20b5a2d2b73481c7cefe4bf56dc76c7970dd77673e4383f62998b6923f103eb0e5c1ce91e43da83495961460b677c261a027db4ca979597a8232691c3ece94456e313ca57f8c2021334cd4e0735453597d516dcf6e04d386ac61bcee073f7520d205fb1ec6c35c6c96511e8a067ce5ba3d701beacde937c925b204ea011521b3e1219650568ff9dda90e043c9d20224fd767670586812a41ad83208f5d62f7892b22500be3ab2028207f738c21301e1aeab23d1bd4e46d46f2ec1991683e987d3d834bc260113372e3eadbf825f86d42f463795050f5821a6afadfe42cc1cad6fe942d16af7e35dd08004ef676558ecc8801c45d37a8c147102e120ecb7c965a2e33ddab0a43133692de2133cc64e655961e66caff271e0625c469a24baf126ea7d300bac5f0335dd5926e99394d45280cd6e14e7c3d5be3b3745b617d9f7e01f0bbe15a0512e2501bb7361a17c62f4549df0e765cf8a2556a9d1827ccf22c75680db0d7391da9f0c18926bb90423c7e084f4fa11cf05914bddbb8359684dd920db82bff035702f2484621ea1d71d2589a3d5db2a876d78b2228a1b4b7b9ccc8c4ed6f5df7010771ed118f96bda339ed2025808099333224f99f207e3e808312f49cdad7e00000063020003810a02fdd12c3cba97447dd59111452581743c53880ed8fb161904e6b97c4ce83fac66328bf77cb920ba7d2d28790a9dcdaeacafba83a59a56315ba410acd64c6ebd7862608044814df5ad160befb4eccaaa7ef1e7cd45a26898ab87c6c3ad4dfd4e10603300000000000000017d32a9010e698107419c4e5b47c05ec25624ea0d6f432f75b744a15b8f8381b5fec29c0b55b8eb600b91a3e13c0e56e601c23882ffd62fc218b1da72e2ad732a47f7279d32cbb24eda0caaeaca8d8fe4bc920e0baa6821b47f7790416a5bdf13d691c51914358a431dbb2e9154bc01da79483cc9617f4d57a6f4d2d1380ea2450c292ada85eb663a23c76a6adc0c7abf8ff71b41a56478b66003ba839295df69edeaccc54a9b3803c9d3eda9cd47e478fd852a316802c8def8014a449cb886d0fcb5d56086e8742a346b983657f331330f6e8ec4bf72b314cc6d69bd94be0bb6e6896ec01f773c1a4c329e7ddbf326b83780ab22da08a144fc1c8dfda604cc1b2858682ad3decb097c1ae3e992596ae997422c7d381d8d9354be1658c43e5d5c1e49f0e7263aee9093c018b09ef44ca7adf853c625187a8ed252527b94a5bd70e13c30b22f05038404d99c18c0cd76a461ad7dc4ba63d132101ee471bfac835eabe0f11487ab7361e337f5ca8dca3cfb25de4958c58d59df6ea016a9436856a3af505884a4e38d9cc1ac955c40228c22ffe385dd48b3f1c27d40e7794ce62822645b2a2e42346f9771f2744fdf5064309f9f7f84747131369ee9b5421a07d24ec6e7baeaf1c99cf8339f38e44b0864ef46684815c320df48159f83aa80e247d617acf1b1c7a2da56cb3725811ef028987573f59c90587f88553fc6a11723fa5e45424de05d2b0f548dff87a8e1b094a929f695f01b7a127b522ba2a6d6290991d0985af8059f002f514f5027fe98d292fc85f050d5a19189a27344f83f737ccf254c97728054ed01e1d229f65b2b9d66a7c82116bf26ecfc026446cee24c5603e0bf0df9875461623340a7148de14a058f1a37e8c627bac2acfa2aa1de65d1349e7d02d565852af1de756203d2aac22330c43b12f1e1889c8ff2959b1c11e85b2a1f577b47e1242db2b1bb4cb03979ab255353bd91a728a67827a86899ab68b3ecb64e2303c6c701c1ba3aa09740264a42194277fde906dd6caab566c089fc83fb9ad4528d50c48d72d8a68e8bdfa846284979e7201f41d225b2a782ae77cccef12da93d2c2e73f5df35f75102fd7bae8c5c2c92e79236f687b8559b7d625658f6121101ff205dfed8356fd447c9670330b3f197c3249b05dc72f943f1760489dbb1bd53b2bbe65ba8ed7c880ecf97a1cdb9e78551c978201aed0c1e6202d2bf807df2334bac733ae2cec1af8a409cb8b32830fa0696c18ad11d99c3cd0de7136b83d903d955acb584117e4ce39958d75d6e1ed790e4f5613fcae6a827078a45676afb7fa82f0642d37c273e2378e58403ca9542d542d6ae549752bb9a85cb1c5d71819cf8985c5fe52e6de0c75c61a2d4b597014009e2bbfa7a44085bc75af6adf6de4d0f1e5fa8dd68d5e13e7b10710d9ae67838a775b17370a052c019ee984e169235a2a1a20e7a157d0e3c93f477907e48f018780e0300b9c1cdea826a81d9900547b7fb7e133d5dea37482e40d27d3feeea57a07dc795737af5f01286ab37003c7dbd8e335978639704333af1988feea17da0af7606f5cad04660495009788afd99412e036db5c9c9fb0c643873fd0a301d7c37975f6b54906d3cd992c7c435b334f695c1f87ef071a58b890b2dc2771c2bec4ffcb9c121feec068ff0cf4924ca1b3cc10b802558f05d7cc2970c3b0df9cb7ddbc306269dc42d8dd882943182cf092d6007248288822d6ee80bfd24f4077f1f662cd3c0f577f831df25cc20d2c1541c44df2cd07586f4efa26e0c208430889dcd4e548be9adba2def0cd048b57d73ecee8e3005181e73d4d12bf11d225a234cb3019c0cbebd0d9c2f3bea6832eeff2109d8843ee61e682098250641df7bbe21c72c7831c215e0234d71cedd22b2370ef3d574f321c6d45607175ad9568dc06520f33d2b15ef2bfb0fe9e48bc01560dcdd73b6fcba2caeeafaab2646f7b46e9d1c3c992afb18b7c2d9d2f88095c1033bbbb9449ec6467da2e302aea9979b28fcce685878619a8d8757451d5b80d4e57a3a213a599b467703c5f96297ee6ce44fc06b1afbe411f1a665ad0745bd7fd2a5b49ceef6b468817f500479af2a8f6c0e3557eb98df51a4df26fcd5cfcdda48e5441114c24573bcca96356d3c99d01eb8f8a7ab397d6c8a54dd9abde6d16cac1ff2ce86095ffee79a304355df03d72f2d332b50898ae06a775f5f7fcef3784c152f51b8ddf9cfea4f0bd271eb98ebca53529f103228aedbf64f03966c5bc2e774c980cd13db22f3c3f6136b6b03ca6cef7a4f310b57dbbe9431946d784fea7eef3258f10a7bd5dca55102bfa49c04fd117a8c521a5b691249e994b8e935bbfd1b86b5512a56ac222e989f04dd07c34a5219dcd5ab003ab118ad40746ec25bcc056b35afc35b656895bddb4d368623e17a61f3803213c1f122d8e6281d013df14fba919209fc2e4bc538021e5d5ca8a1a751859f908f47b39f1a3112611a3e19264513a7301e68979bf0221f1cb418f9cafb7b81db4ebf08e0c7a1b57da5cfe8e32ad16b0c2fbe9b5f7ffa5c80aa3217b082e4f6c9f51cb79fbe27ba459e09b01b3fdef45edb5d1b063fc99937a822a5a43803b610a3081b67f7279e18481754f3802753c5201a60e4fd89e0947616a33ed4218d8e708ed81fec6e3f39d7a94378d92fd6d8d64769bcbd4cc1d66cdf4ada5b189e03461b583dc88f2972c6e4904afc3b49b38818be26f83c94cff7ed4c826917f3314a931b92d65e562014cd9a1a68ea79fafceddd09b8b0e48eeac86e6190e470ebe8ec5cee12948942f80de6a40dc2c657b6ade6a2ab4b3297ec713bc3cebcf91f8465a14e9d9d5325fed40d2a2af8bd0731d9b626095653e5fd292cd5de3a7831c0ae81292630409ab755fceaedc4e76e78b829219209476b94d0c6224930bd6c7d4a6b06ac9699be79caca17b1a7c9254f1b884a87e44de4ce5b15f312b09210d09436a8bc1ee39b6e5f96ba5b620d614a09259b251910219ae39d65c2650e2d2a27cc0d2dbd5e2aa40b5b4bc4ead5ed531d7f206a4bfbfabb96785b768aac21ab8f11f927d54949ec3c595f31391bea8b4f1a63db49e26d875be2cd4333eb5785ab1cfe7f83c6e4a445702f9178343e039a7651b62acd31d694db89287c1ec5a636933a630b3465d27015e564bd2a4848d0910739702debb3d9c7c133c2a2f5c6d93000ae74bffd2af4ec66180e7219ad8af293ec89fdbb0d43d6b9dc5fd539c338136436ef1ce088af4590f47af91d78338c67b03500d4c69de61b44e09a776399d7cc349c95752405f65b0ec19a14434d715aa11a14c5be94d42114c546af8c02d291b3d54471ae463d249237fe3bd18f7afc569c43e1c1cd284538e48444f39e8c83d9d52f7754c04a6198711f8ebdfbf647002ddb54ca3c8833a3a21e0bd7a8cfa1274f61a36183fcd63670f1f5b425f2d06ce8338410baa860faf2331ef93f781d1fcf10c38b2be7ca21cb27430147466867d233acbe6f7ff46136ef736a1a1b5af97cb871a8351d7774bbcf0f0f47ef10c7a5b26f0a25d403fc7cf2e7bb57a1f16c68260092523c82ea020f0df2660faf2f6d85e695cb672857bc9fd4f7ea0b93f735007d9ad15e661329a22bc465f6c65f442f5be91c665f3d7311290b47fb7c10342a5a367ee18dacfc51a83ad0bba7503b54a27545abe372078505062f4b859947168b46638f3a4ebd116fdaea1d96238c4cdae5882f326287da8e94dfbcf9c82f92ec94ec8706dc6ce194fcf7890e047e106aa387173662ac2ff1302627f80c567fc7e74d36473bb601681bfc1b5221e15863bb9f8d5e30bef41ba5839349a677e35d30e0000596691b2bde87e386998e3e2a463aea434ad9002438375ef1071afe9bc5027cec29b5cca4196b2b34b8f92cfba033a9e2539aeee306c5acb88f22c7799bd7208853a735d317df6c957108c6c10c53e9e1055f6108369aa4918dabfaffa446c40b20c73216e976a9fe03cd157ee29efc03e6a8df077a5222008e37f257816703e1b9e214ebda174ed7b4aa1b5e0494f5285704ff6ee22fc1f386dae624b72a7e24d2a56c97a8d8b816ceddc68119c279a2654f19d3d76cd314e9fb6218b9682455f81c7064e33295060dd0b91b958dc04599a5713795c39b51744b5629512a9028a38de8f674214de7bd4845e53244705e431526fb28b8c51b3bfde0202c50187f6748581d5faccee866d0c317345ff6b65b954ed479750d0a052e3fe3f557c88f4964cd95826a7be6da14b54d4c00dbf9b2392aab6d084262427f24d163ce590b8d36547ed8139bd241b8f18d9d9c32850a29473820f68e9197f97e7d54ec76bfebe6fc3006b3c7aaf370416d758fe4426758fb8720bb764b6cd1aa174a58d42361ca8c2396079a634bea9e492a7e1fa5d443a2299c66ae23a064d6e70c605019527f1b499a614c28d3c8cdfee753abb9b1a5b8d9bfde29a5ea869ab95a1c7c1c076f933938008060800636f357a48862bedfd89a70ab30ba31919bdf6b53edd085b3836657a4bb214cebd2dfae4030d19fb9473e046ce6ec39871150a4f0ea03e3513c5615bb50135678d024e69eb754bbdda896eb0f2d39a1f7671231ab6887902faa3adc79cb77d122e184031f7e3a9cc222b3e9788dd9c417cada21fb6bac493b15fc306d64cb701dac8534cda58bd37121adebe474ddfffa1afd26a999b41280b043992b5b7fd6f4926b5b6994a621fca3d13ead3142d8c255d80c33a86ee4d6ef04289a23f0d39f7b73c30ba59005ff0f1eef21f9ec01e703aafc1171a4d24d8257917b239c5c3b447549cb2c9602188fea59024d6def3b37e26789c2fdd90beaeb30790afcde5cb8179770cd3194d5ddeae7eebad7b273c7c53eb184f17b3934f4d0cfbddd9f8e9b135ad4fffa8b5edb04e2fd34e21f29717f3f2b9c01c0a547b3e522041bc5a0c647d7c8eb543b94856a40ad9c4d2ebe94a3de31b810fa99aa4b19a9a0ee51abd355b3c556f26dec3405b19d5a5da8a6c8e263c8e2e97514053a7c57097cde1649bd6c77fe78ffb96ffc69cd43fea598e611ff55a0a306883b01a44ecdba59e103626f4a08e3444868d27e737ad41f3c2564b593ed169036a7c4b883594bcd141847f22c1933e04fbbfedf71d885c5cfe17769eb36b295950e9a420919d06110774029a42ceba64c6f3ec12404047e78f1c67178e65d1caa49894f8b606244a365744c8c826c682a756f560c1d4f71e1fd566547a8c070fd64eb2ba941e844f86af062e67bfecfeca33f0a69c186a5ad2242e100b0bbab31322cc9dcad523297d53f44c4ad8cbc2826bd2e1f211cf6fe29116f6c0bc5d37f7ac8376a574dba76dede5fc6e72e4853d4cbc0d302e20bc130578419d8730215172a470f98e9bc868c1f7511bcc353e879199d0b25a06cf49184808bdf76c165e91565d0b7328ade3b164d5bf1870ab9000a38389ae1de035eaa0ff3673f6b01ff8e7cc3358b1f6b068b93b47d26482f8d5317a109f1b5475a86dd46df188f6d857b2c753b2323e14b70cddc6c5ce19f67e955f085f47480b55a164ede57fb029f3f7af1e0c0bb569e52db150f69c8763308109cae4dbc2cb22b9d0bf5842f0d80b0c2120f20f7f0f80e77084791eedbbb50f573ef7f7ac12735c91fe2603053c00b66c310029f779f229b249ebf21e0a09c4629900e66c8d86957251d64784d84385ae863e45a33b9f651bae7d3028c5f0bf036dd45ae41a72e72e412520c29e559928bc3f4c6a608f8e22cff57e2b40636c0dd27ec8673a01ad04d4c773970b6678d9e117eb10a3e24faaf4ebebc45b13c9dcbf23567647056b1f7dd319018d2bee8a059c8f2d1740aec65eb54aef3709f1a5f680fbdd9fda390ea28");

        pset_rtt("70736574ff01020402000000010401000105010001fb040200000000");
        pset_rtt("70736574ff01020402000000010401010105010001fb04020000000001017a0ad92644e9bf6cb8d0856a8ca713c8a212d3a62142e85454b7865217890e52ec3108a469a9811ec1c1df7a98dbc3a7f71860293e98c6fad8a7ef6828344e9172547302217d344513f0a5ed1a60ebeba01460c505ad63d95b3542fb303aca8f9382777d160014bd5c31aaea2ddc585f317ee589bc6800bc95e7e6010e208965573f41392a88d8bb106cf13a7bdc69f1ab914cd5e8de11235467b514e5a9010f040100000000");
        pset_rtt("70736574ff01020402000000010401020105010001fb04020000000001017a0ad92644e9bf6cb8d0856a8ca713c8a212d3a62142e85454b7865217890e52ec3108a469a9811ec1c1df7a98dbc3a7f71860293e98c6fad8a7ef6828344e9172547302217d344513f0a5ed1a60ebeba01460c505ad63d95b3542fb303aca8f9382777d160014bd5c31aaea2ddc585f317ee589bc6800bc95e7e6010e208965573f41392a88d8bb106cf13a7bdc69f1ab914cd5e8de11235467b514e5a9010f04010000000001017a0af0b70a2237872fb9e84fbc002358469c51f85bcb6215930df63dd29953bbf5cf090e6df3e3b4e589ce447d3deb7cd4fa7a3c264a3d18b5e245a60add9f01137a4b0365026bb845d512434305eb2309656cd0701de8adfdcc84dd8b05d9e240ee55e6160014adf9a42f6d4643f7ae69d94114cfebc3824209ae010e208965573f41392a88d8bb106cf13a7bdc69f1ab914cd5e8de11235467b514e5a9010f040000000000");
        pset_rtt("70736574ff01020402000000010401020105010201fb04020000000001017a0ad92644e9bf6cb8d0856a8ca713c8a212d3a62142e85454b7865217890e52ec3108a469a9811ec1c1df7a98dbc3a7f71860293e98c6fad8a7ef6828344e9172547302217d344513f0a5ed1a60ebeba01460c505ad63d95b3542fb303aca8f9382777d160014bd5c31aaea2ddc585f317ee589bc6800bc95e7e6010e208965573f41392a88d8bb106cf13a7bdc69f1ab914cd5e8de11235467b514e5a9010f04010000000001017a0af0b70a2237872fb9e84fbc002358469c51f85bcb6215930df63dd29953bbf5cf090e6df3e3b4e589ce447d3deb7cd4fa7a3c264a3d18b5e245a60add9f01137a4b0365026bb845d512434305eb2309656cd0701de8adfdcc84dd8b05d9e240ee55e6160014adf9a42f6d4643f7ae69d94114cfebc3824209ae010e208965573f41392a88d8bb106cf13a7bdc69f1ab914cd5e8de11235467b514e5a9010f04000000000007fc0470736574012108378fd3af2f7af7009fcf06b5ecae126d5446b134c6763d0a2c103b61ec348c5007fc047073657403210a1862832b5a1ff4c222398ab482534c75decc4176450df7c78280b4dd90062da70104220020c731ad44c00a2928d508ad82b05868cb42733a5b0d0b208f483307ce8c328d9307fc047073657404fd4e1060330000000000000001e772fd0127f16a4db9c194d7a039b46117fb73586a2826f59597af6eceb7a1762ffd8a88d62d846f2f64698505c921ac735fd08d784e833d930c8127fd8e2439e1d4541db5170e5aba306fbaac4c28ee6a30ad6e12886418dac926f46113c8ed01d146a9ca2b98171b63bfa0629ea26d256e8c9f7d6d936945e568dbc707be87439b65cdbd9bafbd3da43475bef08dda59fe1a7f661626e23da0ed70e5b2901f5a34790ceadb3dfed265e003143993b2674fa12f2188d88a1ec03c6767028d774b495a132f89b9404ff9b9772b92f22a75f5af5c5f4ae3ed213881d247141fe061f96fd7d619a657238c960b52cfd836e1255469eb787f1472d19091473fd26dc86f6f7ed613ac985b2c1716ea53b2cefdd0facd69b8428336d516de195422cea82842270a8b20f9ebb44b9492243430943540c5a82c17e6ec53e3ccb386925d2675d03d9a157757c60aa611dbb43873e89d8501d3a09aa7a38f606ab7e58a4d9aa456a125c502b9f5c0963b71348d71fd0db9aa7f9d4e6acf245a77c7701d4a5f58b876b154ba44cc2988024d81aa882b7babb80f0dde1b3468e9e575265c35d979910b8aa2cbd639db98268d9c58efcd12f9cb0ce2d13019866741b2efd0410d0129a6d06f0e95065ba7c41bddb6f1ede6e61a3016f9a5b53a7ceaa7f5d3b653c8603a50581e99c98e4d6bebbc914ed675efd060a8d9e8d796d1d5de0714014dcfd489a4810296092ead5009643fc93579e089fe2cf5e09889001714b12b550a4d7a85fb3538c58526f00075b2de37f4fae993c2493725911cef68cfeae49705844e16614944a9cb5e45784da4d1d4ac73b62340c175813aea49d1052f81cd7e2dcbb00f38473075d238bfe5dfd4f44863ddb2680e3859bdeb94044a4c469e55823d9502df43adbb60868d8240ec0bfc8f617a81e8d967710cb5971ad55b1069efe4b066c2e6efe4aaeccf786e5fe01f43a66ee8a2d0e6f360bf3fd8f98253d487c3f413a60945b6294b38eb9e67aa7fff203bce2f8e88e3530615ea44d8b058c92e4724821159e83baef0c17bb7bce9503bdc217758e2013b76028fde49121a4e9fa9219a9bd340a6feae9d0b4ced850f82d73f029e8fadb622e6b21e6829288054dd1e7bf5239f5750d97fbafba6753ca1fad8c2091a6a822f156e9d1667490fa0e6bd2668003f23382c651334882400adc52dae8bc4162cfabffb71dd89f3ffce25086455eca92ddfa2186fc8ab9cafb260e9a553125ec7636b0132f2cf4adc66f2d9f23d5bd4d2e36b1338bc103b59733f745e5d8f90d99bb04ac330224b9d609f695cc0aa93cd7c358c79d579f4f556bfc0bb42134ecf82876dfcbe22f487fe19cfa59457a3d3eb9846a99345ecdba7ab4e962456ccc1dad26baf9717e9982578296befd71d046eff05ddaed84cffb8d7b40cc264e59e43ceeafcb26c5bfaa5f0771d6e50b2874cfbc4a42bbd1866d19bf069ef65aed77952414de74096796388b2b2646a570dd6cdfffba2ea2531b8048d1d7a6cdeb53acb96be25d3206a8829b4ac683dafaa3aafb91778ef900eb3635afdb7a9ccda84a711c21018317cfca7101f35d34bdfe7d20198a3b7909c1dcd40d6e83043c246841b989166e85b77dfc849420da0a509256ea5dbc8ed088a73309df5a1340accc50f56fad29e37f3703a5116e6167b337d5a6787f2bb976055e124ada49fe0782836943b7013c026828c8566c75cdc55becbcd2011f10c110b0c388b0fe683b1eec3e8ebc2b3dddff465a8c13aa5b40222ffc0beb32edc9c6c80f08d93cf3209d4bb1b34279319526f186e0250536a3e8a5361fb034122d70e3d0a9bd4d3c62452aaf55d0c86648eb8a9324138f3b83e7b6e77b9ee70239e1b1c81c953f53a5524e0033b51a840caf171584137d46111fdf4e5041f560d2bb715c3f8a0892f4d65d65a7dc8e5130d444bdfd5af8c657eb7c6705950c9be7013bec799aaaae7b081b9f88f8d50cd92ec4d57ea980b5722c71cad6c75aef5fb2ce6c38c9ef53b580c49406e0dc4a85438651e79760670061b94a33cbeee90ad92954544e9c63086571980adc9072e54ffda0377e9771bc212734ba71ccfe5d433eda4909dd806c669283ae08ff35f4a6f768aa4aaf4e7fdd4d5614585d1269a3486971376db161df03118d02b0da31ed2e6fca2904a4b4be9f6578a7ef4545a2534923e4b3864a27612501fbc35e76bbeebe8488b222c99cc508db29d48aa335b4d2a0974f948c3207c92eec89716239dc6ec857776ac61ebe485c29e64ed8d1bf0acb547515c79a3dacb2316dcb5979d23df154e1fafa827f9011e43c5323478f9f48a89913bedbe4dc9b0c8535f8e82fe64179cd74d7fb37d7ad587b65af57b3784810c7b6ee412b6eaf5d1500082fc208a921bf94ae5329016645967c568874abb19a3ee9f752e7b17f35d49b73a66b62e5c41fe0f0683824123e3f0b6b5d3a9b47d2b5eae10913b08cb4370c754d769d6cfb4e4f30fabb38dcf243009bb8f36b6e2e086d70d3286b5633c23559190a5b0107c85474e9e3e87c7110271705e6944dfb232d6a9624d114baa3fa91108d3ba429381aacc0ca9ff188dde3c8836565b4d858fd0cf99c1f14dbf563128d0525c67b1e8014f1a88511d16cbd41046f2c13fc972797b65f3a8ab4407f317b64f4a458b7bd778349d602becad67df6d15793878f4403e1af6f4f54509a85e32e72eab2cedac74da77031908b3f358ff750140ed750267cdcc7e32e8ed32e461bf0aa7d8173e20f4352719a9297f1811e05f691421141eb7fb9d1997b596c629f89b96c08abd77f12f0ad8e76122a17c707e159f590ffec5947392d76ccb5ffb6d4311baa6a00957d185df86166a58ecd9956606ee147229ab58c3664d4c4a260a04558de5442afca4f1301bfea71b327238061f69f78f6154f684f590475bdcc6748775c3275023092f1347eac859b0073bc94e9722aeb4435d816778aba600b33ccc86d7ff502ffd3b5e5228294337c32c0b8aaf95a82cd920e095d0fbf93707be62fe12a27ab2f6c9fb07207787af7c50a4f61e1d860a510726125b0fccc8420ac41897d90f6a8790e984cb9f89e3ab1885e2ccbb3b17253f35336f423e7e04f31305330f27fac32b056117db89ddaa2a0657054e9ad0853ae6f62aedf30196f9b94152c7f7bbf88a83f2f58fe5cdb0d75f56e6050fca4047ad11042e0fd4b2951da3892b66a7674be99d1e82debd98493d80d857d943def54e7acfe405d2672f582bb64924c25495f2dc338735ae0d2b159fc52b26364375630c72cca71bda7b01dfabf4822037ee44f95e934321d853a87bcef2963382b6de64082ab9b3a0c91433c1a87a45c6290a804a34fce3b86e761c58896d0c9f3708661cc61aac282619cd96c60713dffbec7b357fdf51279d50365e008eed72c32f34003b2fc76089238d434d5d912135a553f543b6befec4f7a9496c90ba236eafc7953f4a081de67e2dc549ff15c7734bf12b184670d0424bf20f53662983749aa91a65651d899fb4858abc55282552d22be27f697a7d89cf548591d7d5e7a16a2211c8ff09792e81a9c9042e58a5e76ee678580d3680840465a10692d45ce84faf5cd7fcc9aca49aceee374814110abdda662f4955d99bb27ad310d47e6fb735ce5008fa374d72924f707dff39233bd4109839c3bc61054f7e6715d27e55bcc3464c5c31d109102b95480a0a77e69a2e2cec60c0ce5b0511e8b54445c6eb2086aaa9f47a7130b28fea6fbe2fc26d68fe52d14193d4498f5164f652e8c0259f34956331526acda2611357cc259835351b250137ae3ed44a0d2d25796a8c0cd5d84a0753444509fc0682ea0aa232f6937054864493acf2317c626d36bf13251a92fdae72e7a184e32745343d2b968f2497e79d859059ce132bd898a84c989e5687537caddd4d2f8206e5e10f2f44ee6864baf71ed219c294a7373c5730323b19893b9fdbcb6137d0a5045c3be8bf837c6f5747ab0d91d8db1f17fdee9860e3123fec121148266e8579570bde602ef156ae16ad75fbb31db0e451e06299924ccf2963f600756a47ffe688ad700ce4e1bff02f37f9029a799fc53133b1df2841622981cbe9a1e2753e0db6ecc35fc2beebce4a28c47f6f1ad4bd972befc6fd606f83dc4d319b4935c65709e1e16e97c893ae007634b0883bc2b8a4e2174bcf6bd485c47b9c96c0b11939c4f5edd3db999124d46a4ce4c2564a535406430aa679b2f850272dda5b282b3f9a2431470765e00eec90b310800ee317c2a6aae192552b9e85adafddc556458b6bd5b5e76e770998a2a29b1fdbb37b2f57aba1360f912273134e540ee68c097b8f11275c30171ffa1875a8aaa45106758429061c20330a80f1928c2a9d16e33ded189ac103fb021ffdde726e9eeea1e03a3fdd9f34d9e52b4c5be2d3855e9b60150f7acc909a5d011a3f98cade7eb101abe935372bc81f4b5f18c806de51ebec0a8e032c0e4bdbdbf56429aa1996ede1bd98c7263896f81471f41cbff7311b17b42905d802a6460668a773ee1ef426785f866318f129e2cea728a7f127cd0433879f48812f5ab56fafd270b2cd5186f199d3b875ff5c3c20983e4acd2e8fdeddbb3ca68021bcbb9f9f31b3aa4a07d365b1c72e6b7096241e07e441a5e5314afff8b6285f04eedd74eeb20a41b329dc448ccb8161244711b34982dfd42f66da04e132757c16e54bbfa0d479ff8983eedddefca29a53c588db5e6d0f1e5f4a3f51f766dc3076ef722885844d8655301de79a24b484e1759708f1ebf2716b9688314217b5874bd64d2204efa872283ba9c47d85a0ceb5e5e1fa1cd2eff888a74c10a6a3075fcfae2353154cedb9418f9937a06b02c198e608017895a02c65039195e4c91b2dafefc1e238c069d887d450ef3cb2f786f59bb2e9e4caf743382d7aa665b8b32f484dd44fc9000f86ca3ef57c6a39ba31790f3e12c402d1e3a09a892923e3cef063ea8c29559fb2f3dbd6a4e019f037ed89475dbd825962f360e396646f8ffa00c479f9e8460127b728c543117dce38ae17cfb36b109110cf44f2a712b6cc6b2220db93ca7ef58b5fa163559d10d80aea598afc1221290237172692b418ce4267824dbd237ed2143de7a9d73125f8c682a2a2fd42d537bf8fea48336aa508247814875ad24c541386133d8fcbf28ebd0451a67e7d69ef9018609dc09a4f36dc93953006a82c39d601022bc425dedc2edd6bebabe78fd8ba17ae2b3c4fd657e6b9fbc887e5ad442326cc872075cd960b615fb36b18d140735830da257a4d42f2732d501b21cc883d8beb61ea72961864affff658129f91a59bfaf9dd38ae0cc92c7d8f68d531cdd5e06fd115ed9b4e3b24350882c3914c5f8d2df77e8bf615c6d7427665e395cb5487e13c8df9d3935a8431d95d02a26373dbe4f66a71b31100516596175b17fc6d0fa0c5f0d20bb121ec8fd43567721ffe0e1fdc38d20cf3adcf5004784edbcfadbf60d0d1703012ffcdf918b091a4d2807d896aa463a8f037dddbc01024fa34fbb93a06fd3ea23bacab8fb53937425fa14d6b819d50f91a4cc75689e05e988b8dda6ca89a78acd8eb68457c6dfed5f08aff4523f4695e79c315390f829f1241eb78d6f618c6508e15d3cb6ef70f0c4fcb69ca0e90e1186caa9de5b0553729af8c795db4578e061748fc25851e607dcaffd274e3a6e2d561ca4a55684065e1cacbdb5cd75fadd71ce5bc107365e6fb9dbf778248261613d49c36d1dd1b3403580ff4e6494291690c4508a8defac836876a25a4e9054ecad77937cf9df6f22282ed5f0a7778b4affcaf09f103464864c8c1fcbae97d9e4db03750213eb0a78475b45caef4a477f1c73dc8f9e39dd7d4dd50396007fc0470736574056302000385eaed68d747a689f194dd86d5da452bf2f327d795d5d504e1a59b038ec702d9ad78f74c269b6c97c8b2b6496bafcf9790dc9c608304da86ca5edaafbd62dc960bfe5c8bf1b4833e5b5177e26bb83bbd28415ff617db4e3c3c33b03f10427bbb07fc04707365740721027fa518c54bb326d5ce3da5c2eb8a6521ab99df86b511477d0f5ebcd616f063ac0007fc04707365740121090b81ada05aaa354e5c62732358c8a2395dd9576631d9377844935cac78d3b4e807fc047073657403210bc57b6abf30fcb84f8660771267bb93a6e72de69165ecc9e462d6fff5153d6296010422002058037c2d81d3122185c8704d4276e2629122c95b8ea68575c451628d37eea84507fc047073657404fd4e10603300000000000000017823c100e4cb4ea3cd1380fc7986f67a937b71320ac40fcbbcd3fbd3f37dfbb8c4ac0eecc7c8b91d14c7148d2e162d1c4dea595dd8dfb80c0e064b926ef679d2eae0973773f44dcf8cbe7a6e53035366c0c9131cf991bf8eedd5a759ed33baa868e6e3849c93c40bbfdd6d485ce31941d09f9ca07c7d3a3b724760e637191c5344fc7812976c541de2005ef96fc57d8645bfe6e9cf5824a0e084df078006f11dc485c39ee1d196d793a544d458358e4d949c5449a63875196328fda3b29ee227add62fc36f3898512ff596272ea40d79f376a890c806fcbb33d8e7d1552e9aa3dd14420342039157cb991401faf3dcbadace85d5d093ef744462079028c9e68c9aa48b921be8f809b950517af97da5d0e994d1c68a1a9969972a541e3111b0710e552ab40927c165192e263fd00af1b1f0d7eacaef63c52852336c0293b0d0a381b0cd90864240dbb2f6cb61c7149f432a11f62080f7d47d9a04b854b4490eb7a53b4fe33e146db108d235f6b164d22a4a9cab38f5501f4e2bff1963a327f757b8df26d2f65d2d1b933fe6cf8d12c4c7cd8c2f5dd7a69c989516e729b52b6688a4c29333f21a84247e52b152c455d45f582fca280bf818f7c0d8967a43b5d38465922e4de8d2eff49971d28980793eb41a5885cdb4f32e528edf4de6939239ff1c678160b51a1fc5d6e83f3c6cbab2aa88d3e1ab8911779026ede67a6a7b85a57b8a09665150e0cbc3dc615e1d5e39279c2eb24c80423b0568b481b5a37fac1d88b8f686b149c9404b399148aac35515150fbccb29018ddef5c9d219231672ba884020e50ef3e11e29a50a3677fbb427174e2730b1a5293ba9d2f448ae6070294a59de9f0a174273d580af7c87c07acb27962588de2d69c9adf01ab86065f180daef68c9e3399aeb1c290622412484bc88d182ebd19833e6476e24a70a0d1964e61a9258346fa8237b9940612ddb90d91779c5ca2e294679d0ca15367b5db571b81fa0c7e9871147ce9d2729dc3168296d13ee2dbde145ad9bcfb0e24e2542c8a2e06424c5ccf3beb23be0b57acee847f579c1d548306e6fb2fd7bc42c529415002b292d9ce82883d627625a76299f3d055a031be110bcadb95eadffbc6a5a14c97d1a6169dd3ca058e0ee997cefd94f2595e39c06ebebd2862edf7242adabc9716c28555f5ac93ee2609d75c4a852d788eff783c3bcac47b8f7330d2359f004879df8a475ba381c32379d3787761fbbba34a8e9a59fe736bc489562e2ddf71bc9cddf3ee0015857939b6d1af58d3a7fdabd925c8b2e724f0b6a80e7c5c1e7d04bfcb8cc44ecc172f3c18cd73d226f62f4a1fbab7cc6367088f61ec3e562989e01ebba29f8b7f6a94c0c7b32fdcabfc2dbe4ecf404f5fc7d5f05d8694f95c735849ad1e32a44810da350c4cf08c61d8693f468578d09fdb924278add9d261daba0ed187210f239bb4a97763313f2e006ddc202d4550412f68c5be848e1d34a55cce1b894ebc9dce7e9cc16859d940bfad3dd848afb99e2868a92b1d9da7a022ea7405abd42a79995f7351627ced6250f5fcd4f0d179e0101ada67ee8f96e4bd0d7afc1da123616d7a588e07ba84fe948c8ce1e7b51f88d8be970a706c9175d9e46c23388cfff0609533283ab8d2282487f0181d45274ace8a92a8a0eff3d52aba9732a64d787d0effeaa58d03c9df620a43afd2de9607783069ba61e2c583b576150baf140ee48468afe18ffd9da3eecca84b0aa3b7a7af17ef69d77d6f0d99f0e83d9a30652b3487aba49537381ae0afc2885c70ed1fae6dc5cca933d92b8c089bae4855477584e32331623c0369f500d4b36d62d15a81a4d7c197584aa30db415d9197d9cb7ef641cac840a023fdee46c66e3176bae974cdd58ab5ae2c7346390dc696a2208ca7a18c8cf671962791f4e827420e6ceb6cbb58b07054a2355dcd30c2edb64f536860515d515521031f63f9c2a8442694746e9b4ebbf5b85afd96d4e6c25a50013e363681f229645455892f1a1cb8b2a8073a925ecc3832c339d97e9249a8bdd695616cb2818a26bebef23bc94a58a411be30683bcd16a4b6472ba04fc401ecb59f0486dc5b01ac1e0ae57a132c768e4c7fe27dc9b4c422fa647953ba9bec22cf8ad5669c913e0731b03468ebd6009c14283fa1f195fc6636eb30e12cde2c263ae984980a3cd8aacf424e0ebb68c4e9521e2b61c2b39d7ede48d7e98837c7d840455a5525b98f7bf79fd6258059e4e6925db4577eb62b5263d91b7f17a24d3b0ac1163e42d9c367a363034b5c03062c4706885770a5fe3af5ed1ec6e2fa2d3ef23a33acd2fbc30bf436999be36ec7cc9cde96a96bc34d0e0edee7b0ad98a35d8bb1699312d3c1b4966003a054a9bebd8815ca947205fcbfc3dd2c6240a6b911ded609d2c2cbef2fb151d80305615d60ce8fbf4089946780d10523ac165ea7bc38c3a2e6bf800b38d47ca603dcb20bd4dfb40d0c02cf2f3d2727e8995203296b06f2c353f327b2ec1d9503b1060b57144ca9b648c1c87ae982e38ebdd961e3beef4e198eefb1b944f79cc136d38ba449e9800cd2897a2f0e15856883a839fa7f89220c02703f704d1761d8391a183a98e6fc0d9bea48440eed02c84e5e4b70c202c2dfea04047085763766e28e3d4b174ccb7727b05d74c55f7a91de3599834697ba0ce4692a14f966c53fb735109e20599741df2a6ed21d67076dc078b8e565f3afd95e7762bdc3d9818cd69109f59c45aff6088ce3a5ecadf3ba2e10960b115d39d02b559b16488fc7b8a23cbe534311baf5731576c5ed93bfb838edfe4c7c2eeddc2405e8cc4c741f1e6e562592be7f95ecbc26251edbec6b35581738b44673e8295494f804e6ecae2b23527946956f68546fe01b38ff1fd0e8f3090916a0e421d804da219bdac63410d62749b429f82c9c2463c52aa29aa3dc0359051cb5666c6be81a5e7bb85f62be8ec4dd10f2948f82ec66ef4e0471fef64efa4cce7232923b19c72862c674250316448e201abb5fddf248a747689daf8f04343f1e695d3fd045f5e32e98462c0d65d0ff4d751c03826ce02c7513c3c56776325d4566afcf780876ce17fea8450e48d8a36f22879d83014dc6fb7e7ec0ea5fe309723862bb5e2cc1a4899e18583c8ceae1246ba8f12b357dbd91e51718486777b192ac97de65a35a40655b25426a30373278e897a2b99658ad27277ed32e7eac3b7c5d5c775110b5327dac2f3d92125ab3b3bcbc383afd93e795764bf2632c7b4c98876c95e41b7c3fe2952db073cd4ad219ab3aa5d0901cd53b8acd8e2fd92f93d7e5ff0eb5ad97a2240764fc40e8683a1cc28484fb3b1027059a53ffa5552406e9bd7c3d28dc0b081a37cd5a13af22288d39975018984c084cadfaf5ae4c91d8b00a6466ab7cd50f1f143f11ce8ecaf39809a3c4833b5e11945564f1f0d025a07427100e60bc40e065bfe938246b3345fa8fa4a8ee9bb50a5152c90f43d239401ef79894b5f2db6e8f2e98663d6497dabd94f13d9cec86bd2707cf32df56f5a6693ffe9be7ec362c0bc03b6816269dd2b72f5638209dbc1afc97eed232f2916f19d4ccabc55a6cc0a48ebdcbd59ce0404ebb47740a0d802f057116714ddab4aa3bcb5d8ca20069af51e09f941b9efd73e8515aed1db7ba79137146e5c14262dff94a885cfdf435d60d91bf2f508c110106fe4a0eb4c32ca382825ca6a65aa2749a224a62d8a1dbdffc5b53bb4cf2315e9d107a73721cb3ddd111c723cacecbc219ae5c850beae3b3b6a5577222af1706a625965b7c7c7f13f01cbfa9c6f1cf406fd177433b9ad4213fdb30abe01cbe931cde34de1650e69d348d25b6128a26ff8b0a73947399b4162bb6513043167a3871960f0dcd5dce5b6ad680ec782ca48515010244d5692ce8e6a56c291c3512e7ef91680769be39530839adb5a8898d83834d398e63ebb2ad00d42d414233a070dd6bbdd6093c96eb8478953fb04c3e82a7c84a798d7bde36547bdf4486e8bb3a6fddcd9d7ae1b007e61e4da3b85ea327c1ab8f40a66b36190eb3bee753bf1043335ce82cb31751b7e89b84fa9ccec5427b28c161512a963f80bdc72c38fae1b32b4d7900f983b51f42144a82514b535d71f3dc80c0b28f49c20b346d344ed9c81b556ddc49263ddc687e64daa55d659d0a806709a62065e1eb1c694a6e46f6c8b10bd47e76664c42b9d992c23999ce516a5cb6d68a4748957c63b2db6939b86adad8fcdcfb5bb643b08e156d61e5bc4c5810802d5afc1c0e3b160b01d6e5675e5172253d1d943b96a6a6c940925a4f6850612b8c57ddca11e893fcb5e5e791a6749f75969b49c684aca0399bb322b9a72997e204b649c3d26f726ea0a49920ebf4b533bd4b38e1cba3a2422e37c3e259dddd8ec10afce3f1baf2bee470eb752c5721aa49a3b8b4bee25a9f6aa626ade570864246ca2a5c6f0d183ab2d909ebc336db2126a4fd24de704befbd2f07c7cd6c0169a07777e5a583fd3a9a9ff1241fea91c504fd5e4d6c6e636a9a5c3fa56824e74c68c1ebb8c4afa90ff2364acfd4547fff73f94f133d63bef1ddae0a8a338ee8e50777d1b7907f4871bc4efaf746ec2c7b9fadd717bec888026e32e5e26bb0101a269816b9046c29a42b35ee15e203fa26d321fe03f042a8f21cbd62e1bb0bb371d00e46492bd655d0261129393c023d20ce9ddf0f0687820e563d3688cf1e7946a0cdf09737c3715dfa8a6777bf94ddd2d127bb5ad942dd07738eac8b6955019799ce77cc42136dc9aa822470ac56efcd359bf180e95f3fb312cd0ba9ee9bab99560d0b41ea7831bebcf20f27e17303208ef66d5c0f82d26d8093f002418267115e10331646fd87ba1f1a42f72fb45d2a4a4e4353698863e65a7cd4f6f3cd0dea28dbaf5794de216afe202b679899518a3dee9d4024afa3dc9d8d4eaf0179b05ceb22d1e60bd941d44c3866362a92a7951d9de36e4e7d1a681fb2d9420e0fbffe795e9683857846ae0e834d818f990e575a7fa7efe7638fad98fc5b680abbb58cb8da78d783a7ca16fb7521b4be25d4fded9417cc7fd9525c79df7e52bb83894dd905794282a7413bca79bb653afce07cc433e49ffc38d16b7be05c1c9ad05988ed672e1b4dcac2a5d211d7ad1b790e4ec0761533925f528a21305b942e0dd10efdb99bf1fd6d6b906ea0d21ea7bcbb4116490d97246458fe29644f149122586b6f16df620ab1480b55f27f3e8bf32c2c094bece34cce03c20b5a2d2b73481c7cefe4bf56dc76c7970dd77673e4383f62998b6923f103eb0e5c1ce91e43da83495961460b677c261a027db4ca979597a8232691c3ece94456e313ca57f8c2021334cd4e0735453597d516dcf6e04d386ac61bcee073f7520d205fb1ec6c35c6c96511e8a067ce5ba3d701beacde937c925b204ea011521b3e1219650568ff9dda90e043c9d20224fd767670586812a41ad83208f5d62f7892b22500be3ab2028207f738c21301e1aeab23d1bd4e46d46f2ec1991683e987d3d834bc260113372e3eadbf825f86d42f463795050f5821a6afadfe42cc1cad6fe942d16af7e35dd08004ef676558ecc8801c45d37a8c147102e120ecb7c965a2e33ddab0a43133692de2133cc64e655961e66caff271e0625c469a24baf126ea7d300bac5f0335dd5926e99394d45280cd6e14e7c3d5be3b3745b617d9f7e01f0bbe15a0512e2501bb7361a17c62f4549df0e765cf8a2556a9d1827ccf22c75680db0d7391da9f0c18926bb90423c7e084f4fa11cf05914bddbb8359684dd920db82bff035702f2484621ea1d71d2589a3d5db2a876d78b2228a1b4b7b9ccc8c4ed6f5df7010771ed118f96bda339ed2025808099333224f99f207e3e808312f49cdad7e0007fc0470736574056302000381eb5d013a1bbdfc28e27c272822893a4b674355a29a306afa132cf3fe9dc2955ab2375883d5f7e42ada61971ea91f8af2f106402c5592e676a32e3313d03af9eba6e1185d722a0b726da16714e13cd416c8e99f1b7f0aa44b721c483fdf593b07fc047073657407210302e71fc2fff37aeb6d2e2a7b7f2308d4ab7d4bf0a4cf9be7c06e89a66442b48300");
        pset_rtt("70736574ff01020402000000010401020105010401fb04020000000001017a0ad92644e9bf6cb8d0856a8ca713c8a212d3a62142e85454b7865217890e52ec3108a469a9811ec1c1df7a98dbc3a7f71860293e98c6fad8a7ef6828344e9172547302217d344513f0a5ed1a60ebeba01460c505ad63d95b3542fb303aca8f9382777d160014bd5c31aaea2ddc585f317ee589bc6800bc95e7e6010e208965573f41392a88d8bb106cf13a7bdc69f1ab914cd5e8de11235467b514e5a9010f04010000000001017a0af0b70a2237872fb9e84fbc002358469c51f85bcb6215930df63dd29953bbf5cf090e6df3e3b4e589ce447d3deb7cd4fa7a3c264a3d18b5e245a60add9f01137a4b0365026bb845d512434305eb2309656cd0701de8adfdcc84dd8b05d9e240ee55e6160014adf9a42f6d4643f7ae69d94114cfebc3824209ae010e208965573f41392a88d8bb106cf13a7bdc69f1ab914cd5e8de11235467b514e5a9010f04000000000007fc0470736574012108378fd3af2f7af7009fcf06b5ecae126d5446b134c6763d0a2c103b61ec348c5007fc047073657403210a1862832b5a1ff4c222398ab482534c75decc4176450df7c78280b4dd90062da70104220020c731ad44c00a2928d508ad82b05868cb42733a5b0d0b208f483307ce8c328d9307fc047073657404fd4e1060330000000000000001e772fd0127f16a4db9c194d7a039b46117fb73586a2826f59597af6eceb7a1762ffd8a88d62d846f2f64698505c921ac735fd08d784e833d930c8127fd8e2439e1d4541db5170e5aba306fbaac4c28ee6a30ad6e12886418dac926f46113c8ed01d146a9ca2b98171b63bfa0629ea26d256e8c9f7d6d936945e568dbc707be87439b65cdbd9bafbd3da43475bef08dda59fe1a7f661626e23da0ed70e5b2901f5a34790ceadb3dfed265e003143993b2674fa12f2188d88a1ec03c6767028d774b495a132f89b9404ff9b9772b92f22a75f5af5c5f4ae3ed213881d247141fe061f96fd7d619a657238c960b52cfd836e1255469eb787f1472d19091473fd26dc86f6f7ed613ac985b2c1716ea53b2cefdd0facd69b8428336d516de195422cea82842270a8b20f9ebb44b9492243430943540c5a82c17e6ec53e3ccb386925d2675d03d9a157757c60aa611dbb43873e89d8501d3a09aa7a38f606ab7e58a4d9aa456a125c502b9f5c0963b71348d71fd0db9aa7f9d4e6acf245a77c7701d4a5f58b876b154ba44cc2988024d81aa882b7babb80f0dde1b3468e9e575265c35d979910b8aa2cbd639db98268d9c58efcd12f9cb0ce2d13019866741b2efd0410d0129a6d06f0e95065ba7c41bddb6f1ede6e61a3016f9a5b53a7ceaa7f5d3b653c8603a50581e99c98e4d6bebbc914ed675efd060a8d9e8d796d1d5de0714014dcfd489a4810296092ead5009643fc93579e089fe2cf5e09889001714b12b550a4d7a85fb3538c58526f00075b2de37f4fae993c2493725911cef68cfeae49705844e16614944a9cb5e45784da4d1d4ac73b62340c175813aea49d1052f81cd7e2dcbb00f38473075d238bfe5dfd4f44863ddb2680e3859bdeb94044a4c469e55823d9502df43adbb60868d8240ec0bfc8f617a81e8d967710cb5971ad55b1069efe4b066c2e6efe4aaeccf786e5fe01f43a66ee8a2d0e6f360bf3fd8f98253d487c3f413a60945b6294b38eb9e67aa7fff203bce2f8e88e3530615ea44d8b058c92e4724821159e83baef0c17bb7bce9503bdc217758e2013b76028fde49121a4e9fa9219a9bd340a6feae9d0b4ced850f82d73f029e8fadb622e6b21e6829288054dd1e7bf5239f5750d97fbafba6753ca1fad8c2091a6a822f156e9d1667490fa0e6bd2668003f23382c651334882400adc52dae8bc4162cfabffb71dd89f3ffce25086455eca92ddfa2186fc8ab9cafb260e9a553125ec7636b0132f2cf4adc66f2d9f23d5bd4d2e36b1338bc103b59733f745e5d8f90d99bb04ac330224b9d609f695cc0aa93cd7c358c79d579f4f556bfc0bb42134ecf82876dfcbe22f487fe19cfa59457a3d3eb9846a99345ecdba7ab4e962456ccc1dad26baf9717e9982578296befd71d046eff05ddaed84cffb8d7b40cc264e59e43ceeafcb26c5bfaa5f0771d6e50b2874cfbc4a42bbd1866d19bf069ef65aed77952414de74096796388b2b2646a570dd6cdfffba2ea2531b8048d1d7a6cdeb53acb96be25d3206a8829b4ac683dafaa3aafb91778ef900eb3635afdb7a9ccda84a711c21018317cfca7101f35d34bdfe7d20198a3b7909c1dcd40d6e83043c246841b989166e85b77dfc849420da0a509256ea5dbc8ed088a73309df5a1340accc50f56fad29e37f3703a5116e6167b337d5a6787f2bb976055e124ada49fe0782836943b7013c026828c8566c75cdc55becbcd2011f10c110b0c388b0fe683b1eec3e8ebc2b3dddff465a8c13aa5b40222ffc0beb32edc9c6c80f08d93cf3209d4bb1b34279319526f186e0250536a3e8a5361fb034122d70e3d0a9bd4d3c62452aaf55d0c86648eb8a9324138f3b83e7b6e77b9ee70239e1b1c81c953f53a5524e0033b51a840caf171584137d46111fdf4e5041f560d2bb715c3f8a0892f4d65d65a7dc8e5130d444bdfd5af8c657eb7c6705950c9be7013bec799aaaae7b081b9f88f8d50cd92ec4d57ea980b5722c71cad6c75aef5fb2ce6c38c9ef53b580c49406e0dc4a85438651e79760670061b94a33cbeee90ad92954544e9c63086571980adc9072e54ffda0377e9771bc212734ba71ccfe5d433eda4909dd806c669283ae08ff35f4a6f768aa4aaf4e7fdd4d5614585d1269a3486971376db161df03118d02b0da31ed2e6fca2904a4b4be9f6578a7ef4545a2534923e4b3864a27612501fbc35e76bbeebe8488b222c99cc508db29d48aa335b4d2a0974f948c3207c92eec89716239dc6ec857776ac61ebe485c29e64ed8d1bf0acb547515c79a3dacb2316dcb5979d23df154e1fafa827f9011e43c5323478f9f48a89913bedbe4dc9b0c8535f8e82fe64179cd74d7fb37d7ad587b65af57b3784810c7b6ee412b6eaf5d1500082fc208a921bf94ae5329016645967c568874abb19a3ee9f752e7b17f35d49b73a66b62e5c41fe0f0683824123e3f0b6b5d3a9b47d2b5eae10913b08cb4370c754d769d6cfb4e4f30fabb38dcf243009bb8f36b6e2e086d70d3286b5633c23559190a5b0107c85474e9e3e87c7110271705e6944dfb232d6a9624d114baa3fa91108d3ba429381aacc0ca9ff188dde3c8836565b4d858fd0cf99c1f14dbf563128d0525c67b1e8014f1a88511d16cbd41046f2c13fc972797b65f3a8ab4407f317b64f4a458b7bd778349d602becad67df6d15793878f4403e1af6f4f54509a85e32e72eab2cedac74da77031908b3f358ff750140ed750267cdcc7e32e8ed32e461bf0aa7d8173e20f4352719a9297f1811e05f691421141eb7fb9d1997b596c629f89b96c08abd77f12f0ad8e76122a17c707e159f590ffec5947392d76ccb5ffb6d4311baa6a00957d185df86166a58ecd9956606ee147229ab58c3664d4c4a260a04558de5442afca4f1301bfea71b327238061f69f78f6154f684f590475bdcc6748775c3275023092f1347eac859b0073bc94e9722aeb4435d816778aba600b33ccc86d7ff502ffd3b5e5228294337c32c0b8aaf95a82cd920e095d0fbf93707be62fe12a27ab2f6c9fb07207787af7c50a4f61e1d860a510726125b0fccc8420ac41897d90f6a8790e984cb9f89e3ab1885e2ccbb3b17253f35336f423e7e04f31305330f27fac32b056117db89ddaa2a0657054e9ad0853ae6f62aedf30196f9b94152c7f7bbf88a83f2f58fe5cdb0d75f56e6050fca4047ad11042e0fd4b2951da3892b66a7674be99d1e82debd98493d80d857d943def54e7acfe405d2672f582bb64924c25495f2dc338735ae0d2b159fc52b26364375630c72cca71bda7b01dfabf4822037ee44f95e934321d853a87bcef2963382b6de64082ab9b3a0c91433c1a87a45c6290a804a34fce3b86e761c58896d0c9f3708661cc61aac282619cd96c60713dffbec7b357fdf51279d50365e008eed72c32f34003b2fc76089238d434d5d912135a553f543b6befec4f7a9496c90ba236eafc7953f4a081de67e2dc549ff15c7734bf12b184670d0424bf20f53662983749aa91a65651d899fb4858abc55282552d22be27f697a7d89cf548591d7d5e7a16a2211c8ff09792e81a9c9042e58a5e76ee678580d3680840465a10692d45ce84faf5cd7fcc9aca49aceee374814110abdda662f4955d99bb27ad310d47e6fb735ce5008fa374d72924f707dff39233bd4109839c3bc61054f7e6715d27e55bcc3464c5c31d109102b95480a0a77e69a2e2cec60c0ce5b0511e8b54445c6eb2086aaa9f47a7130b28fea6fbe2fc26d68fe52d14193d4498f5164f652e8c0259f34956331526acda2611357cc259835351b250137ae3ed44a0d2d25796a8c0cd5d84a0753444509fc0682ea0aa232f6937054864493acf2317c626d36bf13251a92fdae72e7a184e32745343d2b968f2497e79d859059ce132bd898a84c989e5687537caddd4d2f8206e5e10f2f44ee6864baf71ed219c294a7373c5730323b19893b9fdbcb6137d0a5045c3be8bf837c6f5747ab0d91d8db1f17fdee9860e3123fec121148266e8579570bde602ef156ae16ad75fbb31db0e451e06299924ccf2963f600756a47ffe688ad700ce4e1bff02f37f9029a799fc53133b1df2841622981cbe9a1e2753e0db6ecc35fc2beebce4a28c47f6f1ad4bd972befc6fd606f83dc4d319b4935c65709e1e16e97c893ae007634b0883bc2b8a4e2174bcf6bd485c47b9c96c0b11939c4f5edd3db999124d46a4ce4c2564a535406430aa679b2f850272dda5b282b3f9a2431470765e00eec90b310800ee317c2a6aae192552b9e85adafddc556458b6bd5b5e76e770998a2a29b1fdbb37b2f57aba1360f912273134e540ee68c097b8f11275c30171ffa1875a8aaa45106758429061c20330a80f1928c2a9d16e33ded189ac103fb021ffdde726e9eeea1e03a3fdd9f34d9e52b4c5be2d3855e9b60150f7acc909a5d011a3f98cade7eb101abe935372bc81f4b5f18c806de51ebec0a8e032c0e4bdbdbf56429aa1996ede1bd98c7263896f81471f41cbff7311b17b42905d802a6460668a773ee1ef426785f866318f129e2cea728a7f127cd0433879f48812f5ab56fafd270b2cd5186f199d3b875ff5c3c20983e4acd2e8fdeddbb3ca68021bcbb9f9f31b3aa4a07d365b1c72e6b7096241e07e441a5e5314afff8b6285f04eedd74eeb20a41b329dc448ccb8161244711b34982dfd42f66da04e132757c16e54bbfa0d479ff8983eedddefca29a53c588db5e6d0f1e5f4a3f51f766dc3076ef722885844d8655301de79a24b484e1759708f1ebf2716b9688314217b5874bd64d2204efa872283ba9c47d85a0ceb5e5e1fa1cd2eff888a74c10a6a3075fcfae2353154cedb9418f9937a06b02c198e608017895a02c65039195e4c91b2dafefc1e238c069d887d450ef3cb2f786f59bb2e9e4caf743382d7aa665b8b32f484dd44fc9000f86ca3ef57c6a39ba31790f3e12c402d1e3a09a892923e3cef063ea8c29559fb2f3dbd6a4e019f037ed89475dbd825962f360e396646f8ffa00c479f9e8460127b728c543117dce38ae17cfb36b109110cf44f2a712b6cc6b2220db93ca7ef58b5fa163559d10d80aea598afc1221290237172692b418ce4267824dbd237ed2143de7a9d73125f8c682a2a2fd42d537bf8fea48336aa508247814875ad24c541386133d8fcbf28ebd0451a67e7d69ef9018609dc09a4f36dc93953006a82c39d601022bc425dedc2edd6bebabe78fd8ba17ae2b3c4fd657e6b9fbc887e5ad442326cc872075cd960b615fb36b18d140735830da257a4d42f2732d501b21cc883d8beb61ea72961864affff658129f91a59bfaf9dd38ae0cc92c7d8f68d531cdd5e06fd115ed9b4e3b24350882c3914c5f8d2df77e8bf615c6d7427665e395cb5487e13c8df9d3935a8431d95d02a26373dbe4f66a71b31100516596175b17fc6d0fa0c5f0d20bb121ec8fd43567721ffe0e1fdc38d20cf3adcf5004784edbcfadbf60d0d1703012ffcdf918b091a4d2807d896aa463a8f037dddbc01024fa34fbb93a06fd3ea23bacab8fb53937425fa14d6b819d50f91a4cc75689e05e988b8dda6ca89a78acd8eb68457c6dfed5f08aff4523f4695e79c315390f829f1241eb78d6f618c6508e15d3cb6ef70f0c4fcb69ca0e90e1186caa9de5b0553729af8c795db4578e061748fc25851e607dcaffd274e3a6e2d561ca4a55684065e1cacbdb5cd75fadd71ce5bc107365e6fb9dbf778248261613d49c36d1dd1b3403580ff4e6494291690c4508a8defac836876a25a4e9054ecad77937cf9df6f22282ed5f0a7778b4affcaf09f103464864c8c1fcbae97d9e4db03750213eb0a78475b45caef4a477f1c73dc8f9e39dd7d4dd50396007fc0470736574056302000385eaed68d747a689f194dd86d5da452bf2f327d795d5d504e1a59b038ec702d9ad78f74c269b6c97c8b2b6496bafcf9790dc9c608304da86ca5edaafbd62dc960bfe5c8bf1b4833e5b5177e26bb83bbd28415ff617db4e3c3c33b03f10427bbb07fc04707365740721027fa518c54bb326d5ce3da5c2eb8a6521ab99df86b511477d0f5ebcd616f063ac0007fc04707365740121090b81ada05aaa354e5c62732358c8a2395dd9576631d9377844935cac78d3b4e807fc047073657403210bc57b6abf30fcb84f8660771267bb93a6e72de69165ecc9e462d6fff5153d6296010422002058037c2d81d3122185c8704d4276e2629122c95b8ea68575c451628d37eea84507fc047073657404fd4e10603300000000000000017823c100e4cb4ea3cd1380fc7986f67a937b71320ac40fcbbcd3fbd3f37dfbb8c4ac0eecc7c8b91d14c7148d2e162d1c4dea595dd8dfb80c0e064b926ef679d2eae0973773f44dcf8cbe7a6e53035366c0c9131cf991bf8eedd5a759ed33baa868e6e3849c93c40bbfdd6d485ce31941d09f9ca07c7d3a3b724760e637191c5344fc7812976c541de2005ef96fc57d8645bfe6e9cf5824a0e084df078006f11dc485c39ee1d196d793a544d458358e4d949c5449a63875196328fda3b29ee227add62fc36f3898512ff596272ea40d79f376a890c806fcbb33d8e7d1552e9aa3dd14420342039157cb991401faf3dcbadace85d5d093ef744462079028c9e68c9aa48b921be8f809b950517af97da5d0e994d1c68a1a9969972a541e3111b0710e552ab40927c165192e263fd00af1b1f0d7eacaef63c52852336c0293b0d0a381b0cd90864240dbb2f6cb61c7149f432a11f62080f7d47d9a04b854b4490eb7a53b4fe33e146db108d235f6b164d22a4a9cab38f5501f4e2bff1963a327f757b8df26d2f65d2d1b933fe6cf8d12c4c7cd8c2f5dd7a69c989516e729b52b6688a4c29333f21a84247e52b152c455d45f582fca280bf818f7c0d8967a43b5d38465922e4de8d2eff49971d28980793eb41a5885cdb4f32e528edf4de6939239ff1c678160b51a1fc5d6e83f3c6cbab2aa88d3e1ab8911779026ede67a6a7b85a57b8a09665150e0cbc3dc615e1d5e39279c2eb24c80423b0568b481b5a37fac1d88b8f686b149c9404b399148aac35515150fbccb29018ddef5c9d219231672ba884020e50ef3e11e29a50a3677fbb427174e2730b1a5293ba9d2f448ae6070294a59de9f0a174273d580af7c87c07acb27962588de2d69c9adf01ab86065f180daef68c9e3399aeb1c290622412484bc88d182ebd19833e6476e24a70a0d1964e61a9258346fa8237b9940612ddb90d91779c5ca2e294679d0ca15367b5db571b81fa0c7e9871147ce9d2729dc3168296d13ee2dbde145ad9bcfb0e24e2542c8a2e06424c5ccf3beb23be0b57acee847f579c1d548306e6fb2fd7bc42c529415002b292d9ce82883d627625a76299f3d055a031be110bcadb95eadffbc6a5a14c97d1a6169dd3ca058e0ee997cefd94f2595e39c06ebebd2862edf7242adabc9716c28555f5ac93ee2609d75c4a852d788eff783c3bcac47b8f7330d2359f004879df8a475ba381c32379d3787761fbbba34a8e9a59fe736bc489562e2ddf71bc9cddf3ee0015857939b6d1af58d3a7fdabd925c8b2e724f0b6a80e7c5c1e7d04bfcb8cc44ecc172f3c18cd73d226f62f4a1fbab7cc6367088f61ec3e562989e01ebba29f8b7f6a94c0c7b32fdcabfc2dbe4ecf404f5fc7d5f05d8694f95c735849ad1e32a44810da350c4cf08c61d8693f468578d09fdb924278add9d261daba0ed187210f239bb4a97763313f2e006ddc202d4550412f68c5be848e1d34a55cce1b894ebc9dce7e9cc16859d940bfad3dd848afb99e2868a92b1d9da7a022ea7405abd42a79995f7351627ced6250f5fcd4f0d179e0101ada67ee8f96e4bd0d7afc1da123616d7a588e07ba84fe948c8ce1e7b51f88d8be970a706c9175d9e46c23388cfff0609533283ab8d2282487f0181d45274ace8a92a8a0eff3d52aba9732a64d787d0effeaa58d03c9df620a43afd2de9607783069ba61e2c583b576150baf140ee48468afe18ffd9da3eecca84b0aa3b7a7af17ef69d77d6f0d99f0e83d9a30652b3487aba49537381ae0afc2885c70ed1fae6dc5cca933d92b8c089bae4855477584e32331623c0369f500d4b36d62d15a81a4d7c197584aa30db415d9197d9cb7ef641cac840a023fdee46c66e3176bae974cdd58ab5ae2c7346390dc696a2208ca7a18c8cf671962791f4e827420e6ceb6cbb58b07054a2355dcd30c2edb64f536860515d515521031f63f9c2a8442694746e9b4ebbf5b85afd96d4e6c25a50013e363681f229645455892f1a1cb8b2a8073a925ecc3832c339d97e9249a8bdd695616cb2818a26bebef23bc94a58a411be30683bcd16a4b6472ba04fc401ecb59f0486dc5b01ac1e0ae57a132c768e4c7fe27dc9b4c422fa647953ba9bec22cf8ad5669c913e0731b03468ebd6009c14283fa1f195fc6636eb30e12cde2c263ae984980a3cd8aacf424e0ebb68c4e9521e2b61c2b39d7ede48d7e98837c7d840455a5525b98f7bf79fd6258059e4e6925db4577eb62b5263d91b7f17a24d3b0ac1163e42d9c367a363034b5c03062c4706885770a5fe3af5ed1ec6e2fa2d3ef23a33acd2fbc30bf436999be36ec7cc9cde96a96bc34d0e0edee7b0ad98a35d8bb1699312d3c1b4966003a054a9bebd8815ca947205fcbfc3dd2c6240a6b911ded609d2c2cbef2fb151d80305615d60ce8fbf4089946780d10523ac165ea7bc38c3a2e6bf800b38d47ca603dcb20bd4dfb40d0c02cf2f3d2727e8995203296b06f2c353f327b2ec1d9503b1060b57144ca9b648c1c87ae982e38ebdd961e3beef4e198eefb1b944f79cc136d38ba449e9800cd2897a2f0e15856883a839fa7f89220c02703f704d1761d8391a183a98e6fc0d9bea48440eed02c84e5e4b70c202c2dfea04047085763766e28e3d4b174ccb7727b05d74c55f7a91de3599834697ba0ce4692a14f966c53fb735109e20599741df2a6ed21d67076dc078b8e565f3afd95e7762bdc3d9818cd69109f59c45aff6088ce3a5ecadf3ba2e10960b115d39d02b559b16488fc7b8a23cbe534311baf5731576c5ed93bfb838edfe4c7c2eeddc2405e8cc4c741f1e6e562592be7f95ecbc26251edbec6b35581738b44673e8295494f804e6ecae2b23527946956f68546fe01b38ff1fd0e8f3090916a0e421d804da219bdac63410d62749b429f82c9c2463c52aa29aa3dc0359051cb5666c6be81a5e7bb85f62be8ec4dd10f2948f82ec66ef4e0471fef64efa4cce7232923b19c72862c674250316448e201abb5fddf248a747689daf8f04343f1e695d3fd045f5e32e98462c0d65d0ff4d751c03826ce02c7513c3c56776325d4566afcf780876ce17fea8450e48d8a36f22879d83014dc6fb7e7ec0ea5fe309723862bb5e2cc1a4899e18583c8ceae1246ba8f12b357dbd91e51718486777b192ac97de65a35a40655b25426a30373278e897a2b99658ad27277ed32e7eac3b7c5d5c775110b5327dac2f3d92125ab3b3bcbc383afd93e795764bf2632c7b4c98876c95e41b7c3fe2952db073cd4ad219ab3aa5d0901cd53b8acd8e2fd92f93d7e5ff0eb5ad97a2240764fc40e8683a1cc28484fb3b1027059a53ffa5552406e9bd7c3d28dc0b081a37cd5a13af22288d39975018984c084cadfaf5ae4c91d8b00a6466ab7cd50f1f143f11ce8ecaf39809a3c4833b5e11945564f1f0d025a07427100e60bc40e065bfe938246b3345fa8fa4a8ee9bb50a5152c90f43d239401ef79894b5f2db6e8f2e98663d6497dabd94f13d9cec86bd2707cf32df56f5a6693ffe9be7ec362c0bc03b6816269dd2b72f5638209dbc1afc97eed232f2916f19d4ccabc55a6cc0a48ebdcbd59ce0404ebb47740a0d802f057116714ddab4aa3bcb5d8ca20069af51e09f941b9efd73e8515aed1db7ba79137146e5c14262dff94a885cfdf435d60d91bf2f508c110106fe4a0eb4c32ca382825ca6a65aa2749a224a62d8a1dbdffc5b53bb4cf2315e9d107a73721cb3ddd111c723cacecbc219ae5c850beae3b3b6a5577222af1706a625965b7c7c7f13f01cbfa9c6f1cf406fd177433b9ad4213fdb30abe01cbe931cde34de1650e69d348d25b6128a26ff8b0a73947399b4162bb6513043167a3871960f0dcd5dce5b6ad680ec782ca48515010244d5692ce8e6a56c291c3512e7ef91680769be39530839adb5a8898d83834d398e63ebb2ad00d42d414233a070dd6bbdd6093c96eb8478953fb04c3e82a7c84a798d7bde36547bdf4486e8bb3a6fddcd9d7ae1b007e61e4da3b85ea327c1ab8f40a66b36190eb3bee753bf1043335ce82cb31751b7e89b84fa9ccec5427b28c161512a963f80bdc72c38fae1b32b4d7900f983b51f42144a82514b535d71f3dc80c0b28f49c20b346d344ed9c81b556ddc49263ddc687e64daa55d659d0a806709a62065e1eb1c694a6e46f6c8b10bd47e76664c42b9d992c23999ce516a5cb6d68a4748957c63b2db6939b86adad8fcdcfb5bb643b08e156d61e5bc4c5810802d5afc1c0e3b160b01d6e5675e5172253d1d943b96a6a6c940925a4f6850612b8c57ddca11e893fcb5e5e791a6749f75969b49c684aca0399bb322b9a72997e204b649c3d26f726ea0a49920ebf4b533bd4b38e1cba3a2422e37c3e259dddd8ec10afce3f1baf2bee470eb752c5721aa49a3b8b4bee25a9f6aa626ade570864246ca2a5c6f0d183ab2d909ebc336db2126a4fd24de704befbd2f07c7cd6c0169a07777e5a583fd3a9a9ff1241fea91c504fd5e4d6c6e636a9a5c3fa56824e74c68c1ebb8c4afa90ff2364acfd4547fff73f94f133d63bef1ddae0a8a338ee8e50777d1b7907f4871bc4efaf746ec2c7b9fadd717bec888026e32e5e26bb0101a269816b9046c29a42b35ee15e203fa26d321fe03f042a8f21cbd62e1bb0bb371d00e46492bd655d0261129393c023d20ce9ddf0f0687820e563d3688cf1e7946a0cdf09737c3715dfa8a6777bf94ddd2d127bb5ad942dd07738eac8b6955019799ce77cc42136dc9aa822470ac56efcd359bf180e95f3fb312cd0ba9ee9bab99560d0b41ea7831bebcf20f27e17303208ef66d5c0f82d26d8093f002418267115e10331646fd87ba1f1a42f72fb45d2a4a4e4353698863e65a7cd4f6f3cd0dea28dbaf5794de216afe202b679899518a3dee9d4024afa3dc9d8d4eaf0179b05ceb22d1e60bd941d44c3866362a92a7951d9de36e4e7d1a681fb2d9420e0fbffe795e9683857846ae0e834d818f990e575a7fa7efe7638fad98fc5b680abbb58cb8da78d783a7ca16fb7521b4be25d4fded9417cc7fd9525c79df7e52bb83894dd905794282a7413bca79bb653afce07cc433e49ffc38d16b7be05c1c9ad05988ed672e1b4dcac2a5d211d7ad1b790e4ec0761533925f528a21305b942e0dd10efdb99bf1fd6d6b906ea0d21ea7bcbb4116490d97246458fe29644f149122586b6f16df620ab1480b55f27f3e8bf32c2c094bece34cce03c20b5a2d2b73481c7cefe4bf56dc76c7970dd77673e4383f62998b6923f103eb0e5c1ce91e43da83495961460b677c261a027db4ca979597a8232691c3ece94456e313ca57f8c2021334cd4e0735453597d516dcf6e04d386ac61bcee073f7520d205fb1ec6c35c6c96511e8a067ce5ba3d701beacde937c925b204ea011521b3e1219650568ff9dda90e043c9d20224fd767670586812a41ad83208f5d62f7892b22500be3ab2028207f738c21301e1aeab23d1bd4e46d46f2ec1991683e987d3d834bc260113372e3eadbf825f86d42f463795050f5821a6afadfe42cc1cad6fe942d16af7e35dd08004ef676558ecc8801c45d37a8c147102e120ecb7c965a2e33ddab0a43133692de2133cc64e655961e66caff271e0625c469a24baf126ea7d300bac5f0335dd5926e99394d45280cd6e14e7c3d5be3b3745b617d9f7e01f0bbe15a0512e2501bb7361a17c62f4549df0e765cf8a2556a9d1827ccf22c75680db0d7391da9f0c18926bb90423c7e084f4fa11cf05914bddbb8359684dd920db82bff035702f2484621ea1d71d2589a3d5db2a876d78b2228a1b4b7b9ccc8c4ed6f5df7010771ed118f96bda339ed2025808099333224f99f207e3e808312f49cdad7e0007fc0470736574056302000381eb5d013a1bbdfc28e27c272822893a4b674355a29a306afa132cf3fe9dc2955ab2375883d5f7e42ada61971ea91f8af2f106402c5592e676a32e3313d03af9eba6e1185d722a0b726da16714e13cd416c8e99f1b7f0aa44b721c483fdf593b07fc047073657407210302e71fc2fff37aeb6d2e2a7b7f2308d4ab7d4bf0a4cf9be7c06e89a66442b48300010308f40100000000000007fc04707365740220230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b20104000007fc0470736574012109870d0ad593316a7ff67dee90f2c2d8e305cfcdc4619fe0922c706560eac5d8f507fc047073657403210b9991881df2ec384ff5616f6c03d45cf033ee64536297c3557f9fffec716c1fbe0104220020cd4ed5f0db8c450e8b0be595b6410c1759c19f1f6926279095c83dade9862b6d07fc047073657404fd4e10603300000000000000017d32a9010e698107419c4e5b47c05ec25624ea0d6f432f75b744a15b8f8381b5fec29c0b55b8eb600b91a3e13c0e56e601c23882ffd62fc218b1da72e2ad732a47f7279d32cbb24eda0caaeaca8d8fe4bc920e0baa6821b47f7790416a5bdf13d691c51914358a431dbb2e9154bc01da79483cc9617f4d57a6f4d2d1380ea2450c292ada85eb663a23c76a6adc0c7abf8ff71b41a56478b66003ba839295df69edeaccc54a9b3803c9d3eda9cd47e478fd852a316802c8def8014a449cb886d0fcb5d56086e8742a346b983657f331330f6e8ec4bf72b314cc6d69bd94be0bb6e6896ec01f773c1a4c329e7ddbf326b83780ab22da08a144fc1c8dfda604cc1b2858682ad3decb097c1ae3e992596ae997422c7d381d8d9354be1658c43e5d5c1e49f0e7263aee9093c018b09ef44ca7adf853c625187a8ed252527b94a5bd70e13c30b22f05038404d99c18c0cd76a461ad7dc4ba63d132101ee471bfac835eabe0f11487ab7361e337f5ca8dca3cfb25de4958c58d59df6ea016a9436856a3af505884a4e38d9cc1ac955c40228c22ffe385dd48b3f1c27d40e7794ce62822645b2a2e42346f9771f2744fdf5064309f9f7f84747131369ee9b5421a07d24ec6e7baeaf1c99cf8339f38e44b0864ef46684815c320df48159f83aa80e247d617acf1b1c7a2da56cb3725811ef028987573f59c90587f88553fc6a11723fa5e45424de05d2b0f548dff87a8e1b094a929f695f01b7a127b522ba2a6d6290991d0985af8059f002f514f5027fe98d292fc85f050d5a19189a27344f83f737ccf254c97728054ed01e1d229f65b2b9d66a7c82116bf26ecfc026446cee24c5603e0bf0df9875461623340a7148de14a058f1a37e8c627bac2acfa2aa1de65d1349e7d02d565852af1de756203d2aac22330c43b12f1e1889c8ff2959b1c11e85b2a1f577b47e1242db2b1bb4cb03979ab255353bd91a728a67827a86899ab68b3ecb64e2303c6c701c1ba3aa09740264a42194277fde906dd6caab566c089fc83fb9ad4528d50c48d72d8a68e8bdfa846284979e7201f41d225b2a782ae77cccef12da93d2c2e73f5df35f75102fd7bae8c5c2c92e79236f687b8559b7d625658f6121101ff205dfed8356fd447c9670330b3f197c3249b05dc72f943f1760489dbb1bd53b2bbe65ba8ed7c880ecf97a1cdb9e78551c978201aed0c1e6202d2bf807df2334bac733ae2cec1af8a409cb8b32830fa0696c18ad11d99c3cd0de7136b83d903d955acb584117e4ce39958d75d6e1ed790e4f5613fcae6a827078a45676afb7fa82f0642d37c273e2378e58403ca9542d542d6ae549752bb9a85cb1c5d71819cf8985c5fe52e6de0c75c61a2d4b597014009e2bbfa7a44085bc75af6adf6de4d0f1e5fa8dd68d5e13e7b10710d9ae67838a775b17370a052c019ee984e169235a2a1a20e7a157d0e3c93f477907e48f018780e0300b9c1cdea826a81d9900547b7fb7e133d5dea37482e40d27d3feeea57a07dc795737af5f01286ab37003c7dbd8e335978639704333af1988feea17da0af7606f5cad04660495009788afd99412e036db5c9c9fb0c643873fd0a301d7c37975f6b54906d3cd992c7c435b334f695c1f87ef071a58b890b2dc2771c2bec4ffcb9c121feec068ff0cf4924ca1b3cc10b802558f05d7cc2970c3b0df9cb7ddbc306269dc42d8dd882943182cf092d6007248288822d6ee80bfd24f4077f1f662cd3c0f577f831df25cc20d2c1541c44df2cd07586f4efa26e0c208430889dcd4e548be9adba2def0cd048b57d73ecee8e3005181e73d4d12bf11d225a234cb3019c0cbebd0d9c2f3bea6832eeff2109d8843ee61e682098250641df7bbe21c72c7831c215e0234d71cedd22b2370ef3d574f321c6d45607175ad9568dc06520f33d2b15ef2bfb0fe9e48bc01560dcdd73b6fcba2caeeafaab2646f7b46e9d1c3c992afb18b7c2d9d2f88095c1033bbbb9449ec6467da2e302aea9979b28fcce685878619a8d8757451d5b80d4e57a3a213a599b467703c5f96297ee6ce44fc06b1afbe411f1a665ad0745bd7fd2a5b49ceef6b468817f500479af2a8f6c0e3557eb98df51a4df26fcd5cfcdda48e5441114c24573bcca96356d3c99d01eb8f8a7ab397d6c8a54dd9abde6d16cac1ff2ce86095ffee79a304355df03d72f2d332b50898ae06a775f5f7fcef3784c152f51b8ddf9cfea4f0bd271eb98ebca53529f103228aedbf64f03966c5bc2e774c980cd13db22f3c3f6136b6b03ca6cef7a4f310b57dbbe9431946d784fea7eef3258f10a7bd5dca55102bfa49c04fd117a8c521a5b691249e994b8e935bbfd1b86b5512a56ac222e989f04dd07c34a5219dcd5ab003ab118ad40746ec25bcc056b35afc35b656895bddb4d368623e17a61f3803213c1f122d8e6281d013df14fba919209fc2e4bc538021e5d5ca8a1a751859f908f47b39f1a3112611a3e19264513a7301e68979bf0221f1cb418f9cafb7b81db4ebf08e0c7a1b57da5cfe8e32ad16b0c2fbe9b5f7ffa5c80aa3217b082e4f6c9f51cb79fbe27ba459e09b01b3fdef45edb5d1b063fc99937a822a5a43803b610a3081b67f7279e18481754f3802753c5201a60e4fd89e0947616a33ed4218d8e708ed81fec6e3f39d7a94378d92fd6d8d64769bcbd4cc1d66cdf4ada5b189e03461b583dc88f2972c6e4904afc3b49b38818be26f83c94cff7ed4c826917f3314a931b92d65e562014cd9a1a68ea79fafceddd09b8b0e48eeac86e6190e470ebe8ec5cee12948942f80de6a40dc2c657b6ade6a2ab4b3297ec713bc3cebcf91f8465a14e9d9d5325fed40d2a2af8bd0731d9b626095653e5fd292cd5de3a7831c0ae81292630409ab755fceaedc4e76e78b829219209476b94d0c6224930bd6c7d4a6b06ac9699be79caca17b1a7c9254f1b884a87e44de4ce5b15f312b09210d09436a8bc1ee39b6e5f96ba5b620d614a09259b251910219ae39d65c2650e2d2a27cc0d2dbd5e2aa40b5b4bc4ead5ed531d7f206a4bfbfabb96785b768aac21ab8f11f927d54949ec3c595f31391bea8b4f1a63db49e26d875be2cd4333eb5785ab1cfe7f83c6e4a445702f9178343e039a7651b62acd31d694db89287c1ec5a636933a630b3465d27015e564bd2a4848d0910739702debb3d9c7c133c2a2f5c6d93000ae74bffd2af4ec66180e7219ad8af293ec89fdbb0d43d6b9dc5fd539c338136436ef1ce088af4590f47af91d78338c67b03500d4c69de61b44e09a776399d7cc349c95752405f65b0ec19a14434d715aa11a14c5be94d42114c546af8c02d291b3d54471ae463d249237fe3bd18f7afc569c43e1c1cd284538e48444f39e8c83d9d52f7754c04a6198711f8ebdfbf647002ddb54ca3c8833a3a21e0bd7a8cfa1274f61a36183fcd63670f1f5b425f2d06ce8338410baa860faf2331ef93f781d1fcf10c38b2be7ca21cb27430147466867d233acbe6f7ff46136ef736a1a1b5af97cb871a8351d7774bbcf0f0f47ef10c7a5b26f0a25d403fc7cf2e7bb57a1f16c68260092523c82ea020f0df2660faf2f6d85e695cb672857bc9fd4f7ea0b93f735007d9ad15e661329a22bc465f6c65f442f5be91c665f3d7311290b47fb7c10342a5a367ee18dacfc51a83ad0bba7503b54a27545abe372078505062f4b859947168b46638f3a4ebd116fdaea1d96238c4cdae5882f326287da8e94dfbcf9c82f92ec94ec8706dc6ce194fcf7890e047e106aa387173662ac2ff1302627f80c567fc7e74d36473bb601681bfc1b5221e15863bb9f8d5e30bef41ba5839349a677e35d30e0000596691b2bde87e386998e3e2a463aea434ad9002438375ef1071afe9bc5027cec29b5cca4196b2b34b8f92cfba033a9e2539aeee306c5acb88f22c7799bd7208853a735d317df6c957108c6c10c53e9e1055f6108369aa4918dabfaffa446c40b20c73216e976a9fe03cd157ee29efc03e6a8df077a5222008e37f257816703e1b9e214ebda174ed7b4aa1b5e0494f5285704ff6ee22fc1f386dae624b72a7e24d2a56c97a8d8b816ceddc68119c279a2654f19d3d76cd314e9fb6218b9682455f81c7064e33295060dd0b91b958dc04599a5713795c39b51744b5629512a9028a38de8f674214de7bd4845e53244705e431526fb28b8c51b3bfde0202c50187f6748581d5faccee866d0c317345ff6b65b954ed479750d0a052e3fe3f557c88f4964cd95826a7be6da14b54d4c00dbf9b2392aab6d084262427f24d163ce590b8d36547ed8139bd241b8f18d9d9c32850a29473820f68e9197f97e7d54ec76bfebe6fc3006b3c7aaf370416d758fe4426758fb8720bb764b6cd1aa174a58d42361ca8c2396079a634bea9e492a7e1fa5d443a2299c66ae23a064d6e70c605019527f1b499a614c28d3c8cdfee753abb9b1a5b8d9bfde29a5ea869ab95a1c7c1c076f933938008060800636f357a48862bedfd89a70ab30ba31919bdf6b53edd085b3836657a4bb214cebd2dfae4030d19fb9473e046ce6ec39871150a4f0ea03e3513c5615bb50135678d024e69eb754bbdda896eb0f2d39a1f7671231ab6887902faa3adc79cb77d122e184031f7e3a9cc222b3e9788dd9c417cada21fb6bac493b15fc306d64cb701dac8534cda58bd37121adebe474ddfffa1afd26a999b41280b043992b5b7fd6f4926b5b6994a621fca3d13ead3142d8c255d80c33a86ee4d6ef04289a23f0d39f7b73c30ba59005ff0f1eef21f9ec01e703aafc1171a4d24d8257917b239c5c3b447549cb2c9602188fea59024d6def3b37e26789c2fdd90beaeb30790afcde5cb8179770cd3194d5ddeae7eebad7b273c7c53eb184f17b3934f4d0cfbddd9f8e9b135ad4fffa8b5edb04e2fd34e21f29717f3f2b9c01c0a547b3e522041bc5a0c647d7c8eb543b94856a40ad9c4d2ebe94a3de31b810fa99aa4b19a9a0ee51abd355b3c556f26dec3405b19d5a5da8a6c8e263c8e2e97514053a7c57097cde1649bd6c77fe78ffb96ffc69cd43fea598e611ff55a0a306883b01a44ecdba59e103626f4a08e3444868d27e737ad41f3c2564b593ed169036a7c4b883594bcd141847f22c1933e04fbbfedf71d885c5cfe17769eb36b295950e9a420919d06110774029a42ceba64c6f3ec12404047e78f1c67178e65d1caa49894f8b606244a365744c8c826c682a756f560c1d4f71e1fd566547a8c070fd64eb2ba941e844f86af062e67bfecfeca33f0a69c186a5ad2242e100b0bbab31322cc9dcad523297d53f44c4ad8cbc2826bd2e1f211cf6fe29116f6c0bc5d37f7ac8376a574dba76dede5fc6e72e4853d4cbc0d302e20bc130578419d8730215172a470f98e9bc868c1f7511bcc353e879199d0b25a06cf49184808bdf76c165e91565d0b7328ade3b164d5bf1870ab9000a38389ae1de035eaa0ff3673f6b01ff8e7cc3358b1f6b068b93b47d26482f8d5317a109f1b5475a86dd46df188f6d857b2c753b2323e14b70cddc6c5ce19f67e955f085f47480b55a164ede57fb029f3f7af1e0c0bb569e52db150f69c8763308109cae4dbc2cb22b9d0bf5842f0d80b0c2120f20f7f0f80e77084791eedbbb50f573ef7f7ac12735c91fe2603053c00b66c310029f779f229b249ebf21e0a09c4629900e66c8d86957251d64784d84385ae863e45a33b9f651bae7d3028c5f0bf036dd45ae41a72e72e412520c29e559928bc3f4c6a608f8e22cff57e2b40636c0dd27ec8673a01ad04d4c773970b6678d9e117eb10a3e24faaf4ebebc45b13c9dcbf23567647056b1f7dd319018d2bee8a059c8f2d1740aec65eb54aef3709f1a5f680fbdd9fda390ea2807fc04707365740563020003810a02fdd12c3cba97447dd59111452581743c53880ed8fb161904e6b97c4ce83fac66328bf77cb920ba7d2d28790a9dcdaeacafba83a59a56315ba410acd64c6ebd7862608044814df5ad160befb4eccaaa7ef1e7cd45a26898ab87c6c3ad4d07fc047073657407210252a4b012198c2131d70498b5939c401c01eb1178dfd58123b55766b03f008f7b00");
        pset_rtt("70736574ff01020402000000010401020105010401fb04020000000001017a0ad92644e9bf6cb8d0856a8ca713c8a212d3a62142e85454b7865217890e52ec3108a469a9811ec1c1df7a98dbc3a7f71860293e98c6fad8a7ef6828344e9172547302217d344513f0a5ed1a60ebeba01460c505ad63d95b3542fb303aca8f9382777d160014bd5c31aaea2ddc585f317ee589bc6800bc95e7e6220203f73515486481e116a5c2cb6fb4c5ee7a518523f878a1570b83e7989222d0236f4730440220330e4801f9d385f6e7a59b1fbd782357d44578ee95b59cb4030bfbeab44e43c5022037cf1eb808ee08b3ff929caa631f58a689cdf15e1540c965358419ad3cf6337d01010e208965573f41392a88d8bb106cf13a7bdc69f1ab914cd5e8de11235467b514e5a9010f04010000000001017a0af0b70a2237872fb9e84fbc002358469c51f85bcb6215930df63dd29953bbf5cf090e6df3e3b4e589ce447d3deb7cd4fa7a3c264a3d18b5e245a60add9f01137a4b0365026bb845d512434305eb2309656cd0701de8adfdcc84dd8b05d9e240ee55e6160014adf9a42f6d4643f7ae69d94114cfebc3824209ae010e208965573f41392a88d8bb106cf13a7bdc69f1ab914cd5e8de11235467b514e5a9010f04000000000007fc0470736574012108378fd3af2f7af7009fcf06b5ecae126d5446b134c6763d0a2c103b61ec348c5007fc047073657403210a1862832b5a1ff4c222398ab482534c75decc4176450df7c78280b4dd90062da70104220020c731ad44c00a2928d508ad82b05868cb42733a5b0d0b208f483307ce8c328d9307fc047073657404fd4e1060330000000000000001e772fd0127f16a4db9c194d7a039b46117fb73586a2826f59597af6eceb7a1762ffd8a88d62d846f2f64698505c921ac735fd08d784e833d930c8127fd8e2439e1d4541db5170e5aba306fbaac4c28ee6a30ad6e12886418dac926f46113c8ed01d146a9ca2b98171b63bfa0629ea26d256e8c9f7d6d936945e568dbc707be87439b65cdbd9bafbd3da43475bef08dda59fe1a7f661626e23da0ed70e5b2901f5a34790ceadb3dfed265e003143993b2674fa12f2188d88a1ec03c6767028d774b495a132f89b9404ff9b9772b92f22a75f5af5c5f4ae3ed213881d247141fe061f96fd7d619a657238c960b52cfd836e1255469eb787f1472d19091473fd26dc86f6f7ed613ac985b2c1716ea53b2cefdd0facd69b8428336d516de195422cea82842270a8b20f9ebb44b9492243430943540c5a82c17e6ec53e3ccb386925d2675d03d9a157757c60aa611dbb43873e89d8501d3a09aa7a38f606ab7e58a4d9aa456a125c502b9f5c0963b71348d71fd0db9aa7f9d4e6acf245a77c7701d4a5f58b876b154ba44cc2988024d81aa882b7babb80f0dde1b3468e9e575265c35d979910b8aa2cbd639db98268d9c58efcd12f9cb0ce2d13019866741b2efd0410d0129a6d06f0e95065ba7c41bddb6f1ede6e61a3016f9a5b53a7ceaa7f5d3b653c8603a50581e99c98e4d6bebbc914ed675efd060a8d9e8d796d1d5de0714014dcfd489a4810296092ead5009643fc93579e089fe2cf5e09889001714b12b550a4d7a85fb3538c58526f00075b2de37f4fae993c2493725911cef68cfeae49705844e16614944a9cb5e45784da4d1d4ac73b62340c175813aea49d1052f81cd7e2dcbb00f38473075d238bfe5dfd4f44863ddb2680e3859bdeb94044a4c469e55823d9502df43adbb60868d8240ec0bfc8f617a81e8d967710cb5971ad55b1069efe4b066c2e6efe4aaeccf786e5fe01f43a66ee8a2d0e6f360bf3fd8f98253d487c3f413a60945b6294b38eb9e67aa7fff203bce2f8e88e3530615ea44d8b058c92e4724821159e83baef0c17bb7bce9503bdc217758e2013b76028fde49121a4e9fa9219a9bd340a6feae9d0b4ced850f82d73f029e8fadb622e6b21e6829288054dd1e7bf5239f5750d97fbafba6753ca1fad8c2091a6a822f156e9d1667490fa0e6bd2668003f23382c651334882400adc52dae8bc4162cfabffb71dd89f3ffce25086455eca92ddfa2186fc8ab9cafb260e9a553125ec7636b0132f2cf4adc66f2d9f23d5bd4d2e36b1338bc103b59733f745e5d8f90d99bb04ac330224b9d609f695cc0aa93cd7c358c79d579f4f556bfc0bb42134ecf82876dfcbe22f487fe19cfa59457a3d3eb9846a99345ecdba7ab4e962456ccc1dad26baf9717e9982578296befd71d046eff05ddaed84cffb8d7b40cc264e59e43ceeafcb26c5bfaa5f0771d6e50b2874cfbc4a42bbd1866d19bf069ef65aed77952414de74096796388b2b2646a570dd6cdfffba2ea2531b8048d1d7a6cdeb53acb96be25d3206a8829b4ac683dafaa3aafb91778ef900eb3635afdb7a9ccda84a711c21018317cfca7101f35d34bdfe7d20198a3b7909c1dcd40d6e83043c246841b989166e85b77dfc849420da0a509256ea5dbc8ed088a73309df5a1340accc50f56fad29e37f3703a5116e6167b337d5a6787f2bb976055e124ada49fe0782836943b7013c026828c8566c75cdc55becbcd2011f10c110b0c388b0fe683b1eec3e8ebc2b3dddff465a8c13aa5b40222ffc0beb32edc9c6c80f08d93cf3209d4bb1b34279319526f186e0250536a3e8a5361fb034122d70e3d0a9bd4d3c62452aaf55d0c86648eb8a9324138f3b83e7b6e77b9ee70239e1b1c81c953f53a5524e0033b51a840caf171584137d46111fdf4e5041f560d2bb715c3f8a0892f4d65d65a7dc8e5130d444bdfd5af8c657eb7c6705950c9be7013bec799aaaae7b081b9f88f8d50cd92ec4d57ea980b5722c71cad6c75aef5fb2ce6c38c9ef53b580c49406e0dc4a85438651e79760670061b94a33cbeee90ad92954544e9c63086571980adc9072e54ffda0377e9771bc212734ba71ccfe5d433eda4909dd806c669283ae08ff35f4a6f768aa4aaf4e7fdd4d5614585d1269a3486971376db161df03118d02b0da31ed2e6fca2904a4b4be9f6578a7ef4545a2534923e4b3864a27612501fbc35e76bbeebe8488b222c99cc508db29d48aa335b4d2a0974f948c3207c92eec89716239dc6ec857776ac61ebe485c29e64ed8d1bf0acb547515c79a3dacb2316dcb5979d23df154e1fafa827f9011e43c5323478f9f48a89913bedbe4dc9b0c8535f8e82fe64179cd74d7fb37d7ad587b65af57b3784810c7b6ee412b6eaf5d1500082fc208a921bf94ae5329016645967c568874abb19a3ee9f752e7b17f35d49b73a66b62e5c41fe0f0683824123e3f0b6b5d3a9b47d2b5eae10913b08cb4370c754d769d6cfb4e4f30fabb38dcf243009bb8f36b6e2e086d70d3286b5633c23559190a5b0107c85474e9e3e87c7110271705e6944dfb232d6a9624d114baa3fa91108d3ba429381aacc0ca9ff188dde3c8836565b4d858fd0cf99c1f14dbf563128d0525c67b1e8014f1a88511d16cbd41046f2c13fc972797b65f3a8ab4407f317b64f4a458b7bd778349d602becad67df6d15793878f4403e1af6f4f54509a85e32e72eab2cedac74da77031908b3f358ff750140ed750267cdcc7e32e8ed32e461bf0aa7d8173e20f4352719a9297f1811e05f691421141eb7fb9d1997b596c629f89b96c08abd77f12f0ad8e76122a17c707e159f590ffec5947392d76ccb5ffb6d4311baa6a00957d185df86166a58ecd9956606ee147229ab58c3664d4c4a260a04558de5442afca4f1301bfea71b327238061f69f78f6154f684f590475bdcc6748775c3275023092f1347eac859b0073bc94e9722aeb4435d816778aba600b33ccc86d7ff502ffd3b5e5228294337c32c0b8aaf95a82cd920e095d0fbf93707be62fe12a27ab2f6c9fb07207787af7c50a4f61e1d860a510726125b0fccc8420ac41897d90f6a8790e984cb9f89e3ab1885e2ccbb3b17253f35336f423e7e04f31305330f27fac32b056117db89ddaa2a0657054e9ad0853ae6f62aedf30196f9b94152c7f7bbf88a83f2f58fe5cdb0d75f56e6050fca4047ad11042e0fd4b2951da3892b66a7674be99d1e82debd98493d80d857d943def54e7acfe405d2672f582bb64924c25495f2dc338735ae0d2b159fc52b26364375630c72cca71bda7b01dfabf4822037ee44f95e934321d853a87bcef2963382b6de64082ab9b3a0c91433c1a87a45c6290a804a34fce3b86e761c58896d0c9f3708661cc61aac282619cd96c60713dffbec7b357fdf51279d50365e008eed72c32f34003b2fc76089238d434d5d912135a553f543b6befec4f7a9496c90ba236eafc7953f4a081de67e2dc549ff15c7734bf12b184670d0424bf20f53662983749aa91a65651d899fb4858abc55282552d22be27f697a7d89cf548591d7d5e7a16a2211c8ff09792e81a9c9042e58a5e76ee678580d3680840465a10692d45ce84faf5cd7fcc9aca49aceee374814110abdda662f4955d99bb27ad310d47e6fb735ce5008fa374d72924f707dff39233bd4109839c3bc61054f7e6715d27e55bcc3464c5c31d109102b95480a0a77e69a2e2cec60c0ce5b0511e8b54445c6eb2086aaa9f47a7130b28fea6fbe2fc26d68fe52d14193d4498f5164f652e8c0259f34956331526acda2611357cc259835351b250137ae3ed44a0d2d25796a8c0cd5d84a0753444509fc0682ea0aa232f6937054864493acf2317c626d36bf13251a92fdae72e7a184e32745343d2b968f2497e79d859059ce132bd898a84c989e5687537caddd4d2f8206e5e10f2f44ee6864baf71ed219c294a7373c5730323b19893b9fdbcb6137d0a5045c3be8bf837c6f5747ab0d91d8db1f17fdee9860e3123fec121148266e8579570bde602ef156ae16ad75fbb31db0e451e06299924ccf2963f600756a47ffe688ad700ce4e1bff02f37f9029a799fc53133b1df2841622981cbe9a1e2753e0db6ecc35fc2beebce4a28c47f6f1ad4bd972befc6fd606f83dc4d319b4935c65709e1e16e97c893ae007634b0883bc2b8a4e2174bcf6bd485c47b9c96c0b11939c4f5edd3db999124d46a4ce4c2564a535406430aa679b2f850272dda5b282b3f9a2431470765e00eec90b310800ee317c2a6aae192552b9e85adafddc556458b6bd5b5e76e770998a2a29b1fdbb37b2f57aba1360f912273134e540ee68c097b8f11275c30171ffa1875a8aaa45106758429061c20330a80f1928c2a9d16e33ded189ac103fb021ffdde726e9eeea1e03a3fdd9f34d9e52b4c5be2d3855e9b60150f7acc909a5d011a3f98cade7eb101abe935372bc81f4b5f18c806de51ebec0a8e032c0e4bdbdbf56429aa1996ede1bd98c7263896f81471f41cbff7311b17b42905d802a6460668a773ee1ef426785f866318f129e2cea728a7f127cd0433879f48812f5ab56fafd270b2cd5186f199d3b875ff5c3c20983e4acd2e8fdeddbb3ca68021bcbb9f9f31b3aa4a07d365b1c72e6b7096241e07e441a5e5314afff8b6285f04eedd74eeb20a41b329dc448ccb8161244711b34982dfd42f66da04e132757c16e54bbfa0d479ff8983eedddefca29a53c588db5e6d0f1e5f4a3f51f766dc3076ef722885844d8655301de79a24b484e1759708f1ebf2716b9688314217b5874bd64d2204efa872283ba9c47d85a0ceb5e5e1fa1cd2eff888a74c10a6a3075fcfae2353154cedb9418f9937a06b02c198e608017895a02c65039195e4c91b2dafefc1e238c069d887d450ef3cb2f786f59bb2e9e4caf743382d7aa665b8b32f484dd44fc9000f86ca3ef57c6a39ba31790f3e12c402d1e3a09a892923e3cef063ea8c29559fb2f3dbd6a4e019f037ed89475dbd825962f360e396646f8ffa00c479f9e8460127b728c543117dce38ae17cfb36b109110cf44f2a712b6cc6b2220db93ca7ef58b5fa163559d10d80aea598afc1221290237172692b418ce4267824dbd237ed2143de7a9d73125f8c682a2a2fd42d537bf8fea48336aa508247814875ad24c541386133d8fcbf28ebd0451a67e7d69ef9018609dc09a4f36dc93953006a82c39d601022bc425dedc2edd6bebabe78fd8ba17ae2b3c4fd657e6b9fbc887e5ad442326cc872075cd960b615fb36b18d140735830da257a4d42f2732d501b21cc883d8beb61ea72961864affff658129f91a59bfaf9dd38ae0cc92c7d8f68d531cdd5e06fd115ed9b4e3b24350882c3914c5f8d2df77e8bf615c6d7427665e395cb5487e13c8df9d3935a8431d95d02a26373dbe4f66a71b31100516596175b17fc6d0fa0c5f0d20bb121ec8fd43567721ffe0e1fdc38d20cf3adcf5004784edbcfadbf60d0d1703012ffcdf918b091a4d2807d896aa463a8f037dddbc01024fa34fbb93a06fd3ea23bacab8fb53937425fa14d6b819d50f91a4cc75689e05e988b8dda6ca89a78acd8eb68457c6dfed5f08aff4523f4695e79c315390f829f1241eb78d6f618c6508e15d3cb6ef70f0c4fcb69ca0e90e1186caa9de5b0553729af8c795db4578e061748fc25851e607dcaffd274e3a6e2d561ca4a55684065e1cacbdb5cd75fadd71ce5bc107365e6fb9dbf778248261613d49c36d1dd1b3403580ff4e6494291690c4508a8defac836876a25a4e9054ecad77937cf9df6f22282ed5f0a7778b4affcaf09f103464864c8c1fcbae97d9e4db03750213eb0a78475b45caef4a477f1c73dc8f9e39dd7d4dd50396007fc0470736574056302000385eaed68d747a689f194dd86d5da452bf2f327d795d5d504e1a59b038ec702d9ad78f74c269b6c97c8b2b6496bafcf9790dc9c608304da86ca5edaafbd62dc960bfe5c8bf1b4833e5b5177e26bb83bbd28415ff617db4e3c3c33b03f10427bbb07fc04707365740721027fa518c54bb326d5ce3da5c2eb8a6521ab99df86b511477d0f5ebcd616f063ac0007fc04707365740121090b81ada05aaa354e5c62732358c8a2395dd9576631d9377844935cac78d3b4e807fc047073657403210bc57b6abf30fcb84f8660771267bb93a6e72de69165ecc9e462d6fff5153d6296010422002058037c2d81d3122185c8704d4276e2629122c95b8ea68575c451628d37eea84507fc047073657404fd4e10603300000000000000017823c100e4cb4ea3cd1380fc7986f67a937b71320ac40fcbbcd3fbd3f37dfbb8c4ac0eecc7c8b91d14c7148d2e162d1c4dea595dd8dfb80c0e064b926ef679d2eae0973773f44dcf8cbe7a6e53035366c0c9131cf991bf8eedd5a759ed33baa868e6e3849c93c40bbfdd6d485ce31941d09f9ca07c7d3a3b724760e637191c5344fc7812976c541de2005ef96fc57d8645bfe6e9cf5824a0e084df078006f11dc485c39ee1d196d793a544d458358e4d949c5449a63875196328fda3b29ee227add62fc36f3898512ff596272ea40d79f376a890c806fcbb33d8e7d1552e9aa3dd14420342039157cb991401faf3dcbadace85d5d093ef744462079028c9e68c9aa48b921be8f809b950517af97da5d0e994d1c68a1a9969972a541e3111b0710e552ab40927c165192e263fd00af1b1f0d7eacaef63c52852336c0293b0d0a381b0cd90864240dbb2f6cb61c7149f432a11f62080f7d47d9a04b854b4490eb7a53b4fe33e146db108d235f6b164d22a4a9cab38f5501f4e2bff1963a327f757b8df26d2f65d2d1b933fe6cf8d12c4c7cd8c2f5dd7a69c989516e729b52b6688a4c29333f21a84247e52b152c455d45f582fca280bf818f7c0d8967a43b5d38465922e4de8d2eff49971d28980793eb41a5885cdb4f32e528edf4de6939239ff1c678160b51a1fc5d6e83f3c6cbab2aa88d3e1ab8911779026ede67a6a7b85a57b8a09665150e0cbc3dc615e1d5e39279c2eb24c80423b0568b481b5a37fac1d88b8f686b149c9404b399148aac35515150fbccb29018ddef5c9d219231672ba884020e50ef3e11e29a50a3677fbb427174e2730b1a5293ba9d2f448ae6070294a59de9f0a174273d580af7c87c07acb27962588de2d69c9adf01ab86065f180daef68c9e3399aeb1c290622412484bc88d182ebd19833e6476e24a70a0d1964e61a9258346fa8237b9940612ddb90d91779c5ca2e294679d0ca15367b5db571b81fa0c7e9871147ce9d2729dc3168296d13ee2dbde145ad9bcfb0e24e2542c8a2e06424c5ccf3beb23be0b57acee847f579c1d548306e6fb2fd7bc42c529415002b292d9ce82883d627625a76299f3d055a031be110bcadb95eadffbc6a5a14c97d1a6169dd3ca058e0ee997cefd94f2595e39c06ebebd2862edf7242adabc9716c28555f5ac93ee2609d75c4a852d788eff783c3bcac47b8f7330d2359f004879df8a475ba381c32379d3787761fbbba34a8e9a59fe736bc489562e2ddf71bc9cddf3ee0015857939b6d1af58d3a7fdabd925c8b2e724f0b6a80e7c5c1e7d04bfcb8cc44ecc172f3c18cd73d226f62f4a1fbab7cc6367088f61ec3e562989e01ebba29f8b7f6a94c0c7b32fdcabfc2dbe4ecf404f5fc7d5f05d8694f95c735849ad1e32a44810da350c4cf08c61d8693f468578d09fdb924278add9d261daba0ed187210f239bb4a97763313f2e006ddc202d4550412f68c5be848e1d34a55cce1b894ebc9dce7e9cc16859d940bfad3dd848afb99e2868a92b1d9da7a022ea7405abd42a79995f7351627ced6250f5fcd4f0d179e0101ada67ee8f96e4bd0d7afc1da123616d7a588e07ba84fe948c8ce1e7b51f88d8be970a706c9175d9e46c23388cfff0609533283ab8d2282487f0181d45274ace8a92a8a0eff3d52aba9732a64d787d0effeaa58d03c9df620a43afd2de9607783069ba61e2c583b576150baf140ee48468afe18ffd9da3eecca84b0aa3b7a7af17ef69d77d6f0d99f0e83d9a30652b3487aba49537381ae0afc2885c70ed1fae6dc5cca933d92b8c089bae4855477584e32331623c0369f500d4b36d62d15a81a4d7c197584aa30db415d9197d9cb7ef641cac840a023fdee46c66e3176bae974cdd58ab5ae2c7346390dc696a2208ca7a18c8cf671962791f4e827420e6ceb6cbb58b07054a2355dcd30c2edb64f536860515d515521031f63f9c2a8442694746e9b4ebbf5b85afd96d4e6c25a50013e363681f229645455892f1a1cb8b2a8073a925ecc3832c339d97e9249a8bdd695616cb2818a26bebef23bc94a58a411be30683bcd16a4b6472ba04fc401ecb59f0486dc5b01ac1e0ae57a132c768e4c7fe27dc9b4c422fa647953ba9bec22cf8ad5669c913e0731b03468ebd6009c14283fa1f195fc6636eb30e12cde2c263ae984980a3cd8aacf424e0ebb68c4e9521e2b61c2b39d7ede48d7e98837c7d840455a5525b98f7bf79fd6258059e4e6925db4577eb62b5263d91b7f17a24d3b0ac1163e42d9c367a363034b5c03062c4706885770a5fe3af5ed1ec6e2fa2d3ef23a33acd2fbc30bf436999be36ec7cc9cde96a96bc34d0e0edee7b0ad98a35d8bb1699312d3c1b4966003a054a9bebd8815ca947205fcbfc3dd2c6240a6b911ded609d2c2cbef2fb151d80305615d60ce8fbf4089946780d10523ac165ea7bc38c3a2e6bf800b38d47ca603dcb20bd4dfb40d0c02cf2f3d2727e8995203296b06f2c353f327b2ec1d9503b1060b57144ca9b648c1c87ae982e38ebdd961e3beef4e198eefb1b944f79cc136d38ba449e9800cd2897a2f0e15856883a839fa7f89220c02703f704d1761d8391a183a98e6fc0d9bea48440eed02c84e5e4b70c202c2dfea04047085763766e28e3d4b174ccb7727b05d74c55f7a91de3599834697ba0ce4692a14f966c53fb735109e20599741df2a6ed21d67076dc078b8e565f3afd95e7762bdc3d9818cd69109f59c45aff6088ce3a5ecadf3ba2e10960b115d39d02b559b16488fc7b8a23cbe534311baf5731576c5ed93bfb838edfe4c7c2eeddc2405e8cc4c741f1e6e562592be7f95ecbc26251edbec6b35581738b44673e8295494f804e6ecae2b23527946956f68546fe01b38ff1fd0e8f3090916a0e421d804da219bdac63410d62749b429f82c9c2463c52aa29aa3dc0359051cb5666c6be81a5e7bb85f62be8ec4dd10f2948f82ec66ef4e0471fef64efa4cce7232923b19c72862c674250316448e201abb5fddf248a747689daf8f04343f1e695d3fd045f5e32e98462c0d65d0ff4d751c03826ce02c7513c3c56776325d4566afcf780876ce17fea8450e48d8a36f22879d83014dc6fb7e7ec0ea5fe309723862bb5e2cc1a4899e18583c8ceae1246ba8f12b357dbd91e51718486777b192ac97de65a35a40655b25426a30373278e897a2b99658ad27277ed32e7eac3b7c5d5c775110b5327dac2f3d92125ab3b3bcbc383afd93e795764bf2632c7b4c98876c95e41b7c3fe2952db073cd4ad219ab3aa5d0901cd53b8acd8e2fd92f93d7e5ff0eb5ad97a2240764fc40e8683a1cc28484fb3b1027059a53ffa5552406e9bd7c3d28dc0b081a37cd5a13af22288d39975018984c084cadfaf5ae4c91d8b00a6466ab7cd50f1f143f11ce8ecaf39809a3c4833b5e11945564f1f0d025a07427100e60bc40e065bfe938246b3345fa8fa4a8ee9bb50a5152c90f43d239401ef79894b5f2db6e8f2e98663d6497dabd94f13d9cec86bd2707cf32df56f5a6693ffe9be7ec362c0bc03b6816269dd2b72f5638209dbc1afc97eed232f2916f19d4ccabc55a6cc0a48ebdcbd59ce0404ebb47740a0d802f057116714ddab4aa3bcb5d8ca20069af51e09f941b9efd73e8515aed1db7ba79137146e5c14262dff94a885cfdf435d60d91bf2f508c110106fe4a0eb4c32ca382825ca6a65aa2749a224a62d8a1dbdffc5b53bb4cf2315e9d107a73721cb3ddd111c723cacecbc219ae5c850beae3b3b6a5577222af1706a625965b7c7c7f13f01cbfa9c6f1cf406fd177433b9ad4213fdb30abe01cbe931cde34de1650e69d348d25b6128a26ff8b0a73947399b4162bb6513043167a3871960f0dcd5dce5b6ad680ec782ca48515010244d5692ce8e6a56c291c3512e7ef91680769be39530839adb5a8898d83834d398e63ebb2ad00d42d414233a070dd6bbdd6093c96eb8478953fb04c3e82a7c84a798d7bde36547bdf4486e8bb3a6fddcd9d7ae1b007e61e4da3b85ea327c1ab8f40a66b36190eb3bee753bf1043335ce82cb31751b7e89b84fa9ccec5427b28c161512a963f80bdc72c38fae1b32b4d7900f983b51f42144a82514b535d71f3dc80c0b28f49c20b346d344ed9c81b556ddc49263ddc687e64daa55d659d0a806709a62065e1eb1c694a6e46f6c8b10bd47e76664c42b9d992c23999ce516a5cb6d68a4748957c63b2db6939b86adad8fcdcfb5bb643b08e156d61e5bc4c5810802d5afc1c0e3b160b01d6e5675e5172253d1d943b96a6a6c940925a4f6850612b8c57ddca11e893fcb5e5e791a6749f75969b49c684aca0399bb322b9a72997e204b649c3d26f726ea0a49920ebf4b533bd4b38e1cba3a2422e37c3e259dddd8ec10afce3f1baf2bee470eb752c5721aa49a3b8b4bee25a9f6aa626ade570864246ca2a5c6f0d183ab2d909ebc336db2126a4fd24de704befbd2f07c7cd6c0169a07777e5a583fd3a9a9ff1241fea91c504fd5e4d6c6e636a9a5c3fa56824e74c68c1ebb8c4afa90ff2364acfd4547fff73f94f133d63bef1ddae0a8a338ee8e50777d1b7907f4871bc4efaf746ec2c7b9fadd717bec888026e32e5e26bb0101a269816b9046c29a42b35ee15e203fa26d321fe03f042a8f21cbd62e1bb0bb371d00e46492bd655d0261129393c023d20ce9ddf0f0687820e563d3688cf1e7946a0cdf09737c3715dfa8a6777bf94ddd2d127bb5ad942dd07738eac8b6955019799ce77cc42136dc9aa822470ac56efcd359bf180e95f3fb312cd0ba9ee9bab99560d0b41ea7831bebcf20f27e17303208ef66d5c0f82d26d8093f002418267115e10331646fd87ba1f1a42f72fb45d2a4a4e4353698863e65a7cd4f6f3cd0dea28dbaf5794de216afe202b679899518a3dee9d4024afa3dc9d8d4eaf0179b05ceb22d1e60bd941d44c3866362a92a7951d9de36e4e7d1a681fb2d9420e0fbffe795e9683857846ae0e834d818f990e575a7fa7efe7638fad98fc5b680abbb58cb8da78d783a7ca16fb7521b4be25d4fded9417cc7fd9525c79df7e52bb83894dd905794282a7413bca79bb653afce07cc433e49ffc38d16b7be05c1c9ad05988ed672e1b4dcac2a5d211d7ad1b790e4ec0761533925f528a21305b942e0dd10efdb99bf1fd6d6b906ea0d21ea7bcbb4116490d97246458fe29644f149122586b6f16df620ab1480b55f27f3e8bf32c2c094bece34cce03c20b5a2d2b73481c7cefe4bf56dc76c7970dd77673e4383f62998b6923f103eb0e5c1ce91e43da83495961460b677c261a027db4ca979597a8232691c3ece94456e313ca57f8c2021334cd4e0735453597d516dcf6e04d386ac61bcee073f7520d205fb1ec6c35c6c96511e8a067ce5ba3d701beacde937c925b204ea011521b3e1219650568ff9dda90e043c9d20224fd767670586812a41ad83208f5d62f7892b22500be3ab2028207f738c21301e1aeab23d1bd4e46d46f2ec1991683e987d3d834bc260113372e3eadbf825f86d42f463795050f5821a6afadfe42cc1cad6fe942d16af7e35dd08004ef676558ecc8801c45d37a8c147102e120ecb7c965a2e33ddab0a43133692de2133cc64e655961e66caff271e0625c469a24baf126ea7d300bac5f0335dd5926e99394d45280cd6e14e7c3d5be3b3745b617d9f7e01f0bbe15a0512e2501bb7361a17c62f4549df0e765cf8a2556a9d1827ccf22c75680db0d7391da9f0c18926bb90423c7e084f4fa11cf05914bddbb8359684dd920db82bff035702f2484621ea1d71d2589a3d5db2a876d78b2228a1b4b7b9ccc8c4ed6f5df7010771ed118f96bda339ed2025808099333224f99f207e3e808312f49cdad7e0007fc0470736574056302000381eb5d013a1bbdfc28e27c272822893a4b674355a29a306afa132cf3fe9dc2955ab2375883d5f7e42ada61971ea91f8af2f106402c5592e676a32e3313d03af9eba6e1185d722a0b726da16714e13cd416c8e99f1b7f0aa44b721c483fdf593b07fc047073657407210302e71fc2fff37aeb6d2e2a7b7f2308d4ab7d4bf0a4cf9be7c06e89a66442b48300010308f40100000000000007fc04707365740220230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b20104000007fc0470736574012109870d0ad593316a7ff67dee90f2c2d8e305cfcdc4619fe0922c706560eac5d8f507fc047073657403210b9991881df2ec384ff5616f6c03d45cf033ee64536297c3557f9fffec716c1fbe0104220020cd4ed5f0db8c450e8b0be595b6410c1759c19f1f6926279095c83dade9862b6d07fc047073657404fd4e10603300000000000000017d32a9010e698107419c4e5b47c05ec25624ea0d6f432f75b744a15b8f8381b5fec29c0b55b8eb600b91a3e13c0e56e601c23882ffd62fc218b1da72e2ad732a47f7279d32cbb24eda0caaeaca8d8fe4bc920e0baa6821b47f7790416a5bdf13d691c51914358a431dbb2e9154bc01da79483cc9617f4d57a6f4d2d1380ea2450c292ada85eb663a23c76a6adc0c7abf8ff71b41a56478b66003ba839295df69edeaccc54a9b3803c9d3eda9cd47e478fd852a316802c8def8014a449cb886d0fcb5d56086e8742a346b983657f331330f6e8ec4bf72b314cc6d69bd94be0bb6e6896ec01f773c1a4c329e7ddbf326b83780ab22da08a144fc1c8dfda604cc1b2858682ad3decb097c1ae3e992596ae997422c7d381d8d9354be1658c43e5d5c1e49f0e7263aee9093c018b09ef44ca7adf853c625187a8ed252527b94a5bd70e13c30b22f05038404d99c18c0cd76a461ad7dc4ba63d132101ee471bfac835eabe0f11487ab7361e337f5ca8dca3cfb25de4958c58d59df6ea016a9436856a3af505884a4e38d9cc1ac955c40228c22ffe385dd48b3f1c27d40e7794ce62822645b2a2e42346f9771f2744fdf5064309f9f7f84747131369ee9b5421a07d24ec6e7baeaf1c99cf8339f38e44b0864ef46684815c320df48159f83aa80e247d617acf1b1c7a2da56cb3725811ef028987573f59c90587f88553fc6a11723fa5e45424de05d2b0f548dff87a8e1b094a929f695f01b7a127b522ba2a6d6290991d0985af8059f002f514f5027fe98d292fc85f050d5a19189a27344f83f737ccf254c97728054ed01e1d229f65b2b9d66a7c82116bf26ecfc026446cee24c5603e0bf0df9875461623340a7148de14a058f1a37e8c627bac2acfa2aa1de65d1349e7d02d565852af1de756203d2aac22330c43b12f1e1889c8ff2959b1c11e85b2a1f577b47e1242db2b1bb4cb03979ab255353bd91a728a67827a86899ab68b3ecb64e2303c6c701c1ba3aa09740264a42194277fde906dd6caab566c089fc83fb9ad4528d50c48d72d8a68e8bdfa846284979e7201f41d225b2a782ae77cccef12da93d2c2e73f5df35f75102fd7bae8c5c2c92e79236f687b8559b7d625658f6121101ff205dfed8356fd447c9670330b3f197c3249b05dc72f943f1760489dbb1bd53b2bbe65ba8ed7c880ecf97a1cdb9e78551c978201aed0c1e6202d2bf807df2334bac733ae2cec1af8a409cb8b32830fa0696c18ad11d99c3cd0de7136b83d903d955acb584117e4ce39958d75d6e1ed790e4f5613fcae6a827078a45676afb7fa82f0642d37c273e2378e58403ca9542d542d6ae549752bb9a85cb1c5d71819cf8985c5fe52e6de0c75c61a2d4b597014009e2bbfa7a44085bc75af6adf6de4d0f1e5fa8dd68d5e13e7b10710d9ae67838a775b17370a052c019ee984e169235a2a1a20e7a157d0e3c93f477907e48f018780e0300b9c1cdea826a81d9900547b7fb7e133d5dea37482e40d27d3feeea57a07dc795737af5f01286ab37003c7dbd8e335978639704333af1988feea17da0af7606f5cad04660495009788afd99412e036db5c9c9fb0c643873fd0a301d7c37975f6b54906d3cd992c7c435b334f695c1f87ef071a58b890b2dc2771c2bec4ffcb9c121feec068ff0cf4924ca1b3cc10b802558f05d7cc2970c3b0df9cb7ddbc306269dc42d8dd882943182cf092d6007248288822d6ee80bfd24f4077f1f662cd3c0f577f831df25cc20d2c1541c44df2cd07586f4efa26e0c208430889dcd4e548be9adba2def0cd048b57d73ecee8e3005181e73d4d12bf11d225a234cb3019c0cbebd0d9c2f3bea6832eeff2109d8843ee61e682098250641df7bbe21c72c7831c215e0234d71cedd22b2370ef3d574f321c6d45607175ad9568dc06520f33d2b15ef2bfb0fe9e48bc01560dcdd73b6fcba2caeeafaab2646f7b46e9d1c3c992afb18b7c2d9d2f88095c1033bbbb9449ec6467da2e302aea9979b28fcce685878619a8d8757451d5b80d4e57a3a213a599b467703c5f96297ee6ce44fc06b1afbe411f1a665ad0745bd7fd2a5b49ceef6b468817f500479af2a8f6c0e3557eb98df51a4df26fcd5cfcdda48e5441114c24573bcca96356d3c99d01eb8f8a7ab397d6c8a54dd9abde6d16cac1ff2ce86095ffee79a304355df03d72f2d332b50898ae06a775f5f7fcef3784c152f51b8ddf9cfea4f0bd271eb98ebca53529f103228aedbf64f03966c5bc2e774c980cd13db22f3c3f6136b6b03ca6cef7a4f310b57dbbe9431946d784fea7eef3258f10a7bd5dca55102bfa49c04fd117a8c521a5b691249e994b8e935bbfd1b86b5512a56ac222e989f04dd07c34a5219dcd5ab003ab118ad40746ec25bcc056b35afc35b656895bddb4d368623e17a61f3803213c1f122d8e6281d013df14fba919209fc2e4bc538021e5d5ca8a1a751859f908f47b39f1a3112611a3e19264513a7301e68979bf0221f1cb418f9cafb7b81db4ebf08e0c7a1b57da5cfe8e32ad16b0c2fbe9b5f7ffa5c80aa3217b082e4f6c9f51cb79fbe27ba459e09b01b3fdef45edb5d1b063fc99937a822a5a43803b610a3081b67f7279e18481754f3802753c5201a60e4fd89e0947616a33ed4218d8e708ed81fec6e3f39d7a94378d92fd6d8d64769bcbd4cc1d66cdf4ada5b189e03461b583dc88f2972c6e4904afc3b49b38818be26f83c94cff7ed4c826917f3314a931b92d65e562014cd9a1a68ea79fafceddd09b8b0e48eeac86e6190e470ebe8ec5cee12948942f80de6a40dc2c657b6ade6a2ab4b3297ec713bc3cebcf91f8465a14e9d9d5325fed40d2a2af8bd0731d9b626095653e5fd292cd5de3a7831c0ae81292630409ab755fceaedc4e76e78b829219209476b94d0c6224930bd6c7d4a6b06ac9699be79caca17b1a7c9254f1b884a87e44de4ce5b15f312b09210d09436a8bc1ee39b6e5f96ba5b620d614a09259b251910219ae39d65c2650e2d2a27cc0d2dbd5e2aa40b5b4bc4ead5ed531d7f206a4bfbfabb96785b768aac21ab8f11f927d54949ec3c595f31391bea8b4f1a63db49e26d875be2cd4333eb5785ab1cfe7f83c6e4a445702f9178343e039a7651b62acd31d694db89287c1ec5a636933a630b3465d27015e564bd2a4848d0910739702debb3d9c7c133c2a2f5c6d93000ae74bffd2af4ec66180e7219ad8af293ec89fdbb0d43d6b9dc5fd539c338136436ef1ce088af4590f47af91d78338c67b03500d4c69de61b44e09a776399d7cc349c95752405f65b0ec19a14434d715aa11a14c5be94d42114c546af8c02d291b3d54471ae463d249237fe3bd18f7afc569c43e1c1cd284538e48444f39e8c83d9d52f7754c04a6198711f8ebdfbf647002ddb54ca3c8833a3a21e0bd7a8cfa1274f61a36183fcd63670f1f5b425f2d06ce8338410baa860faf2331ef93f781d1fcf10c38b2be7ca21cb27430147466867d233acbe6f7ff46136ef736a1a1b5af97cb871a8351d7774bbcf0f0f47ef10c7a5b26f0a25d403fc7cf2e7bb57a1f16c68260092523c82ea020f0df2660faf2f6d85e695cb672857bc9fd4f7ea0b93f735007d9ad15e661329a22bc465f6c65f442f5be91c665f3d7311290b47fb7c10342a5a367ee18dacfc51a83ad0bba7503b54a27545abe372078505062f4b859947168b46638f3a4ebd116fdaea1d96238c4cdae5882f326287da8e94dfbcf9c82f92ec94ec8706dc6ce194fcf7890e047e106aa387173662ac2ff1302627f80c567fc7e74d36473bb601681bfc1b5221e15863bb9f8d5e30bef41ba5839349a677e35d30e0000596691b2bde87e386998e3e2a463aea434ad9002438375ef1071afe9bc5027cec29b5cca4196b2b34b8f92cfba033a9e2539aeee306c5acb88f22c7799bd7208853a735d317df6c957108c6c10c53e9e1055f6108369aa4918dabfaffa446c40b20c73216e976a9fe03cd157ee29efc03e6a8df077a5222008e37f257816703e1b9e214ebda174ed7b4aa1b5e0494f5285704ff6ee22fc1f386dae624b72a7e24d2a56c97a8d8b816ceddc68119c279a2654f19d3d76cd314e9fb6218b9682455f81c7064e33295060dd0b91b958dc04599a5713795c39b51744b5629512a9028a38de8f674214de7bd4845e53244705e431526fb28b8c51b3bfde0202c50187f6748581d5faccee866d0c317345ff6b65b954ed479750d0a052e3fe3f557c88f4964cd95826a7be6da14b54d4c00dbf9b2392aab6d084262427f24d163ce590b8d36547ed8139bd241b8f18d9d9c32850a29473820f68e9197f97e7d54ec76bfebe6fc3006b3c7aaf370416d758fe4426758fb8720bb764b6cd1aa174a58d42361ca8c2396079a634bea9e492a7e1fa5d443a2299c66ae23a064d6e70c605019527f1b499a614c28d3c8cdfee753abb9b1a5b8d9bfde29a5ea869ab95a1c7c1c076f933938008060800636f357a48862bedfd89a70ab30ba31919bdf6b53edd085b3836657a4bb214cebd2dfae4030d19fb9473e046ce6ec39871150a4f0ea03e3513c5615bb50135678d024e69eb754bbdda896eb0f2d39a1f7671231ab6887902faa3adc79cb77d122e184031f7e3a9cc222b3e9788dd9c417cada21fb6bac493b15fc306d64cb701dac8534cda58bd37121adebe474ddfffa1afd26a999b41280b043992b5b7fd6f4926b5b6994a621fca3d13ead3142d8c255d80c33a86ee4d6ef04289a23f0d39f7b73c30ba59005ff0f1eef21f9ec01e703aafc1171a4d24d8257917b239c5c3b447549cb2c9602188fea59024d6def3b37e26789c2fdd90beaeb30790afcde5cb8179770cd3194d5ddeae7eebad7b273c7c53eb184f17b3934f4d0cfbddd9f8e9b135ad4fffa8b5edb04e2fd34e21f29717f3f2b9c01c0a547b3e522041bc5a0c647d7c8eb543b94856a40ad9c4d2ebe94a3de31b810fa99aa4b19a9a0ee51abd355b3c556f26dec3405b19d5a5da8a6c8e263c8e2e97514053a7c57097cde1649bd6c77fe78ffb96ffc69cd43fea598e611ff55a0a306883b01a44ecdba59e103626f4a08e3444868d27e737ad41f3c2564b593ed169036a7c4b883594bcd141847f22c1933e04fbbfedf71d885c5cfe17769eb36b295950e9a420919d06110774029a42ceba64c6f3ec12404047e78f1c67178e65d1caa49894f8b606244a365744c8c826c682a756f560c1d4f71e1fd566547a8c070fd64eb2ba941e844f86af062e67bfecfeca33f0a69c186a5ad2242e100b0bbab31322cc9dcad523297d53f44c4ad8cbc2826bd2e1f211cf6fe29116f6c0bc5d37f7ac8376a574dba76dede5fc6e72e4853d4cbc0d302e20bc130578419d8730215172a470f98e9bc868c1f7511bcc353e879199d0b25a06cf49184808bdf76c165e91565d0b7328ade3b164d5bf1870ab9000a38389ae1de035eaa0ff3673f6b01ff8e7cc3358b1f6b068b93b47d26482f8d5317a109f1b5475a86dd46df188f6d857b2c753b2323e14b70cddc6c5ce19f67e955f085f47480b55a164ede57fb029f3f7af1e0c0bb569e52db150f69c8763308109cae4dbc2cb22b9d0bf5842f0d80b0c2120f20f7f0f80e77084791eedbbb50f573ef7f7ac12735c91fe2603053c00b66c310029f779f229b249ebf21e0a09c4629900e66c8d86957251d64784d84385ae863e45a33b9f651bae7d3028c5f0bf036dd45ae41a72e72e412520c29e559928bc3f4c6a608f8e22cff57e2b40636c0dd27ec8673a01ad04d4c773970b6678d9e117eb10a3e24faaf4ebebc45b13c9dcbf23567647056b1f7dd319018d2bee8a059c8f2d1740aec65eb54aef3709f1a5f680fbdd9fda390ea2807fc04707365740563020003810a02fdd12c3cba97447dd59111452581743c53880ed8fb161904e6b97c4ce83fac66328bf77cb920ba7d2d28790a9dcdaeacafba83a59a56315ba410acd64c6ebd7862608044814df5ad160befb4eccaaa7ef1e7cd45a26898ab87c6c3ad4d07fc047073657407210252a4b012198c2131d70498b5939c401c01eb1178dfd58123b55766b03f008f7b00");
        pset_rtt("70736574ff01020402000000010401020105010401fb04020000000001017a0ad92644e9bf6cb8d0856a8ca713c8a212d3a62142e85454b7865217890e52ec3108a469a9811ec1c1df7a98dbc3a7f71860293e98c6fad8a7ef6828344e9172547302217d344513f0a5ed1a60ebeba01460c505ad63d95b3542fb303aca8f9382777d160014bd5c31aaea2ddc585f317ee589bc6800bc95e7e6220203f73515486481e116a5c2cb6fb4c5ee7a518523f878a1570b83e7989222d0236f4730440220330e4801f9d385f6e7a59b1fbd782357d44578ee95b59cb4030bfbeab44e43c5022037cf1eb808ee08b3ff929caa631f58a689cdf15e1540c965358419ad3cf6337d01010e208965573f41392a88d8bb106cf13a7bdc69f1ab914cd5e8de11235467b514e5a9010f04010000000001017a0af0b70a2237872fb9e84fbc002358469c51f85bcb6215930df63dd29953bbf5cf090e6df3e3b4e589ce447d3deb7cd4fa7a3c264a3d18b5e245a60add9f01137a4b0365026bb845d512434305eb2309656cd0701de8adfdcc84dd8b05d9e240ee55e6160014adf9a42f6d4643f7ae69d94114cfebc3824209ae2202032e7429173d6c0a555e9389dc90df48c5248af4b73384159c37d533a2aa79753a473044022070679d770419120e2380c6611f7a78b21f64fe88f015646ced3b6cf5e843807402201360c9015b4867e7f771a2f6059dceee13295a3529bc6a56769a3902c32f6b3d01010e208965573f41392a88d8bb106cf13a7bdc69f1ab914cd5e8de11235467b514e5a9010f04000000000007fc0470736574012108378fd3af2f7af7009fcf06b5ecae126d5446b134c6763d0a2c103b61ec348c5007fc047073657403210a1862832b5a1ff4c222398ab482534c75decc4176450df7c78280b4dd90062da70104220020c731ad44c00a2928d508ad82b05868cb42733a5b0d0b208f483307ce8c328d9307fc047073657404fd4e1060330000000000000001e772fd0127f16a4db9c194d7a039b46117fb73586a2826f59597af6eceb7a1762ffd8a88d62d846f2f64698505c921ac735fd08d784e833d930c8127fd8e2439e1d4541db5170e5aba306fbaac4c28ee6a30ad6e12886418dac926f46113c8ed01d146a9ca2b98171b63bfa0629ea26d256e8c9f7d6d936945e568dbc707be87439b65cdbd9bafbd3da43475bef08dda59fe1a7f661626e23da0ed70e5b2901f5a34790ceadb3dfed265e003143993b2674fa12f2188d88a1ec03c6767028d774b495a132f89b9404ff9b9772b92f22a75f5af5c5f4ae3ed213881d247141fe061f96fd7d619a657238c960b52cfd836e1255469eb787f1472d19091473fd26dc86f6f7ed613ac985b2c1716ea53b2cefdd0facd69b8428336d516de195422cea82842270a8b20f9ebb44b9492243430943540c5a82c17e6ec53e3ccb386925d2675d03d9a157757c60aa611dbb43873e89d8501d3a09aa7a38f606ab7e58a4d9aa456a125c502b9f5c0963b71348d71fd0db9aa7f9d4e6acf245a77c7701d4a5f58b876b154ba44cc2988024d81aa882b7babb80f0dde1b3468e9e575265c35d979910b8aa2cbd639db98268d9c58efcd12f9cb0ce2d13019866741b2efd0410d0129a6d06f0e95065ba7c41bddb6f1ede6e61a3016f9a5b53a7ceaa7f5d3b653c8603a50581e99c98e4d6bebbc914ed675efd060a8d9e8d796d1d5de0714014dcfd489a4810296092ead5009643fc93579e089fe2cf5e09889001714b12b550a4d7a85fb3538c58526f00075b2de37f4fae993c2493725911cef68cfeae49705844e16614944a9cb5e45784da4d1d4ac73b62340c175813aea49d1052f81cd7e2dcbb00f38473075d238bfe5dfd4f44863ddb2680e3859bdeb94044a4c469e55823d9502df43adbb60868d8240ec0bfc8f617a81e8d967710cb5971ad55b1069efe4b066c2e6efe4aaeccf786e5fe01f43a66ee8a2d0e6f360bf3fd8f98253d487c3f413a60945b6294b38eb9e67aa7fff203bce2f8e88e3530615ea44d8b058c92e4724821159e83baef0c17bb7bce9503bdc217758e2013b76028fde49121a4e9fa9219a9bd340a6feae9d0b4ced850f82d73f029e8fadb622e6b21e6829288054dd1e7bf5239f5750d97fbafba6753ca1fad8c2091a6a822f156e9d1667490fa0e6bd2668003f23382c651334882400adc52dae8bc4162cfabffb71dd89f3ffce25086455eca92ddfa2186fc8ab9cafb260e9a553125ec7636b0132f2cf4adc66f2d9f23d5bd4d2e36b1338bc103b59733f745e5d8f90d99bb04ac330224b9d609f695cc0aa93cd7c358c79d579f4f556bfc0bb42134ecf82876dfcbe22f487fe19cfa59457a3d3eb9846a99345ecdba7ab4e962456ccc1dad26baf9717e9982578296befd71d046eff05ddaed84cffb8d7b40cc264e59e43ceeafcb26c5bfaa5f0771d6e50b2874cfbc4a42bbd1866d19bf069ef65aed77952414de74096796388b2b2646a570dd6cdfffba2ea2531b8048d1d7a6cdeb53acb96be25d3206a8829b4ac683dafaa3aafb91778ef900eb3635afdb7a9ccda84a711c21018317cfca7101f35d34bdfe7d20198a3b7909c1dcd40d6e83043c246841b989166e85b77dfc849420da0a509256ea5dbc8ed088a73309df5a1340accc50f56fad29e37f3703a5116e6167b337d5a6787f2bb976055e124ada49fe0782836943b7013c026828c8566c75cdc55becbcd2011f10c110b0c388b0fe683b1eec3e8ebc2b3dddff465a8c13aa5b40222ffc0beb32edc9c6c80f08d93cf3209d4bb1b34279319526f186e0250536a3e8a5361fb034122d70e3d0a9bd4d3c62452aaf55d0c86648eb8a9324138f3b83e7b6e77b9ee70239e1b1c81c953f53a5524e0033b51a840caf171584137d46111fdf4e5041f560d2bb715c3f8a0892f4d65d65a7dc8e5130d444bdfd5af8c657eb7c6705950c9be7013bec799aaaae7b081b9f88f8d50cd92ec4d57ea980b5722c71cad6c75aef5fb2ce6c38c9ef53b580c49406e0dc4a85438651e79760670061b94a33cbeee90ad92954544e9c63086571980adc9072e54ffda0377e9771bc212734ba71ccfe5d433eda4909dd806c669283ae08ff35f4a6f768aa4aaf4e7fdd4d5614585d1269a3486971376db161df03118d02b0da31ed2e6fca2904a4b4be9f6578a7ef4545a2534923e4b3864a27612501fbc35e76bbeebe8488b222c99cc508db29d48aa335b4d2a0974f948c3207c92eec89716239dc6ec857776ac61ebe485c29e64ed8d1bf0acb547515c79a3dacb2316dcb5979d23df154e1fafa827f9011e43c5323478f9f48a89913bedbe4dc9b0c8535f8e82fe64179cd74d7fb37d7ad587b65af57b3784810c7b6ee412b6eaf5d1500082fc208a921bf94ae5329016645967c568874abb19a3ee9f752e7b17f35d49b73a66b62e5c41fe0f0683824123e3f0b6b5d3a9b47d2b5eae10913b08cb4370c754d769d6cfb4e4f30fabb38dcf243009bb8f36b6e2e086d70d3286b5633c23559190a5b0107c85474e9e3e87c7110271705e6944dfb232d6a9624d114baa3fa91108d3ba429381aacc0ca9ff188dde3c8836565b4d858fd0cf99c1f14dbf563128d0525c67b1e8014f1a88511d16cbd41046f2c13fc972797b65f3a8ab4407f317b64f4a458b7bd778349d602becad67df6d15793878f4403e1af6f4f54509a85e32e72eab2cedac74da77031908b3f358ff750140ed750267cdcc7e32e8ed32e461bf0aa7d8173e20f4352719a9297f1811e05f691421141eb7fb9d1997b596c629f89b96c08abd77f12f0ad8e76122a17c707e159f590ffec5947392d76ccb5ffb6d4311baa6a00957d185df86166a58ecd9956606ee147229ab58c3664d4c4a260a04558de5442afca4f1301bfea71b327238061f69f78f6154f684f590475bdcc6748775c3275023092f1347eac859b0073bc94e9722aeb4435d816778aba600b33ccc86d7ff502ffd3b5e5228294337c32c0b8aaf95a82cd920e095d0fbf93707be62fe12a27ab2f6c9fb07207787af7c50a4f61e1d860a510726125b0fccc8420ac41897d90f6a8790e984cb9f89e3ab1885e2ccbb3b17253f35336f423e7e04f31305330f27fac32b056117db89ddaa2a0657054e9ad0853ae6f62aedf30196f9b94152c7f7bbf88a83f2f58fe5cdb0d75f56e6050fca4047ad11042e0fd4b2951da3892b66a7674be99d1e82debd98493d80d857d943def54e7acfe405d2672f582bb64924c25495f2dc338735ae0d2b159fc52b26364375630c72cca71bda7b01dfabf4822037ee44f95e934321d853a87bcef2963382b6de64082ab9b3a0c91433c1a87a45c6290a804a34fce3b86e761c58896d0c9f3708661cc61aac282619cd96c60713dffbec7b357fdf51279d50365e008eed72c32f34003b2fc76089238d434d5d912135a553f543b6befec4f7a9496c90ba236eafc7953f4a081de67e2dc549ff15c7734bf12b184670d0424bf20f53662983749aa91a65651d899fb4858abc55282552d22be27f697a7d89cf548591d7d5e7a16a2211c8ff09792e81a9c9042e58a5e76ee678580d3680840465a10692d45ce84faf5cd7fcc9aca49aceee374814110abdda662f4955d99bb27ad310d47e6fb735ce5008fa374d72924f707dff39233bd4109839c3bc61054f7e6715d27e55bcc3464c5c31d109102b95480a0a77e69a2e2cec60c0ce5b0511e8b54445c6eb2086aaa9f47a7130b28fea6fbe2fc26d68fe52d14193d4498f5164f652e8c0259f34956331526acda2611357cc259835351b250137ae3ed44a0d2d25796a8c0cd5d84a0753444509fc0682ea0aa232f6937054864493acf2317c626d36bf13251a92fdae72e7a184e32745343d2b968f2497e79d859059ce132bd898a84c989e5687537caddd4d2f8206e5e10f2f44ee6864baf71ed219c294a7373c5730323b19893b9fdbcb6137d0a5045c3be8bf837c6f5747ab0d91d8db1f17fdee9860e3123fec121148266e8579570bde602ef156ae16ad75fbb31db0e451e06299924ccf2963f600756a47ffe688ad700ce4e1bff02f37f9029a799fc53133b1df2841622981cbe9a1e2753e0db6ecc35fc2beebce4a28c47f6f1ad4bd972befc6fd606f83dc4d319b4935c65709e1e16e97c893ae007634b0883bc2b8a4e2174bcf6bd485c47b9c96c0b11939c4f5edd3db999124d46a4ce4c2564a535406430aa679b2f850272dda5b282b3f9a2431470765e00eec90b310800ee317c2a6aae192552b9e85adafddc556458b6bd5b5e76e770998a2a29b1fdbb37b2f57aba1360f912273134e540ee68c097b8f11275c30171ffa1875a8aaa45106758429061c20330a80f1928c2a9d16e33ded189ac103fb021ffdde726e9eeea1e03a3fdd9f34d9e52b4c5be2d3855e9b60150f7acc909a5d011a3f98cade7eb101abe935372bc81f4b5f18c806de51ebec0a8e032c0e4bdbdbf56429aa1996ede1bd98c7263896f81471f41cbff7311b17b42905d802a6460668a773ee1ef426785f866318f129e2cea728a7f127cd0433879f48812f5ab56fafd270b2cd5186f199d3b875ff5c3c20983e4acd2e8fdeddbb3ca68021bcbb9f9f31b3aa4a07d365b1c72e6b7096241e07e441a5e5314afff8b6285f04eedd74eeb20a41b329dc448ccb8161244711b34982dfd42f66da04e132757c16e54bbfa0d479ff8983eedddefca29a53c588db5e6d0f1e5f4a3f51f766dc3076ef722885844d8655301de79a24b484e1759708f1ebf2716b9688314217b5874bd64d2204efa872283ba9c47d85a0ceb5e5e1fa1cd2eff888a74c10a6a3075fcfae2353154cedb9418f9937a06b02c198e608017895a02c65039195e4c91b2dafefc1e238c069d887d450ef3cb2f786f59bb2e9e4caf743382d7aa665b8b32f484dd44fc9000f86ca3ef57c6a39ba31790f3e12c402d1e3a09a892923e3cef063ea8c29559fb2f3dbd6a4e019f037ed89475dbd825962f360e396646f8ffa00c479f9e8460127b728c543117dce38ae17cfb36b109110cf44f2a712b6cc6b2220db93ca7ef58b5fa163559d10d80aea598afc1221290237172692b418ce4267824dbd237ed2143de7a9d73125f8c682a2a2fd42d537bf8fea48336aa508247814875ad24c541386133d8fcbf28ebd0451a67e7d69ef9018609dc09a4f36dc93953006a82c39d601022bc425dedc2edd6bebabe78fd8ba17ae2b3c4fd657e6b9fbc887e5ad442326cc872075cd960b615fb36b18d140735830da257a4d42f2732d501b21cc883d8beb61ea72961864affff658129f91a59bfaf9dd38ae0cc92c7d8f68d531cdd5e06fd115ed9b4e3b24350882c3914c5f8d2df77e8bf615c6d7427665e395cb5487e13c8df9d3935a8431d95d02a26373dbe4f66a71b31100516596175b17fc6d0fa0c5f0d20bb121ec8fd43567721ffe0e1fdc38d20cf3adcf5004784edbcfadbf60d0d1703012ffcdf918b091a4d2807d896aa463a8f037dddbc01024fa34fbb93a06fd3ea23bacab8fb53937425fa14d6b819d50f91a4cc75689e05e988b8dda6ca89a78acd8eb68457c6dfed5f08aff4523f4695e79c315390f829f1241eb78d6f618c6508e15d3cb6ef70f0c4fcb69ca0e90e1186caa9de5b0553729af8c795db4578e061748fc25851e607dcaffd274e3a6e2d561ca4a55684065e1cacbdb5cd75fadd71ce5bc107365e6fb9dbf778248261613d49c36d1dd1b3403580ff4e6494291690c4508a8defac836876a25a4e9054ecad77937cf9df6f22282ed5f0a7778b4affcaf09f103464864c8c1fcbae97d9e4db03750213eb0a78475b45caef4a477f1c73dc8f9e39dd7d4dd50396007fc0470736574056302000385eaed68d747a689f194dd86d5da452bf2f327d795d5d504e1a59b038ec702d9ad78f74c269b6c97c8b2b6496bafcf9790dc9c608304da86ca5edaafbd62dc960bfe5c8bf1b4833e5b5177e26bb83bbd28415ff617db4e3c3c33b03f10427bbb07fc04707365740721027fa518c54bb326d5ce3da5c2eb8a6521ab99df86b511477d0f5ebcd616f063ac0007fc04707365740121090b81ada05aaa354e5c62732358c8a2395dd9576631d9377844935cac78d3b4e807fc047073657403210bc57b6abf30fcb84f8660771267bb93a6e72de69165ecc9e462d6fff5153d6296010422002058037c2d81d3122185c8704d4276e2629122c95b8ea68575c451628d37eea84507fc047073657404fd4e10603300000000000000017823c100e4cb4ea3cd1380fc7986f67a937b71320ac40fcbbcd3fbd3f37dfbb8c4ac0eecc7c8b91d14c7148d2e162d1c4dea595dd8dfb80c0e064b926ef679d2eae0973773f44dcf8cbe7a6e53035366c0c9131cf991bf8eedd5a759ed33baa868e6e3849c93c40bbfdd6d485ce31941d09f9ca07c7d3a3b724760e637191c5344fc7812976c541de2005ef96fc57d8645bfe6e9cf5824a0e084df078006f11dc485c39ee1d196d793a544d458358e4d949c5449a63875196328fda3b29ee227add62fc36f3898512ff596272ea40d79f376a890c806fcbb33d8e7d1552e9aa3dd14420342039157cb991401faf3dcbadace85d5d093ef744462079028c9e68c9aa48b921be8f809b950517af97da5d0e994d1c68a1a9969972a541e3111b0710e552ab40927c165192e263fd00af1b1f0d7eacaef63c52852336c0293b0d0a381b0cd90864240dbb2f6cb61c7149f432a11f62080f7d47d9a04b854b4490eb7a53b4fe33e146db108d235f6b164d22a4a9cab38f5501f4e2bff1963a327f757b8df26d2f65d2d1b933fe6cf8d12c4c7cd8c2f5dd7a69c989516e729b52b6688a4c29333f21a84247e52b152c455d45f582fca280bf818f7c0d8967a43b5d38465922e4de8d2eff49971d28980793eb41a5885cdb4f32e528edf4de6939239ff1c678160b51a1fc5d6e83f3c6cbab2aa88d3e1ab8911779026ede67a6a7b85a57b8a09665150e0cbc3dc615e1d5e39279c2eb24c80423b0568b481b5a37fac1d88b8f686b149c9404b399148aac35515150fbccb29018ddef5c9d219231672ba884020e50ef3e11e29a50a3677fbb427174e2730b1a5293ba9d2f448ae6070294a59de9f0a174273d580af7c87c07acb27962588de2d69c9adf01ab86065f180daef68c9e3399aeb1c290622412484bc88d182ebd19833e6476e24a70a0d1964e61a9258346fa8237b9940612ddb90d91779c5ca2e294679d0ca15367b5db571b81fa0c7e9871147ce9d2729dc3168296d13ee2dbde145ad9bcfb0e24e2542c8a2e06424c5ccf3beb23be0b57acee847f579c1d548306e6fb2fd7bc42c529415002b292d9ce82883d627625a76299f3d055a031be110bcadb95eadffbc6a5a14c97d1a6169dd3ca058e0ee997cefd94f2595e39c06ebebd2862edf7242adabc9716c28555f5ac93ee2609d75c4a852d788eff783c3bcac47b8f7330d2359f004879df8a475ba381c32379d3787761fbbba34a8e9a59fe736bc489562e2ddf71bc9cddf3ee0015857939b6d1af58d3a7fdabd925c8b2e724f0b6a80e7c5c1e7d04bfcb8cc44ecc172f3c18cd73d226f62f4a1fbab7cc6367088f61ec3e562989e01ebba29f8b7f6a94c0c7b32fdcabfc2dbe4ecf404f5fc7d5f05d8694f95c735849ad1e32a44810da350c4cf08c61d8693f468578d09fdb924278add9d261daba0ed187210f239bb4a97763313f2e006ddc202d4550412f68c5be848e1d34a55cce1b894ebc9dce7e9cc16859d940bfad3dd848afb99e2868a92b1d9da7a022ea7405abd42a79995f7351627ced6250f5fcd4f0d179e0101ada67ee8f96e4bd0d7afc1da123616d7a588e07ba84fe948c8ce1e7b51f88d8be970a706c9175d9e46c23388cfff0609533283ab8d2282487f0181d45274ace8a92a8a0eff3d52aba9732a64d787d0effeaa58d03c9df620a43afd2de9607783069ba61e2c583b576150baf140ee48468afe18ffd9da3eecca84b0aa3b7a7af17ef69d77d6f0d99f0e83d9a30652b3487aba49537381ae0afc2885c70ed1fae6dc5cca933d92b8c089bae4855477584e32331623c0369f500d4b36d62d15a81a4d7c197584aa30db415d9197d9cb7ef641cac840a023fdee46c66e3176bae974cdd58ab5ae2c7346390dc696a2208ca7a18c8cf671962791f4e827420e6ceb6cbb58b07054a2355dcd30c2edb64f536860515d515521031f63f9c2a8442694746e9b4ebbf5b85afd96d4e6c25a50013e363681f229645455892f1a1cb8b2a8073a925ecc3832c339d97e9249a8bdd695616cb2818a26bebef23bc94a58a411be30683bcd16a4b6472ba04fc401ecb59f0486dc5b01ac1e0ae57a132c768e4c7fe27dc9b4c422fa647953ba9bec22cf8ad5669c913e0731b03468ebd6009c14283fa1f195fc6636eb30e12cde2c263ae984980a3cd8aacf424e0ebb68c4e9521e2b61c2b39d7ede48d7e98837c7d840455a5525b98f7bf79fd6258059e4e6925db4577eb62b5263d91b7f17a24d3b0ac1163e42d9c367a363034b5c03062c4706885770a5fe3af5ed1ec6e2fa2d3ef23a33acd2fbc30bf436999be36ec7cc9cde96a96bc34d0e0edee7b0ad98a35d8bb1699312d3c1b4966003a054a9bebd8815ca947205fcbfc3dd2c6240a6b911ded609d2c2cbef2fb151d80305615d60ce8fbf4089946780d10523ac165ea7bc38c3a2e6bf800b38d47ca603dcb20bd4dfb40d0c02cf2f3d2727e8995203296b06f2c353f327b2ec1d9503b1060b57144ca9b648c1c87ae982e38ebdd961e3beef4e198eefb1b944f79cc136d38ba449e9800cd2897a2f0e15856883a839fa7f89220c02703f704d1761d8391a183a98e6fc0d9bea48440eed02c84e5e4b70c202c2dfea04047085763766e28e3d4b174ccb7727b05d74c55f7a91de3599834697ba0ce4692a14f966c53fb735109e20599741df2a6ed21d67076dc078b8e565f3afd95e7762bdc3d9818cd69109f59c45aff6088ce3a5ecadf3ba2e10960b115d39d02b559b16488fc7b8a23cbe534311baf5731576c5ed93bfb838edfe4c7c2eeddc2405e8cc4c741f1e6e562592be7f95ecbc26251edbec6b35581738b44673e8295494f804e6ecae2b23527946956f68546fe01b38ff1fd0e8f3090916a0e421d804da219bdac63410d62749b429f82c9c2463c52aa29aa3dc0359051cb5666c6be81a5e7bb85f62be8ec4dd10f2948f82ec66ef4e0471fef64efa4cce7232923b19c72862c674250316448e201abb5fddf248a747689daf8f04343f1e695d3fd045f5e32e98462c0d65d0ff4d751c03826ce02c7513c3c56776325d4566afcf780876ce17fea8450e48d8a36f22879d83014dc6fb7e7ec0ea5fe309723862bb5e2cc1a4899e18583c8ceae1246ba8f12b357dbd91e51718486777b192ac97de65a35a40655b25426a30373278e897a2b99658ad27277ed32e7eac3b7c5d5c775110b5327dac2f3d92125ab3b3bcbc383afd93e795764bf2632c7b4c98876c95e41b7c3fe2952db073cd4ad219ab3aa5d0901cd53b8acd8e2fd92f93d7e5ff0eb5ad97a2240764fc40e8683a1cc28484fb3b1027059a53ffa5552406e9bd7c3d28dc0b081a37cd5a13af22288d39975018984c084cadfaf5ae4c91d8b00a6466ab7cd50f1f143f11ce8ecaf39809a3c4833b5e11945564f1f0d025a07427100e60bc40e065bfe938246b3345fa8fa4a8ee9bb50a5152c90f43d239401ef79894b5f2db6e8f2e98663d6497dabd94f13d9cec86bd2707cf32df56f5a6693ffe9be7ec362c0bc03b6816269dd2b72f5638209dbc1afc97eed232f2916f19d4ccabc55a6cc0a48ebdcbd59ce0404ebb47740a0d802f057116714ddab4aa3bcb5d8ca20069af51e09f941b9efd73e8515aed1db7ba79137146e5c14262dff94a885cfdf435d60d91bf2f508c110106fe4a0eb4c32ca382825ca6a65aa2749a224a62d8a1dbdffc5b53bb4cf2315e9d107a73721cb3ddd111c723cacecbc219ae5c850beae3b3b6a5577222af1706a625965b7c7c7f13f01cbfa9c6f1cf406fd177433b9ad4213fdb30abe01cbe931cde34de1650e69d348d25b6128a26ff8b0a73947399b4162bb6513043167a3871960f0dcd5dce5b6ad680ec782ca48515010244d5692ce8e6a56c291c3512e7ef91680769be39530839adb5a8898d83834d398e63ebb2ad00d42d414233a070dd6bbdd6093c96eb8478953fb04c3e82a7c84a798d7bde36547bdf4486e8bb3a6fddcd9d7ae1b007e61e4da3b85ea327c1ab8f40a66b36190eb3bee753bf1043335ce82cb31751b7e89b84fa9ccec5427b28c161512a963f80bdc72c38fae1b32b4d7900f983b51f42144a82514b535d71f3dc80c0b28f49c20b346d344ed9c81b556ddc49263ddc687e64daa55d659d0a806709a62065e1eb1c694a6e46f6c8b10bd47e76664c42b9d992c23999ce516a5cb6d68a4748957c63b2db6939b86adad8fcdcfb5bb643b08e156d61e5bc4c5810802d5afc1c0e3b160b01d6e5675e5172253d1d943b96a6a6c940925a4f6850612b8c57ddca11e893fcb5e5e791a6749f75969b49c684aca0399bb322b9a72997e204b649c3d26f726ea0a49920ebf4b533bd4b38e1cba3a2422e37c3e259dddd8ec10afce3f1baf2bee470eb752c5721aa49a3b8b4bee25a9f6aa626ade570864246ca2a5c6f0d183ab2d909ebc336db2126a4fd24de704befbd2f07c7cd6c0169a07777e5a583fd3a9a9ff1241fea91c504fd5e4d6c6e636a9a5c3fa56824e74c68c1ebb8c4afa90ff2364acfd4547fff73f94f133d63bef1ddae0a8a338ee8e50777d1b7907f4871bc4efaf746ec2c7b9fadd717bec888026e32e5e26bb0101a269816b9046c29a42b35ee15e203fa26d321fe03f042a8f21cbd62e1bb0bb371d00e46492bd655d0261129393c023d20ce9ddf0f0687820e563d3688cf1e7946a0cdf09737c3715dfa8a6777bf94ddd2d127bb5ad942dd07738eac8b6955019799ce77cc42136dc9aa822470ac56efcd359bf180e95f3fb312cd0ba9ee9bab99560d0b41ea7831bebcf20f27e17303208ef66d5c0f82d26d8093f002418267115e10331646fd87ba1f1a42f72fb45d2a4a4e4353698863e65a7cd4f6f3cd0dea28dbaf5794de216afe202b679899518a3dee9d4024afa3dc9d8d4eaf0179b05ceb22d1e60bd941d44c3866362a92a7951d9de36e4e7d1a681fb2d9420e0fbffe795e9683857846ae0e834d818f990e575a7fa7efe7638fad98fc5b680abbb58cb8da78d783a7ca16fb7521b4be25d4fded9417cc7fd9525c79df7e52bb83894dd905794282a7413bca79bb653afce07cc433e49ffc38d16b7be05c1c9ad05988ed672e1b4dcac2a5d211d7ad1b790e4ec0761533925f528a21305b942e0dd10efdb99bf1fd6d6b906ea0d21ea7bcbb4116490d97246458fe29644f149122586b6f16df620ab1480b55f27f3e8bf32c2c094bece34cce03c20b5a2d2b73481c7cefe4bf56dc76c7970dd77673e4383f62998b6923f103eb0e5c1ce91e43da83495961460b677c261a027db4ca979597a8232691c3ece94456e313ca57f8c2021334cd4e0735453597d516dcf6e04d386ac61bcee073f7520d205fb1ec6c35c6c96511e8a067ce5ba3d701beacde937c925b204ea011521b3e1219650568ff9dda90e043c9d20224fd767670586812a41ad83208f5d62f7892b22500be3ab2028207f738c21301e1aeab23d1bd4e46d46f2ec1991683e987d3d834bc260113372e3eadbf825f86d42f463795050f5821a6afadfe42cc1cad6fe942d16af7e35dd08004ef676558ecc8801c45d37a8c147102e120ecb7c965a2e33ddab0a43133692de2133cc64e655961e66caff271e0625c469a24baf126ea7d300bac5f0335dd5926e99394d45280cd6e14e7c3d5be3b3745b617d9f7e01f0bbe15a0512e2501bb7361a17c62f4549df0e765cf8a2556a9d1827ccf22c75680db0d7391da9f0c18926bb90423c7e084f4fa11cf05914bddbb8359684dd920db82bff035702f2484621ea1d71d2589a3d5db2a876d78b2228a1b4b7b9ccc8c4ed6f5df7010771ed118f96bda339ed2025808099333224f99f207e3e808312f49cdad7e0007fc0470736574056302000381eb5d013a1bbdfc28e27c272822893a4b674355a29a306afa132cf3fe9dc2955ab2375883d5f7e42ada61971ea91f8af2f106402c5592e676a32e3313d03af9eba6e1185d722a0b726da16714e13cd416c8e99f1b7f0aa44b721c483fdf593b07fc047073657407210302e71fc2fff37aeb6d2e2a7b7f2308d4ab7d4bf0a4cf9be7c06e89a66442b48300010308f40100000000000007fc04707365740220230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b20104000007fc0470736574012109870d0ad593316a7ff67dee90f2c2d8e305cfcdc4619fe0922c706560eac5d8f507fc047073657403210b9991881df2ec384ff5616f6c03d45cf033ee64536297c3557f9fffec716c1fbe0104220020cd4ed5f0db8c450e8b0be595b6410c1759c19f1f6926279095c83dade9862b6d07fc047073657404fd4e10603300000000000000017d32a9010e698107419c4e5b47c05ec25624ea0d6f432f75b744a15b8f8381b5fec29c0b55b8eb600b91a3e13c0e56e601c23882ffd62fc218b1da72e2ad732a47f7279d32cbb24eda0caaeaca8d8fe4bc920e0baa6821b47f7790416a5bdf13d691c51914358a431dbb2e9154bc01da79483cc9617f4d57a6f4d2d1380ea2450c292ada85eb663a23c76a6adc0c7abf8ff71b41a56478b66003ba839295df69edeaccc54a9b3803c9d3eda9cd47e478fd852a316802c8def8014a449cb886d0fcb5d56086e8742a346b983657f331330f6e8ec4bf72b314cc6d69bd94be0bb6e6896ec01f773c1a4c329e7ddbf326b83780ab22da08a144fc1c8dfda604cc1b2858682ad3decb097c1ae3e992596ae997422c7d381d8d9354be1658c43e5d5c1e49f0e7263aee9093c018b09ef44ca7adf853c625187a8ed252527b94a5bd70e13c30b22f05038404d99c18c0cd76a461ad7dc4ba63d132101ee471bfac835eabe0f11487ab7361e337f5ca8dca3cfb25de4958c58d59df6ea016a9436856a3af505884a4e38d9cc1ac955c40228c22ffe385dd48b3f1c27d40e7794ce62822645b2a2e42346f9771f2744fdf5064309f9f7f84747131369ee9b5421a07d24ec6e7baeaf1c99cf8339f38e44b0864ef46684815c320df48159f83aa80e247d617acf1b1c7a2da56cb3725811ef028987573f59c90587f88553fc6a11723fa5e45424de05d2b0f548dff87a8e1b094a929f695f01b7a127b522ba2a6d6290991d0985af8059f002f514f5027fe98d292fc85f050d5a19189a27344f83f737ccf254c97728054ed01e1d229f65b2b9d66a7c82116bf26ecfc026446cee24c5603e0bf0df9875461623340a7148de14a058f1a37e8c627bac2acfa2aa1de65d1349e7d02d565852af1de756203d2aac22330c43b12f1e1889c8ff2959b1c11e85b2a1f577b47e1242db2b1bb4cb03979ab255353bd91a728a67827a86899ab68b3ecb64e2303c6c701c1ba3aa09740264a42194277fde906dd6caab566c089fc83fb9ad4528d50c48d72d8a68e8bdfa846284979e7201f41d225b2a782ae77cccef12da93d2c2e73f5df35f75102fd7bae8c5c2c92e79236f687b8559b7d625658f6121101ff205dfed8356fd447c9670330b3f197c3249b05dc72f943f1760489dbb1bd53b2bbe65ba8ed7c880ecf97a1cdb9e78551c978201aed0c1e6202d2bf807df2334bac733ae2cec1af8a409cb8b32830fa0696c18ad11d99c3cd0de7136b83d903d955acb584117e4ce39958d75d6e1ed790e4f5613fcae6a827078a45676afb7fa82f0642d37c273e2378e58403ca9542d542d6ae549752bb9a85cb1c5d71819cf8985c5fe52e6de0c75c61a2d4b597014009e2bbfa7a44085bc75af6adf6de4d0f1e5fa8dd68d5e13e7b10710d9ae67838a775b17370a052c019ee984e169235a2a1a20e7a157d0e3c93f477907e48f018780e0300b9c1cdea826a81d9900547b7fb7e133d5dea37482e40d27d3feeea57a07dc795737af5f01286ab37003c7dbd8e335978639704333af1988feea17da0af7606f5cad04660495009788afd99412e036db5c9c9fb0c643873fd0a301d7c37975f6b54906d3cd992c7c435b334f695c1f87ef071a58b890b2dc2771c2bec4ffcb9c121feec068ff0cf4924ca1b3cc10b802558f05d7cc2970c3b0df9cb7ddbc306269dc42d8dd882943182cf092d6007248288822d6ee80bfd24f4077f1f662cd3c0f577f831df25cc20d2c1541c44df2cd07586f4efa26e0c208430889dcd4e548be9adba2def0cd048b57d73ecee8e3005181e73d4d12bf11d225a234cb3019c0cbebd0d9c2f3bea6832eeff2109d8843ee61e682098250641df7bbe21c72c7831c215e0234d71cedd22b2370ef3d574f321c6d45607175ad9568dc06520f33d2b15ef2bfb0fe9e48bc01560dcdd73b6fcba2caeeafaab2646f7b46e9d1c3c992afb18b7c2d9d2f88095c1033bbbb9449ec6467da2e302aea9979b28fcce685878619a8d8757451d5b80d4e57a3a213a599b467703c5f96297ee6ce44fc06b1afbe411f1a665ad0745bd7fd2a5b49ceef6b468817f500479af2a8f6c0e3557eb98df51a4df26fcd5cfcdda48e5441114c24573bcca96356d3c99d01eb8f8a7ab397d6c8a54dd9abde6d16cac1ff2ce86095ffee79a304355df03d72f2d332b50898ae06a775f5f7fcef3784c152f51b8ddf9cfea4f0bd271eb98ebca53529f103228aedbf64f03966c5bc2e774c980cd13db22f3c3f6136b6b03ca6cef7a4f310b57dbbe9431946d784fea7eef3258f10a7bd5dca55102bfa49c04fd117a8c521a5b691249e994b8e935bbfd1b86b5512a56ac222e989f04dd07c34a5219dcd5ab003ab118ad40746ec25bcc056b35afc35b656895bddb4d368623e17a61f3803213c1f122d8e6281d013df14fba919209fc2e4bc538021e5d5ca8a1a751859f908f47b39f1a3112611a3e19264513a7301e68979bf0221f1cb418f9cafb7b81db4ebf08e0c7a1b57da5cfe8e32ad16b0c2fbe9b5f7ffa5c80aa3217b082e4f6c9f51cb79fbe27ba459e09b01b3fdef45edb5d1b063fc99937a822a5a43803b610a3081b67f7279e18481754f3802753c5201a60e4fd89e0947616a33ed4218d8e708ed81fec6e3f39d7a94378d92fd6d8d64769bcbd4cc1d66cdf4ada5b189e03461b583dc88f2972c6e4904afc3b49b38818be26f83c94cff7ed4c826917f3314a931b92d65e562014cd9a1a68ea79fafceddd09b8b0e48eeac86e6190e470ebe8ec5cee12948942f80de6a40dc2c657b6ade6a2ab4b3297ec713bc3cebcf91f8465a14e9d9d5325fed40d2a2af8bd0731d9b626095653e5fd292cd5de3a7831c0ae81292630409ab755fceaedc4e76e78b829219209476b94d0c6224930bd6c7d4a6b06ac9699be79caca17b1a7c9254f1b884a87e44de4ce5b15f312b09210d09436a8bc1ee39b6e5f96ba5b620d614a09259b251910219ae39d65c2650e2d2a27cc0d2dbd5e2aa40b5b4bc4ead5ed531d7f206a4bfbfabb96785b768aac21ab8f11f927d54949ec3c595f31391bea8b4f1a63db49e26d875be2cd4333eb5785ab1cfe7f83c6e4a445702f9178343e039a7651b62acd31d694db89287c1ec5a636933a630b3465d27015e564bd2a4848d0910739702debb3d9c7c133c2a2f5c6d93000ae74bffd2af4ec66180e7219ad8af293ec89fdbb0d43d6b9dc5fd539c338136436ef1ce088af4590f47af91d78338c67b03500d4c69de61b44e09a776399d7cc349c95752405f65b0ec19a14434d715aa11a14c5be94d42114c546af8c02d291b3d54471ae463d249237fe3bd18f7afc569c43e1c1cd284538e48444f39e8c83d9d52f7754c04a6198711f8ebdfbf647002ddb54ca3c8833a3a21e0bd7a8cfa1274f61a36183fcd63670f1f5b425f2d06ce8338410baa860faf2331ef93f781d1fcf10c38b2be7ca21cb27430147466867d233acbe6f7ff46136ef736a1a1b5af97cb871a8351d7774bbcf0f0f47ef10c7a5b26f0a25d403fc7cf2e7bb57a1f16c68260092523c82ea020f0df2660faf2f6d85e695cb672857bc9fd4f7ea0b93f735007d9ad15e661329a22bc465f6c65f442f5be91c665f3d7311290b47fb7c10342a5a367ee18dacfc51a83ad0bba7503b54a27545abe372078505062f4b859947168b46638f3a4ebd116fdaea1d96238c4cdae5882f326287da8e94dfbcf9c82f92ec94ec8706dc6ce194fcf7890e047e106aa387173662ac2ff1302627f80c567fc7e74d36473bb601681bfc1b5221e15863bb9f8d5e30bef41ba5839349a677e35d30e0000596691b2bde87e386998e3e2a463aea434ad9002438375ef1071afe9bc5027cec29b5cca4196b2b34b8f92cfba033a9e2539aeee306c5acb88f22c7799bd7208853a735d317df6c957108c6c10c53e9e1055f6108369aa4918dabfaffa446c40b20c73216e976a9fe03cd157ee29efc03e6a8df077a5222008e37f257816703e1b9e214ebda174ed7b4aa1b5e0494f5285704ff6ee22fc1f386dae624b72a7e24d2a56c97a8d8b816ceddc68119c279a2654f19d3d76cd314e9fb6218b9682455f81c7064e33295060dd0b91b958dc04599a5713795c39b51744b5629512a9028a38de8f674214de7bd4845e53244705e431526fb28b8c51b3bfde0202c50187f6748581d5faccee866d0c317345ff6b65b954ed479750d0a052e3fe3f557c88f4964cd95826a7be6da14b54d4c00dbf9b2392aab6d084262427f24d163ce590b8d36547ed8139bd241b8f18d9d9c32850a29473820f68e9197f97e7d54ec76bfebe6fc3006b3c7aaf370416d758fe4426758fb8720bb764b6cd1aa174a58d42361ca8c2396079a634bea9e492a7e1fa5d443a2299c66ae23a064d6e70c605019527f1b499a614c28d3c8cdfee753abb9b1a5b8d9bfde29a5ea869ab95a1c7c1c076f933938008060800636f357a48862bedfd89a70ab30ba31919bdf6b53edd085b3836657a4bb214cebd2dfae4030d19fb9473e046ce6ec39871150a4f0ea03e3513c5615bb50135678d024e69eb754bbdda896eb0f2d39a1f7671231ab6887902faa3adc79cb77d122e184031f7e3a9cc222b3e9788dd9c417cada21fb6bac493b15fc306d64cb701dac8534cda58bd37121adebe474ddfffa1afd26a999b41280b043992b5b7fd6f4926b5b6994a621fca3d13ead3142d8c255d80c33a86ee4d6ef04289a23f0d39f7b73c30ba59005ff0f1eef21f9ec01e703aafc1171a4d24d8257917b239c5c3b447549cb2c9602188fea59024d6def3b37e26789c2fdd90beaeb30790afcde5cb8179770cd3194d5ddeae7eebad7b273c7c53eb184f17b3934f4d0cfbddd9f8e9b135ad4fffa8b5edb04e2fd34e21f29717f3f2b9c01c0a547b3e522041bc5a0c647d7c8eb543b94856a40ad9c4d2ebe94a3de31b810fa99aa4b19a9a0ee51abd355b3c556f26dec3405b19d5a5da8a6c8e263c8e2e97514053a7c57097cde1649bd6c77fe78ffb96ffc69cd43fea598e611ff55a0a306883b01a44ecdba59e103626f4a08e3444868d27e737ad41f3c2564b593ed169036a7c4b883594bcd141847f22c1933e04fbbfedf71d885c5cfe17769eb36b295950e9a420919d06110774029a42ceba64c6f3ec12404047e78f1c67178e65d1caa49894f8b606244a365744c8c826c682a756f560c1d4f71e1fd566547a8c070fd64eb2ba941e844f86af062e67bfecfeca33f0a69c186a5ad2242e100b0bbab31322cc9dcad523297d53f44c4ad8cbc2826bd2e1f211cf6fe29116f6c0bc5d37f7ac8376a574dba76dede5fc6e72e4853d4cbc0d302e20bc130578419d8730215172a470f98e9bc868c1f7511bcc353e879199d0b25a06cf49184808bdf76c165e91565d0b7328ade3b164d5bf1870ab9000a38389ae1de035eaa0ff3673f6b01ff8e7cc3358b1f6b068b93b47d26482f8d5317a109f1b5475a86dd46df188f6d857b2c753b2323e14b70cddc6c5ce19f67e955f085f47480b55a164ede57fb029f3f7af1e0c0bb569e52db150f69c8763308109cae4dbc2cb22b9d0bf5842f0d80b0c2120f20f7f0f80e77084791eedbbb50f573ef7f7ac12735c91fe2603053c00b66c310029f779f229b249ebf21e0a09c4629900e66c8d86957251d64784d84385ae863e45a33b9f651bae7d3028c5f0bf036dd45ae41a72e72e412520c29e559928bc3f4c6a608f8e22cff57e2b40636c0dd27ec8673a01ad04d4c773970b6678d9e117eb10a3e24faaf4ebebc45b13c9dcbf23567647056b1f7dd319018d2bee8a059c8f2d1740aec65eb54aef3709f1a5f680fbdd9fda390ea2807fc04707365740563020003810a02fdd12c3cba97447dd59111452581743c53880ed8fb161904e6b97c4ce83fac66328bf77cb920ba7d2d28790a9dcdaeacafba83a59a56315ba410acd64c6ebd7862608044814df5ad160befb4eccaaa7ef1e7cd45a26898ab87c6c3ad4d07fc047073657407210252a4b012198c2131d70498b5939c401c01eb1178dfd58123b55766b03f008f7b00");
        pset_rtt("70736574ff01020402000000010401020105010401fb04020000000001086b024730440220330e4801f9d385f6e7a59b1fbd782357d44578ee95b59cb4030bfbeab44e43c5022037cf1eb808ee08b3ff929caa631f58a689cdf15e1540c965358419ad3cf6337d012103f73515486481e116a5c2cb6fb4c5ee7a518523f878a1570b83e7989222d0236f010e208965573f41392a88d8bb106cf13a7bdc69f1ab914cd5e8de11235467b514e5a9010f04010000000001086b02473044022070679d770419120e2380c6611f7a78b21f64fe88f015646ced3b6cf5e843807402201360c9015b4867e7f771a2f6059dceee13295a3529bc6a56769a3902c32f6b3d0121032e7429173d6c0a555e9389dc90df48c5248af4b73384159c37d533a2aa79753a010e208965573f41392a88d8bb106cf13a7bdc69f1ab914cd5e8de11235467b514e5a9010f04000000000007fc0470736574012108378fd3af2f7af7009fcf06b5ecae126d5446b134c6763d0a2c103b61ec348c5007fc047073657403210a1862832b5a1ff4c222398ab482534c75decc4176450df7c78280b4dd90062da70104220020c731ad44c00a2928d508ad82b05868cb42733a5b0d0b208f483307ce8c328d9307fc047073657404fd4e1060330000000000000001e772fd0127f16a4db9c194d7a039b46117fb73586a2826f59597af6eceb7a1762ffd8a88d62d846f2f64698505c921ac735fd08d784e833d930c8127fd8e2439e1d4541db5170e5aba306fbaac4c28ee6a30ad6e12886418dac926f46113c8ed01d146a9ca2b98171b63bfa0629ea26d256e8c9f7d6d936945e568dbc707be87439b65cdbd9bafbd3da43475bef08dda59fe1a7f661626e23da0ed70e5b2901f5a34790ceadb3dfed265e003143993b2674fa12f2188d88a1ec03c6767028d774b495a132f89b9404ff9b9772b92f22a75f5af5c5f4ae3ed213881d247141fe061f96fd7d619a657238c960b52cfd836e1255469eb787f1472d19091473fd26dc86f6f7ed613ac985b2c1716ea53b2cefdd0facd69b8428336d516de195422cea82842270a8b20f9ebb44b9492243430943540c5a82c17e6ec53e3ccb386925d2675d03d9a157757c60aa611dbb43873e89d8501d3a09aa7a38f606ab7e58a4d9aa456a125c502b9f5c0963b71348d71fd0db9aa7f9d4e6acf245a77c7701d4a5f58b876b154ba44cc2988024d81aa882b7babb80f0dde1b3468e9e575265c35d979910b8aa2cbd639db98268d9c58efcd12f9cb0ce2d13019866741b2efd0410d0129a6d06f0e95065ba7c41bddb6f1ede6e61a3016f9a5b53a7ceaa7f5d3b653c8603a50581e99c98e4d6bebbc914ed675efd060a8d9e8d796d1d5de0714014dcfd489a4810296092ead5009643fc93579e089fe2cf5e09889001714b12b550a4d7a85fb3538c58526f00075b2de37f4fae993c2493725911cef68cfeae49705844e16614944a9cb5e45784da4d1d4ac73b62340c175813aea49d1052f81cd7e2dcbb00f38473075d238bfe5dfd4f44863ddb2680e3859bdeb94044a4c469e55823d9502df43adbb60868d8240ec0bfc8f617a81e8d967710cb5971ad55b1069efe4b066c2e6efe4aaeccf786e5fe01f43a66ee8a2d0e6f360bf3fd8f98253d487c3f413a60945b6294b38eb9e67aa7fff203bce2f8e88e3530615ea44d8b058c92e4724821159e83baef0c17bb7bce9503bdc217758e2013b76028fde49121a4e9fa9219a9bd340a6feae9d0b4ced850f82d73f029e8fadb622e6b21e6829288054dd1e7bf5239f5750d97fbafba6753ca1fad8c2091a6a822f156e9d1667490fa0e6bd2668003f23382c651334882400adc52dae8bc4162cfabffb71dd89f3ffce25086455eca92ddfa2186fc8ab9cafb260e9a553125ec7636b0132f2cf4adc66f2d9f23d5bd4d2e36b1338bc103b59733f745e5d8f90d99bb04ac330224b9d609f695cc0aa93cd7c358c79d579f4f556bfc0bb42134ecf82876dfcbe22f487fe19cfa59457a3d3eb9846a99345ecdba7ab4e962456ccc1dad26baf9717e9982578296befd71d046eff05ddaed84cffb8d7b40cc264e59e43ceeafcb26c5bfaa5f0771d6e50b2874cfbc4a42bbd1866d19bf069ef65aed77952414de74096796388b2b2646a570dd6cdfffba2ea2531b8048d1d7a6cdeb53acb96be25d3206a8829b4ac683dafaa3aafb91778ef900eb3635afdb7a9ccda84a711c21018317cfca7101f35d34bdfe7d20198a3b7909c1dcd40d6e83043c246841b989166e85b77dfc849420da0a509256ea5dbc8ed088a73309df5a1340accc50f56fad29e37f3703a5116e6167b337d5a6787f2bb976055e124ada49fe0782836943b7013c026828c8566c75cdc55becbcd2011f10c110b0c388b0fe683b1eec3e8ebc2b3dddff465a8c13aa5b40222ffc0beb32edc9c6c80f08d93cf3209d4bb1b34279319526f186e0250536a3e8a5361fb034122d70e3d0a9bd4d3c62452aaf55d0c86648eb8a9324138f3b83e7b6e77b9ee70239e1b1c81c953f53a5524e0033b51a840caf171584137d46111fdf4e5041f560d2bb715c3f8a0892f4d65d65a7dc8e5130d444bdfd5af8c657eb7c6705950c9be7013bec799aaaae7b081b9f88f8d50cd92ec4d57ea980b5722c71cad6c75aef5fb2ce6c38c9ef53b580c49406e0dc4a85438651e79760670061b94a33cbeee90ad92954544e9c63086571980adc9072e54ffda0377e9771bc212734ba71ccfe5d433eda4909dd806c669283ae08ff35f4a6f768aa4aaf4e7fdd4d5614585d1269a3486971376db161df03118d02b0da31ed2e6fca2904a4b4be9f6578a7ef4545a2534923e4b3864a27612501fbc35e76bbeebe8488b222c99cc508db29d48aa335b4d2a0974f948c3207c92eec89716239dc6ec857776ac61ebe485c29e64ed8d1bf0acb547515c79a3dacb2316dcb5979d23df154e1fafa827f9011e43c5323478f9f48a89913bedbe4dc9b0c8535f8e82fe64179cd74d7fb37d7ad587b65af57b3784810c7b6ee412b6eaf5d1500082fc208a921bf94ae5329016645967c568874abb19a3ee9f752e7b17f35d49b73a66b62e5c41fe0f0683824123e3f0b6b5d3a9b47d2b5eae10913b08cb4370c754d769d6cfb4e4f30fabb38dcf243009bb8f36b6e2e086d70d3286b5633c23559190a5b0107c85474e9e3e87c7110271705e6944dfb232d6a9624d114baa3fa91108d3ba429381aacc0ca9ff188dde3c8836565b4d858fd0cf99c1f14dbf563128d0525c67b1e8014f1a88511d16cbd41046f2c13fc972797b65f3a8ab4407f317b64f4a458b7bd778349d602becad67df6d15793878f4403e1af6f4f54509a85e32e72eab2cedac74da77031908b3f358ff750140ed750267cdcc7e32e8ed32e461bf0aa7d8173e20f4352719a9297f1811e05f691421141eb7fb9d1997b596c629f89b96c08abd77f12f0ad8e76122a17c707e159f590ffec5947392d76ccb5ffb6d4311baa6a00957d185df86166a58ecd9956606ee147229ab58c3664d4c4a260a04558de5442afca4f1301bfea71b327238061f69f78f6154f684f590475bdcc6748775c3275023092f1347eac859b0073bc94e9722aeb4435d816778aba600b33ccc86d7ff502ffd3b5e5228294337c32c0b8aaf95a82cd920e095d0fbf93707be62fe12a27ab2f6c9fb07207787af7c50a4f61e1d860a510726125b0fccc8420ac41897d90f6a8790e984cb9f89e3ab1885e2ccbb3b17253f35336f423e7e04f31305330f27fac32b056117db89ddaa2a0657054e9ad0853ae6f62aedf30196f9b94152c7f7bbf88a83f2f58fe5cdb0d75f56e6050fca4047ad11042e0fd4b2951da3892b66a7674be99d1e82debd98493d80d857d943def54e7acfe405d2672f582bb64924c25495f2dc338735ae0d2b159fc52b26364375630c72cca71bda7b01dfabf4822037ee44f95e934321d853a87bcef2963382b6de64082ab9b3a0c91433c1a87a45c6290a804a34fce3b86e761c58896d0c9f3708661cc61aac282619cd96c60713dffbec7b357fdf51279d50365e008eed72c32f34003b2fc76089238d434d5d912135a553f543b6befec4f7a9496c90ba236eafc7953f4a081de67e2dc549ff15c7734bf12b184670d0424bf20f53662983749aa91a65651d899fb4858abc55282552d22be27f697a7d89cf548591d7d5e7a16a2211c8ff09792e81a9c9042e58a5e76ee678580d3680840465a10692d45ce84faf5cd7fcc9aca49aceee374814110abdda662f4955d99bb27ad310d47e6fb735ce5008fa374d72924f707dff39233bd4109839c3bc61054f7e6715d27e55bcc3464c5c31d109102b95480a0a77e69a2e2cec60c0ce5b0511e8b54445c6eb2086aaa9f47a7130b28fea6fbe2fc26d68fe52d14193d4498f5164f652e8c0259f34956331526acda2611357cc259835351b250137ae3ed44a0d2d25796a8c0cd5d84a0753444509fc0682ea0aa232f6937054864493acf2317c626d36bf13251a92fdae72e7a184e32745343d2b968f2497e79d859059ce132bd898a84c989e5687537caddd4d2f8206e5e10f2f44ee6864baf71ed219c294a7373c5730323b19893b9fdbcb6137d0a5045c3be8bf837c6f5747ab0d91d8db1f17fdee9860e3123fec121148266e8579570bde602ef156ae16ad75fbb31db0e451e06299924ccf2963f600756a47ffe688ad700ce4e1bff02f37f9029a799fc53133b1df2841622981cbe9a1e2753e0db6ecc35fc2beebce4a28c47f6f1ad4bd972befc6fd606f83dc4d319b4935c65709e1e16e97c893ae007634b0883bc2b8a4e2174bcf6bd485c47b9c96c0b11939c4f5edd3db999124d46a4ce4c2564a535406430aa679b2f850272dda5b282b3f9a2431470765e00eec90b310800ee317c2a6aae192552b9e85adafddc556458b6bd5b5e76e770998a2a29b1fdbb37b2f57aba1360f912273134e540ee68c097b8f11275c30171ffa1875a8aaa45106758429061c20330a80f1928c2a9d16e33ded189ac103fb021ffdde726e9eeea1e03a3fdd9f34d9e52b4c5be2d3855e9b60150f7acc909a5d011a3f98cade7eb101abe935372bc81f4b5f18c806de51ebec0a8e032c0e4bdbdbf56429aa1996ede1bd98c7263896f81471f41cbff7311b17b42905d802a6460668a773ee1ef426785f866318f129e2cea728a7f127cd0433879f48812f5ab56fafd270b2cd5186f199d3b875ff5c3c20983e4acd2e8fdeddbb3ca68021bcbb9f9f31b3aa4a07d365b1c72e6b7096241e07e441a5e5314afff8b6285f04eedd74eeb20a41b329dc448ccb8161244711b34982dfd42f66da04e132757c16e54bbfa0d479ff8983eedddefca29a53c588db5e6d0f1e5f4a3f51f766dc3076ef722885844d8655301de79a24b484e1759708f1ebf2716b9688314217b5874bd64d2204efa872283ba9c47d85a0ceb5e5e1fa1cd2eff888a74c10a6a3075fcfae2353154cedb9418f9937a06b02c198e608017895a02c65039195e4c91b2dafefc1e238c069d887d450ef3cb2f786f59bb2e9e4caf743382d7aa665b8b32f484dd44fc9000f86ca3ef57c6a39ba31790f3e12c402d1e3a09a892923e3cef063ea8c29559fb2f3dbd6a4e019f037ed89475dbd825962f360e396646f8ffa00c479f9e8460127b728c543117dce38ae17cfb36b109110cf44f2a712b6cc6b2220db93ca7ef58b5fa163559d10d80aea598afc1221290237172692b418ce4267824dbd237ed2143de7a9d73125f8c682a2a2fd42d537bf8fea48336aa508247814875ad24c541386133d8fcbf28ebd0451a67e7d69ef9018609dc09a4f36dc93953006a82c39d601022bc425dedc2edd6bebabe78fd8ba17ae2b3c4fd657e6b9fbc887e5ad442326cc872075cd960b615fb36b18d140735830da257a4d42f2732d501b21cc883d8beb61ea72961864affff658129f91a59bfaf9dd38ae0cc92c7d8f68d531cdd5e06fd115ed9b4e3b24350882c3914c5f8d2df77e8bf615c6d7427665e395cb5487e13c8df9d3935a8431d95d02a26373dbe4f66a71b31100516596175b17fc6d0fa0c5f0d20bb121ec8fd43567721ffe0e1fdc38d20cf3adcf5004784edbcfadbf60d0d1703012ffcdf918b091a4d2807d896aa463a8f037dddbc01024fa34fbb93a06fd3ea23bacab8fb53937425fa14d6b819d50f91a4cc75689e05e988b8dda6ca89a78acd8eb68457c6dfed5f08aff4523f4695e79c315390f829f1241eb78d6f618c6508e15d3cb6ef70f0c4fcb69ca0e90e1186caa9de5b0553729af8c795db4578e061748fc25851e607dcaffd274e3a6e2d561ca4a55684065e1cacbdb5cd75fadd71ce5bc107365e6fb9dbf778248261613d49c36d1dd1b3403580ff4e6494291690c4508a8defac836876a25a4e9054ecad77937cf9df6f22282ed5f0a7778b4affcaf09f103464864c8c1fcbae97d9e4db03750213eb0a78475b45caef4a477f1c73dc8f9e39dd7d4dd50396007fc0470736574056302000385eaed68d747a689f194dd86d5da452bf2f327d795d5d504e1a59b038ec702d9ad78f74c269b6c97c8b2b6496bafcf9790dc9c608304da86ca5edaafbd62dc960bfe5c8bf1b4833e5b5177e26bb83bbd28415ff617db4e3c3c33b03f10427bbb07fc04707365740721027fa518c54bb326d5ce3da5c2eb8a6521ab99df86b511477d0f5ebcd616f063ac0007fc04707365740121090b81ada05aaa354e5c62732358c8a2395dd9576631d9377844935cac78d3b4e807fc047073657403210bc57b6abf30fcb84f8660771267bb93a6e72de69165ecc9e462d6fff5153d6296010422002058037c2d81d3122185c8704d4276e2629122c95b8ea68575c451628d37eea84507fc047073657404fd4e10603300000000000000017823c100e4cb4ea3cd1380fc7986f67a937b71320ac40fcbbcd3fbd3f37dfbb8c4ac0eecc7c8b91d14c7148d2e162d1c4dea595dd8dfb80c0e064b926ef679d2eae0973773f44dcf8cbe7a6e53035366c0c9131cf991bf8eedd5a759ed33baa868e6e3849c93c40bbfdd6d485ce31941d09f9ca07c7d3a3b724760e637191c5344fc7812976c541de2005ef96fc57d8645bfe6e9cf5824a0e084df078006f11dc485c39ee1d196d793a544d458358e4d949c5449a63875196328fda3b29ee227add62fc36f3898512ff596272ea40d79f376a890c806fcbb33d8e7d1552e9aa3dd14420342039157cb991401faf3dcbadace85d5d093ef744462079028c9e68c9aa48b921be8f809b950517af97da5d0e994d1c68a1a9969972a541e3111b0710e552ab40927c165192e263fd00af1b1f0d7eacaef63c52852336c0293b0d0a381b0cd90864240dbb2f6cb61c7149f432a11f62080f7d47d9a04b854b4490eb7a53b4fe33e146db108d235f6b164d22a4a9cab38f5501f4e2bff1963a327f757b8df26d2f65d2d1b933fe6cf8d12c4c7cd8c2f5dd7a69c989516e729b52b6688a4c29333f21a84247e52b152c455d45f582fca280bf818f7c0d8967a43b5d38465922e4de8d2eff49971d28980793eb41a5885cdb4f32e528edf4de6939239ff1c678160b51a1fc5d6e83f3c6cbab2aa88d3e1ab8911779026ede67a6a7b85a57b8a09665150e0cbc3dc615e1d5e39279c2eb24c80423b0568b481b5a37fac1d88b8f686b149c9404b399148aac35515150fbccb29018ddef5c9d219231672ba884020e50ef3e11e29a50a3677fbb427174e2730b1a5293ba9d2f448ae6070294a59de9f0a174273d580af7c87c07acb27962588de2d69c9adf01ab86065f180daef68c9e3399aeb1c290622412484bc88d182ebd19833e6476e24a70a0d1964e61a9258346fa8237b9940612ddb90d91779c5ca2e294679d0ca15367b5db571b81fa0c7e9871147ce9d2729dc3168296d13ee2dbde145ad9bcfb0e24e2542c8a2e06424c5ccf3beb23be0b57acee847f579c1d548306e6fb2fd7bc42c529415002b292d9ce82883d627625a76299f3d055a031be110bcadb95eadffbc6a5a14c97d1a6169dd3ca058e0ee997cefd94f2595e39c06ebebd2862edf7242adabc9716c28555f5ac93ee2609d75c4a852d788eff783c3bcac47b8f7330d2359f004879df8a475ba381c32379d3787761fbbba34a8e9a59fe736bc489562e2ddf71bc9cddf3ee0015857939b6d1af58d3a7fdabd925c8b2e724f0b6a80e7c5c1e7d04bfcb8cc44ecc172f3c18cd73d226f62f4a1fbab7cc6367088f61ec3e562989e01ebba29f8b7f6a94c0c7b32fdcabfc2dbe4ecf404f5fc7d5f05d8694f95c735849ad1e32a44810da350c4cf08c61d8693f468578d09fdb924278add9d261daba0ed187210f239bb4a97763313f2e006ddc202d4550412f68c5be848e1d34a55cce1b894ebc9dce7e9cc16859d940bfad3dd848afb99e2868a92b1d9da7a022ea7405abd42a79995f7351627ced6250f5fcd4f0d179e0101ada67ee8f96e4bd0d7afc1da123616d7a588e07ba84fe948c8ce1e7b51f88d8be970a706c9175d9e46c23388cfff0609533283ab8d2282487f0181d45274ace8a92a8a0eff3d52aba9732a64d787d0effeaa58d03c9df620a43afd2de9607783069ba61e2c583b576150baf140ee48468afe18ffd9da3eecca84b0aa3b7a7af17ef69d77d6f0d99f0e83d9a30652b3487aba49537381ae0afc2885c70ed1fae6dc5cca933d92b8c089bae4855477584e32331623c0369f500d4b36d62d15a81a4d7c197584aa30db415d9197d9cb7ef641cac840a023fdee46c66e3176bae974cdd58ab5ae2c7346390dc696a2208ca7a18c8cf671962791f4e827420e6ceb6cbb58b07054a2355dcd30c2edb64f536860515d515521031f63f9c2a8442694746e9b4ebbf5b85afd96d4e6c25a50013e363681f229645455892f1a1cb8b2a8073a925ecc3832c339d97e9249a8bdd695616cb2818a26bebef23bc94a58a411be30683bcd16a4b6472ba04fc401ecb59f0486dc5b01ac1e0ae57a132c768e4c7fe27dc9b4c422fa647953ba9bec22cf8ad5669c913e0731b03468ebd6009c14283fa1f195fc6636eb30e12cde2c263ae984980a3cd8aacf424e0ebb68c4e9521e2b61c2b39d7ede48d7e98837c7d840455a5525b98f7bf79fd6258059e4e6925db4577eb62b5263d91b7f17a24d3b0ac1163e42d9c367a363034b5c03062c4706885770a5fe3af5ed1ec6e2fa2d3ef23a33acd2fbc30bf436999be36ec7cc9cde96a96bc34d0e0edee7b0ad98a35d8bb1699312d3c1b4966003a054a9bebd8815ca947205fcbfc3dd2c6240a6b911ded609d2c2cbef2fb151d80305615d60ce8fbf4089946780d10523ac165ea7bc38c3a2e6bf800b38d47ca603dcb20bd4dfb40d0c02cf2f3d2727e8995203296b06f2c353f327b2ec1d9503b1060b57144ca9b648c1c87ae982e38ebdd961e3beef4e198eefb1b944f79cc136d38ba449e9800cd2897a2f0e15856883a839fa7f89220c02703f704d1761d8391a183a98e6fc0d9bea48440eed02c84e5e4b70c202c2dfea04047085763766e28e3d4b174ccb7727b05d74c55f7a91de3599834697ba0ce4692a14f966c53fb735109e20599741df2a6ed21d67076dc078b8e565f3afd95e7762bdc3d9818cd69109f59c45aff6088ce3a5ecadf3ba2e10960b115d39d02b559b16488fc7b8a23cbe534311baf5731576c5ed93bfb838edfe4c7c2eeddc2405e8cc4c741f1e6e562592be7f95ecbc26251edbec6b35581738b44673e8295494f804e6ecae2b23527946956f68546fe01b38ff1fd0e8f3090916a0e421d804da219bdac63410d62749b429f82c9c2463c52aa29aa3dc0359051cb5666c6be81a5e7bb85f62be8ec4dd10f2948f82ec66ef4e0471fef64efa4cce7232923b19c72862c674250316448e201abb5fddf248a747689daf8f04343f1e695d3fd045f5e32e98462c0d65d0ff4d751c03826ce02c7513c3c56776325d4566afcf780876ce17fea8450e48d8a36f22879d83014dc6fb7e7ec0ea5fe309723862bb5e2cc1a4899e18583c8ceae1246ba8f12b357dbd91e51718486777b192ac97de65a35a40655b25426a30373278e897a2b99658ad27277ed32e7eac3b7c5d5c775110b5327dac2f3d92125ab3b3bcbc383afd93e795764bf2632c7b4c98876c95e41b7c3fe2952db073cd4ad219ab3aa5d0901cd53b8acd8e2fd92f93d7e5ff0eb5ad97a2240764fc40e8683a1cc28484fb3b1027059a53ffa5552406e9bd7c3d28dc0b081a37cd5a13af22288d39975018984c084cadfaf5ae4c91d8b00a6466ab7cd50f1f143f11ce8ecaf39809a3c4833b5e11945564f1f0d025a07427100e60bc40e065bfe938246b3345fa8fa4a8ee9bb50a5152c90f43d239401ef79894b5f2db6e8f2e98663d6497dabd94f13d9cec86bd2707cf32df56f5a6693ffe9be7ec362c0bc03b6816269dd2b72f5638209dbc1afc97eed232f2916f19d4ccabc55a6cc0a48ebdcbd59ce0404ebb47740a0d802f057116714ddab4aa3bcb5d8ca20069af51e09f941b9efd73e8515aed1db7ba79137146e5c14262dff94a885cfdf435d60d91bf2f508c110106fe4a0eb4c32ca382825ca6a65aa2749a224a62d8a1dbdffc5b53bb4cf2315e9d107a73721cb3ddd111c723cacecbc219ae5c850beae3b3b6a5577222af1706a625965b7c7c7f13f01cbfa9c6f1cf406fd177433b9ad4213fdb30abe01cbe931cde34de1650e69d348d25b6128a26ff8b0a73947399b4162bb6513043167a3871960f0dcd5dce5b6ad680ec782ca48515010244d5692ce8e6a56c291c3512e7ef91680769be39530839adb5a8898d83834d398e63ebb2ad00d42d414233a070dd6bbdd6093c96eb8478953fb04c3e82a7c84a798d7bde36547bdf4486e8bb3a6fddcd9d7ae1b007e61e4da3b85ea327c1ab8f40a66b36190eb3bee753bf1043335ce82cb31751b7e89b84fa9ccec5427b28c161512a963f80bdc72c38fae1b32b4d7900f983b51f42144a82514b535d71f3dc80c0b28f49c20b346d344ed9c81b556ddc49263ddc687e64daa55d659d0a806709a62065e1eb1c694a6e46f6c8b10bd47e76664c42b9d992c23999ce516a5cb6d68a4748957c63b2db6939b86adad8fcdcfb5bb643b08e156d61e5bc4c5810802d5afc1c0e3b160b01d6e5675e5172253d1d943b96a6a6c940925a4f6850612b8c57ddca11e893fcb5e5e791a6749f75969b49c684aca0399bb322b9a72997e204b649c3d26f726ea0a49920ebf4b533bd4b38e1cba3a2422e37c3e259dddd8ec10afce3f1baf2bee470eb752c5721aa49a3b8b4bee25a9f6aa626ade570864246ca2a5c6f0d183ab2d909ebc336db2126a4fd24de704befbd2f07c7cd6c0169a07777e5a583fd3a9a9ff1241fea91c504fd5e4d6c6e636a9a5c3fa56824e74c68c1ebb8c4afa90ff2364acfd4547fff73f94f133d63bef1ddae0a8a338ee8e50777d1b7907f4871bc4efaf746ec2c7b9fadd717bec888026e32e5e26bb0101a269816b9046c29a42b35ee15e203fa26d321fe03f042a8f21cbd62e1bb0bb371d00e46492bd655d0261129393c023d20ce9ddf0f0687820e563d3688cf1e7946a0cdf09737c3715dfa8a6777bf94ddd2d127bb5ad942dd07738eac8b6955019799ce77cc42136dc9aa822470ac56efcd359bf180e95f3fb312cd0ba9ee9bab99560d0b41ea7831bebcf20f27e17303208ef66d5c0f82d26d8093f002418267115e10331646fd87ba1f1a42f72fb45d2a4a4e4353698863e65a7cd4f6f3cd0dea28dbaf5794de216afe202b679899518a3dee9d4024afa3dc9d8d4eaf0179b05ceb22d1e60bd941d44c3866362a92a7951d9de36e4e7d1a681fb2d9420e0fbffe795e9683857846ae0e834d818f990e575a7fa7efe7638fad98fc5b680abbb58cb8da78d783a7ca16fb7521b4be25d4fded9417cc7fd9525c79df7e52bb83894dd905794282a7413bca79bb653afce07cc433e49ffc38d16b7be05c1c9ad05988ed672e1b4dcac2a5d211d7ad1b790e4ec0761533925f528a21305b942e0dd10efdb99bf1fd6d6b906ea0d21ea7bcbb4116490d97246458fe29644f149122586b6f16df620ab1480b55f27f3e8bf32c2c094bece34cce03c20b5a2d2b73481c7cefe4bf56dc76c7970dd77673e4383f62998b6923f103eb0e5c1ce91e43da83495961460b677c261a027db4ca979597a8232691c3ece94456e313ca57f8c2021334cd4e0735453597d516dcf6e04d386ac61bcee073f7520d205fb1ec6c35c6c96511e8a067ce5ba3d701beacde937c925b204ea011521b3e1219650568ff9dda90e043c9d20224fd767670586812a41ad83208f5d62f7892b22500be3ab2028207f738c21301e1aeab23d1bd4e46d46f2ec1991683e987d3d834bc260113372e3eadbf825f86d42f463795050f5821a6afadfe42cc1cad6fe942d16af7e35dd08004ef676558ecc8801c45d37a8c147102e120ecb7c965a2e33ddab0a43133692de2133cc64e655961e66caff271e0625c469a24baf126ea7d300bac5f0335dd5926e99394d45280cd6e14e7c3d5be3b3745b617d9f7e01f0bbe15a0512e2501bb7361a17c62f4549df0e765cf8a2556a9d1827ccf22c75680db0d7391da9f0c18926bb90423c7e084f4fa11cf05914bddbb8359684dd920db82bff035702f2484621ea1d71d2589a3d5db2a876d78b2228a1b4b7b9ccc8c4ed6f5df7010771ed118f96bda339ed2025808099333224f99f207e3e808312f49cdad7e0007fc0470736574056302000381eb5d013a1bbdfc28e27c272822893a4b674355a29a306afa132cf3fe9dc2955ab2375883d5f7e42ada61971ea91f8af2f106402c5592e676a32e3313d03af9eba6e1185d722a0b726da16714e13cd416c8e99f1b7f0aa44b721c483fdf593b07fc047073657407210302e71fc2fff37aeb6d2e2a7b7f2308d4ab7d4bf0a4cf9be7c06e89a66442b48300010308f40100000000000007fc04707365740220230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b20104000007fc0470736574012109870d0ad593316a7ff67dee90f2c2d8e305cfcdc4619fe0922c706560eac5d8f507fc047073657403210b9991881df2ec384ff5616f6c03d45cf033ee64536297c3557f9fffec716c1fbe0104220020cd4ed5f0db8c450e8b0be595b6410c1759c19f1f6926279095c83dade9862b6d07fc047073657404fd4e10603300000000000000017d32a9010e698107419c4e5b47c05ec25624ea0d6f432f75b744a15b8f8381b5fec29c0b55b8eb600b91a3e13c0e56e601c23882ffd62fc218b1da72e2ad732a47f7279d32cbb24eda0caaeaca8d8fe4bc920e0baa6821b47f7790416a5bdf13d691c51914358a431dbb2e9154bc01da79483cc9617f4d57a6f4d2d1380ea2450c292ada85eb663a23c76a6adc0c7abf8ff71b41a56478b66003ba839295df69edeaccc54a9b3803c9d3eda9cd47e478fd852a316802c8def8014a449cb886d0fcb5d56086e8742a346b983657f331330f6e8ec4bf72b314cc6d69bd94be0bb6e6896ec01f773c1a4c329e7ddbf326b83780ab22da08a144fc1c8dfda604cc1b2858682ad3decb097c1ae3e992596ae997422c7d381d8d9354be1658c43e5d5c1e49f0e7263aee9093c018b09ef44ca7adf853c625187a8ed252527b94a5bd70e13c30b22f05038404d99c18c0cd76a461ad7dc4ba63d132101ee471bfac835eabe0f11487ab7361e337f5ca8dca3cfb25de4958c58d59df6ea016a9436856a3af505884a4e38d9cc1ac955c40228c22ffe385dd48b3f1c27d40e7794ce62822645b2a2e42346f9771f2744fdf5064309f9f7f84747131369ee9b5421a07d24ec6e7baeaf1c99cf8339f38e44b0864ef46684815c320df48159f83aa80e247d617acf1b1c7a2da56cb3725811ef028987573f59c90587f88553fc6a11723fa5e45424de05d2b0f548dff87a8e1b094a929f695f01b7a127b522ba2a6d6290991d0985af8059f002f514f5027fe98d292fc85f050d5a19189a27344f83f737ccf254c97728054ed01e1d229f65b2b9d66a7c82116bf26ecfc026446cee24c5603e0bf0df9875461623340a7148de14a058f1a37e8c627bac2acfa2aa1de65d1349e7d02d565852af1de756203d2aac22330c43b12f1e1889c8ff2959b1c11e85b2a1f577b47e1242db2b1bb4cb03979ab255353bd91a728a67827a86899ab68b3ecb64e2303c6c701c1ba3aa09740264a42194277fde906dd6caab566c089fc83fb9ad4528d50c48d72d8a68e8bdfa846284979e7201f41d225b2a782ae77cccef12da93d2c2e73f5df35f75102fd7bae8c5c2c92e79236f687b8559b7d625658f6121101ff205dfed8356fd447c9670330b3f197c3249b05dc72f943f1760489dbb1bd53b2bbe65ba8ed7c880ecf97a1cdb9e78551c978201aed0c1e6202d2bf807df2334bac733ae2cec1af8a409cb8b32830fa0696c18ad11d99c3cd0de7136b83d903d955acb584117e4ce39958d75d6e1ed790e4f5613fcae6a827078a45676afb7fa82f0642d37c273e2378e58403ca9542d542d6ae549752bb9a85cb1c5d71819cf8985c5fe52e6de0c75c61a2d4b597014009e2bbfa7a44085bc75af6adf6de4d0f1e5fa8dd68d5e13e7b10710d9ae67838a775b17370a052c019ee984e169235a2a1a20e7a157d0e3c93f477907e48f018780e0300b9c1cdea826a81d9900547b7fb7e133d5dea37482e40d27d3feeea57a07dc795737af5f01286ab37003c7dbd8e335978639704333af1988feea17da0af7606f5cad04660495009788afd99412e036db5c9c9fb0c643873fd0a301d7c37975f6b54906d3cd992c7c435b334f695c1f87ef071a58b890b2dc2771c2bec4ffcb9c121feec068ff0cf4924ca1b3cc10b802558f05d7cc2970c3b0df9cb7ddbc306269dc42d8dd882943182cf092d6007248288822d6ee80bfd24f4077f1f662cd3c0f577f831df25cc20d2c1541c44df2cd07586f4efa26e0c208430889dcd4e548be9adba2def0cd048b57d73ecee8e3005181e73d4d12bf11d225a234cb3019c0cbebd0d9c2f3bea6832eeff2109d8843ee61e682098250641df7bbe21c72c7831c215e0234d71cedd22b2370ef3d574f321c6d45607175ad9568dc06520f33d2b15ef2bfb0fe9e48bc01560dcdd73b6fcba2caeeafaab2646f7b46e9d1c3c992afb18b7c2d9d2f88095c1033bbbb9449ec6467da2e302aea9979b28fcce685878619a8d8757451d5b80d4e57a3a213a599b467703c5f96297ee6ce44fc06b1afbe411f1a665ad0745bd7fd2a5b49ceef6b468817f500479af2a8f6c0e3557eb98df51a4df26fcd5cfcdda48e5441114c24573bcca96356d3c99d01eb8f8a7ab397d6c8a54dd9abde6d16cac1ff2ce86095ffee79a304355df03d72f2d332b50898ae06a775f5f7fcef3784c152f51b8ddf9cfea4f0bd271eb98ebca53529f103228aedbf64f03966c5bc2e774c980cd13db22f3c3f6136b6b03ca6cef7a4f310b57dbbe9431946d784fea7eef3258f10a7bd5dca55102bfa49c04fd117a8c521a5b691249e994b8e935bbfd1b86b5512a56ac222e989f04dd07c34a5219dcd5ab003ab118ad40746ec25bcc056b35afc35b656895bddb4d368623e17a61f3803213c1f122d8e6281d013df14fba919209fc2e4bc538021e5d5ca8a1a751859f908f47b39f1a3112611a3e19264513a7301e68979bf0221f1cb418f9cafb7b81db4ebf08e0c7a1b57da5cfe8e32ad16b0c2fbe9b5f7ffa5c80aa3217b082e4f6c9f51cb79fbe27ba459e09b01b3fdef45edb5d1b063fc99937a822a5a43803b610a3081b67f7279e18481754f3802753c5201a60e4fd89e0947616a33ed4218d8e708ed81fec6e3f39d7a94378d92fd6d8d64769bcbd4cc1d66cdf4ada5b189e03461b583dc88f2972c6e4904afc3b49b38818be26f83c94cff7ed4c826917f3314a931b92d65e562014cd9a1a68ea79fafceddd09b8b0e48eeac86e6190e470ebe8ec5cee12948942f80de6a40dc2c657b6ade6a2ab4b3297ec713bc3cebcf91f8465a14e9d9d5325fed40d2a2af8bd0731d9b626095653e5fd292cd5de3a7831c0ae81292630409ab755fceaedc4e76e78b829219209476b94d0c6224930bd6c7d4a6b06ac9699be79caca17b1a7c9254f1b884a87e44de4ce5b15f312b09210d09436a8bc1ee39b6e5f96ba5b620d614a09259b251910219ae39d65c2650e2d2a27cc0d2dbd5e2aa40b5b4bc4ead5ed531d7f206a4bfbfabb96785b768aac21ab8f11f927d54949ec3c595f31391bea8b4f1a63db49e26d875be2cd4333eb5785ab1cfe7f83c6e4a445702f9178343e039a7651b62acd31d694db89287c1ec5a636933a630b3465d27015e564bd2a4848d0910739702debb3d9c7c133c2a2f5c6d93000ae74bffd2af4ec66180e7219ad8af293ec89fdbb0d43d6b9dc5fd539c338136436ef1ce088af4590f47af91d78338c67b03500d4c69de61b44e09a776399d7cc349c95752405f65b0ec19a14434d715aa11a14c5be94d42114c546af8c02d291b3d54471ae463d249237fe3bd18f7afc569c43e1c1cd284538e48444f39e8c83d9d52f7754c04a6198711f8ebdfbf647002ddb54ca3c8833a3a21e0bd7a8cfa1274f61a36183fcd63670f1f5b425f2d06ce8338410baa860faf2331ef93f781d1fcf10c38b2be7ca21cb27430147466867d233acbe6f7ff46136ef736a1a1b5af97cb871a8351d7774bbcf0f0f47ef10c7a5b26f0a25d403fc7cf2e7bb57a1f16c68260092523c82ea020f0df2660faf2f6d85e695cb672857bc9fd4f7ea0b93f735007d9ad15e661329a22bc465f6c65f442f5be91c665f3d7311290b47fb7c10342a5a367ee18dacfc51a83ad0bba7503b54a27545abe372078505062f4b859947168b46638f3a4ebd116fdaea1d96238c4cdae5882f326287da8e94dfbcf9c82f92ec94ec8706dc6ce194fcf7890e047e106aa387173662ac2ff1302627f80c567fc7e74d36473bb601681bfc1b5221e15863bb9f8d5e30bef41ba5839349a677e35d30e0000596691b2bde87e386998e3e2a463aea434ad9002438375ef1071afe9bc5027cec29b5cca4196b2b34b8f92cfba033a9e2539aeee306c5acb88f22c7799bd7208853a735d317df6c957108c6c10c53e9e1055f6108369aa4918dabfaffa446c40b20c73216e976a9fe03cd157ee29efc03e6a8df077a5222008e37f257816703e1b9e214ebda174ed7b4aa1b5e0494f5285704ff6ee22fc1f386dae624b72a7e24d2a56c97a8d8b816ceddc68119c279a2654f19d3d76cd314e9fb6218b9682455f81c7064e33295060dd0b91b958dc04599a5713795c39b51744b5629512a9028a38de8f674214de7bd4845e53244705e431526fb28b8c51b3bfde0202c50187f6748581d5faccee866d0c317345ff6b65b954ed479750d0a052e3fe3f557c88f4964cd95826a7be6da14b54d4c00dbf9b2392aab6d084262427f24d163ce590b8d36547ed8139bd241b8f18d9d9c32850a29473820f68e9197f97e7d54ec76bfebe6fc3006b3c7aaf370416d758fe4426758fb8720bb764b6cd1aa174a58d42361ca8c2396079a634bea9e492a7e1fa5d443a2299c66ae23a064d6e70c605019527f1b499a614c28d3c8cdfee753abb9b1a5b8d9bfde29a5ea869ab95a1c7c1c076f933938008060800636f357a48862bedfd89a70ab30ba31919bdf6b53edd085b3836657a4bb214cebd2dfae4030d19fb9473e046ce6ec39871150a4f0ea03e3513c5615bb50135678d024e69eb754bbdda896eb0f2d39a1f7671231ab6887902faa3adc79cb77d122e184031f7e3a9cc222b3e9788dd9c417cada21fb6bac493b15fc306d64cb701dac8534cda58bd37121adebe474ddfffa1afd26a999b41280b043992b5b7fd6f4926b5b6994a621fca3d13ead3142d8c255d80c33a86ee4d6ef04289a23f0d39f7b73c30ba59005ff0f1eef21f9ec01e703aafc1171a4d24d8257917b239c5c3b447549cb2c9602188fea59024d6def3b37e26789c2fdd90beaeb30790afcde5cb8179770cd3194d5ddeae7eebad7b273c7c53eb184f17b3934f4d0cfbddd9f8e9b135ad4fffa8b5edb04e2fd34e21f29717f3f2b9c01c0a547b3e522041bc5a0c647d7c8eb543b94856a40ad9c4d2ebe94a3de31b810fa99aa4b19a9a0ee51abd355b3c556f26dec3405b19d5a5da8a6c8e263c8e2e97514053a7c57097cde1649bd6c77fe78ffb96ffc69cd43fea598e611ff55a0a306883b01a44ecdba59e103626f4a08e3444868d27e737ad41f3c2564b593ed169036a7c4b883594bcd141847f22c1933e04fbbfedf71d885c5cfe17769eb36b295950e9a420919d06110774029a42ceba64c6f3ec12404047e78f1c67178e65d1caa49894f8b606244a365744c8c826c682a756f560c1d4f71e1fd566547a8c070fd64eb2ba941e844f86af062e67bfecfeca33f0a69c186a5ad2242e100b0bbab31322cc9dcad523297d53f44c4ad8cbc2826bd2e1f211cf6fe29116f6c0bc5d37f7ac8376a574dba76dede5fc6e72e4853d4cbc0d302e20bc130578419d8730215172a470f98e9bc868c1f7511bcc353e879199d0b25a06cf49184808bdf76c165e91565d0b7328ade3b164d5bf1870ab9000a38389ae1de035eaa0ff3673f6b01ff8e7cc3358b1f6b068b93b47d26482f8d5317a109f1b5475a86dd46df188f6d857b2c753b2323e14b70cddc6c5ce19f67e955f085f47480b55a164ede57fb029f3f7af1e0c0bb569e52db150f69c8763308109cae4dbc2cb22b9d0bf5842f0d80b0c2120f20f7f0f80e77084791eedbbb50f573ef7f7ac12735c91fe2603053c00b66c310029f779f229b249ebf21e0a09c4629900e66c8d86957251d64784d84385ae863e45a33b9f651bae7d3028c5f0bf036dd45ae41a72e72e412520c29e559928bc3f4c6a608f8e22cff57e2b40636c0dd27ec8673a01ad04d4c773970b6678d9e117eb10a3e24faaf4ebebc45b13c9dcbf23567647056b1f7dd319018d2bee8a059c8f2d1740aec65eb54aef3709f1a5f680fbdd9fda390ea2807fc04707365740563020003810a02fdd12c3cba97447dd59111452581743c53880ed8fb161904e6b97c4ce83fac66328bf77cb920ba7d2d28790a9dcdaeacafba83a59a56315ba410acd64c6ebd7862608044814df5ad160befb4eccaaa7ef1e7cd45a26898ab87c6c3ad4d07fc047073657407210252a4b012198c2131d70498b5939c401c01eb1178dfd58123b55766b03f008f7b00");
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

    #[test]
    fn pset_issuance() {
        use std::str::FromStr;
        use rand::{self, SeedableRng};
        let secp = secp256k1_zkp::Secp256k1::new();
        #[allow(deprecated)]
        let mut rng = rand::rngs::StdRng::seed_from_u64(0);

        let policy = crate::AssetId::from_str("5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225").unwrap();
        let pk = bitcoin::key::PublicKey::from_str("020202020202020202020202020202020202020202020202020202020202020202").unwrap();
        let script = crate::Script::from_hex("0014d2bcde17e7744f6377466ca1bd35d212954674c8").unwrap();
        let sats_in = 10000;
        let sats_fee = 1000;
        let btc_txout_secrets = TxOutSecrets {
            asset_bf: AssetBlindingFactor::from_str("1111111111111111111111111111111111111111111111111111111111111111").unwrap(),
            value_bf: ValueBlindingFactor::from_str("2222222222222222222222222222222222222222222222222222222222222222").unwrap(),
            value: sats_in,
            asset: policy,
        };
        let previous_output = TxOut::default();  // Does not match btc_txout_secrets
        let prevout = OutPoint::default();
        let sats_asset = 10;
        let sats_token = 1;

        let mut pset = PartiallySignedTransaction::new_v2();
        let mut input = Input::from_prevout(prevout);
        input.witness_utxo = Some(previous_output);
        input.issuance_value_amount = Some(sats_asset);
        input.issuance_inflation_keys = Some(sats_token);
        let (asset, token) = input.issuance_ids();
        pset.add_input(input);

        // Add asset
        let mut output = Output::new_explicit(script.clone(), sats_asset, asset, Some(pk));
        output.blinder_index = Some(0);
        pset.add_output(output);
        // Add token
        let mut output = Output::new_explicit(script.clone(), sats_token, token, Some(pk));
        output.blinder_index = Some(0);
        pset.add_output(output);
        // Add L-BTC
        let mut output = Output::new_explicit(script.clone(), sats_in - sats_fee, policy, Some(pk));
        output.blinder_index = Some(0);
        pset.add_output(output);
        // Add fee
        let output = Output::new_explicit(crate::Script::new(), sats_fee, policy, None);
        pset.add_output(output);

        let mut inp_txout_sec = HashMap::new();
        inp_txout_sec.insert(0, btc_txout_secrets);

        let err = pset.blind_last(&mut rng, &secp, &inp_txout_sec).unwrap_err();
        assert_eq!(err, PsetBlindError::BlindingIssuanceUnsupported(0));

        let input = &mut pset.inputs_mut()[0];
        input.blinded_issuance = Some(0x01);
        let err = pset.blind_last(&mut rng, &secp, &inp_txout_sec).unwrap_err();
        assert_eq!(err, PsetBlindError::BlindingIssuanceUnsupported(0));

        let input = &mut pset.inputs_mut()[0];
        input.blinded_issuance = Some(0x00);
        pset.blind_last(&mut rng, &secp, &inp_txout_sec).unwrap();
        let pset_bytes = encode::serialize(&pset);
        let pset_des = encode::deserialize(&pset_bytes).unwrap();
        assert_eq!(pset, pset_des);
    }
}
