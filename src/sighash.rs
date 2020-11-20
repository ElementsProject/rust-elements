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

use encode::{self, Encodable};
use hash_types::SigHash;
use hashes::{sha256d, Hash};
use script::Script;
use std::ops::Deref;
use std::io;
use transaction::SigHashType;
use transaction::Transaction;
use confidential;

/// A replacement for SigHashComponents which supports all sighash modes
pub struct SigHashCache<T> {
    /// Access to transaction required for various introspection
    tx: T,
    /// Hash of all the previous outputs, computed as required
    hash_prevouts: Option<sha256d::Hash>,
    /// Hash of all the input sequence nos, computed as required
    hash_sequence: Option<sha256d::Hash>,
    /// Hash of all the outputs in this transaction, computed as required
    hash_outputs: Option<sha256d::Hash>,
    /// Hash of all the issunaces in this transaction, computed as required
    hash_issuances: Option<sha256d::Hash>,
}

impl<R: Deref<Target = Transaction>> SigHashCache<R> {
    /// Compute the sighash components from an unsigned transaction and auxiliary
    /// in a lazy manner when required.
    /// For the generated sighashes to be valid, no fields in the transaction may change except for
    /// script_sig and witnesses.
    pub fn new(tx: R) -> Self {
        SigHashCache {
            tx: tx,
            hash_prevouts: None,
            hash_sequence: None,
            hash_outputs: None,
            hash_issuances: None,
        }
    }

    /// Calculate hash for prevouts
    pub fn hash_prevouts(&mut self) -> sha256d::Hash {
        let hash_prevout = &mut self.hash_prevouts;
        let input = &self.tx.input;
        *hash_prevout.get_or_insert_with(|| {
            let mut enc = sha256d::Hash::engine();
            for txin in input {
                txin.previous_output.consensus_encode(&mut enc).unwrap();
            }
            sha256d::Hash::from_engine(enc)
        })
    }

    /// Calculate hash for input sequence values
    pub fn hash_sequence(&mut self) -> sha256d::Hash {
        let hash_sequence = &mut self.hash_sequence;
        let input = &self.tx.input;
        *hash_sequence.get_or_insert_with(|| {
            let mut enc = sha256d::Hash::engine();
            for txin in input {
                txin.sequence.consensus_encode(&mut enc).unwrap();
            }
            sha256d::Hash::from_engine(enc)
        })
    }

    /// Calculate hash for issuances
    pub fn hash_issuances(&mut self) -> sha256d::Hash {
        let hash_issuance = &mut self.hash_issuances;
        let input = &self.tx.input;
        *hash_issuance.get_or_insert_with(|| {
            let mut enc = sha256d::Hash::engine();
            for txin in input {
                if txin.has_issuance() {
                    txin.asset_issuance.consensus_encode(&mut enc).unwrap();
                } else {
                    0u8.consensus_encode(&mut enc).unwrap();
                }
            }
            sha256d::Hash::from_engine(enc)
        })
    }

    /// Calculate hash for outputs
    pub fn hash_outputs(&mut self) -> sha256d::Hash {
        let hash_output = &mut self.hash_outputs;
        let output = &self.tx.output;
        *hash_output.get_or_insert_with(|| {
            let mut enc = sha256d::Hash::engine();
            for txout in output {
                txout.consensus_encode(&mut enc).unwrap();
            }
            sha256d::Hash::from_engine(enc)
        })
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
        sighash_type: SigHashType,
    ) -> Result<(), encode::Error> {
        let zero_hash = sha256d::Hash::default();

        let (sighash, anyone_can_pay) = sighash_type.split_anyonecanpay_flag();

        self.tx.version.consensus_encode(&mut writer)?;

        if !anyone_can_pay {
            self.hash_prevouts().consensus_encode(&mut writer)?;
        } else {
            zero_hash.consensus_encode(&mut writer)?;
        }

        if !anyone_can_pay && sighash != SigHashType::Single && sighash != SigHashType::None {
            self.hash_sequence().consensus_encode(&mut writer)?;
        } else {
            zero_hash.consensus_encode(&mut writer)?;
        }

        // Elements: Push the hash issuance zero hash as required
        // If required implement for issuance, but not necessary as of now
        if !anyone_can_pay {
            self.hash_issuances().consensus_encode(&mut writer)?;
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
        if sighash != SigHashType::Single && sighash != SigHashType::None {
            self.hash_outputs().consensus_encode(&mut writer)?;
        } else if sighash == SigHashType::Single && input_index < self.tx.output.len() {
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
        sighash_type: SigHashType
    ) -> SigHash {
        let mut enc = SigHash::engine();
        self.encode_segwitv0_signing_data_to(&mut enc, input_index, script_code, value, sighash_type)
            .expect("engines don't error");
        SigHash::from_engine(enc)
    }
}

#[cfg(test)]
mod tests{
    use super::*;
    use encode::deserialize;
    use bitcoin::hashes::hex::FromHex;
    use bitcoin;

    fn test_segwit_sighash(tx: &str, script: &str, input_index: usize, value: &str, hash_type: SigHashType, expected_result: &str) {
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
        test_segwit_sighash("010000000001715df5ccebaf02ff18d6fae7263fa69fed5de59c900f4749556eba41bc7bf2af0000000000000000000201230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b2010000000124101100001f5175517551755175517551755175517551755175517551755175517551755101230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b2010000000005f5e100000000000000", "76a914f54a5851e9372b87810a8e60cdd2e7cfd80b6e3188ac", 0, "0850863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352", SigHashType::All, "e201b4019129a03ca0304989731c6dccde232c854d86fce999b7411da1e90048");
        test_segwit_sighash("010000000001715df5ccebaf02ff18d6fae7263fa69fed5de59c900f4749556eba41bc7bf2af0000000000000000000201230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b2010000000124101100001f5175517551755175517551755175517551755175517551755175517551755101230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b2010000000005f5e100000000000000", "76a914f54a5851e9372b87810a8e60cdd2e7cfd80b6e3188ac", 0, "0850863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352", SigHashType::None, "bfc6599816673083334ae82ac3459a2d0fef478d3e580e3ae203a28347502cb4");
        test_segwit_sighash("010000000001715df5ccebaf02ff18d6fae7263fa69fed5de59c900f4749556eba41bc7bf2af0000000000000000000201230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b2010000000124101100001f5175517551755175517551755175517551755175517551755175517551755101230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b2010000000005f5e100000000000000", "76a914f54a5851e9372b87810a8e60cdd2e7cfd80b6e3188ac", 0, "0850863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352", SigHashType::Single, "4bc8546e32d31c5415444138184696e80f49e537a083bfcc89be2ab41d962e76");
        test_segwit_sighash("010000000001715df5ccebaf02ff18d6fae7263fa69fed5de59c900f4749556eba41bc7bf2af0000000000000000000201230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b2010000000124101100001f5175517551755175517551755175517551755175517551755175517551755101230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b2010000000005f5e100000000000000", "76a914f54a5851e9372b87810a8e60cdd2e7cfd80b6e3188ac", 0, "0850863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352", SigHashType::AllPlusAnyoneCanPay, "b70ba5f4a1c2c48cd7f2104b2baa6a5c97987eb560916d39a5d427deb8b1dc2a");
        test_segwit_sighash("010000000001715df5ccebaf02ff18d6fae7263fa69fed5de59c900f4749556eba41bc7bf2af0000000000000000000201230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b2010000000124101100001f5175517551755175517551755175517551755175517551755175517551755101230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b2010000000005f5e100000000000000", "76a914f54a5851e9372b87810a8e60cdd2e7cfd80b6e3188ac", 0, "0850863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352", SigHashType::NonePlusAnyoneCanPay, "6d6a4749c09ffd9a8df4c5de5d939325d896009e18f94bb095c9d7d695a8465e");
        test_segwit_sighash("010000000001715df5ccebaf02ff18d6fae7263fa69fed5de59c900f4749556eba41bc7bf2af0000000000000000000201230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b2010000000124101100001f5175517551755175517551755175517551755175517551755175517551755101230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b2010000000005f5e100000000000000", "76a914f54a5851e9372b87810a8e60cdd2e7cfd80b6e3188ac", 0, "0850863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352", SigHashType::SinglePlusAnyoneCanPay, "7fc34367b42bf0e2bb78d8c20f45a64b81b2d4fbb59cbff8649322f619e88a0f");
        test_segwit_sighash("010000000001715df5ccebaf02ff18d6fae7263fa69fed5de59c900f4749556eba41bc7bf2af0000000000000000000201230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b2010000000124101100001f5175517551755175517551755175517551755175517551755175517551755101230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b2010000000005f5e100000000000000", "76a914f54a5851e9372b87810a8e60cdd2e7cfd80b6e3188ac", 0, "010000000005f5e100", SigHashType::All, "71141639d982f1a1a8901e32fb1a9e15a0ea168b37d33300a3c9619fc3767388");
        test_segwit_sighash("010000000001715df5ccebaf02ff18d6fae7263fa69fed5de59c900f4749556eba41bc7bf2af0000000000000000000201230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b2010000000124101100001f5175517551755175517551755175517551755175517551755175517551755101230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b2010000000005f5e100000000000000", "76a914f54a5851e9372b87810a8e60cdd2e7cfd80b6e3188ac", 0, "010000000005f5e100", SigHashType::None, "00730922d0e1d55b4b5fffafd087b06aeb44c4cedb58d8e182cbb9b87382cddb");
        test_segwit_sighash("010000000001715df5ccebaf02ff18d6fae7263fa69fed5de59c900f4749556eba41bc7bf2af0000000000000000000201230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b2010000000124101100001f5175517551755175517551755175517551755175517551755175517551755101230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b2010000000005f5e100000000000000", "76a914f54a5851e9372b87810a8e60cdd2e7cfd80b6e3188ac", 0, "010000000005f5e100", SigHashType::Single, "100063ea0923ef4432dd51c5756383530f28b31ffe9d50b59a11b94a63c84c78");
        test_segwit_sighash("010000000001715df5ccebaf02ff18d6fae7263fa69fed5de59c900f4749556eba41bc7bf2af0000000000000000000201230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b2010000000124101100001f5175517551755175517551755175517551755175517551755175517551755101230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b2010000000005f5e100000000000000", "76a914f54a5851e9372b87810a8e60cdd2e7cfd80b6e3188ac", 0, "010000000005f5e100", SigHashType::AllPlusAnyoneCanPay, "e1c4ddf5f723759f7d99d4f162155119160b1c6b765fdbdb25aedb2059769b74");
        test_segwit_sighash("010000000001715df5ccebaf02ff18d6fae7263fa69fed5de59c900f4749556eba41bc7bf2af0000000000000000000201230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b2010000000124101100001f5175517551755175517551755175517551755175517551755175517551755101230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b2010000000005f5e100000000000000", "76a914f54a5851e9372b87810a8e60cdd2e7cfd80b6e3188ac", 0, "010000000005f5e100", SigHashType::NonePlusAnyoneCanPay, "b0be275e0c69e89ef5c482fdf330038c3b2994ebce3e3639bb81456d15a95a7a");
        test_segwit_sighash("010000000001715df5ccebaf02ff18d6fae7263fa69fed5de59c900f4749556eba41bc7bf2af0000000000000000000201230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b2010000000124101100001f5175517551755175517551755175517551755175517551755175517551755101230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b2010000000005f5e100000000000000", "76a914f54a5851e9372b87810a8e60cdd2e7cfd80b6e3188ac", 0, "010000000005f5e100", SigHashType::SinglePlusAnyoneCanPay, "27c293da7a0f08e161fa2a77aeefa6743c929905597b5bcb28f2015fe648aa0c");

        // Test a issuance test with only sighash all
        test_segwit_sighash("010000000001715df5ccebaf02ff18d6fae7263fa69fed5de59c900f4749556eba41bc7bf2af000000800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000003e801000000000000000a0201230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b2010000000124101100001f5175517551755175517551755175517551755175517551755175517551755101230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b2010000000005f5e100000000000000", "76a914f54a5851e9372b87810a8e60cdd2e7cfd80b6e3188ac", 0, "0850863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352", SigHashType::All, "ea946ee417d5a16a1038b2c3b54d1b7b12a9f98c0dcb4684bf005eb1c27d0c92");
    }
}