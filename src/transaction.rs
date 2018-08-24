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

use std::fmt;

use bitcoin::network::encodable::{ConsensusEncodable, ConsensusDecodable, VarInt};
use bitcoin::network::serialize::{self, BitcoinHash, SimpleEncoder, SimpleDecoder};
use bitcoin::blockdata::opcodes;
use bitcoin::blockdata::script::{Script, Instruction};
use bitcoin::util::hash::Sha256dHash;

use confidential;

/// Description of an asset issuance in a transaction input
#[derive(Copy, Clone, Debug, Default, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub struct AssetIssuance {
    /// Zero for a new asset issuance; otherwise a blinding factor for the input
    pub asset_blinding_nonce: [u8; 32],
    /// Freeform entropy field
    pub asset_entropy: [u8; 32],
    /// Amount of asset to issue
    pub amount: confidential::Value,
    /// Amount of inflation keys to issue
    pub inflation_keys: confidential::Value,
}
serde_struct_impl!(AssetIssuance, asset_blinding_nonce, asset_entropy, amount, inflation_keys);
impl_consensus_encoding!(AssetIssuance, asset_blinding_nonce, asset_entropy, amount, inflation_keys);

/// A reference to a transaction output
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub struct OutPoint {
    /// The referenced transaction's txid
    pub txid: Sha256dHash,
    /// The index of the referenced output in its transaction's vout
    pub vout: u32,
    /// Flag indicating that this outpoint refers to something on the main chain
    pub is_pegin: bool,
    /// Flag indicating that this outpoint has an asset issuance attached
    pub has_issuance: bool,
}
serde_struct_impl!(OutPoint, txid, vout, is_pegin, has_issuance);

impl Default for OutPoint {
    /// Coinbase outpoint
    fn default() -> OutPoint {
        OutPoint {
            txid: Sha256dHash::default(),
            vout: 0xffffffff,
            is_pegin: false,
            has_issuance: false,
        }
    }
}

impl<S: SimpleEncoder> ConsensusEncodable<S> for OutPoint {
    fn consensus_encode(&self, s: &mut S) -> Result<(), serialize::Error> {
        let mut vout = self.vout;
        if self.is_pegin {
            vout |= 1 << 30;
        }
        if self.has_issuance {
            vout |= 1 << 31;
        }
        self.txid.consensus_encode(s)?;
        vout.consensus_encode(s)
    }
}

impl<D: SimpleDecoder> ConsensusDecodable<D> for OutPoint {
    fn consensus_decode(d: &mut D) -> Result<OutPoint, serialize::Error> {
        let txid = Sha256dHash::consensus_decode(d)?;
        let mut vout = u32::consensus_decode(d)?;
        let is_pegin;
        let has_issuance;

        // Pegin/issuance flags are encoded into the high bits of `vout`, *except*
        // if vout is all 1's; this indicates a coinbase transaction
        if vout == 0xffffffff {
            is_pegin = false;
            has_issuance = false;
        } else {
            is_pegin = vout & (1 << 30) != 0;
            has_issuance = vout & (1 << 31) != 0;
            vout &= !(3 << 30);
        }

        Ok(OutPoint {
            txid: txid,
            vout: vout,
            is_pegin: is_pegin,
            has_issuance: has_issuance,
        })
    }
}

impl fmt::Display for OutPoint {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match (self.is_pegin, self.has_issuance) {
            (false, false) => f.write_str("[  ]")?,
            (false, true)  => f.write_str("[ I]")?,
            (true,  false) => f.write_str("[P ]")?,
            (true,  true)  => f.write_str("[PI]")?,
        }
        write!(f, "{}:{}", self.txid, self.vout)
    }
}

/// Transaction input witness
#[derive(Clone, Default, PartialEq, Eq, Debug, Hash)]
pub struct TxInWitness {
    /// Amount rangeproof
    pub amount_rangeproof: Vec<u8>,
    /// Rangeproof for inflation keys
    pub inflation_keys_rangeproof: Vec<u8>,
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
        self.amount_rangeproof.is_empty() &&
            self.inflation_keys_rangeproof.is_empty() &&
            self.script_witness.is_empty() &&
            self.pegin_witness.is_empty()
    }
}

/// A transaction input, which defines old coins to be consumed
#[derive(Clone, PartialEq, Eq, Debug, Hash)]
pub struct TxIn {
    /// The reference to the previous output that is being used an an input
    pub previous_output: OutPoint,
    /// The script which pushes values on the stack which will cause
    /// the referenced output's script to accept
    pub script_sig: Script,
    /// The sequence number, which suggests to miners which of two
    /// conflicting transactions should be preferred, or 0xFFFFFFFF
    /// to ignore this feature. This is generally never used since
    /// the miner behaviour cannot be enforced.
    pub sequence: u32,
    /// Asset issuance data
    pub asset_issuance: AssetIssuance,
    /// Witness data - not deserialized/serialized as part of a `TxIn` object
    /// (rather as part of its containing transaction, if any) but is logically
    /// part of the txin.
    pub witness: TxInWitness,
}
serde_struct_impl!(TxIn, previous_output, script_sig, sequence, asset_issuance, witness);

impl<S: SimpleEncoder> ConsensusEncodable<S> for TxIn {
    fn consensus_encode(&self, s: &mut S) -> Result<(), serialize::Error> {
        self.previous_output.consensus_encode(s)?;
        self.script_sig.consensus_encode(s)?;
        self.sequence.consensus_encode(s)?;
        if self.has_issuance() {
            self.asset_issuance.consensus_encode(s)?;
        }
        Ok(())
    }
}

impl<D: SimpleDecoder> ConsensusDecodable<D> for TxIn {
    fn consensus_decode(d: &mut D) -> Result<TxIn, serialize::Error> {
        let outp = OutPoint::consensus_decode(d)?;
        let script_sig = Script::consensus_decode(d)?;
        let sequence = u32::consensus_decode(d)?;
        let issuance;
        if outp.has_issuance {
            issuance = AssetIssuance::consensus_decode(d)?;
        } else {
            issuance = AssetIssuance::default();
        }
        Ok(TxIn {
            previous_output: outp,
            script_sig: script_sig,
            sequence: sequence,
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
        self.previous_output.is_pegin
    }

    /// Helper to determine whether an input has an asset issuance attached
    pub fn has_issuance(&self) -> bool {
        self.previous_output.has_issuance
    }
}

/// Transaction output witness
#[derive(Clone, Default, PartialEq, Eq, Debug, Hash)]
pub struct TxOutWitness {
    /// Surjection proof showing that the asset commitment is legitimate
    pub surjection_proof: Vec<u8>,
    /// Rangeproof showing that the value commitment is legitimate
    pub rangeproof: Vec<u8>,
}
serde_struct_impl!(TxOutWitness, surjection_proof, rangeproof);
impl_consensus_encoding!(TxOutWitness, surjection_proof, rangeproof);

impl TxOutWitness {
    /// Whether this witness is null
    pub fn is_empty(&self) -> bool {
        self.surjection_proof.is_empty() && self.rangeproof.is_empty()
    }
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

impl<S: SimpleEncoder> ConsensusEncodable<S> for TxOut {
    fn consensus_encode(&self, s: &mut S) -> Result<(), serialize::Error> {
        self.asset.consensus_encode(s)?;
        self.value.consensus_encode(s)?;
        self.nonce.consensus_encode(s)?;
        self.script_pubkey.consensus_encode(s)
    }
}

impl<D: SimpleDecoder> ConsensusDecodable<D> for TxOut {
    fn consensus_decode(d: &mut D) -> Result<TxOut, serialize::Error> {
        Ok(TxOut {
            asset: ConsensusDecodable::consensus_decode(d)?,
            value: ConsensusDecodable::consensus_decode(d)?,
            nonce: ConsensusDecodable::consensus_decode(d)?,
            script_pubkey: ConsensusDecodable::consensus_decode(d)?,
            witness: TxOutWitness::default(),
        })
    }
}

impl TxOut {
    /// Whether this data represents nulldata (OP_RETURN followed by pushes)
    pub fn is_null_data(&self) -> bool {
        let mut iter = self.script_pubkey.iter(false);
        if iter.next() == Some(Instruction::Op(opcodes::All::OP_RETURN)) {
            for push in iter {
                match push {
                    Instruction::Op(op) if op as u8 > opcodes::All::OP_PUSHNUM_16 as u8 => {}
                    Instruction::PushBytes(..) => {},
                    _ => return false
                }
            }
            true
        } else {
            false
        }
    }

    /// Whether or not this output is a fee output
    pub fn is_fee(&self) -> bool {
        self.script_pubkey.is_empty()
    }

    /// Extracts the minimum value from the rangeproof, if there is one, or returns 0.
    pub fn minimum_value(&self) -> u64 {
        let min_value = if self.script_pubkey.is_op_return() { 0 } else { 1 };

        match self.value {
            confidential::Value::Null => min_value,
            confidential::Value::Explicit(n) => n,
            confidential::Value::Confidential(..) => {
                if self.witness.rangeproof.is_empty() {
                    min_value
                } else {
                    debug_assert!(self.witness.rangeproof.len() > 10);

                    let has_nonzero_range = self.witness.rangeproof[0] & 64 == 64;
                    let has_min = self.witness.rangeproof[0] & 32 == 32;

                    if !has_min {
                        min_value
                    } else if has_nonzero_range {
                        serialize::deserialize::<u64>(&self.witness.rangeproof[2..10])
                            .expect("any 8 bytes is a u64")
                            .swap_bytes()  // min-value is BE
                    } else {
                        serialize::deserialize::<u64>(&self.witness.rangeproof[1..9])
                            .expect("any 8 bytes is a u64")
                            .swap_bytes()  // min-value is BE
                    }
                }
            }
        }
    }
}

/// Elements transaction
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct Transaction {
    /// Transaction version field (should always be 2)
    pub version: u32,
    /// Transaction locktime
    pub lock_time: u32,
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
    pub fn get_weight(&self) -> usize {
        let witness_flag = self.has_witness();

        let input_weight = self.input.iter().map(|input| {
            4 * (
                32 + 4 + 4 + // output + nSequence
                VarInt(input.script_sig.len() as u64).encoded_length() as usize +
                input.script_sig.len() + if input.has_issuance() {
                    64 +
                    input.asset_issuance.amount.encoded_length() +
                    input.asset_issuance.inflation_keys.encoded_length()
                } else {
                    0
                }
            ) + if witness_flag {
                VarInt(input.witness.amount_rangeproof.len() as u64).encoded_length() as usize +
                input.witness.amount_rangeproof.len() +
                VarInt(input.witness.inflation_keys_rangeproof.len() as u64).encoded_length() as usize +
                input.witness.inflation_keys_rangeproof.len() +
                VarInt(input.witness.script_witness.len() as u64).encoded_length() as usize +
                input.witness.script_witness.iter().map(|wit|
                    VarInt(wit.len() as u64).encoded_length() as usize +
                    wit.len()
                ).sum::<usize>() +
                VarInt(input.witness.pegin_witness.len() as u64).encoded_length() as usize +
                input.witness.pegin_witness.iter().map(|wit|
                    VarInt(wit.len() as u64).encoded_length() as usize +
                    wit.len()
                ).sum::<usize>()
            } else {
                0
            }
        }).sum::<usize>();

        let output_weight = self.output.iter().map(|output| {
            4 * (
                output.asset.encoded_length() +
                output.value.encoded_length() +
                output.nonce.encoded_length() +
                VarInt(output.script_pubkey.len() as u64).encoded_length() as usize +
                output.script_pubkey.len()
            ) + if witness_flag {
                VarInt(output.witness.surjection_proof.len() as u64).encoded_length() as usize +
                output.witness.surjection_proof.len() +
                VarInt(output.witness.rangeproof.len() as u64).encoded_length() as usize +
                output.witness.rangeproof.len()
            } else {
                0
            }
        }).sum::<usize>();

        4 * (
            4 + // version
            4 + // locktime
            VarInt(self.input.len() as u64).encoded_length() as usize +
            VarInt(self.output.len() as u64).encoded_length() as usize +
            1 // segwit flag byte (note this is *not* witness data in Elements)
        ) + input_weight + output_weight
    }

    /// The txid of the transaction. To get its hash, use `BitcoinHash::bitcoin_hash()`.
    pub fn txid(&self) -> Sha256dHash {
        use bitcoin::util::hash::Sha256dEncoder;

        let mut enc = Sha256dEncoder::new();
        self.version.consensus_encode(&mut enc).unwrap();
        0u8.consensus_encode(&mut enc).unwrap();
        self.input.consensus_encode(&mut enc).unwrap();
        self.output.consensus_encode(&mut enc).unwrap();
        self.lock_time.consensus_encode(&mut enc).unwrap();
        enc.into_hash()
    }
}

impl BitcoinHash for Transaction {
    /// To get a transaction's txid, which is usually what you want, use the `txid` method.
    fn bitcoin_hash(&self) -> Sha256dHash {
        use bitcoin::util::hash::Sha256dEncoder;

        let mut enc = Sha256dEncoder::new();
        self.consensus_encode(&mut enc).unwrap();
        enc.into_hash()
    }
}

impl<S: SimpleEncoder> ConsensusEncodable<S> for Transaction {
    fn consensus_encode(&self, s: &mut S) -> Result<(), serialize::Error> {
        self.version.consensus_encode(s)?;

        let wit_flag = self.has_witness();
        if wit_flag {
            1u8.consensus_encode(s)?;
        } else {
            0u8.consensus_encode(s)?;
        }
        self.input.consensus_encode(s)?;
        self.output.consensus_encode(s)?;
        self.lock_time.consensus_encode(s)?;

        if wit_flag {
            for i in &self.input {
                i.witness.consensus_encode(s)?;
            }
            for o in &self.output {
                o.witness.consensus_encode(s)?;
            }
        }
        Ok(())
    }
}

impl<D: SimpleDecoder> ConsensusDecodable<D> for Transaction {
    fn consensus_decode(d: &mut D) -> Result<Transaction, serialize::Error> {
        let version = u32::consensus_decode(d)?;
        let wit_flag = u8::consensus_decode(d)?;
        let mut input = Vec::<TxIn>::consensus_decode(d)?;
        let mut output = Vec::<TxOut>::consensus_decode(d)?;
        let lock_time = u32::consensus_decode(d)?;

        match wit_flag {
            0 => Ok(Transaction {
                version: version,
                input: input,
                output: output,
                lock_time: lock_time,
            }),
            1 => {
                for i in &mut input {
                    i.witness = ConsensusDecodable::consensus_decode(d)?;
                }
                for o in &mut output {
                    o.witness = ConsensusDecodable::consensus_decode(d)?;
                }
                if input.iter().all(|input| input.witness.is_empty()) &&
                    output.iter().all(|output| output.witness.is_empty()) {
                    Err(serialize::Error::ParseFailed("witness flag set but no witnesses were given"))
                } else {
                    Ok(Transaction {
                        version: version,
                        input: input,
                        output: output,
                        lock_time: lock_time,
                    })
                }
            }
            _ => Err(serialize::Error::ParseFailed("bad witness flag in tx")),
        }
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::network::serialize::BitcoinHash;

    use Transaction;
    use confidential;

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
            tx.bitcoin_hash().to_string(),
            "758f784bdfa89b62c8b882542afb46074d3851a6da997199bcfb7cc6daed3cf2"
        );
        assert_eq!(
            tx.txid().to_string(),
            "758f784bdfa89b62c8b882542afb46074d3851a6da997199bcfb7cc6daed3cf2"
        );
        assert_eq!(tx.input.len(), 1);
        assert_eq!(tx.output.len(), 2);
        assert_eq!(tx.output[0].is_fee(), false);
        assert_eq!(tx.output[1].is_fee(), true);
        assert_eq!(tx.output[0].value, confidential::Value::Explicit(9999996700));
        assert_eq!(tx.output[1].value, confidential::Value::Explicit(      3300));
        assert_eq!(tx.output[0].minimum_value(), 9999996700);
        assert_eq!(tx.output[1].minimum_value(),       3300);

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
            tx.bitcoin_hash().to_string(),
            "7ac6c1400003162ab667406221656f06dad902c70f96ee703f3f5f9f09df4bb9"
        );
        assert_eq!(
            tx.txid().to_string(),
            "d606b563122409191e3b114a41d5611332dc58237ad5d2dccded302664fd56c4"
        );
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
            tx.bitcoin_hash().to_string(),
            "69e214ecad13b954208084572a6dedc264a016b953d71901f5aa1706d5f4916a"
        );
        assert_eq!(
            tx.txid().to_string(),
            "cc1f895908af2509e55719e662acf4a50ca4dcf0454edd718459241745e2b0aa"
        );
        assert_eq!(tx.input.len(), 1);
        assert_eq!(tx.input[0].is_coinbase(), true);
        assert_eq!(tx.is_coinbase(), true);

        assert_eq!(tx.output.len(), 2);
        assert_eq!(tx.output[0].is_null_data(), true);
        assert_eq!(tx.output[1].is_null_data(), true);

    }
}

