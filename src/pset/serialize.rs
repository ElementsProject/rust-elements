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

//! # PSET Serialization
//!
//! Defines traits used for (de)serializing PSET values into/from raw
//! bytes in PSET key-value pairs.

use std::convert::TryFrom;
use std::io;

use crate::confidential;
use crate::encode::{self, deserialize, deserialize_partial, serialize, Decodable, Encodable};
use crate::hashes::{hash160, ripemd160, sha256, sha256d, Hash};
use crate::transaction::TxOutWithWitness;
use crate::{AssetId, BlockHash, Script, Transaction, TxOut, Txid};
use crate::hex::ToHex;
use bitcoin::bip32::{ChildNumber, Fingerprint, KeySource};
use bitcoin::{self, VarInt};
use bitcoin::{PublicKey, key::XOnlyPublicKey};
use secp256k1_zkp::{self, RangeProof, SurjectionProof, Tweak};

use super::map::{PsbtSighashType, TapTree};
use crate::schnorr;
use crate::taproot::{ControlBlock, LeafVersion, TapBranchHash, TapLeafHash};

use crate::sighash::SchnorrSighashType;
use crate::taproot::TaprootBuilder;

/// A trait for serializing a value as raw data for insertion into PSET
/// key-value pairs.
pub trait Serialize {
    /// Serialize a value as raw data.
    fn serialize(&self) -> Vec<u8>;
}

/// A trait for deserializing a value from raw data in PSET key-value pairs.
pub trait Deserialize: Sized {
    /// Deserialize a value from raw data.
    fn deserialize(bytes: &[u8]) -> Result<Self, encode::Error>;
}

/// Encode an object into a hex-encoded string
pub fn serialize_hex<T: Serialize + ?Sized>(data: &T) -> String {
    Serialize::serialize(data)[..].to_hex()
}

impl_pset_de_serialize!(Transaction);
impl_pset_de_serialize!(TxOut);
impl_pset_de_serialize!(TxOutWithWitness);
impl_pset_de_serialize!(AssetId);
impl_pset_de_serialize!(u8);
impl_pset_de_serialize!(u32);
impl_pset_de_serialize!(u64);
impl_pset_de_serialize!(crate::LockTime);
impl_pset_de_serialize!(crate::Sequence);
impl_pset_de_serialize!(crate::locktime::Height);
impl_pset_de_serialize!(crate::locktime::Time);
impl_pset_de_serialize!([u8; 32]);
impl_pset_de_serialize!(VarInt);
impl_pset_de_serialize!(Vec<Vec<u8>>); // scriptWitness
impl_pset_hash_de_serialize!(Txid);
impl_pset_hash_de_serialize!(ripemd160::Hash);
impl_pset_hash_de_serialize!(sha256::Hash);
impl_pset_hash_de_serialize!(hash160::Hash);
impl_pset_hash_de_serialize!(sha256d::Hash);
impl_pset_hash_de_serialize!(BlockHash);
impl_pset_hash_de_serialize!(TapLeafHash);
impl_pset_hash_de_serialize!(TapBranchHash);

// required for pegin bitcoin::Transactions
impl_pset_de_serialize!(bitcoin::Transaction);

// taproot
impl_pset_de_serialize!(Vec<TapLeafHash>);

impl Serialize for Tweak {
    fn serialize(&self) -> Vec<u8> {
        encode::serialize(self.as_ref())
    }
}

impl Deserialize for Tweak {
    fn deserialize(bytes: &[u8]) -> Result<Self, encode::Error> {
        let x = deserialize::<[u8; 32]>(bytes)?;
        Tweak::from_slice(&x).map_err(|_| encode::Error::ParseFailed("invalid Tweak"))
    }
}

impl Serialize for Script {
    fn serialize(&self) -> Vec<u8> {
        self.to_bytes()
    }
}

impl Deserialize for Script {
    fn deserialize(bytes: &[u8]) -> Result<Self, encode::Error> {
        Ok(Self::from(bytes.to_vec()))
    }
}

impl Serialize for PublicKey {
    fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.write_into(&mut buf).expect("vecs don't error");
        buf
    }
}

impl Deserialize for PublicKey {
    fn deserialize(bytes: &[u8]) -> Result<Self, encode::Error> {
        PublicKey::from_slice(bytes).map_err(|_| encode::Error::ParseFailed("invalid public key"))
    }
}

impl Serialize for KeySource {
    fn serialize(&self) -> Vec<u8> {
        let mut rv: Vec<u8> = Vec::with_capacity(key_source_len(self));

        rv.append(&mut self.0.to_bytes().to_vec());

        for cnum in self.1.into_iter() {
            rv.append(&mut serialize(&u32::from(*cnum)))
        }

        rv
    }
}

impl Deserialize for KeySource {
    fn deserialize(bytes: &[u8]) -> Result<Self, encode::Error> {
        let prefix = match <[u8; 4]>::try_from(&bytes[0..4]) {
            Ok(prefix) => prefix,
            Err(_) => return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into()),
        };

        let fprint: Fingerprint = Fingerprint::from(prefix);
        let mut dpath: Vec<ChildNumber> = Default::default();

        let mut d = &bytes[4..];
        while !d.is_empty() {
            match u32::consensus_decode(&mut d) {
                Ok(index) => dpath.push(index.into()),
                Err(e) => return Err(e),
            }
        }

        Ok((fprint, dpath.into()))
    }
}

// partial sigs
impl Serialize for Vec<u8> {
    fn serialize(&self) -> Vec<u8> {
        self.clone()
    }
}

impl Deserialize for Vec<u8> {
    fn deserialize(bytes: &[u8]) -> Result<Self, encode::Error> {
        Ok(bytes.to_vec())
    }
}

impl Serialize for PsbtSighashType {
    fn serialize(&self) -> Vec<u8> {
        serialize(&self.to_u32())
    }
}

impl Deserialize for PsbtSighashType {
    fn deserialize(bytes: &[u8]) -> Result<Self, encode::Error> {
        let raw: u32 = encode::deserialize(bytes)?;
        Ok(PsbtSighashType::from_u32(raw))
    }
}

impl Serialize for confidential::Value {
    fn serialize(&self) -> Vec<u8> {
        match self {
            confidential::Value::Null => vec![], // should never be invoked
            confidential::Value::Explicit(x) => Serialize::serialize(x),
            y => encode::serialize(y), // confidential can serialized as is
        }
    }
}

impl Deserialize for confidential::Value {
    fn deserialize(bytes: &[u8]) -> Result<Self, encode::Error> {
        match bytes.len() {
            8 => Ok(confidential::Value::Explicit(encode::deserialize(bytes)?)),
            _ => Ok(encode::deserialize(bytes)?),
        }
    }
}

impl Serialize for secp256k1_zkp::PedersenCommitment {
    fn serialize(&self) -> Vec<u8> {
        self.serialize().to_vec()
    }
}

impl Deserialize for secp256k1_zkp::PedersenCommitment {
    fn deserialize(bytes: &[u8]) -> Result<Self, encode::Error> {
        let comm = secp256k1_zkp::PedersenCommitment::from_slice(bytes)?;
        Ok(comm)
    }
}

impl Serialize for secp256k1_zkp::Generator {
    fn serialize(&self) -> Vec<u8> {
        self.serialize().to_vec()
    }
}

impl Deserialize for secp256k1_zkp::Generator {
    fn deserialize(bytes: &[u8]) -> Result<Self, encode::Error> {
        let comm = secp256k1_zkp::Generator::from_slice(bytes)?;
        Ok(comm)
    }
}

impl Serialize for confidential::Asset {
    fn serialize(&self) -> Vec<u8> {
        match self {
            confidential::Asset::Null => vec![], // should never be invoked
            confidential::Asset::Explicit(x) => Serialize::serialize(x),
            y => encode::serialize(y), // confidential can serialized as is
        }
    }
}

impl Deserialize for confidential::Asset {
    fn deserialize(bytes: &[u8]) -> Result<Self, encode::Error> {
        match bytes.len() {
            32 => Ok(confidential::Asset::Explicit(encode::deserialize(bytes)?)),
            _ => Ok(encode::deserialize(bytes)?),
        }
    }
}

impl Serialize for Box<RangeProof> {
    fn serialize(&self) -> Vec<u8> {
        RangeProof::serialize(self)
    }
}

impl Deserialize for Box<RangeProof> {
    fn deserialize(bytes: &[u8]) -> Result<Self, encode::Error> {
        let prf = RangeProof::from_slice(bytes)
            .map_err(|_| encode::Error::ParseFailed("Invalid Rangeproof"))?;
        Ok(Box::new(prf))
    }
}

impl Serialize for Box<SurjectionProof> {
    fn serialize(&self) -> Vec<u8> {
        SurjectionProof::serialize(self)
    }
}

impl Deserialize for Box<SurjectionProof> {
    fn deserialize(bytes: &[u8]) -> Result<Self, encode::Error> {
        let prf = SurjectionProof::from_slice(bytes)
            .map_err(|_| encode::Error::ParseFailed("Invalid SurjectionProof"))?;
        Ok(Box::new(prf))
    }
}

// Taproot related ser/deser
impl Serialize for XOnlyPublicKey {
    fn serialize(&self) -> Vec<u8> {
        XOnlyPublicKey::serialize(self).to_vec()
    }
}

impl Deserialize for XOnlyPublicKey {
    fn deserialize(bytes: &[u8]) -> Result<Self, encode::Error> {
        XOnlyPublicKey::from_slice(bytes)
            .map_err(|_| encode::Error::ParseFailed("Invalid xonly public key"))
    }
}

impl Serialize for schnorr::SchnorrSig {
    fn serialize(&self) -> Vec<u8> {
        self.to_vec()
    }
}

impl Deserialize for schnorr::SchnorrSig {
    fn deserialize(bytes: &[u8]) -> Result<Self, encode::Error> {
        match bytes.len() {
            65 => {
                let hash_ty = SchnorrSighashType::from_u8(bytes[64])
                    .ok_or(encode::Error::ParseFailed("Invalid Sighash type"))?;
                let sig = secp256k1_zkp::schnorr::Signature::from_slice(&bytes[..64])
                    .map_err(|_| encode::Error::ParseFailed("Invalid Schnorr signature"))?;
                Ok(schnorr::SchnorrSig { sig, hash_ty })
            }
            64 => {
                let sig = secp256k1_zkp::schnorr::Signature::from_slice(&bytes[..64])
                    .map_err(|_| encode::Error::ParseFailed("Invalid Schnorr signature"))?;
                Ok(schnorr::SchnorrSig {
                    sig,
                    hash_ty: SchnorrSighashType::Default,
                })
            }
            _ => Err(encode::Error::ParseFailed("Invalid Schnorr signature len")),
        }
    }
}

impl Serialize for (XOnlyPublicKey, TapLeafHash) {
    fn serialize(&self) -> Vec<u8> {
        let ser_pk = self.0.serialize();
        let mut buf = Vec::with_capacity(ser_pk.len() + TapLeafHash::LEN);
        buf.extend(&ser_pk);
        buf.extend(&self.1.to_byte_array());
        buf
    }
}

impl Deserialize for (XOnlyPublicKey, TapLeafHash) {
    fn deserialize(bytes: &[u8]) -> Result<Self, encode::Error> {
        if bytes.len() < 32 {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into());
        }
        let a: XOnlyPublicKey = Deserialize::deserialize(&bytes[..32])?;
        let b: TapLeafHash = Deserialize::deserialize(&bytes[32..])?;
        Ok((a, b))
    }
}

impl Serialize for ControlBlock {
    fn serialize(&self) -> Vec<u8> {
        ControlBlock::serialize(self)
    }
}

impl Deserialize for ControlBlock {
    fn deserialize(bytes: &[u8]) -> Result<Self, encode::Error> {
        Self::from_slice(bytes).map_err(|_| encode::Error::ParseFailed("Invalid control block"))
    }
}

// Versioned Script
impl Serialize for (Script, LeafVersion) {
    fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.0.len() + 1);
        buf.extend(self.0.as_bytes());
        buf.push(self.1.as_u8());
        buf
    }
}

impl Deserialize for (Script, LeafVersion) {
    fn deserialize(bytes: &[u8]) -> Result<Self, encode::Error> {
        if bytes.is_empty() {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into());
        }
        // The last byte is LeafVersion.
        let script = Script::deserialize(&bytes[..bytes.len() - 1])?;
        let leaf_ver = LeafVersion::from_u8(bytes[bytes.len() - 1])
            .map_err(|_| encode::Error::ParseFailed("invalid leaf version"))?;
        Ok((script, leaf_ver))
    }
}

impl Serialize for (Vec<TapLeafHash>, KeySource) {
    fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(32 * self.0.len() + key_source_len(&self.1));
        self.0
            .consensus_encode(&mut buf)
            .expect("Vecs don't error allocation");
        // TODO: Add support for writing into a writer for key-source
        buf.extend(self.1.serialize());
        buf
    }
}

impl Deserialize for (Vec<TapLeafHash>, KeySource) {
    fn deserialize(bytes: &[u8]) -> Result<Self, encode::Error> {
        let (leafhash_vec, consumed) = deserialize_partial::<Vec<TapLeafHash>>(bytes)?;
        let key_source = KeySource::deserialize(&bytes[consumed..])?;
        Ok((leafhash_vec, key_source))
    }
}

impl Serialize for TapTree {
    fn serialize(&self) -> Vec<u8> {
        match (self.0.branch().len(), self.0.branch().last()) {
            (1, Some(Some(root))) => {
                let mut buf = Vec::new();
                for leaf_info in root.leaves.iter() {
                    // # Cast Safety:
                    //
                    // TaprootMerkleBranch can only have len atmost 128(TAPROOT_CONTROL_MAX_NODE_COUNT).
                    // safe to cast from usize to u8
                    buf.push(leaf_info.merkle_branch.as_inner().len() as u8);
                    buf.push(leaf_info.ver.as_u8());
                    leaf_info
                        .script
                        .consensus_encode(&mut buf)
                        .expect("Vecs dont err");
                }
                buf
            }
            // This should be unreachable as we Taptree is already finalized
            _ => unreachable!(),
        }
    }
}

impl Deserialize for TapTree {
    fn deserialize(bytes: &[u8]) -> Result<Self, encode::Error> {
        let mut builder = TaprootBuilder::new();
        let mut bytes_iter = bytes.iter();
        while let Some(depth) = bytes_iter.next() {
            let version = bytes_iter
                .next()
                .ok_or(encode::Error::ParseFailed("Invalid Taproot Builder"))?;
            let (script, consumed) = deserialize_partial::<Script>(bytes_iter.as_slice())?;
            if consumed > 0 {
                bytes_iter.nth(consumed - 1);
            }

            let leaf_version = LeafVersion::from_u8(*version)
                .map_err(|_| encode::Error::ParseFailed("Leaf Version Error"))?;
            builder = builder
                .add_leaf_with_ver(usize::from(*depth), script, leaf_version)
                .map_err(|_| encode::Error::ParseFailed("Tree not in DFS order"))?;
        }
        if builder.is_complete() {
            Ok(TapTree(builder))
        } else {
            Err(encode::Error::ParseFailed("Incomplete taproot Tree"))
        }
    }
}

// Helper function to compute key source len
fn key_source_len(key_source: &KeySource) -> usize {
    4 + 4 * (key_source.1).as_ref().len()
}
