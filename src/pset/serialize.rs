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

use std::io;

use bitcoin::PublicKey;
use {Script, SigHashType, Transaction, TxOut, Txid};
use encode::{self, serialize, Decodable};
use bitcoin::util::bip32::{ChildNumber, Fingerprint, KeySource};
use hashes::{hash160, ripemd160, sha256, sha256d, Hash};
use pset;

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

impl_pset_de_serialize!(Transaction);
impl_pset_de_serialize!(TxOut);
impl_pset_de_serialize!(u32);
impl_pset_de_serialize!(u64);
impl_pset_de_serialize!(Vec<Vec<u8>>); // scriptWitness
impl_pset_hash_de_serialize!(Txid);
impl_pset_hash_de_serialize!(ripemd160::Hash);
impl_pset_hash_de_serialize!(sha256::Hash);
impl_pset_hash_de_serialize!(hash160::Hash);
impl_pset_hash_de_serialize!(sha256d::Hash);

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
        PublicKey::from_slice(bytes)
            .map_err(|_| encode::Error::ParseFailed("invalid public key"))
    }
}

impl Serialize for KeySource {
    fn serialize(&self) -> Vec<u8> {
        let mut rv: Vec<u8> = Vec::with_capacity(4 + 4 * (self.1).as_ref().len());

        rv.append(&mut self.0.to_bytes().to_vec());

        for cnum in self.1.into_iter() {
            rv.append(&mut serialize(&u32::from(*cnum)))
        }

        rv
    }
}

impl Deserialize for KeySource {
    fn deserialize(bytes: &[u8]) -> Result<Self, encode::Error> {
        if bytes.len() < 4 {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into())
        }

        let fprint: Fingerprint = Fingerprint::from(&bytes[0..4]);
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

impl Serialize for SigHashType {
    fn serialize(&self) -> Vec<u8> {
        serialize(&self.as_u32())
    }
}

impl Deserialize for SigHashType {
    fn deserialize(bytes: &[u8]) -> Result<Self, encode::Error> {
        let raw: u32 = encode::deserialize(bytes)?;
        let rv: SigHashType = SigHashType::from_u32(raw);

        if rv.as_u32() == raw {
            Ok(rv)
        } else {
            Err(pset::Error::NonStandardSigHashType(raw).into())
        }
    }
}
