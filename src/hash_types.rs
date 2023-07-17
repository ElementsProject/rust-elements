// Rust Elements Library
// Written in 2020 by
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

//! File defines types for hashes used throughout the library. These types are needed in order
//! to avoid mixing data of the same hash format (like SHA256d) but of different meaning
//! (transaction id, block hash etc).

use crate:: hashes::{hash_newtype, hash160, sha256, sha256d, Hash};
use bitcoin::secp256k1::ThirtyTwoByteHash;

macro_rules! impl_hashencode {
    ($hashtype:ident) => {
        impl $crate::encode::Encodable for $hashtype {
            fn consensus_encode<W: std::io::Write>(&self, w: W) -> Result<usize, crate::encode::Error> {
                self.0.consensus_encode(w)
            }
        }

        impl $crate::encode::Decodable for $hashtype {
            fn consensus_decode<R: std::io::Read>(r: R) -> Result<Self, $crate::encode::Error> {
                Ok(Self::from_byte_array(<<$hashtype as $crate::hashes::Hash>::Bytes>::consensus_decode(r)?))
            }
        }
    };
}

hash_newtype! {
    /// An elements transaction ID
    pub struct Txid(sha256d::Hash); 
    /// An elements witness transaction ID
    pub struct Wtxid(sha256d::Hash); 
    /// An elements blockhash
    pub struct BlockHash(sha256d::Hash); 

    /// "Hash of the transaction according to the signature algorithm"
    pub struct Sighash(sha256d::Hash); 

    /// A hash of a public key.
    pub struct PubkeyHash(hash160::Hash);
    /// A hash of Bitcoin Script bytecode.
    pub struct ScriptHash(hash160::Hash);
    /// SegWit version of a public key hash.
    pub struct WPubkeyHash(hash160::Hash);
    /// SegWit version of a Bitcoin Script bytecode hash.
    pub struct WScriptHash(sha256::Hash);

    /// A hash of the Merkle tree branch or root for transactions
    pub struct TxMerkleNode(sha256d::Hash);
}


impl_hashencode!(Txid);
impl_hashencode!(Wtxid);
impl_hashencode!(Sighash);
impl_hashencode!(BlockHash);
impl_hashencode!(TxMerkleNode);

impl ThirtyTwoByteHash for Sighash {
    fn into_32(self) -> [u8; 32] {
        self.0.to_byte_array()
    }
}
