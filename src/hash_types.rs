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

//! File defines types for hashes used throughout the library.
//!
//! These types are needed in order
//! to avoid mixing data of the same hash format (like `SHA256d`) but of different meaning
//! (transaction id, block hash etc).

use crate::hashes::{hash160, hash_newtype, sha256, sha256d, Hash};

// Re-export bitcoin's pubkeyhash types. We already re-export bitcoin's `PublicKey` type.
pub use bitcoin::{PubkeyHash, WPubkeyHash};

macro_rules! impl_hashencode {
    ($hashtype:ident) => {
        impl $crate::encode::Encodable for $hashtype {
            fn consensus_encode<W: std::io::Write>(
                &self,
                w: W,
            ) -> Result<usize, crate::encode::Error> {
                self.0.consensus_encode(w)
            }
        }

        impl $crate::encode::Decodable for $hashtype {
            fn consensus_decode<R: std::io::Read>(r: R) -> Result<Self, $crate::encode::Error> {
                Ok(Self::from_byte_array(
                    <<$hashtype as $crate::hashes::Hash>::Bytes>::consensus_decode(r)?,
                ))
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

    /// A hash of Bitcoin Script bytecode.
    pub struct ScriptHash(hash160::Hash);
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

#[cfg(test)]
#[cfg(feature = "serde")]
mod serde_tests {
    use super::*;
    use crate::{AssetEntropy, AssetId, ContractHash, DynafedRoot};
    use crate::dynafed::{ElidedRoot, ParamsRoot};

    /// An arbitrary test vector.
    ///
    /// Mainly its goal is to make sure we don't mess up and reverse stuff we don't
    /// intend to reverse, or vice-versa, so its only requirement is that it not be
    /// invariant under reversal.
    const TEST_VECTOR: [u8; 32] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x00, 0x00, 0x00, 0x00, 0x11, 0x22, 0x33, 0x44,
        0xff, 0xff, 0xff, 0xff, 0x11, 0x22, 0x33, 0x44,
    ];

    /// The vector encoded as CBOR
    const CBOR: [u8; 34] = [
        0x58, 0x20,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x00, 0x00, 0x00, 0x00, 0x11, 0x22, 0x33, 0x44,
        0xff, 0xff, 0xff, 0xff, 0x11, 0x22, 0x33, 0x44,
    ];
    /// The vector encoded as JSON (non-reversed hash)
    const FORWARD_JSON: &str = "\"0102030405060708090a0b0c0d0e0f100000000011223344ffffffff11223344\"";
    /// The vector encoded as JSON (reversed hash)
    const REVERSED_JSON: &str = "\"44332211ffffffff4433221100000000100f0e0d0c0b0a090807060504030201\"";

    /// Constructs a test which attempts to (de-)serialize the 32-byte hash `TEST_VECTOR`,
    ///
    /// Checks that serialization works, matches the given target, and can deserialize
    /// to match the original value.
    macro_rules! serde_rtt_test32 {
        ($testname:ident, $ty:ty, $json:expr) => {
            #[test]
            fn $testname() {
                let obj = <$ty>::from_byte_array(TEST_VECTOR);
                // JSON (human-readable) round-trip
                let enc_json = serde_json::to_string(&obj).expect("encode json");
                assert_eq!(
                    enc_json,
                    $json,
                    "encoded JSON did not match target '{}'", $json
                );
                let dec_json: $ty = serde_json::from_str(&enc_json).expect("decode json");
                assert_eq!(
                    dec_json,
                    obj,
                    "decoded JSON did not match object '{}'", obj
                );

                // CBOR (non-human-readable) round-trip
                let enc_cbor = serde_cbor::to_vec(&obj).expect("encode cbor");
                assert_eq!(
                    enc_cbor,
                    CBOR,
                    "encoded CBOR did not match target '{:?}'", CBOR
                );
                let dec_cbor: $ty = serde_cbor::from_slice(&enc_cbor).expect("decode cbor");
                assert_eq!(
                    dec_cbor,
                    obj,
                    "decoded CBOR did not match object '{}'", obj
                );

                // While we're here, do a string round-trip test
                let s = obj.to_string();
                assert_eq!(
                    s,
                    $json[1..65],
                    "encoded string did not match target '{:?}'", $json
                );
                let dec_s: $ty = s.parse().expect("parsing string");
                assert_eq!(
                    dec_s,
                    obj,
                    "decoded string did not match object '{}'", obj
                );
            }
        }
    }

    serde_rtt_test32!(serde_rtt_txid, Txid, REVERSED_JSON);
    serde_rtt_test32!(serde_rtt_wtxid, Wtxid, REVERSED_JSON);
    serde_rtt_test32!(serde_rtt_blockhash, BlockHash, REVERSED_JSON);
    serde_rtt_test32!(serde_rtt_wscripthash, WScriptHash, FORWARD_JSON);
    serde_rtt_test32!(serde_rtt_merklenode, TxMerkleNode, REVERSED_JSON);
    serde_rtt_test32!(serde_rtt_assetid, AssetId, REVERSED_JSON);
    serde_rtt_test32!(serde_rtt_contracthash, ContractHash, REVERSED_JSON);

    serde_rtt_test32!(serde_rtt_entropy, AssetEntropy, REVERSED_JSON);
    serde_rtt_test32!(serde_rtt_dynaroot, DynafedRoot, REVERSED_JSON);
    serde_rtt_test32!(serde_rtt_elidedroot, ElidedRoot, REVERSED_JSON);
    serde_rtt_test32!(serde_rtt_paramsroot, ParamsRoot, REVERSED_JSON);
}
