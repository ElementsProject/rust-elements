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

//! # Blocks
//!

use std::io;

use bitcoin::hashes::{sha256, Hash};
#[cfg(feature = "serde")]
use serde::{Deserialize, Deserializer, Serialize, Serializer};
#[cfg(feature = "serde")]
use std::fmt;

use dynafed;
use encode::{self, serialize, Decodable, Encodable};
use Transaction;
use {BlockHash, Script, TxMerkleNode, VarInt};

/// Data related to block signatures
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum ExtData {
    /// Liquid v1-style static `signblockscript` and witness
    Proof {
        /// Block "public key"
        challenge: Script,
        /// Satisfying witness to the above challenge, or nothing
        solution: Script,
    },
    /// Dynamic federations
    Dynafed {
        /// Current dynamic federation parameters
        current: dynafed::Params,
        /// Proposed dynamic federation parameters
        proposed: dynafed::Params,
        /// Witness satisfying the current blocksigning script
        signblock_witness: Vec<Vec<u8>>,
    },
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for ExtData {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        use serde::de;

        enum Enum {
            Unknown,
            Challenge,
            Solution,
            Current,
            Proposed,
            Witness,
        }
        struct EnumVisitor;

        impl<'de> de::Visitor<'de> for EnumVisitor {
            type Value = Enum;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a field name")
            }

            fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
                match v {
                    "challenge" => Ok(Enum::Challenge),
                    "solution" => Ok(Enum::Solution),
                    "current" => Ok(Enum::Current),
                    "proposed" => Ok(Enum::Proposed),
                    "signblock_witness" => Ok(Enum::Witness),
                    _ => Ok(Enum::Unknown),
                }
            }
        }

        impl<'de> Deserialize<'de> for Enum {
            fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                d.deserialize_str(EnumVisitor)
            }
        }

        struct Visitor;
        impl<'de> de::Visitor<'de> for Visitor {
            type Value = ExtData;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("block header extra data")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: de::MapAccess<'de>,
            {
                let mut challenge = None;
                let mut solution = None;
                let mut current = None;
                let mut proposed = None;
                let mut witness = None;

                loop {
                    match map.next_key::<Enum>()? {
                        Some(Enum::Unknown) => {
                            map.next_value::<de::IgnoredAny>()?;
                        }
                        Some(Enum::Challenge) => challenge = Some(map.next_value()?),
                        Some(Enum::Solution) => solution = Some(map.next_value()?),
                        Some(Enum::Current) => current = Some(map.next_value()?),
                        Some(Enum::Proposed) => proposed = Some(map.next_value()?),
                        Some(Enum::Witness) => witness = Some(map.next_value()?),
                        None => {
                            break;
                        }
                    }
                }

                let challenge_missing = challenge.is_some();
                if let (Some(chal), Some(soln)) = (challenge, solution) {
                    Ok(ExtData::Proof {
                        challenge: chal,
                        solution: soln,
                    })
                } else if let (Some(cur), Some(prop), Some(wit)) = (current, proposed, witness) {
                    Ok(ExtData::Dynafed {
                        current: cur,
                        proposed: prop,
                        signblock_witness: wit,
                    })
                } else if challenge_missing {
                    Err(de::Error::missing_field("challenge"))
                } else {
                    Err(de::Error::missing_field("solution"))
                }
            }
        }

        static FIELDS: &[&str] = &[
            "challenge",
            "solution",
            "current",
            "proposed",
            "signblock_witness",
        ];
        d.deserialize_struct("ExtData", FIELDS, Visitor)
    }
}

#[cfg(feature = "serde")]
impl Serialize for ExtData {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;

        match *self {
            ExtData::Proof {
                ref challenge,
                ref solution,
            } => {
                let mut st = s.serialize_struct("ExtData", 2)?;
                st.serialize_field("challenge", challenge)?;
                st.serialize_field("solution", solution)?;
                st.end()
            }
            ExtData::Dynafed {
                ref current,
                ref proposed,
                ref signblock_witness,
            } => {
                let mut st = s.serialize_struct("ExtData", 3)?;
                st.serialize_field("current", current)?;
                st.serialize_field("proposed", proposed)?;
                st.serialize_field("signblock_witness", signblock_witness)?;
                st.end()
            }
        }
    }
}

impl Encodable for ExtData {
    fn consensus_encode<S: io::Write>(&self, mut s: S) -> Result<usize, encode::Error> {
        Ok(match *self {
            ExtData::Proof {
                ref challenge,
                ref solution,
            } => challenge.consensus_encode(&mut s)? + solution.consensus_encode(&mut s)?,
            ExtData::Dynafed {
                ref current,
                ref proposed,
                ref signblock_witness,
            } => {
                current.consensus_encode(&mut s)?
                    + proposed.consensus_encode(&mut s)?
                    + signblock_witness.consensus_encode(&mut s)?
            }
        })
    }
}

impl Default for ExtData {
    fn default() -> ExtData {
        ExtData::Dynafed {
            current: dynafed::Params::Null,
            proposed: dynafed::Params::Null,
            signblock_witness: vec![],
        }
    }
}

/// Elements block header
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
pub struct BlockHeader {
    /// Version - should be 0x20000000 except when versionbits signalling
    pub version: u32,
    /// Previous blockhash
    pub prev_blockhash: BlockHash,
    /// Transaction Merkle root
    pub merkle_root: TxMerkleNode,
    /// Block timestamp
    pub time: u32,
    /// Block height
    pub height: u32,
    /// Block signature and dynamic federation-related data
    pub ext: ExtData,
}
serde_struct_impl!(
    BlockHeader,
    version,
    prev_blockhash,
    merkle_root,
    time,
    height,
    ext
);

impl BlockHeader {
    /// Return the block hash.
    pub fn block_hash(&self) -> BlockHash {
        let version = if let ExtData::Dynafed { .. } = self.ext {
            self.version | 0x8000_0000
        } else {
            self.version
        };

        // Everything except the signblock witness goes into the hash
        let mut enc = BlockHash::engine();
        version.consensus_encode(&mut enc).unwrap();
        self.prev_blockhash.consensus_encode(&mut enc).unwrap();
        self.merkle_root.consensus_encode(&mut enc).unwrap();
        self.time.consensus_encode(&mut enc).unwrap();
        self.height.consensus_encode(&mut enc).unwrap();
        match self.ext {
            ExtData::Proof { ref challenge, .. } => {
                challenge.consensus_encode(&mut enc).unwrap();
            }
            ExtData::Dynafed {
                ref current,
                ref proposed,
                ..
            } => {
                current.consensus_encode(&mut enc).unwrap();
                proposed.consensus_encode(&mut enc).unwrap();
            }
        }
        BlockHash::from_engine(enc)
    }

    /// Returns true if this is a block with dynamic federations enabled.
    pub fn is_dynafed(&self) -> bool {
        if let ExtData::Dynafed { .. } = self.ext {
            true
        } else {
            false
        }
    }

    /// Remove the witness data of the block header.
    /// This is all the data that can be removed without changing
    /// the block hash.
    pub fn clear_witness(&mut self) {
        match &mut self.ext {
            ExtData::Proof {
                ref mut solution, ..
            } => {
                *solution = Script::new();
            }
            ExtData::Dynafed {
                ref mut signblock_witness,
                ..
            } => {
                signblock_witness.clear();
            }
        }
    }

    /// Calculate the root of the dynafed params. Returns [None] when not dynafed.
    pub fn calculate_dynafed_params_root(&self) -> Option<sha256::Midstate> {
        match self.ext {
            ExtData::Proof { .. } => None,
            ExtData::Dynafed {
                ref current,
                ref proposed,
                ..
            } => {
                let leaves = [
                    current.calculate_root().into_inner(),
                    proposed.calculate_root().into_inner(),
                ];
                Some(::fast_merkle_root::fast_merkle_root(&leaves[..]))
            }
        }
    }
}

impl Encodable for BlockHeader {
    fn consensus_encode<S: io::Write>(&self, mut s: S) -> Result<usize, encode::Error> {
        let version = if let ExtData::Dynafed { .. } = self.ext {
            self.version | 0x8000_0000
        } else {
            self.version
        };

        Ok(version.consensus_encode(&mut s)?
            + self.prev_blockhash.consensus_encode(&mut s)?
            + self.merkle_root.consensus_encode(&mut s)?
            + self.time.consensus_encode(&mut s)?
            + self.height.consensus_encode(&mut s)?
            + self.ext.consensus_encode(&mut s)?)
    }
}

impl Decodable for BlockHeader {
    fn consensus_decode<D: io::BufRead>(mut d: D) -> Result<Self, encode::Error> {
        let mut version: u32 = Decodable::consensus_decode(&mut d)?;
        let is_dyna = if version >> 31 == 1 {
            version &= 0x7fff_ffff;
            true
        } else {
            false
        };

        Ok(BlockHeader {
            version,
            prev_blockhash: Decodable::consensus_decode(&mut d)?,
            merkle_root: Decodable::consensus_decode(&mut d)?,
            time: Decodable::consensus_decode(&mut d)?,
            height: Decodable::consensus_decode(&mut d)?,
            ext: if is_dyna {
                ExtData::Dynafed {
                    current: Decodable::consensus_decode(&mut d)?,
                    proposed: Decodable::consensus_decode(&mut d)?,
                    signblock_witness: Decodable::consensus_decode(&mut d)?,
                }
            } else {
                ExtData::Proof {
                    challenge: Decodable::consensus_decode(&mut d)?,
                    solution: Decodable::consensus_decode(&mut d)?,
                }
            },
        })
    }
}

/// Elements block
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
pub struct Block {
    /// Header of the block
    pub header: BlockHeader,
    /// Complete list of transaction in the block
    pub txdata: Vec<Transaction>,
}
serde_struct_impl!(Block, header, txdata);
impl_consensus_encoding!(Block, header, txdata);

impl Block {
    /// Return the block hash.
    pub fn block_hash(&self) -> BlockHash {
        self.header.block_hash()
    }

    /// Get the size of the block
    pub fn get_size(&self) -> usize {
        // The size of the header + the size of the varint with the tx count + the txs themselves
        let base_size = serialize(&self.header).len() + VarInt(self.txdata.len() as u64).len();
        let txs_size: usize = self.txdata.iter().map(Transaction::get_size).sum();
        base_size + txs_size
    }

    /// Get the weight of the block
    pub fn get_weight(&self) -> usize {
        let base_weight =
            4 * (serialize(&self.header).len() + VarInt(self.txdata.len() as u64).len());
        let txs_weight: usize = self.txdata.iter().map(Transaction::get_weight).sum();
        base_weight + txs_weight
    }
}

#[cfg(test)]
mod tests {
    use Block;

    use super::*;

    #[test]
    fn block() {
        // Simple block with only coinbase output
        let block: Block = hex_deserialize!(
            "00000020a66e4a4baff69735267346d12e59e8a0da848b593813554deb16a6f3\
             6cd035e9aab0e2451724598471dd4e45f0dca40ca5f4ac62e61957e50925af08\
             59891fcc8842805b020000000151000102000000010100000000000000000000\
             00000000000000000000000000000000000000000000ffffffff03520101ffff\
             ffff0201230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a\
             0d5de1b201000000000000000000016a01230f4f5d4b7c6fa845806ee4f67713\
             459e1b69e8e60fcee2e4940c7a0d5de1b201000000000000000000266a24aa21\
             a9ed94f15ed3a62165e4a0b99699cc28b48e19cb5bc1b1f47155db62d63f1e04\
             7d45000000000000012000000000000000000000000000000000000000000000\
             000000000000000000000000000000"
        );

        assert_eq!(
            block.block_hash().to_string(),
            "287ca47e8da47eb8c28d870663450bb026922eadb30a1b2f8293e6e9d1ca5322"
        );
        assert_eq!(block.header.version, 0x20000000);
        assert_eq!(block.header.height, 2);
        assert_eq!(block.txdata.len(), 1);
        assert_eq!(block.get_size(), serialize(&block).len());
        assert_eq!(block.get_weight(), 1089);

        // Block with 3 transactions ... the rangeproofs are very large :)
        let block: Block = hex_deserialize!(
            "000000207e3dba98460e4136659f0fccf3e59338dfe53ed5f094fb0bb94d771c\
            48341854d875900105c87e5dd46c740cb1129c06f8f4007e868f61b25e37cffa9\
            46c718d8742805b01000000015100030200000001010000000000000000000000\
            000000000000000000000000000000000000000000ffffffff03510101fffffff\
            f0201230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5d\
            e1b2010000000000009b64001976a914608c0ea8194a8ceb57f0196f44a6b48a5\
            4fc065988ac01230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e494\
            0c7a0d5de1b201000000000000000000266a24aa21a9ed8f8a98e5623643b2416\
            7266c2648ead4a50d18b0491c6f34e11398aaee0ca6e800000000000001200000\
            00000000000000000000000000000000000000000000000000000000000000000\
            00000020000000001eb04b68e9a26d116046c76e8ff47332fb71dda90ff4bef53\
            70f25226d3bc09fc0000000000feffffff0201230f4f5d4b7c6fa845806ee4f67\
            713459e1b69e8e60fcee2e4940c7a0d5de1b20100000002540bd71c001976a914\
            48633e2c0ee9495dd3f9c43732c47f4702a362c888ac01230f4f5d4b7c6fa8458\
            06ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b2010000000000000ce400\
            0000000000020000000101f23ceddac67cfbbc997199daa651384d0746fb2a548\
            2b8c8629ba8df4b788f75000000006b483045022100e0feb3e2f292000d67e24b\
            821d87c9532230dac1de428d6a0068c9f416583abf02200e76f072788dd411b23\
            27267cd91c6b1659809598cd4fae35be475efe1e4bbad01210201e15c23c02165\
            2d07c1557b607ea0379fca0462aca840d6c33c4d4927524547feffffff030b604\
            24a423335923c15ae387d95d4f80d944722020bfa55b9f0a0e67579e3c13c081c\
            4f215239c77456d121eb73bd9914a9a6398fe369b4eb8f88a5f78e257fcaa3033\
            01ee46349950886ae115c9556607fcda9381c2f72368f4b5286488c62aa0b0819\
            76a9148bb6c4d5814d43fefb9e330575e326632136389c88ac0bd436b0539f549\
            7af792d7cb281f09b73d8a5abc198b3ce6239d79e68893e5e5d0923899fd35071\
            ba8a209d85b556d5747b6c35539c3b2f8631a27c0d477a1f45a603d1d350b8cbf\
            900f7666da66541bf6252fc4c162141ad49c670884c93c57db6ba1976a9148c7a\
            b6e0fca387d03643d4846f708bf39d47c1e988ac01230f4f5d4b7c6fa845806ee\
            4f67713459e1b69e8e60fcee2e4940c7a0d5de1b2010000000000008e80000000\
            0000000000000043010001dc65ae13f76fde4a7172e0fb380b1a5cc8dc88eaa06\
            59e638a25eac8ae30d79bf93eb7e487eeee323e4ac8e3a2fe6523bdeba6acce32\
            b9b085f2286174c04655fd6c0a6020000000000000000178ad016b3e5d8165423\
            e56d8b37e3eaee96009b2f970043ccf65d61b5c3c1e1ef343e0c479bdba442717\
            dc861c9591566010240b9d4607efb9252a5fcef05edf640e0bb6b606729246ad0\
            7baa49d0d3b52042c65a03ca737744e45b2d2d6d177c36569ae9d6eb4437305b1\
            69bbc59f85cabff3bc49a2d6d08c177cce3121a509d3c47961bd22e35c932b79d\
            4ec5ccaf913fac04034bfebdadbc4ff3127af96344b02ee6b967bb08326cbe6a4\
            e1c924485e64a8c0fdf70b98c99f38acaa15aa0adb2b5b7335ed5502443891bcd\
            657310347cbd928f40f38f1dec087a2b947c9cf7d304798f77bbc4a2c843796b2\
            d49acce91de4e88a0a9c261277df28ffc3320d7f7d64790f592ddded48a1068ef\
            88271395fa5606389ef90856ddd6bd6710a8d27e0147983b5dde2a7efae44e83a\
            d02a3c3da04be43d5f2c05c205f1e17b48554c2177670f46dbb6600bd2e6c75dd\
            5ea2e1072c5f22483dcf05d8124e3f9063a5ddb179a29c23a2d15d6e89f2192f0\
            3dae5938f66fcdcff000c5a96ffd2920f23881880af72153c96a56dd80c218bb4\
            8b44a18e54a8050ff32c869c1264ee574cdb4002f86e0779c724d11dc4a768dbe\
            c1bd22054886f1fdf2e7347e4c247b829159d1375f881c6ce0a5c4da8534000e7\
            fec3a980afb1edc99b725c29de80f260dcf144c873bf589ae1812ef6cb05f2234\
            f9c66c23e874a0d5d0dc52f2209e015bbcf74ee449a397f6b0318c915b7e58dea\
            5904abbe35285e90ccf548ad1f3f52f60c3b19b3cd67644d633e68aef42d8ef17\
            82f22a8edd0620f55f29070720ca7a078ac83e87b9ebd2783ecad17dd854ef1bb\
            d319f1a6d3a1e4931f9097422f5a3c4af037b99e06c7610ee61102c6eea763af1\
            08e9a16b93b2dc0891658d5c6a197df6aae9b306b2c895d21c79cb6cb6dd85b40\
            18b0a9fe7468336e3907eb4adcaf930cacc97e8e951d2d6b25744a4143679bad1\
            f31b210c9a2ed54b80d8f5d7dc1f1c985681534c1926920cd683d95dca7e8ea28\
            5f9906d2e89cd8bfa76a98e38ee4b5152522d55f79610fe8d5278fe6ed5866b5d\
            a4dcf330ea84307c34f30e1a66eb1934dafebb0074fc27c2ff73d8c0bae8416cc\
            87bf611f81119aba9e2a911beaf3ac9507e621fc1ed1cf15dfb31408cf55e2bfd\
            d2880db2d3489a336d6f8348347648d882f9f376331e469e809115c6cc82468f3\
            63c910673e9ded172ded90a369e1cdd135676f623e11a1531ed221177812b1ef0\
            c65e5ca92c0df8de7fe664710f3228a226e019c99607fe1395ecd5643e1c7ad8a\
            132bf5131737cb970a7f0dabc00029755bf71b3f47bd69ba39b3ab104c74f0423\
            9f4919dca1dfce7c9c41cba9d449073e106ebabe3c313b598ee8b11702ec46e9e\
            e53fb9422f0326371898b8fa4c21a951684c687398e0bebd6f6fd91b829e8666b\
            9a19a4273cfda0f34b8ecb902f7adc6539fb9a0cba6f87a63a957acfb2dfa1897\
            3f4a3063668767b2be780311513c63f1814f082176f6a953f2ffaa49ec9b39fec\
            c2eab603be7a969bb4c1dbebf8d39fa90f802d5ea52378b5025a19b64a8c2c2dd\
            6a6133bd8d29730bd5724b5bf50c158b238d1137082937ad91a176aaf91577868\
            db7581b457c917e612b242ce0065ad47e11dcdc1fc6158687142249bcf312497a\
            547b6f43e795af7d4ae8cd022e44e417987e35e83de21e39dcdf86b97bd421e6e\
            61881a432fa2284f20be80e32459443736b875d9036468ceb881589394441e2d1\
            0aa10b6c93332951e8ba56f89fac70baf415b4511873c0f3e418ca4fe8954a28f\
            1f7b5f590d34470119f694e2712f184882d90396c8e6aa850eaa3c2ae51990543\
            638c46c59512167a2c5ad593532dc2142ffb6560476e4159213b9ef017ec75310\
            d2e4624a405bb26f7192a485a94890674928c9caa4a5819ca4ddcba8fa71afc1a\
            6baf63f039452c8fe994f8b63d58c876dfddd61a476345eaed4f66bdc0fcfc38d\
            485c6a5b0e27d0fbc50427ff591ba38d63445c01642cfbd7d4c032f2546a6fe80\
            bc3b598362502c552049523fe360c3bcf1cc572feb04386f97d55871dd8cea039\
            3cdd964e724082adc98126e6f2fe1d576be4bf911e9aca70e35538175f8382bbc\
            d614bbecc97c9607ef25da2ff08a6e5b6f76cbe9ccb0e0fdc3528e3e2c3675a5c\
            897d295bb76524ec8a73a70b97909368f44d92f9aceaef0b03f3dafa1faa89fc6\
            63a92da3c19b4952463fac0e825e78cf046e266cfb9975af72e9d50d2c2cafee8\
            8fe2cecae2b1465fc07b280d83b66062dc9e7a372f81aec8e0bb9e97877814a5a\
            6813c67746e35cd068d45d8664528bd00d5a306a5319e1bea7f38345da92d3a10\
            d91476a26aed6b8441f0f72fbbad5d5e0f8ae5cabc9f4f08e6be7902b5c53632d\
            b5264afee7422c87b3237a32d5213ad0eb807b61977d9d90666cbb0c70500526b\
            0eb762c99351796db41166b0aa2f221b5607e0d629fac4e938488245c11557381\
            a4f8addcc49913b11d42481cf8668e37bacbad4a20509e4fe4ccbcee7aea2909a\
            2abe59052f7f28b9340cd92f69729d615b8d3b530941c0b30506498cd4e561a9c\
            82d915266bb7115967bc76c5593c06d094bdf4294b868afc5fa52742d3bdbd593\
            2df599f0e1187c49f0dba8679c771a514cc9da75e03506957800bf470d4a07c4b\
            b8918d6085499bb8ceeaba23c0b465863327e9ab8b6b8cf8b3ca530ca7b02cfad\
            f85437b750f305e8fbc8855c95bee8595a7e9e1f0993a03adbadc68665a18936c\
            c99b6530b4518c0754990d7bfdfdac76f88cfcbcb7b3d9a71ee10cbd3a1bdbc2e\
            50b642c1fef56511962f845bbec6eab727b1d4add335db8d80c4c07e8356ad05a\
            dad68b012489fa5bb5d9019a667778ddf7f5edd80f1d3c4abd64397a89e554c80\
            07809336ddc2b2e7d5219c39fdf39aad33b9350f6b18fe3b98c690b9068f36d4b\
            7669530fd216373842fbf70fe9bbe80854b31eed4bd515d6caeb065d6c609846c\
            9bfae1b3fce3db70b5bfb448ec69512e7f25019c789301b77a75f2a0f81c65ec2\
            9f41bf96d597a00c310e8ba4b48ac82b5a735c1e83f22394eb2fc9b35d42a3553\
            3c938f26290a5860175637982f1733c99be39c44ac4a09187406306bde2fd3d28\
            e4e7bda73719912c338804dea03987757dac4d73def665e11da126f9414f71624\
            a3b753797eb0472bd334094515c4f9fe57fdd8d185f22b4bf82e4b5f6b800870c\
            ce19a0c8174dc11ee9f1cb9ffe0ac6f6fff1ebf7c915c7ae20172bb70390e3759\
            912e0e0a4e83a0a2d2318f4386314a89f6438ccb331f89377ff7947fe4b24f788\
            aef85c1656ca87ee41c959f1b09bde09f20c2a51ac481646b28e9b0fc2ff49cfe\
            8cf28577bf5bf6f261f54f97fcd2875da4210c6dfe685450280b68e378d9a4862\
            43cc682ed4ec747c37de1fde848e4a8f70498d22e40c462c469c884cd67330e77\
            b694e759232313f31a1624e0e1960f23ddae47b68ff553d0de0910c8abe2e8e5f\
            b063aa744ff77465fc731c7af79a84dcaa9b3f741a46dd3c932877d49242c6d88\
            3e14392b8c4530986605812b636a73590ef437f27e40d1af37ed1cbd68fb4e9ca\
            5b0b41e5daee0142c1bf59c9d71f6c19b25e6148dfbb9fb142107aabe3701e366\
            11a7e0b13ea32d3c5f8a51f63c5f34415baa15f6ca77300eb323241ffe73c5acd\
            97fcb682c21dc8911392979e9cb81be5218acf452b5b93f6681d323b7989fdd10\
            efe6fe9e2ac88d0d76a4cf3ee45e3b5c430100014142c1fc7e8a658eff437594a\
            25cf34d269556d8511918f27fdc7e9d6dd73f0e4790b91f225e9d131e6abb3dbf\
            b66549a9aa57948fbd2f183fcd951b1d2305bffd6c0a602000000000000000016\
            f5cdf9fb6c1b5e98a36befdc2c55bd4fd8793d554b2506f51c909362495e1216e\
            e83cd270ddb0a00785600ba23bd3363f0798e3a7a117990415adec88e61be6517\
            0bd587ab4d2ee38edb22a91e5c29afa397dd5a73465c51c6263f5fbde47fa801c\
            e84464acc32589acaafadfe44d6558774b7085612a88f3424b6dca3c6f07217d1\
            cbd5c41bda46a6a492a0119c1de4d25b58c94250bee3fba6b8223777535673a2f\
            4da6af27598030f88144f408120f07ca9c98d5d9edcdf6cdc9073f118fce55e6c\
            9d0be80b5e87992ddaa9c22053b3a00d42bdedc9768de25c0b37a5c4fb4e86710\
            b33cebed5588d88adde607f6bca14f0279ce35126d403ffa50f288c87f528c197\
            49ed43bd846c513fcd92c173fe76d8f2e69770439d3d075cb19b1094a42ee07ae\
            1de197e8c136e2bc688a75a74db24adb0fbb73872dc80074f61c9cce9bd33861b\
            dd921ee3edacab1d6e7cec325c172b6b6e82ada11687e4fc931225074dd1f20a0\
            f9342dbce1fc3fdbf5bb6cb74ab6475e574e9f5f247a2f7e4fcfcc354d4da8c80\
            66e574642c7fccbbb9ef0aa592ecab5366fe87eb8e14cd64aee34578aa48f68f8\
            f4c5372df2c3fc429f5a3e39ef6c034c87f9c52b2ea35e28c7bf3be737c3817ef\
            d6569466dc859e8ff8965c5249b6f045934d3d08b0ffd388aec58df8194ac2c4f\
            ec2152942d2626595e65664b1fa33b5dae8ee796a840a56d885cbf7ae6483fad0\
            5e507ada3f075ebce0d791b626c6dfe93f8492c4dd3b34aafc33d7644c5c8e38b\
            fd8c19194f65be88fcb4538778632e489a626896372fdd2498b16e64daa7d3c5c\
            fac688d6f9cdf3717261b0a1f25be1bdd6be6558ddb826fa04b5f668810a291ae\
            a51a6f05ff7c34dcf81c74849a8015bad5e4e416989b10ef01de304775db725fa\
            0b665f4330dc9c540dc29aab144837362a97d6bb0165cb3272338c2d32386cd95\
            ee3e66d876b591a25a6907237523cf908f736d2fdc8e54ea8d9c7562697161d1f\
            72fc4d7b775052415cd0e5ae5bdf6edfab5776b6ff75ce5e1f8f2beea6ec74252\
            b63966cca58abd638279dc5c998a1068079f3e5dcc8a69165c304c3d8c362ccfa\
            dab05ad12208a5655ab389eb727e8ed5f86b300331a13be26e2fbabf89fbfd2b9\
            8481dd5edb52ed456a0e03a84b6f89761f91ff251412f5cfa286e35fb9f48ef0e\
            044c4742b6e860a08767ecb80548c2f3df3b371cdb40e86dbe118f64e84faf45e\
            cb78d73364e9e31e3412ca2a3fad0a35983370ea9e6264a222edd1fd4aca30e3c\
            169d7ca2d07609262e786ecd019c1417a06b7dfa32a54e0897afdc6492f266115\
            55cbff47dba3b76381f239d597a8f687669333e0b47b53d5bcc4fea1919490bad\
            3c6f0b6a58a50aca7ddeb9745ead454e0a38d9486fb52aefe0dbb92bf7fd6c215\
            078aba3482b11274ec8cddff92c359bbc6d20bd823ad0bbf859cfaadf8e775b3d\
            37b3078319f46c6d2a112cf60a673fee467538c70f1687d97fbe9d9f8a0856061\
            592a4e00b6d10e979e674dd2cd0ba8b853f733877cd508062d5f723d58d215ad6\
            9c2be6be742496aef54eb87338622eb36a9bbc5a7a602d280a45e095b1e078dab\
            54479e783a513c722066acaae44ccc15f9560da91ed053ec05c36d82f68097668\
            76c45c4fbeb2321d50f48f7995437d0c5fc365974a571fb0352d28cb1cdbd21d6\
            9fab576a2e68d6b881776027bcdb7f01be22b1c847d91f26e680ef6ab2c128a89\
            b59432383d9bd661b0b01432cf8a25319426d38ac2e2114825f59b4250569c798\
            b1094920bb31130728313ff56a6eef2e6c4b275215dce3786d0f9024952b5f572\
            566c53597e7ef4ab1f75743e605a564054d667f48906b5481d924769ef65751e3\
            49891d725a2c1bf8b102fea4c25c874d2fc2ce1bfec4b39bea76fbf7a28855725\
            d52b595a4fc96892c3f1f961d46310ebd5221df729c02060035c559baf0fd7efa\
            73a2213ca29642857aeb8ebf7efdf9d2f5c84746b6fc35ab355a8dca56e7dde48\
            31e47ca1be6b62af30cfcf807c384e56ab84ff03bbe786251e6c4b932c9217bf6\
            71046217bd0511fdc06aa69050c1480281e4843eb73d80095a2fb8e68a2c0c98c\
            9aea637b99d87ad847a3a76d59ea308c751f9cb4a4fce2989822bd6ba2f901f09\
            df647536dc30730ea3160dd35b8c6dcc9aa815b79ed492a8a299a298ccdf784b9\
            b0211ca877ec1723817c98529acaa4d3727162b5740b0fc9b498dfb2212a3cbf0\
            c63dc4f7663fafad7905643a792862b651e8497b0f0da632b897ecf9ee63f2b20\
            b54fa5eb2f2e424dcce5a075f50b856af266655be3a815fc83ed8027508b25369\
            76982196b160e2219ffdb5c7a56dd3e6b700860c711f4439dbf72973f4f26fe32\
            60ec43a3446fe14444b9787d877e107be610147eec4a3574745e95a1f424aff06\
            2f84c559d13b1e6b59e8dc2221515c229f07db8eb39c515a321d8bd07b1bd6c9a\
            79dac6d951c04415553c7a2ce1eb77495c7f89c4d5b4cffd289435b69bc535850\
            95083cc5a1b191781342266e204e1566aca8175e2ae84a8bd711d188b666dfb65\
            a6442776d3e23c1b5192af09ec712537f2157d0ccbc1bb3b3a1969d9705671f16\
            bdc266e615ad2e50a8cbd666f3ee7465cc430c6cd69d30c91e717b12f7094b6f0\
            ef89134d6c1620d28d8f238c181146448b348e4ca2e93c737210350f18fb878fb\
            91b70ecc5689e5b6101ecfc545f6a1c903115b0c6419c91a50fb2dbe2edd362f2\
            815f0c75070974507c34130ac9b29747ff7efbe6e37ee4c62be3ecfedfa817fdf\
            3309163aaff677775b77f0d288c9858cfe59cb0fa18afa591e7d574eaef43c82e\
            79d71542c4177de4e5bd724b18cfd33c68530665728a9d5ef192772094acbf3d8\
            85d5146c1634e74754e3fbcb94fa349eac8280cfd7d1f46a0813b57a83bd078b1\
            f7cb5a60a59b59380fe04e1c600c33b33d1add69a9ff1be546f0ec5c0083979fc\
            e940b23711f382ac0d011c1103f02cb6082c18e39cf7a9c3bf4c081f905ae7b87\
            951a7880b57e934465ccd634e5a17fd8d8866abfdfebd33b2c3d2c5be58144900\
            c04e9c18de0c80270660e62a3c185277555f89da4c41bd33cec1359f4ed21abdb\
            586e1d97f720a92d16014d7f1822f1836f74c97cb7f7b38e073477c6ab064fde8\
            35916c1e624de81f2ad90f6260073c5e1848582860f033630bde225821b39c257\
            2b30c36adf8fdb8317c33df05f6413447f4985d12e9012629df09dc8f43373a6d\
            0db4b0048453a6f1ec662472c77a30d5cf4ac7084f736d0d598c251f2aefc9860\
            52fbf12a657885d7140ad36b07c63ab86388a2be12d943747f3f29ef9f2e11e14\
            44cc873df0ed7826eef675389a0d5a0388a8504fe89c4791ea4a572bfd406d5f0\
            1418b4f888c9a7a566e32811936bf6950bbf786b86c41c28f2045d31953fcd15f\
            179e7bc00c72870890537921f7deff82270b0e44b88720aa738f60a85567deb7c\
            90b0c2444467621e53e1c079436d31d3d0b34dd237fc281eb9d87175237a9a433\
            142db4bb7f8c4cb6a34e2dc73f074045d216695ce88ef68e18564c935c9cbd902\
            e939655c258de2ab78def8746bffd972083afce3b6881b7147262e1a44e022468\
            9fafa1a3cb823c8da6eb7df091bec0638bf728b7b10aa95f2bce512ec8d325293\
            8d2eb77b44ace7a2f976588032cac5af670f9e5ca25cb0721bc1baec26f9c3a9f\
            41b02fb62997d6cb0a01314845e9d0e78139ea49f2ead8736e0000"
        );

        assert_eq!(
            block.block_hash().to_string(),
            "e935d06cf3a616eb4d551338598b84daa0e8592ed14673263597f6af4b4a6ea6"
        );
        assert_eq!(block.header.version, 0x20000000);
        assert_eq!(block.header.height, 1);
        assert_eq!(block.txdata.len(), 3);
        assert_eq!(block.get_size(), serialize(&block).len());

        // 2-of-3 signed block from Liquid integration tests
        let block: Block = hex_deserialize!(
            "0000002069de100c1bae40e1cf8819bd18282e4ca370f62123c8ea2c60836984\
             ba052270ee0cb6e5458591ac157ad414a111db4d34cedffc22e096291f7b4b3c\
             8de3f69f8d53815b03000000695221031c25c60ef342990d9bf75425c1dc2392\
             b5e206268d9d35044b731735db230c38210319c5a32a8ae698aaf1246784f542\
             31d8d20f81b91c31353214538b827d718c8d210399d55e0a7fb30281da074dfb\
             bb2654cacc2d03289ba79feae702ad6dbb542aab53ae9000463044022029bbe1\
             79c2f0d8e6d1576869cea19ef439d0e52373f7efab77cd6ccb551b29f6022042\
             baa3c17fccfb265ee878059b6cb85d40b976a30495c6ca14b7ffe6d1d8757247\
             3045022100da88bb6fa1ecf3060ad7c8347eaa1a7ef8c9ae27a8b0136cff9099\
             94ca409f9e022068ddf3090bde1e04deda04f762eb35858d7dfc17e156bfc1c8\
             131ca07a349dda01020000000101000000000000000000000000000000000000\
             0000000000000000000000000000ffffffff03530101ffffffff02018dc25a05\
             5e773e7e91d4678053ebc702cce47f07b29f3ebd7c4b34cd30fb240201000000\
             000000000000016a018dc25a055e773e7e91d4678053ebc702cce47f07b29f3e\
             bd7c4b34cd30fb240201000000000000000000266a24aa21a9ed94f15ed3a621\
             65e4a0b99699cc28b48e19cb5bc1b1f47155db62d63f1e047d45000000000000\
             0120000000000000000000000000000000000000000000000000000000000000\
             00000000000000"
        );

        assert_eq!(
            block.block_hash().to_string(),
            "bcc6eb2ab6c97b9b4590825b9136f100b22e090c0469818572b8b93926a79f28"
        );
        assert_eq!(block.header.version, 0x20000000);
        if let ExtData::Proof {
            challenge,
            solution,
        } = block.header.ext
        {
            assert_eq!(challenge.len(), 1 + 3 * 34 + 2);
            assert_eq!(solution.len(), 144);
        } else {
            panic!("dynafed test vector was parsed as non-dynafed");
        }
    }

    #[test]
    fn dynafed_block() {
        // Copied from elements RPC during a functionary integration test run
        let block: Block = hex_deserialize!(
            "\
            000000a0da9d569617d1d65c3390a01c18c4fa7c4d0f4738b6fc2b5c5faf2e8a\
            463abbaa46eb9123808e1e2ff75e9472fa0f0589b53b7518a69d3d6fcb9228ed\
            345734ea06b9c45d070000000122002057c555a91edf9552282d88624d1473c2\
            75e64b7218870eb8fb0335b442976b8d02010000fbee9cea00d8efdc49cfbec3\
            28537e0d7032194de6ebf3cf42e5c05bb89a08b100040047304402206f55bc87\
            1387a9840489d47624b02995e774e3b70fed56d1eb43a9a53d4fd3e102201e1c\
            bfbbd1079f5bea3bc216882d3fefbf6f27aa761820d3a88f12e5a5ea7ff00148\
            3045022100c072816f6561e73ee6c0ae32d55c3eec4da73b035425e4eb05ab50\
            772591b4360220311bf295010094a489d9b280d9dafb724d776a1d99b9ede31c\
            4b59bc2095c5c30169522103cadff18e928133df2e670a3715c4e7a81d357de3\
            6ddaa5016628e70a3e6a452f21021f0d8638c413ef7769cd711ce84c8f192f5a\
            85f0fd6d8e63ddb4d2cf6740b23b210296db75c11ea3a292a372f6c94f5013ea\
            eb379f701857a702f3b83f88da21be6f53ae0102000000010100000000000000\
            00000000000000000000000000000000000000000000000000ffffffff035701\
            01ffffffff020137c495f58d698979ff9124e8c7455fe79b13ddb96afa25c458\
            94eb059868a8c001000000000000000000016a0137c495f58d698979ff9124e8\
            c7455fe79b13ddb96afa25c45894eb059868a8c001000000000000000000266a\
            24aa21a9ed94f15ed3a62165e4a0b99699cc28b48e19cb5bc1b1f47155db62d6\
            3f1e047d45000000000000012000000000000000000000000000000000000000\
            000000000000000000000000000000000000\
        "
        );

        // Test that this is a block with compact current params and null proposed params
        if let ExtData::Dynafed {
            current, proposed, ..
        } = block.clone().header.ext
        {
            if let dynafed::Params::Compact {
                signblock_witness_limit,
                ..
            } = current
            {
                assert_eq!(signblock_witness_limit, 258);
            } else {
                panic!("Current block dynafed params not compact");
            }
            if let dynafed::Params::Null { .. } = proposed {
                /* pass */
            } else {
                panic!("Proposed block dynafed params not compact");
            }
        } else {
            panic!("No dynafed params");
        }

        assert_eq!(
            block.block_hash().to_string(),
            "4961df970cf12d789383974e6ab439f780d956b5a50162ca9d281362e46c605a"
        );
        assert_eq!(block.header.version, 0x20000000);

        // Full current and proposal
        let block: Block = hex_deserialize!(
            "\
            000000a01ecf88cda4d9e6339109c685417c526e8316fe0d3ea058765634dcbb\
            205d3081bd83073b1f1793154ab820c70a1fda32a0d45bb0e1f40c0c61ae0350\
            7f49c293debcc45d1400000002220020a6794de47a1612cc94c1b978d5bd1b25\
            873f4cab0b1a76260b0b8af9ad954dc74b0100002200204ae81572f06e1b88fd\
            5ced7a1a000945432e83e1551e6f721ee9c00b8cc33260015100022200204cb4\
            0d59d6e1bbe963f3a63021b0d7d5474b87206978a1129fbffc4d1c1cf7e44b01\
            00002200204ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c0\
            0b8cc332600151000500483045022100ab2203a8a68d7eca8a3a0fac91e7c780\
            2656d937535800da82f7102e1c06f7b80220576f004cb14b95178c71e36bf947\
            bfea496b00b66c18d2eb8febf46362d50e2b0147304402202d4630887d661a50\
            b76b7b32555fd76906ad298ce24483df42310ffbf62d451802200e0d64069e58\
            047c271c1b4051c1ff3d1cba7d32e56abb0d8b8bc30e1bed075b014830450221\
            00c6b196967c661c4543802a895ae731af44862e75d9e3c65b8efdd668727a34\
            af022041ff4d67029052eb6305d25d0fc4813d21a939ff5316a12562d0c90389\
            76f8e1016953210296db75c11ea3a292a372f6c94f5013eaeb379f701857a702\
            f3b83f88da21be6f21021f0d8638c413ef7769cd711ce84c8f192f5a85f0fd6d\
            8e63ddb4d2cf6740b23b2103cadff18e928133df2e670a3715c4e7a81d357de3\
            6ddaa5016628e70a3e6a452f53ae010200000001010000000000000000000000\
            000000000000000000000000000000000000000000ffffffff0401140101ffff\
            ffff020137c495f58d698979ff9124e8c7455fe79b13ddb96afa25c45894eb05\
            9868a8c001000000000000000000016a0137c495f58d698979ff9124e8c7455f\
            e79b13ddb96afa25c45894eb059868a8c001000000000000000000266a24aa21\
            a9ed94f15ed3a62165e4a0b99699cc28b48e19cb5bc1b1f47155db62d63f1e04\
            7d45000000000000012000000000000000000000000000000000000000000000\
            000000000000000000000000000000\
        "
        );

        // Test that this is a block with full current params and full proposed params
        if let ExtData::Dynafed {
            current, proposed, ..
        } = block.clone().header.ext
        {
            if let dynafed::Params::Full { .. } = current {
                /* pass */
            } else {
                panic!("Current block dynafed params not full");
            }
            if let dynafed::Params::Full { .. } = proposed {
                /* pass */
            } else {
                panic!("Proposed block dynafed params not full");
            }
        } else {
            panic!("No dynafed params");
        }
        assert_eq!(
            block.block_hash().to_string(),
            "e9a5176b1690a448f76fb691ab4d516e60e13a6e7a49454c62dbf0d611ffcce7"
        );
    }
}
