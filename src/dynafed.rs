// Rust Elements Library
// Written in 2019 by
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

//! Dynamic Federations

use std::io;

use bitcoin;
use bitcoin::hashes::{Hash, sha256, sha256d};
#[cfg(feature = "serde")] use serde::{Deserialize, Deserializer, Serialize, Serializer};
#[cfg(feature = "serde")] use std::fmt;

use encode::{self, Encodable, Decodable};

/// Dynamic federations paramaters, as encoded in a block header
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum Params {
    /// Null entry, used to signal "no vote" as a proposal
    Null,
    /// Compact params where the fedpeg data and extension space
    /// are not included, and are assumed to be equal to the values
    /// from the previous block
    Compact {
        /// "scriptPubKey" used for block signing
        signblockscript: bitcoin::Script,
        /// Maximum, in bytes, of the size of a blocksigning witness
        signblock_witness_limit: u32,
        /// Merkle root of extra data
        elided_root: sha256::Midstate,
    },
    /// Full dynamic federations parameters
    Full {
        /// "scriptPubKey" used for block signing
        signblockscript: bitcoin::Script,
        /// Maximum, in bytes, of the size of a blocksigning witness
        signblock_witness_limit: u32,
        /// Untweaked `scriptPubKey` used for pegins
        fedpeg_program: bitcoin::Script,
        /// For v0 fedpeg programs, the witness script of the untweaked
        /// pegin address. For future versions, this data has no defined
        /// meaning and will be considered "anyone can spend".
        fedpegscript: Vec<u8>,
        /// "Extension space" used by Liquid for PAK key entries
        extension_space: Vec<Vec<u8>>,
    },
}

impl Params {
    /// Check whether this is [Params::Null].
    pub fn is_null(&self) -> bool {
        match *self {
            Params::Null => true,
            Params::Compact { .. } => false,
            Params::Full { .. } => false,
        }
    }

    /// Check whether this is [Params::Compact].
    pub fn is_compact(&self) -> bool {
        match *self {
            Params::Null => false,
            Params::Compact { .. } => true,
            Params::Full { .. } => false,
        }
    }

    /// Check whether this is [Params::Full].
    pub fn is_full(&self) -> bool {
        match *self {
            Params::Null => false,
            Params::Compact { .. } => false,
            Params::Full { .. } => true,
        }
    }

    /// Get the signblockscript. Is [None] for [Null] params.
    pub fn signblockscript(&self) -> Option<&bitcoin::Script> {
        match *self {
            Params::Null => None,
            Params::Compact { ref signblockscript, ..} => Some(signblockscript),
            Params::Full { ref signblockscript, ..} => Some(signblockscript),
        }
    }

    /// Get the signblock_witness_limit. Is [None] for [Null] params.
    pub fn signblock_witness_limit(&self) -> Option<u32> {
        match *self {
            Params::Null => None,
            Params::Compact { signblock_witness_limit, ..} => Some(signblock_witness_limit),
            Params::Full { signblock_witness_limit, ..} => Some(signblock_witness_limit),
        }
    }

    /// Get the fedpeg_program. Is [None] for non-[Full] params.
    pub fn fedpeg_program(&self) -> Option<&bitcoin::Script> {
        match *self {
            Params::Null => None,
            Params::Compact { .. } => None,
            Params::Full { ref fedpeg_program, ..} => Some(fedpeg_program),
        }
    }

    /// Get the fedpegscript. Is [None] for non-[Full] params.
    pub fn fedpegscript(&self) -> Option<&Vec<u8>> {
        match *self {
            Params::Null => None,
            Params::Compact { .. } => None,
            Params::Full { ref fedpegscript, ..} => Some(fedpegscript),
        }
    }

    /// Get the extension_space. Is [None] for non-[Full] params.
    pub fn extension_space(&self) -> Option<&Vec<Vec<u8>>> {
        match *self {
            Params::Null => None,
            Params::Compact { .. } => None,
            Params::Full { ref extension_space, ..} => Some(extension_space),
        }
    }

    /// Get the elided_root. Is [None] for non-[Compact] params.
    pub fn elided_root(&self) -> Option<&sha256::Midstate> {
        match *self {
            Params::Null => None,
            Params::Compact { ref elided_root, ..} => Some(elided_root),
            Params::Full { .. } => None,
        }
    }

    /// Calculate the root of this [Params].
    pub fn calculate_root(&self) -> sha256::Midstate {
        fn serialize_hash<E: Encodable>(obj: &E) -> sha256d::Hash {
            let mut engine = sha256d::Hash::engine();
            obj.consensus_encode(&mut engine).expect("engines don't error");
            sha256d::Hash::from_engine(engine)
        }

        if self.is_null() {
            return sha256::Midstate::from_inner([0u8; 32]);
        }

        let extra_root = match *self {
            Params::Null => return sha256::Midstate::from_inner([0u8; 32]),
            Params::Compact { ref elided_root, .. } => *elided_root,
            Params::Full { ref fedpeg_program, ref fedpegscript, ref extension_space, .. } => {
                let leaves = [
                    serialize_hash(fedpeg_program).into_inner(),
                    serialize_hash(fedpegscript).into_inner(),
                    serialize_hash(extension_space).into_inner(),
                ];
                ::fast_merkle_root::fast_merkle_root(&leaves[..])
            },
        };
        let leaves = [
            serialize_hash(self.signblockscript().unwrap()).into_inner(),
            serialize_hash(&self.signblock_witness_limit().unwrap()).into_inner(),
        ];
        let compact_root = ::fast_merkle_root::fast_merkle_root(&leaves[..]);

        let leaves = [
            compact_root.into_inner(),
            extra_root.into_inner(),
        ];
        ::fast_merkle_root::fast_merkle_root(&leaves[..])
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for Params {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        use serde::de;

        enum Enum {
            Unknown,
            SignblockScript,
            SignblockWitnessLimit,
            ElidedRoot,
            FedpegProgram,
            FedpegScript,
            ExtSpace,
        }
        struct EnumVisitor;

        impl<'de> de::Visitor<'de> for EnumVisitor {
            type Value = Enum;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a field name")
            }

            fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
                match v {
                    "signblockscript" => Ok(Enum::SignblockScript),
                    "signblock_witness_limit" => Ok(Enum::SignblockWitnessLimit),
                    "elided_root" => Ok(Enum::ElidedRoot),
                    "fedpeg_program" => Ok(Enum::FedpegProgram),
                    "fedpegscript" => Ok(Enum::FedpegScript),
                    "extension_space" => Ok(Enum::ExtSpace),
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
            type Value = Params;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("block header extra data")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: de::MapAccess<'de>,
            {
                let mut signblockscript = None;
                let mut signblock_witness_limit = None;
                let mut elided_root = None;
                let mut fedpeg_program = None;
                let mut fedpegscript = None;
                let mut extension_space = None;

                loop {
                    match map.next_key::<Enum>()? {
                        Some(Enum::Unknown) => {
                            map.next_value::<de::IgnoredAny>()?;
                        },
                        Some(Enum::SignblockScript) => {
                            signblockscript = Some(map.next_value()?);
                        },
                        Some(Enum::SignblockWitnessLimit) => {
                            signblock_witness_limit = Some(map.next_value()?);
                        },
                        Some(Enum::ElidedRoot) => {
                            elided_root = Some(map.next_value()?);
                        },
                        Some(Enum::FedpegProgram) => {
                            fedpeg_program = Some(map.next_value()?);
                        },
                        Some(Enum::FedpegScript) => {
                            fedpegscript = Some(map.next_value()?);
                        },
                        Some(Enum::ExtSpace) => {
                            extension_space = Some(map.next_value()?);
                        },
                        None => { break; }
                    }
                }

                match (
                    signblockscript,
                    signblock_witness_limit,
                    elided_root,
                    fedpeg_program,
                    fedpegscript,
                    extension_space,
                ) {
                    (
                        Some(signblockscript),
                        Some(signblock_witness_limit),
                        _,
                        Some(fedpeg_program),
                        Some(fedpegscript),
                        Some(extension_space),
                    ) => Ok(Params::Full {
                        signblockscript,
                        signblock_witness_limit,
                        fedpeg_program,
                        fedpegscript,
                        extension_space,
                    }),
                    (
                        Some(signblockscript),
                        Some(signblock_witness_limit),
                        Some(elided_root),
                        _,
                        _,
                        _
                    ) => Ok(Params::Compact {
                        signblockscript,
                        signblock_witness_limit,
                        elided_root,
                    }),
                    // We should probably be stricter about errors here
                    _ => Ok(Params::Null),
                }
            }
        }

        static FIELDS: &'static [&'static str] = &[
            "signblockscript",
            "signblock_witness_limit",
            "fedpeg_program",
            "fedpegscript",
            "extension_space",
        ];
        d.deserialize_struct("Params", FIELDS, Visitor)
    }
}

#[cfg(feature = "serde")]
impl Serialize for Params {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;

        match *self {
            Params::Null => {
                let st = s.serialize_struct("Params", 0)?;
                st.end()
            },
            Params::Compact {
                ref signblockscript,
                ref signblock_witness_limit,
                ref elided_root,
            } => {
                let mut st = s.serialize_struct("Params", 2)?;
                st.serialize_field("signblockscript", signblockscript)?;
                st.serialize_field("signblock_witness_limit", signblock_witness_limit)?;
                st.serialize_field("elided_root", elided_root)?;
                st.end()
            },
            Params::Full {
                ref signblockscript,
                ref signblock_witness_limit,
                ref fedpeg_program,
                ref fedpegscript,
                ref extension_space,
            } => {
                let mut st = s.serialize_struct("Params", 5)?;
                st.serialize_field("signblockscript", signblockscript)?;
                st.serialize_field("signblock_witness_limit", signblock_witness_limit)?;
                st.serialize_field("fedpeg_program", fedpeg_program)?;
                st.serialize_field("fedpegscript", fedpegscript)?;
                st.serialize_field("extension_space", extension_space)?;
                st.end()
            },
        }
    }
}

impl Encodable for Params {
    fn consensus_encode<S: io::Write>(&self, mut s: S) -> Result<usize, encode::Error> {
        Ok(match *self {
            Params::Null => Encodable::consensus_encode(&0u8, &mut s)?,
            Params::Compact {
                ref signblockscript,
                ref signblock_witness_limit,
                ref elided_root,
            } => {
                Encodable::consensus_encode(&1u8, &mut s)? +
                Encodable::consensus_encode(signblockscript, &mut s)? +
                Encodable::consensus_encode(signblock_witness_limit, &mut s)? +
                Encodable::consensus_encode(&elided_root.into_inner(), &mut s)?
            },
            Params::Full {
                ref signblockscript,
                ref signblock_witness_limit,
                ref fedpeg_program,
                ref fedpegscript,
                ref extension_space,
            } => {
                Encodable::consensus_encode(&2u8, &mut s)? +
                Encodable::consensus_encode(signblockscript, &mut s)? +
                Encodable::consensus_encode(signblock_witness_limit, &mut s)? +
                Encodable::consensus_encode(fedpeg_program, &mut s)? +
                Encodable::consensus_encode(fedpegscript, &mut s)? +
                Encodable::consensus_encode(extension_space, &mut s)?
            },
        })
    }
}

impl Decodable for Params {
    fn consensus_decode<D: io::Read>(mut d: D) -> Result<Self, encode::Error> {
        let ser_type: u8 = Decodable::consensus_decode(&mut d)?;
        match ser_type {
            0 => Ok(Params::Null),
            1 => Ok(Params::Compact {
                signblockscript: Decodable::consensus_decode(&mut d)?,
                signblock_witness_limit: Decodable::consensus_decode(&mut d)?,
                elided_root: sha256::Midstate::from_inner(Decodable::consensus_decode(&mut d)?),
            }),
            2 => Ok(Params::Full {
                signblockscript: Decodable::consensus_decode(&mut d)?,
                signblock_witness_limit: Decodable::consensus_decode(&mut d)?,
                fedpeg_program: Decodable::consensus_decode(&mut d)?,
                fedpegscript: Decodable::consensus_decode(&mut d)?,
                extension_space: Decodable::consensus_decode(&mut d)?,
            }),
            _ => Err(encode::Error::ParseFailed(
                "bad serialize type for dynafed parameters"
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use bitcoin;
    use bitcoin::hashes::hex::ToHex;
    use bitcoin::hashes::sha256;

    #[test]
    fn test_param_roots() {
        // Taken from the following Elements Core test:

        // CScript signblockscript(opcodetype(1));
        // uint32_t signblock_wl(2);
        // CScript fp_program(opcodetype(3));
        // CScript fp_script(opcodetype(4));
        // std::vector<std::vector<unsigned char>> ext{ {5, 6}, {7} };
        //
        // DynaFedParamEntry compact_entry = DynaFedParamEntry(signblockscript, signblock_wl);
        // BOOST_CHECK_EQUAL(
        //     compact_entry.CalculateRoot().GetHex(),
        //     "dff5f3793abc06a6d75e80fe3cfd47406f732fa4ec9305960ae2a229222a1ad5"
        // );
        //
        // DynaFedParamEntry full_entry =
        //     DynaFedParamEntry(signblockscript, signblock_wl, fp_program, fp_script, ext);
        // BOOST_CHECK_EQUAL(
        //     full_entry.CalculateRoot().GetHex(),
        //     "175be2087ba7cc0e33348bef493bd3e34f31f64bf9226e5881ab310dafa432ff"
        // );
        //
        // DynaFedParams params = DynaFedParams(compact_entry, full_entry);
        // BOOST_CHECK_EQUAL(
        //     params.CalculateRoot().GetHex(),
        //     "e56cf79487952dfa85fe6a85829600adc19714ba6ab1157fdff02b25ae60cee2"
        // );

        let signblockscript: bitcoin::Script = vec![1].into();
        let signblock_wl = 2;
        let fp_program: bitcoin::Script = vec![3].into();
        let fp_script = vec![4];
        let ext = vec![vec![5, 6], vec![7]];

        let compact_entry = Params::Compact {
            signblockscript: signblockscript.clone(),
            signblock_witness_limit: signblock_wl,
            elided_root: sha256::Midstate::from_inner([0; 32]),
        };
        assert_eq!(
            compact_entry.calculate_root().to_hex(),
            "f98f149fd11da6fbe26d0ee53cadd28372fa9eed2cb7080f41da7ca311531777"
        );

        let full_entry = Params::Full {
            signblockscript: signblockscript,
            signblock_witness_limit: signblock_wl,
            fedpeg_program: fp_program,
            fedpegscript: fp_script,
            extension_space: ext,
        };
        assert_eq!(
            full_entry.calculate_root().to_hex(),
            "8eb1b83cce69a3d8b0bfb7fbe77ae8f1d24b57a9cae047b8c0aba084ad878249"
        );

        let header = ::block::BlockHeader{
            ext: ::block::ExtData::Dynafed {
                current: compact_entry,
                proposed: full_entry,
                signblock_witness: vec![],
            },
            ..Default::default()
        };
        assert_eq!(
            header.calculate_dynafed_params_root().unwrap().to_hex(),
            "113160f76dc17fe367a2def79aefe06feeea9c795310c9e88aeedc23e145982e"
        );
    }
}
