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

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for Params {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        use serde::de;

        enum Enum {
            Unknown,
            SignblockScript,
            SignblockWitnessLimit,
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
                    fedpeg_program,
                    fedpegscript,
                    extension_space,
                ) {
                    (
                        Some(signblockscript),
                        Some(signblock_witness_limit),
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
                        _,
                        _,
                        _
                    ) => Ok(Params::Compact {
                        signblockscript,
                        signblock_witness_limit,
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
            } => {
                let mut st = s.serialize_struct("Params", 2)?;
                st.serialize_field("signblockscript", signblockscript)?;
                st.serialize_field("signblock_witness_limit", signblock_witness_limit)?;
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
            } => {
                Encodable::consensus_encode(&1u8, &mut s)? +
                Encodable::consensus_encode(signblockscript, &mut s)? +
                Encodable::consensus_encode(signblock_witness_limit, &mut s)?
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
