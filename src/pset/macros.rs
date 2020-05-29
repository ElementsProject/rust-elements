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

#[allow(unused_macros)]
macro_rules! hex_psbt {
    ($s:expr) => { ::consensus::deserialize(&<Vec<u8> as ::hashes::hex::FromHex>::from_hex($s).unwrap()) };
}

macro_rules! merge {
    ($thing:ident, $slf:ident, $other:ident) => {
        if let (&None, Some($thing)) = (&$slf.$thing, $other.$thing) {
            $slf.$thing = Some($thing);
        }
    };
}

macro_rules! impl_psbt_de_serialize {
    ($thing:ty) => {
        impl_psbt_serialize!($thing);
        impl_psbt_deserialize!($thing);
    };
}

macro_rules! impl_psbt_deserialize {
    ($thing:ty) => {
        impl ::pset::serialize::Deserialize for $thing {
            fn deserialize(bytes: &[u8]) -> Result<Self, ::encode::Error> {
                ::encode::deserialize(&bytes[..])
            }
        }
    };
}

macro_rules! impl_psbt_serialize {
    ($thing:ty) => {
        impl ::pset::serialize::Serialize for $thing {
            fn serialize(&self) -> Vec<u8> {
                ::encode::serialize(self)
            }
        }
    };
}

macro_rules! impl_psbtmap_consensus_encoding {
    ($thing:ty) => {
        impl ::encode::Encodable for $thing {
            fn consensus_encode<S: ::std::io::Write>(
                &self,
                mut s: S,
            ) -> Result<usize, ::encode::Error> {
                let mut len = 0;
                for pair in ::pset::Map::get_pairs(self)? {
                    len += ::encode::Encodable::consensus_encode(
                        &pair,
                        &mut s,
                    )?;
                }

                Ok(len + ::encode::Encodable::consensus_encode(&0x00_u8, s)?)
            }
        }
    };
}

macro_rules! impl_psbtmap_consensus_decoding {
    ($thing:ty) => {
        impl ::encode::Decodable for $thing {
            fn consensus_decode<D: ::std::io::Read>(
                mut d: D,
            ) -> Result<Self, ::encode::Error> {
                let mut rv: Self = ::std::default::Default::default();

                loop {
                    match ::encode::Decodable::consensus_decode(&mut d) {
                        Ok(pair) => ::pset::Map::insert_pair(&mut rv, pair)?,
                        Err(::encode::Error::Pset(::pset::Error::NoMorePairs)) => return Ok(rv),
                        Err(e) => return Err(e),
                    }
                }
            }
        }
    };
}

macro_rules! impl_psbtmap_consensus_enc_dec_oding {
    ($thing:ty) => {
        impl_psbtmap_consensus_decoding!($thing);
        impl_psbtmap_consensus_encoding!($thing);
    };
}

#[cfg_attr(rustfmt, rustfmt_skip)]
macro_rules! impl_psbt_insert_pair {
    ($slf:ident.$unkeyed_name:ident <= <$raw_key:ident: _>|<$raw_value:ident: $unkeyed_value_type:ty>) => {
        if $raw_key.key.is_empty() {
            if $slf.$unkeyed_name.is_none() {
                let val: $unkeyed_value_type = ::pset::serialize::Deserialize::deserialize(&$raw_value)?;

                $slf.$unkeyed_name = Some(val)
            } else {
                return Err(::pset::Error::DuplicateKey($raw_key.into()).into());
            }
        } else {
            return Err(::pset::Error::InvalidKey($raw_key.into()).into());
        }
    };
    ($slf:ident.$keyed_name:ident <= <$raw_key:ident: $keyed_key_type:ty>|<$raw_value:ident: $keyed_value_type:ty>) => {
        if !$raw_key.key.is_empty() {
            let key_val: $keyed_key_type = ::pset::serialize::Deserialize::deserialize(&$raw_key.key)?;

            match $slf.$keyed_name.entry(key_val) {
                ::std::collections::btree_map::Entry::Vacant(empty_key) => {
                    let val: $keyed_value_type = ::pset::serialize::Deserialize::deserialize(&$raw_value)?;
                    empty_key.insert(val);
                }
                ::std::collections::btree_map::Entry::Occupied(_) => return Err(::pset::Error::DuplicateKey($raw_key.into()).into()),
            }
        } else {
            return Err(::pset::Error::InvalidKey($raw_key.into()).into());
        }
    };
}

#[cfg_attr(rustfmt, rustfmt_skip)]
macro_rules! impl_psbt_extract_prop {
    ($prop_key:expr, $raw_key:ident, $raw_value:ident) => {{
        let prop_key = $prop_key;
        if $raw_key.key.len() >= prop_key.len() + 1 &&
            $raw_key.key[0..prop_key.len()] == prop_key[..]
        {
            let raw_key = ::pset::raw::BorrowedKey {
                type_value: $raw_key.key[prop_key.len()],
                key: &$raw_key.key[prop_key.len() + 1 ..],
            };
            Some((raw_key, $raw_value))
        } else {
            None
        }
    }}
}

#[cfg_attr(rustfmt, rustfmt_skip)]
macro_rules! impl_psbt_get_pair {
    ($rv:ident.push($slf:ident.$unkeyed_name:ident as <$unkeyed_typeval:expr, _>|<$unkeyed_value_type:ty>)) => {
        if let Some(ref $unkeyed_name) = $slf.$unkeyed_name {
            $rv.push(::pset::raw::Pair {
                key: ::pset::raw::Key {
                    type_value: $unkeyed_typeval,
                    key: vec![],
                },
                value: ::pset::serialize::Serialize::serialize($unkeyed_name),
            });
        }
    };
    ($rv:ident.push($slf:ident.$keyed_name:ident as <$keyed_typeval:expr, $keyed_key_type:ty>|<$keyed_value_type:ty>)) => {
        for (key, val) in &$slf.$keyed_name {
            $rv.push(::pset::raw::Pair {
                key: ::pset::raw::Key {
                    type_value: $keyed_typeval,
                    key: ::pset::serialize::Serialize::serialize(key),
                },
                value: ::pset::serialize::Serialize::serialize(val),
            });
        }
    };
}

#[cfg_attr(rustfmt, rustfmt_skip)]
macro_rules! impl_psbt_get_prop_pair {
    ($rv:ident.push($slf:ident.$unkeyed_name:ident as <$prop_key:expr, $unkeyed_typeval:expr, _>|<$unkeyed_value_type:ty>)) => {
        if let Some(ref $unkeyed_name) = $slf.$unkeyed_name {
            $rv.push(::pset::raw::Pair {
                key: ::pset::raw::Key {
                    type_value: ::pset::PSET_PROP_KEY,
                    key: {
                        let prop_key = $prop_key;
                        let mut buf = Vec::with_capacity(prop_key.len() + 1);
                        buf[0] = $unkeyed_typeval;
                        buf[1..].copy_from_slice(prop_key);
                        buf
                    },
                },
                value: ::pset::serialize::Serialize::serialize($unkeyed_name),
            });
        }
    };
    ($rv:ident.push($slf:ident.$keyed_name:ident as <$prop_key:expr, $keyed_typeval:expr, $keyed_key_type:ty>|<$keyed_value_type:ty>)) => {
        for (key, val) in &$slf.$keyed_name {
            $rv.push(::pset::raw::Pair {
                key: ::pset::raw::Key {
                    type_value: ::pset::PSET_PROP_KEY,
                    key: {
                        let key = ::pset::serialize::Serialize::serialize(key);
                        let prop_key = $prop_key;
                        let mut buf = Vec::with_capacity(key.len() + prop_key.len() + 1);
                        buf[0] = $unkeyed_typeval;
                        buf[1..prop_key.len()+1].copy_from_slice(prop_key);
                        buf[prop_key.len()+1..].copy_from_slice(key);
                        buf
                    },
                },
                value: ::pset::serialize::Serialize::serialize(val),
            });
        }
    };
}
