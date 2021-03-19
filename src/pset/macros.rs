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
macro_rules! hex_pset {
    ($s:expr) => { $crate::encode::deserialize(&<Vec<u8> as $crate::hashes::hex::FromHex>::from_hex($s).unwrap()) };
}

macro_rules! merge {
    ($thing:ident, $slf:ident, $other:ident) => {
        if let (&None, Some($thing)) = (&$slf.$thing, $other.$thing) {
            $slf.$thing = Some($thing);
        }
    };
}

macro_rules! impl_pset_de_serialize {
    ($thing:ty) => {
        impl_pset_serialize!($thing);
        impl_pset_deserialize!($thing);
    };
}

macro_rules! impl_pset_deserialize {
    ($thing:ty) => {
        impl $crate::pset::serialize::Deserialize for $thing {
            fn deserialize(bytes: &[u8]) -> Result<Self, $crate::encode::Error> {
                $crate::encode::deserialize(&bytes[..])
            }
        }
    };
}

macro_rules! impl_pset_serialize {
    ($thing:ty) => {
        impl $crate::pset::serialize::Serialize for $thing {
            fn serialize(&self) -> Vec<u8> {
                $crate::encode::serialize(self)
            }
        }
    };
}

macro_rules! impl_psetmap_consensus_encoding {
    ($thing:ty) => {
        impl $crate::encode::Encodable for $thing {
            fn consensus_encode<S: ::std::io::Write>(
                &self,
                mut s: S,
            ) -> Result<usize, $crate::encode::Error> {
                let mut len = 0;
                for pair in $crate::pset::Map::get_pairs(self)? {
                    len += $crate::encode::Encodable::consensus_encode(
                        &pair,
                        &mut s,
                    )?;
                }

                Ok(len + $crate::encode::Encodable::consensus_encode(&0x00_u8, s)?)
            }
        }
    };
}

#[cfg_attr(rustfmt, rustfmt_skip)]
macro_rules! impl_pset_prop_insert_pair {
    ($slf:ident.$unkeyed_name:ident <= <$raw_key:ident: _>|<$raw_value:ident: $unkeyed_value_type:ty>) => {
        if $crate::pset::raw::ProprietaryKey::<u8>::from_key($raw_key.clone())?.key.is_empty() {
            if $slf.$unkeyed_name.is_none() {
                let val: $unkeyed_value_type = $crate::pset::serialize::Deserialize::deserialize(&$raw_value)?;
                $slf.$unkeyed_name = Some(val)
            } else {
                return Err($crate::pset::Error::DuplicateKey($raw_key).into());
            }
        } else {
            return Err($crate::pset::Error::InvalidKey($raw_key).into());
        }
    };
    ($unkeyed_name:ident <= <$raw_key:ident: _>|<$raw_value:ident: $unkeyed_value_type:ty>) => {
        if $crate::pset::raw::ProprietaryKey::<u8>::from_key($raw_key.clone())?.key.is_empty() {
            if $unkeyed_name.is_none() {
                let val: $unkeyed_value_type = $crate::pset::serialize::Deserialize::deserialize(&$raw_value)?;
                $unkeyed_name = Some(val)
            } else {
                return Err($crate::pset::Error::DuplicateKey($raw_key).into());
            }
        } else {
            return Err($crate::pset::Error::InvalidKey($raw_key).into());
        }
    };
}

#[cfg_attr(rustfmt, rustfmt_skip)]
macro_rules! impl_pset_insert_pair {
    ($slf:ident.$unkeyed_name:ident <= <$raw_key:ident: _>|<$raw_value:ident: $unkeyed_value_type:ty>) => {
        if $raw_key.key.is_empty() {
            if $slf.$unkeyed_name.is_none() {
                let val: $unkeyed_value_type = $crate::pset::serialize::Deserialize::deserialize(&$raw_value)?;
                $slf.$unkeyed_name = Some(val)
            } else {
                return Err($crate::pset::Error::DuplicateKey($raw_key).into());
            }
        } else {
            return Err($crate::pset::Error::InvalidKey($raw_key).into());
        }
    };
    ($unkeyed_name:ident <= <$raw_key:ident: _>|<$raw_value:ident: $unkeyed_value_type:ty>) => {
        if $raw_key.key.is_empty() {
            if $unkeyed_name.is_none() {
                let val: $unkeyed_value_type = $crate::pset::serialize::Deserialize::deserialize(&$raw_value)?;
                $unkeyed_name = Some(val)
            } else {
                return Err($crate::pset::Error::DuplicateKey($raw_key).into());
            }
        } else {
            return Err($crate::pset::Error::InvalidKey($raw_key).into());
        }
    };
    ($slf:ident.$keyed_name:ident <= <$raw_key:ident: $keyed_key_type:ty>|<$raw_value:ident: $keyed_value_type:ty>) => {
        if !$raw_key.key.is_empty() {
            let key_val: $keyed_key_type = $crate::pset::serialize::Deserialize::deserialize(&$raw_key.key)?;
            match $slf.$keyed_name.entry(key_val) {
                ::std::collections::btree_map::Entry::Vacant(empty_key) => {
                    let val: $keyed_value_type = $crate::pset::serialize::Deserialize::deserialize(&$raw_value)?;
                    empty_key.insert(val);
                }
                ::std::collections::btree_map::Entry::Occupied(_) => return Err($crate::pset::Error::DuplicateKey($raw_key).into()),
            }
        } else {
            return Err($crate::pset::Error::InvalidKey($raw_key).into());
        }
    };
}


#[cfg_attr(rustfmt, rustfmt_skip)]
macro_rules! impl_pset_get_pair {
    ($rv:ident.push($slf:ident.$unkeyed_name:ident as <$unkeyed_typeval:expr, _>)) => {
        if let Some(ref $unkeyed_name) = $slf.$unkeyed_name {
            $rv.push($crate::pset::raw::Pair {
                key: $crate::pset::raw::Key {
                    type_value: $unkeyed_typeval,
                    key: vec![],
                },
                value: $crate::pset::serialize::Serialize::serialize($unkeyed_name),
            });
        }
    };
    ($rv:ident.push($unkeyed_name:ident as <$unkeyed_typeval:expr, _>)) => {
        if let Some(ref $unkeyed_name) = $unkeyed_name {
            $rv.push($crate::pset::raw::Pair {
                key: $crate::pset::raw::Key {
                    type_value: $unkeyed_typeval,
                    key: vec![],
                },
                value: $crate::pset::serialize::Serialize::serialize($unkeyed_name),
            });
        }
    };
    ($rv:ident.push_prop($slf:ident.$unkeyed_name:ident as <$unkeyed_typeval:expr, _>)) => {
        if let Some(ref $unkeyed_name) = $slf.$unkeyed_name {
            let key = $crate::pset::raw::ProprietaryKey::from_pset_pair($unkeyed_typeval, vec![]);
            $rv.push($crate::pset::raw::Pair {
                key: key.to_key(),
                value: $crate::pset::serialize::Serialize::serialize($unkeyed_name),
            });
        }
    };
    ($rv:ident.push_mandatory($unkeyed_name:ident as <$unkeyed_typeval:expr, _>)) => {
            $rv.push($crate::pset::raw::Pair {
                key: $crate::pset::raw::Key {
                    type_value: $unkeyed_typeval,
                    key: vec![],
                },
                value: $crate::pset::serialize::Serialize::serialize(&$unkeyed_name),
            });
    };
    ($rv:ident.push($slf:ident.$keyed_name:ident as <$keyed_typeval:expr, $keyed_key_type:ty>)) => {
        for (key, val) in &$slf.$keyed_name {
            $rv.push($crate::pset::raw::Pair {
                key: $crate::pset::raw::Key {
                    type_value: $keyed_typeval,
                    key: $crate::pset::serialize::Serialize::serialize(key),
                },
                value: $crate::pset::serialize::Serialize::serialize(val),
            });
        }
    };
}

// macros for serde of hashes
macro_rules! impl_pset_hash_de_serialize {
    ($hash_type:ty) => {
        impl_pset_hash_serialize!($hash_type);
        impl_pset_hash_deserialize!($hash_type);
    };
}

macro_rules! impl_pset_hash_deserialize {
    ($hash_type:ty) => {
        impl $crate::pset::serialize::Deserialize for $hash_type {
            fn deserialize(bytes: &[u8]) -> Result<Self, $crate::encode::Error> {
                <$hash_type>::from_slice(&bytes[..]).map_err(|e| {
                    $crate::pset::Error::from(e).into()
                })
            }
        }
    };
}

macro_rules! impl_pset_hash_serialize {
    ($hash_type:ty) => {
        impl $crate::pset::serialize::Serialize for $hash_type {
            fn serialize(&self) -> Vec<u8> {
                self.into_inner().to_vec()
            }
        }
    };
}
