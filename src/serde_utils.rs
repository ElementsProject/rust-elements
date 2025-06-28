//! Module for special serde serializations.
//! Copied from rust-bitcoin as is.
pub mod btreemap_byte_values {
    //! Module for serialization of `BTreeMaps` with hex byte values.
    #![allow(missing_docs)]

    // NOTE: This module can be exactly copied to use with HashMap.

    use ::std::collections::BTreeMap;
    use crate::hex::{FromHex, ToHex};
    use serde;

    pub fn serialize<S, T>(v: &BTreeMap<T, Vec<u8>>, s: S)
        -> Result<S::Ok, S::Error> where
        S: serde::Serializer,
        T: serde::Serialize + ::std::hash::Hash + Eq + Ord,
    {
        use serde::ser::SerializeMap;

        // Don't do anything special when not human readable.
        if s.is_human_readable() {
            let mut map = s.serialize_map(Some(v.len()))?;
            for (key, value) in v {
                map.serialize_entry(key, &value.to_hex())?;
            }
            map.end()
        } else {
            serde::Serialize::serialize(v, s)
        }
    }

    pub fn deserialize<'de, D, T>(d: D)
        -> Result<BTreeMap<T, Vec<u8>>, D::Error> where
        D: serde::Deserializer<'de>,
        T: serde::Deserialize<'de> + ::std::hash::Hash + Eq + Ord,
    {
        use ::std::marker::PhantomData;

        struct Visitor<T>(PhantomData<T>);
        impl<'de, T> serde::de::Visitor<'de> for Visitor<T> where
            T: serde::Deserialize<'de> + ::std::hash::Hash + Eq + Ord,
        {
            type Value = BTreeMap<T, Vec<u8>>;

            fn expecting(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
                write!(f, "a map with hexadecimal values")
            }

            fn visit_map<A: serde::de::MapAccess<'de>>(self, mut a: A)
                -> Result<Self::Value, A::Error>
            {
                let mut ret = BTreeMap::new();
                while let Some((key, value)) = a.next_entry()? {
                    ret.insert(key, FromHex::from_hex(value).map_err(serde::de::Error::custom)?);
                }
                Ok(ret)
            }
        }

        // Don't do anything special when not human readable.
        if d.is_human_readable() {
            d.deserialize_map(Visitor(PhantomData))
        } else {
            serde::Deserialize::deserialize(d)
        }
    }
}

pub mod btreemap_as_seq {
    //! Module for serialization of `BTreeMaps` as lists of sequences because
    //! `serde_json` will not serialize hashmaps with non-string keys be default.
    #![allow(missing_docs)]

    // NOTE: This module can be exactly copied to use with HashMap.

    use ::std::collections::BTreeMap;
    use serde;

    pub fn serialize<S, T, U>(v: &BTreeMap<T, U>, s: S)
        -> Result<S::Ok, S::Error> where
        S: serde::Serializer,
        T: serde::Serialize + ::std::hash::Hash + Eq + Ord,
        U: serde::Serialize,
    {
        use serde::ser::SerializeSeq;

        // Don't do anything special when not human readable.
        if s.is_human_readable() {
            let mut seq = s.serialize_seq(Some(v.len()))?;
            for pair in v {
                seq.serialize_element(&pair)?;
            }
            seq.end()
        } else {
            serde::Serialize::serialize(v, s)
        }
    }

    pub fn deserialize<'de, D, T, U>(d: D)
        -> Result<BTreeMap<T, U>, D::Error> where
        D: serde::Deserializer<'de>,
        T: serde::Deserialize<'de> + ::std::hash::Hash + Eq + Ord,
        U: serde::Deserialize<'de>,
    {
        use ::std::marker::PhantomData;

        struct Visitor<T, U>(PhantomData<(T, U)>);
        impl<'de, T, U> serde::de::Visitor<'de> for Visitor<T, U> where
            T: serde::Deserialize<'de> + ::std::hash::Hash + Eq + Ord,
            U: serde::Deserialize<'de>,
        {
            type Value = BTreeMap<T, U>;

            fn expecting(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
                write!(f, "a sequence of pairs")
            }

            fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut a: A)
                -> Result<Self::Value, A::Error>
            {
                let mut ret = BTreeMap::new();
                while let Some((key, value)) = a.next_element()? {
                    ret.insert(key, value);
                }
                Ok(ret)
            }
        }

        // Don't do anything special when not human readable.
        if d.is_human_readable() {
            d.deserialize_seq(Visitor(PhantomData))
        } else {
            serde::Deserialize::deserialize(d)
        }
    }
}

pub mod btreemap_as_seq_byte_values {
    //! Module for serialization of `BTreeMaps` as lists of sequences because
    //! `serde_json` will not serialize hashmaps with non-string keys be default.
    #![allow(missing_docs)]

    // NOTE: This module can be exactly copied to use with HashMap.

    use ::std::collections::BTreeMap;
    use serde;

    /// A custom key-value pair type that serialized the bytes as hex.
    #[derive(Debug, serde::Deserialize)]
    struct OwnedPair<T>(
        T,
        #[serde(deserialize_with = "crate::serde_utils::hex_bytes::deserialize")]
        Vec<u8>,
    );

    /// A custom key-value pair type that serialized the bytes as hex.
    #[derive(Debug, serde::Serialize)]
    struct BorrowedPair<'a, T: 'static>(
        &'a T,
        #[serde(serialize_with = "crate::serde_utils::hex_bytes::serialize")]
        &'a [u8],
    );

    pub fn serialize<S, T>(v: &BTreeMap<T, Vec<u8>>, s: S)
        -> Result<S::Ok, S::Error> where
        S: serde::Serializer,
        T: serde::Serialize + ::std::hash::Hash + Eq + Ord + 'static,
    {
        use serde::ser::SerializeSeq;

        // Don't do anything special when not human readable.
        if s.is_human_readable() {
            let mut seq = s.serialize_seq(Some(v.len()))?;
            for (key, value) in v {
                seq.serialize_element(&BorrowedPair(key, value))?;
            }
            seq.end()
        } else {
            serde::Serialize::serialize(v, s)
        }
    }

    pub fn deserialize<'de, D, T>(d: D)
        -> Result<BTreeMap<T, Vec<u8>>, D::Error> where
        D: serde::Deserializer<'de>,
        T: serde::Deserialize<'de> + ::std::hash::Hash + Eq + Ord,
    {
        use ::std::marker::PhantomData;

        struct Visitor<T>(PhantomData<T>);
        impl<'de, T> serde::de::Visitor<'de> for Visitor<T> where
            T: serde::Deserialize<'de> + ::std::hash::Hash + Eq + Ord,
        {
            type Value = BTreeMap<T, Vec<u8>>;

            fn expecting(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
                write!(f, "a sequence of pairs")
            }

            fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut a: A)
                -> Result<Self::Value, A::Error>
            {
                let mut ret = BTreeMap::new();
                while let Option::Some(OwnedPair(key, value)) = a.next_element()? {
                    ret.insert(key, value);
                }
                Ok(ret)
            }
        }

        // Don't do anything special when not human readable.
        if d.is_human_readable() {
            d.deserialize_seq(Visitor(PhantomData))
        } else {
            serde::Deserialize::deserialize(d)
        }
    }
}

pub mod hex_bytes {
    //! Module for serialization of byte arrays as hex strings.
    #![allow(missing_docs)]

    use crate::hex::{FromHex, ToHex};
    use serde;

    pub fn serialize<T, S>(bytes: &T, s: S) -> Result<S::Ok, S::Error>
        where T: serde::Serialize + AsRef<[u8]>, S: serde::Serializer
    {
        // Don't do anything special when not human readable.
        if s.is_human_readable() {
            s.serialize_str(&bytes.as_ref().to_hex())
        } else {
            serde::Serialize::serialize(bytes, s)
        }
    }

    pub fn deserialize<'de, D, B>(d: D) -> Result<B, D::Error>
        where D: serde::Deserializer<'de>, B: serde::Deserialize<'de> + FromHex,
    {
        struct Visitor<B>(::std::marker::PhantomData<B>);

        impl<B: FromHex> serde::de::Visitor<'_> for Visitor<B> {
            type Value = B;

            fn expecting(&self, formatter: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
                formatter.write_str("an ASCII hex string")
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
                where E: serde::de::Error,
            {
                if let Ok(hex) = ::std::str::from_utf8(v) {
                    FromHex::from_hex(hex).map_err(E::custom)
                } else {
                    Err(E::invalid_value(serde::de::Unexpected::Bytes(v), &self))
                }
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
                where E: serde::de::Error,
            {
                FromHex::from_hex(v).map_err(E::custom)
            }
        }

        // Don't do anything special when not human readable.
        if d.is_human_readable() {
            d.deserialize_str(Visitor(::std::marker::PhantomData))
        } else {
            serde::Deserialize::deserialize(d)
        }
    }
}
