// Rust Bitcoin Library
// Written in 2014 by
//     Andrew Poelstra <apoelstra@wpsoftware.net>
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

macro_rules! impl_consensus_encoding {
    ($thing:ident, $($field:ident),+) => (
        impl $crate::encode::Encodable for $thing {
            #[inline]
            fn consensus_encode<S: std::io::Write>(&self, mut s: S) -> Result<usize, $crate::encode::Error> {
                let mut ret = 0;
                $( ret += self.$field.consensus_encode(&mut s)?; )+
                Ok(ret)
            }
        }

        impl $crate::encode::Decodable for $thing {
            #[inline]
            fn consensus_decode<D: std::io::Read>(mut d: D) -> Result<$thing, $crate::encode::Error> {
                Ok($thing {
                    $( $field: $crate::encode::Decodable::consensus_decode(&mut d)?, )+
                })
            }
        }
    );
}

macro_rules! serde_struct_impl {
    ($name:ident, $($fe:ident),*) => (
        #[cfg(feature = "serde")]
        impl<'de> $crate::serde::Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<$name, D::Error>
            where
                D: $crate::serde::de::Deserializer<'de>,
            {
                use std::fmt::{self, Formatter};
                use $crate::serde::de::IgnoredAny;

                #[allow(non_camel_case_types)]
                enum Enum { Unknown__Field, $($fe),* }

                struct EnumVisitor;
                impl<'de> $crate::serde::de::Visitor<'de> for EnumVisitor {
                    type Value = Enum;

                    fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
                        formatter.write_str("a field name")
                    }

                    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
                    where
                        E: $crate::serde::de::Error,
                    {
                        match v {
                            $(
                            stringify!($fe) => Ok(Enum::$fe)
                            ),*,
                            _ => Ok(Enum::Unknown__Field)
                        }
                    }
                }

                impl<'de> $crate::serde::Deserialize<'de> for Enum {
                    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
                    where
                        D: ::serde::de::Deserializer<'de>,
                    {
                        deserializer.deserialize_str(EnumVisitor)
                    }
                }

                struct Visitor;

                impl<'de> $crate::serde::de::Visitor<'de> for Visitor {
                    type Value = $name;

                    fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
                        formatter.write_str("a struct")
                    }

                    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
                    where
                        A: $crate::serde::de::MapAccess<'de>,
                    {
                        use $crate::serde::de::Error;

                        $(let mut $fe = None;)*

                        loop {
                            match map.next_key::<Enum>()? {
                                Some(Enum::Unknown__Field) => {
                                    map.next_value::<IgnoredAny>()?;
                                }
                                $(
                                    Some(Enum::$fe) => {
                                        $fe = Some(map.next_value()?);
                                    }
                                )*
                                None => { break; }
                            }
                        }

                        $(
                            let Some($fe) = $fe else {
                                return Err(A::Error::missing_field(stringify!($fe)));
                            };
                        )*

                        let ret = $name {
                            $($fe),*
                        };

                        Ok(ret)
                    }
                }
                // end type defs

                static FIELDS: &'static [&'static str] = &[$(stringify!($fe)),*];

                deserializer.deserialize_struct(stringify!($name), FIELDS, Visitor)
            }
        }

        #[cfg(feature = "serde")]
        impl $crate::serde::Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: $crate::serde::Serializer,
            {
                use $crate::serde::ser::SerializeStruct;

                // Only used to get the struct length.
                static FIELDS: &'static [&'static str] = &[$(stringify!($fe)),*];

                let mut st = serializer.serialize_struct(stringify!($name), FIELDS.len())?;

                $(
                    st.serialize_field(stringify!($fe), &self.$fe)?;
                )*

                st.end()
            }
        }
    )
}

macro_rules! serde_string_impl {
    ($name:ident, $expecting:expr) => {
        #[cfg(feature = "serde")]
        impl<'de> $crate::serde::Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<$name, D::Error>
            where
                D: $crate::serde::de::Deserializer<'de>,
            {
                use ::std::fmt::{self, Formatter};
                use ::std::str::FromStr;

                struct Visitor;
                impl<'de> $crate::serde::de::Visitor<'de> for Visitor {
                    type Value = $name;

                    fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
                        formatter.write_str($expecting)
                    }

                    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
                    where
                        E: $crate::serde::de::Error,
                    {
                        $name::from_str(v).map_err(E::custom)
                    }

                    fn visit_borrowed_str<E>(self, v: &'de str) -> Result<Self::Value, E>
                    where
                        E: $crate::serde::de::Error,
                    {
                        self.visit_str(v)
                    }

                    fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
                    where
                        E: $crate::serde::de::Error,
                    {
                        self.visit_str(&v)
                    }
                }

                deserializer.deserialize_str(Visitor)
            }
        }

        #[cfg(feature = "serde")]
        impl<'de> $crate::serde::Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: $crate::serde::Serializer,
            {
                serializer.collect_str(&self)
            }
        }
    };
}

/// A combination of `serde_struct_impl` and `serde_string_impl` where string is
/// used for human-readable serialization and struct is used for
/// non-human-readable serialization.
macro_rules! serde_struct_human_string_impl {
    ($name:ident, $expecting:expr, $($fe:ident),*) => (
        #[cfg(feature = "serde")]
        impl<'de> $crate::serde::Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<$name, D::Error>
            where
                D: $crate::serde::de::Deserializer<'de>,
            {
                if deserializer.is_human_readable() {
                    use ::std::fmt::{self, Formatter};
                    use ::std::str::FromStr;

                    struct Visitor;
                    impl<'de> $crate::serde::de::Visitor<'de> for Visitor {
                        type Value = $name;

                        fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
                            formatter.write_str($expecting)
                        }

                        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
                        where
                            E: $crate::serde::de::Error,
                        {
                            $name::from_str(v).map_err(E::custom)
                        }

                        fn visit_borrowed_str<E>(self, v: &'de str) -> Result<Self::Value, E>
                        where
                            E: $crate::serde::de::Error,
                        {
                            self.visit_str(v)
                        }

                        fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
                        where
                            E: $crate::serde::de::Error,
                        {
                            self.visit_str(&v)
                        }
                    }

                    deserializer.deserialize_str(Visitor)
                } else {
                    use ::std::fmt::{self, Formatter};
                    use $crate::serde::de::IgnoredAny;

                    #[allow(non_camel_case_types)]
                    enum Enum { Unknown__Field, $($fe),* }

                    struct EnumVisitor;
                    impl<'de> $crate::serde::de::Visitor<'de> for EnumVisitor {
                        type Value = Enum;

                        fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
                            formatter.write_str("a field name")
                        }

                        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
                        where
                            E: $crate::serde::de::Error,
                        {
                            match v {
                                $(
                                stringify!($fe) => Ok(Enum::$fe)
                                ),*,
                                _ => Ok(Enum::Unknown__Field)
                            }
                        }
                    }

                    impl<'de> $crate::serde::Deserialize<'de> for Enum {
                        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
                        where
                            D: $crate::serde::de::Deserializer<'de>,
                        {
                            deserializer.deserialize_str(EnumVisitor)
                        }
                    }

                    struct Visitor;

                    impl<'de> $crate::serde::de::Visitor<'de> for Visitor {
                        type Value = $name;

                        fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
                            formatter.write_str("a struct")
                        }

                        fn visit_seq<V>(self, mut seq: V) -> Result<Self::Value, V::Error>
                        where
                            V: $crate::serde::de::SeqAccess<'de>,
                        {
                            use $crate::serde::de::Error;

                            let length = 0;
                            $(
                                let $fe = seq.next_element()?.ok_or_else(|| {
                                    Error::invalid_length(length, &self)
                                })?;
                                #[allow(unused_variables)]
                                let length = length + 1;
                            )*

                            let ret = $name {
                                $($fe),*
                            };

                            Ok(ret)
                        }

                        fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
                        where
                            A: $crate::serde::de::MapAccess<'de>,
                        {
                            use $crate::serde::de::Error;

                            $(let mut $fe = None;)*

                            loop {
                                match map.next_key::<Enum>()? {
                                    Some(Enum::Unknown__Field) => {
                                        map.next_value::<IgnoredAny>()?;
                                    }
                                    $(
                                        Some(Enum::$fe) => {
                                            $fe = Some(map.next_value()?);
                                        }
                                    )*
                                    None => { break; }
                                }
                            }

                            $(
                                let Some($fe) = $fe else {
                                    return Err(A::Error::missing_field(stringify!($fe)));
                                };
                            )*

                            let ret = $name {
                                $($fe),*
                            };

                            Ok(ret)
                        }
                    }
                    // end type defs

                    static FIELDS: &'static [&'static str] = &[$(stringify!($fe)),*];

                    deserializer.deserialize_struct(stringify!($name), FIELDS, Visitor)
                }
            }
        }

        #[cfg(feature = "serde")]
        impl<'de> $crate::serde::Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: $crate::serde::Serializer,
            {
                if serializer.is_human_readable() {
                    serializer.collect_str(&self)
                } else {
                    use $crate::serde::ser::SerializeStruct;

                    // Only used to get the struct length.
                    static FIELDS: &'static [&'static str] = &[$(stringify!($fe)),*];

                    let mut st = serializer.serialize_struct(stringify!($name), FIELDS.len())?;

                    $(
                        st.serialize_field(stringify!($fe), &self.$fe)?;
                    )*

                    st.end()
                }
            }
        }
    )
}

macro_rules! impl_sha256_midstate_wrapper {
    {
        #[$($type_attrs:meta)*]
        pub struct $ty:ident([u8; 32]);
    } => {
        $(#[$type_attrs])*
        #[derive(Copy, Clone, PartialEq, Eq, Default, PartialOrd, Ord, Hash)]
        pub struct $ty([u8; 32]);

        impl $ty {
            /// Constructs this wrapper struct from raw bytes.
            pub fn from_byte_array(inner: [u8; 32]) -> Self {
                Self(inner)
            }

            /// The raw bytes within the wrapper type.
            pub fn as_byte_array(&self) -> &[u8; 32] {
                &self.0
            }

            /// The raw bytes within the wrapper type.
            pub fn to_byte_array(self) -> [u8; 32] {
                self.0
            }

            /// (Private) convert a sha256 midstate to an object.
            fn from_midstate(value: crate::hashes::sha256::Midstate) -> Self {
                Self(value.to_parts().0)
            }
        }

        impl ::std::fmt::Display for $ty {
            fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
                ::std::fmt::LowerHex::fmt(&self, f)
            }
        }

        impl ::std::fmt::LowerHex for $ty {
            fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
                hex::fmt_hex_exact!(f, 32, self.0.iter().rev(), hex::Case::Lower)
            }
        }

        impl ::std::fmt::UpperHex for $ty {
            fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
                hex::fmt_hex_exact!(f, 32, self.0.iter().rev(), hex::Case::Upper)
            }
        }

        impl ::std::fmt::Debug for $ty {
            fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
                ::std::fmt::Display::fmt(&self, f)
            }
        }

        impl ::core::str::FromStr for $ty {
            type Err = hex::DecodeFixedLengthBytesError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                let mut arr = hex::decode_to_array(s)?;
                arr.reverse();
                Ok(Self(arr))
            }
        }

        #[cfg(feature = "serde")]
        impl ::serde::Serialize for $ty {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
                where
                    S: serde::Serializer {
                // "cheat" by just copying sha256d serde serialization
                crate::hashes::sha256d::Hash::from_byte_array(self.to_byte_array()).serialize(serializer)
            }
        }

        #[cfg(feature = "serde")]
        impl<'de> ::serde::Deserialize<'de> for $ty {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
                where
                    D: serde::Deserializer<'de> {
                // "cheat" by just copying sha256d serde serialization
                let hash = crate::hashes::sha256d::Hash::deserialize(deserializer)?;
                Ok(Self::from_byte_array(hash.to_byte_array()))
            }
        }
    }
}

#[cfg(test)]
macro_rules! hex_deserialize(
    ($e:expr) => ({
        use $crate::encode::deserialize;

        fn hex_char(c: char) -> u8 {
            match c {
                '0' => 0,
                '1' => 1,
                '2' => 2,
                '3' => 3,
                '4' => 4,
                '5' => 5,
                '6' => 6,
                '7' => 7,
                '8' => 8,
                '9' => 9,
                'a' | 'A' => 10,
                'b' | 'B' => 11,
                'c' | 'C' => 12,
                'd' | 'D' => 13,
                'e' | 'E' => 14,
                'f' | 'F' => 15,
                x => panic!("Invalid character {} in hex string", x),
            }
        }

        let mut ret = Vec::with_capacity($e.len() / 2);
        let mut byte = 0;
        for (ch, store) in $e.chars().zip([false, true].iter().cycle()) {
            byte = (byte << 4) + hex_char(ch);
            if *store {
                ret.push(byte);
                byte = 0;
            }
        }
        deserialize(&ret).expect("deserialize object")
    });
);

#[cfg(test)]
macro_rules! hex_script(
    ($e:expr) => (crate::Script::from_hex_no_prefix($e).expect("hex decoding"))
);
