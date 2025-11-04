// Rust Elements Library
// Written in 2023 by
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

//! Hex Encoding and Decoding

// The rust-bitcoin hex stury is such a mess right now that the most
// straightforward thing is to just reimplement everything here.
//
// This is a copy/paste of the bitcoin_hashes hex module, with the
// std/alloc feature gates, and the benchmarks, removed.
//

use std::{fmt, io, str};

use hex_conservative::{decode_to_vec, DecodeVariableLengthBytesError};

/// Trait for objects that can be serialized as hex strings.
pub trait ToHex {
    /// Converts to a hexadecimal representation of the object.
    fn to_hex(&self) -> String;
}

/// Trait for objects that can be deserialized from hex strings.
pub trait FromHex: Sized {
    /// Error returned by [`FromHex::from_hex`], may differ depending
    /// on whether `Self` is fixed size of variable length.
    type Err;

    /// Produces an object from a hex string.
    fn from_hex(s: &str) -> Result<Self, Self::Err>;
}

impl<T: fmt::LowerHex> ToHex for T {
    /// Outputs the hash in hexadecimal form.
    fn to_hex(&self) -> String {
        format!("{:x}", self)
    }
}

/// Outputs hex into an object implementing `fmt::Write`.
///
/// This is usually more efficient than going through a `String` using [`ToHex`].
pub fn format_hex(data: &[u8], f: &mut fmt::Formatter) -> fmt::Result {
    let prec = f.precision().unwrap_or(2 * data.len());
    let width = f.width().unwrap_or(2 * data.len());
    for _ in (2 * data.len())..width {
        f.write_str("0")?;
    }
    for ch in data.iter().take(prec / 2) {
        write!(f, "{:02x}", *ch)?;
    }
    if prec < 2 * data.len() && prec % 2 == 1 {
        write!(f, "{:x}", data[prec / 2] / 16)?;
    }
    Ok(())
}

/// Outputs hex in reverse order.
///
/// Used for `sha256d::Hash` whose standard hex encoding has the bytes reversed.
pub fn format_hex_reverse(data: &[u8], f: &mut fmt::Formatter) -> fmt::Result {
    let prec = f.precision().unwrap_or(2 * data.len());
    let width = f.width().unwrap_or(2 * data.len());
    for _ in (2 * data.len())..width {
        f.write_str("0")?;
    }
    for ch in data.iter().rev().take(prec / 2) {
        write!(f, "{:02x}", *ch)?;
    }
    if prec < 2 * data.len() && prec % 2 == 1 {
        write!(f, "{:x}", data[data.len() - 1 - prec / 2] / 16)?;
    }
    Ok(())
}

impl ToHex for [u8] {
    fn to_hex(&self) -> String {
        use core::fmt::Write;
        let mut ret = String::with_capacity(2 * self.len());
        for ch in self {
            write!(ret, "{:02x}", ch).expect("writing to string");
        }
        ret
    }
}

/// A struct implementing [`io::Write`] that converts what's written to it into
/// a hex String.
///
/// If you already have the data to be converted in a `Vec<u8>` use [`ToHex`]
/// but if you have an encodable object, by using this you avoid the
/// serialization to `Vec<u8>` by going directly to `String`.
///
/// Note that to achieve better performance than [`ToHex`] the struct must be
/// created with the right `capacity` of the final hex string so that the inner
/// `String` doesn't re-allocate.
pub struct HexWriter(String);

impl HexWriter {
    /// Creates a new [`HexWriter`] with the `capacity` of the inner `String`
    /// that will contain final hex value.
    pub fn new(capacity: usize) -> Self {
        HexWriter(String::with_capacity(capacity))
    }

    /// Returns the resulting hex string.
    pub fn result(self) -> String {
        self.0
    }
}

impl io::Write for HexWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        use core::fmt::Write;
        for ch in buf {
            write!(self.0, "{:02x}", ch).expect("writing to string");
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl FromHex for Vec<u8> {
    type Err = DecodeVariableLengthBytesError;

    fn from_hex(s: &str) -> Result<Self, Self::Err> {
        decode_to_vec(s)
    }
}

macro_rules! impl_fromhex_array {
    ($len:expr) => {
        impl FromHex for [u8; $len] {
            type Err = hex_conservative::DecodeFixedLengthBytesError;

            fn from_hex(s: &str) -> Result<Self, Self::Err> {
                hex_conservative::decode_to_array(s)
            }
        }
    }
}

impl_fromhex_array!(2);
impl_fromhex_array!(4);
impl_fromhex_array!(6);
impl_fromhex_array!(8);
impl_fromhex_array!(10);
impl_fromhex_array!(12);
impl_fromhex_array!(14);
impl_fromhex_array!(16);
impl_fromhex_array!(20);
impl_fromhex_array!(24);
impl_fromhex_array!(28);
impl_fromhex_array!(32);
impl_fromhex_array!(33);
impl_fromhex_array!(64);
impl_fromhex_array!(65);
impl_fromhex_array!(128);
impl_fromhex_array!(256);
impl_fromhex_array!(384);
impl_fromhex_array!(512);

#[cfg(test)]
mod tests {
    use hex_conservative::DecodeFixedLengthBytesError;

    use super::*;

    use core::fmt;
    use std::io::Write;

    #[test]
    fn hex_roundtrip() {
        let expected = "0123456789abcdef";
        let expected_up = "0123456789ABCDEF";

        let parse: Vec<u8> = FromHex::from_hex(expected).expect("parse lowercase string");
        assert_eq!(parse, vec![0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]);
        let ser = parse.to_hex();
        assert_eq!(ser, expected);

        let parse: Vec<u8> = FromHex::from_hex(expected_up).expect("parse uppercase string");
        assert_eq!(parse, vec![0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]);
        let ser = parse.to_hex();
        assert_eq!(ser, expected);

        let parse: [u8; 8] = FromHex::from_hex(expected_up).expect("parse uppercase string");
        assert_eq!(parse, [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]);
        let ser = parse.to_hex();
        assert_eq!(ser, expected);
    }

    #[test]
    fn hex_truncate() {
        struct HexBytes(Vec<u8>);
        impl fmt::LowerHex for HexBytes {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                format_hex(&self.0, f)
            }
        }

        let bytes = HexBytes(vec![1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10]);

        assert_eq!(
            format!("{:x}", bytes),
            "0102030405060708090a"
        );

        for i in 0..20 {
            assert_eq!(
                format!("{:.prec$x}", bytes, prec = i),
                &"0102030405060708090a"[0..i]
            );
        }

        assert_eq!(
            format!("{:25x}", bytes),
            "000000102030405060708090a"
        );
        assert_eq!(
            format!("{:26x}", bytes),
            "0000000102030405060708090a"
        );
    }

    #[test]
    fn hex_truncate_rev() {
        struct HexBytes(Vec<u8>);
        impl fmt::LowerHex for HexBytes {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                format_hex_reverse(&self.0, f)
            }
        }

        let bytes = HexBytes(vec![1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10]);

        assert_eq!(
            format!("{:x}", bytes),
            "0a090807060504030201"
        );

        for i in 0..20 {
            assert_eq!(
                format!("{:.prec$x}", bytes, prec = i),
                &"0a090807060504030201"[0..i]
            );
        }

        assert_eq!(
            format!("{:25x}", bytes),
            "000000a090807060504030201"
        );
        assert_eq!(
            format!("{:26x}", bytes),
            "0000000a090807060504030201"
        );
    }

    #[test]
    fn hex_error() {
        let oddlen = "0123456789abcdef0";
        let badchar1 = "Z123456789abcdef";
        let badchar2 = "012Y456789abcdeb";
        let badchar3 = "«23456789abcdef";

        let result = Vec::<u8>::from_hex(oddlen);
        assert!(
            matches!(&result, Err(DecodeVariableLengthBytesError::OddLengthString(err))
                if err.length() == 17),
            "Got: {:?}", result
        );
        let result = <[u8; 4]>::from_hex(oddlen);
        assert!(
            matches!(&result, Err(DecodeFixedLengthBytesError::InvalidLength(err))
                if err.invalid_length() == 17),
            "Got: {:?}", result
        );
        let result = <[u8; 8]>::from_hex(oddlen);
        assert!(
            matches!(&result, Err(DecodeFixedLengthBytesError::InvalidLength(err))
                if err.invalid_length() == 17),
            "Got: {:?}", result
        );
        let result = Vec::<u8>::from_hex(badchar1);
        assert!(
            matches!(&result, Err(DecodeVariableLengthBytesError::InvalidChar(_))),
            "Got: {:?}", result
        );
        let result = Vec::<u8>::from_hex(badchar2);
        assert!(
            matches!(&result, Err(DecodeVariableLengthBytesError::InvalidChar(_))),
            "Got: {:?}", result
        );
        let result = Vec::<u8>::from_hex(badchar3);
        assert!(
            matches!(&result, Err(DecodeVariableLengthBytesError::InvalidChar(_))),
            "Got: {:?}", result
        );
    }


    #[test]
    fn hex_writer() {
        let vec: Vec<_>  = (0u8..32).collect();
        let mut writer = HexWriter::new(64);
        writer.write_all(&vec[..]).unwrap();
        assert_eq!(vec.to_hex(), writer.result());
    }
}
