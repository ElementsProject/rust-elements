// Rust Elements Library
// Written by
//   The Elements developers
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.

// This file is an adaptation of the bech32 crate with the following
// license notice:
//
// Copyright (c) 2017 Clark Moody
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

//! # Blech32
//!
//! A variation of the bech32 encoding for blinded Elements addresses.

// Original documentation is left untouched, so it corresponds to bech32.

use std::fmt;

// AsciiExt is needed until for Rust 1.26 but not for newer versions
#[allow(unused_imports, deprecated)]
use std::ascii::AsciiExt;

use bitcoin::bech32::{u5, Error};

/// Encode a bech32 payload to an [fmt::Formatter].
pub fn encode_to_fmt<T: AsRef<[u5]>>(fmt: &mut fmt::Formatter, hrp: &str, data: T) -> fmt::Result {
    let hrp_bytes: &[u8] = hrp.as_bytes();
    let checksum = create_checksum(hrp_bytes, data.as_ref());
    let data_part = data.as_ref().iter().chain(checksum.iter());

    write!(
        fmt,
        "{}{}{}",
        hrp,
        SEP,
        data_part
            .map(|p| CHARSET[*p.as_ref() as usize])
            .collect::<String>()
    )
}

/// Decode a bech32 string into the raw HRP and the data bytes.
/// The HRP is returned as it was found in the original string,
/// so it can be either lower or upper case.
pub fn decode(s: &str) -> Result<(&str, Vec<u5>), Error> {
    // Ensure overall length is within bounds
    let len: usize = s.len();
    // ELEMENTS: 8->14
    if len < 14 {
        return Err(Error::InvalidLength);
    }

    // Split at separator and check for two pieces
    let (raw_hrp, raw_data) = match s.rfind('1') {
        None => return Err(Error::MissingSeparator),
        Some(sep) => {
            let (hrp, data) = s.split_at(sep);
            (hrp, &data[1..])
        }
    };
    // ELEMENTS: 6->12
    if raw_hrp.is_empty() || raw_data.len() < 12 || raw_hrp.len() > 83 {
        return Err(Error::InvalidLength);
    }

    let mut has_lower: bool = false;
    let mut has_upper: bool = false;
    let mut hrp_bytes: Vec<u8> = Vec::new();
    for b in raw_hrp.bytes() {
        // Valid subset of ASCII
        if b < 33 || b > 126 {
            return Err(Error::InvalidChar(b as char));
        }
        let mut c = b;
        // Lowercase
        if b >= b'a' && b <= b'z' {
            has_lower = true;
        }
        // Uppercase
        if b >= b'A' && b <= b'Z' {
            has_upper = true;
            // Convert to lowercase
            c = b + (b'a' - b'A');
        }
        hrp_bytes.push(c);
    }

    // Check data payload
    let mut data = raw_data
        .chars()
        .map(|c| {
            // Only check if c is in the ASCII range, all invalid ASCII characters have the value -1
            // in CHARSET_REV (which covers the whole ASCII range) and will be filtered out later.
            if !c.is_ascii() {
                return Err(Error::InvalidChar(c));
            }

            if c.is_lowercase() {
                has_lower = true;
            } else if c.is_uppercase() {
                has_upper = true;
            }

            // c should be <128 since it is in the ASCII range, CHARSET_REV.len() == 128
            let num_value = CHARSET_REV[c as usize];

            if num_value > 31 || num_value < 0 {
                return Err(Error::InvalidChar(c));
            }

            Ok(u5::try_from_u8(num_value as u8).expect("range checked above, num_value <= 31"))
        })
        .collect::<Result<Vec<u5>, Error>>()?;

    // Ensure no mixed case
    if has_lower && has_upper {
        return Err(Error::MixedCase);
    }

    // Ensure checksum
    if !verify_checksum(&hrp_bytes, &data) {
        return Err(Error::InvalidChecksum);
    }

    // Remove checksum from data payload
    let dbl: usize = data.len();
    data.truncate(dbl - 12); // ELEMENTS: 6->12

    Ok((raw_hrp, data))
}

fn create_checksum(hrp: &[u8], data: &[u5]) -> Vec<u5> {
    let mut values: Vec<u5> = hrp_expand(hrp);
    values.extend_from_slice(data);
    // Pad with 12 zeros
    values.extend_from_slice(&[u5::try_from_u8(0).unwrap(); 12]); // ELEMENTS: 6->12
    let plm: u64 = polymod(&values) ^ 1;
    let mut checksum: Vec<u5> = Vec::new();
    // ELEMENTS: 6->12
    for p in 0..12 {
        checksum.push(u5::try_from_u8(((plm >> (5 * (11 - p))) & 0x1f) as u8).unwrap());
        // ELEMENTS: 5->11
    }
    checksum
}

fn verify_checksum(hrp: &[u8], data: &[u5]) -> bool {
    let mut exp = hrp_expand(hrp);
    exp.extend_from_slice(data);
    polymod(&exp) == 1u64
}

fn hrp_expand(hrp: &[u8]) -> Vec<u5> {
    let mut v: Vec<u5> = Vec::new();
    for b in hrp {
        v.push(u5::try_from_u8(*b >> 5).expect("can't be out of range, max. 7"));
    }
    v.push(u5::try_from_u8(0).unwrap());
    for b in hrp {
        v.push(u5::try_from_u8(*b & 0x1f).expect("can't be out of range, max. 31"));
    }
    v
}

fn polymod(values: &[u5]) -> u64 {
    let mut chk: u64 = 1;
    let mut b: u8;
    for v in values {
        b = (chk >> 55) as u8; // ELEMENTS: 25->55
        chk = (chk & 0x7fffffffffffff) << 5 ^ (u64::from(*v.as_ref())); // ELEMENTS 0x1ffffff->0x7fffffffffffff
        for (i, coef) in GEN.iter().enumerate() {
            if (b >> i) & 1 == 1 {
                chk ^= coef
            }
        }
    }
    chk
}

/// Human-readable part and data part separator
const SEP: char = '1';

/// Encoding character set. Maps data value -> char
const CHARSET: [char; 32] = [
    'q', 'p', 'z', 'r', 'y', '9', 'x', '8', 'g', 'f', '2', 't', 'v', 'd', 'w', '0', 's', '3', 'j',
    'n', '5', '4', 'k', 'h', 'c', 'e', '6', 'm', 'u', 'a', '7', 'l',
];

// Reverse character set. Maps ASCII byte -> CHARSET index on [0,31]
const CHARSET_REV: [i8; 128] = [
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    15, -1, 10, 17, 21, 20, 26, 30, 7, 5, -1, -1, -1, -1, -1, -1, -1, 29, -1, 24, 13, 25, 9, 8, 23,
    -1, 18, 22, 31, 27, 19, -1, 1, 0, 3, 16, 11, 28, 12, 14, 6, 4, 2, -1, -1, -1, -1, -1, -1, 29,
    -1, 24, 13, 25, 9, 8, 23, -1, 18, 22, 31, 27, 19, -1, 1, 0, 3, 16, 11, 28, 12, 14, 6, 4, 2, -1,
    -1, -1, -1, -1,
];

/// Generator coefficients
const GEN: [u64; 5] = [
    // ELEMENTS
    0x7d52fba40bd886,
    0x5e8dbf1a03950c,
    0x1c3a3c74072a18,
    0x385d72fa0e5139,
    0x7093e5a608865b,
];

#[cfg(test)]
mod test {
    use super::*;

    use bitcoin::bech32::ToBase32;
    use rand;

    #[test]
    fn test_polymod_sanity() {
        let data: [u8; 32] = rand::random();

        let data1 = data.to_vec();
        let data1_b32 = data1.to_base32();
        let polymod1 = polymod(&data1_b32);

        let data2 = data.to_vec();
        let mut data2_b32 = data2.to_base32();
        data2_b32.extend(vec![u5::try_from_u8(0).unwrap(); 1023]);
        let polymod2 = polymod(&data2_b32);
        assert_eq!(polymod1, polymod2);
    }

    #[test]
    fn test_checksum() {
        let data = vec![7, 2, 3, 4, 5, 6, 7, 8, 9, 234, 123, 213, 16];
        let cs = create_checksum(b"lq", &data.to_base32());
        let expected_cs = vec![22, 13, 13, 5, 4, 4, 23, 7, 28, 21, 30, 12];
        for i in 0..expected_cs.len() {
            assert_eq!(expected_cs[i], *cs[i].as_ref());
        }
    }
}
