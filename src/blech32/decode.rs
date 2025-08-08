//
// This file is essentially a copy of src/primitives/decode.rs from the bech32
// crate. It is not public-domain licensed. It is MIT-licensed. The changes are:
//   * Imports changed to use the public bech32 crate
//   * Bech32 changed to Blech32 by search-and-replace
//   * Fe32::from_char_unchecked and .0 were changed to use public API
//   * CheckedHrpstring::validate_witness_program_length replaced to use Elements limits
//   * `std` feature gates were removed
//   * a couple tests with fixed vectors were disabled since we replaced the checksum
//   * doccomment examples with fixed vectors were removed
//

// Copyright (c) 2023 Tobin Harding and Andrew Poelstra
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

//! Decoding of bech32 encoded strings as specified by [BIP-173] and [BIP-350].
//!
//! You should only need to use this module directly if you want control over exactly what is
//! checked and when it is checked (correct bech32 characters, valid checksum, valid checksum for
//! specific checksum algorithm, etc). If you are parsing/validating modern (post BIP-350) bitcoin
//! segwit addresses consider using the higher crate level API.
//!
//! If you do find yourself using this module directly then consider using the most general type
//! that serves your purposes, each type can be created by parsing an address string to `new`. You
//! likely do not want to arbitrarily transition from one type to the next even though possible. And
//! be prepared to spend some time with the bips - you have been warned :)
//!
//! # Details
//!
//! A Blech32 string is at most 90 characters long and consists of:
//!
//! - The human-readable part, which is intended to convey the type of data, or anything else that
//!   is relevant to the reader. This part MUST contain 1 to 83 US-ASCII characters.
//! - The separator, which is always "1".
//! - The data part, which is at least 6 characters long and only consists of alphanumeric
//!   characters excluding "1", "b", "i", and "o".
//!
//! The types in this module heavily lean on the wording in BIP-173: *We first
//! describe the general checksummed base32 format called Blech32 and then define Segregated Witness
//! addresses using it.*
//!
//! - `UncheckedHrpstring`: Parses the general checksummed base32 format and provides checksum validation.
//! - `CheckedHrpstring`: Provides access to the data encoded by a general checksummed base32 string and segwit checks.
//! - `SegwitHrpstring`: Provides access to the data encoded by a segwit address.
//!
//! [BIP-173]: <https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki>
//! [BIP-350]: <https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki>

use core::{fmt, iter, slice, str};

use crate::error::write_err;
use bech32::primitives::checksum::{self, Checksum};
use bech32::primitives::gf32::Fe32;
use bech32::primitives::hrp::{self, Hrp};
use bech32::primitives::iter::{Fe32IterExt, FesToBytes};
use bech32::primitives::segwit::{WitnessLengthError, VERSION_0};
use super::{Blech32, Blech32m};

/// Separator between the hrp and payload (as defined by BIP-173).
const SEP: char = '1';

/// An HRP string that has been parsed but not yet had the checksum checked.
///
/// Parsing an HRP string only checks validity of the characters, it does not validate the
/// checksum in any way.
///
/// Unless you are attempting to validate a string with multiple checksums then you likely do not
/// want to use this type directly, instead use [`CheckedHrpstring::new`].
#[derive(Debug)]
pub struct UncheckedHrpstring<'s> {
    /// The human-readable part, guaranteed to be lowercase ASCII characters.
    hrp: Hrp,
    /// This is ASCII byte values of the parsed string, guaranteed to be valid bech32 characters.
    ///
    /// Contains the checksum if one was present in the parsed string.
    data: &'s [u8],
}

impl<'s> UncheckedHrpstring<'s> {
    /// Parses an bech32 encode string and constructs a [`UncheckedHrpstring`] object.
    ///
    /// Checks for valid ASCII values, does not validate the checksum.
    #[inline]
    pub fn new(s: &'s str) -> Result<Self, UncheckedHrpstringError> {
        let sep_pos = check_characters(s)?;
        let (hrp, data) = s.split_at(sep_pos);

        let ret = UncheckedHrpstring {
            hrp: Hrp::parse(hrp)?,
            data: &data.as_bytes()[1..], // Skip the separator.
        };

        Ok(ret)
    }

    /// Returns the human-readable part.
    #[inline]
    pub fn hrp(&self) -> Hrp { self.hrp }

    /// Validates that data has a valid checksum for the `Ck` algorithm and returns a [`CheckedHrpstring`].
    #[inline]
    pub fn validate_and_remove_checksum<Ck: Checksum>(
        self,
    ) -> Result<CheckedHrpstring<'s>, ChecksumError> {
        self.validate_checksum::<Ck>()?;
        Ok(self.remove_checksum::<Ck>())
    }

    /// Validates that data has a valid checksum for the `Ck` algorithm (this may mean an empty
    /// checksum if `NoChecksum` is used).
    ///
    /// This is useful if you do not know which checksum algorithm was used and wish to validate
    /// against multiple algorithms consecutively. If this function returns `true` then call
    /// `remove_checksum` to get a [`CheckedHrpstring`].
    #[inline]
    pub fn has_valid_checksum<Ck: Checksum>(&self) -> bool {
        self.validate_checksum::<Ck>().is_ok()
    }

    /// Validates that data has a valid checksum for the `Ck` algorithm (this may mean an empty
    /// checksum if `NoChecksum` is used).
    #[inline]
    pub fn validate_checksum<Ck: Checksum>(&self) -> Result<(), ChecksumError> {
        use ChecksumError as E;

        if Ck::CHECKSUM_LENGTH == 0 {
            // Called with NoChecksum
            return Ok(());
        }

        if self.data.len() < Ck::CHECKSUM_LENGTH {
            return Err(E::InvalidChecksumLength);
        }

        let mut checksum_eng = checksum::Engine::<Ck>::new();
        checksum_eng.input_hrp(self.hrp());

        // Unwrap ok since we checked all characters in our constructor.
        for fe in self.data.iter().map(|&b| Fe32::from_char(b.into()).unwrap()) {
            checksum_eng.input_fe(fe);
        }

        if checksum_eng.residue() != &Ck::TARGET_RESIDUE {
            return Err(E::InvalidChecksum);
        }

        Ok(())
    }

    /// Removes the checksum for the `Ck` algorithm and returns an [`CheckedHrpstring`].
    ///
    /// Data must be valid (ie, first call `has_valid_checksum` or `validate_checksum()`). This
    /// function is typically paired with `has_valid_checksum` when validating against multiple
    /// checksum algorithms consecutively.
    ///
    /// # Panics
    ///
    /// May panic if data is not valid.
    #[inline]
    pub fn remove_checksum<Ck: Checksum>(self) -> CheckedHrpstring<'s> {
        let data_len = self.data.len() - Ck::CHECKSUM_LENGTH;

        CheckedHrpstring { hrp: self.hrp(), data: &self.data[..data_len] }
    }
}

/// An HRP string that has been parsed and had the checksum validated.
///
/// This type does not treat the first byte of the data in any special way i.e., as the witness
/// version byte. If you are parsing Bitcoin segwit addresses you likely want to use [`SegwitHrpstring`].
///
/// > We first describe the general checksummed base32 format called Blech32 and then
/// > define Segregated Witness addresses using it.
///
/// This type abstracts over the general checksummed base32 format called Blech32.
#[derive(Debug)]
pub struct CheckedHrpstring<'s> {
    /// The human-readable part, guaranteed to be lowercase ASCII characters.
    hrp: Hrp,
    /// This is ASCII byte values of the parsed string, guaranteed to be valid bech32 characters,
    /// with the checksum removed.
    data: &'s [u8],
}

impl<'s> CheckedHrpstring<'s> {
    /// Parses and validates an HRP string, without treating the first data character specially.
    ///
    /// If you are validating the checksum multiple times consider using [`UncheckedHrpstring`].
    ///
    /// This is equivalent to `UncheckedHrpstring::new().validate_and_remove_checksum::<CK>()`.
    #[inline]
    pub fn new<Ck: Checksum>(s: &'s str) -> Result<Self, CheckedHrpstringError> {
        let unchecked = UncheckedHrpstring::new(s)?;
        let checked = unchecked.validate_and_remove_checksum::<Ck>()?;
        Ok(checked)
    }

    /// Returns the human-readable part.
    #[inline]
    pub fn hrp(&self) -> Hrp { self.hrp }

    /// Returns an iterator that yields the data part of the parsed bech32 encoded string.
    ///
    /// Converts the ASCII bytes representing field elements to the respective field elements, then
    /// converts the stream of field elements to a stream of bytes.
    #[inline]
    pub fn byte_iter(&self) -> ByteIter<'_> {
        ByteIter { iter: AsciiToFe32Iter { iter: self.data.iter().copied() }.fes_to_bytes() }
    }

    /// Converts this type to a [`SegwitHrpstring`] after validating the witness and HRP.
    #[inline]
    pub fn validate_segwit(mut self) -> Result<SegwitHrpstring<'s>, SegwitHrpstringError> {
        if self.data.is_empty() {
            return Err(SegwitHrpstringError::MissingWitnessVersion);
        }
        // Unwrap ok since check_characters checked the bech32-ness of this char.
        let witness_version = Fe32::from_char(self.data[0].into()).unwrap();
        self.data = &self.data[1..]; // Remove the witness version byte from data.

        self.validate_padding()?;
        self.validate_witness_program_length(witness_version)?;

        Ok(SegwitHrpstring { hrp: self.hrp(), witness_version, data: self.data })
    }

    /// Validates the segwit padding rules.
    ///
    /// Must be called after the witness version byte is removed from the data.
    ///
    /// From BIP-173:
    /// > Re-arrange those bits into groups of 8 bits. Any incomplete group at the
    /// > end MUST be 4 bits or less, MUST be all zeroes, and is discarded.
    fn validate_padding(&self) -> Result<(), PaddingError> {
        if self.data.is_empty() {
            return Ok(()); // Empty data implies correct padding.
        }

        let fe_iter = AsciiToFe32Iter { iter: self.data.iter().copied() };
        let padding_len = fe_iter.len() * 5 % 8;

        if padding_len > 4 {
            return Err(PaddingError::TooMuch)?;
        }

        let last_fe = fe_iter.last().expect("checked above");
        let last_byte = last_fe.to_u8();

        let padding_contains_non_zero_bits = match padding_len {
            0 => false,
            1 => last_byte & 0b0001 > 0,
            2 => last_byte & 0b0011 > 0,
            3 => last_byte & 0b0111 > 0,
            4 => last_byte & 0b1111 > 0,
            _ => unreachable!("checked above"),
        };
        if padding_contains_non_zero_bits {
            Err(PaddingError::NonZero)
        } else {
            Ok(())
        }
    }

    /// Validates the segwit witness length rules.
    ///
    /// Must be called after the witness version byte is removed from the data.
    fn validate_witness_program_length(
        &self,
        witness_version: Fe32,
    ) -> Result<(), WitnessLengthError> {
        let len = self.byte_iter().len();
        if len < 2 {
            Err(WitnessLengthError::TooShort)
        } else if len > 40 + 33 {
            Err(WitnessLengthError::TooLong)
        } else if witness_version == Fe32::Q && len != 53 && len != 65 {
            Err(WitnessLengthError::InvalidSegwitV0)
        } else {
            Ok(())
        }
    }
}

/// An HRP string that has been parsed, had the checksum validated, had the witness version
/// validated, had the witness data length checked, and the had witness version and checksum
/// removed.
///
#[derive(Debug)]
pub struct SegwitHrpstring<'s> {
    /// The human-readable part, valid for segwit addresses.
    hrp: Hrp,
    /// The first byte of the parsed data.
    witness_version: Fe32,
    /// This is ASCII byte values of the parsed string, guaranteed to be valid bech32 characters,
    /// with the witness version and checksum removed.
    data: &'s [u8],
}

impl<'s> SegwitHrpstring<'s> {
    /// Parses an HRP string, treating the first data character as a witness version.
    ///
    /// The version byte does not appear in the extracted binary data, but is covered by the
    /// checksum. It can be accessed with [`Self::witness_version`].
    ///
    /// NOTE: We do not enforce any restrictions on the HRP, use [`SegwitHrpstring::has_valid_hrp`]
    /// to get strict BIP conformance (also [`Hrp::is_valid_on_mainnet`] and friends).
    #[inline]
    pub fn new(s: &'s str) -> Result<Self, SegwitHrpstringError> {
        let unchecked = UncheckedHrpstring::new(s)?;

        if unchecked.data.is_empty() {
            return Err(SegwitHrpstringError::MissingWitnessVersion);
        }

        // Unwrap ok since check_characters (in `Self::new`) checked the bech32-ness of this char.
        let witness_version = Fe32::from_char(unchecked.data[0].into()).unwrap();
        if witness_version.to_u8() > 16 {
            return Err(SegwitHrpstringError::InvalidWitnessVersion(witness_version));
        }

        let checked: CheckedHrpstring<'s> = match witness_version {
            VERSION_0 => unchecked.validate_and_remove_checksum::<Blech32>()?,
            _ => unchecked.validate_and_remove_checksum::<Blech32m>()?,
        };

        checked.validate_segwit()
    }

    /// Parses an HRP string, treating the first data character as a witness version.
    ///
    /// ## WARNING
    ///
    /// You almost certainly do not want to use this function.
    ///
    /// It is provided for backwards comparability to parse addresses that have an non-zero witness
    /// version because [BIP-173] explicitly allows using the bech32 checksum with any witness
    /// version however [BIP-350] specifies all witness version > 0 now MUST use bech32m.
    ///
    /// [BIP-173]: https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
    /// [BIP-350]: https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki
    #[inline]
    pub fn new_bech32(s: &'s str) -> Result<Self, SegwitHrpstringError> {
        let unchecked = UncheckedHrpstring::new(s)?;

        // Unwrap ok since check_characters (in `Self::new`) checked the bech32-ness of this char.
        let witness_version = Fe32::from_char(unchecked.data[0].into()).unwrap();
        if witness_version.to_u8() > 16 {
            return Err(SegwitHrpstringError::InvalidWitnessVersion(witness_version));
        }

        let checked = unchecked.validate_and_remove_checksum::<Blech32>()?;
        checked.validate_segwit()
    }

    /// Returns `true` if the HRP is "bc" or "tb".
    ///
    /// BIP-173 requires that the HRP is "bc" or "tb" but software in the Bitcoin ecosystem uses
    /// other HRPs, specifically "bcrt" for regtest addresses. We provide this function in order to
    /// be BIP-173 compliant but their are no restrictions on the HRP of [`SegwitHrpstring`].
    #[inline]
    pub fn has_valid_hrp(&self) -> bool { self.hrp().is_valid_segwit() }

    /// Returns the human-readable part.
    #[inline]
    pub fn hrp(&self) -> Hrp { self.hrp }

    /// Returns the witness version.
    #[inline]
    pub fn witness_version(&self) -> Fe32 { self.witness_version }

    /// Returns an iterator that yields the data part, excluding the witness version, of the parsed
    /// bech32 encoded string.
    ///
    /// Converts the ASCII bytes representing field elements to the respective field elements, then
    /// converts the stream of field elements to a stream of bytes.
    ///
    /// Use `self.witness_version()` to get the witness version.
    #[inline]
    pub fn byte_iter(&self) -> ByteIter<'_> {
        ByteIter { iter: AsciiToFe32Iter { iter: self.data.iter().copied() }.fes_to_bytes() }
    }
}

/// Checks whether a given HRP string has data characters in the bech32 alphabet (incl. checksum
/// characters), and that the whole string has consistent casing (hrp, data, and checksum).
///
/// # Returns
///
/// The byte-index into the string where the '1' separator occurs, or an error if it does not.
fn check_characters(s: &str) -> Result<usize, CharError> {
    use CharError as E;

    let mut has_upper = false;
    let mut has_lower = false;
    let mut req_bech32 = true;
    let mut sep_pos = None;
    for (n, ch) in s.char_indices().rev() {
        if ch == SEP && sep_pos.is_none() {
            req_bech32 = false;
            sep_pos = Some(n);
        }
        if req_bech32 {
            Fe32::from_char(ch).map_err(|_| E::InvalidChar(ch))?;
        }
        if ch.is_ascii_uppercase() {
            has_upper = true;
        } else if ch.is_ascii_lowercase() {
            has_lower = true;
        }
    }
    if has_upper && has_lower {
        Err(E::MixedCase)
    } else if let Some(pos) = sep_pos {
        Ok(pos)
    } else {
        Err(E::MissingSeparator)
    }
}

/// An iterator over a parsed HRP string data as bytes.
pub struct ByteIter<'s> {
    iter: FesToBytes<AsciiToFe32Iter<iter::Copied<slice::Iter<'s, u8>>>>,
}

impl Iterator for ByteIter<'_> {
    type Item = u8;
    #[inline]
    fn next(&mut self) -> Option<u8> { self.iter.next() }
    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) { self.iter.size_hint() }
}

impl ExactSizeIterator for ByteIter<'_> {
    #[inline]
    fn len(&self) -> usize { self.iter.len() }
}

/// Helper iterator adaptor that maps an iterator of valid bech32 character ASCII bytes to an
/// iterator of field elements.
///
/// # Panics
///
/// If any `u8` in the input iterator is out of range for an [`Fe32`]. Should only be used on data
/// that has already been checked for validity (eg, by using `check_characters`).
struct AsciiToFe32Iter<I: Iterator<Item = u8>> {
    iter: I,
}

impl<I> Iterator for AsciiToFe32Iter<I>
where
    I: Iterator<Item = u8>,
{
    type Item = Fe32;
    #[inline]
    fn next(&mut self) -> Option<Fe32> { self.iter.next().map(|ch| Fe32::from_char(ch.into()).unwrap()) }
    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        // Each ASCII character is an fe32 so iterators are the same size.
        self.iter.size_hint()
    }
}

impl<I> ExactSizeIterator for AsciiToFe32Iter<I>
where
    I: Iterator<Item = u8> + ExactSizeIterator,
{
    #[inline]
    fn len(&self) -> usize { self.iter.len() }
}

/// An error while constructing a [`SegwitHrpstring`] type.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SegwitHrpstringError {
    /// Error while parsing the encoded address string.
    Unchecked(UncheckedHrpstringError),
    /// The witness version byte is missing.
    MissingWitnessVersion,
    /// Invalid witness version (must be 0-16 inclusive).
    InvalidWitnessVersion(Fe32),
    /// Invalid padding on the witness data.
    Padding(PaddingError),
    /// Invalid witness length.
    WitnessLength(WitnessLengthError),
    /// Invalid checksum.
    Checksum(ChecksumError),
}

impl fmt::Display for SegwitHrpstringError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Self::Unchecked(ref e) => write_err!(f, "parsing unchecked hrpstring failed"; e),
            Self::MissingWitnessVersion => write!(f, "the witness version byte is missing"),
            Self::InvalidWitnessVersion(fe) => write!(f, "invalid segwit witness version: {}", fe.to_u8()),
            Self::Padding(ref e) => write_err!(f, "invalid padding on the witness data"; e),
            Self::WitnessLength(ref e) => write_err!(f, "invalid witness length"; e),
            Self::Checksum(ref e) => write_err!(f, "invalid checksum"; e),
        }
    }
}

impl std::error::Error for SegwitHrpstringError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match *self {
            Self::Unchecked(ref e) => Some(e),
            Self::Padding(ref e) => Some(e),
            Self::WitnessLength(ref e) => Some(e),
            Self::Checksum(ref e) => Some(e),
            Self::MissingWitnessVersion | Self::InvalidWitnessVersion(_) => None,
        }
    }
}

impl From<UncheckedHrpstringError> for SegwitHrpstringError {
    #[inline]
    fn from(e: UncheckedHrpstringError) -> Self { Self::Unchecked(e) }
}

impl From<WitnessLengthError> for SegwitHrpstringError {
    #[inline]
    fn from(e: WitnessLengthError) -> Self { Self::WitnessLength(e) }
}

impl From<PaddingError> for SegwitHrpstringError {
    #[inline]
    fn from(e: PaddingError) -> Self { Self::Padding(e) }
}

impl From<ChecksumError> for SegwitHrpstringError {
    #[inline]
    fn from(e: ChecksumError) -> Self { Self::Checksum(e) }
}

/// An error while constructing a [`CheckedHrpstring`] type.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CheckedHrpstringError {
    /// Error while parsing the encoded address string.
    Parse(UncheckedHrpstringError),
    /// Invalid checksum.
    Checksum(ChecksumError),
}

impl fmt::Display for CheckedHrpstringError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Self::Parse(ref e) => write_err!(f, "parse failed"; e),
            Self::Checksum(ref e) => write_err!(f, "invalid checksum"; e),
        }
    }
}

impl std::error::Error for CheckedHrpstringError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match *self {
            Self::Parse(ref e) => Some(e),
            Self::Checksum(ref e) => Some(e),
        }
    }
}

impl From<UncheckedHrpstringError> for CheckedHrpstringError {
    #[inline]
    fn from(e: UncheckedHrpstringError) -> Self { Self::Parse(e) }
}

impl From<ChecksumError> for CheckedHrpstringError {
    #[inline]
    fn from(e: ChecksumError) -> Self { Self::Checksum(e) }
}

/// Errors when parsing a bech32 encoded string.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum UncheckedHrpstringError {
    /// An error with the characters of the input string.
    Char(CharError),
    /// The human-readable part is invalid.
    Hrp(hrp::Error),
}

impl fmt::Display for UncheckedHrpstringError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Self::Char(ref e) => write_err!(f, "character error"; e),
            Self::Hrp(ref e) => write_err!(f, "invalid human-readable part"; e),
        }
    }
}

impl std::error::Error for UncheckedHrpstringError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match *self {
            Self::Char(ref e) => Some(e),
            Self::Hrp(ref e) => Some(e),
        }
    }
}

impl From<CharError> for UncheckedHrpstringError {
    #[inline]
    fn from(e: CharError) -> Self { Self::Char(e) }
}

impl From<hrp::Error> for UncheckedHrpstringError {
    #[inline]
    fn from(e: hrp::Error) -> Self { Self::Hrp(e) }
}

/// Character errors in a bech32 encoded string.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CharError {
    /// String does not contain the separator character.
    MissingSeparator,
    /// No characters after the separator.
    NothingAfterSeparator,
    /// The checksum does not match the rest of the data.
    InvalidChecksum,
    /// The checksum is not a valid length.
    InvalidChecksumLength,
    /// Some part of the string contains an invalid character.
    InvalidChar(char),
    /// The whole string must be of one case.
    MixedCase,
}

impl fmt::Display for CharError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Self::MissingSeparator => write!(f, "missing human-readable separator, \"{}\"", SEP),
            Self::NothingAfterSeparator => write!(f, "invalid data - no characters after the separator"),
            Self::InvalidChecksum => write!(f, "invalid checksum"),
            Self::InvalidChecksumLength => write!(f, "the checksum is not a valid length"),
            Self::InvalidChar(n) => write!(f, "invalid character (code={})", n),
            Self::MixedCase => write!(f, "mixed-case strings not allowed"),
        }
    }
}

impl std::error::Error for CharError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match *self {
            Self::MissingSeparator
            | Self::NothingAfterSeparator
            | Self::InvalidChecksum
            | Self::InvalidChecksumLength
            | Self::InvalidChar(_)
            | Self::MixedCase => None,
        }
    }
}

/// Errors in the checksum of a bech32 encoded string.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ChecksumError {
    /// The checksum does not match the rest of the data.
    InvalidChecksum,
    /// The checksum is not a valid length.
    InvalidChecksumLength,
}

impl fmt::Display for ChecksumError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Self::InvalidChecksum => write!(f, "invalid checksum"),
            Self::InvalidChecksumLength => write!(f, "the checksum is not a valid length"),
        }
    }
}

impl std::error::Error for ChecksumError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match *self {
            Self::InvalidChecksum | Self::InvalidChecksumLength => None,
        }
    }
}

/// Error validating the padding bits on the witness data.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PaddingError {
    /// The data payload has too many bits of padding.
    TooMuch,
    /// The data payload is padded with non-zero bits.
    NonZero,
}

impl fmt::Display for PaddingError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Self::TooMuch => write!(f, "the data payload has too many bits of padding"),
            Self::NonZero => write!(f, "the data payload is padded with non-zero bits"),
        }
    }
}

impl std::error::Error for PaddingError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match *self {
            Self::TooMuch | Self::NonZero => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bip_173_invalid_parsing_fails() {
        use UncheckedHrpstringError as E;

        let invalid: Vec<(&str, UncheckedHrpstringError)> = vec!(
            ("\u{20}1nwldj5",
             // TODO: Rust >= 1.59.0 use Hrp(hrp::Error::InvalidAsciiByte('\u{20}'.try_into().unwrap()))),
             E::Hrp(hrp::Error::InvalidAsciiByte(32))),
            ("\u{7F}1axkwrx",
             E::Hrp(hrp::Error::InvalidAsciiByte(127))),
            ("\u{80}1eym55h",
             E::Hrp(hrp::Error::NonAsciiChar('\u{80}'))),
            ("an84characterslonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11d6pts4",
             E::Hrp(hrp::Error::TooLong(84))),
            ("pzry9x0s0muk",
             E::Char(CharError::MissingSeparator)),
            ("1pzry9x0s0muk",
             E::Hrp(hrp::Error::Empty)),
            ("x1b4n0q5v",
             E::Char(CharError::InvalidChar('b'))),
            // "li1dgmt3" in separate test because error is a checksum error.
            ("de1lg7wt\u{ff}",
             E::Char(CharError::InvalidChar('\u{ff}'))),
            // "A1G7SGD8" in separate test because error is a checksum error.
            ("10a06t8",
             E::Hrp(hrp::Error::Empty)),
            ("1qzzfhee",
             E::Hrp(hrp::Error::Empty)),
        );

        for (s, want) in invalid {
            let got = UncheckedHrpstring::new(s).unwrap_err();
            assert_eq!(got, want);
        }
    }

    /*
    #[test]
    fn bip_173_invalid_parsing_fails_invalid_checksum() {
        use ChecksumError as E;

        let err = UncheckedHrpstring::new("li1dgmt3")
            .expect("string parses correctly")
            .validate_checksum::<Blech32>()
            .unwrap_err();
        assert_eq!(err, E::InvalidChecksumLength);

        let err = UncheckedHrpstring::new("A1G7SGD8")
            .expect("string parses correctly")
            .validate_checksum::<Blech32>()
            .unwrap_err();
        assert_eq!(err, E::InvalidChecksum);
    }
    */

    #[test]
    fn bip_350_invalid_parsing_fails() {
        use UncheckedHrpstringError as E;

        let invalid: Vec<(&str, UncheckedHrpstringError)> = vec!(
            ("\u{20}1xj0phk",
             // TODO: Rust >= 1.59.0 use Hrp(hrp::Error::InvalidAsciiByte('\u{20}'.try_into().unwrap()))),
             E::Hrp(hrp::Error::InvalidAsciiByte(32))),
            ("\u{7F}1g6xzxy",
             E::Hrp(hrp::Error::InvalidAsciiByte(127))),
            ("\u{80}1g6xzxy",
             E::Hrp(hrp::Error::NonAsciiChar('\u{80}'))),
            ("an84characterslonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1569pvx",
             E::Hrp(hrp::Error::TooLong(84))),
            ("qyrz8wqd2c9m",
             E::Char(CharError::MissingSeparator)),
            ("1qyrz8wqd2c9m",
             E::Hrp(hrp::Error::Empty)),
            ("y1b0jsk6g",
             E::Char(CharError::InvalidChar('b'))),
            ("lt1igcx5c0",
             E::Char(CharError::InvalidChar('i'))),
            // "in1muywd" in separate test because error is a checksum error.
            ("mm1crxm3i",
             E::Char(CharError::InvalidChar('i'))),
            ("au1s5cgom",
             E::Char(CharError::InvalidChar('o'))),
            // "M1VUXWEZ" in separate test because error is a checksum error.
            ("16plkw9",
             E::Hrp(hrp::Error::Empty)),
            ("1p2gdwpf",
             E::Hrp(hrp::Error::Empty)),

        );

        for (s, want) in invalid {
            let got = UncheckedHrpstring::new(s).unwrap_err();
            assert_eq!(got, want);
        }
    }

    /*
    #[test]
    fn bip_350_invalid_because_of_invalid_checksum() {
        use ChecksumError::*;

        // Note the "bc1p2" test case is not from the bip test vectors.
        let invalid: Vec<&str> = vec!["in1muywd", "bc1p2"];

        for s in invalid {
            let err =
                UncheckedHrpstring::new(s).unwrap().validate_checksum::<Blech32m>().unwrap_err();
            assert_eq!(err, InvalidChecksumLength);
        }

        let err = UncheckedHrpstring::new("M1VUXWEZ")
            .unwrap()
            .validate_checksum::<Blech32m>()
            .unwrap_err();
        assert_eq!(err, InvalidChecksum);
    }
    */

    #[test]
    fn check_hrp_uppercase_returns_lower() {
        let addr = "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4";
        let unchecked = UncheckedHrpstring::new(addr).expect("failed to parse address");
        assert_eq!(unchecked.hrp(), Hrp::parse_unchecked("bc"));
    }

    #[test]
    fn check_hrp_max_length() {
        let hrps =
            "an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio";

        let hrp = Hrp::parse_unchecked(hrps);
        let s = bech32::encode::<Blech32>(hrp, &[]).expect("failed to encode empty buffer");

        let unchecked = UncheckedHrpstring::new(&s).expect("failed to parse address");
        assert_eq!(unchecked.hrp(), hrp);
    }

    /*
    #[test]
    fn mainnet_valid_addresses() {
        let addresses = vec![
            "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",
            "23451QAR0SRRR7XFKVY5L643LYDNW9RE59GTZZLKULZK",
        ];
        for valid in addresses {
            assert!(CheckedHrpstring::new::<Blech32>(valid).is_ok())
        }
    }
    */

    macro_rules! check_invalid_segwit_addresses {
        ($($test_name:ident, $reason:literal, $address:literal);* $(;)?) => {
            $(
                #[test]
                fn $test_name() {
                    let res = SegwitHrpstring::new($address);
                    if res.is_ok() {
                        panic!("{} sting should not be valid: {}", $address, $reason);
                    }
                }
            )*
        }
    }
    check_invalid_segwit_addresses! {
        invalid_segwit_address_0, "missing hrp", "1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq";
        invalid_segwit_address_1, "missing data-checksum", "91111";
        invalid_segwit_address_2, "invalid witness version", "bc14r0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq";
        invalid_segwit_address_3, "invalid checksum length", "bc1q5mdq";
        invalid_segwit_address_4, "missing data", "bc1qwf5mdq";
        invalid_segwit_address_5, "invalid program length", "bc14r0srrr7xfkvy5l643lydnw9rewf5mdq";
    }
}
