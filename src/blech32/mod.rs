// This file is an adaptation of the segwit-specific parts of the bech32 crate.
// Rust Elements Library
// Written in 2024 by
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

//! Blech32-Encoding (Elements Segwit) Support
//!
//! A variation of the bech32 encoding for blinded Elements addresses.
//!

pub mod decode;

// *** Definitions of checksums ***

/// The blech32 checksum algorithm.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Blech32 {}

impl crate::bech32::Checksum for Blech32 {
    type MidstateRepr = u64;
    const CHECKSUM_LENGTH: usize = 12;
    const GENERATOR_SH: [u64; 5] = [
        0x7d52fba40bd886,
        0x5e8dbf1a03950c,
        0x1c3a3c74072a18,
        0x385d72fa0e5139,
        0x7093e5a608865b,
    ];
    const TARGET_RESIDUE: u64 = 1;
}

/// The blech32m checksum algorithm.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Blech32m {}

impl crate::bech32::Checksum for Blech32m {
    type MidstateRepr = u64;
    const CHECKSUM_LENGTH: usize = 12;
    const GENERATOR_SH: [u64; 5] = [
        0x7d52fba40bd886,
        0x5e8dbf1a03950c,
        0x1c3a3c74072a18,
        0x385d72fa0e5139,
        0x7093e5a608865b,
    ];
    const TARGET_RESIDUE: u64 = 0x455972a3350f7a1;
}
