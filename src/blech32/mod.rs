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

impl bech32::Checksum for Blech32 {
    type MidstateRepr = u64;
    const CHECKSUM_LENGTH: usize = 12;
    const GENERATOR_SH: [u64; 5] = [
        0x7d_52fb_a40b_d886,
        0x5e_8dbf_1a03_950c,
        0x1c_3a3c_7407_2a18,
        0x38_5d72_fa0e_5139,
        0x70_93e5_a608_865b,
    ];
    const TARGET_RESIDUE: u64 = 1;

    const CODE_LENGTH: usize = 1024;
}

/// The blech32m checksum algorithm.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Blech32m {}

impl bech32::Checksum for Blech32m {
    type MidstateRepr = u64;
    const CHECKSUM_LENGTH: usize = 12;
    const GENERATOR_SH: [u64; 5] = [
        0x7d_52fb_a40b_d886,
        0x5e_8dbf_1a03_950c,
        0x1c_3a3c_7407_2a18,
        0x38_5d72_fa0e_5139,
        0x70_93e5_a608_865b,
    ];
    const TARGET_RESIDUE: u64 = 0x455_972a_3350_f7a1;

    const CODE_LENGTH: usize = 1024;
}
