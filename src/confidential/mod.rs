// Rust Elements Library
// Written in 2018 by
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

//! # Confidential Commitments
//!
//! Structures representing Pedersen commitments of various types
//!

mod asset;
mod nonce;
mod range_proof;
mod surjection_proof;
mod value;

use core::fmt;

use secp256k1_zkp;

pub use self::asset::{Asset, AssetBlindingFactor};
pub use self::nonce::Nonce;
pub use self::range_proof::RangeProof;
pub use self::surjection_proof::SurjectionProof;
pub use self::value::{Value, ValueBlindingFactor};
use crate::encode;
use crate::issuance::AssetId;

/// Error decoding hexadecimal string into tweak-like value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TweakHexDecodeError {
    /// Invalid hexadecimal string.
    InvalidHex(hex::DecodeFixedLengthBytesError),
    /// Invalid tweak after decoding hexadecimal string.
    InvalidTweak(secp256k1_zkp::Error),
}

impl fmt::Display for TweakHexDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            TweakHexDecodeError::InvalidHex(err) => {
                write!(f, "Invalid hex: {}", err)
            }
            TweakHexDecodeError::InvalidTweak(err) => {
                write!(f, "Invalid tweak: {}", err)
            }
        }
    }
}

#[doc(hidden)]
impl From<hex::DecodeFixedLengthBytesError> for TweakHexDecodeError {
    fn from(err: hex::DecodeFixedLengthBytesError) -> Self { TweakHexDecodeError::InvalidHex(err) }
}

#[doc(hidden)]
impl From<secp256k1_zkp::Error> for TweakHexDecodeError {
    fn from(err: secp256k1_zkp::Error) -> Self { TweakHexDecodeError::InvalidTweak(err) }
}

impl From<TweakHexDecodeError> for encode::Error {
    fn from(value: TweakHexDecodeError) -> Self {
        match value {
            TweakHexDecodeError::InvalidHex(err) => encode::Error::HexFixedError(err),
            TweakHexDecodeError::InvalidTweak(err) => encode::Error::Secp256k1zkp(err),
        }
    }
}

impl std::error::Error for TweakHexDecodeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            TweakHexDecodeError::InvalidHex(err) => Some(err),
            TweakHexDecodeError::InvalidTweak(err) => Some(err),
        }
    }
}
#[cfg(test)]
mod tests {
    #[cfg(feature = "serde")]
    use std::str::FromStr;

    #[cfg(feature = "serde")]
    use bincode;

    use super::*;
    use crate::encode::Encodable as _;

    const VALUE_EXPLICIT: [u8; 9] = [1, 0, 0, 0, 0, 0, 0, 3, 232];

    const VALUE_COMMITMENT1: [u8; 33] = [
        0x08, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        1, 1, 1, 1,
    ];

    const VALUE_COMMITMENT2: [u8; 33] = [
        0x09, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        1, 1, 1, 1,
    ];

    const NONCE_EXPLICIT: [u8; 33] = [
        0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0,
    ];

    const NONCE_COMMITMENT1: [u8; 33] = [
        0x02, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        1, 1, 1, 1,
    ];

    const NONCE_COMMITMENT2: [u8; 33] = [
        0x03, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        1, 1, 1, 1,
    ];

    const ASSET_EXPLICIT: [u8; 33] = [
        0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0,
    ];

    const ASSET_COMMITMENT1: [u8; 33] = [
        0x0a, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        1, 1, 1, 1,
    ];

    const ASSET_COMMITMENT2: [u8; 33] = [
        0x0b, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        1, 1, 1, 1,
    ];

    #[test]
    fn encode_length() {
        let val_encodings = [
            vec![0],
            VALUE_EXPLICIT.to_vec(),
            VALUE_COMMITMENT1.to_vec(),
            VALUE_COMMITMENT2.to_vec(),
        ];
        let vals = [
            Value::Null,
            Value::Explicit(1000),
            Value::from_commitment(&VALUE_COMMITMENT1).unwrap(),
            Value::from_commitment(&VALUE_COMMITMENT2).unwrap(),
        ];
        for (v, enc) in vals.iter().zip(val_encodings.iter()) {
            let mut x = vec![];
            assert_eq!(v.consensus_encode(&mut x).unwrap(), v.encoded_length());
            assert_eq!(x.len(), v.encoded_length());
            assert_eq!(x, *enc);
        }

        let nonce_encodings = [
            vec![0],
            NONCE_EXPLICIT.to_vec(),
            NONCE_COMMITMENT1.to_vec(),
            NONCE_COMMITMENT2.to_vec(),
        ];
        let nonces = [
            Nonce::Null,
            Nonce::Explicit([0; 32]),
            Nonce::from_commitment(&NONCE_COMMITMENT1).unwrap(),
            Nonce::from_commitment(&NONCE_COMMITMENT2).unwrap(),
        ];
        for (v, enc) in nonces.iter().zip(nonce_encodings.iter()) {
            let mut x = vec![];
            assert_eq!(v.consensus_encode(&mut x).unwrap(), v.encoded_length());
            assert_eq!(x.len(), v.encoded_length());
            assert_eq!(x, *enc);
        }

        let asset_encodings = [
            vec![0],
            ASSET_EXPLICIT.to_vec(),
            ASSET_COMMITMENT1.to_vec(),
            ASSET_COMMITMENT2.to_vec(),
        ];
        let assets = [
            Asset::Null,
            Asset::Explicit(AssetId::from_byte_array([0; 32])),
            Asset::from_commitment(&ASSET_COMMITMENT1).unwrap(),
            Asset::from_commitment(&ASSET_COMMITMENT2).unwrap(),
        ];
        for (v, enc) in assets.iter().zip(asset_encodings.iter()) {
            let mut x = vec![];
            assert_eq!(v.consensus_encode(&mut x).unwrap(), v.encoded_length());
            assert_eq!(x.len(), v.encoded_length());
            assert_eq!(x, *enc);
        }
    }

    #[test]
    fn commitments() {
        let x = Value::from_commitment(&VALUE_COMMITMENT1).unwrap();
        let commitment = x.commitment().unwrap();
        let mut commitment = commitment.serialize();
        assert_eq!(x, Value::from_commitment(&commitment[..]).unwrap());
        commitment[0] = 42;
        assert!(Value::from_commitment(&commitment[..]).is_err());

        let x = Asset::from_commitment(&ASSET_COMMITMENT1).unwrap();
        let commitment = x.commitment().unwrap();
        let mut commitment = commitment.serialize();
        assert_eq!(x, Asset::from_commitment(&commitment[..]).unwrap());
        commitment[0] = 42;
        assert!(Asset::from_commitment(&commitment[..]).is_err());

        let x = Nonce::from_commitment(&NONCE_COMMITMENT1).unwrap();
        let commitment = x.commitment().unwrap();
        let mut commitment = commitment.serialize();
        assert_eq!(x, Nonce::from_commitment(&commitment[..]).unwrap());
        commitment[0] = 42;
        assert!(Nonce::from_commitment(&commitment[..]).is_err());
    }

    #[cfg(feature = "serde")]
    #[test]
    fn value_serde() {
        use serde_test::{assert_tokens, Configure, Token};

        let value = Value::Explicit(100_000_000);
        assert_tokens(
            &value,
            &[
                Token::Seq { len: Some(2) },
                Token::U8(1),
                Token::U64(63_601_271_583_539_200),
                Token::SeqEnd,
            ],
        );

        let value = Value::from_commitment(&VALUE_COMMITMENT1).unwrap();
        assert_tokens(
            &value.readable(),
            &[
                Token::Seq { len: Some(2) },
                Token::U8(2),
                Token::Str("080101010101010101010101010101010101010101010101010101010101010101"),
                Token::SeqEnd,
            ],
        );
        assert_tokens(
            &value.compact(),
            &[
                Token::Seq { len: Some(2) },
                Token::U8(2),
                Token::Bytes(&VALUE_COMMITMENT1),
                Token::SeqEnd,
            ],
        );

        let value = Value::Null;
        assert_tokens(&value, &[Token::Seq { len: Some(1) }, Token::U8(0), Token::SeqEnd]);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn asset_serde() {
        use serde_test::{assert_tokens, Configure, Token};

        let asset_id =
            AssetId::from_str("630ed6f9b176af03c0cd3f8aa430f9e7b4d988cf2d0b2f204322488f03b00bf8")
                .unwrap();
        let asset = Asset::Explicit(asset_id);
        assert_tokens(
            &asset.readable(),
            &[
                Token::Seq { len: Some(2) },
                Token::U8(1),
                Token::Str("630ed6f9b176af03c0cd3f8aa430f9e7b4d988cf2d0b2f204322488f03b00bf8"),
                Token::SeqEnd,
            ],
        );
        assert_tokens(
            &asset.compact(),
            &[
                Token::Seq { len: Some(2) },
                Token::U8(1),
                Token::Bytes(&[
                    248, 11, 176, 3, 143, 72, 34, 67, 32, 47, 11, 45, 207, 136, 217, 180, 231, 249,
                    48, 164, 138, 63, 205, 192, 3, 175, 118, 177, 249, 214, 14, 99,
                ]),
                Token::SeqEnd,
            ],
        );

        let asset = Asset::from_commitment(&ASSET_COMMITMENT1).unwrap();
        assert_tokens(
            &asset.readable(),
            &[
                Token::Seq { len: Some(2) },
                Token::U8(2),
                Token::Str("0a0101010101010101010101010101010101010101010101010101010101010101"),
                Token::SeqEnd,
            ],
        );
        assert_tokens(
            &asset.compact(),
            &[
                Token::Seq { len: Some(2) },
                Token::U8(2),
                Token::Bytes(&ASSET_COMMITMENT1),
                Token::SeqEnd,
            ],
        );

        let asset = Asset::Null;
        assert_tokens(&asset, &[Token::Seq { len: Some(1) }, Token::U8(0), Token::SeqEnd]);
    }

    #[cfg(feature = "serde")]
    #[test]
    #[rustfmt::skip]
    fn nonce_serde() {
        use serde_test::{assert_tokens, Configure, Token};

        let nonce = Nonce::Explicit([
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        ]);
        assert_tokens(
            &nonce,
            &[
                Token::Seq { len: Some(2) },
                Token::U8(1),
                Token::Tuple { len: 32 },
                Token::U8(1), Token::U8(1), Token::U8(1), Token::U8(1),
                Token::U8(1), Token::U8(1), Token::U8(1), Token::U8(1),
                Token::U8(1), Token::U8(1), Token::U8(1), Token::U8(1),
                Token::U8(1), Token::U8(1), Token::U8(1), Token::U8(1),
                Token::U8(1), Token::U8(1), Token::U8(1), Token::U8(1),
                Token::U8(1), Token::U8(1), Token::U8(1), Token::U8(1),
                Token::U8(1), Token::U8(1), Token::U8(1), Token::U8(1),
                Token::U8(1), Token::U8(1), Token::U8(1), Token::U8(1),
                Token::TupleEnd,
                Token::SeqEnd
            ]
        );

        let nonce = Nonce::from_commitment(&NONCE_COMMITMENT1).unwrap();
        assert_tokens(
            &nonce.readable(),
            &[
                Token::Seq { len: Some(2) },
                Token::U8(2),
                Token::Str(
                    "020101010101010101010101010101010101010101010101010101010101010101"
                ),
                Token::SeqEnd
            ]
        );
        assert_tokens(
            &nonce.compact(),
            &[
                Token::Seq { len: Some(2) },
                Token::U8(2),
                Token::Tuple { len: 33 },
                Token::U8(2), Token::U8(1), Token::U8(1), Token::U8(1),
                Token::U8(1), Token::U8(1), Token::U8(1), Token::U8(1),
                Token::U8(1), Token::U8(1), Token::U8(1), Token::U8(1),
                Token::U8(1), Token::U8(1), Token::U8(1), Token::U8(1),
                Token::U8(1), Token::U8(1), Token::U8(1), Token::U8(1),
                Token::U8(1), Token::U8(1), Token::U8(1), Token::U8(1),
                Token::U8(1), Token::U8(1), Token::U8(1), Token::U8(1),
                Token::U8(1), Token::U8(1), Token::U8(1), Token::U8(1),
                Token::U8(1),
                Token::TupleEnd,
                Token::SeqEnd
            ]
        );

        let nonce = Nonce::Null;
        assert_tokens(
            &nonce,
            &[
                Token::Seq { len: Some(1) },
                Token::U8(0),
                Token::SeqEnd
            ]
        );
    }

    #[cfg(feature = "serde")]
    #[test]
    fn bf_serde() {
        use std::str::FromStr;

        use serde_json;

        let abf_str = "a5b3d111cdaa5fc111e2723df4caf315864f25fb4610cc737f10d5a55cd4096f";
        let abf_str_quoted = format!("\"{}\"", abf_str);
        let abf_from_serde: AssetBlindingFactor = serde_json::from_str(&abf_str_quoted).unwrap();
        let abf_from_str = AssetBlindingFactor::from_str(abf_str).unwrap();
        assert_eq!(abf_from_serde, abf_from_str);
        assert_eq!(abf_str_quoted, serde_json::to_string(&abf_from_serde).unwrap());

        let vbf_str = "e36a4de359469f547571d117bc5509fb74fba73c84b0cdd6f4edfa7ff7fa457d";
        let vbf_str_quoted = format!("\"{}\"", vbf_str);
        let vbf_from_serde: ValueBlindingFactor = serde_json::from_str(&vbf_str_quoted).unwrap();
        let vbf_from_str = ValueBlindingFactor::from_str(vbf_str).unwrap();
        assert_eq!(vbf_from_serde, vbf_from_str);
        assert_eq!(vbf_str_quoted, serde_json::to_string(&vbf_from_serde).unwrap());
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_value_bincode_be() {
        let value = Value::Explicit(500);
        let bytes = bincode::serialize(&value).unwrap();
        let decoded: Value = bincode::deserialize(&bytes).unwrap();
        assert_eq!(value, decoded);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_value_bincode_le() {
        use bincode::Options;
        let value = Value::Explicit(500);
        let bytes =
            bincode::DefaultOptions::default().with_little_endian().serialize(&value).unwrap();
        let decoded: Value =
            bincode::DefaultOptions::default().with_little_endian().deserialize(&bytes).unwrap();
        assert_eq!(value, decoded);
    }
}
