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

#![warn(clippy::use_self)]

mod asset;
mod nonce;
mod range_proof;
mod surjection_proof;
mod value;

use core::{fmt, slice};

use secp256k1_zkp;

pub use self::asset::{
    Asset, BlindingFactor as AssetBlindingFactor, Decoder as AssetDecoder,
    DecoderError as AssetDecoderError, Encoder as AssetEncoder,
};
pub use self::nonce::{
    Decoder as NonceDecoder, DecoderError as NonceDecoderError, Encoder as NonceEncoder, Nonce,
};
pub use self::range_proof::{
    Decoder as RangeProofDecoder, DecoderError as RangeProofDecoderError,
    Encoder as RangeProofEncoder, RangeProof,
};
pub use self::surjection_proof::{
    Decoder as SurjectionProofDecoder, DecoderError as SurjectionProofDecoderError,
    Encoder as SurjectionProofEncoder, SurjectionProof,
};
pub use self::value::{
    BlindingFactor as ValueBlindingFactor, Decoder as ValueDecoder,
    DecoderError as ValueDecoderError, Encoder as ValueEncoder, Value,
};
use crate::issuance::AssetId;
use crate::{encode, encoding};

const CONFIDENTIAL_LEN: usize = 33;

pub(crate) fn checked_commitment_slice(bytes: &[u8]) -> Result<&[u8], encode::Error> {
    // The upstream FFI parsers take no length and unconditionally read 33 bytes.
    if bytes.len() != CONFIDENTIAL_LEN {
        return Err(encode::Error::ParseFailed("invalid confidential commitment length"));
    }
    Ok(bytes)
}

#[derive(Clone, Debug)]
enum CommitmentEncoder<'e> {
    Null(u8),
    Explicit8(Option<u8>, [u8; 8]),
    Explicit32(Option<u8>, &'e [u8; 32]),
    Explicit33([u8; 33]),
}

impl encoding::Encoder for CommitmentEncoder<'_> {
    fn current_chunk(&self) -> &[u8] {
        match *self {
            Self::Null(ref prefix) => slice::from_ref(prefix),
            Self::Explicit8(ref prefix, ref arr) => prefix.as_ref().map_or(arr, slice::from_ref),
            Self::Explicit32(ref prefix, arr) => prefix.as_ref().map_or(arr, slice::from_ref),
            Self::Explicit33(ref arr) => arr,
        }
    }

    fn advance(&mut self) -> encoding::EncoderStatus {
        match *self {
            Self::Explicit8(ref mut prefix @ Some(_), _)
            | Self::Explicit32(ref mut prefix @ Some(_), _) => {
                *prefix = None;
                encoding::EncoderStatus::HasMore
            }
            _ => encoding::EncoderStatus::Finished,
        }
    }
}

impl encoding::ExactSizeEncoder for CommitmentEncoder<'_> {
    fn len(&self) -> usize {
        match *self {
            Self::Null(_) => 1,
            Self::Explicit8(Some(_), _) => 9,
            Self::Explicit8(None, _) => 8,
            Self::Explicit32(Some(_), _) => 33,
            Self::Explicit32(None, _) => 32,
            Self::Explicit33(_) => 33,
        }
    }
}

/// Because the rust-secp256k1-zkp proof types have no `as_bytes()` method, we need
/// to serialize them to a byte vector before encoding them.
///
/// This encoder accomplishes that -- this situation never happens in rust-bitcoin
/// so there is no "owned bytes encoder" shipped with bitcoin-consensus-encoding.
#[derive(Clone, Debug)]
struct PrefixedByteVecEncoder {
    prefix_encoder: Option<encoding::CompactSizeEncoder>,
    data: Vec<u8>,
}

impl PrefixedByteVecEncoder {
    pub fn new(data: Vec<u8>) -> Self {
        Self { prefix_encoder: Some(encoding::CompactSizeEncoder::new(data.len())), data }
    }
}

impl encoding::Encoder for PrefixedByteVecEncoder {
    fn current_chunk(&self) -> &[u8] {
        if let Some(ref enc) = self.prefix_encoder {
            return enc.current_chunk();
        }
        &self.data
    }

    fn advance(&mut self) -> encoding::EncoderStatus {
        if let Some(ref mut enc) = self.prefix_encoder {
            if enc.advance().has_finished() {
                self.prefix_encoder = None;
                if self.data.is_empty() {
                    return encoding::EncoderStatus::Finished;
                }
            }
            encoding::EncoderStatus::HasMore
        } else {
            encoding::EncoderStatus::Finished
        }
    }
}

impl encoding::ExactSizeEncoder for PrefixedByteVecEncoder {
    fn len(&self) -> usize {
        self.prefix_encoder.as_ref().map_or(0, encoding::CompactSizeEncoder::len) + self.data.len()
    }
}

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
            Self::InvalidHex(err) => {
                write!(f, "Invalid hex: {}", err)
            }
            Self::InvalidTweak(err) => {
                write!(f, "Invalid tweak: {}", err)
            }
        }
    }
}

#[doc(hidden)]
impl From<hex::DecodeFixedLengthBytesError> for TweakHexDecodeError {
    fn from(err: hex::DecodeFixedLengthBytesError) -> Self { Self::InvalidHex(err) }
}

#[doc(hidden)]
impl From<secp256k1_zkp::Error> for TweakHexDecodeError {
    fn from(err: secp256k1_zkp::Error) -> Self { Self::InvalidTweak(err) }
}

impl From<TweakHexDecodeError> for encode::Error {
    fn from(value: TweakHexDecodeError) -> Self {
        match value {
            TweakHexDecodeError::InvalidHex(err) => Self::HexFixedError(err),
            TweakHexDecodeError::InvalidTweak(err) => Self::Secp256k1zkp(err),
        }
    }
}

impl std::error::Error for TweakHexDecodeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidHex(err) => Some(err),
            Self::InvalidTweak(err) => Some(err),
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
    use crate::encoding;

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
    fn prefixed_byte_encoder() {
        assert_eq!(encoding::drain_to_vec(&mut PrefixedByteVecEncoder::new(vec![])), [0]);
        assert_eq!(
            encoding::drain_to_vec(&mut PrefixedByteVecEncoder::new(vec![1, 2, 3])),
            [3, 1, 2, 3]
        );
    }

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

            assert_eq!(encoding::encode_to_vec(v), *enc);
            assert_eq!(encoding::decode_from_slice(enc), Ok(*v));
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

            assert_eq!(encoding::encode_to_vec(v), *enc);
            assert_eq!(encoding::decode_from_slice(enc), Ok(*v));
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

            assert_eq!(encoding::encode_to_vec(v), *enc);
            assert_eq!(encoding::decode_from_slice(enc), Ok(*v));
        }
    }

    #[test]
    fn commitments() {
        for len in [0usize, 1, 32, 34] {
            let bytes = vec![0u8; len];
            assert!(Value::from_commitment(&bytes).is_err());
            assert!(Asset::from_commitment(&bytes).is_err());
            assert!(Nonce::from_commitment(&bytes).is_err());
        }

        let x = Value::from_commitment(&VALUE_COMMITMENT1).unwrap();
        let commitment = x.commitment().unwrap();
        let mut commitment = commitment.serialize();
        assert_eq!(x, Value::from_commitment(&commitment[..]).unwrap());
        commitment[0] = 42;
        assert!(Value::from_commitment(&commitment[..]).is_err());
        assert_eq!(encoding::encode_to_vec(&x), VALUE_COMMITMENT1);

        let x = Asset::from_commitment(&ASSET_COMMITMENT1).unwrap();
        let commitment = x.commitment().unwrap();
        let mut commitment = commitment.serialize();
        assert_eq!(x, Asset::from_commitment(&commitment[..]).unwrap());
        commitment[0] = 42;
        assert!(Asset::from_commitment(&commitment[..]).is_err());
        assert_eq!(encoding::encode_to_vec(&x), ASSET_COMMITMENT1);

        let x = Nonce::from_commitment(&NONCE_COMMITMENT1).unwrap();
        let commitment = x.commitment().unwrap();
        let mut commitment = commitment.serialize();
        assert_eq!(x, Nonce::from_commitment(&commitment[..]).unwrap());
        commitment[0] = 42;
        assert!(Nonce::from_commitment(&commitment[..]).is_err());
        assert_eq!(encoding::encode_to_vec(&x), NONCE_COMMITMENT1);
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
