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

//! Consensus-encodable types
//!

use std::io::Cursor;
use std::{error, fmt, io, mem};

use bitcoin::ScriptBuf;
use secp256k1_zkp::{self, RangeProof, SurjectionProof, Tweak};

use crate::hashes::{sha256, Hash};
use crate::pset;
use crate::transaction::{Transaction, TxIn, TxOut};

pub use bitcoin::{self, consensus::encode::MAX_VEC_SIZE};

use crate::taproot::TapLeafHash;

/// Encoding error
#[derive(Debug)]
pub enum Error {
    /// And I/O error
    Io(io::Error),
    /// A Bitcoin encoding error.
    Bitcoin(bitcoin::consensus::encode::Error),
    /// Tried to allocate an oversized vector
    OversizedVectorAllocation {
        /// The capacity requested
        requested: usize,
        /// The maximum capacity
        max: usize,
    },
    /// Parsing error
    ParseFailed(&'static str),
    /// We unexpectedly hit the end of the buffer
    UnexpectedEOF,
    /// Invalid prefix for the confidential type.
    InvalidConfidentialPrefix(u8),
    /// Parsing within libsecp256k1 failed
    Secp256k1(secp256k1_zkp::UpstreamError),
    /// Parsing within libsecp256k1-zkp failed
    Secp256k1zkp(secp256k1_zkp::Error),
    /// Pset related Errors
    PsetError(pset::Error),
    /// Hex parsing errors
    HexError(crate::hex::Error),
    /// Got a time-based locktime when expecting a height-based one, or vice-versa
    BadLockTime(crate::LockTime),
    /// `VarInt` was encoded in a non-minimal way.
    NonMinimalVarInt,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::Io(ref e) => write!(f, "I/O error: {}", e),
            Error::Bitcoin(ref e) => write!(f, "a Bitcoin type encoding error: {}", e),
            Error::OversizedVectorAllocation {
                requested: ref r,
                max: ref m,
            } => write!(
                f,
                "oversized vector allocation: requested {}, maximum {}",
                r, m
            ),
            Error::ParseFailed(e) => write!(f, "parse failed: {}", e),
            Error::UnexpectedEOF => write!(f, "unexpected EOF"),
            Error::InvalidConfidentialPrefix(p) => {
                write!(f, "invalid confidential prefix: 0x{:02x}", p)
            }
            Error::Secp256k1(ref e) => write!(f, "{}", e),
            Error::Secp256k1zkp(ref e) => write!(f, "{}", e),
            Error::PsetError(ref e) => write!(f, "Pset Error: {}", e),
            Error::HexError(ref e) => write!(f, "Hex error {}", e),
            Error::BadLockTime(ref lt) => write!(f, "Invalid locktime {}", lt),
            Error::NonMinimalVarInt => write!(f, "non-minimal varint"),
        }
    }
}

impl error::Error for Error {
    fn cause(&self) -> Option<&dyn error::Error> {
        match *self {
            Error::Secp256k1zkp(ref e) => Some(e),
            _ => None,
        }
    }
}
#[doc(hidden)]
impl From<bitcoin::consensus::encode::Error> for Error {
    fn from(e: bitcoin::consensus::encode::Error) -> Error {
        Error::Bitcoin(e)
    }
}

#[doc(hidden)]
impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Error::Io(error)
    }
}

#[doc(hidden)]
impl From<pset::Error> for Error {
    fn from(e: pset::Error) -> Error {
        Error::PsetError(e)
    }
}

#[doc(hidden)]
impl From<secp256k1_zkp::UpstreamError> for Error {
    fn from(e: secp256k1_zkp::UpstreamError) -> Self {
        Error::Secp256k1(e)
    }
}

#[doc(hidden)]
impl From<secp256k1_zkp::Error> for Error {
    fn from(e: secp256k1_zkp::Error) -> Self {
        Error::Secp256k1zkp(e)
    }
}

#[doc(hidden)]
impl From<crate::hex::Error> for Error {
    fn from(e: crate::hex::Error) -> Self {
        Error::HexError(e)
    }
}

/// Data which can be encoded in a consensus-consistent way
pub trait Encodable {
    /// Encode an object with a well-defined format, should only ever error if
    /// the underlying `Write` errors. Returns the number of bytes written on
    /// success
    fn consensus_encode<W: io::Write>(&self, e: W) -> Result<usize, Error>;
}

/// Data which can be encoded in a consensus-consistent way
pub trait Decodable: Sized {
    /// Decode an object with a well-defined format
    fn consensus_decode<D: io::Read>(d: D) -> Result<Self, Error>;
}

/// Encode an object into a vector
pub fn serialize<T: Encodable + ?Sized>(data: &T) -> Vec<u8> {
    let mut encoder = Cursor::new(vec![]);
    data.consensus_encode(&mut encoder).unwrap();
    encoder.into_inner()
}

/// Encode an object into a hex-encoded string
pub fn serialize_hex<T: Encodable + ?Sized>(data: &T) -> String {
    crate::hex::ToHex::to_hex(&serialize(data)[..])
}

/// Deserialize an object from a vector, will error if said deserialization
/// doesn't consume the entire vector.
pub fn deserialize<T: Decodable>(data: &[u8]) -> Result<T, Error> {
    let (rv, consumed) = deserialize_partial(data)?;

    // Fail if data are not consumed entirely.
    if consumed == data.len() {
        Ok(rv)
    } else {
        Err(Error::ParseFailed(
            "data not consumed entirely when explicitly deserializing",
        ))
    }
}

/// Deserialize an object from a vector, but will not report an error if said deserialization
/// doesn't consume the entire vector.
pub fn deserialize_partial<T: Decodable>(data: &[u8]) -> Result<(T, usize), Error> {
    let mut decoder = Cursor::new(data);
    let rv = Decodable::consensus_decode(&mut decoder)?;
    let consumed = decoder.position() as usize;

    Ok((rv, consumed))
}

impl Encodable for sha256::Midstate {
    fn consensus_encode<W: io::Write>(&self, e: W) -> Result<usize, Error> {
        self.to_byte_array().consensus_encode(e)
    }
}

impl Decodable for sha256::Midstate {
    fn consensus_decode<D: io::Read>(d: D) -> Result<Self, Error> {
        Ok(Self::from_byte_array(<[u8; 32]>::consensus_decode(d)?))
    }
}

pub(crate) fn consensus_encode_with_size<S: crate::WriteExt>(
    data: &[u8],
    mut s: S,
) -> Result<usize, Error> {
    let vi_len = VarInt(data.len() as u64).consensus_encode(&mut s)?;
    s.emit_slice(data)?;
    Ok(vi_len + data.len())
}

// Specific locktime types (which appear in PSET/PSBT2 but not in rust-bitcoin PSBT)
impl Encodable for crate::locktime::Height {
    fn consensus_encode<S: io::Write>(&self, s: S) -> Result<usize, Error> {
        crate::LockTime::from(*self).consensus_encode(s)
    }
}
impl Decodable for crate::locktime::Height {
    fn consensus_decode<D: io::Read>(d: D) -> Result<Self, Error> {
        match crate::LockTime::consensus_decode(d)? {
            crate::LockTime::Blocks(h) => Ok(h),
            x @ crate::LockTime::Seconds(_) => Err(Error::BadLockTime(x)),
        }
    }
}

impl Encodable for crate::locktime::Time {
    fn consensus_encode<S: io::Write>(&self, s: S) -> Result<usize, Error> {
        crate::LockTime::from(*self).consensus_encode(s)
    }
}
impl Decodable for crate::locktime::Time {
    fn consensus_decode<D: io::Read>(d: D) -> Result<Self, Error> {
        match crate::LockTime::consensus_decode(d)? {
            crate::LockTime::Seconds(t) => Ok(t),
            x @ crate::LockTime::Blocks(_) => Err(Error::BadLockTime(x)),
        }
    }
}

/// A variable sized integer.
pub struct VarInt(pub u64);
impl Encodable for VarInt {
    fn consensus_encode<W: crate::WriteExt>(&self, mut e: W) -> Result<usize, Error> {
        Ok(e.emit_varint(self.0)?)
    }
}
impl Decodable for VarInt {
    fn consensus_decode<D: crate::ReadExt>(mut d: D) -> Result<Self, Error> {
        Ok(VarInt(d.read_varint()?))
    }
}
impl VarInt {
    /// returns the byte size used if this var int is serialized
    pub fn size(&self) -> usize {
        match self.0 {
            0..=0xFC => 1,
            0xFD..=0xFFFF => 3,
            0x10000..=0xFFFF_FFFF => 5,
            _ => 9,
        }
    }
}

// Primitive types
macro_rules! impl_int {
    ($ty:ident, $meth_dec:ident, $meth_enc:ident) => {
        impl Encodable for $ty {
            fn consensus_encode<W: crate::WriteExt>(&self, mut w: W) -> Result<usize, Error> {
                w.$meth_enc(*self)?;
                Ok(mem::size_of::<$ty>())
            }
        }
        impl Decodable for $ty {
            fn consensus_decode<R: crate::ReadExt>(mut r: R) -> Result<Self, Error> {
                crate::ReadExt::$meth_dec(&mut r)
            }
        }
    };
}

impl_int!(u8, read_u8, emit_u8);
impl_int!(u16, read_u16, emit_u16);
impl_int!(u32, read_u32, emit_u32);
impl_int!(u64, read_u64, emit_u64);

impl Encodable for bitcoin::ScriptBuf {
    fn consensus_encode<W: io::Write>(&self, w: W) -> Result<usize, Error> {
        consensus_encode_with_size(self.as_script().as_bytes(), w)
    }
}
impl Decodable for bitcoin::ScriptBuf {
    fn consensus_decode<D: io::Read>(d: D) -> Result<Self, Error> {
        let bytes = Vec::<u8>::consensus_decode(d)?;
        Ok(ScriptBuf::from_bytes(bytes))
    }
}

impl Encodable for bitcoin::hashes::sha256d::Hash {
    fn consensus_encode<W: io::Write>(&self, mut w: W) -> Result<usize, Error> {
        self.as_byte_array().consensus_encode(&mut w)
    }
}
impl Decodable for bitcoin::hashes::sha256d::Hash {
    fn consensus_decode<D: io::Read>(d: D) -> Result<Self, Error> {
        Ok(Self::from_byte_array(
            <<Self as Hash>::Bytes>::consensus_decode(d)?,
        ))
    }
}

// Vectors
macro_rules! impl_vec {
    ($type: ty) => {
        impl Encodable for Vec<$type> {
            #[inline]
            fn consensus_encode<S: io::Write>(&self, mut s: S) -> Result<usize, Error> {
                let mut len = 0;
                len += VarInt(self.len() as u64).consensus_encode(&mut s)?;
                for c in self.iter() {
                    len += c.consensus_encode(&mut s)?;
                }
                Ok(len)
            }
        }

        impl Decodable for Vec<$type> {
            #[inline]
            fn consensus_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
                let len = VarInt::consensus_decode(&mut d)?.0;
                let byte_size = (len as usize)
                    .checked_mul(mem::size_of::<$type>())
                    .ok_or(self::Error::ParseFailed("Invalid length"))?;
                if byte_size > MAX_VEC_SIZE {
                    return Err(self::Error::OversizedVectorAllocation {
                        requested: byte_size,
                        max: MAX_VEC_SIZE,
                    });
                }
                let mut ret = Vec::with_capacity(len as usize);
                for _ in 0..len {
                    ret.push(Decodable::consensus_decode(&mut d)?);
                }
                Ok(ret)
            }
        }
    };
}
impl_vec!(TxIn);
impl_vec!(TxOut);
impl_vec!(Transaction);
impl_vec!(TapLeafHash);
impl_vec!(Vec<u8>); // Vec<Vec<u8>>

macro_rules! impl_array {
    ( $size:literal ) => {
        impl Encodable for [u8; $size] {
            #[inline]
            fn consensus_encode<W: crate::WriteExt>(
                &self,
                mut w: W,
            ) -> core::result::Result<usize, Error> {
                w.emit_slice(&self[..])?;
                Ok($size)
            }
        }

        impl Decodable for [u8; $size] {
            #[inline]
            fn consensus_decode<R: crate::ReadExt>(mut r: R) -> core::result::Result<Self, Error> {
                let mut ret = [0; $size];
                r.read_slice(&mut ret)?;
                Ok(ret)
            }
        }
    };
}
impl_array!(4);
impl_array!(32);
impl_array!(33);

impl Encodable for Box<[u8]> {
    fn consensus_encode<W: io::Write>(&self, mut w: W) -> Result<usize, Error> {
        consensus_encode_with_size(&self[..], &mut w)
    }
}
impl Decodable for Box<[u8]> {
    fn consensus_decode<D: io::Read>(d: D) -> Result<Self, Error> {
        let v = Vec::<u8>::consensus_decode(d)?;
        Ok(v.into())
    }
}

impl Encodable for Vec<u8> {
    fn consensus_encode<W: io::Write>(&self, mut w: W) -> Result<usize, Error> {
        consensus_encode_with_size(&self[..], &mut w)
    }
}
impl Decodable for Vec<u8> {
    fn consensus_decode<D: crate::ReadExt>(mut d: D) -> Result<Self, Error> {
        let s = VarInt::consensus_decode(&mut d)?.0 as usize;
        if s > MAX_VEC_SIZE {
            return Err(self::Error::OversizedVectorAllocation {
                requested: s,
                max: MAX_VEC_SIZE,
            });
        }
        let mut v = vec![0; s];
        d.read_slice(&mut v)?;
        Ok(v)
    }
}

macro_rules! impl_box_option {
    ($type: ty) => {
        impl Encodable for Option<Box<$type>> {
            #[inline]
            fn consensus_encode<W: io::Write>(&self, e: W) -> Result<usize, Error> {
                match self {
                    None => Vec::<u8>::new().consensus_encode(e),
                    Some(v) => v.serialize().consensus_encode(e),
                }
            }
        }

        impl Decodable for Option<Box<$type>> {
            #[inline]
            fn consensus_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
                let v: Vec<u8> = Decodable::consensus_decode(&mut d)?;
                if v.is_empty() {
                    Ok(None)
                } else {
                    Ok(Some(Box::new(<$type>::from_slice(&v)?)))
                }
            }
        }
    };
}
// special implementations for elements only fields
impl Encodable for Tweak {
    fn consensus_encode<W: io::Write>(&self, e: W) -> Result<usize, Error> {
        self.as_ref().consensus_encode(e)
    }
}

impl Decodable for Tweak {
    fn consensus_decode<D: io::Read>(d: D) -> Result<Self, Error> {
        Ok(Tweak::from_inner(<[u8; 32]>::consensus_decode(d)?)?)
    }
}

impl Encodable for RangeProof {
    fn consensus_encode<W: io::Write>(&self, e: W) -> Result<usize, Error> {
        self.serialize().consensus_encode(e)
    }
}

impl Decodable for RangeProof {
    fn consensus_decode<D: io::Read>(d: D) -> Result<Self, Error> {
        Ok(RangeProof::from_slice(&<Vec<u8>>::consensus_decode(d)?)?)
    }
}

impl Encodable for SurjectionProof {
    fn consensus_encode<W: io::Write>(&self, e: W) -> Result<usize, Error> {
        self.serialize().consensus_encode(e)
    }
}

impl Decodable for SurjectionProof {
    fn consensus_decode<D: io::Read>(d: D) -> Result<Self, Error> {
        Ok(SurjectionProof::from_slice(&<Vec<u8>>::consensus_decode(
            d,
        )?)?)
    }
}

impl Encodable for sha256::Hash {
    fn consensus_encode<S: io::Write>(&self, s: S) -> Result<usize, Error> {
        self.to_byte_array().consensus_encode(s)
    }
}

impl Decodable for sha256::Hash {
    fn consensus_decode<D: io::Read>(d: D) -> Result<Self, Error> {
        Ok(Self::from_byte_array(
            <<Self as Hash>::Bytes>::consensus_decode(d)?,
        ))
    }
}

impl Encodable for TapLeafHash {
    fn consensus_encode<S: io::Write>(&self, s: S) -> Result<usize, Error> {
        self.to_byte_array().consensus_encode(s)
    }
}

impl Decodable for TapLeafHash {
    fn consensus_decode<D: io::Read>(d: D) -> Result<Self, Error> {
        Ok(Self::from_byte_array(
            <<Self as Hash>::Bytes>::consensus_decode(d)?,
        ))
    }
}

impl_box_option!(RangeProof);
impl_box_option!(SurjectionProof);
