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

use bitcoin::consensus::encode as btcenc;
use bitcoin::hashes::sha256;

use transaction::{Transaction, TxIn, TxOut};

pub use bitcoin::consensus::encode::MAX_VEC_SIZE;

/// Encoding error
#[derive(Debug)]
pub enum Error {
    /// A Bitcoin encoding error.
    Bitcoin(btcenc::Error),
    /// Tried to allocate an oversized vector
    OversizedVectorAllocation {
        /// The capacity requested
        requested: usize,
        /// The maximum capacity
        max: usize,
    },
    /// Parsing error
    ParseFailed(&'static str),
    /// Invalid prefix for the confidential type.
    InvalidConfidentialPrefix(u8),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::Bitcoin(ref e) => write!(f, "a Bitcoin type encoding error: {}", e),
            Error::OversizedVectorAllocation {
                requested: ref r,
                max: ref m,
            } => write!(f, "oversized vector allocation: requested {}, maximum {}", r, m),
            Error::ParseFailed(ref e) => write!(f, "parse failed: {}", e),
            Error::InvalidConfidentialPrefix(p) => write!(f, "invalid confidential prefix: 0x{:02x}", p),
        }
    }
}

impl error::Error for Error {
    fn cause(&self) -> Option<&dyn error::Error> {
        match *self {
            Error::Bitcoin(ref e) => Some(e),
            _ => None,
        }
    }
}

#[doc(hidden)]
impl From<btcenc::Error> for Error {
    fn from(e: btcenc::Error) -> Error {
        Error::Bitcoin(e)
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
    ::bitcoin::hashes::hex::ToHex::to_hex(&serialize(data)[..])
}

/// Deserialize an object from a vector, will error if said deserialization
/// doesn't consume the entire vector.
pub fn deserialize<'a, T: Decodable>(data: &'a [u8]) -> Result<T, Error> {
    let (rv, consumed) = deserialize_partial(data)?;

    // Fail if data are not consumed entirely.
    if consumed == data.len() {
        Ok(rv)
    } else {
        Err(Error::ParseFailed("data not consumed entirely when explicitly deserializing"))
    }
}

/// Deserialize an object from a vector, but will not report an error if said deserialization
/// doesn't consume the entire vector.
pub fn deserialize_partial<'a, T: Decodable>(data: &'a [u8]) -> Result<(T, usize), Error> {
    let mut decoder = Cursor::new(data);
    let rv = Decodable::consensus_decode(&mut decoder)?;
    let consumed = decoder.position() as usize;

    Ok((rv, consumed))
}

impl Encodable for sha256::Midstate {
    fn consensus_encode<W: io::Write>(&self, e: W) -> Result<usize, Error> {
        self.into_inner().consensus_encode(e)
    }
}

impl Decodable for sha256::Midstate {
    fn consensus_decode<D: io::Read>(d: D) -> Result<Self, Error> {
        Ok(Self::from_inner(<[u8; 32]>::consensus_decode(d)?))
    }
}

/// Implement Elements encodable traits for Bitcoin encodable types.
macro_rules! impl_upstream {
    ($type: ty) => {
        impl Encodable for $type {
            fn consensus_encode<W: io::Write>(&self, mut e: W) -> Result<usize, Error> {
                Ok(btcenc::Encodable::consensus_encode(self, &mut e)?)
            }
        }

        impl Decodable for $type {
            fn consensus_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
                Ok(btcenc::Decodable::consensus_decode(&mut d)?)
            }
        }
    };
}
impl_upstream!(u8);
impl_upstream!(u32);
impl_upstream!(u64);
impl_upstream!([u8; 32]);
impl_upstream!(Box<[u8]>);
impl_upstream!(Vec<u8>);
impl_upstream!(Vec<Vec<u8>>);
impl_upstream!(btcenc::VarInt);
impl_upstream!(::bitcoin::blockdata::script::Script);
impl_upstream!(::bitcoin::hashes::sha256d::Hash);
impl_upstream!(::bitcoin::Txid);
impl_upstream!(::bitcoin::TxMerkleNode);
impl_upstream!(::bitcoin::BlockHash);

// Vectors
macro_rules! impl_vec {
    ($type: ty) => {
        impl Encodable for Vec<$type> {
            #[inline]
            fn consensus_encode<S: io::Write>(&self, mut s: S) -> Result<usize, Error> {
                let mut len = 0;
                len += btcenc::VarInt(self.len() as u64).consensus_encode(&mut s)?;
                for c in self.iter() {
                    len += c.consensus_encode(&mut s)?;
                }
                Ok(len)
            }
        }

        impl Decodable for Vec<$type> {
            #[inline]
            fn consensus_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
                let len = btcenc::VarInt::consensus_decode(&mut d)?.0;
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
