// Rust Bitcoin Library
// Written in 2022 by
//     Tobin C. Harding <me@tobin.cc>
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

//! Provides type [`LockTime`] that implements the logic around `nLockTime/OP_CHECKLOCKTIMEVERIFY`.
//!
//! There are two types of lock time: lock-by-blockheight and lock-by-blocktime, distinguished by
//! whether `LockTime < LOCKTIME_THRESHOLD`.
//!

use std::{mem, fmt};
use std::cmp::{PartialOrd, Ordering};
use std::io::{Read, Write};

use crate::encode::{self, Decodable, Encodable};
use crate::parse::impl_parse_str_through_int;

pub use bitcoin_units::locktime::absolute::{Height, Time};
pub use bitcoin_units::locktime::absolute::ConversionError;
pub use bitcoin_units::locktime::absolute::LOCK_TIME_THRESHOLD;

/// A lock time value, representing either a block height or a UNIX timestamp (seconds since epoch).
///
/// Used for transaction lock time (`nLockTime` in Bitcoin Core and [`crate::Transaction::lock_time`]
/// in this library) and also for the argument to opcode `OP_CHECKLOCKTIMEVERIFY`.
///
/// ### Relevant BIPs
///
/// * [BIP-65 OP_CHECKLOCKTIMEVERIFY](https://github.com/bitcoin/bips/blob/master/bip-0065.mediawiki)
/// * [BIP-113 Median time-past as endpoint for lock-time calculations](https://github.com/bitcoin/bips/blob/master/bip-0113.mediawiki)
///
/// # Examples
/// ```
/// # use elements::LockTime;
/// # let n = LockTime::from_consensus(100);          // n OP_CHECKLOCKTIMEVERIFY
/// # let lock_time = LockTime::from_consensus(100);  // nLockTime
/// // To compare lock times there are various `is_satisfied_*` methods, you may also use:
/// let is_satisfied = match (n, lock_time) {
///     (LockTime::Blocks(n), LockTime::Blocks(lock_time)) => n <= lock_time,
///     (LockTime::Seconds(n), LockTime::Seconds(lock_time)) => n <= lock_time,
///     _ => panic!("handle invalid comparison error"),
/// };
/// ```
#[allow(clippy::derive_ord_xor_partial_ord)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LockTime {
    /// A block height lock time value.
    ///
    /// # Examples
    /// ```rust
    /// use elements::LockTime;
    ///
    /// let block: u32 = 741521;
    /// let n = LockTime::from_height(block).expect("valid height");
    /// assert!(n.is_block_height());
    /// assert_eq!(n.to_consensus_u32(), block);
    /// ```
    Blocks(Height),
    /// A UNIX timestamp lock time value.
    ///
    /// # Examples
    /// ```rust
    /// use elements::LockTime;
    ///
    /// let seconds: u32 = 1653195600; // May 22nd, 5am UTC.
    /// let n = LockTime::from_time(seconds).expect("valid time");
    /// assert!(n.is_block_time());
    /// assert_eq!(n.to_consensus_u32(), seconds);
    /// ```
    Seconds(Time),
}

impl LockTime {
    /// If [`crate::Transaction::lock_time`] is set to zero it is ignored, in other words a
    /// transaction with nLocktime==0 is able to be included immediately in any block.
    pub const ZERO: LockTime = LockTime::Blocks(Height::ZERO);

    /// Constructs a `LockTime` from an nLockTime value or the argument to `OP_CHEKCLOCKTIMEVERIFY`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use elements::LockTime;
    /// let n = LockTime::from_consensus(741521); // n OP_CHECKLOCKTIMEVERIFY
    ///
    /// // `from_consensus` roundtrips as expected with `to_consensus_u32`.
    /// let n_lock_time: u32 = 741521;
    /// let lock_time = LockTime::from_consensus(n_lock_time);
    /// assert_eq!(lock_time.to_consensus_u32(), n_lock_time);
    #[inline]
    pub fn from_consensus(n: u32) -> Self {
        if is_block_height(n) {
            Self::Blocks(Height::from_consensus(n).expect("n is valid"))
        } else {
            Self::Seconds(Time::from_consensus(n).expect("n is valid"))
        }
    }

    /// Constructs a `LockTime` from `n`, expecting `n` to be a valid block height.
    ///
    /// See [`LOCK_TIME_THRESHOLD`] for definition of a valid height value.
    ///
    /// # Examples
    /// ```rust
    /// use elements::LockTime;
    /// assert!(LockTime::from_height(741521).is_ok());
    /// assert!(LockTime::from_height(1653195600).is_err());
    /// ```
    #[inline]
    pub fn from_height(n: u32) -> Result<Self, ConversionError> {
        let height = Height::from_consensus(n)?;
        Ok(LockTime::Blocks(height))
    }

    /// Constructs a `LockTime` from `n`, expecting `n` to be a valid block time.
    ///
    /// See [`LOCK_TIME_THRESHOLD`] for definition of a valid time value.
    ///
    /// # Examples
    /// ```rust
    /// use elements::LockTime;
    /// assert!(LockTime::from_time(1653195600).is_ok());
    /// assert!(LockTime::from_time(741521).is_err());
    /// ```
    #[inline]
    pub fn from_time(n: u32) -> Result<Self, ConversionError> {
        let time = Time::from_consensus(n)?;
        Ok(LockTime::Seconds(time))
    }

    /// Returns true if both lock times use the same unit i.e., both height based or both time based.
    #[inline]
    pub fn is_same_unit(&self, other: LockTime) -> bool {
        mem::discriminant(self) == mem::discriminant(&other)
    }

    /// Returns true if this lock time value is a block height.
    #[inline]
    pub fn is_block_height(&self) -> bool {
        match *self {
            LockTime::Blocks(_) => true,
            LockTime::Seconds(_) => false,
        }
    }

    /// Returns true if this lock time value is a block time (UNIX timestamp).
    #[inline]
    pub fn is_block_time(&self) -> bool {
        !self.is_block_height()
    }

    /// Returns true if this timelock constraint is satisfied by the respective `height`/`time`.
    ///
    /// If `self` is a blockheight based lock then it is checked against `height` and if `self` is a
    /// blocktime based lock it is checked against `time`.
    ///
    /// A 'timelock constraint' refers to the `n` from `n OP_CHEKCLOCKTIMEVERIFY`, this constraint
    /// is satisfied if a transaction with nLockTime ([`crate::Transaction::lock_time`]) set to
    /// `height`/`time` is valid.
    ///
    /// # Examples
    /// ```no_run
    /// # use elements::locktime::{LockTime, Height, Time};
    /// // Can be implemented if block chain data is available.
    /// fn get_height() -> Height { todo!("return the current block height") }
    /// fn get_time() -> Time { todo!("return the current block time") }
    ///
    /// let n = LockTime::from_consensus(741521); // `n OP_CHEKCLOCKTIMEVERIFY`.
    /// if n.is_satisfied_by(get_height(), get_time()) {
    ///     // Can create and mine a transaction that satisfies the OP_CLTV timelock constraint.
    /// }
    /// ````
    #[inline]
    pub fn is_satisfied_by(&self, height: Height, time: Time) -> bool {
        match *self {
            LockTime::Blocks(n) => n <= height,
            LockTime::Seconds(n) => n <= time,
        }
    }

    /// Returns the inner `u32` value. This is the value used when creating this `LockTime`
    /// i.e., `n OP_CHECKLOCKTIMEVERIFY` or nLockTime.
    ///
    /// # Warning
    ///
    /// Do not compare values return by this method. The whole point of the `LockTime` type is to
    /// assist in doing correct comparisons. Either use `is_satisfied_by` or use the pattern below:
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use elements::LockTime;
    /// # let n = LockTime::from_consensus(100);          // n OP_CHECKLOCKTIMEVERIFY
    /// # let lock_time = LockTime::from_consensus(100);  // nLockTime
    ///
    /// let is_satisfied = match (n, lock_time) {
    ///     (LockTime::Blocks(n), LockTime::Blocks(lock_time)) => n <= lock_time,
    ///     (LockTime::Seconds(n), LockTime::Seconds(lock_time)) => n <= lock_time,
    ///     _ => panic!("invalid comparison"),
    /// };
    ///
    /// // Or, if you have Rust 1.53 or greater
    /// // let is_satisfied = n.partial_cmp(&lock_time).expect("invalid comparison").is_le();
    /// ```
    #[inline]
    pub fn to_consensus_u32(self) -> u32 {
        match self {
            LockTime::Blocks(ref h) => h.to_consensus_u32(),
            LockTime::Seconds(ref t) => t.to_consensus_u32(),
        }
    }
}

impl_parse_str_through_int!(LockTime, from_consensus);

impl From<Height> for LockTime {
    fn from(h: Height) -> Self {
        LockTime::Blocks(h)
    }
}

impl From<Time> for LockTime {
    fn from(t: Time) -> Self {
        LockTime::Seconds(t)
    }
}

impl PartialOrd for LockTime {
    fn partial_cmp(&self, other: &LockTime) -> Option<Ordering> {
        match (*self, *other) {
            (Self::Blocks(ref a), Self::Blocks(ref b)) => a.partial_cmp(b),
            (Self::Seconds(ref a), Self::Seconds(ref b)) => a.partial_cmp(b),
            (_, _) => None,
        }
    }
}

impl fmt::Display for LockTime {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if f.alternate() {
            match *self {
                Self::Blocks(ref h) => write!(f, "block-height {}", h),
                Self::Seconds(ref t) => write!(f, "block-time {} (seconds since epoch)", t),
            }
        } else {
            match *self {
                Self::Blocks(ref h) => fmt::Display::fmt(h, f),
                Self::Seconds(ref t) => fmt::Display::fmt(t, f),
            }
        }
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for LockTime {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer {
        self.to_consensus_u32().serialize(serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for LockTime {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de> {
        u32::deserialize(deserializer).map(Self::from_consensus)
    }
}

impl Encodable for LockTime {
    #[inline]
    fn consensus_encode<W: Write>(&self, w: W) -> Result<usize, encode::Error> {
        let v = self.to_consensus_u32();
        v.consensus_encode(w)
    }
}

impl Decodable for LockTime {
    #[inline]
    fn consensus_decode<R: Read>(r: R) -> Result<Self, encode::Error> {
        u32::consensus_decode(r).map(LockTime::from_consensus)
    }
}

/// Returns true if `n` is a block height i.e., less than 500,000,000.
fn is_block_height(n: u32) -> bool {
    n < LOCK_TIME_THRESHOLD
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_and_alternate() {
        let n = LockTime::from_consensus(100);
        let s = format!("{}", n);
        assert_eq!(&s, "100");

        let got = format!("{:#}", n);
        assert_eq!(got, "block-height 100");
    }
}
