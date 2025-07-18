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
//

//! # Addresses
//!

use std::convert::TryFrom as _;
use std::error;
use std::fmt;
use std::fmt::Write as _;
use std::str::FromStr;

use bech32::{Bech32, Bech32m, ByteIterExt, Fe32, Fe32IterExt, Hrp};
use crate::blech32::{Blech32, Blech32m};
use crate::hashes::Hash;
use bitcoin::base58;
use bitcoin::PublicKey;
use secp256k1_zkp;
use secp256k1_zkp::Secp256k1;
use secp256k1_zkp::Verification;
#[cfg(feature = "serde")]
use serde;

use crate::schnorr::{TapTweak, TweakedPublicKey, UntweakedPublicKey};
use crate::taproot::TapNodeHash;

use crate::{opcodes, script};
use crate::{PubkeyHash, ScriptHash, WPubkeyHash, WScriptHash};

/// Encoding error
#[derive(Debug, PartialEq)]
pub enum AddressError {
    /// Base58 encoding error
    Base58(base58::Error),
    /// Bech32 encoding error
    Bech32(bech32::primitives::decode::SegwitHrpstringError),
    /// Blech32 encoding error
    Blech32(crate::blech32::decode::SegwitHrpstringError),
    /// Was unable to parse the address.
    InvalidAddress(String),
    /// Script version must be 0 to 16 inclusive
    InvalidWitnessVersion(u8),
    /// The witness program must be between 2 and 40 bytes in length.
    InvalidWitnessProgramLength(usize),
    /// A v0 witness program must be either of length 20 or 32.
    InvalidSegwitV0ProgramLength(usize),
    /// A v1+ witness program must use b(l)ech32m not b(l)ech32
    InvalidWitnessEncoding,
    /// A v0 witness program must use b(l)ech32 not b(l)ech32m
    InvalidSegwitV0Encoding,

    /// An invalid blinding pubkey was encountered.
    InvalidBlindingPubKey(secp256k1_zkp::UpstreamError),

    /// The length (in bytes) of the object was not correct.
    InvalidLength(usize),

    /// Address version byte were not recognized.
    InvalidAddressVersion(u8),
}

impl From<bech32::primitives::decode::SegwitHrpstringError> for AddressError {
    fn from(e: bech32::primitives::decode::SegwitHrpstringError) -> Self {
        AddressError::Bech32(e)
    }
}

impl From<crate::blech32::decode::SegwitHrpstringError> for AddressError {
    fn from(e: crate::blech32::decode::SegwitHrpstringError) -> Self {
        AddressError::Blech32(e)
    }
}

impl fmt::Display for AddressError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            AddressError::Base58(ref e) => write!(f, "base58 error: {}", e),
            AddressError::Bech32(ref e) => write!(f, "bech32 error: {}", e),
            AddressError::Blech32(ref e) => write!(f, "blech32 error: {}", e),
            AddressError::InvalidAddress(ref a) => {
                write!(f, "was unable to parse the address: {}", a)
            }
            AddressError::InvalidWitnessVersion(ref wver) => {
                write!(f, "invalid witness script version: {}", wver)
            }
            AddressError::InvalidWitnessProgramLength(ref len) => {
                write!(
                    f,
                    "the witness program must be between 2 and 40 bytes in length, not {}",
                    len
                )
            }
            AddressError::InvalidSegwitV0ProgramLength(ref len) => {
                write!(
                    f,
                    "a v0 witness program must be length 20 or 32, not {}",
                    len
                )
            }
            AddressError::InvalidBlindingPubKey(ref e) => {
                write!(f, "an invalid blinding pubkey was encountered: {}", e)
            }
            AddressError::InvalidWitnessEncoding => {
                write!(f, "v1+ witness program must use b(l)ech32m not b(l)ech32")
            }
            AddressError::InvalidSegwitV0Encoding => {
                write!(f, "v0 witness program must use b(l)ech32 not b(l)ech32m")
            }
            AddressError::InvalidLength(len) => {
                write!(f, "Address data has invalid length {}", len)
            }
            AddressError::InvalidAddressVersion(v) => {
                write!(f, "address version {} is invalid for this type", v)
            }
        }
    }
}

impl error::Error for AddressError {
    fn cause(&self) -> Option<&dyn error::Error> {
        match *self {
            AddressError::Base58(ref e) => Some(e),
            AddressError::Bech32(ref e) => Some(e),
            AddressError::Blech32(ref e) => Some(e),
            AddressError::InvalidBlindingPubKey(ref e) => Some(e),
            _ => None,
        }
    }
}

#[doc(hidden)]
impl From<base58::Error> for AddressError {
    fn from(e: base58::Error) -> AddressError {
        AddressError::Base58(e)
    }
}

/// The parameters to derive addresses.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AddressParams {
    /// The base58 prefix for p2pkh addresses.
    pub p2pkh_prefix: u8,
    /// The base58 prefix for p2sh addresses.
    pub p2sh_prefix: u8,
    /// The base58 prefix for blinded addresses.
    pub blinded_prefix: u8,
    /// The bech32 HRP for unblinded segwit addresses.
    pub bech_hrp: Hrp,
    /// The bech32 HRP for blinded segwit addresses.
    pub blech_hrp: Hrp,
}

impl AddressParams {
    /// The Liquid network address parameters.
    pub const LIQUID: AddressParams = AddressParams {
        p2pkh_prefix: 57,
        p2sh_prefix: 39,
        blinded_prefix: 12,
        bech_hrp: Hrp::parse_unchecked("ex"),
        blech_hrp: Hrp::parse_unchecked("lq"),
    };

    /// The default Elements network address parameters.
    pub const ELEMENTS: AddressParams = AddressParams {
        p2pkh_prefix: 235,
        p2sh_prefix: 75,
        blinded_prefix: 4,
        bech_hrp: Hrp::parse_unchecked("ert"),
        blech_hrp: Hrp::parse_unchecked("el"),
    };

    /// The default liquid testnet network address parameters.
    pub const LIQUID_TESTNET: AddressParams = AddressParams {
        p2pkh_prefix: 36,
        p2sh_prefix: 19,
        blinded_prefix: 23,
        bech_hrp: Hrp::parse_unchecked("tex"),
        blech_hrp: Hrp::parse_unchecked("tlq"),
    };
}

/// The method used to produce an address
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Payload {
    /// pay-to-pkhash address
    PubkeyHash(PubkeyHash),
    /// P2SH address
    ScriptHash(ScriptHash),
    /// Segwit address
    WitnessProgram {
        /// The segwit version.
        version: Fe32,
        /// The segwit program.
        program: Vec<u8>,
    },
}

/// An Elements address.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Address {
    /// the network
    pub params: &'static AddressParams,
    /// the traditional non-confidential payload
    pub payload: Payload,
    /// the blinding pubkey
    pub blinding_pubkey: Option<secp256k1_zkp::PublicKey>,
}

impl Address {
    /// Inspect if the address is a blinded address.
    pub fn is_blinded(&self) -> bool {
        self.blinding_pubkey.is_some()
    }

    /// Return if the address is for the Liquid network
    pub fn is_liquid(&self) -> bool {
        self.params == &AddressParams::LIQUID
    }

    /// Creates a pay to (compressed) public key hash address from a public key
    /// This is the preferred non-witness type address
    #[inline]
    pub fn p2pkh(
        pk: &PublicKey,
        blinder: Option<secp256k1_zkp::PublicKey>,
        params: &'static AddressParams,
    ) -> Address {
        let mut hash_engine = PubkeyHash::engine();
        pk.write_into(&mut hash_engine)
            .expect("engines don't error");

        Address {
            params,
            payload: Payload::PubkeyHash(PubkeyHash::from_engine(hash_engine)),
            blinding_pubkey: blinder,
        }
    }

    /// Creates a pay to script hash P2SH address from a script
    /// This address type was introduced with BIP16 and is the popular type to implement multi-sig these days.
    #[inline]
    pub fn p2sh(
        script: &script::Script,
        blinder: Option<secp256k1_zkp::PublicKey>,
        params: &'static AddressParams,
    ) -> Address {
        Address {
            params,
            payload: Payload::ScriptHash(ScriptHash::hash(&script[..])),
            blinding_pubkey: blinder,
        }
    }

    /// Create a witness pay to public key address from a public key
    /// This is the native segwit address type for an output redeemable with a single signature
    pub fn p2wpkh(
        pk: &PublicKey,
        blinder: Option<secp256k1_zkp::PublicKey>,
        params: &'static AddressParams,
    ) -> Address {
        let mut hash_engine = WPubkeyHash::engine();
        pk.write_into(&mut hash_engine)
            .expect("engines don't error");

        Address {
            params,
            payload: Payload::WitnessProgram {
                version: Fe32::Q,
                program: WPubkeyHash::from_engine(hash_engine)[..].to_vec(),
            },
            blinding_pubkey: blinder,
        }
    }

    /// Create a pay to script address that embeds a witness pay to public key
    /// This is a segwit address type that looks familiar (as p2sh) to legacy clients
    pub fn p2shwpkh(
        pk: &PublicKey,
        blinder: Option<secp256k1_zkp::PublicKey>,
        params: &'static AddressParams,
    ) -> Address {
        let mut hash_engine = ScriptHash::engine();
        pk.write_into(&mut hash_engine)
            .expect("engines don't error");

        let builder = script::Builder::new()
            .push_int(0)
            .push_slice(&ScriptHash::from_engine(hash_engine)[..]);

        Address {
            params,
            payload: Payload::ScriptHash(ScriptHash::hash(builder.into_script().as_bytes())),
            blinding_pubkey: blinder,
        }
    }

    /// Create a witness pay to script hash address
    pub fn p2wsh(
        script: &script::Script,
        blinder: Option<secp256k1_zkp::PublicKey>,
        params: &'static AddressParams,
    ) -> Address {
        Address {
            params,
            payload: Payload::WitnessProgram {
                version: Fe32::Q,
                program: WScriptHash::hash(&script[..])[..].to_vec(),
            },
            blinding_pubkey: blinder,
        }
    }

    /// Create a pay to script address that embeds a witness pay to script hash address
    /// This is a segwit address type that looks familiar (as p2sh) to legacy clients
    pub fn p2shwsh(
        script: &script::Script,
        blinder: Option<secp256k1_zkp::PublicKey>,
        params: &'static AddressParams,
    ) -> Address {
        let ws = script::Builder::new()
            .push_int(0)
            .push_slice(&WScriptHash::hash(&script[..])[..])
            .into_script();

        Address {
            params,
            payload: Payload::ScriptHash(ScriptHash::hash(&ws[..])),
            blinding_pubkey: blinder,
        }
    }

    /// Creates a pay to taproot address from an untweaked key.
    pub fn p2tr<C: Verification>(
        secp: &Secp256k1<C>,
        internal_key: UntweakedPublicKey,
        merkle_root: Option<TapNodeHash>,
        blinder: Option<secp256k1_zkp::PublicKey>,
        params: &'static AddressParams,
    ) -> Address {
        Address {
            params,
            payload: {
                let (output_key, _parity) = internal_key.tap_tweak(secp, merkle_root);
                Payload::WitnessProgram {
                    version: Fe32::P,
                    program: output_key.into_inner().serialize().to_vec(),
                }
            },
            blinding_pubkey: blinder,
        }
    }

    /// Creates a pay to taproot address from a pre-tweaked output key.
    ///
    /// This method is not recommended for use, [`Address::p2tr()`] should be used where possible.
    pub fn p2tr_tweaked(
        output_key: TweakedPublicKey,
        blinder: Option<secp256k1_zkp::PublicKey>,
        params: &'static AddressParams,
    ) -> Address {
        Address {
            params,
            payload: Payload::WitnessProgram {
                version: Fe32::P,
                program: output_key.into_inner().serialize().to_vec(),
            },
            blinding_pubkey: blinder,
        }
    }

    /// Get an [Address] from an output script.
    pub fn from_script(
        script: &script::Script,
        blinder: Option<secp256k1_zkp::PublicKey>,
        params: &'static AddressParams,
    ) -> Option<Address> {
        Some(Address {
            payload: if script.is_p2pkh() {
                Payload::PubkeyHash(Hash::from_slice(&script.as_bytes()[3..23]).unwrap())
            } else if script.is_p2sh() {
                Payload::ScriptHash(Hash::from_slice(&script.as_bytes()[2..22]).unwrap())
            } else if script.is_v0_p2wpkh() {
                Payload::WitnessProgram {
                    version: Fe32::Q,
                    program: script.as_bytes()[2..22].to_vec(),
                }
            } else if script.is_v0_p2wsh() {
                Payload::WitnessProgram {
                    version: Fe32::Q,
                    program: script.as_bytes()[2..34].to_vec(),
                }
            } else if script.is_v1plus_p2witprog() {
                Payload::WitnessProgram {
                    version: Fe32::try_from(script.as_bytes()[0] - 0x50).expect("0<32"),
                    program: script.as_bytes()[2..].to_vec(),
                }
            } else {
                return None;
            },
            blinding_pubkey: blinder,
            params,
        })
    }

    /// Generates a script pubkey spending to this address
    pub fn script_pubkey(&self) -> script::Script {
        match self.payload {
            Payload::PubkeyHash(ref hash) => script::Builder::new()
                .push_opcode(opcodes::all::OP_DUP)
                .push_opcode(opcodes::all::OP_HASH160)
                .push_slice(&hash[..])
                .push_opcode(opcodes::all::OP_EQUALVERIFY)
                .push_opcode(opcodes::all::OP_CHECKSIG),
            Payload::ScriptHash(ref hash) => script::Builder::new()
                .push_opcode(opcodes::all::OP_HASH160)
                .push_slice(&hash[..])
                .push_opcode(opcodes::all::OP_EQUAL),
            Payload::WitnessProgram {
                version: witver,
                program: ref witprog,
            } => script::Builder::new()
                .push_int(i64::from(witver.to_u8()))
                .push_slice(witprog),
        }
        .into_script()
    }

    /// Convert this address to an unconfidential address.
    #[must_use]
    pub fn to_unconfidential(&self) -> Address {
        Address {
            params: self.params,
            payload: self.payload.clone(),
            blinding_pubkey: None,
        }
    }

    /// Convert this address to a confidential address with the given blinding pubkey.
    #[must_use]
    pub fn to_confidential(&self, blinding_pubkey: secp256k1_zkp::PublicKey) -> Address {
        Address {
            params: self.params,
            payload: self.payload.clone(),
            blinding_pubkey: Some(blinding_pubkey),
        }
    }

    fn from_bech32(
        s: &str,
        blinded: bool,
        params: &'static AddressParams,
    ) -> Result<Address, AddressError> {
        let (version, data): (Fe32, Vec<u8>) = if blinded {
            let hs = crate::blech32::decode::SegwitHrpstring::new(s)?;
            (hs.witness_version(), hs.byte_iter().collect())
        } else {
            let hs = bech32::primitives::decode::SegwitHrpstring::new(s)?;
            (hs.witness_version(), hs.byte_iter().collect())
        };

        let (blinding_pubkey, program) = match blinded {
            true => (
                Some(
                    secp256k1_zkp::PublicKey::from_slice(&data[..33])
                        .map_err(AddressError::InvalidBlindingPubKey)?,
                ),
                data[33..].to_vec(),
            ),
            false => (None, data),
        };

        Ok(Address {
            params,
            payload: Payload::WitnessProgram { version, program },
            blinding_pubkey,
        })
    }

    // data.len() should be >= 1 when this method is called
    fn from_base58(data: &[u8], params: &'static AddressParams) -> Result<Address, AddressError> {
        // When unblinded, the structure is:
        // <1: regular prefix> <20: hash160>
        // When blinded, the structure is:
        // <1: blinding prefix> <1: regular prefix> <33: blinding pubkey> <20: hash160>

        let blinded = data[0] == params.blinded_prefix;
        let prefix = match (blinded, data.len()) {
            (true, 55) => data[1],
            (false, 21) => data[0],
            (_, len) => return Err(AddressError::InvalidLength(len)),
        };

        let (blinding_pubkey, payload_data) = match blinded {
            true => (
                Some(
                    secp256k1_zkp::PublicKey::from_slice(&data[2..35])
                        .map_err(AddressError::InvalidBlindingPubKey)?,
                ),
                &data[35..],
            ),
            false => (None, &data[1..]),
        };

        let payload = if prefix == params.p2pkh_prefix {
            Payload::PubkeyHash(PubkeyHash::from_slice(payload_data).unwrap())
        } else if prefix == params.p2sh_prefix {
            Payload::ScriptHash(ScriptHash::from_slice(payload_data).unwrap())
        } else {
            return Err(AddressError::InvalidAddressVersion(prefix));
        };

        Ok(Address {
            params,
            payload,
            blinding_pubkey,
        })
    }

    /// Parse the address using the given parameters.
    /// When using the built-in parameters, you can use [`FromStr`].
    pub fn parse_with_params(
        s: &str,
        params: &'static AddressParams,
    ) -> Result<Address, AddressError> {
        // Bech32.
        let prefix = find_prefix(s);
        let b32_ex = match_prefix(prefix, params.bech_hrp);
        let b32_bl = match_prefix(prefix, params.blech_hrp);
        if b32_ex || b32_bl {
            return Address::from_bech32(s, b32_bl, params);
        }

        // Base58.
        if s.len() > 150 {
            return Err(AddressError::InvalidLength(s.len() * 11 / 15));
        }
        let data = base58::decode_check(s)?;
        Address::from_base58(&data, params)
    }
}

impl fmt::Display for Address {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        match self.payload {
            Payload::PubkeyHash(ref hash) => {
                if let Some(ref blinder) = self.blinding_pubkey {
                    let mut prefixed = [0; 55]; // 1 + 1 + 33 + 20
                    prefixed[0] = self.params.blinded_prefix;
                    prefixed[1] = self.params.p2pkh_prefix;
                    prefixed[2..35].copy_from_slice(&blinder.serialize());
                    prefixed[35..].copy_from_slice(&hash[..]);
                    base58::encode_check_to_fmt(fmt, &prefixed[..])
                } else {
                    let mut prefixed = [0; 21];
                    prefixed[0] = self.params.p2pkh_prefix;
                    prefixed[1..].copy_from_slice(&hash[..]);
                    base58::encode_check_to_fmt(fmt, &prefixed[..])
                }
            }
            Payload::ScriptHash(ref hash) => {
                if let Some(ref blinder) = self.blinding_pubkey {
                    let mut prefixed = [0; 55]; // 1 + 1 + 33 + 20
                    prefixed[0] = self.params.blinded_prefix;
                    prefixed[1] = self.params.p2sh_prefix;
                    prefixed[2..35].copy_from_slice(&blinder.serialize());
                    prefixed[35..].copy_from_slice(&hash[..]);
                    base58::encode_check_to_fmt(fmt, &prefixed[..])
                } else {
                    let mut prefixed = [0; 21];
                    prefixed[0] = self.params.p2sh_prefix;
                    prefixed[1..].copy_from_slice(&hash[..]);
                    base58::encode_check_to_fmt(fmt, &prefixed[..])
                }
            }
            Payload::WitnessProgram {
                version: witver,
                program: ref witprog,
            } => {
                let hrp = match self.blinding_pubkey.is_some() {
                    true => self.params.blech_hrp,
                    false => self.params.bech_hrp,
                };

                // FIXME: surely we can fix this logic to not be so repetitive.
                if self.is_blinded() {
                    if let Some(ref blinder) = self.blinding_pubkey {
                        let byte_iter = IntoIterator::into_iter(blinder.serialize())
                            .chain(witprog.iter().copied());
                        let fe_iter = byte_iter.bytes_to_fes();
                        if witver.to_u8() == 0 {
                            for c in fe_iter
                                .with_checksum::<Blech32>(&hrp)
                                .with_witness_version(witver)
                                .chars()
                            {
                                fmt.write_char(c)?;
                            }
                        } else {
                            for c in fe_iter
                                .with_checksum::<Blech32m>(&hrp)
                                .with_witness_version(witver)
                                .chars()
                            {
                                fmt.write_char(c)?;
                            }
                        }
                        return Ok(());
                    }
                }

                let byte_iter = witprog.iter().copied();
                let fe_iter = byte_iter.bytes_to_fes();
                if witver.to_u8() == 0 {
                    for c in fe_iter
                        .with_checksum::<Bech32>(&hrp)
                        .with_witness_version(witver)
                        .chars()
                    {
                        fmt.write_char(c)?;
                    }
                } else {
                    for c in fe_iter
                        .with_checksum::<Bech32m>(&hrp)
                        .with_witness_version(witver)
                        .chars()
                    {
                        fmt.write_char(c)?;
                    }
                }
                Ok(())
            }
        }
    }
}

impl fmt::Debug for Address {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(self, fmt)
    }
}

/// Extract the bech32 prefix.
/// Returns the same slice when no prefix is found.
fn find_prefix(bech32: &str) -> &str {
    // Split at the last occurrence of the separator character '1'.
    match bech32.rfind('1') {
        None => bech32,
        Some(sep) => bech32.split_at(sep).0,
    }
}

/// Checks if both prefixes match, regardless of case.
/// The first prefix can be mixed case, but the second one is expected in
/// lower case.
fn match_prefix(prefix_mixed: &str, target: Hrp) -> bool {
    target.len() == prefix_mixed.len() && target
        .lowercase_char_iter()
        .zip(prefix_mixed.chars())
        .all(|(char_lower, char_mixed)| char_lower == char_mixed.to_ascii_lowercase())
}

impl FromStr for Address {
    type Err = AddressError;

    fn from_str(s: &str) -> Result<Address, AddressError> {
        // shorthands
        let liq = &AddressParams::LIQUID;
        let ele = &AddressParams::ELEMENTS;
        let liq_test = &AddressParams::LIQUID_TESTNET;

        let net_arr = [liq, ele, liq_test];

        let prefix = find_prefix(s);
        for net in &net_arr {
            // Bech32.
            if match_prefix(prefix, net.bech_hrp) {
                return Address::from_bech32(s, false, net);
            }
            if match_prefix(prefix, net.blech_hrp) {
                return Address::from_bech32(s, true, net);
            }
        }

        // Base58.
        if s.len() > 150 {
            return Err(AddressError::InvalidLength(s.len() * 11 / 15));
        }
        let data = base58::decode_check(s)?;
        if data.is_empty() {
            return Err(AddressError::InvalidLength(data.len()));
        }

        let p = data[0];
        for net in &net_arr {
            if p == net.p2pkh_prefix || p == net.p2sh_prefix || p == net.blinded_prefix {
                return Address::from_base58(&data, net);
            }
        }

        Err(AddressError::InvalidAddress(s.to_owned()))
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Address {
    #[inline]
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use std::fmt::Formatter;

        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = Address;

            fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
                formatter.write_str("a Bitcoin address")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Address::from_str(v).map_err(E::custom)
            }

            fn visit_borrowed_str<E>(self, v: &'de str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                self.visit_str(v)
            }

            fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                self.visit_str(&v)
            }
        }

        deserializer.deserialize_str(Visitor)
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for Address {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::Script;
    use bitcoin::key;
    use secp256k1_zkp::{PublicKey, Secp256k1};
    #[cfg(feature = "serde")]
    use serde_json;

    fn roundtrips(addr: &Address) {
        assert_eq!(
            Address::from_str(&addr.to_string()).ok().as_ref(),
            Some(addr),
            "string round-trip failed for {}",
            addr,
        );
        assert_eq!(
            Address::from_script(&addr.script_pubkey(), addr.blinding_pubkey, addr.params).as_ref(),
            Some(addr),
            "script round-trip failed for {}",
            addr,
        );
        #[cfg(feature = "serde")]
        assert_eq!(
            serde_json::from_value::<Address>(serde_json::to_value(addr).unwrap())
                .ok()
                .as_ref(),
            Some(addr)
        );
    }

    #[test]
    fn regression_188() {
        // Tests that the `tlq` prefix was not accidentally changed, e.g. to `tlg` :).
        let addr = Address::from_str("tlq1qq2xvpcvfup5j8zscjq05u2wxxjcyewk7979f3mmz5l7uw5pqmx6xf5xy50hsn6vhkm5euwt72x878eq6zxx2z58hd7zrsg9qn").unwrap();
        roundtrips(&addr);
    }

    #[test]
    fn exhaustive() {
        let blinder_hex = "0218845781f631c48f1c9709e23092067d06837f30aa0cd0544ac887fe91ddd166";
        let blinder = PublicKey::from_str(blinder_hex).unwrap();
        let sk_wif = "cVt4o7BGAig1UXywgGSmARhxMdzP5qvQsxKkSsc1XEkw3tDTQFpy";
        let sk = key::PrivateKey::from_wif(sk_wif).unwrap();
        let pk = sk.public_key(&Secp256k1::new());
        let script: Script = vec![1u8, 2, 42, 255, 196].into();

        let vectors = [
            /* #00 */ Address::p2pkh(&pk, None, &AddressParams::LIQUID),
            /* #01 */ Address::p2pkh(&pk, None, &AddressParams::ELEMENTS),
            /* #02 */ Address::p2pkh(&pk, Some(blinder), &AddressParams::LIQUID),
            /* #03 */ Address::p2pkh(&pk, Some(blinder), &AddressParams::ELEMENTS),
            /* #04 */ Address::p2sh(&script, None, &AddressParams::LIQUID),
            /* #05 */ Address::p2sh(&script, None, &AddressParams::ELEMENTS),
            /* #06 */ Address::p2sh(&script, Some(blinder), &AddressParams::LIQUID),
            /* #07 */
            Address::p2sh(&script, Some(blinder), &AddressParams::ELEMENTS),
            /* #08 */ Address::p2wpkh(&pk, None, &AddressParams::LIQUID),
            /* #09 */ Address::p2wpkh(&pk, None, &AddressParams::ELEMENTS),
            /* #10 */ Address::p2wpkh(&pk, Some(blinder), &AddressParams::LIQUID),
            /* #11 */ Address::p2wpkh(&pk, Some(blinder), &AddressParams::ELEMENTS),
            /* #12 */ Address::p2shwpkh(&pk, None, &AddressParams::LIQUID),
            /* #13 */ Address::p2shwpkh(&pk, None, &AddressParams::ELEMENTS),
            /* #14 */ Address::p2shwpkh(&pk, Some(blinder), &AddressParams::LIQUID),
            /* #15 */
            Address::p2shwpkh(&pk, Some(blinder), &AddressParams::ELEMENTS),
            /* #16 */ Address::p2wsh(&script, None, &AddressParams::LIQUID),
            /* #17 */ Address::p2wsh(&script, None, &AddressParams::ELEMENTS),
            /* #18 */ Address::p2wsh(&script, Some(blinder), &AddressParams::LIQUID),
            /* #19 */
            Address::p2wsh(&script, Some(blinder), &AddressParams::ELEMENTS),
            /* #20 */ Address::p2shwsh(&script, None, &AddressParams::LIQUID),
            /* #21 */ Address::p2shwsh(&script, None, &AddressParams::ELEMENTS),
            /* #22 */
            Address::p2shwsh(&script, Some(blinder), &AddressParams::LIQUID),
            /* #23 */
            Address::p2shwsh(&script, Some(blinder), &AddressParams::ELEMENTS),
        ];

        for addr in &vectors {
            roundtrips(addr);
        }
    }

    #[test]
    fn test_actuals() {
        // vectors: (address, blinded?, params)
        let addresses = [
            // Elements
            ("2dxmEBXc2qMYcLSKiDBxdEePY3Ytixmnh4E", false, AddressParams::ELEMENTS),
            ("CTEo6VKG8xbe7HnfVW9mQoWTgtgeRSPktwTLbELzGw5tV8Ngzu53EBiasFMQKVbWmKWWTAdN5AUf4M6Y", true, AddressParams::ELEMENTS),
            ("ert1qwhh2n5qypypm0eufahm2pvj8raj9zq5c27cysu", false, AddressParams::ELEMENTS),
            ("el1qq0umk3pez693jrrlxz9ndlkuwne93gdu9g83mhhzuyf46e3mdzfpva0w48gqgzgrklncnm0k5zeyw8my2ypfsmxh4xcjh2rse", true, AddressParams::ELEMENTS),
            // Liquid
            ("GqiQRsPEyJLAsEBFB5R34KHuqxDNkG3zur", false, AddressParams::LIQUID),
            ("VJLDwMVWXg8RKq4mRe3YFNTAEykVN6V8x5MRUKKoC3nfRnbpnZeiG3jygMC6A4Gw967GY5EotJ4Rau2F", true, AddressParams::LIQUID),
            ("ex1q7gkeyjut0mrxc3j0kjlt7rmcnvsh0gt45d3fud", false, AddressParams::LIQUID),
            ("lq1qqf8er278e6nyvuwtgf39e6ewvdcnjupn9a86rzpx655y5lhkt0walu3djf9cklkxd3ryld97hu8h3xepw7sh2rlu7q45dcew5", true, AddressParams::LIQUID),
        ];

        for &(a, blinded, ref params) in &addresses {
            let result = a.parse();
            assert!(
                result.is_ok(),
                "vector: {}, err: \"{}\"",
                a,
                result.unwrap_err()
            );
            let addr: Address = result.unwrap();
            assert_eq!(a, &addr.to_string(), "vector: {}", a);
            assert_eq!(blinded, addr.is_blinded());
            assert_eq!(params, addr.params);
            roundtrips(&addr);
        }
    }

    #[test]
    fn test_blech32_vectors() {
        // taken from Elements test/functional/rpc_invalid_address_message.py
        let address: Result<Address, _> = "el1qq0umk3pez693jrrlxz9ndlkuwne93gdu9g83mhhzuyf46e3mdzfpva0w48gqgzgrklncnm0k5zeyw8my2ypfsmxh4xcjh2rse".parse();
        assert!(address.is_ok());

        let address: Result<Address, _> = "el1pq0umk3pez693jrrlxz9ndlkuwne93gdu9g83mhhzuyf46e3mdzfpva0w48gqgzgrklncnm0k5zeyw8my2ypfsxguu9nrdg2pc".parse();
        assert_eq!(
            address.err().unwrap().to_string(),
            "blech32 error: invalid checksum", // is valid blech32, but should be blech32m
        );

        let address: Result<Address, _> = "el1qq0umk3pez693jrrlxz9ndlkuwne93gdu9g83mhhzuyf46e3mdzfpva0w48gqgzgrklncnm0k5zeyw8my2ypfsnnmzrstzt7de".parse();
        assert_eq!(
            address.err().unwrap().to_string(),
            "blech32 error: invalid checksum", // is valid blech32m, but should be blech32
        );

        let address: Result<Address, _> =
            "ert130xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqqu2tys".parse();
        assert_eq!(
            address.err().unwrap().to_string(),
            "bech32 error: invalid segwit witness version: 17 (bech32 character: '3')",
        );

        let address: Result<Address, _> = "el1pq0umk3pez693jrrlxz9ndlkuwne93gdu9g83mhhzuyf46e3mdzfpva0w48gqgzgrklncnm0k5zeyw8my2ypfsqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqpe9jfn0gypaj".parse();
        assert_eq!(
            address.err().unwrap().to_string(),
            "blech32 error: invalid witness length",
        );

        // "invalid prefix" gives a weird error message because we do
        // a dumb prefix check before even attempting bech32 decoding
        let address: Result<Address, _> = "rrr1qq0umk3pez693jrrlxz9ndlkuwne93gdu9g83mhhzuyf46e3mdzfpva0w48gqgzgrklncnm0k5zeyw8my2ypfs2d9rp7meq4kg".parse();
        assert_eq!(address.err().unwrap().to_string(), "base58 error: decode",);
    }

    #[test]
    fn test_fixed_addresses() {
        let pk = bitcoin::PublicKey::from_str(
            "0212bf0ea45b733dfde8ecb5e896306c4165c666c99fc5d1ab887f71393a975cea",
        )
        .unwrap();
        let script = Script::default();
        let secp = Secp256k1::verification_only();
        let internal_key = UntweakedPublicKey::from_str(
            "93c7378d96518a75448821c4f7c8f4bae7ce60f804d03d1f0628dd5dd0f5de51",
        )
        .unwrap();
        let tap_node_hash = TapNodeHash::all_zeros();

        let mut expected = IntoIterator::into_iter([
            "2dszRCFv8Ub4ytKo1Q1vXXGgSx7mekNDwSJ",
            "XToMocNywBYNSiXUe5xvoa2naAps9Ek1hq",
            "ert1qew0l0emv7449u7hqgc8utzdzryhse79yhq2sxv",
            "XZF6k8S6eoVxXMB4NpWjh2s7LjQUP7pw2R",
            "ert1quwcvgs5clswpfxhm7nyfjmaeysn6us0yvjdexn9yjkv3k7zjhp2szaqlpq",
            "ert1p8qs0qcn25l2y6yvtc5t95rr8w9pndcj64c8rkutnvkcvdp6gh02q2cqvj9",
            "ert1pxrrurkg8j8pve97lffvv2y67cf7ux478h077c87qacqzhue7390sqkjp06",
            "CTEkC79sYAvWNcxd8iTYnYo226FqRBbzBcMppq7L2dA8jVXJWoo1kKWB3UBLY6gBjiXf87ibs8c6mQyZ",
            "AzpjUhKMLJi9y2oLt3ZdM3BP9nHdLPJfGMVxRBaRc2gDpeNqPMVpShTszJW7bX42vT2KoejYy8GtbcxH",
            "el1qqgft7r4ytdenml0gaj67393sd3qkt3nxex0ut5dt3plhzwf6jaww4jul7lnkeat2teawq3s0cky6yxf0pnu2gmz9ej9kyq5yc",
            "AzpjUhKMLJi9y2oLt3ZdM3BP9nHdLPJfGMVxRBaRc2gDpeNvq6SLVpBVwtakF6nmUFundyW7YjUdVkpr",
            "el1qqgft7r4ytdenml0gaj67393sd3qkt3nxex0ut5dt3plhzwf6jaww4casc3pf3lquzjd0haxgn9hmjfp84eq7geymjdx2f9verdu99wz4h79u87cnxdzq",
            "el1pqgft7r4ytdenml0gaj67393sd3qkt3nxex0ut5dt3plhzwf6jaww5wpq7p3x4f75f5gch3gktgxxwu2rxm394tsw8dchxedsc6r53w75cj24fq2u2ls5",
            "el1pqgft7r4ytdenml0gaj67393sd3qkt3nxex0ut5dt3plhzwf6jaww5vx8c8vs0ywzejta7jjcc5f4asnacdtu0wlaas0upmsq90enaz2lhjd0k0q7qn4h",
            "QFq3vvrr6Ub2KAyb3LdoCxEQvKukB6nN9i",
            "GydeMhecNgrq17WMkyyTM4ETv1YubMVtLN",
            "ex1qew0l0emv7449u7hqgc8utzdzryhse79ydjqgek",
            "H55PJDhj6JpR5k9wViXGEX4nga8WmhXtnD",
            "ex1quwcvgs5clswpfxhm7nyfjmaeysn6us0yvjdexn9yjkv3k7zjhp2s4sla8h",
            "ex1p8qs0qcn25l2y6yvtc5t95rr8w9pndcj64c8rkutnvkcvdp6gh02qa4lw5j",
            "ex1pxrrurkg8j8pve97lffvv2y67cf7ux478h077c87qacqzhue7390shmdrfd",
            "VTptY6cqJbusNpL5xvo8VL38nLX9PGDjfYQfqhu9EaA7FtuidkWyQzMHY9jzZrpBcCXT437vM6V4N8kh",
            "VJL64Ep3rcngP4cScRme15q9i8MCNiuqWeiG3YbtduUidVyorg7nRsgmmF714QtH3sNpWB2CqsVVciQh",
            "lq1qqgft7r4ytdenml0gaj67393sd3qkt3nxex0ut5dt3plhzwf6jaww4jul7lnkeat2teawq3s0cky6yxf0pnu2gs2923tg58xcz",
            "VJL64Ep3rcngP4cScRme15q9i8MCNiuqWeiG3YbtduUidVyuJR4JUzQPiqBdhzd1bgGHLVnmRUjfHc68",
            "lq1qqgft7r4ytdenml0gaj67393sd3qkt3nxex0ut5dt3plhzwf6jaww4casc3pf3lquzjd0haxgn9hmjfp84eq7geymjdx2f9verdu99wz47jmkmgmr9a4s",
            "lq1pqgft7r4ytdenml0gaj67393sd3qkt3nxex0ut5dt3plhzwf6jaww5wpq7p3x4f75f5gch3gktgxxwu2rxm394tsw8dchxedsc6r53w75375l4kfvf08y",
            "lq1pqgft7r4ytdenml0gaj67393sd3qkt3nxex0ut5dt3plhzwf6jaww5vx8c8vs0ywzejta7jjcc5f4asnacdtu0wlaas0upmsq90enaz2l77n92erwrrz8",
            "FojPFeboBgrd953mXXe72KWthjVwHWozqN",
            "8vsafXgrB5bJeSidGbK5eYnjKvQ3RiB4BB",
            "tex1qew0l0emv7449u7hqgc8utzdzryhse79yh5jp9a",
            "92KKc3jxthYtj5ND1KrtY1d46UyeWV6XbP",
            "tex1quwcvgs5clswpfxhm7nyfjmaeysn6us0yvjdexn9yjkv3k7zjhp2s5fd6kc",
            "tex1p8qs0qcn25l2y6yvtc5t95rr8w9pndcj64c8rkutnvkcvdp6gh02quvdf9a",
            "tex1pxrrurkg8j8pve97lffvv2y67cf7ux478h077c87qacqzhue7390skzlycz",
            "vtS71VhcpFt978sha5d1L2gCzp3UL5kXacRpb3N4GTW5MwvBzz5HwxYyB8Pns4yM2dd2osmQkHSkp88u",
            "vjTuLJ76nGi8PUopBVmGK8bLKPfBpaBWf6wKfn8z9Vdz6ubVhpvmMr6TK2RcqAYiujN1g1uwg8kejrM3",
            "tlq1qqgft7r4ytdenml0gaj67393sd3qkt3nxex0ut5dt3plhzwf6jaww4jul7lnkeat2teawq3s0cky6yxf0pnu2gq8g2kuxfj8ft",
            "vjTuLJ76nGi8PUopBVmGK8bLKPfBpaBWf6wKfn8z9Vdz6ubb9ZsHQxp5GcWFUkHTTYFUWLgWFk1DN5Fe",
            "tlq1qqgft7r4ytdenml0gaj67393sd3qkt3nxex0ut5dt3plhzwf6jaww4casc3pf3lquzjd0haxgn9hmjfp84eq7geymjdx2f9verdu99wz4e6vcdfcyp5m8",
            "tlq1pqgft7r4ytdenml0gaj67393sd3qkt3nxex0ut5dt3plhzwf6jaww5wpq7p3x4f75f5gch3gktgxxwu2rxm394tsw8dchxedsc6r53w75kkr3rh2tdxfn",
            "tlq1pqgft7r4ytdenml0gaj67393sd3qkt3nxex0ut5dt3plhzwf6jaww5vx8c8vs0ywzejta7jjcc5f4asnacdtu0wlaas0upmsq90enaz2lekytucqf82vs",
        ]);

        for params in [
            &AddressParams::ELEMENTS,
            &AddressParams::LIQUID,
            &AddressParams::LIQUID_TESTNET,
        ] {
            for blinder in [None, Some(pk.inner)] {
                let addr = Address::p2pkh(&pk, blinder, params);
                assert_eq!(&addr.to_string(), expected.next().unwrap());

                let addr = Address::p2sh(&script, blinder, params);
                assert_eq!(&addr.to_string(), expected.next().unwrap());

                let addr = Address::p2wpkh(&pk, blinder, params);
                assert_eq!(&addr.to_string(), expected.next().unwrap());

                let addr = Address::p2shwpkh(&pk, blinder, params);
                assert_eq!(&addr.to_string(), expected.next().unwrap());

                let addr = Address::p2wsh(&script, blinder, params);
                assert_eq!(&addr.to_string(), expected.next().unwrap());

                let addr = Address::p2tr(&secp, internal_key, None, blinder, params);
                assert_eq!(&addr.to_string(), expected.next().unwrap());

                let addr = Address::p2tr(&secp, internal_key, Some(tap_node_hash), blinder, params);
                assert_eq!(&addr.to_string(), expected.next().unwrap());
            }
        }
    }
}
