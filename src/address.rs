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

use std::error;
use std::fmt;
use std::str::FromStr;

// AsciiExt is needed until for Rust 1.26 but not for newer versions
#[allow(unused_imports, deprecated)]
use std::ascii::AsciiExt;

use bitcoin::bech32::{self, u5, FromBase32, ToBase32};
use bitcoin::blockdata::{opcodes, script};
use bitcoin::util::base58;
use bitcoin::PublicKey;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1;
#[cfg(feature = "serde")]
use serde;

use blech32;

use {PubkeyHash, ScriptHash, WPubkeyHash, WScriptHash};

/// Encoding error
#[derive(Debug, PartialEq)]
pub enum AddressError {
    /// Base58 encoding error
    Base58(base58::Error),
    /// Bech32 encoding error
    Bech32(bech32::Error),
    /// Blech32 encoding error
    Blech32(bech32::Error),
    /// Was unable to parse the address.
    InvalidAddress(String),
    /// Script version must be 0 to 16 inclusive
    InvalidWitnessVersion,
    /// Unsupported witness version
    UnsupportedWitnessVersion(u8),
    /// An invalid blinding pubkey was encountered.
    InvalidBlindingPubKey(secp256k1::Error),
    /// Given the program version, the length is invalid
    ///
    /// Version 0 scripts must be either 20 or 32 bytes
    InvalidWitnessProgramLength,
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
            AddressError::UnsupportedWitnessVersion(ref wver) => {
                write!(f, "unsupported witness version: {}", wver)
            }
            AddressError::InvalidBlindingPubKey(ref e) => {
                write!(f, "an invalid blinding pubkey was encountered: {}", e)
            }
            AddressError::InvalidWitnessProgramLength => {
                write!(f, "program length incompatible with version")
            }
            AddressError::InvalidWitnessVersion => write!(f, "invalid witness script version"),
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
    pub bech_hrp: &'static str,
    /// The bech32 HRP for blinded segwit addresses.
    pub blech_hrp: &'static str,
}

impl AddressParams {
    /// The Liquid network address parameters.
    pub const LIQUID: AddressParams = AddressParams {
        p2pkh_prefix: 57,
        p2sh_prefix: 39,
        blinded_prefix: 12,
        bech_hrp: "ex",
        blech_hrp: "lq",
    };

    /// The default Elements network address parameters.
    pub const ELEMENTS: AddressParams = AddressParams {
        p2pkh_prefix: 235,
        p2sh_prefix: 75,
        blinded_prefix: 4,
        bech_hrp: "ert",
        blech_hrp: "el",
    };
}

/// The method used to produce an address
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Payload {
    /// pay-to-pkhash address
    PubkeyHash(PubkeyHash),
    /// P2SH address
    ScriptHash(ScriptHash),
    /// Segwit address
    WitnessProgram {
        /// The segwit version.
        version: u5,
        /// The segwit program.
        program: Vec<u8>,
    },
}

/// An Elements address.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Address {
    /// the network
    pub params: &'static AddressParams,
    /// the traditional non-confidential payload
    pub payload: Payload,
    /// the blinding pubkey
    pub blinding_pubkey: Option<secp256k1::PublicKey>,
}

impl Address {
    /// Inspect if the address is a blinded address.
    pub fn is_blinded(&self) -> bool {
        self.blinding_pubkey.is_some()
    }

    /// Creates a pay to (compressed) public key hash address from a public key
    /// This is the preferred non-witness type address
    #[inline]
    pub fn p2pkh(
        pk: &PublicKey,
        blinder: Option<secp256k1::PublicKey>,
        params: &'static AddressParams,
    ) -> Address {
        let mut hash_engine = PubkeyHash::engine();
        pk.write_into(&mut hash_engine);

        Address {
            params: params,
            payload: Payload::PubkeyHash(PubkeyHash::from_engine(hash_engine)),
            blinding_pubkey: blinder,
        }
    }

    /// Creates a pay to script hash P2SH address from a script
    /// This address type was introduced with BIP16 and is the popular type to implement multi-sig these days.
    #[inline]
    pub fn p2sh(
        script: &script::Script,
        blinder: Option<secp256k1::PublicKey>,
        params: &'static AddressParams,
    ) -> Address {
        Address {
            params: params,
            payload: Payload::ScriptHash(ScriptHash::hash(&script[..])),
            blinding_pubkey: blinder,
        }
    }

    /// Create a witness pay to public key address from a public key
    /// This is the native segwit address type for an output redeemable with a single signature
    pub fn p2wpkh(
        pk: &PublicKey,
        blinder: Option<secp256k1::PublicKey>,
        params: &'static AddressParams,
    ) -> Address {
        let mut hash_engine = WPubkeyHash::engine();
        pk.write_into(&mut hash_engine);

        Address {
            params: params,
            payload: Payload::WitnessProgram {
                version: u5::try_from_u8(0).expect("0<32"),
                program: WPubkeyHash::from_engine(hash_engine)[..].to_vec(),
            },
            blinding_pubkey: blinder,
        }
    }

    /// Create a pay to script address that embeds a witness pay to public key
    /// This is a segwit address type that looks familiar (as p2sh) to legacy clients
    pub fn p2shwpkh(
        pk: &PublicKey,
        blinder: Option<secp256k1::PublicKey>,
        params: &'static AddressParams,
    ) -> Address {
        let mut hash_engine = ScriptHash::engine();
        pk.write_into(&mut hash_engine);

        let builder = script::Builder::new()
            .push_int(0)
            .push_slice(&ScriptHash::from_engine(hash_engine)[..]);

        Address {
            params: params,
            payload: Payload::ScriptHash(ScriptHash::hash(builder.into_script().as_bytes())),
            blinding_pubkey: blinder,
        }
    }

    /// Create a witness pay to script hash address
    pub fn p2wsh(
        script: &script::Script,
        blinder: Option<secp256k1::PublicKey>,
        params: &'static AddressParams,
    ) -> Address {
        Address {
            params: params,
            payload: Payload::WitnessProgram {
                version: u5::try_from_u8(0).expect("0<32"),
                program: WScriptHash::hash(&script[..])[..].to_vec(),
            },
            blinding_pubkey: blinder,
        }
    }

    /// Create a pay to script address that embeds a witness pay to script hash address
    /// This is a segwit address type that looks familiar (as p2sh) to legacy clients
    pub fn p2shwsh(
        script: &script::Script,
        blinder: Option<secp256k1::PublicKey>,
        params: &'static AddressParams,
    ) -> Address {
        let ws = script::Builder::new()
            .push_int(0)
            .push_slice(&WScriptHash::hash(&script[..])[..])
            .into_script();

        Address {
            params: params,
            payload: Payload::ScriptHash(ScriptHash::hash(&ws[..])),
            blinding_pubkey: blinder,
        }
    }

    /// Get an [Address] from an output script.
    pub fn from_script(
        script: &script::Script,
        blinder: Option<secp256k1::PublicKey>,
        params: &'static AddressParams,
    ) -> Option<Address> {
        Some(Address {
            payload: if script.is_p2pkh() {
                Payload::PubkeyHash(Hash::from_slice(&script.as_bytes()[3..23]).unwrap())
            } else if script.is_p2sh() {
                Payload::ScriptHash(Hash::from_slice(&script.as_bytes()[2..22]).unwrap())
            } else if script.is_v0_p2wpkh() {
                Payload::WitnessProgram {
                    version: u5::try_from_u8(0).expect("0<32"),
                    program: script.as_bytes()[2..22].to_vec(),
                }
            } else if script.is_v0_p2wsh() {
                Payload::WitnessProgram {
                    version: u5::try_from_u8(0).expect("0<32"),
                    program: script.as_bytes()[2..34].to_vec(),
                }
            } else {
                return None;
            },
            blinding_pubkey: blinder,
            params: params,
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
            } => script::Builder::new().push_int(witver.to_u8() as i64).push_slice(&witprog),
        }
        .into_script()
    }

    /// Convert this address to an unconfidential address.
    pub fn to_unconfidential(&self) -> Address {
        Address {
            params: self.params,
            payload: self.payload.clone(),
            blinding_pubkey: None,
        }
    }

    /// Convert this address to a confidential address with the given blinding pubkey.
    pub fn to_confidential(&self, blinding_pubkey: secp256k1::PublicKey) -> Address {
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
        let payload = if !blinded {
            bech32::decode(s).map_err(AddressError::Bech32)?.1
        } else {
            blech32::decode(s).map_err(AddressError::Blech32)?.1
        };

        if payload.len() == 0 {
            return Err(AddressError::InvalidAddress(s.to_owned()));
        }

        // Get the script version and program (converted from 5-bit to 8-bit)
        let (version, data) = {
            let (v, p5) = payload.split_at(1);
            let data_res = Vec::from_base32(p5);
            if let Err(e) = data_res {
                return Err(match blinded {
                    true => AddressError::Blech32(e),
                    false => AddressError::Bech32(e),
                });
            }
            (v[0], data_res.unwrap())
        };
        if version.to_u8() > 16 {
            return Err(AddressError::InvalidWitnessVersion);
        }

        // Segwit version specific checks.
        if version.to_u8() != 0 {
            return Err(AddressError::UnsupportedWitnessVersion(version.to_u8()));
        }
        if !blinded && version.to_u8() == 0 && data.len() != 20 && data.len() != 32 {
            return Err(AddressError::InvalidWitnessProgramLength);
        }
        if blinded && version.to_u8() == 0 && data.len() != 53 && data.len() != 65 {
            return Err(AddressError::InvalidWitnessProgramLength);
        }

        let (blinding_pubkey, program) = match blinded {
            true => (
                Some(
                    secp256k1::PublicKey::from_slice(&data[..33])
                        .map_err(AddressError::InvalidBlindingPubKey)?,
                ),
                data[33..].to_vec(),
            ),
            false => (None, data),
        };

        Ok(Address {
            params: params,
            payload: Payload::WitnessProgram {
                version: version,
                program: program,
            },
            blinding_pubkey: blinding_pubkey,
        })
    }

    // data.len() should be >= 1 when this method is called
    fn from_base58(data: &[u8], params: &'static AddressParams) -> Result<Address, AddressError> {
        // When unblinded, the structure is:
        // <1: regular prefix> <20: hash160>
        // When blinded, the structure is:
        // <1: blinding prefix> <1: regular prefix> <33: blinding pubkey> <20: hash160>

        let (blinded, prefix) = match data[0] == params.blinded_prefix {
            true => {
                if data.len() != 55 {
                    return Err(base58::Error::InvalidLength(data.len()))?;
                }
                (true, data[1])
            }
            false => {
                if data.len() != 21 {
                    return Err(base58::Error::InvalidLength(data.len()))?;
                }
                (false, data[0])
            }
        };

        let (blinding_pubkey, payload_data) = match blinded {
            true => (
                Some(
                    secp256k1::PublicKey::from_slice(&data[2..35])
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
            return Err(base58::Error::InvalidVersion(vec![prefix]))?;
        };

        Ok(Address {
            params: params,
            payload: payload,
            blinding_pubkey: blinding_pubkey,
        })
    }

    /// Parse the address using the given parameters.
    /// When using the built-in parameters, you can use [FromStr].
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
            return Err(base58::Error::InvalidLength(s.len() * 11 / 15))?;
        }
        let data = base58::from_check(s)?;
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
                    base58::check_encode_slice_to_fmt(fmt, &prefixed[..])
                } else {
                    let mut prefixed = [0; 21];
                    prefixed[0] = self.params.p2pkh_prefix;
                    prefixed[1..].copy_from_slice(&hash[..]);
                    base58::check_encode_slice_to_fmt(fmt, &prefixed[..])
                }
            }
            Payload::ScriptHash(ref hash) => {
                if let Some(ref blinder) = self.blinding_pubkey {
                    let mut prefixed = [0; 55]; // 1 + 1 + 33 + 20
                    prefixed[0] = self.params.blinded_prefix;
                    prefixed[1] = self.params.p2sh_prefix;
                    prefixed[2..35].copy_from_slice(&blinder.serialize());
                    prefixed[35..].copy_from_slice(&hash[..]);
                    base58::check_encode_slice_to_fmt(fmt, &prefixed[..])
                } else {
                    let mut prefixed = [0; 21];
                    prefixed[0] = self.params.p2sh_prefix;
                    prefixed[1..].copy_from_slice(&hash[..]);
                    base58::check_encode_slice_to_fmt(fmt, &prefixed[..])
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

                if self.is_blinded() {
                    let mut data = Vec::with_capacity(53);
                    if let Some(ref blinder) = self.blinding_pubkey {
                        data.extend_from_slice(&blinder.serialize());
                    }
                    data.extend_from_slice(&witprog);
                    let mut b32_data = vec![witver];
                    b32_data.extend_from_slice(&data.to_base32());
                    blech32::encode_to_fmt(fmt, &hrp, &b32_data)
                } else {
                    let mut bech32_writer = bech32::Bech32Writer::new(hrp, fmt)?;
                    bech32::WriteBase32::write_u5(&mut bech32_writer, witver)?;
                    bech32::ToBase32::write_base32(&witprog, &mut bech32_writer)
                }
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
    match bech32.rfind("1") {
        None => bech32,
        Some(sep) => bech32.split_at(sep).0,
    }
}

/// Checks if both prefixes match, regardless of case.
/// The first prefix can be mixed case, but the second one is expected in
/// lower case.
fn match_prefix(prefix_mixed: &str, prefix_lower: &str) -> bool {
    if prefix_lower.len() != prefix_mixed.len() {
        false
    } else {
        prefix_lower
            .chars()
            .zip(prefix_mixed.chars())
            .all(|(char_lower, char_mixed)| char_lower == char_mixed.to_ascii_lowercase())
    }
}

impl FromStr for Address {
    type Err = AddressError;

    fn from_str(s: &str) -> Result<Address, AddressError> {
        // shorthands
        let liq = &AddressParams::LIQUID;
        let ele = &AddressParams::ELEMENTS;

        // Bech32.
        let prefix = find_prefix(s);
        if match_prefix(prefix, liq.bech_hrp) {
            return Address::from_bech32(s, false, liq);
        }
        if match_prefix(prefix, liq.blech_hrp) {
            return Address::from_bech32(s, true, liq);
        }
        if match_prefix(prefix, ele.bech_hrp) {
            return Address::from_bech32(s, false, ele);
        }
        if match_prefix(prefix, ele.blech_hrp) {
            return Address::from_bech32(s, true, ele);
        }

        // Base58.
        if s.len() > 150 {
            return Err(base58::Error::InvalidLength(s.len() * 11 / 15))?;
        }
        let data = base58::from_check(s)?;
        if data.len() < 1 {
            return Err(base58::Error::InvalidLength(data.len()))?;
        }

        let p = data[0];
        if p == liq.p2pkh_prefix || p == liq.p2sh_prefix || p == liq.blinded_prefix {
            return Address::from_base58(&data, liq);
        }
        if p == ele.p2pkh_prefix || p == ele.p2sh_prefix || p == ele.blinded_prefix {
            return Address::from_base58(&data, ele);
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
    use bitcoin::util::key;
    use bitcoin::Script;
    use bitcoin::secp256k1::{PublicKey, Secp256k1};
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
            serde_json::from_value::<Address>(serde_json::to_value(&addr).unwrap()).ok().as_ref(),
            Some(addr)
        );
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
            /* #02 */ Address::p2pkh(&pk, Some(blinder.clone()), &AddressParams::LIQUID),
            /* #03 */ Address::p2pkh(&pk, Some(blinder.clone()), &AddressParams::ELEMENTS),
            /* #04 */ Address::p2sh(&script, None, &AddressParams::LIQUID),
            /* #05 */ Address::p2sh(&script, None, &AddressParams::ELEMENTS),
            /* #06 */ Address::p2sh(&script, Some(blinder.clone()), &AddressParams::LIQUID),
            /* #07 */
            Address::p2sh(&script, Some(blinder.clone()), &AddressParams::ELEMENTS),
            /* #08 */ Address::p2wpkh(&pk, None, &AddressParams::LIQUID),
            /* #09 */ Address::p2wpkh(&pk, None, &AddressParams::ELEMENTS),
            /* #10 */ Address::p2wpkh(&pk, Some(blinder.clone()), &AddressParams::LIQUID),
            /* #11 */ Address::p2wpkh(&pk, Some(blinder.clone()), &AddressParams::ELEMENTS),
            /* #12 */ Address::p2shwpkh(&pk, None, &AddressParams::LIQUID),
            /* #13 */ Address::p2shwpkh(&pk, None, &AddressParams::ELEMENTS),
            /* #14 */ Address::p2shwpkh(&pk, Some(blinder.clone()), &AddressParams::LIQUID),
            /* #15 */
            Address::p2shwpkh(&pk, Some(blinder.clone()), &AddressParams::ELEMENTS),
            /* #16 */ Address::p2wsh(&script, None, &AddressParams::LIQUID),
            /* #17 */ Address::p2wsh(&script, None, &AddressParams::ELEMENTS),
            /* #18 */ Address::p2wsh(&script, Some(blinder.clone()), &AddressParams::LIQUID),
            /* #19 */
            Address::p2wsh(&script, Some(blinder.clone()), &AddressParams::ELEMENTS),
            /* #20 */ Address::p2shwsh(&script, None, &AddressParams::LIQUID),
            /* #21 */ Address::p2shwsh(&script, None, &AddressParams::ELEMENTS),
            /* #22 */
            Address::p2shwsh(&script, Some(blinder.clone()), &AddressParams::LIQUID),
            /* #23 */
            Address::p2shwsh(&script, Some(blinder.clone()), &AddressParams::ELEMENTS),
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
            assert!(result.is_ok(), "vector: {}, err: \"{}\"", a, result.unwrap_err());
            let addr: Address = result.unwrap();
            assert_eq!(a, &addr.to_string(), "vector: {}", a);
            assert_eq!(blinded, addr.is_blinded());
            assert_eq!(params, addr.params);
            roundtrips(&addr);
        }
    }
}
