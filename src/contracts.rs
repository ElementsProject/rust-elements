//! Handling asset contracts.

use std::collections::BTreeMap;
use std::{error, fmt, str};

use serde_cbor;
use serde_json;
use bitcoin::hashes::Hash;

use issuance::{AssetId, ContractHash};
use transaction::OutPoint;

/// The maximum precision of an asset.
pub const MAX_PRECISION: u8 = 8;

/// The maximum ticker string length.
pub const MAX_TICKER_LENGTH: usize = 5;

/// The contract version byte for legacy JSON contracts.
const CONTRACT_VERSION_JSON: u8 = '{' as u8;

/// The contract version byte for CBOR contracts.
const CONTRACT_VERSION_CBOR: u8 = 1;

/// An asset contract error.
#[derive(Debug)]
pub enum Error {
    /// The contract was empty.
    Empty,
    /// The CBOR format was invalid.
    InvalidCbor(serde_cbor::Error),
    /// the JSON format was invalid.
    InvalidJson(serde_json::Error),
    /// The contract's content are invalid.
    InvalidContract(&'static str),
    /// An unknown contract version was encountered.
    UnknownVersion(u8),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::Empty => write!(f, "the contract was empty"),
            Error::InvalidCbor(ref e) => write!(f, "invalid CBOR format: {}", e),
            Error::InvalidJson(ref e) => write!(f, "invalid JSON format: {}", e),
            Error::InvalidContract(ref e) => write!(f, "invalid contract: {}", e),
            Error::UnknownVersion(v) => write!(f, "unknown contract version: {}", v),
        }
    }
}

#[allow(deprecated)]
impl error::Error for Error {
    fn cause(&self) -> Option<&error::Error> {
        match *self {
            Error::InvalidCbor(ref e) => Some(e),
            Error::InvalidJson(ref e) => Some(e),
            _ => None,
        }
    }

    fn description(&self) -> &str {
        "description() is deprecated; use Display"
    }
}

/// The issuing entity of an asset.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
pub struct ContractDetailsEntity {
    /// The domain name of the issuer.
    pub domain: Option<String>,
}

/// Some well-known details encapsulated inside an asset contract.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractDetails {
    /// The precision of the asset values.
    pub precision: u8,
    /// The ticker of the asset.
    pub ticker: String,

    /// The name of the asset.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// The issuing entity.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entity: Option<ContractDetailsEntity>,
    /// The public key of the issuer.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer_pubkey: Option<bitcoin::PublicKey>,
}

/// The structure of a legacy (JSON) contract.
#[derive(Debug, Clone, Deserialize)]
struct LegacyContract {
    precision: u8,
    ticker: String,
    #[serde(flatten)]
    other: BTreeMap<String, serde_json::Value>,
}

/// The contents of an asset contract.
#[derive(Debug, Clone)]
enum Content {
    Legacy(LegacyContract),
    Modern {
        precision: u8,
        ticker: String,
        //TODO(stevenroose) consider requiring String keys
        other: BTreeMap<String, serde_cbor::Value>,
    },
}

/// Check a precision value.
#[inline]
fn check_precision<P: PartialOrd + From<u8>>(p: P) -> Result<(), Error> {
    if p < 0.into() || p > MAX_PRECISION.into() {
        return Err(Error::InvalidContract("invalid precision"));
    }
    Ok(())
}

/// Check a ticker value.
#[inline]
fn check_ticker(t: &str) -> Result<(), Error> {
    if t.len() > MAX_TICKER_LENGTH {
        return Err(Error::InvalidContract("ticker too long"));
    }
    Ok(())
}

/// Check a key value.
#[inline]
fn check_key(k: &str) -> Result<(), Error> {
    if !k.is_ascii() {
        return Err(Error::InvalidContract("keys must be ASCII"));
    }
    Ok(())
}

impl Content {
    fn from_bytes(contract: &[u8]) -> Result<Content, Error> {
        if contract.len() < 1 {
            return Err(Error::Empty);
        }

        if contract[0] == CONTRACT_VERSION_JSON {
            let content: LegacyContract =
                serde_json::from_slice(contract).map_err(Error::InvalidJson)?;
            check_precision(content.precision)?;
            check_ticker(&content.ticker)?;
            for key in content.other.keys() {
                check_key(key)?;
            }
            Ok(Content::Legacy(content))
        } else if contract[0] == CONTRACT_VERSION_CBOR {
            let content: Vec<serde_cbor::Value> =
                serde_cbor::from_slice(&contract[1..]).map_err(Error::InvalidCbor)?;
            if content.len() != 3 {
                return Err(Error::InvalidContract("CBOR value must be array of 3 elements"));
            }
            let mut iter = content.into_iter();
            Ok(Content::Modern {
                precision: if let serde_cbor::Value::Integer(i) = iter.next().unwrap() {
                    check_precision(i)?;
                    i as u8
                } else {
                    return Err(Error::InvalidContract("first CBOR value must be integer"));
                },
                ticker: if let serde_cbor::Value::Text(t) = iter.next().unwrap() {
                    check_ticker(&t)?;
                    t
                } else {
                    return Err(Error::InvalidContract("second CBOR value must be string"));
                },
                other: if let serde_cbor::Value::Map(m) = iter.next().unwrap() {
                    let mut other = BTreeMap::new();
                    for (key, value) in m.into_iter() {
                        // Use utility methods here after this PR is released:
                        // https://github.com/pyfisch/cbor/pull/191
                        match key {
                            serde_cbor::Value::Text(t) => {
                                check_key(&t)?;
                                other.insert(t, value)
                            },
                            _ => return Err(Error::InvalidContract("keys must be strings")),
                        };
                    }
                    other
                } else {
                    return Err(Error::InvalidContract("third CBOR value must be map"));
                },
            })
        } else {
            Err(Error::UnknownVersion(contract[0]))
        }
    }
}

/// An asset contract.
#[derive(Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct Contract(Vec<u8>);

impl Contract {
    /// Generate a contract from the contract details.
    pub fn from_details(
        mut details: ContractDetails,
        extra_fields: BTreeMap<String, serde_cbor::Value>,
    ) -> Result<Contract, Error> {
        check_precision(details.precision)?;
        check_ticker(&details.ticker)?;

        // Add known fields from details.
        let mut props = BTreeMap::new();
        if let Some(name) = details.name.take() {
            props.insert("name".to_owned().into(), name.into());
        }
        if let Some(mut entity) = details.entity.take() {
            let mut ent = BTreeMap::new();
            if let Some(domain) = entity.domain.take() {
                ent.insert("domain".to_owned().into(), domain.into());
            }
            props.insert("entity".to_owned().into(), ent.into());
        }
        if let Some(issuer_pubkey) = details.issuer_pubkey.take() {
            props.insert("issuer_pubkey".to_owned().into(), issuer_pubkey.to_bytes().into());
        }

        // Add extra fields.
        for (key, value) in extra_fields.into_iter() {
            check_key(&key)?;
            if props.insert(key.into(), value).is_some() {
                return Err(Error::InvalidContract("extra field reused key from details"));
            }
        }

        let cbor: Vec<serde_cbor::Value> = vec![
            details.precision.into(),
            details.ticker.into(),
            props.into(),
        ];

        let mut buffer = vec![CONTRACT_VERSION_CBOR];
        serde_cbor::to_writer(&mut buffer, &cbor).map_err(Error::InvalidCbor)?;
        Ok(Contract(buffer))
    }

    /// Generate a legacy contract from the contract details.
    #[deprecated]
    pub fn legacy_from_details(
        mut details: ContractDetails,
        extra_fields: BTreeMap<String, serde_json::Value>,
    ) -> Result<Contract, Error> {
        check_precision(details.precision)?;
        check_ticker(&details.ticker)?;

        // We will use the extra_fields hashmap to serialize the JSON later.
        for key in extra_fields.keys() {
            check_key(key)?;
        }
        let mut props = extra_fields;

        // Add known fields from details.
        if props.insert("precision".into(), details.precision.into()).is_some() {
            return Err(Error::InvalidContract("extra field reused key from details"));
        }
        if props.insert("ticker".into(), details.ticker.into()).is_some() {
            return Err(Error::InvalidContract("extra field reused key from details"));
        }
        if let Some(name) = details.name.take() {
            if props.insert("name".into(), name.into()).is_some() {
                return Err(Error::InvalidContract("extra field reused key from details"));
            }
        }
        if let Some(entity) = details.entity.take() {
            if props.insert("entity".into(), serde_json::to_value(&entity).unwrap()).is_some() {
                return Err(Error::InvalidContract("extra field reused key from details"));
            }
        }
        if let Some(issuer_pubkey) = details.issuer_pubkey.take() {
            if props.insert("issuer_pubkey".into(), issuer_pubkey.to_string().into()).is_some() {
                return Err(Error::InvalidContract("extra field reused key from details"));
            }
        }

        Ok(Contract(serde_json::to_vec(&props).map_err(Error::InvalidJson)?))
    }

    /// Parse an asset contract from bytes.
    pub fn from_bytes(contract: &[u8]) -> Result<Contract, Error> {
        // Check for validity and then store raw contract.
        let _ = Content::from_bytes(contract)?;
        Ok(Contract(contract.to_vec()))
    }

    /// Get the binary representation of the asset contract.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Get the contract hash of this asset contract.
    pub fn contract_hash(&self) -> ContractHash {
        ContractHash::hash(self.as_bytes())
    }

    /// Calculate the asset ID of an asset issued with this contract.
    pub fn asset_id(&self, prevout: OutPoint) -> AssetId {
        AssetId::from_entropy(AssetId::generate_asset_entropy(prevout, self.contract_hash()))
    }

    /// Get the precision of the asset.
    pub fn precision(&self) -> u8 {
        match Content::from_bytes(&self.as_bytes()).expect("invariant") {
            Content::Legacy(c) => c.precision,
            Content::Modern { precision, .. } => precision,
        }
    }

    /// Get the ticker of the asset.
    pub fn ticker(&self) -> String {
        match Content::from_bytes(&self.as_bytes()).expect("invariant") {
            Content::Legacy(c) => c.ticker,
            Content::Modern { ticker, .. } => ticker,
        }
    }
    
    /// Retrieve a property from the contract.
    /// For precision and ticker, use the designated methods instead.
    pub fn property<T: serde::de::DeserializeOwned>(&self, key: &str) -> Result<Option<T>, Error> {
        match Content::from_bytes(&self.as_bytes()).expect("invariant") {
            Content::Legacy(c) => {
                let value = match c.other.get(key) {
                    Some(v) => v,
                    None => return Ok(None),
                };
                Ok(serde_json::from_value(value.clone()).map_err(Error::InvalidJson)?)
            },
            Content::Modern { other, .. } => {
                let value = match other.get(key) {
                    Some(v) => v,
                    None => return Ok(None),
                };
                //TODO(stevenroose) optimize this when serde_cbor implements from_value
                let bytes = serde_cbor::to_vec(&value).map_err(Error::InvalidCbor)?;
                Ok(serde_cbor::from_slice(&bytes).map_err(Error::InvalidCbor)?)
            },
        }
    }
}

impl fmt::Display for Contract {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // We will display legacy contracts as JSON and others as hex.
        if self.as_bytes()[0] == CONTRACT_VERSION_JSON {
            write!(f, "{}", str::from_utf8(self.as_bytes()).expect("invariant"))
        } else {
            for b in self.as_bytes() {
                write!(f, "{:02x}", b)?;
            }
            Ok(())
        }
    }
}

impl fmt::Debug for Contract {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Contract({:?})", Content::from_bytes(self.as_bytes()).expect("invariant"))
    }
}
