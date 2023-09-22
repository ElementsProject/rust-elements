use super::PartiallySignedTransaction;

/// Possible errors when parsing a PSET from a string
#[derive(Debug)]
pub enum ParseError {
    /// Base64 decoding error
    Base64(bitcoin::base64::DecodeError),
    /// PSET binary encoding error
    Deserialize(crate::encode::Error)
}

impl core::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseError::Base64(_) => write!(f, "Base64 error"),
            ParseError::Deserialize(_) => write!(f, "Deserialize error"),
        }
    }
}

impl std::error::Error for ParseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ParseError::Base64(e) => Some(e),
            ParseError::Deserialize(e) => Some(e),
        }
    }

}

impl std::str::FromStr for PartiallySignedTransaction {
    type Err=ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = bitcoin::base64::decode(s).map_err(ParseError::Base64)?;
        crate::encode::deserialize(&bytes).map_err(ParseError::Deserialize)
    }
}

impl std::fmt::Display for PartiallySignedTransaction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let bytes = crate::encode::serialize(self);
        let base64 = bitcoin::base64::encode(bytes);
        write!(f, "{}", base64)
    }
}
