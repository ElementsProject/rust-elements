use super::PartiallySignedTransaction;

#[derive(Debug)]
pub enum Error {
    Base64(bitcoin::base64::DecodeError),
    Deserialize(crate::encode::Error)
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Base64(_) => write!(f, "Base64 error"),
            Error::Deserialize(_) => write!(f, "Deserialize error"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Base64(e) => Some(e),
            Error::Deserialize(e) => Some(e),
        }
    }

}

impl std::str::FromStr for PartiallySignedTransaction {
    type Err=Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = bitcoin::base64::decode(s).map_err(Error::Base64)?;
        crate::encode::deserialize(&bytes).map_err(Error::Deserialize)
    }
}

impl std::fmt::Display for PartiallySignedTransaction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let bytes = crate::encode::serialize(self);
        let base64 = bitcoin::base64::encode(bytes);
        write!(f, "{}", base64)
    }
}
