//!
//! An implementation of ELIP0102 as defined in
//! <https://github.com/ElementsProject/ELIPs/blob/main/elip-0102.mediawiki>
//!
//! ELIP0102 defines how to encode the extra data for `LiquiDEX` in a PSET.
//!

use crate::pset::{
    confidential::AssetBlindingFactor,
    encode,
    raw::ProprietaryKey,
    serialize::{Deserialize, Serialize},
    Input, Output,
};

/// Input Asset Blinding Factor keytype as defined in ELIP0102
pub const PSBT_ELEMENTS_LIQUIDEX_IN_ABF: u8 = 0x00u8;

/// Output Asset Blinding Factor keytype as defined in ELIP0102
pub const PSBT_ELEMENTS_LIQUIDEX_OUT_ABF: u8 = 0x00u8;

/// Prefix for PSET `LiquiDEX` extension as defined in ELIP0102
pub const PSET_LIQUIDEX_PREFIX: &[u8] = b"pset_liquidex";

fn prop_key(keytype: u8) -> ProprietaryKey {
    ProprietaryKey {
        prefix: PSET_LIQUIDEX_PREFIX.to_vec(),
        subtype: keytype,
        key: vec![],
    }
}

/// ELIP0102 `LiquiDEX` extensions
impl Input {
    /// Set Asset Blinding Factor
    pub fn set_abf(&mut self, abf: AssetBlindingFactor) {
        let key = prop_key(PSBT_ELEMENTS_LIQUIDEX_IN_ABF);
        self.proprietary.insert(key, abf.serialize());
    }

    /// Get Asset Blinding Factor
    pub fn get_abf(&self) -> Option<Result<AssetBlindingFactor, encode::Error>> {
        let key = prop_key(PSBT_ELEMENTS_LIQUIDEX_IN_ABF);
        self.proprietary
            .get(&key)
            .map(|data| AssetBlindingFactor::deserialize(data))
    }
}

/// ELIP0102 `LiquiDEX` extensions
impl Output {
    /// Set Asset Blinding Factor
    pub fn set_abf(&mut self, abf: AssetBlindingFactor) {
        let key = prop_key(PSBT_ELEMENTS_LIQUIDEX_OUT_ABF);
        self.proprietary.insert(key, abf.serialize());
    }

    /// Get Asset Blinding Factor
    pub fn get_abf(&self) -> Option<Result<AssetBlindingFactor, encode::Error>> {
        let key = prop_key(PSBT_ELEMENTS_LIQUIDEX_OUT_ABF);
        self.proprietary
            .get(&key)
            .map(|data| AssetBlindingFactor::deserialize(data))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::AssetId;
    use crate::encode::{serialize_hex, Encodable};
    use crate::hex::{FromHex, ToHex};

    // b'\xfc\rpset_liquidex'
    const ELIP0102_IDENTIFIER: &str = "fc0d707365745f6c69717569646578";

    #[test]
    fn prop_key_serialize() {
        let key = prop_key(PSBT_ELEMENTS_LIQUIDEX_IN_ABF);
        let mut vec = vec![];
        key.consensus_encode(&mut vec).unwrap();

        assert_eq!(
            vec.to_hex(),
            format!("0d{}00", PSET_LIQUIDEX_PREFIX.to_hex())
        );

        assert!(vec.to_hex().starts_with(&ELIP0102_IDENTIFIER[2..])); // cut proprietary prefix "fc"
    }

    #[test]
    fn set_get_abf() {
        // An ABF that's different if serialized in reverse or not
        let abf_hex = "3311111111111111111111111111111111111111111111111111111111111111";
        let abf_bytes = Vec::<u8>::from_hex(abf_hex).unwrap();
        let abf = AssetBlindingFactor::from_slice(&abf_bytes).unwrap();

        let mut input = Input::default();
        assert!(input.get_abf().is_none());
        input.set_abf(abf);
        assert_eq!(input.get_abf().unwrap().unwrap(), abf);
        let input_hex = serialize_hex(&input);
        assert!(input_hex.contains(ELIP0102_IDENTIFIER));
        assert!(input_hex.contains(abf_hex));

        let mut output = Output::default();
        assert!(output.get_abf().is_none());
        output.set_abf(abf);
        assert_eq!(output.get_abf().unwrap().unwrap(), abf);
        let output_hex = serialize_hex(&output);
        assert!(output_hex.contains(ELIP0102_IDENTIFIER));
        assert!(output_hex.contains(abf_hex));
    }

    #[test]
    fn abf_roundtrip() {
        use crate::pset::PartiallySignedTransaction;

        // Set abf on an input and on an output
        let abf = AssetBlindingFactor::from_slice(&[3; 32]).unwrap();
        let mut pset = PartiallySignedTransaction::new_v2();
        let mut input = Input::default();
        input.set_abf(abf);
        pset.add_input(input);
        let mut output = Output {
            amount: Some(1),
            asset: Some(AssetId::from_slice(&[9; 32]).unwrap()),
            ..Default::default()
        };
        output.set_abf(abf);
        pset.add_output(output);

        // Serialize and deserialize
        let bytes = encode::serialize(&pset);
        let pset_back = encode::deserialize::<PartiallySignedTransaction>(&bytes).unwrap();
        // Check the abf
        assert_eq!(pset_back.inputs()[0].get_abf().unwrap().unwrap(), abf);
        assert_eq!(pset_back.outputs()[0].get_abf().unwrap().unwrap(), abf);
    }
}
