extern crate elements;

#[cfg(feature = "integration")]
extern crate elementsd;

#[cfg(all(test, feature = "integration"))]
mod tests {
    use elements::bitcoin::hashes::hex::FromHex;
    use elements::bitcoin::hashes::Hash;
    use elements::encode::{deserialize, serialize};
    use elements::pset::PartiallySignedTransaction;
    use elements::Txid;
    use elements::{AssetId, ContractHash, OutPoint};
    use elementsd::bitcoincore_rpc::jsonrpc::serde_json::{json, Value};
    use elementsd::bitcoincore_rpc::RpcApi;
    use elementsd::bitcoind::BitcoinD;
    use elementsd::{bitcoind, ElementsD};

    trait Call {
        fn call(&self, cmd: &str, args: &[Value]) -> Value;
        fn decode_psbt(&self, psbt: &str) -> Option<Value>;
        fn analyze_psbt(&self, psbt: &str) -> Value;
        fn get_new_address(&self) -> String;
        fn wallet_create_funded_psbt(&self, address: &str) -> String;
        fn expected_next(&self, psbt: &str) -> String;
        fn wallet_process_psbt(&self, psbt: &str) -> String;
        fn finalize_psbt(&self, psbt: &str) -> String;
        fn get_first_prevout(&self) -> OutPoint;
    }

    /*
    pegin
    */

    #[cfg_attr(feature = "integration", test)]
    fn tx_unblinded() {
        let (elementsd, _bitcoind) = setup(false);

        let address = elementsd.get_new_address();
        let psbt_base64 = elementsd.wallet_create_funded_psbt(&address);
        assert_eq!(elementsd.expected_next(&psbt_base64), "blinder");
        psbt_rtt(&elementsd, &psbt_base64);
    }

    #[cfg_attr(feature = "integration", test)]
    fn tx_blinded() {
        let (elementsd, _bitcoind) = setup(false);

        let address = elementsd.get_new_address();
        let psbt_base64 = elementsd.wallet_create_funded_psbt(&address);
        assert_eq!(elementsd.expected_next(&psbt_base64), "blinder");
        let psbt_base64 = elementsd.wallet_process_psbt(&psbt_base64);
        assert_eq!(elementsd.expected_next(&psbt_base64), "finalizer");
        psbt_rtt(&elementsd, &psbt_base64);
    }

    #[cfg_attr(feature = "integration", test)]
    fn tx_issuance() {
        let (elementsd, _bitcoind) = setup(false);

        let address_asset = elementsd.get_new_address();
        let address_reissuance = elementsd.get_new_address();
        let address_lbtc = elementsd.get_new_address();
        let prevout = elementsd.get_first_prevout();

        let contract_hash = ContractHash::from_inner([0u8; 32]);
        let entropy = AssetId::generate_asset_entropy(prevout, contract_hash);
        let asset_id = AssetId::from_entropy(entropy.clone());
        assert_eq!(
            asset_id.to_string(),
            "78b4920005fa0156ae3779129338bc2707e4d07cf8a0c2593583e3c1da3bb58c"
        );
        let reissuance_id = AssetId::reissuance_token_from_entropy(entropy, true);
        assert_eq!(
            reissuance_id.to_string(),
            "78b4920005fa0156ae3779129338bc2707e4d07cf8a0c2593583e3c1da3bb58c"
        );

        let value = elementsd.call(
            "createpsbt",
            &[
                json!([{ "txid": prevout.txid, "vout": prevout.vout, "issuance_amount": 1000, "issuance_tokens": 1}]),
                json!([
                    {address_asset: "1000", "asset": asset_id.to_string(), "blinder_index": 0},
                    {address_reissuance: "1", "asset": reissuance_id.to_string(), "blinder_index": 0},
                    {address_lbtc: "20.9", "blinder_index": 0},
                    {"fee": "0.1" }
                ]),
                0.into(),
                false.into(),
            ],
        );
        let psbt_base64 = value.as_str().unwrap().to_string();
        let value = elementsd.analyze_psbt(&psbt_base64);

        assert_eq!(elementsd.expected_next(&psbt_base64), "updater");
        let psbt_base64 = elementsd.wallet_process_psbt(&psbt_base64);
        assert_eq!(elementsd.expected_next(&psbt_base64), "finalizer");
        psbt_rtt(&elementsd, &psbt_base64);
    }

    fn psbt_rtt(elementsd: &ElementsD, base64: &str) {
        let a = elementsd.decode_psbt(&base64).unwrap();

        let b_psbt = psbt_from_base64(&base64);
        let mut b_bytes = serialize(&b_psbt);
        let b_base64 = base64::encode(&b_bytes);
        let b = elementsd.decode_psbt(&b_base64).unwrap();

        assert_eq!(a, b);

        let mut tests = 0;
        for i in 0..b_bytes.len() {
            // ensuring decode prints all data inside psbt, changing all bytes, if the results is still
            // decodable it should not be equal to initial value
            b_bytes[i] = b_bytes[i].wrapping_add(1);
            let base64 = base64::encode(&b_bytes);
            if let Some(decoded) = elementsd.decode_psbt(&base64) {
                assert_ne!(a, decoded);
                tests += 1;
            }
            b_bytes[i] = b_bytes[i].wrapping_sub(1);
        }
        assert!(tests > 0)
    }

    impl Call for ElementsD {
        fn call(&self, cmd: &str, args: &[Value]) -> Value {
            self.client().call::<Value>(cmd, args).unwrap()
        }

        fn decode_psbt(&self, psbt: &str) -> Option<Value> {
            self.client()
                .call::<Value>("decodepsbt", &[psbt.into()])
                .ok()
        }

        fn analyze_psbt(&self, psbt: &str) -> Value {
            self.call("decodepsbt", &[psbt.into()])
        }

        fn get_new_address(&self) -> String {
            self.call("getnewaddress", &[])
                .as_str()
                .unwrap()
                .to_string()
        }

        fn wallet_create_funded_psbt(&self, address: &str) -> String {
            let value = self.call(
                "walletcreatefundedpsbt",
                &[json!([]), json!([{address.to_string(): "1"}])],
            );
            value.get("psbt").unwrap().as_str().unwrap().to_string()
        }

        fn expected_next(&self, base64: &str) -> String {
            let value = self.call("analyzepsbt", &[base64.into()]);
            value.get("next").unwrap().as_str().unwrap().to_string()
        }

        fn wallet_process_psbt(&self, base64: &str) -> String {
            let value = self.call("walletprocesspsbt", &[base64.into()]);
            value.get("psbt").unwrap().as_str().unwrap().to_string()
        }

        fn finalize_psbt(&self, base64: &str) -> String {
            let value = self.call("finalizepsbt", &[base64.into()]);
            value.get("hex").unwrap().as_str().unwrap().to_string()
        }

        fn get_first_prevout(&self) -> OutPoint {
            let value = self.call("listunspent", &[]);
            let first = value.get(0).unwrap();
            let txid = first.get("txid").unwrap().as_str().unwrap();
            let vout = first.get("vout").unwrap().as_u64().unwrap();

            OutPoint::new(Txid::from_hex(txid).unwrap(), vout as u32)
        }
    }

    fn psbt_from_base64(base64: &str) -> PartiallySignedTransaction {
        let bytes = base64::decode(&base64).unwrap();
        deserialize(&bytes).unwrap()
    }

    fn setup(validate_pegin: bool) -> (ElementsD, Option<BitcoinD>) {
        let mut bitcoind = None;
        if validate_pegin {
            let bitcoind_exe = bitcoind::exe_path().unwrap();
            let bitcoind_conf = bitcoind::Conf::default();
            bitcoind = Some(bitcoind::BitcoinD::with_conf(&bitcoind_exe, &bitcoind_conf).unwrap());
        }

        let conf = elementsd::Conf::new(bitcoind.as_ref());

        let elementsd = ElementsD::with_conf(elementsd::exe_path().unwrap(), &conf).unwrap();

        let create = elementsd.call("createwallet", &["wallet".into()]);
        assert_eq!(create.get("name").unwrap(), "wallet");

        let rescan = elementsd.call("rescanblockchain", &[]);
        assert_eq!(rescan.get("stop_height").unwrap(), 0);

        let balances = elementsd.call("getbalances", &[]);
        let mine = balances.get("mine").unwrap();
        let trusted = mine.get("trusted").unwrap();
        assert_eq!(trusted.get("bitcoin").unwrap(), 21.0);

        (elementsd, bitcoind)
    }
}
