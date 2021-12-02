extern crate elements;

#[cfg(feature = "integration")]
extern crate elementsd;

#[cfg(all(test, feature = "integration"))]
mod tests {
    use elements::encode::{deserialize, serialize};
    use elements::pset::PartiallySignedTransaction;
    use elementsd::bitcoincore_rpc::jsonrpc::serde_json::{json, Value};
    use elementsd::bitcoincore_rpc::RpcApi;
    use elementsd::bitcoind::BitcoinD;
    use elementsd::{bitcoind, ElementsD};

    trait Call {
        fn call(&self, cmd: &str, args: &[Value]) -> Value;
        fn decode_psbt(&self, psbt: &str) -> Option<Value>;
        fn get_new_address(&self) -> String;
        fn wallet_create_funded_psbt(&self, address: &str) -> String;
        fn expected_next(&self, psbt: &str) -> String;
        fn wallet_process_psbt(&self, psbt: &str) -> String;
    }

    /*
    issuance
    reissueance
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
            self.client().call::<Value>("decodepsbt", &[psbt.into()]).ok()
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