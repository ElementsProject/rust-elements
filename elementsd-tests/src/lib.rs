#[cfg(test)]
mod pset;
#[cfg(test)]
mod taproot;

use elementsd::bitcoincore_rpc::jsonrpc::serde_json::{json, Value};
use elementsd::bitcoincore_rpc::RpcApi;
#[cfg(test)]
use elementsd::bitcoind::{self, BitcoinD};
use elementsd::ElementsD;
use std::str::FromStr;

trait Call {
    fn call(&self, cmd: &str, args: &[Value]) -> Value;
    fn decode_psbt(&self, psbt: &str) -> Option<Value>;
    fn get_new_address(&self) -> String;
    fn get_pegin_address(&self) -> (String, String);
    fn wallet_create_funded_psbt(&self, address: &str) -> String;
    fn expected_next(&self, psbt: &str) -> String;
    fn wallet_process_psbt(&self, psbt: &str) -> String;
    fn finalize_psbt(&self, psbt: &str) -> String;
    fn test_mempool_accept(&self, hex: &str) -> bool;
    fn get_first_prevout(&self) -> elements::OutPoint;
    fn generate(&self, blocks: u32);
    fn get_balances(&self) -> Value;

    fn send_to_address(&self, addr: &str, amt: &str) -> String;
    fn get_transaction(&self, txid: &str) -> String;
    fn get_block_hash(&self, id: u32) -> String;
    fn send_raw_transaction(&self, hex: &str) -> String;
}

impl Call for ElementsD {
    fn call(&self, cmd: &str, args: &[Value]) -> Value {
        match self.client().call::<Value>(cmd, args) {
            Ok(v) => v,
            Err(e) => panic!("error {} while calling {} with {:?}", e, cmd, args),
        }
    }

    fn decode_psbt(&self, psbt: &str) -> Option<Value> {
        self.client()
            .call::<Value>("decodepsbt", &[psbt.into()])
            .ok()
    }

    fn get_new_address(&self) -> String {
        self.call("getnewaddress", &[])
            .as_str()
            .unwrap()
            .to_string()
    }

    fn get_pegin_address(&self) -> (String, String) {
        let value = self.call("getpeginaddress", &[]);
        let mainchain_address = value.get("mainchain_address").unwrap();
        let mainchain_address = mainchain_address.as_str().unwrap().to_string();
        let claim_script = value.get("claim_script").unwrap();
        let claim_script = claim_script.as_str().unwrap().to_string();
        (mainchain_address, claim_script)
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

    fn test_mempool_accept(&self, hex: &str) -> bool {
        let result = self.call("testmempoolaccept", &[json!([hex])]);
        let allowed = result.get(0).unwrap().get("allowed");
        allowed.unwrap().as_bool().unwrap()
    }

    fn get_first_prevout(&self) -> elements::OutPoint {
        let value = self.call("listunspent", &[]);
        let first = value.get(0).unwrap();
        let txid = first.get("txid").unwrap().as_str().unwrap();
        let vout = first.get("vout").unwrap().as_u64().unwrap();

        elements::OutPoint::new(elements::Txid::from_str(txid).unwrap(), vout as u32)
    }

    fn generate(&self, blocks: u32) {
        let address = self.get_new_address();
        let _value = self.call("generatetoaddress", &[blocks.into(), address.into()]);
    }

    fn get_balances(&self) -> Value {
        self.call("getbalances", &[])
    }

    fn get_transaction(&self, txid: &str) -> String {
        self.call("gettransaction", &[txid.into()])["hex"]
            .as_str()
            .unwrap()
            .to_string()
    }

    fn send_to_address(&self, addr: &str, amt: &str) -> String {
        self.call("sendtoaddress", &[addr.into(), amt.into()])
            .as_str()
            .unwrap()
            .to_string()
    }

    fn send_raw_transaction(&self, tx: &str) -> String {
        self.call("sendrawtransaction", &[tx.into()])
            .as_str()
            .unwrap()
            .to_string()
    }

    fn get_block_hash(&self, id: u32) -> String {
        self.call("getblockhash", &[id.into()])
            .as_str()
            .unwrap()
            .to_string()
    }
}

#[cfg(test)]
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
