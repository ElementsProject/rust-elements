extern crate bitcoin;
extern crate elements;
extern crate rand;
extern crate serde_json;

use std::{collections::HashMap, str::FromStr};

use elements::confidential::{AssetBlindingFactor, ValueBlindingFactor};
use elements::{
    bitcoin::PublicKey, pset::PartiallySignedTransaction as Pset, Address, AddressParams, OutPoint,
    Script, TxOutSecrets, TxOutWitness, Txid, WScriptHash,
};
use elements::{pset, secp256k1_zkp, SurjectionInput};

use elements::encode::{deserialize, serialize_hex};
use elements::hashes::hex::FromHex;
use elements::{confidential, AssetId, TxOut};
use rand::SeedableRng;

/// Pset example workflow:
/// Simple transaction spending a confidential asset
/// with external signer and blinding done by rust-elements using raw APIs
/// See also coinjoin example for external blinding example
/// Users are recommended to use PSET APIs for handling blinding
/// instead using raw APIs.
static PARAMS: AddressParams = AddressParams::ELEMENTS;

// Assume txouts are simple pay to wpkh
// and keep the secrets correponding to
// confidential txouts
#[derive(Debug, Clone)]
struct Secrets {
    _sk: bitcoin::PrivateKey,
    sec: TxOutSecrets,
}

fn deser_pset(psbt_hex: &str) -> Pset {
    deserialize::<Pset>(&Vec::<u8>::from_hex(psbt_hex).unwrap()).unwrap()
}

fn parse_txout(txout_info: &str) -> (TxOut, Secrets, pset::Input) {
    // Parse the string of data into serde_json::Value.
    let v: serde_json::Value = serde_json::from_str(txout_info).unwrap();

    let txout = TxOut {
        asset: deserialize::<confidential::Asset>(
            &Vec::<u8>::from_hex(&v["assetcommitment"].as_str().unwrap()).unwrap(),
        )
        .unwrap(),
        value: deserialize::<confidential::Value>(
            &Vec::<u8>::from_hex(&v["amountcommitment"].as_str().unwrap()).unwrap(),
        )
        .unwrap(),
        nonce: deserialize::<confidential::Nonce>(
            &Vec::<u8>::from_hex(&v["commitmentnonce"].as_str().unwrap()).unwrap(),
        )
        .unwrap(),
        script_pubkey: Script::from_hex(&v["scriptPubKey"].as_str().unwrap()).unwrap(),
        witness: TxOutWitness::default(),
    };

    let txoutsecrets = Secrets {
        _sk: bitcoin::PrivateKey::from_wif(&v["skwif"].as_str().unwrap()).unwrap(),
        sec: TxOutSecrets {
            asset_bf: AssetBlindingFactor::from_str(&v["assetblinder"].as_str().unwrap()).unwrap(),
            value_bf: ValueBlindingFactor::from_str(&v["amountblinder"].as_str().unwrap()).unwrap(),
            value: bitcoin::Amount::from_str_in(
                &v["amount"].as_str().unwrap(),
                bitcoin::Denomination::Bitcoin,
            )
            .unwrap()
            .to_sat(),
            asset: AssetId::from_hex(&v["asset"].as_str().unwrap()).unwrap(),
        },
    };

    let inp = pset::Input::from_prevout(OutPoint::new(
        Txid::from_str(&v["txid"].as_str().unwrap()).unwrap(),
        v["vout"].as_u64().unwrap() as u32,
    ));

    (txout, txoutsecrets, inp)
}

fn txout_data() -> [(TxOut, Secrets, pset::Input); 2] {
    // Some JSON input data as a &str. Maybe this comes from the user.
    let asset_txout = r#"
    {
        "txid": "ae20ec0b3bbafd466007a448de01d16da3b6f07e1af48d6d273550917146becb",
        "vout": 1,
        "scriptPubKey": "001403bb7619d51d2af2c5538d3908ead081a7ef2b2b",
        "amount": "20.00000000",
        "assetcommitment": "0b90df52169792d13db9b7d074d091aaa3e83aff261b1cc19d291441b62e7a0319",
        "asset": "a5892483c4ff30a0053745ae7554ba55df05c3dccc74d5eddde63cac2c7e63d9",
        "amountcommitment": "0899a91403ca5cd8bded09945bc99c2f980fd27601cada66833a5f4bc108baf639",
        "amountblinder": "db0e2a8dc66f584fac55a35288dc130f81ebbc3b2a674d32bfb6ceb84e325ca2",
        "assetblinder": "670c156bc68fcbe73f40d22d6e5c0e23fe7760421b0a4bf379f7a2f376cc252f",
        "commitmentnonce": "02e8bed2778bf381d17241be029f228664c7d1522ced55379e275b83fe805b3702",
        "skwif": "cVxZfk3WY1wzyjCJDgkxeay8j6LHqpnQ4CA35jat5fNStK7CXnCK"
    }"#;

    let btc_txout = r#"
    {
        "txid": "ae20ec0b3bbafd466007a448de01d16da3b6f07e1af48d6d273550917146becb",
        "vout": 0,
        "scriptPubKey": "00142d2186719dc0c245e7b4a30f17834f371ca7377c",
        "amount": "19.99999636",
        "assetcommitment": "0bab8c49f1fce77440be124c72ce22bb23b58c6f52baf4cdde1f656056cd6b9644",
        "asset": "b2e15d0d7a0c94e4e2ce0fe6e8691b9e451377f6e46e8045a86f7c4b5d4f0f23",
        "amountcommitment": "0980610bc88e4ab656c2e5ff6fe6c6a39967a1c0d386682240c5ff039148dc335d",
        "amountblinder": "9adf40243f6df7d25de35de3b39471182f13619285fb42f81040ebbce4eb35db",
        "assetblinder": "20b145414fc110c476bc114b09adcdaacb71d10cf1ca2d0318ac003177d881b9",
        "commitmentnonce": "03b636cc4beba2967c418a9443e161cd0ac77bec5e44c4bf98e72fc28857abca33",
        "skwif": "cUfcqc2TYuVu9ZDe3H5BLQSWn6pFm97ztngtKu9WPismjQSQuuCj"
      }"#;

    [parse_txout(btc_txout), parse_txout(asset_txout)]
}

fn test_data() -> HashMap<String, String> {
    let mut tests = HashMap::new();
    tests.insert(
        String::from("empty"),
        String::from("70736574ff01020402000000010401000105010001fb040200000000"),
    );
    tests.insert(String::from("one_inp_zero_out") , String::from("70736574ff01020402000000010401010105010001fb04020000000001017a0bab8c49f1fce77440be124c72ce22bb23b58c6f52baf4cdde1f656056cd6b96440980610bc88e4ab656c2e5ff6fe6c6a39967a1c0d386682240c5ff039148dc335d03b636cc4beba2967c418a9443e161cd0ac77bec5e44c4bf98e72fc28857abca331600142d2186719dc0c245e7b4a30f17834f371ca7377c010e20cbbe4671915035276d8df41a7ef0b6a36dd101de48a4076046fdba3b0bec20ae010f040000000000"));
    tests.insert(String::from("two_inp_zero_out") , String::from("70736574ff01020402000000010401020105010001fb04020000000001017a0bab8c49f1fce77440be124c72ce22bb23b58c6f52baf4cdde1f656056cd6b96440980610bc88e4ab656c2e5ff6fe6c6a39967a1c0d386682240c5ff039148dc335d03b636cc4beba2967c418a9443e161cd0ac77bec5e44c4bf98e72fc28857abca331600142d2186719dc0c245e7b4a30f17834f371ca7377c010e20cbbe4671915035276d8df41a7ef0b6a36dd101de48a4076046fdba3b0bec20ae010f04000000000001017a0b90df52169792d13db9b7d074d091aaa3e83aff261b1cc19d291441b62e7a03190899a91403ca5cd8bded09945bc99c2f980fd27601cada66833a5f4bc108baf63902e8bed2778bf381d17241be029f228664c7d1522ced55379e275b83fe805b370216001403bb7619d51d2af2c5538d3908ead081a7ef2b2b010e20cbbe4671915035276d8df41a7ef0b6a36dd101de48a4076046fdba3b0bec20ae010f040100000000"));
    tests.insert(String::from("two_inp_two_out") , include_str!("test_vector/raw_blind/two_inp_two_out.hex").to_string());
    tests.insert(String::from("blinded_unsigned") , include_str!("test_vector/raw_blind/blinded_unsigned.hex").to_string());
    tests.insert(String::from("blinded_one_inp_signed") , include_str!("test_vector/raw_blind/blinded_one_inp_signed.hex").to_string());
    tests.insert(String::from("blinded_signed") , include_str!("test_vector/raw_blind/blinded_signed.hex").to_string());
    tests.insert(String::from("finalized") , include_str!("test_vector/raw_blind/finalized.hex").to_string());
    tests.insert(String::from("extracted_tx") , include_str!("test_vector/raw_blind/extracted_tx.hex").to_string());

    tests
}

fn main() {
    let tests = test_data();
    // Initially secp context and rng global state
    let secp = secp256k1_zkp::Secp256k1::new();

    // NOTE: Zero is not a reasonable seed for production code.
    // It is used here so that we can match test vectors.
    let mut rng = rand_chacha::ChaCha20Rng::from_seed([0u8; 32]);

    let txouts = txout_data();
    let (btc_txout, btc_txout_secrets, btc_inp) = txouts[0].clone();
    let (asset_txout, asset_txout_secrets, asset_inp) = txouts[1].clone();

    let mut pset = Pset::new_v2();
    assert_eq!(pset, deser_pset(&tests["empty"]));

    // Add the btc asset input
    let mut btc_inp = btc_inp;
    btc_inp.witness_utxo = Some(btc_txout.clone());
    pset.add_input(btc_inp);

    // pset after adding the information about the bitcoin input
    // Pset with 1 input and 0 outputs
    assert_eq!(pset, deser_pset(&tests["one_inp_zero_out"]));
    // Add the asset input
    let mut asset_inp = asset_inp;
    asset_inp.witness_utxo = Some(asset_txout.clone());
    pset.add_input(asset_inp);
    assert_eq!(pset, deser_pset(&tests["two_inp_zero_out"]));

    // Add outputs
    // Send 5_000 worth of asset units to new address
    let inputs = [
        (SurjectionInput::from_txout_secrets(btc_txout_secrets.sec)),
        (SurjectionInput::from_txout_secrets(asset_txout_secrets.sec)),
    ];

    let dest_wsh =
        WScriptHash::from_str("e5793ad956ee91ebf3543b37d110701118ed4078ffa0d477eacb8885e486ad85")
            .unwrap();
    let dest_amt = 5_000; // sat
    let dest_blind_pk =
        PublicKey::from_str("0212bf0ea45b733dfde8ecb5e896306c4165c666c99fc5d1ab887f71393a975cea")
            .unwrap();
    let (dest_asset_txout, dest_abf, dest_vbf, _) = TxOut::new_not_last_confidential(
        &mut rng,
        &secp,
        dest_amt,
        Address::p2wsh(
            &Script::new_v0_wsh(&dest_wsh),
            Some(dest_blind_pk.inner),
            &PARAMS,
        ),
        asset_txout_secrets.sec.asset,
        &inputs,
    )
    .expect("Asset Destination txOut creation failure");
    // Add a change remaining 15_000 units of asset
    let change_amt = asset_txout_secrets.sec.value - dest_amt;
    let change_blind_pk =
        PublicKey::from_str("027d07ae478c0aa607321643cb5e8ed59ee1f5ff4d9d55efedec066ccb1f5d537d")
            .unwrap();
    let change_wsh =
        WScriptHash::from_str("f6b43d56e004e9d0b1ec2fc3c95511d81af08420992be8dec7f86cdf8970b3e2")
            .unwrap();
    let (change_asset_txout, asset_change_abf, asset_change_vbf, _) =
        TxOut::new_not_last_confidential(
            &mut rng,
            &secp,
            change_amt,
            Address::p2wsh(
                &Script::new_v0_wsh(&change_wsh),
                Some(change_blind_pk.inner),
                &PARAMS,
            ),
            asset_txout_secrets.sec.asset,
            &inputs,
        )
        .expect("Asset Change txOut creation failure");

    // Add both assets to pset. 5_000 dest address, 15_000 change address
    pset.add_output(pset::Output::from_txout(dest_asset_txout));
    pset.add_output(pset::Output::from_txout(change_asset_txout));

    // Add information about which input index blinded the outputs
    // Spec mandates that blinded inputs must have this information
    assert_eq!(pset, deser_pset(&tests["two_inp_two_out"]));

    // Add two more outputs: btc change amount and btc fees
    let btc_fees_amt = 500; // sat
    let btc_fees_txout = TxOut::new_fee(btc_fees_amt, btc_txout_secrets.sec.asset);
    // Add a change remaining amount units as change btc output
    // Adding the last confidential transaction output requires all the blinding factors of outputs

    let output_secrets = [
        &TxOutSecrets::new(asset_txout_secrets.sec.asset, dest_abf, dest_amt, dest_vbf),
        &TxOutSecrets::new(
            asset_txout_secrets.sec.asset,
            asset_change_abf,
            change_amt,
            asset_change_vbf,
        ),
        &TxOutSecrets::new(
            btc_txout_secrets.sec.asset,
            AssetBlindingFactor::zero(),
            btc_fees_amt,
            ValueBlindingFactor::zero(),
        ),
    ];
    let change_amt = btc_txout_secrets.sec.value - btc_fees_amt;
    let change_blind_pk =
        PublicKey::from_str("02f67fc29266e2d92be547f349a17678a445274243fb1e2fb67d7429f8047421d0")
            .unwrap();
    let change_wsh =
        WScriptHash::from_str("c773786f3addae4c21acb094f39122c032daded1cb6225a64d923a0344087bfd")
            .unwrap();

    // For the last output we require all secrets.
    let inputs = [
        btc_txout_secrets.sec,
        asset_txout_secrets.sec,
    ];
    let (btc_change_txout, _abf, _vbf, _) = TxOut::new_last_confidential(
        &mut rng,
        &secp,
        change_amt,
        btc_txout_secrets.sec.asset,
        Script::new_v0_wsh(&change_wsh),
        change_blind_pk.inner,
        &inputs,
        &output_secrets,
    )
    .expect("Asset Change txOut creation failure");
    // Add both pset outputs to btc transaction
    pset.add_output(pset::Output::from_txout(btc_fees_txout));
    pset.add_output(pset::Output::from_txout(btc_change_txout));
    assert_eq!(pset, deser_pset(&tests["blinded_unsigned"]));

    // Verify the balance checks
    let tx = pset.extract_tx().unwrap();
    // println!("{}", serialize_hex(&tx));
    tx.verify_tx_amt_proofs(&secp, &[btc_txout, asset_txout])
        .unwrap();

    let inp0_sig = Vec::<u8>::from_hex("3044022040d1802d6e10da4c27f05eff807550e614b3d2fa20c663dbf1ebf162d3952689022001f477c953b7c543bce877e3297fccb00ef5dba21d427e79c8bfb8522713309801").unwrap();
    let inp0_pk = bitcoin::PublicKey::from_str(
        "0334c307ad8142e7c8a6bf1ad3552b12fbb860885ea7f2d76c1f49f93a7c4bbbe7",
    )
    .unwrap();

    let inp1_sig = Vec::<u8>::from_hex("3044022017c696503f5e1539fe5cb8dd05f793bd3b6e39f193028a7299a80c94c817a02d022007889009088f46cd9d9f4d137815704170410f53d503b68c1e020292a85b93fa01").unwrap();
    let inp1_pk = bitcoin::PublicKey::from_str(
        "03df8f51c053ba0dfb443cce9793b6dc3339ffb0ce97af4792dade3aae1eb890f6",
    )
    .unwrap();
    // Sign the raw transactions
    // Input zero adds signatures
    pset.inputs_mut()[0]
        .partial_sigs
        .insert(inp0_pk, inp0_sig.clone());
    assert_eq!(pset, deser_pset(&tests["blinded_one_inp_signed"]));
    // Input one adds signatures
    pset.inputs_mut()[1]
        .partial_sigs
        .insert(inp1_pk, inp1_sig.clone());
    assert_eq!(pset, deser_pset(&tests["blinded_signed"]));

    // Finalize(TODO in miniscript)
    pset.inputs_mut()[0].partial_sigs.clear();
    pset.inputs_mut()[0].final_script_witness = Some(vec![
        inp0_sig,
        inp0_pk.to_bytes(),
    ]);
    pset.inputs_mut()[1].partial_sigs.clear();
    pset.inputs_mut()[1].final_script_witness = Some(vec![
        inp1_sig,
        inp1_pk.to_bytes(),
    ]);
    assert_eq!(pset, deser_pset(&tests["finalized"]));

    // Extracted tx
    let tx = pset.extract_tx().unwrap();
    assert_eq!(serialize_hex(&tx), tests["extracted_tx"]);
}
