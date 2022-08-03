//! PSET coinjoin example
//! 1. Person `A` create a transcation with 1 input and 3 outputs(1 fee output)
//! 2. Person `B` takes the transcation from A and adds one input and two outputs
//!    which transact another confidential asset
//! 3. Person `B` blinds it's own outputs and gives the pset back to A
//! 4. B completly blinds the transaction
//! 5. B signs the blinded Transaction and sends it back to A
//! 6. A signs it's input
//! 7. A finalizes the pset
//! 8. A extracts and broadcasts the transaction
//! During the entire interaction, the output blinding factors for A and B are not
//! shared with each other.
extern crate bitcoin;
extern crate elements;
extern crate rand;
extern crate serde_json;

use std::{collections::HashMap, str::FromStr};

use elements::confidential::{AssetBlindingFactor, ValueBlindingFactor};
use elements::{
    bitcoin::PublicKey, pset::PartiallySignedTransaction as Pset, OutPoint,
    Script, TxOutSecrets, TxOutWitness, Txid, WScriptHash,
};
use elements::{pset, secp256k1_zkp};

use elements::encode::{deserialize, serialize_hex};
use elements::hashes::hex::FromHex;
use elements::{confidential, AssetId, TxOut};
use rand::SeedableRng;

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
        "txid": "55855ab698631f8dc9c11aaa299fbd62f05869b082ecb14395372a6c6e95ff7a",
        "vout": 1,
        "scriptPubKey": "0014011d384302576b408aa3686db874e2b17cc2b01b",
        "amount": "10.00000000",
        "assetcommitment": "0ac55f449ddb6853f2508766d5afb9f3b45e41a8ef5368cad75fb88e5e249395d1",
        "asset": "4fa41f2929d4bf6975a55967d9da5b650b6b9bfddeae4d7b54b04394be328f7f",
        "amountcommitment": "097d88c92ca814a207f73441c56cee943f0bb2556da194c14a4b912b078c2238ae",
        "amountblinder": "bcfa96f8068c91cf7b80c197066d1fc0d756606bf6666c9f78e120a653b7d13e",
        "assetblinder": "f4ba5cf033c0557bbaab295a057a87c943f3639a05a62bef37f29dc18aa45886",
        "commitmentnonce": "025341cb5e4e2d8cb69e694cb20e5ea4cc8ddf2801180096fd071addfcd8bc4445",
        "skwif": "cU52mfNAru457o7DQmmb1TpkNasXmg63QLPH1F94LEZSzJe2uK3V"
    }"#;

    let btc_txout = r#"
    {
        "txid": "70478b6898407362d43e9e56fd72a89b0556ac2593ed6e025c16376bba315180",
        "vout": 0,
        "scriptPubKey": "0014d2cbec8783bd01c9f178348b08500a830a89a7f9",
        "amount": "2.30000000",
        "assetcommitment": "0bb9325c276764451bbc2eb82a4c8c4bb6f4007ba803e5a5ba72d0cd7c09848e1a",
        "asset": "b2e15d0d7a0c94e4e2ce0fe6e8691b9e451377f6e46e8045a86f7c4b5d4f0f23",
        "amountcommitment": "091622d935953bf06e0b7393239c68c6f810a00fe19d11c6ae343cffd3037077da",
        "amountblinder": "0f155ac96c49e39c0501e3448e9aac89f5b43c16bf9156e6c1694e310c80f374",
        "assetblinder": "de6ecd62ab6fc66597b2144f38c3be873ba583970aacdfcc8978a1a0b6cb872c",
        "commitmentnonce": "02535fe4ad0fcd675cd0f62bf73b60a554dc1569b80f1f76a2bbfc9f00d439bf4b",
        "skwif": "cRrq6NyygXvNBHW7ozK6b33F1qZqbNbKTVtTSQph947jgPKN8WCH"
      }"#;

    [parse_txout(btc_txout), parse_txout(asset_txout)]
}

fn test_data() -> HashMap<String, String> {
    let mut tests = HashMap::new();
    tests.insert(
        String::from("empty"),
        String::from("70736574ff01020402000000010401000105010001fb040200000000"),
    );
    tests.insert(String::from("A_pset_unblinded") , String::from("70736574ff01020402000000010401010105010301fb04020000000001017a0bb9325c276764451bbc2eb82a4c8c4bb6f4007ba803e5a5ba72d0cd7c09848e1a091622d935953bf06e0b7393239c68c6f810a00fe19d11c6ae343cffd3037077da02535fe4ad0fcd675cd0f62bf73b60a554dc1569b80f1f76a2bbfc9f00d439bf4b160014d2cbec8783bd01c9f178348b08500a830a89a7f9010e20805131ba6b37165c026eed9325ac56059ba872fd569e3ed462734098688b4770010f04000000000001030820a107000000000007fc04707365740220230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b20104220020e5793ad956ee91ebf3543b37d110701118ed4078ffa0d477eacb8885e486ad8507fc047073657406210212bf0ea45b733dfde8ecb5e896306c4165c666c99fc5d1ab887f71393a975cea07fc0470736574080400000000000103086ce2ad0d0000000007fc04707365740220230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b20104220020f6b43d56e004e9d0b1ec2fc3c95511d81af08420992be8dec7f86cdf8970b3e207fc04707365740621027d07ae478c0aa607321643cb5e8ed59ee1f5ff4d9d55efedec066ccb1f5d537d07fc047073657408040000000000010308f40100000000000007fc04707365740220230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b201040000"));
    tests.insert(String::from("pset_coinjoined_unblinded") , String::from("70736574ff01020402000000010401020105010501fb04020000000001017a0bb9325c276764451bbc2eb82a4c8c4bb6f4007ba803e5a5ba72d0cd7c09848e1a091622d935953bf06e0b7393239c68c6f810a00fe19d11c6ae343cffd3037077da02535fe4ad0fcd675cd0f62bf73b60a554dc1569b80f1f76a2bbfc9f00d439bf4b160014d2cbec8783bd01c9f178348b08500a830a89a7f9010e20805131ba6b37165c026eed9325ac56059ba872fd569e3ed462734098688b4770010f04000000000001017a0ac55f449ddb6853f2508766d5afb9f3b45e41a8ef5368cad75fb88e5e249395d1097d88c92ca814a207f73441c56cee943f0bb2556da194c14a4b912b078c2238ae025341cb5e4e2d8cb69e694cb20e5ea4cc8ddf2801180096fd071addfcd8bc4445160014011d384302576b408aa3686db874e2b17cc2b01b010e207aff956e6c2a379543b1ec82b06958f062bd9f29aa1ac1c98d1f6398b65a8555010f04010000000001030820a107000000000007fc04707365740220230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b20104220020e5793ad956ee91ebf3543b37d110701118ed4078ffa0d477eacb8885e486ad8507fc047073657406210212bf0ea45b733dfde8ecb5e896306c4165c666c99fc5d1ab887f71393a975cea07fc0470736574080400000000000103086ce2ad0d0000000007fc04707365740220230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b20104220020f6b43d56e004e9d0b1ec2fc3c95511d81af08420992be8dec7f86cdf8970b3e207fc04707365740621027d07ae478c0aa607321643cb5e8ed59ee1f5ff4d9d55efedec066ccb1f5d537d07fc047073657408040000000000010308f40100000000000007fc04707365740220230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b20104000001030840420f000000000007fc047073657402207f8f32be9443b0547b4daedefd9b6b0b655bdad96759a57569bfd429291fa44f010422002037831b3ee29fc96f8e61ccb98fbe2dcb03e189dd29cfecc691b5a7442d8548e807fc0470736574062103d559d2a5a4180f418a69c4bed5508971cda9313722fff71e053d3d82fee9d7bd07fc047073657408040100000000010308c0878b3b0000000007fc047073657402207f8f32be9443b0547b4daedefd9b6b0b655bdad96759a57569bfd429291fa44f0104220020e7da55d19cc85b0420c539a90b667d4d85f59ee0ed417493a947c3a2256cc0aa07fc04707365740621029e5980b4f9b9a9fd568c1c4b48631a800c310405ae8b2ac41ddaf87add3062f107fc047073657408040100000000"));
    tests.insert(String::from("pset_coinjoined_B_blinded") , include_str!("test_vector/pset_blind_coinjoin/pset_coinjoined_B_blinded.hex").to_string());
    tests.insert(String::from("pset_coinjoined_blinded") , include_str!("test_vector/pset_blind_coinjoin/pset_coinjoined_blinded.hex").to_string());
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
    assert_eq!(serialize_hex(&pset), tests["empty"]);

    // Add the btc asset input
    let mut btc_inp = btc_inp;
    btc_inp.witness_utxo = Some(btc_txout.clone());
    pset.add_input(btc_inp);

    // Create the first txout
    let dest_btc_wsh =
        WScriptHash::from_str("e5793ad956ee91ebf3543b37d110701118ed4078ffa0d477eacb8885e486ad85")
            .unwrap();
    let dest_btc_amt = 500_000; // sat
    let dest_btc_blind_pk =
        PublicKey::from_str("0212bf0ea45b733dfde8ecb5e896306c4165c666c99fc5d1ab887f71393a975cea")
            .unwrap();
    let dest_btc_txout = TxOut {
        asset: confidential::Asset::Explicit(btc_txout_secrets.sec.asset),
        value: confidential::Value::Explicit(dest_btc_amt),
        nonce: confidential::Nonce::Confidential(dest_btc_blind_pk.inner),
        script_pubkey: Script::new_v0_wsh(&dest_btc_wsh),
        witness: TxOutWitness::default(),
    };

    // Create the change txout
    let btc_fees_amt = 500; // sat
    let change_amt = btc_txout_secrets.sec.value - dest_btc_amt - btc_fees_amt;
    let change_btc_blind_pk =
        PublicKey::from_str("027d07ae478c0aa607321643cb5e8ed59ee1f5ff4d9d55efedec066ccb1f5d537d")
            .unwrap();
    let change_btc_wsh =
        WScriptHash::from_str("f6b43d56e004e9d0b1ec2fc3c95511d81af08420992be8dec7f86cdf8970b3e2")
            .unwrap();
    let change_btc_txout = TxOut {
        asset: confidential::Asset::Explicit(btc_txout_secrets.sec.asset),
        value: confidential::Value::Explicit(change_amt),
        nonce: confidential::Nonce::Confidential(change_btc_blind_pk.inner),
        script_pubkey: Script::new_v0_wsh(&change_btc_wsh),
        witness: TxOutWitness::default(),
    };

    // Create the fee txout
    let btc_fees_txout = TxOut::new_fee(btc_fees_amt, btc_txout_secrets.sec.asset);

    pset.add_output(pset::Output::from_txout(dest_btc_txout));
    pset.add_output(pset::Output::from_txout(change_btc_txout));
    pset.add_output(pset::Output::from_txout(btc_fees_txout));

    // Mark owned outputs for blinding later
    // This tells that person that controls input zero is responsible for
    // blinding outputs 0, 1
    // Output 2 is the fees output
    pset.outputs_mut()[0].blinding_key = Some(dest_btc_blind_pk);
    pset.outputs_mut()[0].blinder_index = Some(0);
    pset.outputs_mut()[1].blinding_key = Some(change_btc_blind_pk);
    pset.outputs_mut()[1].blinder_index = Some(0);

    // pset after adding the information about the bitcoin input from A
    // Pset with 2 input and 3 outputs
    assert_eq!(pset, deser_pset(&tests["A_pset_unblinded"]));
    // ----------------------------------------------------------
    // Party A sends unblinded pset to B. Step 1 completed

    // Add the asset input
    let mut asset_inp = asset_inp;
    asset_inp.witness_utxo = Some(asset_txout.clone());
    pset.add_input(asset_inp);

    // Add outputs
    // Send 5_000 worth of asset units to new address
    // Create the first asset txout(fourth output)
    let dest_asset_wsh =
        WScriptHash::from_str("37831b3ee29fc96f8e61ccb98fbe2dcb03e189dd29cfecc691b5a7442d8548e8")
            .unwrap();
    let dest_asset_amt = 1_000_000; // sat
    let dest_asset_blind_pk =
        PublicKey::from_str("03d559d2a5a4180f418a69c4bed5508971cda9313722fff71e053d3d82fee9d7bd")
            .unwrap();
    let dest_asset_txout = TxOut {
        asset: confidential::Asset::Explicit(asset_txout_secrets.sec.asset),
        value: confidential::Value::Explicit(dest_asset_amt),
        nonce: confidential::Nonce::Confidential(dest_asset_blind_pk.inner),
        script_pubkey: Script::new_v0_wsh(&dest_asset_wsh),
        witness: TxOutWitness::default(),
    };

    // Create the change txout
    let change_asset_amt = asset_txout_secrets.sec.value - dest_asset_amt;
    let change_asset_blind_pk =
        PublicKey::from_str("029e5980b4f9b9a9fd568c1c4b48631a800c310405ae8b2ac41ddaf87add3062f1")
            .unwrap();
    let change_asset_wsh =
        WScriptHash::from_str("e7da55d19cc85b0420c539a90b667d4d85f59ee0ed417493a947c3a2256cc0aa")
            .unwrap();
    let change_asset_txout = TxOut {
        asset: confidential::Asset::Explicit(asset_txout_secrets.sec.asset),
        value: confidential::Value::Explicit(change_asset_amt),
        nonce: confidential::Nonce::Confidential(change_asset_blind_pk.inner),
        script_pubkey: Script::new_v0_wsh(&change_asset_wsh),
        witness: TxOutWitness::default(),
    };

    // Add the outputs
    pset.add_output(pset::Output::from_txout(dest_asset_txout));
    pset.add_output(pset::Output::from_txout(change_asset_txout));

    // This tells that person that controls input index one is responsible for
    // blinding outputs 3, 4.
    pset.outputs_mut()[3].blinding_key = Some(dest_asset_blind_pk);
    pset.outputs_mut()[3].blinder_index = Some(1);
    pset.outputs_mut()[4].blinding_key = Some(change_asset_blind_pk);
    pset.outputs_mut()[4].blinder_index = Some(1);

    // pset after adding the information about the bitcoin input from A
    // and adding B's input. Two inputs and 5 outputs
    assert_eq!(pset, deser_pset(&tests["pset_coinjoined_unblinded"]));
    // ----------------------------------------------------------
    // B Adds it's own outputs. Step 2 completed
    // ----- Step 3: B to blind it's own outputs
    let mut inp_txout_sec = HashMap::new();
    inp_txout_sec.insert(1, asset_txout_secrets.sec);

    pset.blind_non_last(&mut rng, &secp, &inp_txout_sec).unwrap();
    assert_eq!(pset, deser_pset(&tests["pset_coinjoined_B_blinded"]));

    // Step 4: A blinds it's own inputs
    let mut inp_txout_sec_a = HashMap::new();
    inp_txout_sec_a.insert(0, btc_txout_secrets.sec);
    pset.blind_last(&mut rng, &secp, &inp_txout_sec_a).unwrap();
    assert_eq!(pset, deser_pset(&tests["pset_coinjoined_blinded"]));

    // check whether the blinding was correct
    // Verify the balance checks
    let tx = pset.extract_tx().unwrap();
    // println!("{}", serialize_hex(&tx));
    tx.verify_tx_amt_proofs(&secp, &[btc_txout, asset_txout])
        .unwrap();
}
