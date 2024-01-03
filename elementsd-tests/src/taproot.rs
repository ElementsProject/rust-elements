extern crate elements;

extern crate elementsd;
extern crate rand;

use crate::{Call, setup};

use bitcoin::key::{XOnlyPublicKey, Keypair};
use bitcoin::Amount;
use elements::hex::FromHex;
use elements::confidential::{AssetBlindingFactor, ValueBlindingFactor};
use elements::encode::{deserialize, serialize_hex};
use elements::hashes::Hash;
use elements::script::Builder;
use elements::secp256k1_zkp;
use elements::sighash::{self, SighashCache};
use elements::taproot::{LeafVersion, TapTweakHash, TaprootBuilder, TaprootSpendInfo, TapLeafHash};
use elements::OutPoint;
use elements::{
    confidential, opcodes, AssetIssuance, BlockHash, LockTime, SchnorrSig, SchnorrSighashType, Script,
    Sequence, TxInWitness, TxOut, Txid,
};
use elements::{AddressParams, Transaction, TxIn, TxOutSecrets};
use elementsd::ElementsD;
use rand::{rngs, thread_rng};
use secp256k1_zkp::Secp256k1;
use std::str::FromStr;

static PARAMS: AddressParams = AddressParams::ELEMENTS;

fn gen_keypair(
    secp: &secp256k1_zkp::Secp256k1<secp256k1_zkp::All>,
    rng: &mut rngs::ThreadRng,
) -> (XOnlyPublicKey, Keypair) {
    let keypair = Keypair::new(secp, rng);
    let (pk, _) = XOnlyPublicKey::from_keypair(&keypair);
    (pk, keypair)
}

// Spend data for txout with 2 leaves
#[derive(Debug)]
struct TapTxOutData {
    _blind_sk: Option<secp256k1_zkp::SecretKey>,
    _blind_pk: Option<secp256k1_zkp::PublicKey>,
    leaf1_keypair: Keypair,
    _leaf1_pk: XOnlyPublicKey,
    leaf1_script: Script,
    internal_keypair: Keypair,
    internal_pk: XOnlyPublicKey,
    spend_info: TaprootSpendInfo,
    utxo: TxOut,
    prevout: OutPoint,
    txout_secrets: TxOutSecrets,
}

fn funded_tap_txout(
    elementsd: &ElementsD,
    secp: &secp256k1_zkp::Secp256k1<secp256k1_zkp::All>,
    blind: bool,
) -> TapTxOutData {
    // Create a script pub key with a given spendinfo
    let builder = TaprootBuilder::new();
    let leaf1_script_builder = Builder::new();
    let leaf2_script_builder = Builder::new();

    let (leaf1_pk, leaf1_keypair) = gen_keypair(secp, &mut thread_rng());
    let (leaf2_pk, _leaf2_keypair) = gen_keypair(secp, &mut thread_rng());
    let (internal_pk, internal_keypair) = gen_keypair(secp, &mut thread_rng());

    let (blind_sk, blind_pk) = if blind {
        let sk = secp256k1_zkp::SecretKey::new(&mut thread_rng());
        let pk = secp256k1_zkp::PublicKey::from_secret_key(&secp, &sk);
        (Some(sk), Some(pk))
    } else {
        (None, None)
    };

    let leaf1_script = leaf1_script_builder
        .push_slice(&leaf1_pk.serialize())
        .push_opcode(opcodes::all::OP_CHECKSIG)
        .into_script();
    let leaf2_script = leaf2_script_builder
        .push_slice(&leaf2_pk.serialize())
        .push_opcode(opcodes::all::OP_CHECKSIG)
        .into_script();
    #[rustfmt::skip]
    let spend_info = builder
        .add_leaf(1, leaf1_script.clone()).unwrap()
        .add_leaf(1, leaf2_script).unwrap()
        .finalize(secp, internal_pk).unwrap();

    let addr = elements::Address::p2tr(
        secp,
        spend_info.internal_key(),
        spend_info.merkle_root(),
        blind_pk,
        &PARAMS,
    );
    let amt = Amount::from_sat(1_000_000);
    let txid_hex = elementsd.send_to_address(&addr.to_string(), &amt.to_btc().to_string());
    elementsd.generate(1);
    let tx_hex = elementsd.get_transaction(&txid_hex);

    let tx = deserialize::<Transaction>(&Vec::<u8>::from_hex(&tx_hex).unwrap()).unwrap();

    let mut outpoint: Option<OutPoint> = None;
    for (i, out) in tx.output.iter().enumerate() {
        if addr.script_pubkey() == out.script_pubkey {
            outpoint = Some(OutPoint::new(tx.txid(), i as u32));
            break;
        }
    }

    let prevout = outpoint.expect("Outpoint must exist in tx");

    // If txout was blinded, try to unblind it
    let out = &tx.output[prevout.vout as usize];
    let txout_secrets = if blind {
        out.unblind(secp, blind_sk.unwrap()).unwrap()
    } else {
        TxOutSecrets {
            asset: out.asset.explicit().unwrap(),
            asset_bf: AssetBlindingFactor::zero(),
            value: out.value.explicit().unwrap(),
            value_bf: ValueBlindingFactor::zero(),
        }
    };
    TapTxOutData {
        _blind_sk: blind_sk,
        _blind_pk: blind_pk,
        leaf1_keypair,
        _leaf1_pk: leaf1_pk,
        leaf1_script,
        internal_keypair,
        internal_pk,
        spend_info,
        utxo: tx.output[prevout.vout as usize].clone(),
        prevout,
        txout_secrets,
    }
}

fn taproot_spend_test(
    elementsd: &ElementsD,
    secp: &Secp256k1<secp256k1_zkp::All>,
    genesis_hash: BlockHash,
    sighash_ty: SchnorrSighashType,
    blind_prevout: bool,
    blind_tx: bool,
    key_spend: bool,
) {
    let test_data = funded_tap_txout(&elementsd, &secp, blind_prevout);

    // create a new spend that spends the above output
    let mut tx = Transaction {
        version: 2,
        lock_time: LockTime::ZERO,
        input: vec![],
        output: vec![],
    };
    let inp = TxIn {
        previous_output: test_data.prevout,
        is_pegin: false,
        script_sig: Script::new(),
        sequence: Sequence::MAX,
        asset_issuance: AssetIssuance::default(),
        witness: TxInWitness::default(),
    };
    tx.input.push(inp);
    // create two outputs
    // 1) Same as the one we are spending but with lesser amount as some go to fees
    let fees = 1_000; // hardcoded 1000 sat fees
    let btc_asset = test_data.txout_secrets.asset;
    let dest_amt = test_data.txout_secrets.value;
    let mut out1 = test_data.utxo.clone();
    out1.value = confidential::Value::Explicit(dest_amt - fees);
    out1.asset = confidential::Asset::Explicit(btc_asset);
    let fees_out = TxOut::new_fee(fees, btc_asset);
    tx.output.push(out1);
    tx.output.push(fees_out);

    if blind_tx {
        // set the nNonce as some confidential key to mark the output for blinding
        let sk = secp256k1_zkp::SecretKey::new(&mut thread_rng());
        let pk = secp256k1_zkp::PublicKey::from_secret_key(&secp, &sk);
        tx.output[0].nonce = confidential::Nonce::Confidential(pk);
        tx.blind(
            &mut thread_rng(),
            &secp,
            &[test_data.txout_secrets],
            false
        )
        .unwrap();
    }

    let mut cache = SighashCache::new(&tx);

    if key_spend {
        // test key spend
        let sighash_msg = cache
            .taproot_sighash(
                0, // input index
                &sighash::Prevouts::All(&[test_data.utxo]),
                None,       // annex
                None,       // none
                sighash_ty, // sighash_ty
                genesis_hash,
            )
            .unwrap();

        let output_keypair = test_data.internal_keypair; // type is copy
        let tweak = TapTweakHash::from_key_and_tweak(
            test_data.internal_pk,
            test_data.spend_info.merkle_root(),
        );
        let tweak = secp256k1_zkp::Scalar::from_be_bytes(tweak.to_byte_array()).expect("hash value greater than curve order");
        let sig = secp.sign_schnorr(
            &secp256k1_zkp::Message::from_digest_slice(&sighash_msg[..]).unwrap(),
            &output_keypair.add_xonly_tweak(&secp, &tweak).unwrap(),
        );

        let schnorr_sig = SchnorrSig {
            sig: sig,
            hash_ty: sighash_ty,
        };

        tx.input[0].witness.script_witness = vec![schnorr_sig.to_vec()];
    } else {
        // script spend
        // try spending using leaf1
        let sighash_msg = cache
            .taproot_script_spend_signature_hash(
                0, // input index
                &sighash::Prevouts::All(&[test_data.utxo]),
                TapLeafHash::from(sighash::ScriptPath::with_defaults(&test_data.leaf1_script)),
                sighash_ty, // sighash_ty
                genesis_hash,
            )
            .unwrap();

        let sig = secp.sign_schnorr(
            &secp256k1_zkp::Message::from_digest_slice(&sighash_msg[..]).unwrap(),
            &test_data.leaf1_keypair,
        );

        let script_ver = (test_data.leaf1_script, LeafVersion::default());
        let ctrl_block = test_data.spend_info.control_block(&script_ver).unwrap();

        let schnorr_sig = SchnorrSig {
            sig: sig,
            hash_ty: sighash_ty,
        };

        tx.input[0].witness.script_witness = vec![
            schnorr_sig.to_vec(), // witness
            script_ver.0.into_bytes(), // leaf script
            ctrl_block.serialize(), // control block
        ];
    }

    let tx_hex = serialize_hex(&tx);
    assert!(elementsd.test_mempool_accept(&tx_hex));
    let tx_str = elementsd.send_raw_transaction(&tx_hex);
    assert!(Txid::from_str(&tx_str).is_ok());
}

#[test]
fn taproot_tests() {
    let (elementsd, _bitcoind) = setup(false);
    let secp = secp256k1_zkp::Secp256k1::new();

    // lookup genesis hash required for sighash computation
    let genesis_hash_str = elementsd.get_block_hash(0);
    let genesis_hash = BlockHash::from_str(&genesis_hash_str).unwrap();

    let sighash_tys = [
        SchnorrSighashType::Default,
        SchnorrSighashType::Single,
        SchnorrSighashType::SinglePlusAnyoneCanPay,
        SchnorrSighashType::None,
        SchnorrSighashType::NonePlusAnyoneCanPay,
        SchnorrSighashType::All,
        SchnorrSighashType::AllPlusAnyoneCanPay,
    ];

    for &conf_prevout in &[true, false] {
        // whether the input is blinded
        for &blind in &[true, false] {
            // blind the current tx
            if !blind && conf_prevout {
                // trying to spend a confidential txout to all explicit transactions
                // This is not possible to do because we need to balance the blinding factors
                continue;
            }
            for &script_spend in &[true, false] {
                for &sighash_ty in &sighash_tys {
                    taproot_spend_test(
                        &elementsd,
                        &secp,
                        genesis_hash,
                        sighash_ty,
                        conf_prevout,
                        blind,
                        script_spend,
                    );
                }
            }
        }
    }
}

