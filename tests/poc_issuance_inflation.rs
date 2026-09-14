//! Regression tests for unverified confidential issuance amount rangeproofs:
//! `Transaction::verify_tx_amt_proofs` used to push confidential *issuance*
//! amount commitments into the balance sum without verifying any rangeproof,
//! leaving an unconstrained term that made the value-conservation check
//! vacuous for any transaction carrying an issuance.
//!
//! - `forged_issuance_amount_is_rejected` reproduces the attack: 1 L-BTC in,
//!   100 L-BTC out, with the 99 L-BTC gap supplied by a bare curve point equal
//!   to 99 times the L-BTC generator in `asset_issuance.amount` and no
//!   rangeproof. Verification must now fail.
//! - `blinded_issuance_amount_still_verifies` is the positive control: a
//!   properly blinded issuance amount (rangeproof present, produced by the
//!   crate's own blinding code) still verifies, so the fix does not break
//!   legitimate issuances.

use elements::confidential::{Asset, Nonce, Value};
use elements::{
    AssetBlindingNonce, AssetEntropy, AssetId, AssetIssuance, LockTime, OutPoint, Script,
    Transaction, TxIn, TxOut, TxOutWitness, VerificationError,
};
use secp256k1_zkp::{Generator, PedersenCommitment, Secp256k1};

fn txout(asset: Asset, value: Value) -> TxOut {
    TxOut {
        asset,
        value,
        nonce: Nonce::Null,
        script_pubkey: Script::new(),
        witness: TxOutWitness::default(),
    }
}

#[test]
fn forged_issuance_amount_is_rejected() {
    let secp = Secp256k1::new();
    let asset = AssetId::LIQUID_BTC;

    // Honest spent UTXO: 1 L-BTC, explicit (so its commitment is 1*G_LBTC).
    let spent_utxo = txout(Asset::Explicit(asset), Value::Explicit(1));

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
    let tx = Transaction {
        version: 2,
        lock_time: LockTime::ZERO,
        input: vec![input],
        output: vec![txout(Asset::Explicit(asset), Value::Explicit(100))],
    };

    // Before the fix this returned Ok(()) and the tx minted 99 L-BTC.
    assert_eq!(
        tx.verify_tx_amt_proofs(&secp, std::slice::from_ref(&spent_utxo)),
        Err(VerificationError::RangeProofMissing(0)),
        "forged confidential issuance amount must not be accepted"
    );

    // Non-vacuity control: the same tx with the forged issuance removed still
    // fails the aggregate balance check (1 in, 100 out).
    let mut control = tx.clone();
    control.input[0].asset_issuance.amount = Value::Null;
    assert_eq!(
        control.verify_tx_amt_proofs(&secp, &[spent_utxo]),
        Err(VerificationError::BalanceCheckFailed),
        "control tx without the forged issuance should fail the balance check"
    );
}

#[test]
fn blinded_issuance_amount_still_verifies() {
    use elements::confidential::ValueBlindingFactor;
    use rand::thread_rng;
    use secp256k1_zkp::SecretKey;

    let secp = Secp256k1::new();
    let asset = AssetId::LIQUID_BTC;

    let spent_utxo = txout(Asset::Explicit(asset), Value::Explicit(1));

    let mut input = TxIn {
        previous_output: OutPoint::default(),
        asset_issuance: AssetIssuance {
            asset_blinding_nonce: AssetBlindingNonce::NEW_ISSUANCE,
            asset_entropy: AssetEntropy::NEW_ISSUANCE,
            amount: Value::Explicit(10),
            inflation_keys: Value::Null,
        },
        ..Default::default()
    };

    // Blind the issuance amount: this turns it into a confidential commitment
    // and generates the accompanying rangeproof. A zero blinding factor keeps
    // the balance simple (explicit outputs of 1 L-BTC + 10 of the new asset).
    let mut rng = thread_rng();
    input
        .blind_issuances_with_bfs(
            &secp,
            ValueBlindingFactor::zero(),
            ValueBlindingFactor::zero(),
            SecretKey::new(&mut rng),
            SecretKey::new(&mut rng),
        )
        .unwrap();
    assert!(input.asset_issuance.amount.is_confidential());

    let (issued_asset, _token) = input.issuance_ids();

    let tx = Transaction {
        version: 2,
        lock_time: LockTime::ZERO,
        input: vec![input],
        output: vec![
            txout(Asset::Explicit(asset), Value::Explicit(1)),
            txout(Asset::Explicit(issued_asset), Value::Explicit(10)),
        ],
    };

    tx.verify_tx_amt_proofs(&secp, &[spent_utxo])
        .expect("a legitimately blinded issuance amount must still verify");
}
