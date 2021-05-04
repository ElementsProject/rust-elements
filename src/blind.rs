// Rust Elements Library
// Written in 2018 by
//   Sanket K <sanket1729@blockstream.com>
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

//! # Transactions Blinding
//!

use std::{self, fmt};

use secp256k1_zkp::{self, PedersenCommitment, rand::{CryptoRng, RngCore}};
use secp256k1_zkp::{Generator, RangeProof, Secp256k1, Signing, SurjectionProof};

use {Address, AssetId, ConfidentialTxOutError, Transaction, TxOut,
    TxOutWitness, confidential::{Asset, AssetBlindingFactor, Nonce, Value,
    ValueBlindingFactor
}};


#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TxOutError {
    /// Unexpected Null Value
    UnExpectedNullValue,
    /// Unexpected Null asset
    UnExpectedNullAsset,
    /// Money should be between 0 and 21_000_000
    MoneyOutofRange,
    /// Zero value explicit txout with non-provably unspendable script
    NonUnspendableZeroValue,
    /// Zero value pedersen commitment with provably unspendable script
    ZeroValueCommitment,
}

impl std::error::Error for TxOutError {}

impl fmt::Display for TxOutError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            TxOutError::UnExpectedNullValue => write!(f, "UnExpected Null Value"),
            TxOutError::UnExpectedNullAsset => write!(f, "UnExpected Null Asset"),
            TxOutError::MoneyOutofRange => write!(f, "Explicit amount must be\
                less than 21 million"),
            TxOutError::NonUnspendableZeroValue => {
                write!(f, "Zero value explicit amounts must be provably unspendable.\
                    See IsUnspendable in elements")
            }
            TxOutError::ZeroValueCommitment => {
                write!(f, "Tried to create pedersen commitment with zero value.\
                    Zero value is only allowed for provable unspendable scripts,
                    in which case the verification check can ignore the txout")
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VerificationError {
    /// Verification of rangeproof failed
    RangeProofError(usize, secp256k1_zkp::Error),
    /// Missing Range Proof
    RangeProofMissing(usize),
    /// Verification of SurjectionProof failed
    SurjectionProofError(usize, secp256k1_zkp::Error),
    /// Surjection Proof verification error
    SurjectionProofVerificationError(usize),
    /// Missing Range Proof
    SurjectionProofMissing(usize),
    /// Spent Txout error
    SpentTxOutError(usize, TxOutError),
    /// Current transaction txout error
    TxOutError(usize, TxOutError),
    /// Issuance transaction verification not supported yet
    IssuanceTransactionInput(usize),
    /// Spent input len must match the len of transaction input
    UtxoInputLenMismatch,
    /// Balance Check failed
    BalanceCheckFailed,
}

impl fmt::Display for VerificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VerificationError::RangeProofError(i, e) => {
                write!(f, "Rangeproof Error {} : for output index {}", i, e)
            }
            VerificationError::SurjectionProofError(i, e) => {
                write!(f, "Surjection Proof Error {} : for output index {}", i, e)
            }
            VerificationError::SurjectionProofVerificationError(i) => {
                write!(f, "Surjection proof verification failed for output index {}", i)
            }
            VerificationError::IssuanceTransactionInput(i) => {
                write!(f, "Issuance transaction input {} not supported yet", i)
            }
            VerificationError::UtxoInputLenMismatch => {
                write!(f, "Utxo len must match the len of transaction inputs")
            }
            VerificationError::SpentTxOutError(i, e) => {
                write!(f, "Input index {} spent utxo error: {}", i, e)
            }
            VerificationError::TxOutError(i, e) => {
                write!(f, "Output index {} txout: {}", i, e)
            }
            VerificationError::BalanceCheckFailed => {
                write!(f, "Confidential transaction verification balance check failed")
            }
            VerificationError::RangeProofMissing(i) => {
                write!(f, "Missing Rangeproof for output index {}", i)
            }
            VerificationError::SurjectionProofMissing(i) => {
                write!(f, "Missing Surjection Proof for output index {}", i)
            }
        }
    }
}

impl std::error::Error for VerificationError {}
/// The Rangeproof message
struct RangeProofMessage {
    asset: AssetId,
    bf: AssetBlindingFactor,
}

impl RangeProofMessage {
    fn to_bytes(&self) -> [u8; 64] {
        let mut message = [0u8; 64];

        message[..32].copy_from_slice(self.asset.into_tag().as_ref());
        message[32..].copy_from_slice(self.bf.into_inner().as_ref());

        message
    }
}

impl TxOut {
    const RANGEPROOF_MIN_VALUE: u64 = 1;
    const RANGEPROOF_EXP_SHIFT: i32 = 0;
    const RANGEPROOF_MIN_PRIV_BITS: u8 = 52;
    const MAX_MONEY: u64 = 21_000_000 * 100_000_000;

    /// Creates a new confidential output that is **not** the last one in the transaction.
    pub fn new_not_last_confidential<R, C>(
        rng: &mut R,
        secp: &Secp256k1<C>,
        value: u64,
        address: Address,
        asset: AssetId,
        inputs: &[(
            AssetId,
            u64,
            Option<Generator>,
            AssetBlindingFactor,
            ValueBlindingFactor,
        )],
    ) -> Result<(Self, AssetBlindingFactor, ValueBlindingFactor), ConfidentialTxOutError>
    where
        R: RngCore + CryptoRng,
        C: Signing,
    {
        let out_abf = AssetBlindingFactor::new(rng);
        let out_asset = Asset::new_confidential(secp, asset, out_abf);

        let out_asset_commitment = out_asset.commitment().expect("confidential asset");
        let out_vbf = ValueBlindingFactor::new(rng);
        let value_commitment = Value::new_confidential(secp, value, out_asset_commitment, out_vbf);

        let receiver_blinding_pk = &address
            .blinding_pubkey
            .ok_or(ConfidentialTxOutError::NoBlindingKeyInAddress)?;
        let (nonce, shared_secret) = Nonce::new_confidential(rng, secp, receiver_blinding_pk);

        let message = RangeProofMessage { asset, bf: out_abf };
        let rangeproof = RangeProof::new(
            secp,
            Self::RANGEPROOF_MIN_VALUE,
            value_commitment.commitment().expect("confidential value"),
            value,
            out_vbf.0,
            &message.to_bytes(),
            address.script_pubkey().as_bytes(),
            shared_secret,
            Self::RANGEPROOF_EXP_SHIFT,
            Self::RANGEPROOF_MIN_PRIV_BITS,
            out_asset_commitment,
        )?;

        let inputs = inputs
            .iter()
            .map(|(id, _, asset, abf, _)| {
                let asset = asset.as_ref().map(|x| *x)
                .unwrap_or_else(|| Generator::new_blinded(secp, id.into_tag(), abf.into_inner()));
                (asset, id.into_tag(), abf.0)
            })
            .collect::<Vec<_>>();

        let surjection_proof = SurjectionProof::new(
            secp,
            rng,
            asset.into_tag(),
            out_abf.into_inner(),
            inputs.as_ref(),
        )?;

        let txout = TxOut {
            asset: out_asset,
            value: value_commitment,
            nonce,
            script_pubkey: address.script_pubkey(),
            witness: TxOutWitness {
                surjection_proof: Some(surjection_proof),
                rangeproof: Some(rangeproof),
            },
        };

        Ok((txout, out_abf, out_vbf))
    }

        // Internally used function for getting the generator from asset
    // Used in the amount verification check
    fn get_asset_gen<C: secp256k1_zkp::Signing> (
        &self,
        secp: &Secp256k1<C>,
    ) -> Result<Generator, TxOutError> {
        self.asset.into_asset_gen(secp).ok_or(TxOutError::UnExpectedNullAsset)
    }

    // Get the pedersen commitment for the txout. Used internally
    // in tx verification.
    fn get_value_commit<C: secp256k1_zkp::Signing> (
        &self,
        secp: &Secp256k1<C>,
    ) -> Result<PedersenCommitment, TxOutError> {
        // Only error is Null error which is dealt with later
        // when we have more context information about it.
        match self.value {
            Value::Null => return Err(TxOutError::UnExpectedNullValue),
            Value::Explicit(value) => {
                if value > Self::MAX_MONEY {
                    return Err(TxOutError::MoneyOutofRange)
                }
                if value == 0 {
                    // zero values are only allowed if they are provably
                    // unspendable.
                    if self.script_pubkey.is_provably_unspendable() {
                        return Err(TxOutError::ZeroValueCommitment)
                    } else {
                        return Err(TxOutError::NonUnspendableZeroValue)
                    }
                }
                let asset_comm = self.get_asset_gen(secp)?;
                Ok(PedersenCommitment::new_unblinded(secp, value,  asset_comm))
            }
            Value::Confidential(comm) => Ok(comm),
        }
    }

    /// Creates a new confidential output that IS the last one in the transaction.
    pub fn new_last_confidential<R, C>(
        rng: &mut R,
        secp: &Secp256k1<C>,
        value: u64,
        address: Address,
        asset: AssetId,
        inputs: &[(
            AssetId,
            u64,
            Option<Generator>,
            AssetBlindingFactor,
            ValueBlindingFactor,
        )],
        outputs: &[(u64, AssetBlindingFactor, ValueBlindingFactor)],
    ) -> Result<(Self, AssetBlindingFactor, ValueBlindingFactor), ConfidentialTxOutError>
    where
        R: RngCore + CryptoRng,
        C: Signing,
    {
        let (surjection_proof_inputs, value_blind_inputs) = inputs
            .iter()
            .map(|(id, value, asset, abf, vbf)| {
                let asset = asset.as_ref().map(|x| *x)
                .unwrap_or_else(|| Generator::new_blinded(secp, id.into_tag(), abf.into_inner()));
                ((asset, id.into_tag(), abf.0), (*value, *abf, *vbf))
            })
            .unzip::<_, _, Vec<_>, Vec<_>>();

        let out_abf = AssetBlindingFactor::new(rng);
        let out_asset = Asset::new_confidential(secp, asset, out_abf);

        let out_asset_commitment = out_asset.commitment().expect("confidential asset");
        let out_vbf =
            ValueBlindingFactor::last(secp, value, out_abf, &value_blind_inputs, &outputs);
        let value_commitment = Value::new_confidential(secp, value, out_asset_commitment, out_vbf);

        let receiver_blinding_pk = &address
            .blinding_pubkey
            .ok_or(ConfidentialTxOutError::NoBlindingKeyInAddress)?;
        let (nonce, shared_secret) = Nonce::new_confidential(rng, secp, receiver_blinding_pk);

        let message = RangeProofMessage { asset, bf: out_abf };
        let rangeproof = RangeProof::new(
            secp,
            Self::RANGEPROOF_MIN_VALUE,
            value_commitment.commitment().expect("confidential value"),
            value,
            out_vbf.0,
            &message.to_bytes(),
            address.script_pubkey().as_bytes(),
            shared_secret,
            Self::RANGEPROOF_EXP_SHIFT,
            Self::RANGEPROOF_MIN_PRIV_BITS,
            out_asset_commitment,
        )?;

        let surjection_proof = SurjectionProof::new(
            secp,
            rng,
            asset.into_tag(),
            out_abf.into_inner(),
            surjection_proof_inputs.as_ref(),
        )?;

        let txout = TxOut {
            asset: out_asset,
            value: value_commitment,
            nonce,
            script_pubkey: address.script_pubkey(),
            witness: TxOutWitness {
                surjection_proof: Some(surjection_proof),
                rangeproof: Some(rangeproof),
            },
        };

        Ok((txout, out_abf, out_vbf))
    }
}

impl Transaction {

    /// Verify that the transaction has correctly calculated blinding
    /// factors and they CT verification equation holds.
    /// This is *NOT* a complete Transaction verification check
    /// It does *NOT* check whether input witness/script satifies
    /// the script pubkey, or inputs are double-spent and other
    /// consensus checks.
    /// This method only checks if the [Transaction] verification
    /// equation for Confidential transactions holds.
    /// i.e Sum of inputs = Sum of outputs + fees.
    /// And the corresponding surjection/rangeproofs are correct.
    /// For checking of surjection proofs and amounts, spent_utxos parameter
    /// should contain information about the prevouts. Note that the order of
    /// spent_utxos should be consistent with transaction inputs.
    /// ## Examples
    ///
    /// ```
    /// # use std::str::FromStr;
    /// # use elements::hashes::hex::FromHex;
    /// # use elements::encode::deserialize;
    /// # use elements::secp256k1_zkp;
    /// # use elements::{confidential, script, Transaction, TxOut, TxOutWitness};
    /// # fn body() -> Result<(), Box<dyn std::error::Error>> {
    /// let secp = secp256k1_zkp::Secp256k1::new();
    /// let tx: Transaction = deserialize(&Vec::<u8>::from_hex(
    ///     "0200000001014166d8bc73e9f6bf833f6372b021d6e412ae773cdd722467db163ff06d1e1fcb0100000000fdffffff030bbc8258e21ddcfa93f8b13e26675ce0696bab13e48b6e570087d27b8c2e58229108a6dd1a702dc30f897e040004def8dd2e67b7c6567a77b7c4d88e71d837531d76021d91021fab6f42fbae69c1ef0fe51ed088f08f69f9e658c5f702ab8a512334cb160014bea76c13404321e84760d712218e455b559f2ea20b637f6c0c63b8403cb889ee0502f2b4d8f391b8230798e938ea0aff882758f5fc09674f64e8313722b6fda15d4e3be5845a2c8fd7a243312413f026f6dc9541bb6e031465dee3abbf0059ebabf7933cd5bc8725a8e284f9f2868df84dcd78af6e15741600149928d95e500cf680ab923370529b5110b4c6b35501230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b20100000000000000f900006f000000000002473044022018a96048b7b3d732fe44421655a26c076a84adc9b0d210856734ef52093b0ba8022045f3645b9d9f40a47963f56c5fe599a23079bd14fceaa2432750a235c623485e01210232edc2082acf05281c9ddb1d8e024de805ae65f6547848ea34441c09173bee3000430100012bfbd82937b25fc506c0b016d904d63eb15301c8fabc6e796549f0383cc08c7effd3d398b04e4feb1279f90f7c32d9a87907155514d69f9612b059f6fdf2a62ffd4e10603300000000000000013f2817003c824b0c690dbde0739e2e1263411a92287701d3bcb9917b2562397755e3945a5f0e917e4eb71b9245d225abcb97a43c7c8bae23fe9b389991db5e693937b2dc225072e5177673ba18545a9dcafd1f550501543ca45d11eaabd2769e49bc5a26fbe64eedaf38d56ef5f6d5cbac587c97c9846a6472a0525104dbabf24d34fb3db29244ef5dce6c9b71a12d9bd48bb796f6b4f89c1130e767ea70842402a1d1c1e4fa2ab18db1f407587e2b5ecbfc34c05b5fe5d10ab43fc9fda482ae7b08eb0115e9758b9d14de8f8d567133779a6153411e32456241f149e0731dbc263a5831317bb394a0efbed52cbf121abafce5dcde0949b619dffea3a942e0ce237a4725a865f4d3a7dd18f6c3baceefd2504fe03d898687ed44237e6105a237621a71f68a22d43ade7c59e14ebc5ea93e236f29b7d8cdaf933c8dc2df72dfd4b74c4469ce34a263373c7154ee89a66387bda99794ecfda0ac03298f1be66f60a67202053fcc98eea44839f8f6e5e0aa3657b72bd54a236362222ab91b5bc0abc7bf1b19138dbead02f904e0417b45699fa3699f7c8af319db491b7c0990a119ae0fbb0591e5c1185c50aa6b8a6ee85cbb841bc4fb99164e0b4d0e18fd8f61d41e05af83c4e94091256f27fe2838d8b44c657f0035c11c3c7636f62e0e3b2188faed87daa23b01f690a0712a06f06f464be8b5ae955f3f880f750d01d23c3f6ee7472b1a8508b0b7a200675dd347c14d520e77f7d61dc28e87f63129aeeb15c32fce6fc109ea7582bedef9594685b8290ead0fec8f7a0477babf661c61d7e651b19b46a59b06d92472ff1e30033534acfdc6a23bdd287e0582d3ca45be95436120ebae081c0c81da96d60db6870d02e386e5cf0ceeb0d5d746ab7178f9297c47be7d9fae7b73eda435319ed7865fd3357120645cc46bbb8ab4ff58fbffc3252888ac7e1bf6f61ef113c1823e38494c2344897f31f65374b13b677656b37386d95a66089b2d1c557b6f70d0354fb71a903c530ead4a0199d71052f589be243ccbc890537b9412f2d70a4d9585c8af6af9844f403acc40ff8633bd2232c032fff6538aa45218ecac24eb62a48f852b91dab12efea26f2b96f368fd850da25ba319d09289df0ee8052ebc0e39bb006966cc51757a3bc3da2a7483ccc7b82f4b13fdc5222a72f60bb750ffb469fa1821cff233ce8078676a9c8dc4cbdd89337275af2e51fe5351d7ed81ef62dcd944022da3ae3cc501e777d567217b21e13d8f1cc2cfac2d8494343e3b6ae80cff461ea20a3604bd41b42d2ead953bdbd75170c7129139724a6669ae77ac234370625a9533168bc1cad48839ef2abe517d2955d75b5d573e6b6e52e5342d9b6d9e2ed5413bd2cb8190fbbfa22a090da3eb462a886e2c2fbc076fc47c8778d3d10b15b7afdc2fd8886b4f85a565c2f517005b125df57a444a4d2528b7d3ac67a56454fdb2fc764f29d6e9fa8ec0bfb78f562ed9331d24f541c03a51628a932457e0287189ea36a35be4d01577e7a2a766f2081366840780abfd2aff20a9d4cc826fd751fbb0e7b353d518a3cd90bd61e694a7645a7859e21532d8f9759d32804c3341e41164f8815a38411484f4b394db6a8150591faa9d37cc76e812fc2b6cfb1e605d91552a31fe88b9d18cbbc7d2e558db74987564209ce126241c38a80da1df34db585a9d7a1330080cb16fdaf9ec1c37f309a8a0e2e7748ede59e7910b8b6b5caee51532ee6c5bd851db455c150b8d90445a36fbac9858798d73abf605dd0f515c23a0f975d50d09e6d7f541f0250c23c414219c87b15929ada1974a71709809db49ad8cab72958c31b1ddd0064d264641327a433d748713c57bc0063ec45b852a9beb2cc2be7465bd48b3d113ecf3d4981f2e3ddc7494714d21b860eb336ab91e894af0a5ff727f2b8d85c12f7ed321c90038e8f26f544c4918562b7c65e7cc1cecd5c6961ea2d1f806268d1dca92337f127a03c2626fcac5b8caf0a7abc3a6cc4d362f040572b56c5ad09e0dfd92235dbb2c1a8fbccdee13b2cf55681ec8f053575214c9200bee18428b25440b220079ca8708d23c84927103a8afac4bee58b95cce012ea23b175bd2a12636afc07e649675568ef945d352402f222fa62dcbad7f9f0dae132c089aea82d4c8b905655943e8b61f55475b3c3755d5967b01236e2c4b833ff6945031b50f0a68f0ec7130055761f8e9c2ebb2c9462d0b8aa9e99c7ebed1d3213abc471bbd49f44e78e057c750590f3ac02d3baa776d9f9ef39bc1a166dd7cb1cc3e63d94d7bb51544b9b02ad1278f7691973030612534ff513d2cf7988b3235b4449976b90fa5932639bafb7d0d33b58a167617ab4a46189e251bd488cc36a4b40968aa34c20a80f3ee5380152b7dd62de83c1e2a07307861b3713506115c1021880c19f89f45e40a16cebfc1980ebbab7bb9288eb33d4696c39bedada35a41f9e6832a0f5e12f2968303533c8186cc09da7c3ce4e96410f7a9bc5941706fd513a908ace16cd3605c5d0f4b872e931d79361134371285b6d223e1601ad129daa776ab58cb4dc7eaddd45cbf722d4cc4229d75a52e18c7470ed1a7a84671bd8bca4b9bdb0d7b0a34779d1a538fad3b6e2d7cc2972ab1bb98613b8ecc27f9fc25fd797aca4e5d0de4aa6df7f6607ad268baea41f3c1f9afc9dc5da929b29e4ac203a7476fe2c185ac25b835b6f2037c3f540852bfd2d643c179e0951cebc35743f6315a56d2965de934695ef5dbae70924f8548a858518340d7add64f45d2c7b69bfdbb8fb640a2284619fa857d2f5f8bbf615822e45b924622d32e78caedead8ab69fdfe142c97d7fb61af8cd32767d1006c6331d316e0e66b112a765388ff027eecd1181913ef9c701f2a46d0bf35abcaa3fe0cd26863e3d65ded79b262d1e914c538ae7d05ab30390465ba25a73a6ab53ce4296a3f5cbfd3901cca44bdd6818fa8d427ab2ceddc315f0adcd3fcae63074ea9e42f15fa02f1e3ec6276adc953beaadbce84ca6ef04966c882e3e7802436e4042fa5be4c3773d685bed66eec0c5a6cc463770c00740fef403badedadd28984e22027b38a0c66b7a409080adea574cb95ca236d701751056f7ea1e1b3082f0a26acbc630526053be88bd88267e23c2787daef884d709a5ac2c118c8c8b4b1eb6cd9d829ec42d9f249f754cf93b6c4cfdcf99cec0f9d742af36300274df095a35efa8ba95d412d2e61db8776660882519d4500f615e6a3e88640e93e921dc1fc4b74b5776cfdd47eb8b00d422fb0ee5c889c419bd352cef4573dab05fe44abd39bb7014e4ad0af6e5c9ed8236edb16d05057a6794ee76e923b6d1bef5e17e7078f6696af0f23064b1a592e89ff7073f040e9ea236450fa8d8fad6d04606b1a1a407ea14868b0c81c76c0f5fe9047e9c60dd150f9164533a7e4cbcc87f5c58e9e9ce317ce694cdd816b45fc497ec5c66736050ba925fa7ec598274f23a4ff022e7970dc520e4baefb30a26a5464fd5c75906e88a2c245cfcf00807c3b5e0deeb463886d606bfe7f30b73a512c5488f7c586dbcecd03ecc6cfc3caef921930aa01d2ca21ae3acfe5af26003acd436c344f80a4a9d9371a51b5b19b984d12b2a134f2ed89a6c5cf9905b2626d926bee7fd39988282411a0ea0ec1b61c22eceee21cd264c1fede96d9460cddc0624c9e22ccf42ff18bb13f8686bd6ef528aeda6181647a1c6c6ebd90fe05a69cbf169a971ae616d9d74840f1a7a3cc48c7a27b07a14e58bace67aa61dc594f0dc909283fc39c77a5dfadd50a358fc2c05118cb6197f3aba31d75fe2681219bff02e70f6d968f99d59a6c80a2af8bc09c21a2874ecfa47850844221fe066a1e6b40c0c5c4b59f8a8c22b78419c77be2306a9e085a76dbf9552ac9a575b872df0f9834f7aa8d89d585ec34ddb7c1d76c6d132356679263c8458a288c95f36631ca460ef925fdd9801154f886beae75dfb5e794ee58813cd1748e932e279ad65a3e2e894d190e221f07207d6ab5d2c7e328661746bc12e72d6075eb2a4e1f91a3b27d3309f9825d2467aef6f5236c38b071e5a6d17e3a7a88033a3ddb756e7aceb2c7d4fcca92a077a110684337fd8222f9c38e806554d30d9c3fcb647faa000f72adcc8e1d6c811634757a74b4d52f9e47826319f3954756d0623149a9f62f838feb135b1d26fe00e299a96dd94106fd39c9aa14360792870f33b8cde870e98353b27c1bbff569b79ef1d5f0161a4b585f4002b42c970b3e84912bf707c8d49fe56adfca407f8a039314a5c0720060061ace5a8144224bf52d5458e1fff84306c2c88b86061e18116a8b46cfb2adb6b33f704ae6d83aa2aac13bcd61b64c93cb6d2d5c3acc990626f891f9b7befa0f25c1a2665290309add936ff62d4fd182d68adeafb49f75fea798d8572444253886bc936589bda972b5e5625db267de1b30a8501ef215ab8a320574ce27a33fe603a67656ed8744f048b022cd61c132ece087fa0d94c2d4dfbb92a46ea5403341df3896ac49932955c6b3d700bc475c9d173c6173c8d883bd9499aede17e7840294334f1b0585b66f00e121ca298933703951801584c5db57854ef87802d254fc75d31319b8560f5ebee2ea80ffefa63e2a4c4e3d53b007ca18f83539f3078b2736f4fb4f8fff41823912227b04bab8aeeb7d95eb0db3dda58a98077f25e1db6dd454cfcd41068dcfb54f1d1e0b478013e58ca7efe874e98205d7c59ceeeb28cdd55cab4fa3a01ebaa957effe330364f75c0d6728b769dad34e58e9f217d1e8e96d79d896c193b425236ef2303eed072d114c06c198fd6a12a28f4d436dd126d1ab98c7e1621e0f59cc7276dbe7cf267ce2c6c0ed164deb57039fc5be8ae4e72efe26115e0fd59ae6fed9743eebbea873fca30c9d7eda201e73fe22e509b11c19580d368bca3f4cc59b949c8d03fa63e7b2b79f39983235d7ea3fc6fc92fab4c66a7680ec57f998fd818db6fa88ac2913f4a48a4cfbf68f1f565f799a6a95a22c8f6a4d6ba2a5307e51c99d22bcdb399520306446a6804f7cccff394986341187c4a72813392984e57ce3cab06c540722e25be50ba138ca0a54686c8960e2f6118380b3b9255d14071b1e2131d6cda16eb463bc4642cc11391a7c8a75a6da8c5f1424f7752ca3dbd37f2d9a2a3855f3b3aa7104c7a5be0c334df618dd478c43b9bb0fe7d774e93cbc8323816e1f0e1290e52079009150761207d99b1ec995ec7897a0385513abb96ec5f9d2c757662cd946d8e340646944b5fc6cf92f606ed2bd6872fe89c1cdabfa7f755b27dadce1337a18ecad4b78c0291f34e1cf0577eab17c70b05eea58bfb7bb3cdb46d46507db8fe8cbe3dca07d92d1ea2c5a6e354cabba8d532a47f6d9ba6ca48add4df8bf8ebbf3ccf8b0417f4b90756faf134ee210511d40314f218f9902897390fb0f405eabfc4a7ed4467e4fd14edd3ce4ee0337a5f0c21590816126768d5a85d67c8a7ef6b07c8d40dd13978cecbbfff0507d6030167e01bfbcb3557610ebad49f2f98cd9e003d3fe0a4dbc64d4202d4260ece552b7f7dad2be1dc61e3e7fbd5ae5be1f9bc0599807727c1e30eaa6d80ce79bc6d5a28c5c3efb8c1e99ffadde8ba7f42c2f27e3fbadec5b13e8673256b2aea4ea1a7b92d909ac4fd06fc3f03098cff0667224949eb1fc242ee42da5a9a06d93c5c4896e3c54e8815602d2a42c4bcad7a597e9261d24a404ba0f4645eb68f0521b7eb73d7b26ce2f802ba54674d011c07c485c1f7b6e31197c40a39c53e94cbd0b3de605c76ec9d7272a53ea5547b2131da2b51b2b0c099bc93214f02c2469c396dbc6fda284126d7d069fc3d51750037e545cf2ffe35b308d1c515870bf0fb062c2c666367061430100011850912d035bb6962d10e126e5a9666eb4128d7fefc4a0633ba0f388c5f28302a7a2e02653aebda6a6bad0cbdd972b57201a14a7f879c480fe5e1c36db90f749fd4e1060330000000000000001bdbe9301cb099b5fb8baac78310a3529d6677700658a6a87eb00a5f66dceb0862dc11cdcf845e07ba63ea84308200d309ffc3211996c507208560b7f65fa70f0a176dd0cb179ca911797c66d6fb56d27728a4fcc9998919a89c52d8bded3f732a5360861a6639c839f39503ea1457ae5d4ff7e1811ac2d33047823c5c118768343620abe7fd8cf459e5fca0f490ed91d9c09b37303662c201fff61247e8fefed8ffb29f999cddf601670469de151617021352c0dfe54512bc44c3b8e1a4ece73d2eaa727b28093d4741bd01dba0d9c7a4cb69e8a63bf6e887fcf6a57812ae40fd829dcfb6bab3a2a4ac678418e15179613f2436f53ae806ecb8f44115847b16cf935efadee467aa6de4a0cccaf8e4b1835b8dd1f9d04f0bbd4b3164dbc58a3a10db4537c94bafeb0289c6a192b28d5ba48df580a44a0d044ba82140295bfae70214127b73c7efac419bccaa75716867bc0bc75171e54dc3c439635d832cd052c4e9fa7370b1794b3da8a1a740b50cbcc605dc840f4d996f1283018a6356c437e79218a191ec68a48b193d3560b690d44741b354b13320ea16286405dc6476e8e8231d667978ef9c36e84f09e74387b4d557e39a40f51a62f70b5be58415c256f262486fd144489de4b8605a0d53945ed08daf543f3fac38888dcd4650903b95ebfcb4e0f57ca89b3f0132400e4012e00854c41b2788bd7c0d5d40845f48571d954e12013f6cf7ece536f32ff9a3c94ed10f1a2fd50b3f38a0f1272489d583deec9da33d9ac46914efea240aa004a8f17e1e168136b4ada57309b91e10c716eae0a5789c64747c0e09a696b67e8c7bba12c2b8d80248da93acfc7c1455a33b40f8761fd37812e74e572a9a21b0e2d7bc37ccad146d847a53d7a650122d96d00b179e353db2864e5ec929173550e0edf2c02b2ccb595b326582758d700009f4c433cf86837d1070686a6eeee6f4ab1e6ffc44bda783d7e2ff81f289991cdf982b61a73660020e544e5897c3021a446c8a4966ca625bbd6bfdc505e85d1f5acc663607cc2ba18945b74662be550b215878b35d9932f11cbe509456461ffa2b3bad33405f51c5b17b5081bbb4874c2656e0efecb2647d22028e53f263401e779e92ea3f70c860b0405e8109e10e27c2f4986e66965f4ddb895b943ba4dd0315372ac0460f78ec408cd562c21537d7f0f5e12c95e3d86066db77390b02e9073e241aa97af7588bbd6fa967a6776a3e226c0e56936fccae5ecd8aa20af1cc9b74a4579d8bd4fba988438fe455da8261f9aa96bf222e5af2fe297ce1901f0845334e856fa928119e23cc64f5ac541c699befad140a3e2cf53f591112d1ae57391eecf6fb729654fa98ba946ba8a532c3cb8b0dad5f08e3158f128cb065379b2ffc78d8394e5d2f1c7f4fa7b8a5031a7053f0144835e7ef53f4d60c8953bfde31e75fa3ab6bab86bc37617585db21f16318902138c1a7c25db16c212bef0de8aed1575e1c8e1064755b4b493adaec2dd320f8f8b9a240352f7a8a409ff3ac3beaf08114ba7294502f8f0f529e039ac7cda8a9d8e45b9aeb4e7a83d2de5a4edcb363a15020a5d285cf6acc3f43dfa724fd6c8ce76c33d485db88cdf379faaa7a0eb65f52c99daf2fb0edd8eed2e38e2990b044bb4ab7cda75d23b04fb72e842b54d88ed8a7ed236f61ce58e7a7fc34aa94e9100157cda06dcf81722058369df2b912442ea0768383b7c673f239a7f56dd4ec8739cd14698000747b979f22852e72352b0287fe7c0bddb68bd494341a0cbbd0df4fec1d613f7160f8fae32b9009c4d7146a8004a158763efea270c6724d022bd3d5954789e2ebcb50663b98a619182d800263485faee5e621d99f6819068f6d032aba95f7294aa6bb297f93fbd0e1def781351fe5ed7330ffb203d48aef9c6e6af244cca568dd164226131343f37977f11a770bea7f40e8b0593f5efd23ca0ff18594512004a9a34582de5ecfe06519f6223b5576ba1492d817e6da30791abfd2f4e85d235fc16f43ffa1879afd6f3c3aa252a232d567502dbdd70005997da48f8a0c64911af8ba5e8c123a3e81247de4a536ef41330d345c2681e1a508e4accee45140a194a1eedbe6559e67a9daa34580f00166db39d3f6e92d0b996754bb1d8cd3d68d692b872a0e9b086c14c1d143e03ffe5279a6687e5fe139534e59d43e2204ad9794a38a3d9cc9e63245c89123977e66dde7e33800f62a9ab3aa725b09670cbd58890056d62b459473ecdcca375d4784f278042fecd626c635414ed1ed1a1e2cec075d1a495004debb13df0c61e0bfc2f10ac84d94c404400559c6b4209fcc4fd0f4e041fc5101fa8265478fb794e7c008af8172d267e495d314d65b9dc1dc3ede3be27e4c80840ee7b75c31355bb4c940049bb0e02234370a2cd009753983409d87604ff5bd2d179061f9629be6663ffad62e3aed59de373892140475cf491a6482da6d9a1cc1031b4fce7737accce613a01fccaf36f0ac6fe1323828f3cf2a3e8c64cd0f95916c3db7176200e8f6384e6527f8020a761c0e46d388c4c1424118a69afc6bc5884d9ca3a19b5a65f95d3cc476b1f8e1c7bd41969b0f42d6b121816c1f3ebcff888c0c93d582d6f9b1bb5acc1cbdef4db323585ee059b4a68b37dd6ec85fa3a7bdc0ff7cd5e903cc76bc6a30b7965132e551bd5ac1c11ef069da69064086baa14435a9492444619dc3df5466bfb2cda341ff630d767ab55ec2bec5f92fa0e23cd8b4a5386c85cf540fdc4a15e9a27f7ea48c29d92a58c738eb2133005ab4b787d849acca740d58d258e5fe32dac3f2499773ffe3b362cb384632a8f24b9380c1ec1566108052ac157691ccdfe8ee497c57fcb8db7799ff2688288f07dcd7af020e3b21ce8ce9a730fa23f88fe2ade8291a439fd3b5769ff98284e042a1d795b1920b10cf755d3073a7a8e7f9b78b62baea353b77fc4be39caf38c709ad8c548432a7ed102e114f44b0ff22c7c04d4299f9d47bd81172385ddb1e5c9019809968a7638bde0b766d63514f85b22b1a795fb97b9c367b9693299c7447630e333265faf35ea516247d1d1ef7f9ded1219f9cba746100cbf6470becbe5e73fb817e7979bd1d502e9b7ab62bd70a70115cf3f9eee4e7ba131040a4baf9139e7bc6968b0053075f75afc787e2a083caff88d5b627d81d5e8584bb30334211866dceb96a2f03db6734e5a8cd28d4000119a55e32ac45dc38080c5fa05200e0054bea35713648f17634b6954b7be38e38fb29c3f5251f33c3f6531855f393fad9568b3f3ee02fdcf02f2172de1f8007a479d235091c4c39b76941bcf563b46e32248f9adbbb247bc62d552c5444ffdbd0cebf3e5a08212400cd7155236c21a410bb1dc9aca0f82b438c5e1d2c1632c577801ca18d30371e39efd3135092d008e290dba376f799a85dbfa317e9490bf2ee52444567ef8f74c5350e69331c03d51ddc8151822656cf7bbc054dcf9a5166a2bc72b01c5778c4c8f3076343ec1a6f7f3380d3e19bde7c248b23789bc724af6fe17c2173b0c204ff8b6342e5c9bd8f652ff0c80077fce0ce258b0879c74986f5d51e59eae4b946de1e2b785f039ef9bde314753011e35dd9ab9278fd95e4b10f04b4a157a16a6de9ba5a1793a4be0f2e2fd3cf2fd9366b2b7cd358f7a9a9397899833839c8bc968c5c37660488cf391637702de780b5ac526ab11fc895a5c783931dd0d486cc7672f417ceb30914b8f6fc51d270c932c81c7fda22b2b88ff14f7c9285f6341053fc529aefc97755fc5962a5e094b10291b98c991b0bee8c28b639f642bbcbd7c27d9217c19e11a94ecd58bc79c220feb9f1799f952e8a31b9607bb9fc4ababb8515aed1112050e0a75cb5c7811a63b90eafe411e92f2864fdbc4f23ac3c335d300440f9b6c0e7402a825fd5f4eb32ccb76ae4ef43441282356cac29b0147f780252427c9d21abdf7306c9f2836f599cef0a2c2eb4596df9498d661bcf8bcc88d5a7f0779489f9423ad045b735e421ba0f861744beecb7c1efcb5989386e9c2e4e07ef033ce75d5e3ae6b78775cbb3d5ad8fa5b29ee2137f6b59f865c71af63ac98c2f0cecaec428c773a747ba188f8f3dc30ede05077b422a920a313b885c31d247328c691f66a7440bb27581baea7d9365f8da23bf71a7cbbca02c74391928daf1f6b2b0f74acd3b89ad53e3dc87aa2716a25c89c4a6f1a363cbd97745910e399cfa766ddc5b25fe4f40412690316acab688493a1c882ccabf7ba2b1496f77ba6a34133b3a6d9f5c6526309f1d2e14c261959dae012420bf9fa0aa2b3e3862308f6c6f65e7f0660eed3b5fbf3278eb5b2893b1c8dbef827e7bee0fa92fad9393f037c4b90babf62a159e2637f22a46a18bee1baf9c4c3344186083b167de5936437a5fb379ae305e8a502fc22f849398daa9547c8f6c2554d231daba90a5f729069c24bdb2b749cd1a16489f7c0940a59ba7f324dcb2c42e47652179208bfff6d64a1ac5e557a34321a4c3bda6eae6f461e1a6ecc9cee9fbf36e2b6c504ae2e0a3bd03235fb6032725280d64fa1a33f58a7196b56c0a65dc7bbf0a429889d0ee2467796515f857800c78fe21bd17f65807342a7f4a0a7926d064f073d1a7dc76295b9e35195b7880fd83db7e2335709179cca4f285b0b14693fd0b6cef9958cc6906adacdf1ad1b572eaf9e6ef42b574d75a1f58927d49113726572b40bd792b6ca621daa7c5f56645b1f8ed5b0a7ac26f71c4c665b89b975b3c38ed6949271df097c8018e772b2a3f8bba41424bd9c1b06e111cfdedbac883dbdc5345e5a6aec531c722c94b0c6b072288b706afe77a6e179fd38c7f6a0051246f0b161d0a5c696374755b01822181bd843ee8d4f476ef5bf3efbf9cae0f3162ee5de88c0aeafcb3b5fb34a7edaad5292428a612eeea80a54c0dc3ac1ac7b00f103aa39015a038d4537271bdc277e4a8f8648797b6a67cebb7485625406f9963d17b51d1f4706674e58da1b5e4c415eb403791c72a62a2e6a5a4cf50d26fe78d7e9620c50f718dbd0d075efccbeb8b731f8b1ecc988f2b38dce9cda9a644441391728a47ccd8975dac442c39f59726802474ec44a45afb5e545512e8f069e139da079c6e0bafce31f30bef474bb2deeeb6a035ab37757b02d6f4de3ff85a0cd5109290259c1be2a8288a33dcad5518d9d0413a393f659095beef0572193af15d909acbff828b56adba008a3fdb653ee5fcb5653884ef69d8f8f6588b2b46a3dd361dd4983d205d22f9351f4ebc049f867832b35181a70f390158a2960fc9bc2551e23925f2c9a262b7b9e9da6c97f35e5ba21986f5cface9e8d829751921a9e6fdfbe084197a97a778c795c0a9e293c7a07033ac2a34e0f27ca53b4cc7833fc7682c0da1f5784e812e4223933dc2b4b20f77c4d01c40c4f7db5a556ad3de59605e45c02928f5b8a7720eb83f750c9789b062826bfc895ee526f0c813d3a3bdc3a6a03c27c9f3eeaec747bfa72c19da03af860ea21986df7c0509575c2b7f47f036758d9777e6843f620084bafac9c6a2f7910f703c8dff42c9f160a15d852cc4bf2f33b1b53c392959e804d34a3b56c1bf47a4813c7d67d36e66859b1eeb8f105c79aadab1cd2ea927cb9cc48a70da61241b5e3d3a5802c3ba003e7d318628f6a6a37725b6fc721899b30c9dd2b3d6f18d70df0f363ddac2fd3cc79fdde2ac26ccf16462534ba1a8d1baea51b789bc00226febe51678af19898e4f4456f072e5d79345323f8231b085b94419dd812bfae12c4defd363fa4baf09c4ceac1d543365ab52f230925f56840efff264b3b8e961c8aa8e62a8f3df6f204331a1dc08375c6521ebede7a0eaa92d378830d11a989681bd6e07b7a870195f4c2fb579a800000"
    /// ).unwrap()).unwrap();
    /// let conf_asset : confidential::Asset = deserialize(&Vec::<u8>::from_hex("0b37d4818b8ce1df5d3d0b88d140c6848029d6d85fb0f6ee270865caf53d0b82d4").unwrap()).unwrap();
    /// let conf_value : confidential::Value = deserialize(&Vec::<u8>::from_hex("094e2cceeb8005ac14b611821c37fca757b47426afb0bb4eabe41c275d3997c046").unwrap()).unwrap();
    /// let spk : script::Script = deserialize(&Vec::<u8>::from_hex("16001475f578ed4f7a0103182a6e92942c66350dd949dc").unwrap()).unwrap();
    ///
    /// let txout = TxOut {
    ///     asset: conf_asset,
    ///     value: conf_value,
    ///     nonce: confidential::Nonce::Null, // unimportant in verification
    ///     script_pubkey: spk,
    ///     witness: TxOutWitness:: default(),
    ///     // We don't care about witness here since all the blinding
    ///     // factors/explicit values are already known.
    /// };
    /// /// Verify a confidential commitment with amounts. 1 CT input and 3 outputs
    /// /// 1 fee output and 2 CT outputs.
    /// tx.verify_tx_amt_proofs(&secp, &[txout]).expect("Verification");
    /// # Ok(())
    /// # }
    /// # body().unwrap()
    /// ```
    pub fn verify_tx_amt_proofs(
        &self,
        secp: &Secp256k1<secp256k1_zkp::All>,
        spent_utxos: &[TxOut],
    ) -> Result<(), VerificationError>
    {
        if spent_utxos.len() != self.input.len() {
            return Err(VerificationError::UtxoInputLenMismatch);
        }
        // Issuances and reissuances not supported yet
        let mut in_commits = vec![];
        let mut out_commits = vec![];
        for (i, inp) in self.input.iter().enumerate() {
            if inp.has_issuance() {
                return Err(VerificationError::IssuanceTransactionInput(i));
            }
            in_commits.push(
                spent_utxos[i].get_value_commit(secp)
                    .map_err(|e| VerificationError::SpentTxOutError(i, e))?
            );
        }

        let domain = spent_utxos
            .iter()
            .enumerate()
            .map(|(i, out)|
                out.get_asset_gen(secp).map_err(|e| VerificationError::SpentTxOutError(i, e))
            )
            .collect::<Result<Vec<_>, _>>()?;
        for (i, out) in self.output.iter().enumerate() {

            // Compute the value commitments and asset generator
            let out_commit = out.get_value_commit(secp)
                .map_err(|e| VerificationError::SpentTxOutError(i, e))?;
            out_commits.push(out_commit);

            // rangeproof checks
            if let Some(comm) = out.value.commitment() {
                let gen = out.get_asset_gen(secp)
                .map_err(|e| VerificationError::TxOutError(i, e))?;
                let rangeproof = out.witness.rangeproof.as_ref().ok_or(
                    VerificationError::RangeProofMissing(i))?;
                rangeproof.verify(secp, comm, out.script_pubkey.as_bytes(), gen)
                    .map_err(|e| VerificationError::RangeProofError(i, e))?;
            } else {
                // No rangeproof checks for explicit values
            }

            // Surjection proof checks
            if let Some(gen) = out.asset.commitment() {
                let surjectionproof = out.witness.surjection_proof.as_ref().ok_or(
                    VerificationError::SurjectionProofMissing(i))?;
                if !surjectionproof.verify(secp, gen, &domain) {
                    return Err(VerificationError::SurjectionProofVerificationError(i))
                }
            } else {
                // No surjection proof checks for explicit assets
            }
        }
        // Final Balance check
        if !secp256k1_zkp::verify_commitments_sum_to_equal(secp, &in_commits, &out_commits) {
            return Err(VerificationError::BalanceCheckFailed)
        }
        Ok(())
    }
}