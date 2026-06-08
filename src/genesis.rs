// Rust Elements Library
// Written by
//   The Elements developers
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

//! Helpers to calculate the genesis block for a given network.

use crate::hashes::{sha256, Hash, HashEngine};
use crate::opcodes::OP_TRUE;
use crate::pset::serialize::Serialize;
use crate::{script, Script};

/// Parameters that influence chain consensus. The contents of the genesis block for a given network
/// are defined by these values.
#[derive(Clone, Debug)]
pub struct NetworkParams {
    /// The network identifier string that elementsd accepts as the `chain` config argument
    pub network_id: String,
    /// This network's Fedpeg script
    pub fedpeg_script: Script,
    /// This network's `sign_block_script`
    pub sign_block_script: Script,
    /// How many free coins are present in this network
    pub initial_free_coins: u64,
}

impl NetworkParams {
    /// New custom network params
    pub fn new(
        network_id: String,
        fedpeg_script: Script,
        sign_block_script: Script,
        initial_free_coins: u64,
    ) -> NetworkParams {
        NetworkParams {
            network_id,
            fedpeg_script,
            sign_block_script,
            initial_free_coins,
        }
    }

    /// Network params for Liquid mainnet
    pub fn liquidv1() -> Self {
        NetworkParams {
            network_id: "liquidv1".to_string(),
            // Can be verified at https://github.com/ElementsProject/elements/blob/27c2fb6b7de404908f9ef2eb5c98c9989d1ab8e4/src/chainparams.cpp#L1243
            fedpeg_script: Script::from_hex_no_prefix("745c87635b21020e0338c96a8870479f2396c373cc7696ba124e8635d41b0ea581112b678172612102675333a4e4b8fb51d9d4e22fa5a8eaced3fdac8a8cbf9be8c030f75712e6af992102896807d54bc55c24981f24a453c60ad3e8993d693732288068a23df3d9f50d4821029e51a5ef5db3137051de8323b001749932f2ff0d34c82e96a2c2461de96ae56c2102a4e1a9638d46923272c266631d94d36bdb03a64ee0e14c7518e49d2f29bc40102102f8a00b269f8c5e59c67d36db3cdc11b11b21f64b4bffb2815e9100d9aa8daf072103079e252e85abffd3c401a69b087e590a9b86f33f574f08129ccbd3521ecf516b2103111cf405b627e22135b3b3733a4a34aa5723fb0f58379a16d32861bf576b0ec2210318f331b3e5d38156da6633b31929c5b220349859cc9ca3d33fb4e68aa08401742103230dae6b4ac93480aeab26d000841298e3b8f6157028e47b0897c1e025165de121035abff4281ff00660f99ab27bb53e6b33689c2cd8dcd364bc3c90ca5aea0d71a62103bd45cddfacf2083b14310ae4a84e25de61e451637346325222747b157446614c2103cc297026b06c71cbfa52089149157b5ff23de027ac5ab781800a578192d175462103d3bde5d63bdb3a6379b461be64dad45eabff42f758543a9645afd42f6d4248282103ed1e8d5109c9ed66f7941bc53cc71137baa76d50d274bda8d5e8ffbd6e61fe9a5f6702c00fb275522103aab896d53a8e7d6433137bbba940f9c521e085dd07e60994579b64a6d992cf79210291b7d0b1b692f8f524516ed950872e5da10fb1b808b5a526dedc6fed1cf29807210386aa9372fbab374593466bc5451dc59954e90787f08060964d95c87ef34ca5bb5368ae").expect("constant fedpeg script parse"),
            // Can be verified at https://github.com/ElementsProject/elements/blob/27c2fb6b7de404908f9ef2eb5c98c9989d1ab8e4/src/chainparams.cpp#L1193
            sign_block_script: Script::from_hex_no_prefix("5b21026a2a106ec32c8a1e8052e5d02a7b0a150423dbd9b116fc48d46630ff6e6a05b92102791646a8b49c2740352b4495c118d876347bf47d0551c01c4332fdc2df526f1a2102888bda53a424466b0451627df22090143bbf7c060e9eacb1e38426f6b07f2ae12102aee8967150dee220f613de3b239320355a498808084a93eaf39a34dcd62024852102d46e9259d0a0bb2bcbc461a3e68f34adca27b8d08fbe985853992b4b104e27412102e9944e35e5750ab621e098145b8e6cf373c273b7c04747d1aa020be0af40ccd62102f9a9d4b10a6d6c56d8c955c547330c589bb45e774551d46d415e51cd9ad5116321033b421566c124dfde4db9defe4084b7aa4e7f36744758d92806b8f72c2e943309210353dcc6b4cf6ad28aceb7f7b2db92a4bf07ac42d357adf756f3eca790664314b621037f55980af0455e4fb55aad9b85a55068bb6dc4740ea87276dc693f4598db45fa210384001daa88dabd23db878dbb1ce5b4c2a5fa72c3113e3514bf602325d0c37b8e21039056d089f2fe72dbc0a14780b4635b0dc8a1b40b7a59106325dd1bc45cc70493210397ab8ea7b0bf85bc7fc56bb27bf85e75502e94e76a6781c409f3f2ec3d1122192103b00e3b5b77884bf3cae204c4b4eac003601da75f96982ffcb3dcb29c5ee419b92103c1f3c0874cfe34b8131af34699589aacec4093399739ae352e8a46f80a6f68375fae").expect("constant sign_block_script parse"),
            initial_free_coins: 0,
        }
    }

    /// Network params for Liquid testnet
    pub fn liquidtestnet() -> Self {
        NetworkParams {
            network_id: "liquidtestnet".to_string(),
            fedpeg_script: script::Builder::new().push_opcode(OP_TRUE).into_script(),
            // Can be verified at https://github.com/ElementsProject/elements/blob/27c2fb6b7de404908f9ef2eb5c98c9989d1ab8e4/src/chainparams.cpp#L1108
            sign_block_script: Script::from_hex_no_prefix("51210217e403ddb181872c32a0cd468c710040b2f53d8cac69f18dad07985ee37e9a7151ae").expect("constant sign_block_script parse"),
            initial_free_coins: 2_100_000_000_000_000,
        }
    }

    /// Network params for a custom Elements network with defaults
    pub fn custom_network(network_id: String, fedpeg_script: Option<Script>, sign_block_script: Option<Script>, initial_free_coins: Option<u64>) -> Self {
        NetworkParams {
            network_id,
            fedpeg_script: fedpeg_script.unwrap_or_else(|| script::Builder::new().push_opcode(OP_TRUE).into_script()),
            sign_block_script: sign_block_script.unwrap_or_else(|| script::Builder::new().push_opcode(OP_TRUE).into_script()),
            initial_free_coins: initial_free_coins.unwrap_or(0),
        }
    }
}

/// Hash commitment of network parameters for a given Network
pub fn commit_to_custom_network_parameters(params: &NetworkParams) -> Vec<u8> {
    let mut eng = sha256::Hash::engine();
    eng.input(params.network_id.clone().as_bytes());
    eng.input(format!("{:x}", params.fedpeg_script).as_bytes());
    eng.input(format!("{:x}", params.sign_block_script).as_bytes());
    sha256::Hash::from_engine(eng).serialize()
}
