// Rust Bitcoin Library
// Written in 2019 by
//     The rust-bitcoin developers.
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

//! Taproot
//!
use hashes::{sha256, sha256t, Hash};

/// The SHA-256 midstate value for the TapLeaf/elements hash.
const MIDSTATE_TAPLEAF: [u8; 32] = [
    185, 165, 93, 95, 240, 236, 34, 5, 36, 232, 194, 245, 220, 195, 78, 19, 172,
    0, 50, 118, 247, 82, 182, 211, 91, 67, 107, 156, 165, 45, 235, 183
];
// (rev) b7eb2da59c6b435bd3b652f7763200ac134ec3dcf5c2e8240522ecf05f5da5b9

/// The SHA-256 midstate value for the TapBranch hash.
const MIDSTATE_TAPBRANCH: [u8; 32] = [
    252, 158, 245, 135, 52, 103, 176, 127, 235, 57, 57, 126, 85, 222, 151, 33, 244,
    104, 173, 199, 58, 32, 119, 252, 160, 87, 213, 147, 185, 136, 180, 140
];
// (rev) 8cb488b993d557a0fc77203ac7ad68f42197de557e3939eb7fb0673487f59efc

/// The SHA-256 midstate value for the TapTweak hash.
const MIDSTATE_TAPTWEAK: [u8; 32] = [
    7, 183, 63, 121, 138, 46, 7, 245, 251, 66, 173, 40, 201, 174, 109, 157, 27, 32,
    0, 107, 144, 33, 8, 203, 198, 48, 213, 13, 252, 12, 251, 9
];
// (rev) 09fb0cfc0dd530c6cb0821906b00201b9d6daec928ad42fbf5072e8a793fb707

/// The SHA-256 midstate value for the TapSigHash hash.
const MIDSTATE_TAPSIGHASH: [u8; 32] = [
    166, 230, 6, 120, 41, 228, 53, 167, 211, 20, 34, 171, 34, 191, 116, 23, 134,
    105, 138, 238, 229, 146, 92, 206, 255, 57, 14, 164, 52, 159, 126, 13
];
// (rev) 0d7e9f34a40e39ffce5c92e5ee8a69861774bf22ab2214d3a735e4297806e6a6

/// Internal macro to speficy the different taproot tagged hashes.
macro_rules! sha256t_hash_newtype {
    ($newtype:ident, $tag:ident, $midstate:ident, $midstate_len:expr, $docs:meta, $reverse: expr) => {
        sha256t_hash_newtype!($newtype, $tag, $midstate, $midstate_len, $docs, $reverse, stringify!($newtype));
    };

    ($newtype:ident, $tag:ident, $midstate:ident, $midstate_len:expr, $docs:meta, $reverse: expr, $sname:expr) => {
        #[doc = "The tag used for ["]
        #[doc = $sname]
        #[doc = "]"]
        pub struct $tag;

        impl sha256t::Tag for $tag {
            fn engine() -> sha256::HashEngine {
                let midstate = sha256::Midstate::from_inner($midstate);
                sha256::HashEngine::from_midstate(midstate, $midstate_len)
            }
        }

        hash_newtype!($newtype, sha256t::Hash<$tag>, 32, $docs, $reverse);
    };
}

// Taproot test vectors from BIP-341 state the hashes without any reversing
sha256t_hash_newtype!(TapLeafHash, TapLeafTag, MIDSTATE_TAPLEAF, 64,
    doc="Taproot-tagged hash for tapscript Merkle tree leafs", false
);
sha256t_hash_newtype!(TapBranchHash, TapBranchTag, MIDSTATE_TAPBRANCH, 64,
    doc="Taproot-tagged hash for tapscript Merkle tree branches", false
);
sha256t_hash_newtype!(TapTweakHash, TapTweakTag, MIDSTATE_TAPTWEAK, 64,
    doc="Taproot-tagged hash for public key tweaks", false
);
sha256t_hash_newtype!(TapSighashHash, TapSighashTag, MIDSTATE_TAPSIGHASH, 64,
    doc="Taproot-tagged hash for the taproot signature hash", false
);

#[cfg(test)]
mod tests{
    use super::*;
    use hashes::HashEngine;
    use hashes::sha256t::Tag;

    fn tag_engine(tag_name: &str) -> sha256::HashEngine {
        let mut engine = sha256::Hash::engine();
        let tag_hash = sha256::Hash::hash(tag_name.as_bytes());
        engine.input(&tag_hash[..]);
        engine.input(&tag_hash[..]);
        engine
    }

    #[test]
    fn test_midstates() {
        // check midstate against hard-coded values
        assert_eq!(MIDSTATE_TAPLEAF, tag_engine("TapLeaf/elements").midstate().into_inner());
        assert_eq!(MIDSTATE_TAPBRANCH, tag_engine("TapBranch/elements").midstate().into_inner());
        assert_eq!(MIDSTATE_TAPTWEAK, tag_engine("TapTweak/elements").midstate().into_inner());
        assert_eq!(MIDSTATE_TAPSIGHASH, tag_engine("TapSighash/elements").midstate().into_inner());

        // test that engine creation roundtrips
        assert_eq!(tag_engine("TapLeaf/elements").midstate(), TapLeafTag::engine().midstate());
        assert_eq!(tag_engine("TapBranch/elements").midstate(), TapBranchTag::engine().midstate());
        assert_eq!(tag_engine("TapTweak/elements").midstate(), TapTweakTag::engine().midstate());
        assert_eq!(tag_engine("TapSighash/elements").midstate(), TapSighashTag::engine().midstate());

        // check that hash creation is the same as building into the same engine
        fn empty_hash(tag_name: &str) -> [u8; 32] {
            let mut e = tag_engine(tag_name);
            e.input(&[]);
            sha256::Hash::from_engine(e).into_inner()
        }
        assert_eq!(empty_hash("TapLeaf/elements"), TapLeafHash::hash(&[]).into_inner());
        assert_eq!(empty_hash("TapBranch/elements"), TapBranchHash::hash(&[]).into_inner());
        assert_eq!(empty_hash("TapTweak/elements"), TapTweakHash::hash(&[]).into_inner());
        assert_eq!(empty_hash("TapSighash/elements"), TapSighashHash::hash(&[]).into_inner());
    }
}