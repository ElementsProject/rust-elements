// Rust Elements Library
// Written in 2019 by
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

use bitcoin::hashes::{sha256, Hash, HashEngine};

/// Calculate a single sha256 midstate hash of the given left and right leaves.
#[inline]
fn sha256midstate(left: &[u8], right: &[u8]) -> sha256::Midstate {
    let mut engine = sha256::Hash::engine();
    engine.input(left);
    engine.input(right);
    engine.midstate()
}

/// Compute the Merkle root of the give hashes using mid-state only.
/// The inputs must be byte slices of length 32.
/// Note that the merkle root calculated with this method is not the same as the
/// one computed by a normal SHA256(d) merkle root.
pub fn fast_merkle_root(leaves: &[[u8; 32]]) -> sha256::Midstate {
    let mut result_hash = Default::default();
    // Implementation based on ComputeFastMerkleRoot method in Elements Core.
    if leaves.is_empty() {
        return result_hash;
    }

    // inner is an array of eagerly computed subtree hashes, indexed by tree
    // level (0 being the leaves).
    // For example, when count is 25 (11001 in binary), inner[4] is the hash of
    // the first 16 leaves, inner[3] of the next 8 leaves, and inner[0] equal to
    // the last leaf. The other inner entries are undefined.
    //
    // First process all leaves into 'inner' values.
    let mut inner: [sha256::Midstate; 32] = Default::default();
    let mut count: u32 = 0;
    while (count as usize) < leaves.len() {
        let mut temp_hash = sha256::Midstate::from_inner(leaves[count as usize]);
        count += 1;
        // For each of the lower bits in count that are 0, do 1 step. Each
        // corresponds to an inner value that existed before processing the
        // current leaf, and each needs a hash to combine it.
        let mut level = 0;
        while count & (1u32 << level) == 0 {
            temp_hash = sha256midstate(&inner[level][..], &temp_hash[..]);
            level += 1;
        }
        // Store the resulting hash at inner position level.
        inner[level] = temp_hash;
    }

    // Do a final 'sweep' over the rightmost branch of the tree to process
    // odd levels, and reduce everything to a single top value.
    // Level is the level (counted from the bottom) up to which we've sweeped.
    //
    // As long as bit number level in count is zero, skip it. It means there
    // is nothing left at this level.
    let mut level = 0;
    while count & (1u32 << level) == 0 {
        level += 1;
    }
    result_hash = inner[level];

    while count != (1u32 << level) {
        // If we reach this point, hash is an inner value that is not the top.
        // We combine it with itself (Bitcoin's special rule for odd levels in
        // the tree) to produce a higher level one.

        // Increment count to the value it would have if two entries at this
        // level had existed and propagate the result upwards accordingly.
        count += 1 << level;
        level += 1;
        while count & (1u32 << level) == 0 {
            result_hash = sha256midstate(&inner[level][..], &result_hash[..]);
            level += 1;
        }
    }
    // Return result.
    result_hash
}

#[cfg(test)]
mod tests {
    use super::fast_merkle_root;
    use bitcoin::hashes::hex::FromHex;
    use bitcoin::hashes::sha256;

    #[test]
    fn test_fast_merkle_root() {
        // unit test vectors from Elements Core
        let test_leaves = [
            "b66b041650db0f297b53f8d93c0e8706925bf3323f8c59c14a6fac37bfdcd06f",
            "99cb2fa68b2294ae133550a9f765fc755d71baa7b24389fed67d1ef3e5cb0255",
            "257e1b2fa49dd15724c67bac4df7911d44f6689860aa9f65a881ae0a2f40a303",
            "b67b0b9f093fa83d5e44b707ab962502b7ac58630e556951136196e65483bb80",
        ];

        let test_roots = [
            "0000000000000000000000000000000000000000000000000000000000000000",
            "b66b041650db0f297b53f8d93c0e8706925bf3323f8c59c14a6fac37bfdcd06f",
            "f752938da0cb71c051aabdd5a86658e8d0b7ac00e1c2074202d8d2a79d8a6cf6",
            "245d364a28e9ad20d522c4a25ffc6a7369ab182f884e1c7dcd01aa3d32896bd3",
            "317d6498574b6ca75ee0368ec3faec75e096e245bdd5f36e8726fa693f775dfc",
        ];

        let mut leaves = vec![];
        for i in 0..4 {
            let root = fast_merkle_root(&leaves);
            assert_eq!(
                root,
                FromHex::from_hex(&test_roots[i]).unwrap(),
                "root #{}",
                i
            );
            leaves.push(
                sha256::Midstate::from_hex(&test_leaves[i])
                    .unwrap()
                    .into_inner(),
            );
        }
        assert_eq!(
            fast_merkle_root(&leaves),
            FromHex::from_hex(test_roots[4]).unwrap()
        );
    }
}
