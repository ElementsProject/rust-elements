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
use std::cmp::Reverse;
use std::{error, io, fmt};

use crate::hashes::{sha256, sha256t_hash_newtype, Hash, HashEngine};
use crate::schnorr::{UntweakedPublicKey, TweakedPublicKey, TapTweak};
use crate::Script;
use std::collections::{BTreeMap, BTreeSet, BinaryHeap};
use secp256k1_zkp::{self, Secp256k1, Scalar};
use crate::encode::Encodable;

// Taproot test vectors from BIP-341 state the hashes without any reversing
sha256t_hash_newtype! {
    pub struct TapLeafTag = hash_str("TapLeaf/elements");
    /// Taproot-tagged hash for elements tapscript Merkle tree leafs.
    #[hash_newtype(forward)]
    pub struct TapLeafHash(_);

    pub struct TapBranchTag = hash_str("TapBranch/elements");
    /// Tagged hash used in taproot trees; see BIP-340 for tagging rules.
    #[hash_newtype(forward)]
    pub struct TapNodeHash(_);

    pub struct TapTweakTag = hash_str("TapTweak/elements");
    /// Taproot-tagged hash for elements public key tweaks.
    #[hash_newtype(forward)]
    pub struct TapTweakHash(_);

    pub struct TapSighashTag = hash_str("TapSighash/elements");
    /// Taproot-tagged hash for the elements taproot signature hash.
    #[hash_newtype(forward)]
    pub struct TapSighashHash(_);
}

impl TapTweakHash {

    /// Create a new BIP341 [`TapTweakHash`] from key and tweak
    /// Produces `H_taptweak(P||R)` where P is internal key and R is the merkle root
    pub fn from_key_and_tweak(
        internal_key: UntweakedPublicKey,
        merkle_root: Option<TapNodeHash>,
    ) -> TapTweakHash {
        let mut eng = TapTweakHash::engine();
        // always hash the key
        eng.input(&internal_key.serialize());
        if let Some(h) = merkle_root {
            eng.input(h.as_ref());
        } else {
            // nothing to hash
        }
        TapTweakHash::from_engine(eng)
    }

    /// Converts a `TapTweakHash` into a `Scalar` ready for use with key tweaking API.
    pub fn to_scalar(self) -> Scalar {
        // This is statistically extremely unlikely to panic.
        Scalar::from_be_bytes(self.to_byte_array()).expect("hash value greater than curve order")
    }
}

impl TapLeafHash {
    /// function to compute leaf hash from components
    pub fn from_script(script: &Script, ver: LeafVersion) -> TapLeafHash {
        let mut eng = TapLeafHash::engine();
        ver.as_u8()
            .consensus_encode(&mut eng)
            .expect("engines don't error");
        script
            .consensus_encode(&mut eng)
            .expect("engines don't error");
        TapLeafHash::from_engine(eng)
    }
}

/// Maximum depth of a Taproot Tree Script spend path
pub const TAPROOT_CONTROL_MAX_NODE_COUNT: usize = 128;
/// Size of a taproot control node
pub const TAPROOT_CONTROL_NODE_SIZE: usize = 32;
/// Tapleaf mask for getting the leaf version from first byte of control block
pub const TAPROOT_LEAF_MASK: u8 = 0xfe;
/// Tapscript leaf version (Note that this is different from bitcoin's 0xc0)
pub const TAPROOT_LEAF_TAPSCRIPT: u8 = 0xc4;
/// Tapscript control base size
pub const TAPROOT_CONTROL_BASE_SIZE: usize = 33;
/// Tapscript control max size
pub const TAPROOT_CONTROL_MAX_SIZE: usize =
    TAPROOT_CONTROL_BASE_SIZE + TAPROOT_CONTROL_NODE_SIZE * TAPROOT_CONTROL_MAX_NODE_COUNT;

// type alias for versioned tap script corresponding merkle proof
type ScriptMerkleProofMap = BTreeMap<(Script, LeafVersion), BTreeSet<TaprootMerkleBranch>>;
/// Data structure for representing Taproot spending information.
///
/// Taproot output corresponds to a combination of a
/// single public key condition (known the internal key), and zero or more
/// general conditions encoded in scripts organized in the form of a binary tree.
///
/// Taproot can be spent be either:
/// - Spending using the key path i.e., with secret key corresponding to the `output_key`
/// - By satisfying any of the scripts in the script spent path. Each script can be satisfied by providing
///   a witness stack consisting of the script's inputs, plus the script itself and the control block.
///
/// If one or more of the spending conditions consist of just a single key (after aggregation),
/// the most likely one should be made the internal key.
/// See [BIP341 for elements](https://github.com/ElementsProject/elements/blob/master/doc/taproot-sighash.mediawiki) for more details
/// on choosing internal keys for a taproot application
///
/// Note: This library currently does not support [annex](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki#cite_note-5)
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TaprootSpendInfo {
    /// The BIP341 internal key.
    internal_key: UntweakedPublicKey,
    /// The Merkle root of the script tree (None if there are no scripts)
    merkle_root: Option<TapNodeHash>,
    /// The sign final output pubkey as per BIP 341
    output_key_parity: secp256k1_zkp::Parity,
    /// The tweaked output key
    output_key: TweakedPublicKey,
    /// Map from (script, `leaf_version`) to (sets of) [`TaprootMerkleBranch`].
    /// More than one control block for a given script is only possible if it
    /// appears in multiple branches of the tree. In all cases, keeping one should
    /// be enough for spending funds, but we keep all of the paths so that
    /// a full tree can be constructed again from spending data if required.
    script_map: ScriptMerkleProofMap,
}

impl TaprootSpendInfo {
    /// Create a new [`TaprootSpendInfo`] from a list of script(with default script version) and
    /// weights of satisfaction for that script. The weights represent the probability of
    /// each branch being taken. If probabilities/weights for each condition are known,
    /// constructing the tree as a Huffman tree is the optimal way to minimize average
    /// case satisfaction cost. This function takes input an iterator of tuple(u64, &Script)
    /// where usize represents the satisfaction weights of the branch.
    /// For example, [(3, S1), (2, S2), (5, S3)] would construct a `TapTree` that has optimal
    /// satisfaction weight when probability for S1 is 30%, S2 is 20% and S3 is 50%.
    ///
    /// # Errors:
    ///
    /// - When the optimal huffman tree has a depth more than 128
    /// - If the provided list of script weights is empty
    ///
    /// # Edge Cases:
    /// - If the script weight calculations overflow, a sub-optimal tree may be generated. This
    ///   should not happen unless you are dealing with billions of branches with weights close to
    ///   2^32.
    pub fn with_huffman_tree<C, I>(
        secp: &Secp256k1<C>,
        internal_key: UntweakedPublicKey,
        script_weights: I,
    ) -> Result<Self, TaprootBuilderError>
    where
        I: IntoIterator<Item = (u32, Script)>,
        C: secp256k1_zkp::Verification,
    {
        let mut node_weights = BinaryHeap::<(Reverse<u64>, NodeInfo)>::new();
        for (p, leaf) in script_weights {
            node_weights.push((Reverse(u64::from(p)), NodeInfo::new_leaf_with_ver(leaf, LeafVersion::default())));
        }
        if node_weights.is_empty() {
            return Err(TaprootBuilderError::IncompleteTree);
        }
        while node_weights.len() > 1 {
            // Combine the last two elements and insert a new node
            let (p1, s1) = node_weights.pop().expect("len must be at least two");
            let (p2, s2) = node_weights.pop().expect("len must be at least two");
            // Insert the sum of first two in the tree as a new node
            // N.B.: p1 + p2 can not practically saturate as you would need to have 2**32 max u32s
            // from the input to overflow. However, saturating is a reasonable behavior here as
            // huffman tree construction would treat all such elements as "very likely".
            let p = Reverse(p1.0.saturating_add(p2.0));
            node_weights.push((p, NodeInfo::combine(s1, s2)?));
        }
        // Every iteration of the loop reduces the node_weights.len() by exactly 1
        // Therefore, the loop will eventually terminate with exactly 1 element
        debug_assert!(node_weights.len() == 1);
        let node = node_weights.pop().expect("huffman tree algorithm is broken").1;
        Ok(Self::from_node_info(secp, internal_key, node))
    }

    /// Create a new key spend with internal key and proided merkle root.
    /// Provide [`None`] for `merkle_root` if there is no script path.
    ///
    /// *Note*: As per BIP341
    ///
    /// When the merkle root is [`None`], the output key commits to an unspendable
    /// script path instead of having no script path. This is achieved by computing
    /// the output key point as Q = P + int(hashTapTweak(bytes(P)))G.
    /// See also [`TaprootSpendInfo::tap_tweak`].
    /// Refer to BIP 341 footnote (Why should the output key always have
    /// a taproot commitment, even if there is no script path?) for more details
    ///
    pub fn new_key_spend<C: secp256k1_zkp::Verification>(
        secp: &Secp256k1<C>,
        internal_key: UntweakedPublicKey,
        merkle_root: Option<TapNodeHash>,
    ) -> Self {
        let (output_key, parity) = internal_key.tap_tweak(secp, merkle_root);
        Self {
            internal_key,
            merkle_root,
            output_key_parity: parity,
            output_key,
            script_map: BTreeMap::new(),
        }
    }

    /// Obtain the tweak and parity used to compute the `output_key`
    pub fn tap_tweak(&self) -> TapTweakHash {
        TapTweakHash::from_key_and_tweak(self.internal_key, self.merkle_root)
    }

    /// Obtain the internal key
    pub fn internal_key(&self) -> UntweakedPublicKey {
        self.internal_key
    }

    /// Obtain the merkle root
    pub fn merkle_root(&self) -> Option<TapNodeHash> {
        self.merkle_root
    }

    /// Output key(the key used in script pubkey) from Spend data. See also
    /// [`TaprootSpendInfo::output_key_parity`]
    pub fn output_key(&self) -> TweakedPublicKey {
        self.output_key
    }

    /// Parity of the output key. See also [`TaprootSpendInfo::output_key`]
    pub fn output_key_parity(&self) -> secp256k1_zkp::Parity {
        self.output_key_parity
    }

    // Internal function to compute [`TaprootSpendInfo`] from NodeInfo
    fn from_node_info<C: secp256k1_zkp::Verification>(
        secp: &Secp256k1<C>,
        internal_key: UntweakedPublicKey,
        node: NodeInfo,
    ) -> TaprootSpendInfo {
        // Create as if it is a key spend path with the given merkle root
        let root_hash = Some(TapNodeHash::from_byte_array(node.hash.to_byte_array()));
        let mut info = TaprootSpendInfo::new_key_spend(secp, internal_key, root_hash);
        for leaves in node.leaves {
            let key = (leaves.script, leaves.ver);
            let value = leaves.merkle_branch;
            if let Some(set) = info.script_map.get_mut(&key) {
                set.insert(value);
            } else {
                let mut set = BTreeSet::new();
                set.insert(value);
                info.script_map.insert(key, set);
            }
        }
        info
    }

    /// Access the internal script map
    pub fn as_script_map(&self) -> &ScriptMerkleProofMap {
        &self.script_map
    }

    /// Obtain a [`ControlBlock`] for particular script with the given version.
    /// Returns [`None`] if the script is not contained in the [`TaprootSpendInfo`]
    /// If there are multiple `ControlBlocks` possible, this returns the shortest one.
    pub fn control_block(&self, script_ver: &(Script, LeafVersion)) -> Option<ControlBlock> {
        let merkle_branch_set = self.script_map.get(script_ver)?;
        // Choose the smallest one amongst the multiple script maps
        let smallest = merkle_branch_set
            .iter()
            .min_by(|x, y| x.0.len().cmp(&y.0.len()))
            .expect("Invariant: Script map key must contain non-empty set value");
        Some(ControlBlock {
            internal_key: self.internal_key,
            output_key_parity: self.output_key_parity,
            leaf_version: script_ver.1,
            merkle_branch: smallest.clone(),
        })
    }
}

/// Builder for building taproot iteratively. Users can specify tap leaf or omitted/hidden
/// branches in a DFS(Depth first search) walk to construct this tree.
// Similar to Taproot Builder in bitcoin core
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[cfg_attr(feature = "serde",  derive(serde::Serialize, serde::Deserialize))]
pub struct TaprootBuilder {
    // The following doc-comment is from bitcoin core, but modified for rust
    // The comment below describes the current state of the builder for a given tree.
    //
    // For each level in the tree, one NodeInfo object may be present. branch at index 0
    // is information about the root; further values are for deeper subtrees being
    // explored.
    //
    // During the construction of Taptree, for every right branch taken to
    // reach the position we're currently working in, there will be a (Some(_))
    // entry in branch corresponding to the left branch at that level.
    //
    // For example, imagine this tree:     - N0 -
    //                                    /      \
    //                                   N1      N2
    //                                  /  \    /  \
    //                                 A    B  C   N3
    //                                            /  \
    //                                           D    E
    //
    // Initially, branch is empty. After processing leaf A, it would become
    // {None, None, A}. When processing leaf B, an entry at level 2 already
    // exists, and it would thus be combined with it to produce a level 1 one,
    // resulting in {None, N1}. Adding C and D takes us to {None, N1, C}
    // and {None, N1, C, D} respectively. When E is processed, it is combined
    // with D, and then C, and then N1, to produce the root, resulting in {N0}.
    //
    // This structure allows processing with just O(log n) overhead if the leaves
    // are computed on the fly.
    //
    // As an invariant, there can never be None entries at the end. There can
    // also not be more than 128 entries (as that would mean more than 128 levels
    // in the tree). The depth of newly added entries will always be at least
    // equal to the current size of branch (otherwise it does not correspond
    // to a depth-first traversal of a tree). branch is only empty if no entries
    // have ever be processed. branch having length 1 corresponds to being done.
    //
    branch: Vec<Option<NodeInfo>>,
}

impl TaprootBuilder {
    /// Create a new instance of [`TaprootBuilder`]
    pub fn new() -> Self {
        TaprootBuilder { branch: vec![] }
    }

    /// Check if the builder is a complete tree
    pub fn is_complete(&self) -> bool {
        self.branch.len() == 1 && self.branch[0].is_some()
    }

    pub(crate) fn branch(&self) -> &[Option<NodeInfo>]{
        &self.branch
    }

    /// Just like [`TaprootBuilder::add_leaf`] but allows to specify script version
    pub fn add_leaf_with_ver(
        self,
        depth: usize,
        script: Script,
        ver: LeafVersion,
    ) -> Result<Self, TaprootBuilderError> {
        let leaf = NodeInfo::new_leaf_with_ver(script, ver);
        self.insert(leaf, depth)
    }

    /// Add a leaf script at a depth `depth` to the builder with default script version.
    /// This will error if the leave are not provided in a DFS walk order. The depth of the
    /// root node is 0 and it's immediate child would be at depth 1.
    /// See [`TaprootBuilder::add_leaf_with_ver`] for adding a leaf with specific version
    /// See [Wikipedia](https://en.wikipedia.org/wiki/Depth-first_search) for more details
    pub fn add_leaf(self, depth: usize, script: Script) -> Result<Self, TaprootBuilderError> {
        self.add_leaf_with_ver(depth, script, LeafVersion::default())
    }

    /// Add a hidden/omitted node at a depth `depth` to the builder.
    /// This will error if the node are not provided in a DFS walk order. The depth of the
    /// root node is 0 and it's immediate child would be at depth 1.
    pub fn add_hidden(self, depth: usize, hash: sha256::Hash) -> Result<Self, TaprootBuilderError> {
        let node = NodeInfo::new_hidden(hash);
        self.insert(node, depth)
    }

    /// Create [`TaprootSpendInfo`] with the given internal key
    pub fn finalize<C: secp256k1_zkp::Verification>(
        mut self,
        secp: &Secp256k1<C>,
        internal_key: UntweakedPublicKey,
    ) -> Result<TaprootSpendInfo, TaprootBuilderError> {
        if self.branch.len() > 1 {
            return Err(TaprootBuilderError::IncompleteTree);
        }
        let node = self
            .branch
            .pop()
            .ok_or(TaprootBuilderError::EmptyTree)?
            .expect("Builder invariant: last element of the branch must be some");
        Ok(TaprootSpendInfo::from_node_info(secp, internal_key, node))
    }

    // Helper function to insert a leaf at a depth
    fn insert(mut self, mut node: NodeInfo, mut depth: usize) -> Result<Self, TaprootBuilderError> {
        // early error on invalid depth. Though this will be checked later
        // while constructing TaprootMerkelBranch
        if depth > TAPROOT_CONTROL_MAX_NODE_COUNT {
            return Err(TaprootBuilderError::InvalidMerkleTreeDepth(depth));
        }
        // We cannot insert a leaf at a lower depth while a deeper branch is unfinished. Doing
        // so would mean the add_leaf/add_hidden invocations do not correspond to a DFS traversal of a
        // binary tree.
        if depth + 1 < self.branch.len() {
            return Err(TaprootBuilderError::NodeNotInDfsOrder);
        }

        while self.branch.len() == depth + 1 {
            let child = match self.branch.pop() {
                None => unreachable!("Len of branch checked to be >= 1"),
                Some(Some(child)) => child,
                // Needs an explicit push to add the None that we just popped.
                // Cannot use .last() because of borrow checker issues.
                Some(None) => {
                    self.branch.push(None);
                    break;
                } // Cannot combine further
            };
            if depth == 0 {
                // We are trying to combine two nodes at root level.
                // Can't propagate further up than the root
                return Err(TaprootBuilderError::OverCompleteTree);
            }
            node = NodeInfo::combine(node, child)?;
            // Propagate to combine nodes at a lower depth
            depth -= 1;
        }

        if self.branch.len() < depth + 1 {
            // add enough nodes so that we can insert node at depth `depth`
            let num_extra_nodes = depth + 1 - self.branch.len();
            self.branch
                .extend((0..num_extra_nodes).map(|_| None));
        }
        // Push the last node to the branch
        self.branch[depth] = Some(node);
        Ok(self)
    }
}

/// Structure to represent the node information in taproot tree
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde",  derive(serde::Serialize, serde::Deserialize))]
pub struct NodeInfo {
    /// Merkle Hash for this node
    pub(crate) hash: sha256::Hash,
    /// information about leaves inside this node
    pub(crate) leaves: Vec<LeafInfo>,
}

impl NodeInfo {
    /// Creates a new `NodeInfo` with omitted/hidden info
    pub fn new_hidden(hash: sha256::Hash) -> Self {
        Self {
            hash,
            leaves: vec![],
        }
    }

    /// Creates a new leaf with `NodeInfo`
    pub fn new_leaf_with_ver(script: Script, ver: LeafVersion) -> Self {
        let leaf = LeafInfo::new(script, ver);
        Self {
            hash: leaf.hash(),
            leaves: vec![leaf],
        }
    }

    /// Combines two `NodeInfo`'s to create a new parent
    pub fn combine(a: Self, b: Self) -> Result<Self, TaprootBuilderError> {
        let mut all_leaves = Vec::with_capacity(a.leaves.len() + b.leaves.len());
        for mut a_leaf in a.leaves {
            a_leaf.merkle_branch.push(b.hash)?; // add hashing partner
            all_leaves.push(a_leaf);
        }
        for mut b_leaf in b.leaves {
            b_leaf.merkle_branch.push(a.hash)?; // add hashing partner
            all_leaves.push(b_leaf);
        }
        let mut eng = TapNodeHash::engine();
        if a.hash < b.hash {
            eng.input(a.hash.as_ref());
            eng.input(b.hash.as_ref());
        } else {
            eng.input(b.hash.as_ref());
            eng.input(a.hash.as_ref());
        };
        Ok(Self {
            hash: sha256::Hash::from_engine(eng),
            leaves: all_leaves,
        })
    }
}

/// Data Structure to store information about taproot leaf node
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde",  derive(serde::Serialize, serde::Deserialize))]
pub struct LeafInfo {
    // The underlying script
    pub(crate) script: Script,
    // The leaf version
    pub(crate) ver: LeafVersion,
    // The merkle proof(hashing partners) to get this node
    pub(crate) merkle_branch: TaprootMerkleBranch,
}

impl LeafInfo {
    /// Creates an instance of Self from Script with default version and no merkle branch
    pub fn new(script: Script, ver: LeafVersion) -> Self {
        Self {
            script,
            ver,
            merkle_branch: TaprootMerkleBranch(vec![]),
        }
    }

    // Computes a leaf hash for the given leaf
    fn hash(&self) -> sha256::Hash {
        let leaf_hash = TapLeafHash::from_script(&self.script, self.ver);
        sha256::Hash::from_byte_array(leaf_hash.to_byte_array())
    }
}

/// The Merkle proof for inclusion of a tree in a taptree hash
// The type of hash is sha256::Hash because the vector might contain
// both TapNodeHash and TapLeafHash
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[cfg_attr(feature = "serde",  derive(serde::Serialize, serde::Deserialize))]
pub struct TaprootMerkleBranch(Vec<sha256::Hash>);

impl TaprootMerkleBranch {
    /// Obtain a reference to inner
    pub fn as_inner(&self) -> &[sha256::Hash] {
        &self.0
    }

    /// Create a merkle proof from slice
    pub fn from_slice(sl: &[u8]) -> Result<Self, TaprootError> {
        if sl.len() % TAPROOT_CONTROL_NODE_SIZE != 0 {
            Err(TaprootError::InvalidMerkleBranchSize(sl.len()))
        } else if sl.len() > TAPROOT_CONTROL_NODE_SIZE * TAPROOT_CONTROL_MAX_NODE_COUNT {
            Err(TaprootError::InvalidMerkleTreeDepth(
                sl.len() / TAPROOT_CONTROL_NODE_SIZE,
            ))
        } else {
            let inner = sl
                // TODO: Use chunks_exact after MSRV changes to 1.31
                .chunks(TAPROOT_CONTROL_NODE_SIZE)
                .map(|chunk| {
                    sha256::Hash::from_slice(chunk)
                        .expect("chunk exact always returns the correct size")
                })
                .collect();
            Ok(TaprootMerkleBranch(inner))
        }
    }

    /// Serialize to a writer. Returns the number of bytes written
    pub fn encode<Write: io::Write>(&self, mut writer: Write) -> io::Result<usize> {
        let mut written = 0;
        for hash in &self.0 {
            written += writer.write(hash.as_ref())?;
        }
        Ok(written)
    }

    /// Serialize self as bytes
    pub fn serialize(&self) -> Vec<u8> {
        self.0.iter().flat_map(sha256::Hash::as_byte_array).copied().collect::<Vec<u8>>()
    }

    // Internal function to append elements to proof
    fn push(&mut self, h: sha256::Hash) -> Result<(), TaprootBuilderError> {
        if self.0.len() >= TAPROOT_CONTROL_MAX_NODE_COUNT {
            Err(TaprootBuilderError::InvalidMerkleTreeDepth(self.0.len()))
        } else {
            self.0.push(h);
            Ok(())
        }
    }

    /// Create a `MerkleProof` from Vec<[`sha256::Hash`]>. Returns an error when
    /// inner proof len is more than `TAPROOT_CONTROL_MAX_NODE_COUNT` (128)
    pub fn from_inner(inner: Vec<sha256::Hash>) -> Result<Self, TaprootError> {
        if inner.len() > TAPROOT_CONTROL_MAX_NODE_COUNT {
            Err(TaprootError::InvalidMerkleTreeDepth(inner.len()))
        } else {
            Ok(TaprootMerkleBranch(inner))
        }
    }

    /// Consume Self to get Vec<[`sha256::Hash`]>
    pub fn into_inner(self) -> Vec<sha256::Hash> {
        self.0
    }
}

/// Control Block data structure used in Tapscript satisfaction
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde",  derive(serde::Serialize, serde::Deserialize))]
pub struct ControlBlock {
    /// The tapleaf version,
    pub leaf_version: LeafVersion,
    /// The parity of the output key (NOT THE INTERNAL KEY WHICH IS ALWAYS XONLY)
    pub output_key_parity: secp256k1_zkp::Parity,
    /// The internal key
    pub internal_key: UntweakedPublicKey,
    /// The merkle proof of a script associated with this leaf
    pub merkle_branch: TaprootMerkleBranch,
}

impl ControlBlock {
    /// Obtain a `ControlBlock` from slice. This is an extra witness element
    /// that provides the proof that taproot script pubkey is correctly computed
    /// with some specified leaf hash. This is the last element in
    /// taproot witness when spending a output via script path.
    ///
    /// # Errors:
    /// - If the control block size is not of the form 33 + 32m where
    ///   0 <= m <= 128, `InvalidControlBlock` is returned
    pub fn from_slice(sl: &[u8]) -> Result<ControlBlock, TaprootError> {
        if sl.len() < TAPROOT_CONTROL_BASE_SIZE
            || (sl.len() - TAPROOT_CONTROL_BASE_SIZE) % TAPROOT_CONTROL_NODE_SIZE != 0
        {
            return Err(TaprootError::InvalidControlBlockSize(sl.len()));
        }
        let output_key_parity = secp256k1_zkp::Parity::from_u8(sl[0] & 1)
            .expect("Parity is a single bit because it is masked by 0x01");
        let leaf_version = LeafVersion::from_u8(sl[0] & TAPROOT_LEAF_MASK)?;
        let internal_key = UntweakedPublicKey::from_slice(&sl[1..TAPROOT_CONTROL_BASE_SIZE])
            .map_err(TaprootError::InvalidInternalKey)?;
        let merkle_branch = TaprootMerkleBranch::from_slice(&sl[TAPROOT_CONTROL_BASE_SIZE..])?;
        Ok(ControlBlock {
            leaf_version,
            output_key_parity,
            internal_key,
            merkle_branch,
        })
    }

    /// Obtain the size of control block. Faster and more efficient than calling
    /// `serialize()` followed by `len()`. Can be handy for fee estimation
    pub fn size(&self) -> usize {
        TAPROOT_CONTROL_BASE_SIZE + TAPROOT_CONTROL_NODE_SIZE * self.merkle_branch.as_inner().len()
    }

    /// Serialize to a writer. Returns the number of bytes written
    pub fn encode<Write: io::Write>(&self, mut writer: Write) -> io::Result<usize> {
        let first_byte: u8 = self.output_key_parity.to_u8() | self.leaf_version.as_u8();
        let mut bytes_written = 0;
        bytes_written += writer.write(&[first_byte])?;
        bytes_written += writer.write(&self.internal_key.serialize())?;
        bytes_written += self.merkle_branch.encode(&mut writer)?;
        Ok(bytes_written)
    }

    /// Serialize the control block. This would be required when
    /// using `ControlBlock` as a witness element while spending an output via
    /// script path. This serialization does not include the `VarInt` prefix that would be
    /// applied when encoding this element as a witness.
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.size());
        self.encode(&mut buf)
            .expect("writers don't error");
        buf
    }

    /// Verify that a control block is correct proof for a given output key and script
    /// This only checks that script is contained inside the taptree described by
    /// output key, full verification must also execute the script with witness data
    pub fn verify_taproot_commitment<C: secp256k1_zkp::Verification>(
        &self,
        secp: &Secp256k1<C>,
        output_key: &TweakedPublicKey,
        script: &Script,
    ) -> bool {
        // compute the script hash
        // Initially the curr_hash is the leaf hash
        let leaf_hash = TapLeafHash::from_script(script, self.leaf_version);
        let mut curr_hash = TapNodeHash::from_byte_array(leaf_hash.to_byte_array());
        // Verify the proof
        for elem in self.merkle_branch.as_inner() {
            let mut eng = TapNodeHash::engine();
            if curr_hash.as_byte_array() < elem.as_byte_array() {
                eng.input(curr_hash.as_ref());
                eng.input(elem.as_ref());
            } else {
                eng.input(elem.as_ref());
                eng.input(curr_hash.as_ref());
            }
            // Recalculate the curr hash as parent hash
            curr_hash = TapNodeHash::from_engine(eng);
        }
        // compute the taptweak
        let tweak = TapTweakHash::from_key_and_tweak(self.internal_key, Some(curr_hash));
        let tweak = Scalar::from_be_bytes(tweak.to_byte_array()).expect("hash value greater than curve order");

        self.internal_key.tweak_add_check(
            secp,
            output_key.as_inner(),
            self.output_key_parity,
            tweak,
        )
    }
}

/// The leaf version for tapleafs
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde",  derive(serde::Serialize, serde::Deserialize))]
pub struct LeafVersion(u8);

impl Default for LeafVersion {
    fn default() -> Self {
        LeafVersion(TAPROOT_LEAF_TAPSCRIPT)
    }
}

impl LeafVersion {
    /// Obtain `LeafVersion` from u8, will error when last bit of ver is even or
    /// when ver is 0x50 (`ANNEX_TAG`)
    // Text from BIP341:
    // In order to support some forms of static analysis that rely on
    // being able to identify script spends without access to the output being
    // spent, it is recommended to avoid using any leaf versions that would conflict
    // with a valid first byte of either a valid P2WPKH pubkey or a valid P2WSH script
    // (that is, both v and v | 1 should be an undefined, invalid or disabled opcode
    // or an opcode that is not valid as the first opcode).
    // The values that comply to this rule are the 32 even values between
    // 0xc0 and 0xfe and also 0x66, 0x7e, 0x80, 0x84, 0x96, 0x98, 0xba, 0xbc, 0xbe
    pub fn from_u8(ver: u8) -> Result<Self, TaprootError> {
        if ver & TAPROOT_LEAF_MASK == ver && ver != 0x50 {
            Ok(LeafVersion(ver))
        } else {
            Err(TaprootError::InvalidTaprootLeafVersion(ver))
        }
    }

    /// Get the inner version from `LeafVersion`
    pub fn as_u8(&self) -> u8 {
        self.0
    }
}

impl From<LeafVersion> for u8 {
    fn from(lv: LeafVersion) -> u8 {
        lv.0
    }
}

/// Detailed error type for taproot builder
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TaprootBuilderError {
    /// Merkle Tree depth must not be more than 128
    InvalidMerkleTreeDepth(usize),
    /// Nodes must be added specified in DFS order
    NodeNotInDfsOrder,
    /// Two nodes at depth 0 are not allowed
    OverCompleteTree,
    /// Invalid taproot internal key
    InvalidInternalKey(secp256k1_zkp::UpstreamError),
    /// Called finalize on an incomplete tree
    IncompleteTree,
    /// Called finalize on a empty tree
    EmptyTree,
}

impl fmt::Display for TaprootBuilderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            TaprootBuilderError::NodeNotInDfsOrder => {
                write!(f, "add_leaf/add_hidden must be called in DFS walk order",)
            }
            TaprootBuilderError::OverCompleteTree => write!(
                f,
                "Attempted to create a tree with two nodes at depth 0. There must\
                only be a exactly one node at depth 0",
            ),
            TaprootBuilderError::InvalidMerkleTreeDepth(d) => write!(
                f,
                "Merkle Tree depth({}) must be less than {}",
                d, TAPROOT_CONTROL_MAX_NODE_COUNT
            ),
            TaprootBuilderError::InvalidInternalKey(e) => {
                write!(f, "Invalid Internal XOnly key : {}", e)
            }
            TaprootBuilderError::IncompleteTree => {
                write!(f, "Called finalize on an incomplete tree")
            }
            TaprootBuilderError::EmptyTree => {
                write!(f, "Called finalize on an empty tree")
            }
        }
    }
}

impl error::Error for TaprootBuilderError {}

/// Detailed error type for taproot utilities
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TaprootError {
    /// Proof size must be a multiple of 32
    InvalidMerkleBranchSize(usize),
    /// Merkle Tree depth must not be more than 128
    InvalidMerkleTreeDepth(usize),
    /// The last bit of tapleaf version must be zero
    InvalidTaprootLeafVersion(u8),
    /// Invalid Control Block Size
    InvalidControlBlockSize(usize),
    /// Invalid taproot internal key
    InvalidInternalKey(secp256k1_zkp::UpstreamError),
    /// Empty `TapTree`
    EmptyTree,
}

impl fmt::Display for TaprootError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            TaprootError::InvalidMerkleBranchSize(sz) => write!(
                f,
                "Merkle branch size({}) must be a multiple of {}",
                sz, TAPROOT_CONTROL_NODE_SIZE
            ),
            TaprootError::InvalidMerkleTreeDepth(d) => write!(
                f,
                "Merkle Tree depth({}) must be less than {}",
                d, TAPROOT_CONTROL_MAX_NODE_COUNT
            ),
            TaprootError::InvalidTaprootLeafVersion(v) => write!(
                f,
                "Leaf version({}) must have the least significant bit 0",
                v
            ),
            TaprootError::InvalidControlBlockSize(sz) => write!(
                f,
                "Control Block size({}) must be of the form 33 + 32*m where  0 <= m <= {} ",
                sz, TAPROOT_CONTROL_MAX_NODE_COUNT
            ),
            // TODO: add source when in MSRV
            TaprootError::InvalidInternalKey(e) => write!(f, "Invalid Internal XOnly key : {}", e),
            TaprootError::EmptyTree => write!(f, "Taproot Tree must contain at least one script"),
        }
    }
}

impl error::Error for TaprootError {}

#[cfg(test)]
mod tests{
    use super::*;
    use crate::hashes::HashEngine;
    use crate::hashes::sha256t::Tag;
    use crate::hex::FromHex;
    use std::str::FromStr;

    fn tag_engine(tag_name: &str) -> sha256::HashEngine {
        let mut engine = sha256::Hash::engine();
        let tag_hash = sha256::Hash::hash(tag_name.as_bytes());
        engine.input(&tag_hash[..]);
        engine.input(&tag_hash[..]);
        engine
    }

    #[test]
    fn test_midstates() {
        // check that hash creation is the same as building into the same engine
        fn empty_hash(tag_name: &str) -> [u8; 32] {
            let mut e = tag_engine(tag_name);
            e.input(&[]);
            sha256::Hash::from_engine(e).to_byte_array()
        }

        // test that engine creation roundtrips
        assert_eq!(tag_engine("TapLeaf/elements").midstate(), TapLeafTag::engine().midstate());
        assert_eq!(tag_engine("TapBranch/elements").midstate(), TapBranchTag::engine().midstate());
        assert_eq!(tag_engine("TapTweak/elements").midstate(), TapTweakTag::engine().midstate());
        assert_eq!(tag_engine("TapSighash/elements").midstate(), TapSighashTag::engine().midstate());

        assert_eq!(empty_hash("TapLeaf/elements"), TapLeafHash::hash(&[]).to_byte_array());
        assert_eq!(empty_hash("TapBranch/elements"), TapNodeHash::hash(&[]).to_byte_array());
        assert_eq!(empty_hash("TapTweak/elements"), TapTweakHash::hash(&[]).to_byte_array());
        assert_eq!(empty_hash("TapSighash/elements"), TapSighashHash::hash(&[]).to_byte_array());
    }

    #[test]
    fn build_huffman_tree() {
        let secp = Secp256k1::verification_only();
        let internal_key = UntweakedPublicKey::from_str("93c7378d96518a75448821c4f7c8f4bae7ce60f804d03d1f0628dd5dd0f5de51").unwrap();

        let script_weights = vec![
            (10, Script::from_hex("51").unwrap()), // semantics of script don't matter for this test
            (20, Script::from_hex("52").unwrap()),
            (20, Script::from_hex("53").unwrap()),
            (30, Script::from_hex("54").unwrap()),
            (19, Script::from_hex("55").unwrap()),
        ];
        let tree_info = TaprootSpendInfo::with_huffman_tree(&secp, internal_key, script_weights.clone()).unwrap();

        /* The resulting tree should put the scripts into a tree similar
         * to the following:
         *
         *   1      __/\__
         *         /      \
         *        /\     / \
         *   2   54 52  53 /\
         *   3            55 51
         */

        for &(script, length) in &[("51", 3), ("52", 2), ("53", 2), ("54", 2), ("55", 3)] {
            assert_eq!(
                length,
                tree_info
                    .script_map
                    .get(&(Script::from_hex(script).unwrap(), LeafVersion::default()))
                    .expect("Present Key")
                    .iter()
                    .next()
                    .expect("Present Path")
                    .0
                    .len()
            );
        }

        // Obtain the output key
        let output_key = tree_info.output_key();

        // Try to create and verify a control block from each path
        for (_weights, script) in script_weights {
            let ver_script = (script, LeafVersion::default());
            let ctrl_block = tree_info.control_block(&ver_script).unwrap();
            assert!(ctrl_block.verify_taproot_commitment(&secp, &output_key, &ver_script.0));
        }
    }

    #[test]
    fn taptree_builder() {
        let secp = Secp256k1::verification_only();
        let internal_key = UntweakedPublicKey::from_str("93c7378d96518a75448821c4f7c8f4bae7ce60f804d03d1f0628dd5dd0f5de51").unwrap();

        let builder = TaprootBuilder::new();
        // Create a tree as shown below
        // For example, imagine this tree:
        // A, B , C are at depth 2 and D,E are at 3
        //                                       ....
        //                                     /      \
        //                                    /\      /\
        //                                   /  \    /  \
        //                                  A    B  C  / \
        //                                            D   E
        let scripts = [
            Script::from_hex("51").unwrap(),
            Script::from_hex("52").unwrap(),
            Script::from_hex("53").unwrap(),
            Script::from_hex("54").unwrap(),
            Script::from_hex("55").unwrap(),
        ];
        let builder = builder
            .add_leaf(2, scripts[0].clone()).unwrap()
            .add_leaf(2, scripts[1].clone()).unwrap()
            .add_leaf(2, scripts[2].clone()).unwrap()
            .add_leaf(3, scripts[3].clone()).unwrap()
            .add_leaf(3, scripts[4].clone()).unwrap();

        let tree_info = builder.finalize(&secp, internal_key).unwrap();
        let output_key = tree_info.output_key();

        for script in scripts {
            let ver_script = (script, LeafVersion::default());
            let ctrl_block = tree_info.control_block(&ver_script).unwrap();
            assert!(ctrl_block.verify_taproot_commitment(&secp, &output_key, &ver_script.0));
        }
    }
}
