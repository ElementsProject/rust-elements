
# 0.25.2 - 2025-04-18

* [#226](https://github.com/ElementsProject/rust-elements/pull/226) elip102: rename from elip101
* [#225](https://github.com/ElementsProject/rust-elements/pull/225) Make AssetId::from_inner a const function
* [#224](https://github.com/ElementsProject/rust-elements/pull/224) pset: input: insert non-pset proprietary keys
* [#223](https://github.com/ElementsProject/rust-elements/pull/223) clippy: fix for new rust stable
* [#195](https://github.com/ElementsProject/rust-elements/pull/195) Fix WASM build and add a job in CI
* [#222](https://github.com/ElementsProject/rust-elements/pull/222) elementsd-tests: blind asset issuance based on node version
* [#220](https://github.com/ElementsProject/rust-elements/pull/220) tx: discountct: add missing testcase
* [#221](https://github.com/ElementsProject/rust-elements/pull/221) ci: fixes for rust stable clippy, and rust 1.56.1 compilation

# 0.25.1 - 2024-10-24

* [#218](https://github.com/ElementsProject/rust-elements/pull/218) discount: fix weight calculation

# 0.25.0 - 2024-09-23

* [#216](https://github.com/ElementsProject/rust-elements/pull/216) add Address::is_liquid
* [#215](https://github.com/ElementsProject/rust-elements/pull/215) docs: add a bunch of paragraph breaks.
* [#213](https://github.com/ElementsProject/rust-elements/pull/213) ELIP-0101: rename from LiquiDEX
* [#212](https://github.com/ElementsProject/rust-elements/pull/212) Stop implementing elements::Encodable with bitcoin::Encodable
* [#210](https://github.com/ElementsProject/rust-elements/pull/210) Address err refactor
* [#209](https://github.com/ElementsProject/rust-elements/pull/209) upgrade to bitcoin 0.32
* [#207](https://github.com/ElementsProject/rust-elements/pull/207) Add elip_liquidex module
* [#206](https://github.com/ElementsProject/rust-elements/pull/206) pset: elip100: add and get token metadata
* [#204](https://github.com/ElementsProject/rust-elements/pull/204) tx: add discount_weight and discount_vsize
* [#203](https://github.com/ElementsProject/rust-elements/pull/203) transaction: range-check pegin data when parsing
* [#201](https://github.com/ElementsProject/rust-elements/pull/201) pset: add optional asset blinding factor to input and output
* [#200](https://github.com/ElementsProject/rust-elements/pull/200) pset: input: add blinded issuance flag
* [#199](https://github.com/ElementsProject/rust-elements/pull/199) pset: input: add explicit amount and asset, and their proofs

# 0.24.1 - 2024-01-30

* [#196](https://github.com/ElementsProject/rust-elements/pull/196) Add constructor to `FullParams`

# 0.24.0 - 2024-01-12

* [#188](https://github.com/ElementsProject/rust-elements/pull/188) Update rust-bitcoin to 0.31.0, and associated dependencies
* [#186](https://github.com/ElementsProject/rust-elements/pull/186) Updated doc for impl Value blind method - returns blinded value*
* [#185](https://github.com/ElementsProject/rust-elements/pull/185) Exposed RangeProofMessage publically
* [#183](https://github.com/ElementsProject/rust-elements/pull/183) elip100: add missing AssetMetadata::new method
* [#182](https://github.com/ElementsProject/rust-elements/pull/182) ELIP-0100 implementation
* [#178](https://github.com/ElementsProject/rust-elements/pull/178) pset: fix remove_output
* [#177](https://github.com/ElementsProject/rust-elements/pull/177) rename pset::str::Error to ParseError and expose it
* [#176](https://github.com/ElementsProject/rust-elements/pull/176) Remove slip77
* [#175](https://github.com/ElementsProject/rust-elements/pull/175) Add to and from base64 string to pset
* [#173](https://github.com/ElementsProject/rust-elements/pull/173) Fix examples
* [#171](https://github.com/ElementsProject/rust-elements/pull/171) Create explicit empty and null values for some types

# 0.23.0 - 2023-06-18

* [#167](https://github.com/ElementsProject/rust-elements/pull/167) Implement Ord for Transaction
* [#168](https://github.com/ElementsProject/rust-elements/pull/168) add Height::ZERO associated constant
* [#168](https://github.com/ElementsProject/rust-elements/pull/169) rename all Sighash types downcasing the middle "h", for example: SigHash -> Sighash

# 0.22.0 - 2023-06-08

* [#159](https://github.com/ElementsProject/rust-elements/pull/159) Update `TapTweak`, and `schnorr` module generally, to match rust-bitcoin
* [#160](https://github.com/ElementsProject/rust-elements/pull/160) Make `Prevouts` generic over type of `TxOut`
* [#161](https://github.com/ElementsProject/rust-elements/pull/161) Add `Transaction::vsize` method
* [#157](https://github.com/ElementsProject/rust-elements/pull/157) dynafed: extract `FullParams` from `Params`
* [#166](https://github.com/ElementsProject/rust-elements/pull/166) **Update bitcoin dependency to 0.30.0 and secp256k1-zkp dependency to 0.9.1**

# 0.21.1 - 2022-10-21

- Add `PeginData::parse_tx`
- Add `PeginData::parse_merkle_proof`

# 0.21.0 - 2022-10-19

- Copy `Sequence` and `LockTime` structures from rust-bitcoin 0.29.1
- Add `Txin::pegin_prevout` method which returns a `bitcoin::Outpoint`; modify `PeginData::from_pegin_witness` to take a bitcoin outpoint

# 0.20.0 - 2022-06-10

- Remove has_issuance field in TxIn, calculate it directly to avoid the user provide it.
- Blinding API cleanup into smaller chunks
- Issuance: add support for blinding, and surjection proof verification
- Pset: allow inserting inputs/outputs at specified position, fix Tweak serde and key bug
- Add liquid test parameters
- the feature "serde-feature" is now renamed to just "serde"
- update MSRV to 1.41.1
- breaking change in serde in how the Nonce is serialized
- `Block`, `BlockHeader`, `PeginData`, `PegoutData` loose the Default impl
- update rust-bitcoin to 0.29.1
- update secp256k1-zkp to 0.7.0
- update bitcoin_hashes to 0.11.0

# 0.19.2 - 2022-06-16

- revert dynafed field `fedpeg_program` back to `bitcoin::Script`

# 0.19.1 - 2022-06-10

- revert use of `io::BufRead` back to `io::Read` in `ConsensusEncodable` trait
- deprecate `Block::get_size` in favor of new `Block::size`
- deprecate `Block::get_weight` in favor of new `Block::weight`
- deprecate `Transaction::get_size` in favor of new `Transaction::size`
- deprecate `Transaction::get_weight` in favor of new `Transaction::weight`
- implement `Default` on `PartiallySignedTransaction`, `TxIn`

# 0.19 - 2022-04-30 "The Taproot Release"

- Taproot support for complex taptrees compatible with elements taproot signature.
- Taproot psbt support with BIP 371
hash. Refer to spec [here](https://github.com/ElementsProject/elements/blob/master/doc/taproot-sighash.mediawiki)
- Support for new tapscript transaction introspection opcodes as per the [spec](https://github.com/ElementsProject/elements/blob/master/doc/tapscript_opcodes.md).
- Works with bitcoin 0.28 key types.
