
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
