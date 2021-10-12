[![Status](https://travis-ci.org/ElementsProject/rust-elements.png?branch=master)](https://travis-ci.org/ElementsProject/rust-elements)

# Rust Elements Library

Library with support for de/serialization, parsing and executing on data
structures and network messages related to Elements

[Documentation](https://docs.rs/elements/)


## Minimum Supported Rust Version (MSRV)
This library should always compile with any combination of features on **Rust 1.29**.

Because some dependencies have broken the build in minor/patch releases, to
compile with 1.29.0 you will need to run the following version-pinning command:
```
cargo update -p cc --precise "1.0.41" --verbose
```
In order to have serde support, the following versions also need to be pinned:
```
cargo update --package "serde" --precise "1.0.98"
cargo update --package "serde_derive" --precise "1.0.98"
```
