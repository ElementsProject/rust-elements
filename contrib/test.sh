#!/bin/sh -ex

FEATURES="serde"

# Use toolchain if explicitly specified
if [ -n "$TOOLCHAIN" ]
then
    alias cargo="cargo +$TOOLCHAIN"
fi

# Pin dependencies as required if we are using MSRV toolchain.
if cargo --version | grep "1\.41"; then
    # can be removed with elementsd 0.8.0
    cargo update -p zip --precise 0.5.6
    # 1.0.157 uses syn 2.0 which requires edition 2018
    cargo update -p serde --precise 1.0.156
    # 1.0.108 uses `matches!` macro so does not work with Rust 1.41.1, bad `syn` no biscuit.
    cargo update -p syn --precise 1.0.107
fi

# Test without any features first
cargo test --verbose --no-default-features
# Then test with the default features
cargo test --verbose

# Also build and run each example to catch regressions
cargo build --examples
# run all examples
run-parts ./target/debug/examples

# Test each feature
for feature in ${FEATURES}
do
    cargo test --verbose --features="$feature"
done

# Fuzz if told to
if [ "$DO_FUZZ" = true ]
then
    (
        cd fuzz
        cargo test --verbose
        ./travis-fuzz.sh
    )
fi

# Do integration test if told to
if [ "$DO_INTEGRATION" = true ]
then
    (
        cd elementsd-tests
        cargo test
        cd ..
    )
fi
