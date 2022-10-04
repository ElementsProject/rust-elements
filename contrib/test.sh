#!/bin/sh -ex

FEATURES="serde"

# Use toolchain if explicitly specified
if [ -n "$TOOLCHAIN" ]
then
    alias cargo="cargo +$TOOLCHAIN"
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
        cargo test --features integration
    )
fi
