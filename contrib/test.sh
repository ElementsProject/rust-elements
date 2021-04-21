#!/bin/sh -ex

FEATURES="serde-feature"

pin_common_verions() {
    cargo generate-lockfile --verbose
    cargo update -p cc --precise "1.0.41" --verbose
    cargo update -p serde --precise "1.0.98" --verbose
    cargo update -p serde_derive --precise "1.0.98" --verbose
}

# Pin `cc` for Rust 1.29
if [ -n "$PIN_VERSIONS" ]; then
    pin_common_verions
fi


# Use toolchain if explicitly specified
if [ -n "$TOOLCHAIN" ]
then
    alias cargo="cargo +$TOOLCHAIN"
fi

# Test without any features first
cargo test --verbose --no-default-features
# Then test with the default features
cargo test --verbose

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

# Lint if told to
if [ "$DO_LINT" = true ]
then
    (
        rustup component add rustfmt
        cargo fmt --all -- --check
    )
fi