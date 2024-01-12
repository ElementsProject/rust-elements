#!/bin/sh -ex

FEATURES="serde"

# Pin dependencies as required if we are using MSRV toolchain.
if cargo --version | grep "1\.56"; then
    cargo update -p tempfile --precise 3.6.0
    cargo update -p once_cell --precise 1.13.1
    cargo update -p which --precise 4.4.0
    cargo update -p byteorder --precise 1.4.3
fi

if [ "$DO_FEATURE_MATRIX" = true ]
then
    # Test without any features first
    cargo test --verbose --no-default-features
    # Then test with the default features
    cargo test --verbose
    # Then test with the default features
    cargo test --all-features --verbose

    # Also build and run each example to catch regressions
    cargo build --examples
    # run all examples
    run-parts ./target/debug/examples

    # Test each feature
    for feature in ${FEATURES}
    do
        cargo test --verbose --features="$feature"
    done
fi

if [ "$DO_LINT" = true ]
then
    cargo clippy --all-features --all-targets -- -D warnings
fi

# Build the docs if told to (this only works with the nightly toolchain)
if [ "$DO_DOCSRS" = true ]; then
    RUSTDOCFLAGS="--cfg docsrs -D warnings -D rustdoc::broken-intra-doc-links" cargo +nightly doc --all-features
fi

# Build the docs with a stable toolchain, in unison with the DO_DOCSRS command
# above this checks that we feature guarded docs imports correctly.
if [ "$DO_DOCS" = true ]; then
    RUSTDOCFLAGS="-D warnings" cargo +stable doc --all-features
fi


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
