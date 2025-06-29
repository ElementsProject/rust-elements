# No shebang, this file should not be executed.
# shellcheck disable=SC2148
#
# disable verify unused vars, despite the fact that they are used when sourced
# shellcheck disable=SC2034

# Test all these features with "std" enabled.
FEATURES_WITH_STD=""

# Test all these features without "std" enabled.
FEATURES_WITHOUT_STD="json-contract serde base64"

# Run these examples.
EXAMPLES="$(cargo metadata --no-deps --format-version 1 |jq -r '.packages | .[] | .targets | .[] | select(.kind == ["example"]) | .name + ":"')"
