set -eu
package_dir=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
fixture_dir=${RATHOLE_FIXTURE_DIR:-"$package_dir/target/upstream-rathole"}
release=v0.5.0
if [ ! -d "$fixture_dir" ]; then
    mkdir -p "$(dirname -- "$fixture_dir")"
    git clone --quiet --depth 1 --branch "$release" https://github.com/rathole-org/rathole.git "$fixture_dir"
fi
test "$(git -C "$fixture_dir" describe --tags --exact-match)" = "$release"
cargo update --manifest-path "$fixture_dir/Cargo.toml" -p time --precise 0.3.44 >&2
CARGO_TARGET_DIR="$fixture_dir/target" cargo build --manifest-path "$fixture_dir/Cargo.toml" \
    --locked --release --no-default-features --features server,noise >&2
printf '%s\n' "$fixture_dir/target/release/rathole"
