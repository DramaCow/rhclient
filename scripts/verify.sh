set -eu
package_dir=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
cd "$package_dir"
RATHOLE_BIN=${RATHOLE_BIN:-$(sh scripts/build-test-server.sh)}
export RATHOLE_BIN
test -f "$RATHOLE_BIN"
test_dir=$(mktemp -d)
trap 'rm -rf "$test_dir"' EXIT HUP INT TERM
python=${PYTHON:-python3}
"$python" -m venv "$test_dir/build"
"$test_dir/build/bin/python" -m pip install 'maturin==1.16.0'
"$test_dir/build/bin/maturin" build --release --locked --strip --out "$test_dir/wheels"
"$python" -m venv "$test_dir/venv"
"$test_dir/venv/bin/python" -m pip install --only-binary :all: \
    "$test_dir/wheels/"*.whl 'pytest==9.2.0' 'pytest-timeout==2.4.0'
cd "$test_dir"
"$test_dir/venv/bin/python" -m pytest "$package_dir/tests" -q
mkdir -p "$package_dir/dist"
cp "$test_dir/wheels/"*.whl "$package_dir/dist/"
