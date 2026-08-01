#!/bin/bash
set -e

NFTABLES_VERSION="v0.3.0"
NFTABLES_DIR="nftables"
PATCH_FILE="patches/nftables.patch"

rm -rf "$NFTABLES_DIR"

# Download and extract
TMPDIR=$(mktemp -d)
trap "rm -rf $TMPDIR" EXIT
curl -sL "https://github.com/google/nftables/archive/refs/tags/${NFTABLES_VERSION}.tar.gz" | tar xz -C "$TMPDIR"

# Move to target
mv "$TMPDIR/nftables-${NFTABLES_VERSION#v}" "$NFTABLES_DIR"
chmod -R u+w "$NFTABLES_DIR"

# Remove test files (they pull in unnecessary dependencies)
find "$NFTABLES_DIR" -name '*_test.go' -delete
rm -rf "$NFTABLES_DIR"/.github "$NFTABLES_DIR"/integration

# Remove unused dependencies from go.mod
sed -i.bak '/vishvananda/d' "$NFTABLES_DIR/go.mod" && rm -f "$NFTABLES_DIR/go.mod.bak"

# Apply patch
(cd "$NFTABLES_DIR" && patch -p1 < "../$PATCH_FILE")

go mod tidy
echo "Done. nftables@${NFTABLES_VERSION} patched."
