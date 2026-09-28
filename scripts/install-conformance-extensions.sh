#!/usr/bin/env bash
# Installs the extension set the conformance suite expects into a directory:
#   install-conformance-extensions.sh <cargo target profile dir> <extension dir>
# (reference-kv, reference-null, and the fixture executable once per conformance-fixture-<mode>).
set -euo pipefail
src=$1 dst=$2
exe=""
case "$(uname -s)" in MINGW*|MSYS*|CYGWIN*) exe=".exe" ;; esac
mkdir -p "$dst"
for name in openaevc-ext-reference-kv openaevc-ext-reference-null; do
  cp "$src/$name$exe" "$dst/$name$exe"
done
for mode in well-behaved undeclared-resource undeclared-process oversized invalid-frame \
            wrong-digest slow incompatible crash probe detached-child no-read wants-unsupported \
            kind-thief upgrade; do
  cp "$src/openaevc-ext-conformance-fixtures$exe" "$dst/conformance-fixture-$mode$exe"
done
