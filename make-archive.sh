#!/bin/bash
#
# Build the release source archive consumed by the RPM spec (Source0) and COPR.
#
# Produces <name>-<version>.tar.gz from a git ref (default HEAD), containing only
# tracked files under a <name>-<version>/ prefix so it matches the spec's
# %autosetup expectation. Name and version are read from the spec so this stays
# in sync with packaging.
#
# Usage: ./make-archive.sh [git-ref]
#   OUTDIR=<dir>  write the archive somewhere other than the repo root

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SPEC="$SCRIPT_DIR/got-audit.spec"
REF="${1:-HEAD}"
OUTDIR="${OUTDIR:-$SCRIPT_DIR}"

name="$(awk '/^Name:/    {print $2; exit}' "$SPEC")"
version="$(awk '/^Version:/ {print $2; exit}' "$SPEC")"
[ -n "$name" ] && [ -n "$version" ] || { echo "could not read Name/Version from $SPEC" >&2; exit 1; }

archive="$OUTDIR/${name}-${version}.tar.gz"
git -C "$SCRIPT_DIR" archive --format=tar.gz \
    --prefix="${name}-${version}/" -o "$archive" "$REF"

echo "Wrote $archive"
