#!/bin/sh
# curate-rules.sh — mechanical filtering of the opengrep-rules corpus, not
# rule selection (engine-spec §4, spec §7.2.1). Scanning the repository as-is
# fails: its own CI config and test fixtures parse as rule definitions and
# abort the run (spike §6).
#
# usage: curate-rules.sh <clone-dir> <dest-dir>
set -e

SRC="$1"
DST="$2"
if [ -z "$SRC" ] || [ -z "$DST" ]; then
    echo "usage: curate-rules.sh <clone-dir> <dest-dir>" >&2
    exit 1
fi

mkdir -p "$DST"
cd "$SRC"

# Keep rule files under language directories (depth >= 2); drop hidden dirs,
# test fixtures, and the non-language top-level dirs.
find . -mindepth 2 -name '*.yaml' \
    -not -path '*/.*' \
    -not -name '*.test.yaml' \
    -not -name '*.fixture.*' \
    -not -path './ai/*' \
    -not -path './problem-based-packs/*' \
    -not -path './scripts/*' \
    -not -path './stats/*' \
    -not -path './trusted_python/*' \
    -not -path '*/tests/*' \
    -not -path '*/test/*' \
    | while IFS= read -r f; do
        d="$DST/$(dirname "$f")"
        mkdir -p "$d"
        cp "$f" "$d/"
    done

# Count assertion: catches structural breakage, not ordinary upstream churn
# (engine-spec §4.4). Measured 1818 at spike time against this filter family.
COUNT=$(find "$DST" -name '*.yaml' | wc -l)
echo "curated rule files: $COUNT"
if [ "$COUNT" -lt 1700 ] || [ "$COUNT" -gt 2100 ]; then
    echo "rule count $COUNT outside [1700,2100] — upstream restructure?" >&2
    exit 1
fi
