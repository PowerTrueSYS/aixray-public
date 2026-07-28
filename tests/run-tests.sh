#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
FAILED=0

python3 "$ROOT/tests/test-public-funnel.py" "$@" || FAILED=1
python3 "$ROOT/tests/test-review-pack.py" "$@" || FAILED=1
python3 "$ROOT/tests/test-release-integrity.py" "$@" || FAILED=1

exit "$FAILED"
