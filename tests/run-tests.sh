#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
FAILED=0

echo "== public funnel launch contracts =="
if python3 "$ROOT/tests/test-public-funnel.py" "$@"; then
  echo "public funnel launch contracts OK"
else
  echo "FAIL: public funnel launch contracts"
  FAILED=1
fi

echo "== outbound review-pack redaction profile =="
if python3 "$ROOT/tests/test-review-pack.py" "$@"; then
  echo "outbound review-pack redaction profile OK"
else
  echo "FAIL: outbound review-pack redaction profile"
  FAILED=1
fi

exit "$FAILED"
