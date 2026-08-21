#!/bin/ksh
# PTxray outbound pseudonymized review-copy helper.
# Reads one local PTxray HTML report and performs no network action.
set -u

# Must equal VERSION in src/ptxray-aix.sh.in and AIXRAY_STANDALONE_VERSION in
# src/standalone-prelude.ksh. render-public-release.py validates every shipped
# artifact's version against the release tag; a review pack without this line
# was silently skipped by that check and v1.0.0 nearly shipped unversioned,
# a regression from v0.1.0 which carried it.
AIXRAY_REVIEW_PACK_VERSION="1.3.0"

PATH=/usr/bin:/etc:/usr/sbin:/usr/ucb:/usr/bin/X11:/sbin:${PATH:-}
export PATH
LC_ALL=C
export LC_ALL

PROGRAM=${0##*/}
SCRATCH=
SCRATCH_MADE=
FAILURE_OUT=
PUBLISHED_MAP=
PUBLISHED_MANIFEST=
PUBLISHED_HTML=
PUBLISHED_FAILURE=

function inode_of {
  LC_ALL=C ls -ldi "$1" 2>/dev/null \
    | awk 'NR == 1 { print $1; exit }'
}

function same_inode {
  SAME_LEFT=$(inode_of "$1")
  SAME_RIGHT=$(inode_of "$2")
  [ -n "$SAME_LEFT" ] && [ "$SAME_LEFT" = "$SAME_RIGHT" ]
}

function remove_if_ours {
  REMOVE_FINAL=$1
  REMOVE_SCRATCH=$2
  if [ -n "$REMOVE_FINAL" ] && [ -n "$REMOVE_SCRATCH" ] \
      && [ -f "$REMOVE_FINAL" ] && [ ! -L "$REMOVE_FINAL" ] \
      && same_inode "$REMOVE_FINAL" "$REMOVE_SCRATCH"; then
    rm -f "$REMOVE_FINAL" 2>/dev/null
  fi
}

function owner_only_regular {
  PRIVATE_FILE=$1
  PRIVATE_SOURCE=$2
  [ -f "$PRIVATE_FILE" ] && [ ! -L "$PRIVATE_FILE" ] \
    && [ -f "$PRIVATE_SOURCE" ] && [ ! -L "$PRIVATE_SOURCE" ] \
    || return 1
  PRIVATE_INODE_BEFORE=$(inode_of "$PRIVATE_FILE")
  [ -n "$PRIVATE_INODE_BEFORE" ] || return 1
  PRIVATE_METADATA=$(LC_ALL=C ls -ln "$PRIVATE_FILE" 2>/dev/null) \
    || return 1
  set -- $PRIVATE_METADATA
  [ "$#" -ge 3 ] || return 1
  [ "$1" = "-rw-------" ] && [ "$3" = "$CURRENT_UID" ] \
    || return 1
  same_inode "$PRIVATE_FILE" "$PRIVATE_SOURCE" || return 1
  PRIVATE_INODE_AFTER=$(inode_of "$PRIVATE_FILE")
  [ "$PRIVATE_INODE_BEFORE" = "$PRIVATE_INODE_AFTER" ]
}

function cleanup {
  if [ -n "$PUBLISHED_HTML" ]; then
    remove_if_ours "$PUBLISHED_HTML" "$HTML_TMP"
  fi
  if [ -n "$PUBLISHED_MANIFEST" ]; then
    remove_if_ours "$PUBLISHED_MANIFEST" "$MANIFEST_TMP"
  fi
  if [ -n "$PUBLISHED_MAP" ]; then
    remove_if_ours "$PUBLISHED_MAP" "$MAP_TMP"
  fi
  if [ -n "$PUBLISHED_FAILURE" ]; then
    remove_if_ours "$PUBLISHED_FAILURE" "$FAILURE_TMP"
  fi
  if [ -n "$SCRATCH_MADE" ] && [ -n "$SCRATCH" ]; then
    rm -f "$SCRATCH/review.awk" "$SCRATCH/review.html" \
      "$SCRATCH/review.map" "$SCRATCH/stats" "$SCRATCH/date" \
      "$SCRATCH/error" "$SCRATCH/tokens" "$SCRATCH/validation" \
      "$SCRATCH/violations" "$SCRATCH/failure" "$SCRATCH/ledger" \
      "$SCRATCH/manifest" "$SCRATCH/reconcile" 2>/dev/null
    rmdir "$SCRATCH" 2>/dev/null
  fi
}

function fail {
  echo "$PROGRAM: $1" >&2
  exit 1
}

TEST_FAIL_STAGE=${AIXRAY_TEST_FAIL_STAGE:-}
TEST_PAUSE_STAGE=${AIXRAY_TEST_PAUSE_STAGE:-}
TEST_OUTPUT_TOKEN=${AIXRAY_TEST_OUTPUT_TOKEN:-}

function test_pause {
  PAUSE_STAGE=$1
  [ "$TEST_PAUSE_STAGE" = "$PAUSE_STAGE" ] || return 0
  # macOS ksh, used by the acceptance harness, does not dispatch a trap
  # inherited from top level while it is executing a shell function.
  trap 'cleanup; trap - 0 1 2 3 15; exit 1' 1 2 3 15
  if [ -n "${AIXRAY_TEST_PAUSE_MARKER:-}" ]; then
    printf '%s\n' "$PAUSE_STAGE" > "$AIXRAY_TEST_PAUSE_MARKER" \
      || fail "could not write test-only pause marker"
  fi
  if [ -z "${AIXRAY_TEST_PAUSE_RELEASE:-}" ]; then
    while :; do
      :
    done
  fi
  while :; do
    if [ -f "$AIXRAY_TEST_PAUSE_RELEASE" ]; then
      return 0
    fi
    sleep 1
  done
}

function inject_refusal {
  INJECT_STAGE=$1
  if [ "$TEST_FAIL_STAGE" = "$INJECT_STAGE" ]; then
    printf 'injected-%s\ttest-only fail-closed fault\n' "$INJECT_STAGE" \
      > "$VIOLATIONS_TMP"
    publish_refusal "test-only injected $INJECT_STAGE failure"
  fi
}

function inject_hard_failure {
  INJECT_STAGE=$1
  if [ "$TEST_FAIL_STAGE" = "$INJECT_STAGE" ]; then
    fail "test-only injected $INJECT_STAGE failure"
  fi
}

function usage {
  echo "usage: ./$PROGRAM --pseudonymize aixray-<host>-<date>.html" >&2
  echo "       ./$PROGRAM aixray-<host>-<date>.html  # compatibility alias" >&2
  exit 2
}

function help {
  cat <<EOF
usage: ./$PROGRAM --pseudonymize aixray-<host>-<date>.html
       ./$PROGRAM aixray-<host>-<date>.html

Create a separate pseudonymized review candidate from a current PTxray native
or compliance HTML report carrying privacy schema 1. The raw report is never
changed. Automated gates may publish a candidate only with status REVIEW REQUIRED;
the result is NOT ANONYMIZED and must be inspected before sharing.

Local-only artifacts:
  aixray-local-key-*.map       DO NOT SEND decoding key
  aixray-local-removals-*.txt  DO NOT SEND item-level manifest

Only an inspected aixray-review-*.html candidate is eligible to leave this
machine. PTxray sends nothing and performs no network action.

There is no --scrub alias: "scrubbed" would imply a clean guarantee this
discovery-based workflow cannot honestly make. Use --pseudonymize.
EOF
  exit 0
}

function random_token {
  dd if=/dev/urandom bs=4 count=1 2>/dev/null \
    | od -An -tx1 2>/dev/null \
    | tr -d ' \t\r\n'
}

function output_token {
  if [ -n "$TEST_OUTPUT_TOKEN" ]; then
    printf '%s\n' "$TEST_OUTPUT_TOKEN"
  else
    random_token
  fi
}

function publish_refusal {
  REFUSAL_REASON=$1
  FAILURE_TOKEN=
  FAILURE_ATTEMPT=0
  while [ "$FAILURE_ATTEMPT" -lt 40 ] && [ -z "$FAILURE_TOKEN" ]; do
    FAILURE_CANDIDATE=$(random_token)
    case "$FAILURE_CANDIDATE" in
      ????????) ;;
      *) FAILURE_CANDIDATE=;;
    esac
    case "$FAILURE_CANDIDATE" in
      *[!0-9a-f]*) FAILURE_CANDIDATE=;;
    esac
    if [ -n "$FAILURE_CANDIDATE" ]; then
      FAILURE_PATH=$INPUT_DIR/aixray-local-pseudonymize-failed-$FAILURE_CANDIDATE.txt
      if ! LC_ALL=C ls -ld "$FAILURE_PATH" >/dev/null 2>&1; then
        FAILURE_TOKEN=$FAILURE_CANDIDATE
      fi
    fi
    FAILURE_ATTEMPT=$((FAILURE_ATTEMPT+1))
  done
  if [ -z "$FAILURE_TOKEN" ]; then
    echo "$PROGRAM: NOT READY TO SHARE — independent validation failed and no local failure manifest could be published" >&2
    exit 1
  fi

  {
    printf '%s\n' \
      'NOT READY TO SHARE — independent validation could not prove every' \
      'assessment-derived field was de-identified. No review artifact was published.'
    printf 'Reason: %s\n' "$REFUSAL_REASON"
    if [ -s "$VIOLATIONS_TMP" ]; then
      printf '%s\n' 'Unresolved locations:'
      cat "$VIOLATIONS_TMP"
    fi
  } > "$FAILURE_TMP" \
    || { echo "$PROGRAM: NOT READY TO SHARE — could not write the local failure manifest" >&2; exit 1; }
  chmod 0600 "$FAILURE_TMP" \
    || { echo "$PROGRAM: NOT READY TO SHARE — could not protect the local failure manifest" >&2; exit 1; }
  owner_only_regular "$FAILURE_TMP" "$FAILURE_TMP" \
    || { echo "$PROGRAM: NOT READY TO SHARE — could not verify the protected local failure manifest" >&2; exit 1; }
  PUBLISHED_FAILURE=$FAILURE_PATH
  if ! ln "$FAILURE_TMP" "$FAILURE_PATH" 2>/dev/null; then
    echo "$PROGRAM: NOT READY TO SHARE — could not publish the local failure manifest" >&2
    exit 1
  fi
  if ! owner_only_regular "$FAILURE_PATH" "$FAILURE_TMP"; then
    echo "$PROGRAM: NOT READY TO SHARE — could not verify the local failure manifest" >&2
    exit 1
  fi
  FAILURE_OUT=$FAILURE_PATH
  PUBLISHED_FAILURE=
  printf '%s\n' \
    'NOT READY TO SHARE — independent validation could not prove every' \
    'assessment-derived field was de-identified. No review artifact was published.' >&2
  printf 'Inspect the local failure manifest: %s\n' "$FAILURE_OUT" >&2
  exit 1
}

trap 'cleanup' 0
trap 'cleanup; trap - 0 1 2 3 15; exit 1' 1 2 3 15

if [ "$#" -gt 0 ] && [ "$1" = "--scrub" ]; then
  echo "$PROGRAM: --scrub is not supported; use --pseudonymize because this workflow cannot honestly promise a scrubbed-clean result" >&2
  exit 2
fi

case "$#" in
  1)
    case "$1" in
      --help|-h) help;;
      --*) usage;;
      *) INPUT=$1;;
    esac
    ;;
  2)
    [ "$1" = "--pseudonymize" ] || usage
    INPUT=$2
    ;;
  *) usage;;
esac
[ -n "$INPUT" ] || usage

case "$0" in
  */*) PROGRAM_DIR_RAW=${0%/*};;
  *) PROGRAM_DIR_RAW=.;;
esac
PROGRAM_DIR=$(CDPATH= cd -- "$PROGRAM_DIR_RAW" 2>/dev/null \
  && (pwd -P 2>/dev/null || pwd)) \
  || fail "cannot resolve the helper directory"
VALIDATOR_PROGRAM=$PROGRAM_DIR/ptxray-review-validate.awk
if [ ! -f "$VALIDATOR_PROGRAM" ] \
    && [ -f "$PROGRAM_DIR/validate.awk" ]; then
  VALIDATOR_PROGRAM=$PROGRAM_DIR/validate.awk
fi
[ -f "$VALIDATOR_PROGRAM" ] && [ -r "$VALIDATOR_PROGRAM" ] \
  || fail "independent validator is missing or unreadable beside the helper"
[ ! -L "$VALIDATOR_PROGRAM" ] \
  || fail "refusing symlinked independent validator"
VALIDATOR_CONTRACT='# validator-contract: pseudonymize-1'
if ! LC_ALL=C awk -v expected="$VALIDATOR_CONTRACT" '
  /^# validator-contract:/ {
    marker_count++
    if ($0 == expected) match_count++
  }
  END { exit !(marker_count == 1 && match_count == 1) }
' "$VALIDATOR_PROGRAM"; then
  fail "independent validator contract mismatch; copy the helper and validator from the same release"
fi

case "$INPUT" in
  */*)
    INPUT_DIR_RAW=${INPUT%/*}
    INPUT_NAME=${INPUT##*/}
    [ -n "$INPUT_DIR_RAW" ] || INPUT_DIR_RAW=/
    ;;
  *)
    INPUT_DIR_RAW=.
    INPUT_NAME=$INPUT
    ;;
esac

INPUT_DIR=$(CDPATH= cd -- "$INPUT_DIR_RAW" 2>/dev/null \
  && (pwd -P 2>/dev/null || pwd)) \
  || fail "cannot enter input directory '$INPUT_DIR_RAW'"
INPUT_PATH=$INPUT_DIR/$INPUT_NAME

[ -f "$INPUT_PATH" ] && [ -r "$INPUT_PATH" ] \
  || fail "cannot read regular HTML input '$INPUT'"
[ ! -L "$INPUT_PATH" ] \
  || fail "refusing symlinked HTML input '$INPUT'"
CURRENT_UID=$(id -u 2>/dev/null) \
  || fail "cannot determine the current numeric user ID"
case "$CURRENT_UID" in
  ''|*[!0-9]*) fail "current numeric user ID is invalid";;
esac

REPORT_MARKER='<meta name="aixray-report-version" content="1">'
PRIVACY_MARKER='<meta name="aixray-privacy-schema" content="1">'
REPORT_MARKER_COUNT=$(awk -v marker="$REPORT_MARKER" '
  { text = text $0 "\n" }
  END {
    print split(text, marker_parts, marker) - 1
  }
' "$INPUT_PATH") || fail "could not inspect the report marker"
PRIVACY_MARKER_COUNT=$(awk -v marker="$PRIVACY_MARKER" '
  { text = text $0 "\n" }
  END {
    print split(text, marker_parts, marker) - 1
  }
' "$INPUT_PATH") || fail "could not inspect the privacy marker"
if [ "$REPORT_MARKER_COUNT" != "1" ]; then
  echo "$PROGRAM: unsupported input: expected PTxray report version 1 exactly once" >&2
  exit 2
fi
if [ "$PRIVACY_MARKER_COUNT" != "1" ]; then
  echo "$PROGRAM: unsupported input: privacy schema 1 is required; regenerate the report with a current scanner" >&2
  exit 2
fi

for REQUIRED_COMMAND in awk cat chmod cksum dd id ln ls mkdir od rm rmdir sed sleep tr; do
  command -v "$REQUIRED_COMMAND" >/dev/null 2>&1 \
    || fail "required local command is unavailable: $REQUIRED_COMMAND"
done
[ -d "$INPUT_DIR" ] && [ -w "$INPUT_DIR" ] \
  || fail "the report directory is not writable for local review artifacts"

PREFLIGHT_REASON=$(awk '
function count_literal(text, needle,    count, remainder, position) {
  count = 0
  remainder = text
  while ((position = index(remainder, needle)) > 0) {
    count++
    remainder = substr(remainder, position + length("" needle))
  }
  return count
}
function field_value(tag, name,    lower, marker, position, remainder, ending) {
  lower = tolower(tag)
  marker = tolower(name) "=\""
  position = index(lower, marker)
  if (position > 0) {
    remainder = substr(tag, position + length("" marker))
    ending = index(remainder, "\"")
    if (ending > 0) return substr(remainder, 1, ending - 1)
  }
  return ""
}
function field_count(tag, name) {
  return count_literal(tolower(tag), tolower(name) "=")
}
function tag_name(tag,    name) {
  name = tag
  sub(/^<[ \t\r\n]*/, "", name)
  sub(/^[\/!?][ \t\r\n]*/, "", name)
  sub(/[ \t\r\n>\/].*$/, "", name)
  return tolower(name)
}
function supported_family(value) {
  return value == "identity" || value == "observed" \
    || value == "evidence" || value == "technical" \
    || value == "authored"
}
function reject(reason) {
  print reason
  exit 1
}
function inspect_tag(tag,    lower, name, field, location, copy_id, container) {
  lower = tolower(tag)
  name = tag_name(tag)
  if (substr(lower, 1, 2) == "</" \
      || substr(lower, 1, 2) == "<!" \
      || substr(lower, 1, 2) == "<?") return
  if (name == "html") HTML_OPEN++
  else if (name == "head") HEAD_OPEN++
  else if (name == "body") BODY_OPEN++
  if (name == "meta") {
    if (field_value(tag, "name") == "aixray-report-date") {
      DATE_COUNT++
      REPORT_DATE = field_value(tag, "content")
    } else if (field_value(tag, "name") == "aixray-report-host") {
      HOST_COUNT++
      REPORT_HOST = field_value(tag, "content")
    }
  }
  if (field_count(tag, "data-aixray-field") > 1 \
      || field_count(tag, "data-aixray-location") > 1 \
      || field_count(tag, "data-aixray-copy-id") > 1 \
      || field_count(tag, "data-aixray-container") > 1) \
    reject("duplicate privacy annotation")
  field = field_value(tag, "data-aixray-field")
  location = field_value(tag, "data-aixray-location")
  copy_id = field_value(tag, "data-aixray-copy-id")
  container = field_value(tag, "data-aixray-container")
  if ((field_count(tag, "data-aixray-location") > 0 \
      || field_count(tag, "data-aixray-copy-id") > 0) && field == "") \
    reject("privacy annotation lacks a supported field family")
  if (field != "" && !supported_family(field)) \
    reject("unknown privacy field family")
  if (field == "authored") {
    if (copy_id == "" || location != "") \
      reject("authored privacy annotation is incomplete or contradictory")
  } else if (field != "") {
    if (location == "" || copy_id != "") \
      reject("dynamic privacy annotation is incomplete or contradictory")
  }
  if (container != "" \
      && (container != "fields" || field != "" \
        || location != "" || copy_id != "")) \
    reject("privacy field container is unknown or contradictory")
  if (name == "td" && field == "" && container != "fields") \
    reject("assessment cell lacks a privacy annotation")
}
{
  DOCUMENT = DOCUMENT $0 "\n"
}
END {
  LOWER_DOCUMENT = tolower(DOCUMENT)
  if (count_literal(LOWER_DOCUMENT, "<!doctype html>") != 1) \
    reject("expected one HTML doctype")
  if (count_literal(LOWER_DOCUMENT, "</html>") != 1 \
      || count_literal(LOWER_DOCUMENT, "</head>") != 1 \
      || count_literal(LOWER_DOCUMENT, "</body>") != 1) \
    reject("expected one complete HTML envelope")

  remainder = DOCUMENT
  while (remainder != "") {
    opening = index(remainder, "<")
    if (opening == 0) break
    remainder = substr(remainder, opening)
    closing = index(remainder, ">")
    if (closing == 0) reject("unterminated markup")
    inspect_tag(substr(remainder, 1, closing))
    remainder = substr(remainder, closing + 1)
  }
  if (HTML_OPEN != 1 || HEAD_OPEN != 1 || BODY_OPEN != 1) \
    reject("expected one complete HTML envelope")
  if (DATE_COUNT != 1 \
      || REPORT_DATE !~ /^[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]$/) \
    reject("expected one valid PTxray report date marker")
  month = substr(REPORT_DATE, 6, 2) + 0
  day = substr(REPORT_DATE, 9, 2) + 0
  if (month < 1 || month > 12 || day < 1 || day > 31) \
    reject("PTxray report date marker is outside the calendar range")
  if (HOST_COUNT != 1 || REPORT_HOST !~ /^[A-Za-z0-9][A-Za-z0-9_.-]*$/) \
    reject("expected one valid PTxray report host marker")
}
' "$INPUT_PATH")
PREFLIGHT_STATUS=$?
if [ "$PREFLIGHT_STATUS" -ne 0 ] || [ -n "$PREFLIGHT_REASON" ]; then
  [ -n "$PREFLIGHT_REASON" ] || PREFLIGHT_REASON="privacy contract could not be parsed"
  echo "$PROGRAM: unsupported input: $PREFLIGHT_REASON; regenerate the report with a current scanner" >&2
  exit 2
fi

SOURCE_CKSUM_BEFORE=$(cksum < "$INPUT_PATH") \
  || fail "could not snapshot the source report checksum"
SOURCE_MODE_BEFORE=$(LC_ALL=C ls -ld "$INPUT_PATH") \
  || fail "could not snapshot the source report metadata"

umask 077
SCRATCH_SEED=$(random_token)
case "$SCRATCH_SEED" in
  ????????) ;;
  *) fail "could not obtain eight random hexadecimal characters from /dev/urandom";;
esac
case "$SCRATCH_SEED" in
  *[!0-9a-f]*) fail "random token source returned non-hexadecimal data";;
esac

TRY=0
while [ "$TRY" -lt 20 ] && [ -z "$SCRATCH_MADE" ]; do
  CANDIDATE=$INPUT_DIR/.aixray-review.$$.$SCRATCH_SEED.$TRY
  if mkdir -m 700 "$CANDIDATE" 2>/dev/null; then
    SCRATCH=$CANDIDATE
    SCRATCH_MADE=1
  fi
  TRY=$((TRY+1))
done
[ -n "$SCRATCH_MADE" ] \
  || fail "could not create an owner-only scratch directory beside the report"

AWK_PROGRAM=$SCRATCH/review.awk
HTML_TMP=$SCRATCH/review.html
MAP_TMP=$SCRATCH/review.map
STATS_TMP=$SCRATCH/stats
DATE_TMP=$SCRATCH/date
ERROR_TMP=$SCRATCH/error
TOKEN_TMP=$SCRATCH/tokens
VALIDATION_TMP=$SCRATCH/validation
VIOLATIONS_TMP=$SCRATCH/violations
FAILURE_TMP=$SCRATCH/failure
LEDGER_TMP=$SCRATCH/ledger
MANIFEST_TMP=$SCRATCH/manifest
RECONCILE_TMP=$SCRATCH/reconcile

if ! cat > "$AWK_PROGRAM" <<'AWK'
function die(message) {
  print message > error_out
  close(error_out)
  exit 1
}

function count_literal(text, needle,    count, position, rest) {
  if (needle == "") return 0
  count = 0
  rest = text
  while ((position = index(rest, needle)) > 0) {
    count++
    rest = substr(rest, position + length("" needle))
  }
  return count
}

function replace_literal(text, old, replacement,    out, position) {
  if (old == "") return text
  out = ""
  while ((position = index(text, old)) > 0) {
    out = out substr(text, 1, position - 1) replacement
    text = substr(text, position + length("" old))
  }
  return out text
}

function decode_html_entity(entity,    lower, original, base, digits, code, \
    position, character, digit) {
  original = "&" entity ";"
  lower = tolower(entity)
  if (lower == "quot") return "\""
  if (lower == "apos") return "'"
  if (lower == "lt") return "<"
  if (lower == "gt") return ">"
  if (lower == "amp") return "&"
  if (lower == "colon") return ":"
  if (lower == "sol") return "/"
  if (substr(lower, 1, 2) == "#x") {
    base = 16
    digits = substr(lower, 3)
  } else if (substr(lower, 1, 1) == "#") {
    base = 10
    digits = substr(lower, 2)
  } else {
    return original
  }
  if (digits == "") return original
  code = 0
  for (position = 1; position <= length("" digits); position++) {
    character = substr(digits, position, 1)
    digit = index("0123456789", character) - 1
    if (digit < 0 && base == 16) {
      digit = index("abcdef", character)
      if (digit > 0) digit += 9
      else digit = -1
    }
    if (digit < 0 || digit >= base) return original
    code = code * base + digit
    if (code > 127) return original
  }
  if (code < 1) return original
  return sprintf("%c", code)
}

function html_unescape(text,    out, amp, rest, semicolon, entity) {
  out = ""
  while ((amp = index(text, "&")) > 0) {
    out = out substr(text, 1, amp - 1)
    rest = substr(text, amp + 1)
    semicolon = index(rest, ";")
    if (semicolon == 0 || semicolon > 16) {
      out = out "&"
      text = rest
      continue
    }
    entity = substr(rest, 1, semicolon - 1)
    out = out decode_html_entity(entity)
    text = substr(rest, semicolon + 1)
  }
  return out text
}

function html_escape(text) {
  text = replace_literal(text, "&", "&amp;")
  text = replace_literal(text, "\"", "&quot;")
  text = replace_literal(text, "'", "&#39;")
  text = replace_literal(text, "<", "&lt;")
  text = replace_literal(text, ">", "&gt;")
  return text
}

function trim(text) {
  sub(/^[ \t\r\n]+/, "", text)
  sub(/[ \t\r\n]+$/, "", text)
  return text
}

function clean_candidate(value,    character) {
  while (length("" value) > 0) {
    character = substr(value, 1, 1)
    if (character !~ /[\[({"']/) break
    value = substr(value, 2)
  }
  while (length("" value) > 0) {
    character = substr(value, length("" value), 1)
    if (character !~ /[\].,;!?)}"']/) break
    value = substr(value, 1, length("" value) - 1)
  }
  return value
}

function is_identifier_character(character) {
  return character ~ /[A-Za-z0-9_.:@-]/
}

function replace_bounded(text, old, replacement,    out, cursor, relative, position, before, after) {
  LAST_REPLACEMENTS = 0
  if (old == "") return text
  out = ""
  cursor = 1
  while ((relative = index(substr(text, cursor), old)) > 0) {
    position = cursor + relative - 1
    before = position > 1 ? substr(text, position - 1, 1) : ""
    after = position + length("" old) <= length("" text) \
      ? substr(text, position + length("" old), 1) : ""
    if ((before == "" || !is_identifier_character(before)) \
        && (after == "" || !is_identifier_character(after))) {
      out = out substr(text, cursor, position - cursor) replacement
      cursor = position + length("" old)
      LAST_REPLACEMENTS++
    } else {
      out = out substr(text, cursor, position - cursor + 1)
      cursor = position + 1
    }
  }
  return out substr(text, cursor)
}

function contains_bounded(text, value,    cursor, relative, position, before, after) {
  if (value == "") return 0
  cursor = 1
  while ((relative = index(substr(text, cursor), value)) > 0) {
    position = cursor + relative - 1
    before = position > 1 ? substr(text, position - 1, 1) : ""
    after = position + length("" value) <= length("" text) \
      ? substr(text, position + length("" value), 1) : ""
    if ((before == "" || !is_identifier_character(before)) \
        && (after == "" || !is_identifier_character(after))) return 1
    cursor = position + 1
  }
  return 0
}

function valid_name(value) {
  return value ~ /^[A-Za-z0-9_][A-Za-z0-9_.-]*$/ && value ~ /[A-Za-z]/
}

function valid_user(value) {
  return value ~ /^[A-Za-z_][A-Za-z0-9_.-]*$/
}

function all_hex(value) {
  return value != "" && value !~ /[^0-9A-Fa-f]/
}

function is_ipv4(value,    fields, part, count) {
  count = split(value, fields, ".")
  if (count != 4) return 0
  for (part = 1; part <= 4; part++) {
    if (fields[part] == "" || fields[part] !~ /^[0-9]+$/) return 0
    if (fields[part] + 0 < 0 || fields[part] + 0 > 255) return 0
  }
  return 1
}

function is_delimited_hex(value, separator, wanted_count, wanted_width,    fields, part, count) {
  count = split(value, fields, separator)
  if (count != wanted_count) return 0
  for (part = 1; part <= count; part++) {
    if (length("" fields[part]) != wanted_width || !all_hex(fields[part])) return 0
  }
  return 1
}

function is_mac(value) {
  return is_delimited_hex(value, ":", 6, 2) \
    || is_delimited_hex(value, "-", 6, 2) \
    || is_delimited_hex(value, "[.]", 3, 4)
}

function is_wwpn(value,    plain) {
  plain = value
  if (tolower(substr(plain, 1, 2)) == "0x") plain = substr(plain, 3)
  if (length("" plain) == 16 && all_hex(plain)) return 1
  return is_delimited_hex(value, ":", 8, 2) \
    || is_delimited_hex(value, "-", 8, 2) \
    || is_delimited_hex(value, "[.]", 4, 4)
}

function is_ipv6(value,    fields, part, count, colons, compressed, copy) {
  if (value !~ /^[0-9A-Fa-f:.]+$/ || index(value, ":") == 0) return 0
  if (is_mac(value)) return 0
  copy = value
  colons = gsub(/:/, ":", copy)
  compressed = index(value, "::") > 0
  if (compressed && count_literal(value, "::") != 1) return 0
  count = split(value, fields, ":")
  if (!compressed && count != 8) return 0
  if (compressed && colons > 8) return 0
  for (part = 1; part <= count; part++) {
    if (fields[part] == "") continue
    if (length("" fields[part]) > 4 || !all_hex(fields[part])) return 0
  }
  return 1
}

function is_uuid(value,    fields, count) {
  count = split(value, fields, "-")
  if (count != 5) return 0
  return length("" fields[1]) == 8 && all_hex(fields[1]) \
    && length("" fields[2]) == 4 && all_hex(fields[2]) \
    && length("" fields[3]) == 4 && all_hex(fields[3]) \
    && length("" fields[4]) == 4 && all_hex(fields[4]) \
    && length("" fields[5]) == 12 && all_hex(fields[5])
}

function is_aix_location(value,    fields, count, part) {
  if (value !~ /^U[A-Za-z0-9-]+[.][A-Za-z0-9-]+[.][A-Za-z0-9.-]+$/) return 0
  if (value !~ /[0-9]/) return 0
  count = split(value, fields, ".")
  if (count < 3) return 0
  for (part = 1; part <= count; part++) {
    if (fields[part] == "" || fields[part] !~ /^[A-Za-z0-9-]+$/) return 0
  }
  return 1
}

function is_aix_fileset(value,    fields, count, namespace) {
  if (value !~ /^[A-Za-z0-9_+-]+([.][A-Za-z0-9_+-]+)+$/) return 0
  count = split(value, fields, ".")
  if (count < 2) return 0
  namespace = tolower(fields[1])
  if (namespace == "bos" || namespace == "devices" \
      || namespace == "x11" || namespace ~ /^java[0-9_]*$/ \
      || namespace ~ /^openssh/ || namespace == "printers" \
      || namespace == "perl" || namespace == "sysmgt" \
      || namespace == "xlc" || namespace == "xlfrte" \
      || namespace == "rsct" || namespace == "cluster" \
      || namespace == "gpfs" || namespace == "perfagent" \
      || namespace == "vac" || namespace == "ifor_ls" \
      || namespace == "idsldap" || namespace ~ /^gskit/ \
      || namespace == "openssl") return 1
  return 0
}

function is_fqdn(value,    fields, part, count, label, suffix) {
  if (length("" value) > 253 || index(value, ".") == 0) return 0
  count = split(value, fields, ".")
  if (count < 2) return 0
  for (part = 1; part <= count; part++) {
    label = fields[part]
    if (label == "" || length("" label) > 63) return 0
    if (label !~ /^[A-Za-z0-9-]+$/) return 0
    if (substr(label, 1, 1) == "-" \
        || substr(label, length("" label), 1) == "-") return 0
  }
  suffix = tolower(fields[count])
  if (length("" suffix) < 2 || suffix !~ /^[a-z][a-z0-9-]*$/) return 0
  return 1
}

function split_fqdn_candidate(value,    slash, colon, boundary) {
  FQDN_BASE = value
  FQDN_SUFFIX = ""
  slash = index(value, "/")
  colon = index(value, ":")
  boundary = 0
  if (slash > 1) boundary = slash
  if (colon > 1 && (boundary == 0 || colon < boundary)) boundary = colon
  if (boundary > 1) {
    FQDN_BASE = substr(value, 1, boundary - 1)
    FQDN_SUFFIX = substr(value, boundary + 1)
  }
}

function is_email(value,    fields, count, mailbox, domain) {
  count = split(value, fields, "@")
  if (count != 2) return 0
  mailbox = fields[1]
  domain = fields[2]
  if (mailbox == "" || mailbox !~ /^[A-Za-z0-9._%+-]+$/) return 0
  return is_fqdn(domain)
}

function map_index(value,    index_number) {
  for (index_number = 1; index_number <= MAP_COUNT; index_number++) {
    if (MAP_RAW[index_number] == value) return index_number
  }
  return 0
}

function add_map(value, kind,    existing, token, alphabet, group) {
  value = clean_candidate(trim(value))
  if (value == "") return 0
  if (kind == "user" && tolower(value) == "root") return 0
  if (contains_bounded(AUTHORED_ACCUMULATOR, value)) return 0
  existing = map_index(value)
  if (existing) return existing

  if (kind == "host") {
    HOST_TOKEN_COUNT++
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    if (HOST_TOKEN_COUNT <= 26) token = "host-" substr(alphabet, HOST_TOKEN_COUNT, 1)
    else token = "host-" HOST_TOKEN_COUNT
    group = "host"
  } else if (kind == "lpar") {
    LPAR_TOKEN_COUNT++
    token = "lpar-" LPAR_TOKEN_COUNT
    group = "host"
  } else if (kind == "ip") {
    IP_TOKEN_COUNT++
    token = "ip-" IP_TOKEN_COUNT
    group = "network"
  } else if (kind == "mac") {
    MAC_TOKEN_COUNT++
    token = "mac-" MAC_TOKEN_COUNT
    group = "network"
  } else if (kind == "fqdn") {
    FQDN_TOKEN_COUNT++
    token = "fqdn-" FQDN_TOKEN_COUNT
    group = "network"
  } else if (kind == "serial") {
    SERIAL_TOKEN_COUNT++
    token = "serial-" SERIAL_TOKEN_COUNT
    group = "hardware"
  } else if (kind == "wwpn") {
    WWPN_TOKEN_COUNT++
    token = "wwpn-" WWPN_TOKEN_COUNT
    group = "hardware"
  } else if (kind == "user") {
    USER_TOKEN_COUNT++
    token = "user-" USER_TOKEN_COUNT
    group = "people"
  } else if (kind == "path") {
    PATH_TOKEN_COUNT++
    token = "path-" PATH_TOKEN_COUNT
    group = "evidence"
  } else if (kind == "vg") {
    VG_TOKEN_COUNT++
    token = "vg-" VG_TOKEN_COUNT
    group = "evidence"
  } else {
    die("internal error: unknown redaction map class")
  }

  MAP_COUNT++
  MAP_RAW[MAP_COUNT] = value
  MAP_TOKEN[MAP_COUNT] = token
  MAP_GROUP[MAP_COUNT] = group
  MAP_KIND[MAP_COUNT] = kind
  return MAP_COUNT
}

function extract_meta(document, name,    prefix, position, rest, ending) {
  prefix = "<meta name=\"" name "\" content=\""
  if (count_literal(document, prefix) != 1) return ""
  position = index(document, prefix)
  rest = substr(document, position + length("" prefix))
  ending = index(rest, "\">")
  if (ending == 0) return ""
  return substr(rest, 1, ending - 1)
}

function first_value(text,    fields, count) {
  text = trim(text)
  while (substr(text, 1, 1) ~ /[:=]/) text = trim(substr(text, 2))
  count = split(text, fields, /[ \t,;<>]+/)
  if (count < 1) return ""
  return clean_candidate(fields[1])
}

function discover_after(text, label, kind,    lower, offset, relative, position, before, after, rest, value, lower_value) {
  lower = tolower(text)
  offset = 1
  while ((relative = index(substr(lower, offset), label)) > 0) {
    position = offset + relative - 1
    before = position > 1 ? substr(text, position - 1, 1) : ""
    if (before != "" && before ~ /[A-Za-z0-9_]/) {
      offset = position + length("" label)
      continue
    }
    after = position + length("" label) <= length("" text) \
      ? substr(text, position + length("" label), 1) : ""
    if (substr(label, length("" label), 1) ~ /[A-Za-z0-9_]/ \
        && after != "" && after ~ /[A-Za-z0-9_]/) {
      offset = position + length("" label)
      continue
    }
    rest = substr(text, position + length("" label))
    value = first_value(rest)
    lower_value = tolower(value)
    if (kind == "serial" \
        && (lower_value == "number:" || lower_value == "number" \
          || lower_value == "id:" || lower_value == "id")) {
      offset = position + length("" label)
      continue
    }
    if ((kind == "host" || kind == "lpar") && valid_name(value)) add_map(value, kind)
    else if (kind == "user" && valid_user(value)) add_map(value, kind)
    else if (kind == "serial" && value ~ /^[A-Za-z0-9_.:-]+$/) add_map(value, kind)
    else if (kind == "wwpn" && is_wwpn(value)) add_map(value, kind)
    offset = position + length("" label)
  }
}

function discover_quoted_user(text,    lower, marker, position, rest, ending, value) {
  lower = tolower(text)
  marker = "user '"
  position = index(lower, marker)
  while (position > 0) {
    rest = substr(text, position + length("" marker))
    ending = index(rest, "'")
    if (ending > 1) {
      value = substr(rest, 1, ending - 1)
      if (valid_user(value)) add_map(value, "user")
    }
    lower = substr(lower, position + length("" marker))
    text = rest
    position = index(lower, marker)
  }
}

function discover_user_list(text, label,    lower, position, rest, stop, fields, count, part, value) {
  lower = tolower(text)
  position = index(lower, label)
  if (position == 0) return
  rest = substr(text, position + length("" label))
  stop = index(rest, ";")
  if (stop > 0) rest = substr(rest, 1, stop - 1)
  count = split(rest, fields, ",")
  for (part = 1; part <= count; part++) {
    value = first_value(fields[part])
    if (valid_user(value)) add_map(value, "user")
  }
}

function secret_value_end(text, start,    ending, character, entity_rest, semicolon, entity) {
  ending = start
  while (ending <= length("" text)) {
    character = substr(text, ending, 1)
    if (character == "&") {
      entity_rest = substr(text, ending)
      semicolon = index(entity_rest, ";")
      if (semicolon >= 3 && semicolon <= 10) {
        entity = substr(entity_rest, 2, semicolon - 2)
        if (entity ~ /^#[0-9]+$/ || entity ~ /^#[xX][0-9A-Fa-f]+$/ \
            || entity ~ /^[A-Za-z][A-Za-z0-9]+$/) {
          ending += semicolon
          continue
        }
      }
    }
    if (character ~ /[ \t\r\n;,&<>"']/) break
    ending++
  }
  return ending
}

function redact_key(text, key,    lower, offset, relative, position, start, value_start, ending, closing, relative_end) {
  offset = 1
  lower = tolower(text)
  while ((relative = index(substr(lower, offset), key)) > 0) {
    position = offset + relative - 1
    start = position + length("" key)
    while (substr(text, start, 1) ~ /[ \t]/) start++
    value_start = start
    closing = ""
    if (substr(text, start, 1) == "\"" || substr(text, start, 1) == "'") {
      closing = substr(text, start, 1)
      value_start = start + 1
    } else if (substr(text, start, 6) == "&quot;") {
      closing = "&quot;"
      value_start = start + 6
    } else if (substr(text, start, 5) == "&#39;") {
      closing = "&#39;"
      value_start = start + 5
    }
    if (closing != "") {
      relative_end = index(substr(text, value_start), closing)
      ending = relative_end > 0 ? value_start + relative_end - 1 : length("" text) + 1
    } else ending = secret_value_end(text, value_start)
    if (ending == value_start) {
      offset = value_start + length("" closing) + 1
      continue
    }
    if (substr(text, value_start, length("[redacted-secret]")) == "[redacted-secret]") {
      offset = value_start + length("[redacted-secret]")
      continue
    }
    text = substr(text, 1, value_start - 1) "[redacted-secret]" substr(text, ending)
    SECRET_REMOVED++
    if (TRANSFORM_ACTIVE) \
      record_event("remove", "secret", "[redacted-secret]", CURRENT_LOCATION, 1)
    offset = value_start + length("[redacted-secret]")
    lower = tolower(text)
  }
  return text
}

function redact_secrets(text) {
  text = redact_key(text, "bearer ")
  text = redact_key(text, "password=")
  text = redact_key(text, "password:")
  text = redact_key(text, "passwd=")
  text = redact_key(text, "pwd=")
  text = redact_key(text, "api_key=")
  text = redact_key(text, "apikey=")
  text = redact_key(text, "api-key=")
  text = redact_key(text, "credential=")
  text = redact_key(text, "secret=")
  text = redact_key(text, "token=")
  text = redact_key(text, "community=")
  text = redact_key(text, "private_key=")
  text = redact_key(text, "private-key=")
  return text
}

function redact_gecos(text,    lower, offset, relative_equal, relative_colon, relative, position, marker, start, ending, semicolon) {
  lower = tolower(text)
  offset = 1
  while (offset <= length("" text)) {
    relative_equal = index(substr(lower, offset), "gecos=")
    relative_colon = index(substr(lower, offset), "gecos:")
    if (relative_equal == 0) relative = relative_colon
    else if (relative_colon == 0) relative = relative_equal
    else if (relative_equal < relative_colon) relative = relative_equal
    else relative = relative_colon
    if (relative == 0) break
    position = offset + relative - 1
    marker = relative == relative_equal ? "gecos=" : "gecos:"
    start = position + length("" marker)
    while (substr(text, start, 1) ~ /[ \t]/) start++
    semicolon = index(substr(text, start), ";")
    ending = semicolon > 0 ? start + semicolon - 1 : length("" text) + 1
    text = substr(text, 1, start - 1) "[redacted]" substr(text, ending)
    GECOS_REMOVED++
    if (TRANSFORM_ACTIVE) \
      record_event("remove", "GECOS", "[redacted]", CURRENT_LOCATION, 1)
    lower = tolower(text)
    offset = start + length("[redacted]")
  }
  return text
}

function is_cis_control(value, text, td_class,    plain) {
  if (!class_has(td_class, "cis")) return 0
  if (value !~ /^[0-9]+([.][0-9]+)+$/) return 0
  if (is_ipv4(value)) return 0
  plain = trim(html_unescape(text))
  return plain == value " PASS" || plain == value " FAIL"
}

function keep_network_like(value, text, td_class, context,    lower, candidate) {
  lower = tolower(text " " context)
  candidate = tolower(value)
  if (is_cis_control(value, text, td_class)) return 1
  if (index(lower, "vios=" candidate) > 0) return 1
  if (index(lower, "vios " candidate) > 0) return 1
  if (index(lower, "hmc=" candidate) > 0) return 1
  if (index(lower, "version=" candidate) > 0) return 1
  if (index(lower, "version " candidate) > 0) return 1
  if (index(lower, "level=" candidate) > 0) return 1
  if (index(lower, "oslevel=" candidate) > 0) return 1
  if (index(lower, "firmware=" candidate) > 0) return 1
  return 0
}

function host_list_end(text, start,    ending, character) {
  ending = start
  while (ending <= length("" text)) {
    character = substr(text, ending, 1)
    if (character ~ /[ \t\r\n,;<>'"]/) break
    ending++
  }
  return ending
}

function add_host_list_value(value, td_class, context,    fields, count, part, candidate) {
  value = clean_candidate(trim(value))
  if (value == "") return
  if (is_ipv4(value) || is_ipv6(value)) {
    add_map(value, "ip")
    return
  }
  if (is_fqdn(value) && !is_aix_fileset(value)) {
    add_map(value, "fqdn")
    return
  }
  count = split(value, fields, ":")
  for (part = 1; part <= count; part++) {
    candidate = clean_candidate(trim(fields[part]))
    if (candidate == "") continue
    if (is_ipv4(candidate) || is_ipv6(candidate)) add_map(candidate, "ip")
    else if (is_fqdn(candidate) && !is_aix_fileset(candidate)) \
      add_map(candidate, "fqdn")
    else if (valid_name(candidate)) add_map(candidate, "host")
  }
}

function discover_host_list(text, label, td_class, context,    lower, offset, relative, position, before, start, ending, value) {
  lower = tolower(text)
  offset = 1
  while ((relative = index(substr(lower, offset), label)) > 0) {
    position = offset + relative - 1
    before = position > 1 ? substr(text, position - 1, 1) : ""
    if (before != "" && before ~ /[A-Za-z0-9_]/) {
      offset = position + length("" label)
      continue
    }
    start = position + length("" label)
    while (substr(text, start, 1) ~ /[ \t]/) start++
    ending = host_list_end(text, start)
    value = substr(text, start, ending - start)
    add_host_list_value(value, td_class, context)
    offset = ending > start ? ending : start + 1
  }
}

function clean_path_candidate(value,    character) {
  while (length("" value) > 0) {
    character = substr(value, 1, 1)
    if (character !~ /[({"']/) break
    value = substr(value, 2)
  }
  while (length("" value) > 0) {
    character = substr(value, length("" value), 1)
    if (character !~ /[.,;:)}"']/) break
    value = substr(value, 1, length("" value) - 1)
  }
  return value
}

function discover_evidence_paths(text,    fields, count, part, value) {
  count = split(text, fields, /[ \t\r\n]+/)
  for (part = 1; part <= count; part++) {
    value = clean_path_candidate(fields[part])
    if (length("" value) > 1 && substr(value, 1, 1) == "/" \
        && value ~ /^\/[A-Za-z0-9_.+:\/-]+$/) add_map(value, "path")
  }
}

function scan_candidates(text, td_class, context,    fields, count, part, value, lower, slash, base, suffix, domain) {
  count = split(text, fields, /[ \t\r\n,;(){}<>"'=]+/)
  for (part = 1; part <= count; part++) {
    value = clean_candidate(fields[part])
    if (value == "") continue
    lower = tolower(value)

    if (is_email(value)) {
      domain = tolower(substr(value, index(value, "@") + 1))
      if (domain != "powertruesystems.com" && domain != "openssh.com") add_map(value, "user")
      continue
    }
    if (is_aix_location(value)) {
      add_map(value, "serial")
      continue
    }
    if (is_uuid(value)) {
      add_map(value, "serial")
      continue
    }
    if (is_wwpn(value) && index(tolower(context), "wwpn") > 0) {
      add_map(value, "wwpn")
      continue
    }
    if (is_mac(value)) {
      add_map(value, "mac")
      continue
    }

    base = value
    slash = index(base, "/")
    suffix = ""
    if (slash > 1) {
      suffix = substr(base, slash + 1)
      base = substr(base, 1, slash - 1)
    }
    if (is_ipv4(base)) {
      if (!keep_network_like(base, text, td_class, context)) add_map(base, "ip")
      if (is_ipv4(suffix) && !keep_network_like(suffix, text, td_class, context)) \
        add_map(suffix, "ip")
      continue
    }
    if (is_ipv6(base)) {
      if (!keep_network_like(base, text, td_class, context)) add_map(base, "ip")
      continue
    }
    split_fqdn_candidate(value)
    base = FQDN_BASE
    suffix = FQDN_SUFFIX
    lower = tolower(base)
    if (is_aix_fileset(base)) continue
    if (is_fqdn(base)) {
      if (lower == "powertruesystems.com" || lower == "openssh.com") continue
      if (lower == "flrtvc.ksh" || lower == "apar.csv") continue
      if (lower ~ /\.(rte|install|fileset)$/) continue
      if (!keep_network_like(base, text, td_class, context)) add_map(base, "fqdn")
      if (is_fqdn(suffix) \
          && !keep_network_like(suffix, text, td_class, context)) \
        add_map(suffix, "fqdn")
    }
  }
}

function discover_text(text, td_class, context,    safe, lower_context) {
  safe = redact_secrets(html_unescape(text))
  safe = redact_gecos(safe)
  lower_context = tolower(context)

  discover_after(safe, "lpar name", "lpar")
  discover_after(safe, "partition name", "lpar")
  discover_after(safe, "lpar=", "lpar")
  discover_after(safe, "partition=", "lpar")
  discover_after(safe, "hostname=", "host")
  discover_after(safe, "hostname:", "host")
  discover_after(safe, "host:", "host")
  discover_after(safe, "node name", "host")
  discover_after(safe, "node=", "host")
  discover_after(safe, "nodename", "host")

  discover_after(safe, "machine serial", "serial")
  discover_after(safe, "serial number", "serial")
  discover_after(safe, "system serial", "serial")
  discover_after(safe, "serial=", "serial")
  discover_after(safe, "frame id", "serial")
  discover_after(safe, "system id", "serial")
  discover_after(safe, "lpar uuid", "serial")
  discover_after(safe, "partition uuid", "serial")
  discover_after(safe, "wwpn", "wwpn")

  discover_after(safe, "username", "user")
  discover_after(safe, "user=", "user")
  discover_after(safe, "account=", "user")
  discover_quoted_user(safe)
  if (index(lower_context, "uid 0 accounts") > 0) discover_user_list(safe, "extra:")
  if (index(lower_context, "account password aging") > 0) discover_user_list(safe, "never-expire:")
  if (index(lower_context, "stale privileged accounts") > 0) {
    discover_user_list(safe, "stale(>90d):")
    discover_user_list(safe, "never-used non-expiring:")
  }

  if (is_evidence_cell(td_class, context)) {
    discover_host_list(safe, "root=", td_class, context)
    discover_host_list(safe, "access=", td_class, context)
    discover_host_list(safe, "rw=", td_class, context)
    discover_host_list(safe, "ro=", td_class, context)
    discover_evidence_paths(safe)
  }

  scan_candidates(safe, td_class, context)
}

function tag_class(tag,    lower, marker, position, rest, ending) {
  lower = tolower(tag)
  marker = "class=\""
  position = index(lower, marker)
  if (position > 0) {
    rest = substr(tag, position + length("" marker))
    ending = index(rest, "\"")
    if (ending > 0) return substr(rest, 1, ending - 1)
  }
  marker = "class='"
  position = index(lower, marker)
  if (position > 0) {
    rest = substr(tag, position + length("" marker))
    ending = index(rest, "'")
    if (ending > 0) return substr(rest, 1, ending - 1)
  }
  return ""
}

function tag_attribute(tag, name,    lower, marker, position, rest, ending) {
  lower = tolower(tag)
  marker = tolower(name) "=\""
  position = index(lower, marker)
  if (position > 0) {
    rest = substr(tag, position + length("" marker))
    ending = index(rest, "\"")
    if (ending > 0) return substr(rest, 1, ending - 1)
  }
  marker = tolower(name) "='"
  position = index(lower, marker)
  if (position > 0) {
    rest = substr(tag, position + length("" marker))
    ending = index(rest, "'")
    if (ending > 0) return substr(rest, 1, ending - 1)
  }
  return ""
}

function stable_location(tag,    location, copy_id, lower, meta_name) {
  location = tag_attribute(tag, "data-aixray-location")
  if (location != "") return location
  copy_id = tag_attribute(tag, "data-aixray-copy-id")
  if (copy_id != "") return copy_id
  lower = tolower(tag)
  if (lower ~ /^<meta([ >])/) {
    meta_name = tag_attribute(tag, "name")
    if (meta_name == "aixray-report-host") return "report:host-meta"
    if (meta_name == "aixray-report-date") return "report:date-meta"
    return "report:metadata"
  }
  if (lower ~ /^<!--/) return "report:html-comment"
  return ""
}

function simple_tag_name(tag,    name) {
  name = tag
  sub(/^<[ \t\r\n]*/, "", name)
  sub(/^[\/!?][ \t\r\n]*/, "", name)
  sub(/[ \t\r\n>\/].*$/, "", name)
  return tolower(name)
}

function transform_void_tag(name) {
  return name == "meta" || name == "link" || name == "img" \
    || name == "br" || name == "hr" || name == "input" \
    || name == "area" || name == "base" || name == "col" \
    || name == "embed" || name == "param" || name == "source" \
    || name == "track" || name == "wbr"
}

function transform_stack_location() {
  if (TRANSFORM_STACK_DEPTH < 1) return ""
  return TRANSFORM_STACK_LOCATION[TRANSFORM_STACK_DEPTH]
}

function transform_stack_family() {
  if (TRANSFORM_STACK_DEPTH < 1) return ""
  return TRANSFORM_STACK_FAMILY[TRANSFORM_STACK_DEPTH]
}

function transform_push_tag(tag, location, family,    lower, name) {
  lower = tolower(tag)
  if (substr(lower, 1, 2) == "</" \
      || substr(lower, 1, 2) == "<!" \
      || substr(lower, 1, 2) == "<?") return
  name = simple_tag_name(tag)
  if (name == "" || transform_void_tag(name) \
      || tag ~ /\/>$/) return
  TRANSFORM_STACK_DEPTH++
  TRANSFORM_STACK_TAG[TRANSFORM_STACK_DEPTH] = name
  TRANSFORM_STACK_LOCATION[TRANSFORM_STACK_DEPTH] = location
  if (family == "" && TRANSFORM_STACK_DEPTH > 1) \
    family = TRANSFORM_STACK_FAMILY[TRANSFORM_STACK_DEPTH - 1]
  TRANSFORM_STACK_FAMILY[TRANSFORM_STACK_DEPTH] = family
}

function transform_pop_tag(tag,    name, depth) {
  name = simple_tag_name(tag)
  if (name == "" || TRANSFORM_STACK_DEPTH < 1) return
  for (depth = TRANSFORM_STACK_DEPTH; depth >= 1; depth--) {
    if (TRANSFORM_STACK_TAG[depth] == name) {
      while (TRANSFORM_STACK_DEPTH >= depth) {
        delete TRANSFORM_STACK_TAG[TRANSFORM_STACK_DEPTH]
        delete TRANSFORM_STACK_LOCATION[TRANSFORM_STACK_DEPTH]
        delete TRANSFORM_STACK_FAMILY[TRANSFORM_STACK_DEPTH]
        TRANSFORM_STACK_DEPTH--
      }
      return
    }
  }
}

function record_committed_event(action, kind, replacement, location, count,    key) {
  if (count <= 0) return
  if (location == "") location = "report:structural"
  key = action SUBSEP kind SUBSEP replacement SUBSEP location
  if (!(key in LEDGER_SEEN)) {
    LEDGER_SEEN[key] = 1
    LEDGER_ORDER[++LEDGER_COUNT] = key
    LEDGER_ACTION[key] = action
    LEDGER_KIND[key] = kind
    LEDGER_REPLACEMENT[key] = replacement
    LEDGER_LOCATION[key] = location
  }
  LEDGER_OCCURRENCES[key] += count
}

function record_event(action, kind, replacement, location, count) {
  if (count <= 0) return
  if (EVENT_CAPTURE) {
    PENDING_ACTION[++PENDING_COUNT] = action
    PENDING_KIND[PENDING_COUNT] = kind
    PENDING_REPLACEMENT[PENDING_COUNT] = replacement
    PENDING_LOCATION[PENDING_COUNT] = location
    PENDING_OCCURRENCES[PENDING_COUNT] = count
    PENDING_MAP_INDEX[PENDING_COUNT] = 0
    return
  }
  record_committed_event(action, kind, replacement, location, count)
}

function record_map_event(index_number, count) {
  if (count <= 0) return
  if (EVENT_CAPTURE) {
    PENDING_ACTION[++PENDING_COUNT] = "replace"
    PENDING_KIND[PENDING_COUNT] = MAP_KIND[index_number]
    PENDING_REPLACEMENT[PENDING_COUNT] = MAP_TOKEN[index_number]
    PENDING_LOCATION[PENDING_COUNT] = CURRENT_LOCATION
    PENDING_OCCURRENCES[PENDING_COUNT] = count
    PENDING_MAP_INDEX[PENDING_COUNT] = index_number
    return
  }
  MAP_OCCURRENCES[index_number] += count
  record_committed_event("replace", MAP_KIND[index_number], \
    MAP_TOKEN[index_number], CURRENT_LOCATION, count)
}

function begin_event_capture() {
  if (EVENT_CAPTURE) die("internal error: nested transformation event capture")
  EVENT_CAPTURE = 1
  PENDING_COUNT = 0
  CAPTURE_SECRET_BEFORE = SECRET_REMOVED
  CAPTURE_GECOS_BEFORE = GECOS_REMOVED
}

function end_event_capture(commit,    pending_number, index_number) {
  if (!EVENT_CAPTURE) die("internal error: transformation event capture missing")
  EVENT_CAPTURE = 0
  if (!commit) {
    SECRET_REMOVED = CAPTURE_SECRET_BEFORE
    GECOS_REMOVED = CAPTURE_GECOS_BEFORE
  }
  if (commit) {
    for (pending_number = 1; pending_number <= PENDING_COUNT; pending_number++) {
      index_number = PENDING_MAP_INDEX[pending_number]
      if (index_number > 0) \
        MAP_OCCURRENCES[index_number] += PENDING_OCCURRENCES[pending_number]
      record_committed_event(PENDING_ACTION[pending_number], \
        PENDING_KIND[pending_number], PENDING_REPLACEMENT[pending_number], \
        PENDING_LOCATION[pending_number], \
        PENDING_OCCURRENCES[pending_number])
    }
  }
  for (pending_number = 1; pending_number <= PENDING_COUNT; pending_number++) {
    delete PENDING_ACTION[pending_number]
    delete PENDING_KIND[pending_number]
    delete PENDING_REPLACEMENT[pending_number]
    delete PENDING_LOCATION[pending_number]
    delete PENDING_OCCURRENCES[pending_number]
    delete PENDING_MAP_INDEX[pending_number]
  }
  PENDING_COUNT = 0
}

function allowed_remote_resource(value,    lower) {
  lower = tolower(value)
  return lower == "https://powertruesystems.com" \
    || lower ~ /^https:\/\/powertruesystems[.]com\/[A-Za-z0-9_.\/-]+$/ \
    || lower == "mailto:review@powertruesystems.com"
}

function char_count(value,    count) {
  count = 0
  while (substr(value, count + 1, 1) != "") count++
  return count
}

function neutralize_remote_resources(tag,    names, name_count, name_number, schemes, scheme_count, scheme_number, marker, lower, search_start, relative, position, value_start, ending, raw) {
  names[1] = "href"
  names[2] = "src"
  names[3] = "action"
  names[4] = "poster"
  names[5] = "srcset"
  names[6] = "formaction"
  names[7] = "background"
  names[8] = "ping" # network-lint: allow -- rejected HTML attribute name, not a command
  names[9] = "cite"
  names[10] = "data"
  names[11] = "xlink:href"
  name_count = 11
  schemes[1] = "http:"
  schemes[2] = "https:"
  schemes[3] = "//"
  schemes[4] = "ftp:" # network-lint: allow -- rejected URI scheme, not a command
  schemes[5] = "mailto:"
  scheme_count = 5

  for (name_number = 1; name_number <= name_count; name_number++) {
    for (scheme_number = 1; scheme_number <= scheme_count; scheme_number++) {
      marker = names[name_number] "=\"" schemes[scheme_number]
      lower = tolower(tag)
      search_start = 1
      while ((relative = index(substr(lower, search_start), marker)) > 0) {
        position = search_start + relative - 1
        value_start = position + char_count(names[name_number]) + 2
        ending = index(substr(tag, value_start), "\"")
        if (ending == 0) die("remote-resource attribute is malformed")
        raw = substr(tag, value_start, ending - 1)
        if (names[name_number] == "href" \
            && raw == canonical_plan_link_url()) {
          search_start = value_start + ending
          continue
        }
        if (!allowed_remote_resource(raw)) \
          die("remote-resource attribute is not canonical product copy")
        tag = substr(tag, 1, value_start - 1) "#" \
          substr(tag, value_start + ending - 1)
        record_event("remove", "remote-resource", "#", CURRENT_LOCATION, 1)
        lower = tolower(tag)
        search_start = 1
      }

      marker = names[name_number] "='" schemes[scheme_number]
      lower = tolower(tag)
      search_start = 1
      while ((relative = index(substr(lower, search_start), marker)) > 0) {
        position = search_start + relative - 1
        value_start = position + char_count(names[name_number]) + 2
        ending = index(substr(tag, value_start), "'")
        if (ending == 0) die("remote-resource attribute is malformed")
        raw = substr(tag, value_start, ending - 1)
        if (names[name_number] == "href" \
            && raw == canonical_plan_link_url()) {
          search_start = value_start + ending
          continue
        }
        if (!allowed_remote_resource(raw)) \
          die("remote-resource attribute is not canonical product copy")
        tag = substr(tag, 1, value_start - 1) "#" \
          substr(tag, value_start + ending - 1)
        record_event("remove", "remote-resource", "#", CURRENT_LOCATION, 1)
        lower = tolower(tag)
        search_start = 1
      }
    }
  }
  return tag
}

function class_has(class_value, wanted,    fields, count, part) {
  count = split(class_value, fields, /[ \t]+/)
  for (part = 1; part <= count; part++) if (fields[part] == wanted) return 1
  return 0
}

function is_evidence_cell(td_class, context,    lower) {
  if (class_has(td_class, "evidence") \
      || class_has(td_class, "top-risk-observed")) return 1
  if (!class_has(td_class, "obs")) return 0
  lower = tolower(context)
  return index(lower, "nfs export") > 0 \
    || index(lower, "error log") > 0 \
    || index(lower, "decoded error") > 0 \
    || index(lower, "errpt") > 0 \
    || index(lower, "log excerpt") > 0 \
    || index(lower, "comments field") > 0
}

function discovery_text(text) {
  if (text == "" || DISCOVERY_STYLE) return
  if (DISCOVERY_STACK_DEPTH > 0 \
      && (DISCOVERY_STACK_FAMILY[DISCOVERY_STACK_DEPTH] == "technical" \
        || DISCOVERY_STACK_FAMILY[DISCOVERY_STACK_DEPTH] == "authored")) return
  if (DISCOVERY_CAPTURE_CONTEXT) \
    DISCOVERY_ROW_CONTEXT = trim(DISCOVERY_ROW_CONTEXT " " html_unescape(text))
  discover_text(text, DISCOVERY_TD_CLASS, DISCOVERY_ROW_CONTEXT)
}

function accumulate_authored(text) {
  if (text == "" || DISCOVERY_STYLE) return
  if (DISCOVERY_STACK_DEPTH > 0 \
      && DISCOVERY_STACK_FAMILY[DISCOVERY_STACK_DEPTH] == "authored")
    AUTHORED_ACCUMULATOR = AUTHORED_ACCUMULATOR "\n" html_unescape(text)
}

function discovery_push_tag(tag, family,    name) {
  name = simple_tag_name(tag)
  if (name == "" || transform_void_tag(name) || tag ~ /\/>$/) return
  DISCOVERY_STACK_DEPTH++
  DISCOVERY_STACK_TAG[DISCOVERY_STACK_DEPTH] = name
  if (family == "" && DISCOVERY_STACK_DEPTH > 1) \
    family = DISCOVERY_STACK_FAMILY[DISCOVERY_STACK_DEPTH - 1]
  DISCOVERY_STACK_FAMILY[DISCOVERY_STACK_DEPTH] = family
}

function discovery_pop_tag(tag,    name, depth) {
  name = simple_tag_name(tag)
  for (depth = DISCOVERY_STACK_DEPTH; depth >= 1; depth--) {
    if (DISCOVERY_STACK_TAG[depth] == name) {
      while (DISCOVERY_STACK_DEPTH >= depth) {
        delete DISCOVERY_STACK_TAG[DISCOVERY_STACK_DEPTH]
        delete DISCOVERY_STACK_FAMILY[DISCOVERY_STACK_DEPTH]
        DISCOVERY_STACK_DEPTH--
      }
      return
    }
  }
}

function discover_schema_finding_id(tag,    finding_id, location, pieces, count, suffix) {
  finding_id = tag_attribute(tag, "data-aixray-finding-id")
  if (finding_id == "") {
    location = tag_attribute(tag, "data-aixray-location")
    count = split(location, pieces, ":")
    if (count == 3 && pieces[1] == "finding") finding_id = pieces[2]
  }
  if (substr(finding_id, 1, 7) != "savevg_") return
  suffix = substr(finding_id, 8)
  if (!valid_name(suffix)) \
    die("redaction validation failed: dynamic savevg finding ID is malformed")
  add_map(suffix, "vg")
}

function discover_line(line,    rest, opening, closing, text, tag, lower, class_value, family, closing_tag) {
  rest = line
  while (rest != "") {
    opening = index(rest, "<")
    if (opening == 0) {
      if (AUTHORED_PASS) accumulate_authored(rest)
      else discovery_text(rest)
      break
    }
    text = substr(rest, 1, opening - 1)
    if (AUTHORED_PASS) accumulate_authored(text)
    else discovery_text(text)
    rest = substr(rest, opening)
    closing = index(rest, ">")
    if (closing == 0) break
    tag = substr(rest, 1, closing)
    lower = tolower(tag)
    family = tag_attribute(tag, "data-aixray-field")
    closing_tag = substr(lower, 1, 2) == "</"
    if (!closing_tag) discover_schema_finding_id(tag)
    if (lower ~ /^<style([ >])/) DISCOVERY_STYLE = 1
    else if (lower ~ /^<\/style/) DISCOVERY_STYLE = 0
    else if (!DISCOVERY_STYLE && lower ~ /^<div([ >])/) {
      DISCOVERY_DIV_DEPTH++
      class_value = tag_class(tag)
      if (DISCOVERY_EVIDENCE_DIV_DEPTH == 0 \
          && is_evidence_cell(class_value, "")) {
        DISCOVERY_EVIDENCE_DIV_DEPTH = DISCOVERY_DIV_DEPTH
        DISCOVERY_TD_CLASS = class_value
        DISCOVERY_CAPTURE_CONTEXT = 0
      }
    }
    else if (!DISCOVERY_STYLE && lower ~ /^<\/div/) {
      if (DISCOVERY_EVIDENCE_DIV_DEPTH == DISCOVERY_DIV_DEPTH) {
        DISCOVERY_EVIDENCE_DIV_DEPTH = 0
        DISCOVERY_TD_CLASS = ""
        DISCOVERY_CAPTURE_CONTEXT = 0
      }
      if (DISCOVERY_DIV_DEPTH > 0) DISCOVERY_DIV_DEPTH--
    }
    else if (!DISCOVERY_STYLE && lower ~ /^<tr([ >])/) {
      DISCOVERY_ROW_CONTEXT = ""
      DISCOVERY_CAPTURE_CONTEXT = 0
    }
    else if (!DISCOVERY_STYLE && lower ~ /^<td([ >])/) {
      class_value = tag_class(tag)
      DISCOVERY_TD_CLASS = class_value
      DISCOVERY_CAPTURE_CONTEXT = class_has(class_value, "ctl")
    } else if (!DISCOVERY_STYLE && lower ~ /^<\/td/) {
      DISCOVERY_TD_CLASS = ""
      DISCOVERY_CAPTURE_CONTEXT = 0
    } else if (!DISCOVERY_STYLE && lower ~ /^<\/tr/) {
      DISCOVERY_ROW_CONTEXT = ""
      DISCOVERY_CAPTURE_CONTEXT = 0
    }
    if (closing_tag) discovery_pop_tag(tag)
    else discovery_push_tag(tag, family)
    rest = substr(rest, closing + 1)
  }
}

function sort_maps(    left, right, temporary) {
  for (left = 1; left <= MAP_COUNT; left++) MAP_ORDER[left] = left
  for (left = 1; left < MAP_COUNT; left++) {
    for (right = left + 1; right <= MAP_COUNT; right++) {
      if (length("" MAP_RAW[MAP_ORDER[right]]) > length("" MAP_RAW[MAP_ORDER[left]])) {
        temporary = MAP_ORDER[left]
        MAP_ORDER[left] = MAP_ORDER[right]
        MAP_ORDER[right] = temporary
      }
    }
  }
}

function apply_maps(text, host_only,    order_number, index_number, encoded) {
  for (order_number = 1; order_number <= MAP_COUNT; order_number++) {
    index_number = MAP_ORDER[order_number]
    if (host_only && MAP_GROUP[index_number] != "host") continue
    text = replace_bounded(text, MAP_RAW[index_number], MAP_TOKEN[index_number])
    record_map_event(index_number, LAST_REPLACEMENTS)
    encoded = html_escape(MAP_RAW[index_number])
    if (encoded != MAP_RAW[index_number]) {
      text = replace_bounded(text, encoded, MAP_TOKEN[index_number])
      record_map_event(index_number, LAST_REPLACEMENTS)
    }
  }
  return text
}

function normalize_schema_finding_ids(tag,    index_number, raw_id, safe_id, replacements) {
  for (index_number = 1; index_number <= MAP_COUNT; index_number++) {
    if (MAP_KIND[index_number] != "vg") continue
    raw_id = "savevg_" MAP_RAW[index_number]
    safe_id = "savevg_[" MAP_TOKEN[index_number] "]"
    replacements = count_literal(tag, raw_id)
    if (replacements < 1) continue
    tag = replace_literal(tag, raw_id, safe_id)
    record_map_event(index_number, replacements)
  }
  return tag
}

function apply_evidence_maps(text,    order_number, index_number, encoded, replacements) {
  for (order_number = 1; order_number <= MAP_COUNT; order_number++) {
    index_number = MAP_ORDER[order_number]
    replacements = count_literal(text, MAP_RAW[index_number])
    if (replacements > 0) {
      text = replace_literal(text, MAP_RAW[index_number], MAP_TOKEN[index_number])
      record_map_event(index_number, replacements)
    }
    encoded = html_escape(MAP_RAW[index_number])
    if (encoded != MAP_RAW[index_number]) {
      replacements = count_literal(text, encoded)
      if (replacements > 0) {
        text = replace_literal(text, encoded, MAP_TOKEN[index_number])
        record_map_event(index_number, replacements)
      }
    }
  }
  return text
}

function high_entropy(text,    fields, count, part, value, has_lower, has_upper, has_digit) {
  text = html_unescape(text)
  count = split(text, fields, /[^A-Za-z0-9_+\/=.-]+/)
  for (part = 1; part <= count; part++) {
    value = fields[part]
    if (length("" value) < 20) continue
    if (value ~ /^CVE-[0-9]+-[0-9]+$/) continue
    has_lower = value ~ /[a-z]/
    has_upper = value ~ /[A-Z]/
    has_digit = value ~ /[0-9]/
    if (has_lower && has_upper && has_digit) return 1
    if (length("" value) >= 24 && all_hex(value)) return 1
    if (length("" value) >= 24 && value !~ /[.\/_-]/ \
        && ((has_lower && has_digit) || (has_upper && has_digit) \
          || (has_lower && has_upper))) return 1
    if (length("" value) >= 32 && value ~ /^[A-Za-z0-9]+$/) return 1
  }
  return 0
}

function has_pseudotoken_shape(value) {
  return value ~ /^host-([A-Z]|[0-9]+)$/ \
    || value ~ /^(lpar|ip|mac|fqdn|serial|wwpn|user|path|vg)-[0-9]+$/
}

function reject_source_pseudotoken_shapes(document,    plain, fields, count, part) {
  plain = html_unescape(document)
  count = split(plain, fields, /[^A-Za-z0-9_-]+/)
  for (part = 1; part <= count; part++) {
    if (has_pseudotoken_shape(fields[part])) \
      die("redaction validation failed: an unissued pseudotoken-shaped identifier exists in the source report")
  }
}

function is_pseudotoken(value,    index_number) {
  if (!has_pseudotoken_shape(value)) return 0
  for (index_number = 1; index_number <= MAP_COUNT; index_number++) {
    if (MAP_TOKEN[index_number] == value) return 1
  }
  return 0
}

function is_evidence_keyword(value,    lower) {
  lower = tolower(value)
  while (substr(lower, 1, 1) == "-") lower = substr(lower, 2)
  return lower == "root" || lower == "access" || lower == "rw" \
    || lower == "ro" || lower == "mac" || lower == "anon" \
    || lower == "sec" || lower == "vers" || lower == "version" \
    || lower == "proto" || lower == "port" || lower == "public" \
    || lower == "exname" || lower == "nosuid" || lower == "nodev" \
    || lower == "noexec" || lower == "secure" || lower == "soft" \
    || lower == "hard" || lower == "intr" || lower == "acdirmin" \
    || lower == "acdirmax" || lower == "acregmin" \
    || lower == "acregmax" || lower == "timeo" \
    || lower == "retrans" || lower == "rsize" || lower == "wsize" \
    || lower == "cio" || lower == "sys" || lower == "krb5" \
    || lower == "krb5i" || lower == "krb5p" || lower == "tcp" \
    || lower == "udp" || lower == "yes" || lower == "no" \
    || lower == "true" || lower == "false" \
    || lower == "observed"
}

function host_list_has_numeric(text, label,    lower, offset, relative, position, before, start, ending, value, fields, count, part, candidate) {
  lower = tolower(text)
  offset = 1
  while ((relative = index(substr(lower, offset), label)) > 0) {
    position = offset + relative - 1
    before = position > 1 ? substr(text, position - 1, 1) : ""
    if (before != "" && before ~ /[A-Za-z0-9_]/) {
      offset = position + length("" label)
      continue
    }
    start = position + length("" label)
    while (substr(text, start, 1) ~ /[ \t]/) start++
    ending = host_list_end(text, start)
    value = substr(text, start, ending - start)
    count = split(value, fields, ":")
    for (part = 1; part <= count; part++) {
      candidate = clean_candidate(trim(fields[part]))
      if (candidate ~ /^[0-9]+$/) return 1
    }
    offset = ending > start ? ending : start + 1
  }
  return 0
}

function evidence_is_safe(text,    plain, fields, count, part, value, has_path) {
  plain = trim(html_unescape(text))
  if (plain == "") return 1
  if (plain == "[redacted-evidence-line]") return 1
  if (host_list_has_numeric(plain, "root=") \
      || host_list_has_numeric(plain, "access=") \
      || host_list_has_numeric(plain, "rw=") \
      || host_list_has_numeric(plain, "ro=")) return 0
  count = split(plain, fields, /[^A-Za-z0-9_.%-]+/)
  has_path = 0
  for (part = 1; part <= count; part++) {
    value = fields[part]
    if (value == "") continue
    if (value ~ /^path-[0-9]+$/) has_path = 1
    if (is_pseudotoken(value) || is_evidence_keyword(value) \
        || value ~ /^[0-9]+$/) continue
    return 0
  }
  return has_path
}

function projected_tokens(text,    fields, field_count, field_number, value, result) {
  field_count = split(text, fields, /[^A-Za-z0-9_-]+/)
  result = "[redacted-evidence-line]"
  for (field_number = 1; field_number <= field_count; field_number++) {
    value = fields[field_number]
    if (is_pseudotoken(value)) result = result " " value
  }
  return result
}

function projected_token_count(text, wanted,    fields, field_count, field_number, count) {
  field_count = split(text, fields, /[^A-Za-z0-9_-]+/)
  count = 0
  for (field_number = 1; field_number <= field_count; field_number++) \
    if (fields[field_number] == wanted) count++
  return count
}

function record_projected_token_events(text,    order_number, index_number, count) {
  for (order_number = 1; order_number <= MAP_COUNT; order_number++) {
    index_number = MAP_ORDER[order_number]
    count = projected_token_count(text, MAP_TOKEN[index_number])
    if (count > 0) record_map_event(index_number, count)
  }
}

function transform_text(text, evidence,    projected, secret_delta, gecos_delta) {
  begin_event_capture()
  if (evidence) text = apply_evidence_maps(text)
  else text = apply_maps(text, 0)
  text = redact_secrets(text)
  text = redact_gecos(text)
  if (evidence) {
    projected = projected_tokens(text)
    secret_delta = SECRET_REMOVED - CAPTURE_SECRET_BEFORE
    gecos_delta = GECOS_REMOVED - CAPTURE_GECOS_BEFORE
    end_event_capture(0)
    EVIDENCE_REMOVED++
    record_projected_token_events(projected)
    if (secret_delta > 0) {
      SECRET_REMOVED += secret_delta
      record_event("remove", "secret-in-removed-field", \
        "[contained-in-redacted-evidence-line]", CURRENT_LOCATION, \
        secret_delta)
    }
    if (gecos_delta > 0) {
      GECOS_REMOVED += gecos_delta
      record_event("remove", "GECOS-in-removed-field", \
        "[contained-in-redacted-evidence-line]", CURRENT_LOCATION, \
        gecos_delta)
    }
    record_event("remove", "whole-evidence-field", \
      "[redacted-evidence-line]", CURRENT_LOCATION, 1)
    return projected
  }
  end_event_capture(1)
  return text
}

function normalize_generated_date(text,    suffix, hour, minute) {
  if (text == report_date) return text
  if (substr(text, 1, 11) != report_date " ") return text
  suffix = substr(text, 12)
  if (suffix !~ /^[0-9][0-9]:[0-9][0-9] [A-Za-z+-][A-Za-z0-9_+:-]*$/) \
    return text
  hour = substr(suffix, 1, 2) + 0
  minute = substr(suffix, 4, 2) + 0
  if (hour > 23 || minute > 59) return text
  record_event("remove", "generated-time-locality", \
    "[removed-time-and-timezone]", CURRENT_LOCATION, 1)
  return report_date
}

function transform_visible_text(text,    transformed, family) {
  if (TRANSFORM_CAPTURE_CONTEXT) \
    TRANSFORM_ROW_CONTEXT = trim(TRANSFORM_ROW_CONTEXT " " html_unescape(text))
  CURRENT_LOCATION = transform_stack_location()
  if (CURRENT_LOCATION == "" && TRANSFORM_LOCATION != "") \
    CURRENT_LOCATION = TRANSFORM_LOCATION
  if (CURRENT_LOCATION == "") CURRENT_LOCATION = "report:structural"
  if (TRANSFORM_STYLE) {
    CURRENT_LOCATION = "report:print-header"
    return apply_maps(text, 1)
  }
  family = transform_stack_family()
  if (family == "authored") return text
  if (CURRENT_LOCATION == "report:generated-date") \
    return normalize_generated_date(text)
  return transform_text(text, family == "observed" \
    || family == "evidence" \
    || (family == "" && TRANSFORM_EVIDENCE))
}

function transform_line(line,    out, rest, opening, closing, text, tag, lower, class_value, evidence, notice, position, tag_location, tag_family, stack_location, closing_tag) {
  out = ""
  rest = line
  while (rest != "") {
    opening = index(rest, "<")
    if (opening == 0) {
      out = out transform_visible_text(rest)
      break
    }
    text = substr(rest, 1, opening - 1)
    out = out transform_visible_text(text)
    rest = substr(rest, opening)
    closing = index(rest, ">")
    if (closing == 0) {
      out = out rest
      break
    }
    tag = substr(rest, 1, closing)
    lower = tolower(tag)
    closing_tag = substr(lower, 1, 2) == "</"
    tag_location = stable_location(tag)
    tag_family = tag_attribute(tag, "data-aixray-field")
    if (tag_location != "") CURRENT_LOCATION = tag_location
    else if (TRANSFORM_STYLE || lower ~ /^<style([ >])/) \
      CURRENT_LOCATION = "report:print-header"
    else if (TRANSFORM_TITLE || lower ~ /^<title([ >])/) \
      CURRENT_LOCATION = "report:document-title"
    else if (transform_stack_location() != "") \
      CURRENT_LOCATION = transform_stack_location()
    else if (TRANSFORM_LOCATION != "") CURRENT_LOCATION = TRANSFORM_LOCATION
    else CURRENT_LOCATION = "report:structural"
    stack_location = CURRENT_LOCATION
    tag = normalize_schema_finding_ids(tag)
    tag = neutralize_remote_resources(tag)
    lower = tolower(tag)
    if (TRANSFORM_STYLE || lower ~ /^<style([ >])/) out = out apply_maps(tag, 1)
    else out = out apply_maps(tag, 0)

    if (lower ~ /^<style([ >])/) {
      TRANSFORM_STYLE = 1
      TRANSFORM_LOCATION = "report:print-header"
    }
    else if (lower ~ /^<\/style/) {
      TRANSFORM_STYLE = 0
      TRANSFORM_LOCATION = ""
    }
    else if (!TRANSFORM_STYLE && lower ~ /^<title([ >])/) {
      TRANSFORM_TITLE = 1
      TRANSFORM_LOCATION = "report:document-title"
    }
    else if (!TRANSFORM_STYLE && lower ~ /^<\/title/) {
      TRANSFORM_TITLE = 0
      TRANSFORM_LOCATION = ""
    }
    else if (!TRANSFORM_STYLE && lower ~ /^<div([ >])/) {
      TRANSFORM_DIV_DEPTH++
      class_value = tag_class(tag)
      if (TRANSFORM_EVIDENCE_DIV_DEPTH == 0 \
          && is_evidence_cell(class_value, "")) {
        TRANSFORM_EVIDENCE_DIV_DEPTH = TRANSFORM_DIV_DEPTH
        TRANSFORM_TD_CLASS = class_value
        TRANSFORM_EVIDENCE = 1
        TRANSFORM_CAPTURE_CONTEXT = 0
      }
    }
    else if (!TRANSFORM_STYLE && lower ~ /^<\/div/) {
      if (TRANSFORM_EVIDENCE_DIV_DEPTH == TRANSFORM_DIV_DEPTH) {
        TRANSFORM_EVIDENCE_DIV_DEPTH = 0
        TRANSFORM_TD_CLASS = ""
        TRANSFORM_EVIDENCE = 0
        TRANSFORM_CAPTURE_CONTEXT = 0
      }
      if (TRANSFORM_DIV_DEPTH > 0) TRANSFORM_DIV_DEPTH--
    }
    else if (!TRANSFORM_STYLE && lower ~ /^<tr([ >])/) {
      TRANSFORM_ROW_CONTEXT = ""
      TRANSFORM_CAPTURE_CONTEXT = 0
    }
    else if (!TRANSFORM_STYLE && lower ~ /^<td([ >])/) {
      class_value = tag_class(tag)
      TRANSFORM_TD_CLASS = class_value
      TRANSFORM_LOCATION = stable_location(tag)
      if (TRANSFORM_LOCATION == "") TRANSFORM_LOCATION = "assessment-cell"
      TRANSFORM_CAPTURE_CONTEXT = class_has(class_value, "ctl")
      evidence = is_evidence_cell(class_value, TRANSFORM_ROW_CONTEXT)
      TRANSFORM_EVIDENCE = evidence
    } else if (!TRANSFORM_STYLE && lower ~ /^<\/td/) {
      TRANSFORM_TD_CLASS = ""
      TRANSFORM_LOCATION = ""
      TRANSFORM_EVIDENCE = 0
      TRANSFORM_CAPTURE_CONTEXT = 0
    } else if (!TRANSFORM_STYLE && lower ~ /^<\/tr/) {
      TRANSFORM_ROW_CONTEXT = ""
      TRANSFORM_CAPTURE_CONTEXT = 0
    }
    if (closing_tag) transform_pop_tag(tag)
    else transform_push_tag(tag, stack_location, tag_family)
    rest = substr(rest, closing + 1)
  }

  if (!NOTICE_INSERTED && (position = index(out, "<body>")) > 0) {
    notice = "<div class=\"aixray-pseudonymize-notice\" role=\"note\" data-aixray-field=\"authored\" data-aixray-copy-id=\"review-disclosure-v1\" style=\"padding:12px 32px;border-bottom:2px solid #C2703D;font-family:monospace\">" \
      "<strong>PSEUDONYMIZED REVIEW COPY — NOT ANONYMIZED </strong><br>Automated independent validation passed, but no discovery-based tool can guarantee it found every identifier. " \
      "REVIEW REQUIRED: inspect this file and the local removals manifest before sharing. Never send the local decode key or local manifest.</div>\n" \
      "__AIXRAY_CHANGE_SUMMARY_V1__"
    out = substr(out, 1, position + length("<body>") - 1) "\n" notice substr(out, position + length("<body>"))
    NOTICE_INSERTED = 1
  }
  return out
}

function sanitize_summary_location(location,    index_number, raw_id, safe_id) {
  for (index_number = 1; index_number <= MAP_COUNT; index_number++) {
    if (MAP_KIND[index_number] != "vg") continue
    raw_id = "savevg_" MAP_RAW[index_number]
    safe_id = "savevg_[" MAP_TOKEN[index_number] "]"
    location = replace_literal(location, raw_id, safe_id)
  }
  return location
}

function build_change_summary(    summary, order_number, key, action, kind, replacement, location, count) {
  summary = "<div class=\"aixray-change-summary\" data-aixray-field=\"technical\" data-aixray-location=\"review:change-summary\" style=\"padding:10px 32px;border-bottom:1px solid #D9D9D9;font-family:monospace\"><strong>Automated change summary</strong><ul>"
  for (order_number = 1; order_number <= LEDGER_COUNT; order_number++) {
    key = LEDGER_ORDER[order_number]
    action = LEDGER_ACTION[key]
    kind = LEDGER_KIND[key]
    replacement = LEDGER_REPLACEMENT[key]
    location = sanitize_summary_location(LEDGER_LOCATION[key])
    count = LEDGER_OCCURRENCES[key] + 0
    if (action == "replace") {
      summary = summary "<li><code>" html_escape(replacement) \
        "</code> — " html_escape(kind) " replacement at " \
        html_escape(location) " — " count " occurrence(s)</li>"
    } else {
      summary = summary "<li>" html_escape(kind) " removal at " \
        html_escape(location) " — " count " occurrence(s)</li>"
    }
  }
  return summary "</ul></div>"
}

function is_known_keep_word(value, text, td_class, context,    lower, lower_context) {
  lower = tolower(value)
  lower_context = tolower(context)
  if (is_pseudotoken(value) || is_aix_fileset(value)) return 1
  if (lower == "flrtvc.ksh" || lower == "apar.csv" \
      || lower == "utf-8") return 1
  if (lower == "powertruesystems.com" || lower == "openssh.com") return 1
  if (lower == "pass" || lower == "fail" || lower == "warn" \
      || lower == "not_assessed" || lower == "not_applicable" \
      || lower == "high" || lower == "med" || lower == "low" \
      || lower == "active" || lower == "inactive" \
      || lower == "enabled" || lower == "disabled" \
      || lower == "yes" || lower == "no" || lower == "true" \
      || lower == "false" || lower == "none") return 1
  if (value ~ /^CVE-[0-9]+-[0-9]+$/ \
      || value ~ /^(IV|IJ)[0-9]+[A-Za-z0-9-]*$/ \
      || value ~ /^V-[0-9]+$/) return 1
  if (value ~ /^V[0-9]+R[0-9]+[A-Za-z0-9_.-]*$/ \
      || value ~ /^[A-Z][A-Z]*[0-9][A-Za-z0-9]*_[A-Za-z0-9_]+$/) return 1
  if (lower ~ /^(aix|power|ipv|nfsv|jfs)[0-9][a-z0-9_-]*$/ \
      || lower ~ /^(aes|rsa|sha|ssha|tls|ssl)[-_]?[0-9][a-z0-9_.-]*$/) return 1
  if (lower ~ /^j2_[a-z0-9_]+$/) return 1
  if (lower ~ /^smt-[0-9]+$/) return 1
  if (lower ~ /^(hdisk|ent|en|et|fcs|fscsi|fcnet|vscsi|vhost|vfchost|lv|hd|tty|rmt|proc|mem)[0-9]+$/) \
    return 1
  if (index(lower_context, "oslevel") > 0 \
      || index(lower_context, "firmware") > 0 \
      || index(lower_context, "vios") > 0 \
      || index(lower_context, "hmc") > 0 \
      || index(lower_context, "fileset") > 0 \
      || index(lower_context, "device type") > 0 \
      || index(lower_context, "machine model") > 0 \
      || index(lower_context, "timezone") > 0) return 1
  return 0
}

function is_identity_bearing_context(context,    lower) {
  lower = tolower(context)
  return index(lower, "peer") > 0 \
    || index(lower, "powerha") > 0 \
    || index(lower, "cluster node") > 0 \
    || index(lower, "node name") > 0 \
    || index(lower, "hostname") > 0 \
    || index(lower, "host name") > 0 \
    || index(lower, "client host") > 0 \
    || index(lower, "access list") > 0
}

function is_identity_structure_word(value,    lower) {
  lower = tolower(value)
  return lower == "powerha" || lower == "cluster" \
    || lower == "peer" || lower == "peers" \
    || lower == "node" || lower == "nodes" \
    || lower == "host" || lower == "hosts" \
    || lower == "hostname" || lower == "hostnames" \
    || lower == "client" || lower == "clients" \
    || lower == "member" || lower == "members" \
    || lower == "and" || lower == "or" || lower == "observed"
}

function validate_identity_cell(text, td_class, context,    plain, fields, count, part, value) {
  if (!class_has(td_class, "obs") \
      || !is_identity_bearing_context(context)) return
  plain = html_unescape(text)
  count = split(plain, fields, /[^A-Za-z0-9_.-]+/)
  for (part = 1; part <= count; part++) {
    value = clean_candidate(fields[part])
    if (value == "" || is_pseudotoken(value) \
        || is_identity_structure_word(value) \
        || is_known_keep_word(value, plain, td_class, context)) continue
    if (valid_name(value)) \
      die("redaction validation failed: an unresolved identifier-shaped token remains")
  }
}

function validate_labeled_value(text, label, kind,    lower, offset, relative, position, before, rest, value) {
  lower = tolower(text)
  offset = 1
  while ((relative = index(substr(lower, offset), label)) > 0) {
    position = offset + relative - 1
    before = position > 1 ? substr(text, position - 1, 1) : ""
    if (before != "" && before ~ /[A-Za-z0-9_]/) {
      offset = position + length("" label)
      continue
    }
    rest = substr(text, position + length("" label))
    value = first_value(rest)
    if (value != "" && !is_pseudotoken(value)) {
      if ((kind == "host" || kind == "lpar") && valid_name(value)) \
        die("redaction validation failed: an unresolved labeled hostname remains")
      if (kind == "user" && (valid_user(value) || is_email(value))) \
        die("redaction validation failed: an unresolved labeled user identifier remains")
      if (kind == "serial" && value ~ /^[A-Za-z0-9_.:-]+$/) \
        die("redaction validation failed: an unresolved labeled hardware identifier remains")
    }
    offset = position + length("" label)
  }
}

function validate_labels(text) {
  validate_labeled_value(text, "hostname=", "host")
  validate_labeled_value(text, "hostname:", "host")
  validate_labeled_value(text, "host=", "host")
  validate_labeled_value(text, "node=", "host")
  validate_labeled_value(text, "node name:", "host")
  validate_labeled_value(text, "nodename=", "host")
  validate_labeled_value(text, "lpar=", "lpar")
  validate_labeled_value(text, "lpar name:", "lpar")
  validate_labeled_value(text, "partition=", "lpar")
  validate_labeled_value(text, "partition name:", "lpar")
  validate_labeled_value(text, "username=", "user")
  validate_labeled_value(text, "username:", "user")
  validate_labeled_value(text, "user=", "user")
  validate_labeled_value(text, "account=", "user")
  validate_labeled_value(text, "email=", "user")
  validate_labeled_value(text, "serial number:", "serial")
  validate_labeled_value(text, "serial=", "serial")
  validate_labeled_value(text, "frame id=", "serial")
  validate_labeled_value(text, "system id=", "serial")
  validate_labeled_value(text, "location=", "serial")
}

function independent_identifier_check(text, td_class, context, evidence, strong_only,    safe, fields, count, part, value, lower, domain, base, slash, suffix, plain) {
  safe = html_unescape(text)
  plain = trim(safe)
  if (plain == "") return
  if (evidence) {
    if (!evidence_is_safe(safe)) \
      die("redaction validation failed: unresolved evidence token remains")
    return
  }

  validate_identity_cell(safe, td_class, context)
  validate_labels(safe)
  count = split(safe, fields, /[ \t\r\n,;(){}<>"'=]+/)
  for (part = 1; part <= count; part++) {
    value = clean_candidate(fields[part])
    if (value == "" \
        || value == "[redacted]" || value == "[redacted-secret]" \
        || value == "[redacted-evidence-line]") continue
    if (is_pseudotoken(value)) continue
    if (has_pseudotoken_shape(value)) \
      die("redaction validation failed: an unissued pseudotoken-shaped identifier remains")
    lower = tolower(value)

    if (is_email(value)) {
      domain = tolower(substr(value, index(value, "@") + 1))
      if (domain == "powertruesystems.com" || domain == "openssh.com") continue
      die("redaction validation failed: an unresolved email address remains")
    }
    if (is_aix_location(value)) \
      die("redaction validation failed: an unresolved AIX location identifier remains")
    if (is_uuid(value)) \
      die("redaction validation failed: an unresolved UUID remains")
    if (is_wwpn(value)) \
      die("redaction validation failed: an unresolved WWPN remains")
    if (is_mac(value)) \
      die("redaction validation failed: an unresolved MAC address remains")

    base = value
    slash = index(base, "/")
    suffix = ""
    if (slash > 1) {
      suffix = substr(base, slash + 1)
      base = substr(base, 1, slash - 1)
    }
    if (is_ipv4(base)) {
      if (!keep_network_like(base, safe, td_class, context)) \
        die("redaction validation failed: an unresolved IPv4 address remains")
      if (is_ipv4(suffix) && !keep_network_like(suffix, safe, td_class, context)) \
        die("redaction validation failed: an unresolved IPv4 suffix remains")
      continue
    }
    if (is_ipv6(base)) {
      if (!keep_network_like(base, safe, td_class, context)) \
        die("redaction validation failed: an unresolved IPv6 address remains")
      continue
    }
    split_fqdn_candidate(value)
    base = FQDN_BASE
    suffix = FQDN_SUFFIX
    lower = tolower(base)
    if (is_aix_fileset(base) || lower == "flrtvc.ksh" \
        || lower == "apar.csv" || lower ~ /[.](rte|install|fileset)$/) continue
    if (is_fqdn(base)) {
      if (lower == "powertruesystems.com" || lower == "openssh.com") continue
      if (!keep_network_like(base, safe, td_class, context)) \
        die("redaction validation failed: an unresolved FQDN remains")
    }
    if (suffix != "" && is_pseudotoken(base) \
        && tolower(base) ~ /^fqdn-/) \
      die("redaction validation failed: an unresolved FQDN suffix remains")
    if (!strong_only \
        && value ~ /^[A-Za-z][A-Za-z0-9_-]*$/ && value ~ /[0-9]/ \
        && !is_known_keep_word(value, safe, td_class, context)) \
      die("redaction validation failed: an unresolved identifier-shaped token remains")
  }
}

# The helper is standalone on the operator workstation, so it cannot import the
# Python report module at runtime. tests/test-review-pack.py requires this exact
# embedded matrix to match pipeline.report_plan.PLAN_QR_ROWS.
function initialize_plan_qr_rows() {
  PLAN_QR_ROW[1] = "1111111000001100000100010000001101011100101111111"
  PLAN_QR_ROW[2] = "1000001000011110110011101101011000001111101000001"
  PLAN_QR_ROW[3] = "1011101011101010011100111110111010000001101011101"
  PLAN_QR_ROW[4] = "1011101011001010011100001100011100011101001011101"
  PLAN_QR_ROW[5] = "1011101011011110000001111111111100001100001011101"
  PLAN_QR_ROW[6] = "1000001010101010100100100010000101101110001000001"
  PLAN_QR_ROW[7] = "1111111010101010101010101010101010101010101111111"
  PLAN_QR_ROW[8] = "0000000011000101010000100011111111100100100000000"
  PLAN_QR_ROW[9] = "1011111000011011100110111110011100011101001111100"
  PLAN_QR_ROW[10] = "1110100101010110111101011000011010011101011100000"
  PLAN_QR_ROW[11] = "1001101000100010001010101010010100101111000101101"
  PLAN_QR_ROW[12] = "0000010100010101100110000101111010110000000010001"
  PLAN_QR_ROW[13] = "0000101100101001111001111000011101011101100100111"
  PLAN_QR_ROW[14] = "0000010011101011111110110100111000000100001111010"
  PLAN_QR_ROW[15] = "0110101110100011101011110010100101101011000110011"
  PLAN_QR_ROW[16] = "0000110001111000111110110101010000101111010010001"
  PLAN_QR_ROW[17] = "1100011000110011011011001100100111110010111100100"
  PLAN_QR_ROW[18] = "1101110001000000111100011101110010100110011000010"
  PLAN_QR_ROW[19] = "0011111111111100011100010110101111010000111101011"
  PLAN_QR_ROW[20] = "0110100101100110110100010111110010010100101110011"
  PLAN_QR_ROW[21] = "0001101011101101100110111011011100011111110000110"
  PLAN_QR_ROW[22] = "1100110101101001101101010110011010011100011110100"
  PLAN_QR_ROW[23] = "0111111110010111101110111111110000110011111110101"
  PLAN_QR_ROW[24] = "0101100011000101111111100011111011100001100011001"
  PLAN_QR_ROW[25] = "1110101010001111000011101010001001011011101010111"
  PLAN_QR_ROW[26] = "1010100011100000010100100010011100011101100010010"
  PLAN_QR_ROW[27] = "1001111110101100100100111110100010110011111110011"
  PLAN_QR_ROW[28] = "0100100000101001001110001001110111010010100000000"
  PLAN_QR_ROW[29] = "0110011100000101010100101110000100011101100110110"
  PLAN_QR_ROW[30] = "1010000010100001100001110110111110001101111101000"
  PLAN_QR_ROW[31] = "0111101000000010100100100101010001111011111111111"
  PLAN_QR_ROW[32] = "1100100101000001010001010010001101011000100101001"
  PLAN_QR_ROW[33] = "0010111000011001001011011011011000001101110101110"
  PLAN_QR_ROW[34] = "1101110100101110101101111100001101011001110100010"
  PLAN_QR_ROW[35] = "0001101101000001100001011101011000001100001101001"
  PLAN_QR_ROW[36] = "0101000111111111011101110110101111010100100110001"
  PLAN_QR_ROW[37] = "1010001100001000110010000100010100101101110110111"
  PLAN_QR_ROW[38] = "1010000000010000011101111001101110000100010100110"
  PLAN_QR_ROW[39] = "0100011110010100111000111101000110110111111100111"
  PLAN_QR_ROW[40] = "0111000001101101011001111011110111010000110100000"
  PLAN_QR_ROW[41] = "1110001111100000111010111110011101101111111110101"
  PLAN_QR_ROW[42] = "0000000010011001001101100010111100011100100010000"
  PLAN_QR_ROW[43] = "1111111000011101111110101010111001111010101011011"
  PLAN_QR_ROW[44] = "1000001010001001100001100011111110110100100010011"
  PLAN_QR_ROW[45] = "1011101010100110010000111110001101111110111111111"
  PLAN_QR_ROW[46] = "1011101011010101010110110001111100000101101111010"
  PLAN_QR_ROW[47] = "1011101011000100001010111100110010001010011100111"
  PLAN_QR_ROW[48] = "1000001000101010100111111001010000101111011000001"
  PLAN_QR_ROW[49] = "1111111010111110111110001100100111110010000001111"
}

function canonical_plan_qr_path(row, y,    out, run_start, position, module, width) {
  out = ""
  run_start = 0
  for (position = 1; position <= length("" row) + 1; position++) {
    module = position <= length("" row) ? substr(row, position, 1) : "0"
    if (module == "1" && run_start == 0) {
      run_start = position
    } else if (module == "0" && run_start != 0) {
      width = position - run_start
      if (out != "") out = out " "
      out = out "M" (run_start + 3) " " y \
        "h" width "v1h-" width "z"
      run_start = 0
    }
  }
  return out
}

function canonical_plan_qr_svg(    svg, row_number) {
  svg = "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 57 57\" width=\"32mm\" height=\"32mm\" shape-rendering=\"crispEdges\" role=\"img\" aria-labelledby=\"plan-qr-title plan-qr-description\">\n"
  svg = svg "  <title id=\"plan-qr-title\">QR code — send your results for a mitigation Blueprint</title>\n"
  svg = svg "  <desc id=\"plan-qr-description\">Alternate path to powertruesystems.com/assessment/</desc>\n"
  svg = svg "  <rect x=\"0\" y=\"0\" width=\"57\" height=\"57\" fill=\"#fff\"/>\n"
  for (row_number = 1; row_number <= 49; row_number++) {
    svg = svg "  <path fill=\"#000\" d=\"" \
      canonical_plan_qr_path(PLAN_QR_ROW[row_number], row_number + 3) \
      "\"/>\n"
  }
  return svg "</svg>"
}

function canonical_plan_qr_open_tag() {
  return "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 57 57\" width=\"32mm\" height=\"32mm\" shape-rendering=\"crispEdges\" role=\"img\" aria-labelledby=\"plan-qr-title plan-qr-description\">"
}

function canonical_plan_link_url() {
  return "https://powertruesystems.com/assessment/?utm_source=aixray&utm_medium=report&utm_campaign=plan_reentry&utm_content=link#guided"
}

function canonical_plan_qr_url() {
  return "https://powertruesystems.com/assessment/?utm_source=aixray&utm_medium=report&utm_campaign=plan_reentry&utm_content=qr#guided"
}

function plan_qr_surface_count(document) {
  return count_literal(document, \
      "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 57 57\"") \
    + count_literal(document, "plan-qr-title") \
    + count_literal(document, "plan-qr-description")
}

function clear_plan_tag_attributes(    index_number, name) {
  for (index_number = 1; index_number <= PLAN_TAG_ATTRIBUTE_COUNT; index_number++) {
    name = PLAN_TAG_ATTRIBUTE_NAME[index_number]
    delete PLAN_TAG_ATTRIBUTE_PRESENT[name]
    delete PLAN_TAG_ATTRIBUTE_VALUE[name]
    delete PLAN_TAG_ATTRIBUTE_NAME[index_number]
  }
  PLAN_TAG_ATTRIBUTE_COUNT = 0
}

function parse_plan_tag_attributes(tag,    rest, name, lower_name, quote, \
    ending, value) {
  clear_plan_tag_attributes()
  rest = tag
  sub(/^<[ \t\r\n]*[A-Za-z][A-Za-z0-9:_.-]*/, "", rest)
  sub(/[ \t\r\n]*\/?>[ \t\r\n]*$/, "", rest)
  while (rest != "") {
    sub(/^[ \t\r\n]+/, "", rest)
    if (rest == "") break
    if (!match(rest, /^[A-Za-z_:][A-Za-z0-9:_.-]*/)) \
      die("redaction validation failed: malformed HTML attribute syntax")
    name = substr(rest, 1, RLENGTH)
    lower_name = tolower(name)
    if (PLAN_TAG_ATTRIBUTE_PRESENT[lower_name]) \
      die("redaction validation failed: malformed HTML duplicate attribute")
    PLAN_TAG_ATTRIBUTE_COUNT++
    PLAN_TAG_ATTRIBUTE_NAME[PLAN_TAG_ATTRIBUTE_COUNT] = lower_name
    PLAN_TAG_ATTRIBUTE_PRESENT[lower_name] = 1
    rest = substr(rest, RLENGTH + 1)
    sub(/^[ \t\r\n]*/, "", rest)
    value = ""
    if (substr(rest, 1, 1) == "=") {
      rest = substr(rest, 2)
      sub(/^[ \t\r\n]*/, "", rest)
      quote = substr(rest, 1, 1)
      if (quote == "\"" || quote == "'") {
        ending = index(substr(rest, 2), quote)
        if (ending == 0) \
          die("redaction validation failed: malformed HTML unterminated quoted attribute")
        value = substr(rest, 2, ending - 1)
        rest = substr(rest, ending + 2)
      } else {
        if (!match(rest, /^[^ \t\r\n>]+/)) \
          die("redaction validation failed: malformed HTML empty unquoted attribute")
        value = substr(rest, 1, RLENGTH)
        rest = substr(rest, RLENGTH + 1)
      }
    }
    PLAN_TAG_ATTRIBUTE_VALUE[lower_name] = value
  }
}

function plan_style_is_hidden(value,    normalized) {
  normalized = tolower(html_unescape(value))
  gsub(/[ \t\r\n]/, "", normalized)
  return normalized ~ /(^|;)display:none(!important)?(;|$)/ \
    || normalized ~ /(^|;)visibility:(hidden|collapse)(!important)?(;|$)/ \
    || normalized ~ /(^|;)opacity:0([.]0*)?(!important)?(;|$)/
}

function plan_tag_is_hidden(    aria_hidden) {
  if (PLAN_TAG_ATTRIBUTE_PRESENT["hidden"] \
      || PLAN_TAG_ATTRIBUTE_PRESENT["inert"]) return 1
  aria_hidden = tolower(trim(html_unescape( \
    PLAN_TAG_ATTRIBUTE_VALUE["aria-hidden"])))
  if (PLAN_TAG_ATTRIBUTE_PRESENT["aria-hidden"] \
      && aria_hidden == "true") return 1
  return PLAN_TAG_ATTRIBUTE_PRESENT["style"] \
    && plan_style_is_hidden(PLAN_TAG_ATTRIBUTE_VALUE["style"])
}

function is_plan_raw_text_element(name) {
  return name == "script" || name == "style" \
    || name == "textarea" || name == "title" \
    || name == "xmp" || name == "iframe" \
    || name == "noembed" || name == "noscript"
}

function is_plan_void_element(name) {
  return name == "area" || name == "base" || name == "br" \
    || name == "col" || name == "embed" || name == "hr" \
    || name == "img" || name == "input" || name == "link" \
    || name == "meta" || name == "param" || name == "source" \
    || name == "track" || name == "wbr"
}

function canonical_plan_qr_path_index(value,    row_number) {
  for (row_number = 1; row_number <= 49; row_number++) {
    if (value == canonical_plan_qr_path( \
        PLAN_QR_ROW[row_number], row_number + 3)) return row_number
  }
  return 0
}

function validate_plan_structure(document,    raw_marker_count, \
    raw_canonical_svg_count, raw_link_count, raw_qr_url_count, \
    raw_qr_attribute_count, raw_path_count, raw_svg_surface_count, \
    raw_title_surface_count, raw_description_surface_count, \
    raw_signal_count, \
    lower_document, cursor, remaining, opening, tag_position, \
    comment_end, closing, tag, lower_tag, name_text, closing_tag, \
    tag_name, parent_inert, parent_hidden, parent_card, parent_svg, \
    current_inert, current_hidden, current_card, current_svg, \
    is_marker, is_plan_svg, self_closing, raw_close, raw_position, \
    path_value, path_index, identifier) {
  raw_marker_count = count_literal(document, "data-aixray-plan-card")
  raw_canonical_svg_count = count_literal(document, canonical_plan_qr_svg())
  raw_link_count = count_literal(document, canonical_plan_link_url())
  raw_qr_url_count = count_literal(document, canonical_plan_qr_url())
  raw_qr_attribute_count = count_literal(document, "data-plan-qr-url")
  raw_path_count = count_literal(document, "<path fill=\"#000\" d=\"")
  raw_svg_surface_count = count_literal(document, \
    "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 57 57\"")
  raw_title_surface_count = count_literal(document, "plan-qr-title")
  raw_description_surface_count = count_literal( \
    document, "plan-qr-description")
  raw_signal_count = raw_marker_count \
    + raw_canonical_svg_count \
    + raw_link_count \
    + raw_qr_url_count \
    + raw_qr_attribute_count \
    + raw_path_count \
    + plan_qr_surface_count(document)
  if (raw_signal_count == 0) return

  PLAN_STRUCTURE_DEPTH = 0
  PLAN_STRUCTURE_CARD_COUNT = 0
  PLAN_STRUCTURE_SVG_COUNT = 0
  PLAN_STRUCTURE_EXACT_SVG_COUNT = 0
  PLAN_STRUCTURE_PATH_COUNT = 0
  PLAN_STRUCTURE_LINK_COUNT = 0
  PLAN_STRUCTURE_QR_ATTRIBUTE_COUNT = 0
  PLAN_STRUCTURE_RAW_TAG = ""
  lower_document = tolower(document)
  cursor = 1
  while (cursor <= length("" document)) {
    if (PLAN_STRUCTURE_RAW_TAG != "") {
      raw_close = "</" PLAN_STRUCTURE_RAW_TAG
      raw_position = index(substr(lower_document, cursor), raw_close)
      if (raw_position == 0) \
        die("redaction validation failed: malformed HTML raw-text container")
      cursor += raw_position - 1
      PLAN_STRUCTURE_RAW_TAG = ""
    }

    remaining = substr(document, cursor)
    opening = index(remaining, "<")
    if (opening == 0) break
    tag_position = cursor + opening - 1
    if (substr(document, tag_position, 4) == "<!--") {
      comment_end = index(substr(document, tag_position + 4), "-->")
      if (comment_end == 0) \
        die("redaction validation failed: malformed HTML comment")
      cursor = tag_position + comment_end + 6
      continue
    }
    closing = index(substr(document, tag_position), ">")
    if (closing == 0) \
      die("redaction validation failed: malformed HTML unterminated tag fragment")
    tag = substr(document, tag_position, closing)
    lower_tag = tolower(tag)
    cursor = tag_position + closing
    if (lower_tag ~ /^<[ \t\r\n]*[!?]/) continue

    name_text = substr(lower_tag, 2)
    sub(/^[ \t\r\n]*/, "", name_text)
    closing_tag = substr(name_text, 1, 1) == "/"
    if (closing_tag) {
      name_text = substr(name_text, 2)
      sub(/^[ \t\r\n]*/, "", name_text)
    }
    if (!match(name_text, /^[a-z][a-z0-9:_.-]*/)) \
      die("redaction validation failed: malformed HTML tag syntax")
    tag_name = substr(name_text, 1, RLENGTH)

    if (closing_tag) {
      if (PLAN_STRUCTURE_DEPTH == 0 \
          || PLAN_STRUCTURE_TAG[PLAN_STRUCTURE_DEPTH] != tag_name) \
        die("redaction validation failed: malformed HTML element nesting")
      delete PLAN_STRUCTURE_TAG[PLAN_STRUCTURE_DEPTH]
      delete PLAN_STRUCTURE_INERT[PLAN_STRUCTURE_DEPTH]
      delete PLAN_STRUCTURE_HIDDEN[PLAN_STRUCTURE_DEPTH]
      delete PLAN_STRUCTURE_CARD[PLAN_STRUCTURE_DEPTH]
      delete PLAN_STRUCTURE_SVG[PLAN_STRUCTURE_DEPTH]
      PLAN_STRUCTURE_DEPTH--
      continue
    }

    parse_plan_tag_attributes(tag)
    parent_inert = PLAN_STRUCTURE_DEPTH > 0 \
      && PLAN_STRUCTURE_INERT[PLAN_STRUCTURE_DEPTH]
    parent_hidden = PLAN_STRUCTURE_DEPTH > 0 \
      && PLAN_STRUCTURE_HIDDEN[PLAN_STRUCTURE_DEPTH]
    parent_card = PLAN_STRUCTURE_DEPTH > 0 \
      && PLAN_STRUCTURE_CARD[PLAN_STRUCTURE_DEPTH]
    parent_svg = PLAN_STRUCTURE_DEPTH > 0 \
      && PLAN_STRUCTURE_SVG[PLAN_STRUCTURE_DEPTH]
    current_inert = parent_inert || tag_name == "template"
    current_hidden = parent_hidden || plan_tag_is_hidden()
    current_card = parent_card
    current_svg = parent_svg
    is_marker = PLAN_TAG_ATTRIBUTE_PRESENT["data-aixray-plan-card"]

    if (is_marker) {
      PLAN_STRUCTURE_CARD_COUNT++
      if (tag_name != "aside" \
          || !class_has(PLAN_TAG_ATTRIBUTE_VALUE["class"], "plan-card") \
          || PLAN_TAG_ATTRIBUTE_VALUE["data-aixray-plan-card"] != "" \
          || parent_card || current_inert || current_hidden) \
        die("redaction validation failed: Plan QR vector card is not one live semantic subtree")
      current_card = 1
    }

    if (PLAN_TAG_ATTRIBUTE_PRESENT["data-plan-qr-url"]) {
      PLAN_STRUCTURE_QR_ATTRIBUTE_COUNT++
      if (!is_marker \
          || PLAN_TAG_ATTRIBUTE_VALUE["data-plan-qr-url"] \
            != canonical_plan_qr_url()) \
        die("redaction validation failed: Plan QR vector data is outside the live Plan card")
    }

    if (tag_name == "a" \
        && PLAN_TAG_ATTRIBUTE_PRESENT["href"] \
        && PLAN_TAG_ATTRIBUTE_VALUE["href"] == canonical_plan_link_url()) {
      PLAN_STRUCTURE_LINK_COUNT++
      if (!current_card || current_inert || current_hidden) \
        die("redaction validation failed: Plan QR vector link is outside the live Plan card")
    }

    is_plan_svg = tag_name == "svg" \
      && (current_card \
        || PLAN_TAG_ATTRIBUTE_VALUE["aria-labelledby"] \
          == "plan-qr-title plan-qr-description" \
        || tag == canonical_plan_qr_open_tag())
    if (is_plan_svg) {
      PLAN_STRUCTURE_SVG_COUNT++
      if (!current_card || current_inert || current_hidden \
          || parent_svg || tag != canonical_plan_qr_open_tag() \
          || substr(document, tag_position, \
              length("" canonical_plan_qr_svg())) \
            != canonical_plan_qr_svg()) \
        die("redaction validation failed: Plan QR vector SVG is not canonical inside the live Plan card")
      PLAN_STRUCTURE_EXACT_SVG_COUNT++
      current_svg = 1
    }

    if (tag_name == "path" && PLAN_TAG_ATTRIBUTE_PRESENT["d"]) {
      path_value = PLAN_TAG_ATTRIBUTE_VALUE["d"]
      path_index = canonical_plan_qr_path_index(path_value)
      if (parent_svg) {
        PLAN_STRUCTURE_PATH_COUNT++
        if (current_inert || current_hidden \
            || PLAN_STRUCTURE_PATH_COUNT > 49 \
            || path_index != PLAN_STRUCTURE_PATH_COUNT) \
          die("redaction validation failed: Plan QR vector paths are not canonical inside the live Plan card")
      } else if (path_index != 0) {
        die("redaction validation failed: Plan QR vector path is outside the live Plan card")
      }
    }

    if (PLAN_TAG_ATTRIBUTE_PRESENT["id"]) {
      identifier = PLAN_TAG_ATTRIBUTE_VALUE["id"]
      if ((identifier == "plan-qr-title" \
          || identifier == "plan-qr-description") \
          && (!parent_svg || current_inert || current_hidden)) \
        die("redaction validation failed: Plan QR vector surface is outside the live Plan card")
    }

    self_closing = tag ~ /\/[ \t\r\n]*>$/ \
      || is_plan_void_element(tag_name)
    if (!self_closing) {
      PLAN_STRUCTURE_DEPTH++
      PLAN_STRUCTURE_TAG[PLAN_STRUCTURE_DEPTH] = tag_name
      PLAN_STRUCTURE_INERT[PLAN_STRUCTURE_DEPTH] = current_inert
      PLAN_STRUCTURE_HIDDEN[PLAN_STRUCTURE_DEPTH] = current_hidden
      PLAN_STRUCTURE_CARD[PLAN_STRUCTURE_DEPTH] = current_card
      PLAN_STRUCTURE_SVG[PLAN_STRUCTURE_DEPTH] = current_svg
      if (is_plan_raw_text_element(tag_name)) \
        PLAN_STRUCTURE_RAW_TAG = tag_name
    }
  }

  if (PLAN_STRUCTURE_DEPTH != 0) \
    die("redaction validation failed: malformed HTML element nesting")
  if (raw_marker_count != PLAN_STRUCTURE_CARD_COUNT \
      || raw_canonical_svg_count != PLAN_STRUCTURE_EXACT_SVG_COUNT \
      || raw_link_count != PLAN_STRUCTURE_LINK_COUNT \
      || raw_qr_attribute_count != PLAN_STRUCTURE_QR_ATTRIBUTE_COUNT \
      || raw_qr_url_count != PLAN_STRUCTURE_QR_ATTRIBUTE_COUNT \
      || PLAN_STRUCTURE_CARD_COUNT != 1 \
      || PLAN_STRUCTURE_SVG_COUNT != 1 \
      || PLAN_STRUCTURE_EXACT_SVG_COUNT != 1 \
      || PLAN_STRUCTURE_PATH_COUNT != 49 \
      || PLAN_STRUCTURE_LINK_COUNT != 1 \
      || PLAN_STRUCTURE_QR_ATTRIBUTE_COUNT != 1 \
      || raw_path_count != PLAN_STRUCTURE_PATH_COUNT \
      || raw_svg_surface_count != 1 \
      || raw_title_surface_count != 2 \
      || raw_description_surface_count != 2) \
    die("redaction validation failed: Plan QR vector structure does not match the live Plan card contract")
}

function approved_report_attribute(name, value,    lower_name) {
  lower_name = tolower(name)
  if (lower_name == "xmlns") \
    return value == "http://www.w3.org/2000/svg"
  if (lower_name == "data-plan-qr-url") \
    return value == canonical_plan_qr_url()
  if (lower_name != "href") return 0
  return value == "https://powertruesystems.com" \
      || value == "https://powertruesystems.com/assessment" \
      || value == canonical_plan_link_url() \
      || value == "mailto:review@powertruesystems.com"
}

function markup_attribute_value(name, value,    safe, lower_name, raw_lower) {
  safe = html_unescape(value)
  lower_name = tolower(name)
  raw_lower = tolower(value)
  if ((lower_name == "href" || lower_name == "xmlns") \
      && (value ~ /&#[xX]?[0-9A-Fa-f][0-9A-Fa-f]*;?/ \
        || raw_lower ~ /&(colon|sol);?/)) \
    die("redaction validation failed: unapproved report destination")
  if (approved_report_attribute(name, value)) {
    if (lower_name == "href" \
        && value == canonical_plan_link_url()) \
      VALID_PLAN_LINK_COUNT++
    if (lower_name == "data-plan-qr-url") VALID_PLAN_QR_COUNT++
    return ""
  }
  if (lower_name == "data-plan-qr-url") \
    die("redaction validation failed: unapproved Plan QR destination")
  if (lower_name == "href") {
    if (value ~ /^#finding-([0-9][0-9]*|deep-dive)$/) return ""
    value = safe
    sub(/^[ \t\r\n]+/, "", value)
    sub(/^[A-Za-z][A-Za-z0-9+.-]*:/, "", value)
    sub(/^\/\//, "", value)
    independent_identifier_check(value, "", "HTML " name " attribute", 0)
    die("redaction validation failed: unapproved report destination")
  }
  if (lower_name == "xmlns") \
    die("redaction validation failed: unapproved report destination")
  if (lower_name == "d") {
    VALID_PLAN_QR_PATH_COUNT++
    if (VALID_PLAN_QR_COUNT != 1 \
        || VALID_PLAN_QR_PATH_COUNT > 49 \
        || value != canonical_plan_qr_path( \
          PLAN_QR_ROW[VALID_PLAN_QR_PATH_COUNT], \
          VALID_PLAN_QR_PATH_COUNT + 3)) \
      die("redaction validation failed: Plan QR vector path does not match the canonical contract")
    return ""
  }
  if (lower_name == "style") {
    gsub(/#[0-9A-Fa-f]+/, " ", safe)
    gsub(/[0-9][0-9.]*(px|pt|pc|em|rem|ex|ch|vh|vw|vmin|vmax|%|s|ms)/, \
      " ", safe)
  }
  gsub(/[A-Za-z][A-Za-z0-9+.-]*:\/\/+/, "", safe)
  if (tolower(substr(safe, 1, 7)) == "mailto:") safe = substr(safe, 8)
  return safe
}

function validate_tag_attributes(tag,    rest, name, quote, ending, value) {
  rest = tag
  sub(/^<[\/!?]?[A-Za-z][A-Za-z0-9:_.-]*/, "", rest)
  sub(/>$/, "", rest)
  while (rest != "") {
    sub(/^[ \t\r\n\/]+/, "", rest)
    if (rest == "") return
    if (!match(rest, /^[A-Za-z_:][A-Za-z0-9:_.-]*/)) \
      die("redaction validation failed: malformed HTML attribute syntax")
    name = substr(rest, 1, RLENGTH)
    rest = substr(rest, RLENGTH + 1)
    sub(/^[ \t\r\n]*/, "", rest)
    if (substr(rest, 1, 1) != "=") continue
    rest = substr(rest, 2)
    sub(/^[ \t\r\n]*/, "", rest)
    quote = substr(rest, 1, 1)
    if (quote == "\"" || quote == "'") {
      ending = index(substr(rest, 2), quote)
      if (ending == 0) \
        die("redaction validation failed: malformed HTML unterminated quoted attribute")
      value = substr(rest, 2, ending - 1)
      rest = substr(rest, ending + 2)
    } else {
      if (!match(rest, /^[^ \t\r\n>]+/)) \
        die("redaction validation failed: malformed HTML empty unquoted attribute")
      value = substr(rest, 1, RLENGTH)
      rest = substr(rest, RLENGTH + 1)
    }
    value = markup_attribute_value(name, value)
    independent_identifier_check(value, "", "HTML " name " attribute", 0)
  }
}

function validate_markup(tag,    lower, comment) {
  lower = tolower(tag)
  if (lower ~ /^<!--/) {
    comment = tag
    sub(/^<!--[ \t\r\n]*/, "", comment)
    sub(/[ \t\r\n]*-->$/, "", comment)
    independent_identifier_check(comment, "", "HTML comment", 0)
    return
  }
  validate_tag_attributes(tag)
}

function validate_segment(segment, host_only, td_class, context, evidence,    order_number, index_number, encoded) {
  for (order_number = 1; order_number <= MAP_COUNT; order_number++) {
    index_number = MAP_ORDER[order_number]
    if (host_only && MAP_GROUP[index_number] != "host") continue
    if (contains_bounded(segment, MAP_RAW[index_number])) \
      die("redaction validation failed: an original identifier remains in the HTML")
    encoded = html_escape(MAP_RAW[index_number])
    if (encoded != MAP_RAW[index_number] && contains_bounded(segment, encoded)) \
      die("redaction validation failed: an HTML-escaped original identifier remains")
  }
  if (!host_only && td_class != "") \
    independent_identifier_check(segment, td_class, context, evidence)
}

function validation_text(text) {
  if (VALIDATE_CAPTURE_CONTEXT) \
    VALIDATE_ROW_CONTEXT = trim(VALIDATE_ROW_CONTEXT " " html_unescape(text))
  validate_segment(text, VALIDATE_STYLE, VALIDATE_TD_CLASS, \
    VALIDATE_ROW_CONTEXT, VALIDATE_EVIDENCE)
  if (!VALIDATE_STYLE && VALIDATE_TD_CLASS == "") \
    independent_identifier_check(text, "", VALIDATE_ROW_CONTEXT, 0, 1)
}

function validate_line(line,    rest, opening, closing, text, tag, lower, class_value) {
  rest = line
  while (rest != "") {
    opening = index(rest, "<")
    if (opening == 0) {
      validation_text(rest)
      break
    }
    text = substr(rest, 1, opening - 1)
    validation_text(text)
    rest = substr(rest, opening)
    closing = index(rest, ">")
    if (closing == 0) \
      die("redaction validation failed: malformed HTML unterminated tag fragment")
    tag = substr(rest, 1, closing)
    lower = tolower(tag)
    validate_segment(tag, VALIDATE_STYLE || lower ~ /^<style([ >])/, "", "", 0)
    validate_markup(tag)
    if (lower ~ /^<style([ >])/) VALIDATE_STYLE = 1
    else if (lower ~ /^<\/style/) VALIDATE_STYLE = 0
    else if (!VALIDATE_STYLE && lower ~ /^<div([ >])/) {
      VALIDATE_DIV_DEPTH++
      class_value = tag_class(tag)
      if (VALIDATE_EVIDENCE_DIV_DEPTH == 0 \
          && is_evidence_cell(class_value, "")) {
        VALIDATE_EVIDENCE_DIV_DEPTH = VALIDATE_DIV_DEPTH
        VALIDATE_TD_CLASS = class_value
        VALIDATE_EVIDENCE = 1
        VALIDATE_CAPTURE_CONTEXT = 0
      }
    }
    else if (!VALIDATE_STYLE && lower ~ /^<\/div/) {
      if (VALIDATE_EVIDENCE_DIV_DEPTH == VALIDATE_DIV_DEPTH) {
        VALIDATE_EVIDENCE_DIV_DEPTH = 0
        VALIDATE_TD_CLASS = ""
        VALIDATE_EVIDENCE = 0
        VALIDATE_CAPTURE_CONTEXT = 0
      }
      if (VALIDATE_DIV_DEPTH > 0) VALIDATE_DIV_DEPTH--
    }
    else if (!VALIDATE_STYLE && lower ~ /^<tr([ >])/) {
      VALIDATE_ROW_CONTEXT = ""
      VALIDATE_CAPTURE_CONTEXT = 0
    } else if (!VALIDATE_STYLE && lower ~ /^<td([ >])/) {
      class_value = tag_class(tag)
      VALIDATE_TD_CLASS = class_value
      VALIDATE_CAPTURE_CONTEXT = class_has(class_value, "ctl")
      VALIDATE_EVIDENCE = is_evidence_cell(class_value, VALIDATE_ROW_CONTEXT)
    } else if (!VALIDATE_STYLE && lower ~ /^<\/td/) {
      VALIDATE_TD_CLASS = ""
      VALIDATE_EVIDENCE = 0
      VALIDATE_CAPTURE_CONTEXT = 0
    } else if (!VALIDATE_STYLE && lower ~ /^<\/tr/) {
      VALIDATE_ROW_CONTEXT = ""
      VALIDATE_CAPTURE_CONTEXT = 0
    }
    rest = substr(rest, closing + 1)
  }
}

{
  DOCUMENT[NR] = $0
  ALL_DOCUMENT = ALL_DOCUMENT $0 "\n"
}

END {
  initialize_plan_qr_rows()
  validate_plan_structure(ALL_DOCUMENT)
  version_marker = "<meta name=\"aixray-report-version\" content=\"1\">"
  if (count_literal(ALL_DOCUMENT, version_marker) != 1) \
    die("expected PTxray report version marker exactly once; refusing unrecognized input")
  if (count_literal(ALL_DOCUMENT, "<body>") != 1 \
      || count_literal(ALL_DOCUMENT, "</html>") != 1) \
    die("expected one complete PTxray HTML envelope; refusing malformed input")
  plan_card_count = count_literal(ALL_DOCUMENT, "data-aixray-plan-card")
  canonical_plan_qr_count = count_literal( \
    ALL_DOCUMENT, canonical_plan_qr_svg())
  plan_svg_surface_count = plan_qr_surface_count(ALL_DOCUMENT)

  report_date = extract_meta(ALL_DOCUMENT, "aixray-report-date")
  if (report_date !~ /^[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]$/) \
    die("expected one valid PTxray report date marker")
  month = substr(report_date, 6, 2) + 0
  day = substr(report_date, 9, 2) + 0
  if (month < 1 || month > 12 || day < 1 || day > 31) \
    die("PTxray report date marker is outside the calendar range")

  report_host_encoded = extract_meta(ALL_DOCUMENT, "aixray-report-host")
  report_host = html_unescape(report_host_encoded)
  if (!valid_name(report_host)) die("expected one valid PTxray report host marker")
  reject_source_pseudotoken_shapes(ALL_DOCUMENT)

  AUTHORED_ACCUMULATOR = ""
  AUTHORED_PASS = 1
  DISCOVERY_STYLE = 0
  DISCOVERY_TD_CLASS = ""
  DISCOVERY_ROW_CONTEXT = ""
  DISCOVERY_CAPTURE_CONTEXT = 0
  DISCOVERY_DIV_DEPTH = 0
  DISCOVERY_EVIDENCE_DIV_DEPTH = 0
  DISCOVERY_STACK_DEPTH = 0
  for (line_number = 1; line_number <= NR; line_number++) {
    discover_line(DOCUMENT[line_number])
  }
  AUTHORED_PASS = 0

  add_map(report_host, "host")

  DISCOVERY_STYLE = 0
  DISCOVERY_TD_CLASS = ""
  DISCOVERY_ROW_CONTEXT = ""
  DISCOVERY_CAPTURE_CONTEXT = 0
  DISCOVERY_DIV_DEPTH = 0
  DISCOVERY_EVIDENCE_DIV_DEPTH = 0
  DISCOVERY_STACK_DEPTH = 0
  for (line_number = 1; line_number <= NR; line_number++) {
    discover_line(DOCUMENT[line_number])
  }

  SECRET_REMOVED = 0
  GECOS_REMOVED = 0
  sort_maps()

  TRANSFORM_STYLE = 0
  TRANSFORM_TITLE = 0
  TRANSFORM_TD_CLASS = ""
  TRANSFORM_LOCATION = ""
  TRANSFORM_EVIDENCE = 0
  TRANSFORM_ROW_CONTEXT = ""
  TRANSFORM_CAPTURE_CONTEXT = 0
  TRANSFORM_DIV_DEPTH = 0
  TRANSFORM_EVIDENCE_DIV_DEPTH = 0
  TRANSFORM_ACTIVE = 1
  CURRENT_LOCATION = "report:structural"
  TRANSFORM_STACK_DEPTH = 0
  VALIDATE_STYLE = 0
  VALIDATE_TD_CLASS = ""
  VALIDATE_EVIDENCE = 0
  VALIDATE_ROW_CONTEXT = ""
  VALIDATE_CAPTURE_CONTEXT = 0
  VALIDATE_DIV_DEPTH = 0
  VALIDATE_EVIDENCE_DIV_DEPTH = 0
  VALID_PLAN_LINK_COUNT = 0
  VALID_PLAN_QR_COUNT = 0
  VALID_PLAN_QR_PATH_COUNT = 0
  NOTICE_INSERTED = 0
  for (line_number = 1; line_number <= NR; line_number++) {
    transformed = transform_line(DOCUMENT[line_number])
    OUTPUT_DOCUMENT[line_number] = transformed
  }
  if (!NOTICE_INSERTED) die("redaction validation failed: output notice was not inserted")
  if (LEDGER_COUNT == 0) die("redaction validation failed: transformation ledger is empty")

  change_summary = build_change_summary()
  summary_marker_count = 0
  for (line_number = 1; line_number <= NR; line_number++) {
    summary_marker_count += count_literal(OUTPUT_DOCUMENT[line_number], \
      "__AIXRAY_CHANGE_SUMMARY_V1__")
    OUTPUT_DOCUMENT[line_number] = replace_literal(OUTPUT_DOCUMENT[line_number], \
      "__AIXRAY_CHANGE_SUMMARY_V1__", change_summary)
    print OUTPUT_DOCUMENT[line_number] > html_out
  }
  close(html_out)
  if (summary_marker_count != 1) \
    die("redaction validation failed: change summary placement is ambiguous")

  plan_signal_count = VALID_PLAN_LINK_COUNT \
    + VALID_PLAN_QR_COUNT \
    + VALID_PLAN_QR_PATH_COUNT \
    + plan_svg_surface_count
  if ((plan_card_count != 0 || plan_signal_count != 0) \
      && (plan_card_count != 1 || canonical_plan_qr_count != 1)) \
    die("redaction validation failed: Plan QR vector does not match the canonical contract")
  if (VALID_PLAN_LINK_COUNT != VALID_PLAN_QR_COUNT \
      || VALID_PLAN_LINK_COUNT > 1) \
    die("redaction validation failed: incomplete or duplicate Plan destination contract")
  if (VALID_PLAN_QR_PATH_COUNT != 49 * VALID_PLAN_QR_COUNT) \
    die("redaction validation failed: Plan QR vector is incomplete or duplicated")

  print "# DO NOT SEND THIS FILE — local decode key" > map_out
  print "# token\treal value" > map_out
  published_map_count = 0
  for (index_number = 1; index_number <= MAP_COUNT; index_number++) {
    if (MAP_OCCURRENCES[index_number] < 1) continue
    print MAP_TOKEN[index_number] "\t" MAP_RAW[index_number] > map_out
    published_map_count++
  }
  close(map_out)
  if (published_map_count == 0) \
    die("redaction validation failed: no used pseudonym mappings exist")

  print "# action\tkind\treplacement\tlocation\toccurrences" > ledger_out
  for (order_number = 1; order_number <= LEDGER_COUNT; order_number++) {
    key = LEDGER_ORDER[order_number]
    print LEDGER_ACTION[key] "\t" LEDGER_KIND[key] "\t" \
      LEDGER_REPLACEMENT[key] "\t" LEDGER_LOCATION[key] "\t" \
      LEDGER_OCCURRENCES[key] + 0 > ledger_out
  }
  close(ledger_out)

  host_occurrences = 0
  network_occurrences = 0
  hardware_occurrences = 0
  people_occurrences = 0
  for (index_number = 1; index_number <= MAP_COUNT; index_number++) {
    if (MAP_GROUP[index_number] == "host") host_occurrences += MAP_OCCURRENCES[index_number]
    else if (MAP_GROUP[index_number] == "network") network_occurrences += MAP_OCCURRENCES[index_number]
    else if (MAP_GROUP[index_number] == "hardware") hardware_occurrences += MAP_OCCURRENCES[index_number]
    else if (MAP_GROUP[index_number] == "people") people_occurrences += MAP_OCCURRENCES[index_number]
  }
  print host_occurrences + 0 "\t" network_occurrences + 0 "\t" hardware_occurrences + 0 "\t" people_occurrences + 0 "\t" SECRET_REMOVED + 0 "\t" GECOS_REMOVED + 0 "\t" EVIDENCE_REMOVED + 0 > stats_out
  close(stats_out)
  print report_date > date_out
  close(date_out)
}
AWK
then
  fail "could not prepare the local redaction pass"
fi

inject_refusal transform
if ! awk -v html_out="$HTML_TMP" -v map_out="$MAP_TMP" \
    -v ledger_out="$LEDGER_TMP" \
    -v stats_out="$STATS_TMP" -v date_out="$DATE_TMP" \
    -v error_out="$ERROR_TMP" -f "$AWK_PROGRAM" "$INPUT_PATH"; then
  if [ -s "$ERROR_TMP" ]; then
    REASON=$(cat "$ERROR_TMP")
    printf 'transform\t%s\n' "$REASON" > "$VIOLATIONS_TMP"
    publish_refusal "$REASON"
  fi
  publish_refusal "pseudonymization transform failed"
fi

[ -s "$HTML_TMP" ] && [ -s "$MAP_TMP" ] && [ -s "$LEDGER_TMP" ] \
  && [ -s "$STATS_TMP" ] && [ -s "$DATE_TMP" ] \
  || publish_refusal "transform did not produce every required scratch result"

if ! awk -F '\t' '
  /^[#]/ || NF == 0 { next }
  NF != 2 { exit 1 }
  {
    token = $1
    if (token ~ /^host-/) kind = "host"
    else if (token ~ /^lpar-/) kind = "lpar"
    else if (token ~ /^ip-/) kind = "ip"
    else if (token ~ /^mac-/) kind = "mac"
    else if (token ~ /^fqdn-/) kind = "fqdn"
    else if (token ~ /^serial-/) kind = "serial"
    else if (token ~ /^wwpn-/) kind = "wwpn"
    else if (token ~ /^user-/) kind = "user"
    else if (token ~ /^path-/) kind = "path"
    else if (token ~ /^vg-/) kind = "vg"
    else exit 1
    print token "\t" kind
  }
' "$MAP_TMP" > "$TOKEN_TMP"; then
  printf '%s\n' 'token-registry	failed to derive issued token registry' \
    > "$VIOLATIONS_TMP"
  publish_refusal "issued-token registry reconciliation failed"
fi
[ -s "$TOKEN_TMP" ] \
  || publish_refusal "issued-token registry is empty"

if ! awk -v map_in="$MAP_TMP" -v ledger_in="$LEDGER_TMP" \
    -v html_in="$HTML_TMP" -v result_out="$RECONCILE_TMP" \
    -v violation_out="$VIOLATIONS_TMP" '
function char_count(value,    count) {
  count = 0
  while (substr(value, count + 1, 1) != "") count++
  return count
}
function literal_count(text, needle,    count, rest, position) {
  if (needle == "") return 0
  count = 0
  rest = text
  while ((position = index(rest, needle)) > 0) {
    count++
    rest = substr(rest, position + char_count(needle))
  }
  return count
}
function replace_literal(text, old, replacement,    result, position) {
  if (old == "") return text
  result = ""
  while ((position = index(text, old)) > 0) {
    result = result substr(text, 1, position - 1) replacement
    text = substr(text, position + char_count(old))
  }
  return result text
}
function html_escape(text) {
  text = replace_literal(text, "&", "&amp;")
  text = replace_literal(text, "\"", "&quot;")
  text = replace_literal(text, "\047", "&#39;")
  text = replace_literal(text, "<", "&lt;")
  text = replace_literal(text, ">", "&gt;")
  return text
}
function token_kind(token) {
  if (token ~ /^host-/) return "host"
  if (token ~ /^lpar-/) return "lpar"
  if (token ~ /^ip-/) return "ip"
  if (token ~ /^mac-/) return "mac"
  if (token ~ /^fqdn-/) return "fqdn"
  if (token ~ /^serial-/) return "serial"
  if (token ~ /^wwpn-/) return "wwpn"
  if (token ~ /^user-/) return "user"
  if (token ~ /^path-/) return "path"
  if (token ~ /^vg-/) return "vg"
  return ""
}
function token_shape(token) {
  return token ~ /^host-([A-Z]|[0-9]+)$/ \
    || token ~ /^(lpar|ip|mac|fqdn|serial|wwpn|user|path|vg)-[0-9]+$/
}
function identifier_character(character) {
  return character ~ /[A-Za-z0-9_.:@-]/
}
function bounded_count(text, value,    count, cursor, relative, position, before, after, value_size, text_size) {
  if (value == "") return 0
  count = 0
  cursor = 1
  value_size = char_count(value)
  text_size = char_count(text)
  while ((relative = index(substr(text, cursor), value)) > 0) {
    position = cursor + relative - 1
    before = position > 1 ? substr(text, position - 1, 1) : ""
    after = position + value_size <= text_size \
      ? substr(text, position + value_size, 1) : ""
    if ((before == "" || !identifier_character(before)) \
        && (after == "" || !identifier_character(after))) count++
    cursor = position + 1
  }
  return count
}
function pseudotoken_count(text, wanted,    count, fields, field_count, field_number) {
  count = 0
  field_count = split(text, fields, /[^A-Za-z0-9_-]+/)
  for (field_number = 1; field_number <= field_count; field_number++) {
    if (fields[field_number] == wanted) count++
  }
  return count
}
function reject(location, reason, value) {
  printf "%s\t%s", location, reason > violation_out
  # Values are sourced from the raw map, event ledger, or candidate. Keep
  # rejection diagnostics useful without duplicating customer identifiers.
  printf "\n" > violation_out
  FAILED = 1
}
BEGIN {
  while ((status = getline line < map_in) > 0) {
    if (line ~ /^#/ || line == "") continue
    fields = split(line, pieces, "\t")
    if (fields != 2) {
      reject("decode-key", "malformed token mapping", "")
      continue
    }
    token = pieces[1]
    raw = pieces[2]
    kind = token_kind(token)
    if (!token_shape(token) || kind == "" || raw == "") {
      reject("decode-key", "invalid token mapping", token)
      continue
    }
    if (token in MAP_RAW) {
      reject("decode-key", "duplicate issued token", token)
      continue
    }
    if (raw in RAW_TOKEN && RAW_TOKEN[raw] != token) {
      reject("decode-key", "one original value maps to multiple tokens", token)
      continue
    }
    MAP_RAW[token] = raw
    MAP_KIND[token] = kind
    RAW_TOKEN[raw] = token
    MAP_COUNT++
  }
  close(map_in)
  if (status < 0 || MAP_COUNT == 0) \
    reject("decode-key", "could not load a complete token map", "")

  while ((status = getline line < ledger_in) > 0) {
    if (line ~ /^#/ || line == "") continue
    fields = split(line, pieces, "\t")
    if (fields != 5 || pieces[4] == "" \
        || pieces[5] !~ /^[0-9]+$/ || pieces[5] + 0 < 1) {
      reject("event-ledger", "malformed transformation event", line)
      continue
    }
    action = pieces[1]
    kind = pieces[2]
    replacement = pieces[3]
    location = pieces[4]
    occurrences = pieces[5] + 0
    for (issued_token in MAP_RAW) {
      if (MAP_KIND[issued_token] == "vg") {
        raw_finding_id = "savevg_" MAP_RAW[issued_token]
        SUMMARY_TOTAL[issued_token] += \
          literal_count(location, raw_finding_id)
      }
    }
    if (action == "replace") {
      if (!(replacement in MAP_RAW) || MAP_KIND[replacement] != kind) {
        reject(location, "replacement event does not match decode key", replacement)
        continue
      }
      REPLACEMENT_TOTAL[replacement] += occurrences
      SUMMARY_TOTAL[replacement]++
    } else if (action == "remove") {
      if (kind == "secret" && replacement == "[redacted-secret]") \
        PLACEHOLDER_TOTAL[replacement] += occurrences
      else if (kind == "GECOS" && replacement == "[redacted]") \
        PLACEHOLDER_TOTAL[replacement] += occurrences
      else if (kind == "whole-evidence-field" \
          && replacement == "[redacted-evidence-line]") \
        PLACEHOLDER_TOTAL[replacement] += occurrences
      else if (kind == "secret-in-removed-field" \
          && replacement == "[contained-in-redacted-evidence-line]") {
        # The enclosing whole-field placeholder is reconciled below.
      } else if (kind == "GECOS-in-removed-field" \
          && replacement == "[contained-in-redacted-evidence-line]") {
        # The enclosing whole-field placeholder is reconciled below.
      } else if (kind == "generated-time-locality" \
          && replacement == "[removed-time-and-timezone]" \
          && location == "report:generated-date" && occurrences == 1) {
        # The strict output validator reconciles the retained canonical date.
      } else if (kind != "remote-resource" || replacement != "#") \
        reject(location, "unknown irreversible event type", kind)
    } else {
      reject(location, "unknown transformation action", action)
    }
    LEDGER_COUNT++
  }
  close(ledger_in)
  if (status < 0 || LEDGER_COUNT == 0) \
    reject("event-ledger", "transformation ledger is empty or unreadable", "")

  while ((status = getline line < html_in) > 0) DOCUMENT = DOCUMENT line "\n"
  close(html_in)
  if (status < 0 || DOCUMENT == "") \
    reject("review-candidate", "completed scratch HTML is unreadable", "")

  for (token in MAP_RAW) {
    raw = MAP_RAW[token]
    encoded = html_escape(raw)
    if (bounded_count(DOCUMENT, raw) > 0) \
      reject("review-candidate", "raw mapped value remains", raw)
    if (encoded != raw && bounded_count(DOCUMENT, encoded) > 0) \
      reject("review-candidate", "escaped raw mapped value remains", encoded)
    if (!(token in REPLACEMENT_TOTAL) || REPLACEMENT_TOTAL[token] < 1) {
      reject("event-ledger", "issued token has no replacement event", token)
      continue
    }
    actual = pseudotoken_count(DOCUMENT, token)
    expected = REPLACEMENT_TOTAL[token] + SUMMARY_TOTAL[token]
    if (actual != expected) \
      reject("review-candidate", \
        "issued-token occurrence count does not reconcile", \
        token ":actual=" actual ":expected=" expected)
  }

  word_count = split(DOCUMENT, words, /[^A-Za-z0-9_-]+/)
  for (word_number = 1; word_number <= word_count; word_number++) {
    word = words[word_number]
    if (token_shape(word) && !(word in MAP_RAW)) \
      reject("review-candidate", "unissued pseudotoken remains", word)
  }
  placeholders[1] = "[redacted-secret]"
  placeholders[2] = "[redacted]"
  placeholders[3] = "[redacted-evidence-line]"
  for (placeholder_number = 1; placeholder_number <= 3; placeholder_number++) {
    placeholder = placeholders[placeholder_number]
    actual = literal_count(DOCUMENT, placeholder)
    expected = PLACEHOLDER_TOTAL[placeholder] + 0
    if (actual != expected) \
      reject("review-candidate", "irreversible placeholder count does not reconcile", placeholder)
  }

  close(violation_out)
  if (FAILED) exit 1
  print "exact-residual-ledger-reconciliation\tPASS" > result_out
  close(result_out)
}
'; then
  publish_refusal "exact residual and transformation-ledger reconciliation failed"
fi
if [ "$(cat "$RECONCILE_TMP" 2>/dev/null)" \
    != "exact-residual-ledger-reconciliation	PASS" ]; then
  printf '%s\n' 'reconciliation-result	malformed residual gate result' \
    > "$VIOLATIONS_TMP"
  publish_refusal "residual gate returned no valid PASS result"
fi

inject_refusal validator
if ! LC_ALL=C awk -v token_in="$TOKEN_TMP" -v result_out="$VALIDATION_TMP" -v violation_out="$VIOLATIONS_TMP" -f "$VALIDATOR_PROGRAM" "$HTML_TMP"; then
  publish_refusal "independent output validation failed"
fi
if [ "$(cat "$VALIDATION_TMP" 2>/dev/null)" \
    != "independent-output-validation	PASS" ]; then
  printf '%s\n' 'validator-result	malformed independent validator result' \
    > "$VIOLATIONS_TMP"
  publish_refusal "independent validator returned no valid PASS result"
fi

REPORT_DATE=$(cat "$DATE_TMP")
case "$REPORT_DATE" in
  ????-??-??) ;;
  *) fail "redaction pass returned an invalid report date";;
esac

set -- $(cat "$STATS_TMP")
[ "$#" -eq 7 ] || fail "redaction pass returned an incomplete summary"
HOST_COUNT=$1
NETWORK_COUNT=$2
HARDWARE_COUNT=$3
USER_COUNT=$4
SECRET_COUNT=$5
GECOS_COUNT=$6
EVIDENCE_COUNT=$7
for COUNT in "$HOST_COUNT" "$NETWORK_COUNT" "$HARDWARE_COUNT" \
  "$USER_COUNT" "$SECRET_COUNT" "$GECOS_COUNT" "$EVIDENCE_COUNT"; do
  case "$COUNT" in
    ''|*[!0-9]*) fail "redaction pass returned invalid summary counts";;
  esac
done

TOKEN=
ATTEMPT=0
inject_hard_failure collision
while [ "$ATTEMPT" -lt 40 ] && [ -z "$TOKEN" ]; do
  CANDIDATE_TOKEN=$(output_token)
  case "$CANDIDATE_TOKEN" in
    ????????) ;;
    *) fail "could not obtain eight random hexadecimal characters from /dev/urandom";;
  esac
  case "$CANDIDATE_TOKEN" in
    *[!0-9a-f]*) fail "random token source returned non-hexadecimal data";;
  esac
  CANDIDATE_HTML=$INPUT_DIR/aixray-review-$CANDIDATE_TOKEN-$REPORT_DATE.html
  CANDIDATE_MAP=$INPUT_DIR/aixray-local-key-$CANDIDATE_TOKEN.map
  CANDIDATE_MANIFEST=$INPUT_DIR/aixray-local-removals-$CANDIDATE_TOKEN.txt
  if ! LC_ALL=C ls -ld "$CANDIDATE_HTML" >/dev/null 2>&1 \
      && ! LC_ALL=C ls -ld "$CANDIDATE_MAP" >/dev/null 2>&1 \
      && ! LC_ALL=C ls -ld "$CANDIDATE_MANIFEST" >/dev/null 2>&1; then
    TOKEN=$CANDIDATE_TOKEN
    HTML_OUT=$CANDIDATE_HTML
    MAP_OUT=$CANDIDATE_MAP
    MANIFEST_OUT=$CANDIDATE_MANIFEST
  fi
  ATTEMPT=$((ATTEMPT+1))
done
[ -n "$TOKEN" ] || fail "could not select an unused random review filename"

SOURCE_CKSUM_AFTER=$(cksum < "$INPUT_PATH") \
  || publish_refusal "could not recheck the source report checksum"
SOURCE_MODE_AFTER=$(LC_ALL=C ls -ld "$INPUT_PATH") \
  || publish_refusal "could not recheck the source report metadata"
if [ "$SOURCE_CKSUM_AFTER" != "$SOURCE_CKSUM_BEFORE" ] \
    || [ "$SOURCE_MODE_AFTER" != "$SOURCE_MODE_BEFORE" ]; then
  printf '%s\n' 'source-report	source bytes or metadata changed during processing' \
    > "$VIOLATIONS_TMP"
  publish_refusal "the source report changed during pseudonymization"
fi

inject_refusal manifest
if ! awk -v map_in="$MAP_TMP" -v ledger_in="$LEDGER_TMP" \
    -v manifest_out="$MANIFEST_TMP" -v source_name="$INPUT_NAME" \
    -v report_date="$REPORT_DATE" -v review_name="${HTML_OUT##*/}" '
function token_kind(token) {
  if (token ~ /^host-/) return "host"
  if (token ~ /^lpar-/) return "lpar"
  if (token ~ /^ip-/) return "ip"
  if (token ~ /^mac-/) return "mac"
  if (token ~ /^fqdn-/) return "fqdn"
  if (token ~ /^serial-/) return "serial"
  if (token ~ /^wwpn-/) return "wwpn"
  if (token ~ /^user-/) return "user"
  if (token ~ /^path-/) return "path"
  if (token ~ /^vg-/) return "vg"
  return ""
}
function fail_manifest(reason) {
  FAILED = 1
}
function add_total(kind, count) {
  if (kind == "host" || kind == "lpar") TOTAL["host"] += count
  else if (kind == "ip" || kind == "mac" || kind == "fqdn") \
    TOTAL["network"] += count
  else if (kind == "serial" || kind == "wwpn") \
    TOTAL["hardware"] += count
  else if (kind == "user") TOTAL["people"] += count
  else if (kind == "path" || kind == "vg") TOTAL["path"] += count
  else if (kind == "secret" || kind == "secret-in-removed-field") \
    TOTAL["secret"] += count
  else if (kind == "GECOS" || kind == "GECOS-in-removed-field") \
    TOTAL["GECOS"] += count
  else if (kind == "whole-evidence-field") \
    TOTAL["whole evidence-field"] += count
}
BEGIN {
  while ((status = getline line < map_in) > 0) {
    if (line ~ /^#/ || line == "") continue
    field_count = split(line, fields, "\t")
    if (field_count != 2 || fields[1] == "" || fields[2] == "") {
      fail_manifest("manifest: malformed decode-key row")
      continue
    }
    token = fields[1]
    if (token in RAW || token_kind(token) == "") {
      fail_manifest("manifest: duplicate or unknown decode-key token")
      continue
    }
    RAW[token] = fields[2]
    KIND[token] = token_kind(token)
    MAP_ORDER[++MAP_COUNT] = token
  }
  close(map_in)
  if (status < 0 || MAP_COUNT == 0) \
    fail_manifest("manifest: decode key is empty or unreadable")

  while ((status = getline line < ledger_in) > 0) {
    if (line ~ /^#/ || line == "") continue
    field_count = split(line, fields, "\t")
    if (field_count != 5 || fields[4] == "" \
        || fields[5] !~ /^[0-9]+$/ || fields[5] + 0 < 1) {
      fail_manifest("manifest: malformed transformation event")
      continue
    }
    action = fields[1]
    kind = fields[2]
    replacement = fields[3]
    location = fields[4]
    count = fields[5] + 0
    if (action == "replace") {
      if (!(replacement in RAW) || KIND[replacement] != kind) {
        fail_manifest("manifest: replacement event does not reconcile")
        continue
      }
      MAP_EVENT_COUNT[replacement] += count
    } else if (action == "remove") {
      if (!((kind == "secret" && replacement == "[redacted-secret]") \
          || (kind == "GECOS" && replacement == "[redacted]") \
          || (kind == "secret-in-removed-field" \
            && replacement == "[contained-in-redacted-evidence-line]") \
          || (kind == "GECOS-in-removed-field" \
            && replacement == "[contained-in-redacted-evidence-line]") \
          || (kind == "whole-evidence-field" \
            && replacement == "[redacted-evidence-line]") \
          || (kind == "generated-time-locality" \
            && replacement == "[removed-time-and-timezone]" \
            && location == "report:generated-date" && count == 1) \
          || (kind == "remote-resource" && replacement == "#"))) {
        fail_manifest("manifest: unknown irreversible event type")
        continue
      }
    } else {
      fail_manifest("manifest: unknown transformation action")
      continue
    }
    EVENT_ACTION[++EVENT_COUNT] = action
    EVENT_KIND[EVENT_COUNT] = kind
    EVENT_REPLACEMENT[EVENT_COUNT] = replacement
    EVENT_LOCATION[EVENT_COUNT] = location
    EVENT_OCCURRENCES[EVENT_COUNT] = count
    add_total(kind, count)
  }
  close(ledger_in)
  if (status < 0 || EVENT_COUNT == 0) \
    fail_manifest("manifest: event ledger is empty or unreadable")
  for (token in RAW) {
    if (!(token in MAP_EVENT_COUNT) || MAP_EVENT_COUNT[token] < 1) \
      fail_manifest("manifest: issued token has no event")
  }
  if (FAILED) exit 1

  print "DO NOT SEND THIS FILE — local decode and removal evidence" > manifest_out
  print "Overall status: REVIEW REQUIRED" > manifest_out
  print "" > manifest_out
  print "Source report: " source_name > manifest_out
  print "Report date: " report_date > manifest_out
  print "Review candidate: " review_name > manifest_out
  print "Privacy schema: 1" > manifest_out
  print "Helper version: pseudonymize-1" > manifest_out
  print "" > manifest_out
  print "Automated gates:" > manifest_out
  print "privacy-contract-preflight: PASS" > manifest_out
  print "exact-residual-ledger-reconciliation: PASS" > manifest_out
  print "independent-output-validation: PASS" > manifest_out
  print "source-immutability-check: PASS" > manifest_out
  print "" > manifest_out
  print "Item-level transformation evidence:" > manifest_out
  for (event_number = 1; event_number <= EVENT_COUNT; event_number++) {
    action = EVENT_ACTION[event_number]
    kind = EVENT_KIND[event_number]
    replacement = EVENT_REPLACEMENT[event_number]
    location = EVENT_LOCATION[event_number]
    count = EVENT_OCCURRENCES[event_number]
    if (action == "replace") {
      printf "replace\tkind=%s\ttoken=%s\toriginal=%s\tlocation=%s\tcount=%d\n", \
        kind, replacement, RAW[replacement], location, count > manifest_out
    } else {
      printf "remove\tkind=%s\tplaceholder=%s\tlocation=%s\tcount=%d", \
        kind, replacement, location, count > manifest_out
      if (kind == "secret" || kind == "secret-in-removed-field") \
        printf "\traw payload not duplicated; inspect the unchanged source record" \
          > manifest_out
      printf "\n" > manifest_out
    }
  }
  print "" > manifest_out
  print "Totals:" > manifest_out
  print "host: " TOTAL["host"] + 0 > manifest_out
  print "network: " TOTAL["network"] + 0 > manifest_out
  print "hardware: " TOTAL["hardware"] + 0 > manifest_out
  print "people: " TOTAL["people"] + 0 > manifest_out
  print "path: " TOTAL["path"] + 0 > manifest_out
  print "secret: " TOTAL["secret"] + 0 > manifest_out
  print "GECOS: " TOTAL["GECOS"] + 0 > manifest_out
  print "whole evidence-field: " TOTAL["whole evidence-field"] + 0 \
    > manifest_out
  print "" > manifest_out
  print "Verification checklist:" > manifest_out
  print "[ ] Inspect every section of the review candidate." > manifest_out
  print "[ ] Reconcile representative tokens against the local decode key." \
    > manifest_out
  print "[ ] Send neither this manifest nor the local decode key." > manifest_out
  close(manifest_out)
}
'; then
  printf '%s\n' 'manifest	generation or event reconciliation failed' \
    > "$VIOLATIONS_TMP"
  publish_refusal "local removals manifest generation failed"
fi
[ -s "$MANIFEST_TMP" ] \
  || publish_refusal "local removals manifest is empty"

inject_hard_failure chmod
chmod 0600 "$HTML_TMP" "$MAP_TMP" "$MANIFEST_TMP" \
  || fail "could not make validated review files owner-only"
owner_only_regular "$HTML_TMP" "$HTML_TMP" \
    && owner_only_regular "$MAP_TMP" "$MAP_TMP" \
    && owner_only_regular "$MANIFEST_TMP" "$MANIFEST_TMP" \
  || fail "could not verify owner-only scratch publication files"

PUBLISHED_MAP=$MAP_OUT
inject_hard_failure link-key
if ! ln "$MAP_TMP" "$MAP_OUT" 2>/dev/null; then
  fail "could not publish the owner-only local decoding map"
fi
owner_only_regular "$MAP_OUT" "$MAP_TMP" \
  || fail "could not verify the published local decoding map"
test_pause after-key-link

PUBLISHED_MANIFEST=$MANIFEST_OUT
inject_hard_failure link-manifest
if ! ln "$MANIFEST_TMP" "$MANIFEST_OUT" 2>/dev/null; then
  fail "could not publish the owner-only local removals manifest"
fi
owner_only_regular "$MANIFEST_OUT" "$MANIFEST_TMP" \
  || fail "could not verify the published local removals manifest"
test_pause after-manifest-link
test_pause publication

PUBLISHED_HTML=$HTML_OUT
inject_hard_failure link-review
if ! ln "$HTML_TMP" "$HTML_OUT" 2>/dev/null; then
  fail "could not publish the validated review HTML"
fi
test_pause after-review-link
inject_hard_failure final-permission
if ! owner_only_regular "$MAP_OUT" "$MAP_TMP" \
    || ! owner_only_regular "$MANIFEST_OUT" "$MANIFEST_TMP" \
    || ! owner_only_regular "$HTML_OUT" "$HTML_TMP"; then
  fail "could not verify the published review files"
fi

SOURCE_CKSUM_FINAL=$(cksum < "$INPUT_PATH") \
  || fail "could not perform the final source checksum check"
SOURCE_MODE_FINAL=$(LC_ALL=C ls -ld "$INPUT_PATH") \
  || fail "could not perform the final source metadata check"
if [ "$SOURCE_CKSUM_FINAL" != "$SOURCE_CKSUM_BEFORE" ] \
    || [ "$SOURCE_MODE_FINAL" != "$SOURCE_MODE_BEFORE" ]; then
  fail "source report changed before publication completed"
fi

test_pause commit-disarm
# The three links now form one verified commit. Ignore termination while the
# cleanup guard is disarmed in one shell command; otherwise a signal between
# separate assignments could strand only part of the local transaction.
trap '' 1 2 3 15
PUBLISHED_MAP= PUBLISHED_MANIFEST= PUBLISHED_HTML=

printf 'Local removals manifest (DO NOT SEND): %s\n' "$MANIFEST_OUT" >&2
printf 'Review candidate: %s\n' "$HTML_OUT" >&2
printf 'Local decode key (DO NOT SEND): %s\n' "$MAP_OUT" >&2
printf '%s\n' \
  'REVIEW REQUIRED — inspect the review candidate and local removals manifest.' \
  'Send only the review candidate after your inspection.' >&2

exit 0
