#!/bin/ksh
# AIXray outbound review-pack redactor.
# Reads one local AIXray HTML report, writes one redacted HTML copy and one
# owner-only local decoding map. It never opens a socket or performs DNS.
set -u

PATH=/usr/bin:/etc:/usr/sbin:/usr/ucb:/usr/bin/X11:/sbin:${PATH:-}
export PATH
LC_ALL=C
export LC_ALL

PROGRAM=${0##*/}
SCRATCH=
SCRATCH_MADE=

function cleanup {
  if [ -n "$SCRATCH_MADE" ] && [ -n "$SCRATCH" ]; then
    rm -f "$SCRATCH/review.awk" "$SCRATCH/review.html" \
      "$SCRATCH/review.map" "$SCRATCH/stats" "$SCRATCH/date" \
      "$SCRATCH/error" 2>/dev/null
    rmdir "$SCRATCH" 2>/dev/null
  fi
}

function fail {
  echo "$PROGRAM: $1" >&2
  exit 1
}

function usage {
  echo "usage: ./$PROGRAM aixray-<host>-<date>.html" >&2
  exit 2
}

function random_token {
  dd if=/dev/urandom bs=4 count=1 2>/dev/null \
    | od -An -tx1 2>/dev/null \
    | tr -d ' \t\r\n'
}

trap 'cleanup' 0
trap 'cleanup; trap - 0 1 2 3 15; exit 1' 1 2 3 15

[ "$#" -eq 1 ] || usage
INPUT=$1
[ -n "$INPUT" ] || usage

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

function html_unescape(text) {
  text = replace_literal(text, "&quot;", "\"")
  text = replace_literal(text, "&#39;", "'")
  text = replace_literal(text, "&lt;", "<")
  text = replace_literal(text, "&gt;", ">")
  text = replace_literal(text, "&amp;", "&")
  return text
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
  } else {
    die("internal error: unknown redaction map class")
  }

  MAP_COUNT++
  MAP_RAW[MAP_COUNT] = value
  MAP_TOKEN[MAP_COUNT] = token
  MAP_GROUP[MAP_COUNT] = group
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

function discover_after(text, label, kind,    lower, offset, relative, position, before, rest, value, lower_value) {
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

function redact_gecos(text,    lower, position, marker, start, ending, semicolon) {
  lower = tolower(text)
  marker = "gecos="
  position = index(lower, marker)
  if (position == 0) {
    marker = "gecos:"
    position = index(lower, marker)
  }
  while (position > 0) {
    start = position + length("" marker)
    while (substr(text, start, 1) ~ /[ \t]/) start++
    semicolon = index(substr(text, start), ";")
    ending = semicolon > 0 ? start + semicolon - 1 : length("" text) + 1
    text = substr(text, 1, start - 1) "[redacted]" substr(text, ending)
    GECOS_REMOVED++
    lower = tolower(text)
    position = index(substr(lower, start + length("[redacted]")), "gecos=")
    if (position > 0) position += start + length("[redacted]") - 1
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
    if (is_aix_fileset(value)) continue
    if (is_fqdn(value)) {
      if (lower == "powertruesystems.com" || lower == "openssh.com") continue
      if (lower == "flrtvc.ksh" || lower == "apar.csv") continue
      if (lower ~ /\.(rte|install|fileset)$/) continue
      if (!keep_network_like(value, text, td_class, context)) add_map(value, "fqdn")
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
  if (DISCOVERY_CAPTURE_CONTEXT) \
    DISCOVERY_ROW_CONTEXT = trim(DISCOVERY_ROW_CONTEXT " " html_unescape(text))
  discover_text(text, DISCOVERY_TD_CLASS, DISCOVERY_ROW_CONTEXT)
}

function discover_line(line,    rest, opening, closing, text, tag, lower, class_value) {
  rest = line
  while (rest != "") {
    opening = index(rest, "<")
    if (opening == 0) {
      discovery_text(rest)
      break
    }
    text = substr(rest, 1, opening - 1)
    discovery_text(text)
    rest = substr(rest, opening)
    closing = index(rest, ">")
    if (closing == 0) break
    tag = substr(rest, 1, closing)
    lower = tolower(tag)
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
    MAP_OCCURRENCES[index_number] += LAST_REPLACEMENTS
    encoded = html_escape(MAP_RAW[index_number])
    if (encoded != MAP_RAW[index_number]) {
      text = replace_bounded(text, encoded, MAP_TOKEN[index_number])
      MAP_OCCURRENCES[index_number] += LAST_REPLACEMENTS
    }
  }
  return text
}

function apply_evidence_maps(text,    order_number, index_number, encoded, replacements) {
  for (order_number = 1; order_number <= MAP_COUNT; order_number++) {
    index_number = MAP_ORDER[order_number]
    replacements = count_literal(text, MAP_RAW[index_number])
    if (replacements > 0) {
      text = replace_literal(text, MAP_RAW[index_number], MAP_TOKEN[index_number])
      MAP_OCCURRENCES[index_number] += replacements
    }
    encoded = html_escape(MAP_RAW[index_number])
    if (encoded != MAP_RAW[index_number]) {
      replacements = count_literal(text, encoded)
      if (replacements > 0) {
        text = replace_literal(text, encoded, MAP_TOKEN[index_number])
        MAP_OCCURRENCES[index_number] += replacements
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
    || value ~ /^(lpar|ip|mac|fqdn|serial|wwpn|user|path)-[0-9]+$/
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

function transform_text(text, evidence) {
  if (evidence) text = apply_evidence_maps(text)
  else text = apply_maps(text, 0)
  text = redact_secrets(text)
  text = redact_gecos(text)
  if (evidence && (high_entropy(text) || !evidence_is_safe(text))) {
    EVIDENCE_REMOVED++
    return "[redacted-evidence-line]"
  }
  return text
}

function transform_visible_text(text,    transformed) {
  if (TRANSFORM_CAPTURE_CONTEXT) \
    TRANSFORM_ROW_CONTEXT = trim(TRANSFORM_ROW_CONTEXT " " html_unescape(text))
  if (TRANSFORM_STYLE) return apply_maps(text, 1)
  return transform_text(text, TRANSFORM_EVIDENCE)
}

function transform_line(line,    out, rest, opening, closing, text, tag, lower, class_value, evidence, notice, position) {
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
    if (TRANSFORM_STYLE || lower ~ /^<style([ >])/) out = out apply_maps(tag, 1)
    else out = out apply_maps(tag, 0)

    if (lower ~ /^<style([ >])/) TRANSFORM_STYLE = 1
    else if (lower ~ /^<\/style/) TRANSFORM_STYLE = 0
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
      TRANSFORM_CAPTURE_CONTEXT = class_has(class_value, "ctl")
      evidence = is_evidence_cell(class_value, TRANSFORM_ROW_CONTEXT)
      TRANSFORM_EVIDENCE = evidence
    } else if (!TRANSFORM_STYLE && lower ~ /^<\/td/) {
      TRANSFORM_TD_CLASS = ""
      TRANSFORM_EVIDENCE = 0
      TRANSFORM_CAPTURE_CONTEXT = 0
    } else if (!TRANSFORM_STYLE && lower ~ /^<\/tr/) {
      TRANSFORM_ROW_CONTEXT = ""
      TRANSFORM_CAPTURE_CONTEXT = 0
    }
    rest = substr(rest, closing + 1)
  }

  if (!NOTICE_INSERTED && (position = index(out, "<body>")) > 0) {
    notice = "<div class=\"aixray-redaction-notice\" role=\"note\" style=\"padding:12px 32px;border-bottom:2px solid #C2703D;font-family:monospace\"><b>Redacted review copy:</b> identifiers were pseudonymized at the customer's request; the engineer's reply will use these redacted tokens.</div>"
    out = substr(out, 1, position + length("<body>") - 1) "\n" notice substr(out, position + length("<body>"))
    NOTICE_INSERTED = 1
  }
  return out
}

function is_known_keep_word(value, text, td_class, context,    lower, lower_context) {
  lower = tolower(value)
  lower_context = tolower(context)
  if (is_pseudotoken(value) || is_aix_fileset(value)) return 1
  if (lower == "flrtvc.ksh" || lower == "apar.csv") return 1
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

function independent_identifier_check(text, td_class, context, evidence,    safe, fields, count, part, value, lower, domain, base, slash, suffix, plain) {
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
    if (is_aix_fileset(value) || lower == "flrtvc.ksh" \
        || lower == "apar.csv" || lower ~ /[.](rte|install|fileset)$/) continue
    if (is_fqdn(value)) {
      if (lower == "powertruesystems.com" || lower == "openssh.com") continue
      if (!keep_network_like(value, safe, td_class, context)) \
        die("redaction validation failed: an unresolved FQDN remains")
      continue
    }
    if (value ~ /^[A-Za-z][A-Za-z0-9_-]*$/ && value ~ /[0-9]/ \
        && !is_known_keep_word(value, safe, td_class, context)) \
      die("redaction validation failed: an unresolved identifier-shaped token remains")
  }
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
    if (closing == 0) break
    tag = substr(rest, 1, closing)
    lower = tolower(tag)
    validate_segment(tag, VALIDATE_STYLE || lower ~ /^<style([ >])/, "", "", 0)
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
  version_marker = "<meta name=\"aixray-report-version\" content=\"1\">"
  if (count_literal(ALL_DOCUMENT, version_marker) != 1) \
    die("expected AIXray report version marker exactly once; refusing unrecognized input")
  if (count_literal(ALL_DOCUMENT, "<body>") != 1 \
      || count_literal(ALL_DOCUMENT, "</html>") != 1) \
    die("expected one complete AIXray HTML envelope; refusing malformed input")

  report_date = extract_meta(ALL_DOCUMENT, "aixray-report-date")
  if (report_date !~ /^[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]$/) \
    die("expected one valid AIXray report date marker")
  month = substr(report_date, 6, 2) + 0
  day = substr(report_date, 9, 2) + 0
  if (month < 1 || month > 12 || day < 1 || day > 31) \
    die("AIXray report date marker is outside the calendar range")

  report_host_encoded = extract_meta(ALL_DOCUMENT, "aixray-report-host")
  report_host = html_unescape(report_host_encoded)
  if (!valid_name(report_host)) die("expected one valid AIXray report host marker")
  reject_source_pseudotoken_shapes(ALL_DOCUMENT)
  add_map(report_host, "host")

  DISCOVERY_STYLE = 0
  DISCOVERY_TD_CLASS = ""
  DISCOVERY_ROW_CONTEXT = ""
  DISCOVERY_CAPTURE_CONTEXT = 0
  DISCOVERY_DIV_DEPTH = 0
  DISCOVERY_EVIDENCE_DIV_DEPTH = 0
  for (line_number = 1; line_number <= NR; line_number++) {
    discover_line(DOCUMENT[line_number])
  }

  SECRET_REMOVED = 0
  GECOS_REMOVED = 0
  sort_maps()

  print "# DO NOT SEND THIS FILE — it is your local decoding key" > map_out
  print "# token\treal value" > map_out
  for (index_number = 1; index_number <= MAP_COUNT; index_number++) \
    print MAP_TOKEN[index_number] "\t" MAP_RAW[index_number] > map_out
  close(map_out)

  TRANSFORM_STYLE = 0
  TRANSFORM_TD_CLASS = ""
  TRANSFORM_EVIDENCE = 0
  TRANSFORM_ROW_CONTEXT = ""
  TRANSFORM_CAPTURE_CONTEXT = 0
  TRANSFORM_DIV_DEPTH = 0
  TRANSFORM_EVIDENCE_DIV_DEPTH = 0
  VALIDATE_STYLE = 0
  VALIDATE_TD_CLASS = ""
  VALIDATE_EVIDENCE = 0
  VALIDATE_ROW_CONTEXT = ""
  VALIDATE_CAPTURE_CONTEXT = 0
  VALIDATE_DIV_DEPTH = 0
  VALIDATE_EVIDENCE_DIV_DEPTH = 0
  NOTICE_INSERTED = 0
  for (line_number = 1; line_number <= NR; line_number++) {
    transformed = transform_line(DOCUMENT[line_number])
    validate_line(transformed)
    print transformed > html_out
  }
  close(html_out)
  if (!NOTICE_INSERTED) die("redaction validation failed: output notice was not inserted")

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

if ! awk -v html_out="$HTML_TMP" -v map_out="$MAP_TMP" \
    -v stats_out="$STATS_TMP" -v date_out="$DATE_TMP" \
    -v error_out="$ERROR_TMP" -f "$AWK_PROGRAM" "$INPUT_PATH"; then
  if [ -s "$ERROR_TMP" ]; then
    REASON=$(cat "$ERROR_TMP")
    fail "$REASON"
  fi
  fail "redaction pass failed; no review file was written"
fi

[ -s "$HTML_TMP" ] && [ -s "$MAP_TMP" ] \
  && [ -s "$STATS_TMP" ] && [ -s "$DATE_TMP" ] \
  || fail "redaction pass did not produce every validated scratch result"

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
while [ "$ATTEMPT" -lt 40 ] && [ -z "$TOKEN" ]; do
  CANDIDATE_TOKEN=$(random_token)
  case "$CANDIDATE_TOKEN" in
    ????????) ;;
    *) fail "could not obtain eight random hexadecimal characters from /dev/urandom";;
  esac
  case "$CANDIDATE_TOKEN" in
    *[!0-9a-f]*) fail "random token source returned non-hexadecimal data";;
  esac
  CANDIDATE_HTML=$INPUT_DIR/aixray-review-$CANDIDATE_TOKEN-$REPORT_DATE.html
  CANDIDATE_MAP=$INPUT_DIR/aixray-local-key-$CANDIDATE_TOKEN.map
  if ! LC_ALL=C ls -ld "$CANDIDATE_HTML" >/dev/null 2>&1 \
      && ! LC_ALL=C ls -ld "$CANDIDATE_MAP" >/dev/null 2>&1; then
    TOKEN=$CANDIDATE_TOKEN
    HTML_OUT=$CANDIDATE_HTML
    MAP_OUT=$CANDIDATE_MAP
  fi
  ATTEMPT=$((ATTEMPT+1))
done
[ -n "$TOKEN" ] || fail "could not select an unused random review filename"

chmod 0600 "$HTML_TMP" "$MAP_TMP" \
  || fail "could not make validated review files owner-only"
if ! ln "$MAP_TMP" "$MAP_OUT" 2>/dev/null; then
  fail "could not publish the owner-only local decoding map"
fi
if ! ln "$HTML_TMP" "$HTML_OUT" 2>/dev/null; then
  rm -f "$MAP_OUT" 2>/dev/null
  fail "could not publish the validated review HTML; the decoding map was removed"
fi
if ! chmod 0600 "$MAP_OUT" "$HTML_OUT" \
    || [ ! -f "$MAP_OUT" ] || [ -L "$MAP_OUT" ] \
    || [ ! -f "$HTML_OUT" ] || [ -L "$HTML_OUT" ]; then
  rm -f "$HTML_OUT" "$MAP_OUT" 2>/dev/null
  fail "could not verify the published review files; both were removed"
fi

printf 'Hostnames redacted: %s occurrence(s) → host-A/lpar-1 tokens\n' "$HOST_COUNT" >&2
printf 'Network identifiers redacted: %s occurrence(s) → ip-1/mac-1/fqdn-1 tokens\n' "$NETWORK_COUNT" >&2
printf 'Hardware identifiers redacted: %s occurrence(s) → serial-1/wwpn-1 tokens\n' "$HARDWARE_COUNT" >&2
printf 'User identifiers redacted: %s occurrence(s); GECOS fields dropped: %s; secrets removed: %s; evidence lines removed: %s\n' \
  "$USER_COUNT" "$GECOS_COUNT" "$SECRET_COUNT" "$EVIDENCE_COUNT" >&2
printf 'Review file: %s — review the file in your browser before sending to review@powertruesystems.com\n' \
  "$HTML_OUT" >&2

exit 0
