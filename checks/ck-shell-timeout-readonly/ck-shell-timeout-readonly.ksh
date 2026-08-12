#!/bin/ksh
# Generated standalone AIXray check support. READ-ONLY: captures only; no
# remediation, service control, network access, or durable target-host writes.
set -u

# Match the monolith's guarded AIX command search path and parsing locale.
PATH=/usr/bin:/etc:/usr/sbin:/usr/ucb:/usr/bin/X11:/sbin:/usr/ios/cli:${PATH:-}
export PATH
LC_ALL=C
export LC_ALL

AIXRAY_STANDALONE_VERSION="1.1.0"

# aix <key> <command> [args...] — fixture-aware, read-only capture boundary.
function aix {
  typeset key rc
  key=$1
  shift
  if [ -n "${AIXRAY_FIXTURES:-}" ]; then
    if [ -r "$AIXRAY_FIXTURES/$key.out" ]; then
      cat "$AIXRAY_FIXTURES/$key.out"
      rc=0
      [ -r "$AIXRAY_FIXTURES/$key.rc" ] && read rc < "$AIXRAY_FIXTURES/$key.rc"
      return $rc
    fi
    return 127
  fi
  "$@" 2>/dev/null
}

# aixv preserves stderr as evidence, for read-only commands that write their
# version banner or diagnostics there rather than to stdout. (Deliberately no
# example command name here: this comment is copied into all 324 standalone
# tools, and tools/ci/egress-lint.sh reads a banned network command name in a
# comment as a violation just as it would in a command position.)
function aixv {
  typeset key rc
  key=$1
  shift
  if [ -n "${AIXRAY_FIXTURES:-}" ]; then
    if [ -r "$AIXRAY_FIXTURES/$key.out" ] || [ -r "$AIXRAY_FIXTURES/$key.err" ]; then
      [ -r "$AIXRAY_FIXTURES/$key.out" ] && cat "$AIXRAY_FIXTURES/$key.out"
      [ -r "$AIXRAY_FIXTURES/$key.err" ] && cat "$AIXRAY_FIXTURES/$key.err"
      rc=0
      [ -r "$AIXRAY_FIXTURES/$key.rc" ] && read rc < "$AIXRAY_FIXTURES/$key.rc"
      return $rc
    fi
    return 127
  fi
  "$@" 2>&1
}

# aix_capture_missing <key> — fixture-replay helper: true (rc=0) iff no capture
# exists for <key> at all, i.e. the rc a probe just received was the "no
# capture" default and not a genuine command status. aix()/aixv() return 127 for
# BOTH a missing capture and a genuinely absent command, so a module that wants
# to claim "the command is not installed" must first rule out "nobody captured
# it". Live mode returns false (rc=1): a real box has no concept of a missing
# fixture, and rc=127 there genuinely means the command was not found. Must be
# called in the PARENT shell after the probe, not inside the $(aix ...)
# substitution. Byte-for-byte the monolith's semantics (src/aixray-aix.sh.in);
# without it here, an undefined-command rc of 127 makes the guard read false and
# the caller launders a missing capture into NOT_APPLICABLE.
function aix_capture_missing {
  if [ -n "${AIXRAY_FIXTURES:-}" ]; then
    if [ -r "$AIXRAY_FIXTURES/$1.out" ] || [ -r "$AIXRAY_FIXTURES/$1.err" ]; then
      return 1
    fi
    return 0
  fi
  return 1
}

function jesc {
  awk 'BEGIN{ORS=""} {
    gsub(/\\/,"\\\\"); gsub(/"/,"\\\""); gsub(/\t/,"\\t"); gsub(/\r/,"\\r")
    gsub(/[\001-\010\013\014\016-\037]/,"")
    if (NR>1) printf "\\n"
    print
  }'
}

function valid_json_number {
  printf '%s\n' "$1" | awk '
    NR==1 && $0 ~ /^-?(0|[1-9][0-9]*)([.][0-9]+)?([eE][+-]?[0-9]+)?$/ {ok=1}
    END{exit ok?0:1}'
}

# The standalone finding accumulator intentionally carries only fields in the
# section-1.2 envelope. A failure here is internal (exit 1), never a partial
# JSON document.
set -A F_CAT
set -A F_ID
set -A F_ST
set -A F_SEV
set -A F_OBS
set -A F_MEAN
set -A F_FIX
NFIND=0

function add {
  case "$1" in
    lifecycle|patch|storage|performance|errors|resilience|security|config|monitoring) ;;
    *) echo "$AIXRAY_TOOL: internal error: unknown category '$1'" >&2; exit 1;;
  esac
  case "$4" in
    # NOT_APPLICABLE is a verdict, not a refusal: the control constrains a
    # property of a thing that need not exist. It is already a first-class
    # status in the monolith (vios_level on a plain AIX LPAR) and in the
    # contract schema (STATUSES, pipeline/contract_v2/schema.py), but was
    # missing here, so any standalone tool reaching that branch aborted with
    # an internal error instead of emitting its envelope.
    PASS|WARN|FAIL|NOT_ASSESSED|NOT_APPLICABLE) ;;
    *) echo "$AIXRAY_TOOL: internal error: unknown status '$4'" >&2; exit 1;;
  esac
  F_CAT[$NFIND]=$1
  F_ID[$NFIND]=$2
  F_ST[$NFIND]=$4
  F_SEV[$NFIND]=$5
  F_OBS[$NFIND]=$6
  F_MEAN[$NFIND]=$7
  F_FIX[$NFIND]=$8
  NFIND=$((NFIND + 1))
}

MYUID=""
TODAY=""
TODAY_J=0
C7=""
C30=""
NOW=""

# Date math is pure integer arithmetic because AIX does not provide GNU date.
# Validate the full calendar date before any of its fields can reach an
# arithmetic context: ksh recursively evaluates arithmetic expressions stored
# in variables, and the Julian formula also normalizes impossible dates.
function is_leap_year {
  typeset y=$1
  y=${y#0}; y=${y#0}; y=${y#0}
  if [ $((y % 400)) -eq 0 ]; then echo 1
  elif [ $((y % 100)) -eq 0 ]; then echo 0
  elif [ $((y % 4)) -eq 0 ]; then echo 1
  else echo 0; fi
}

function valid_ymd {
  typeset ymd=$1 y m d rest dim
  case "$ymd" in
    [0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]) ;;
    *) echo 0; return;;
  esac
  y=${ymd%%-*}; rest=${ymd#*-}; m=${rest%%-*}; d=${rest#*-}
  m=${m#0}; d=${d#0}
  [ -z "$m" ] && m=0; [ -z "$d" ] && d=0
  if [ "$m" -lt 1 ] || [ "$m" -gt 12 ]; then echo 0; return; fi
  case "$m" in
    1|3|5|7|8|10|12) dim=31;;
    4|6|9|11) dim=30;;
    2) if [ "$(is_leap_year "$y")" -eq 1 ]; then dim=29; else dim=28; fi;;
    *) echo 0; return;;
  esac
  if [ "$d" -lt 1 ] || [ "$d" -gt "$dim" ]; then echo 0; else echo 1; fi
}

function d2j {
  typeset ymd y m d a
  ymd=$1
  if [ "$(valid_ymd "$ymd")" != 1 ]; then
    echo "${AIXRAY_TOOL:-standalone}: internal error: d2j requires a real calendar date in YYYY-MM-DD format" >&2
    return 1
  fi
  y=${ymd%%-*}
  m=${ymd#*-}; m=${m%%-*}
  d=${ymd##*-}
  m=${m#0}; d=${d#0}
  a=$(( (14 - m) / 12 ))
  y=$(( y + 4800 - a ))
  m=$(( m + 12*a - 3 ))
  echo $(( d + (153*m + 2)/5 + 365*y + y/4 - y/100 + y/400 - 32045 ))
}

function j2d {
  typeset a b c d e m
  a=$(( $1 + 32044 ))
  b=$(( (4*a + 3) / 146097 ))
  c=$(( a - 146097*b/4 ))
  d=$(( (4*c + 3) / 1461 ))
  e=$(( c - 1461*d/4 ))
  m=$(( (5*e + 2) / 153 ))
  echo "$(( 100*b + d - 4800 + m/10 )) $(( m + 3 - 12*(m/10) )) $(( e - (153*m + 2)/5 + 1 ))"
}

function errpt_cutoff {
  j2d $(( TODAY_J - $1 )) | awk '{printf "%02d%02d0000%02d", $2, $3, $1 % 100}'
}

function nr_warn {
  typeset nr_status nr_severity
  nr_status=${7:-WARN}
  nr_severity=${8:-med}
  if [ "${MYUID:-1}" != "0" ]; then
    add "$1" "$2" "$3" "$nr_status" "$nr_severity" "n/a" "Could not read $4 (needs root)." \
      "re-run $AIXRAY_TOOL as root, or inspect '$5' manually."
  else
    add "$1" "$2" "$3" "$nr_status" "$nr_severity" "n/a" "Could not read $4 (unexpected as root)." \
      "inspect '$5' manually."
  fi
}

# Constants and accumulator values read by the already-extracted literal cuts.
STOR_PP_PER_PV_HI=3048
STOR_HUGE_PP_MB=512
STOR_SMALL_VG_PPS=64
STOR_SLACK_PCT=10
STOR_SLACK_MB=512
STOR_FACT_MAX_FS_MB=4294967296
STOR_FACT_MAX_USED_PCT=101
ERR_CRIT_RECUR=3
ERRDEMON_LOG_MIN=1048576

CRIT_ERRIDS="
SC_DISK_ERR1|disk operation error (adapter or drive) — investigate the drive and its path
SC_DISK_ERR2|permanent disk hardware error (drive or SAN path) — PERM means replace or repair
SC_DISK_ERR3|disk command/adapter error — I/O to the drive is failing
SC_DISK_ERR4|disk media / bad-block error — sectors going bad; recurring means replace the disk
DISK_ERR1|disk heavily worn — plan a replacement
DISK_ERR2|disk error (often loss of electrical power) — investigate
DISK_ERR3|disk error (often loss of electrical power) — investigate
DISK_ERR4|bad blocks on disk — more than one in a week means replace the disk
SCSI_ERR1|SCSI adapter hardware error
SCSI_ERR10|SCSI adapter/bus error — cabling, termination, or the adapter itself
SCSI_ARRAY_ERR6|RAID array error — a member disk or the array itself degraded
SCSI_ARRAY_ERR7|RAID array error — a member disk or the array itself degraded
FCS_ERR10|Fibre Channel adapter error — SAN link or path degrading
LVM_SA_QUORCLOSE|volume group lost quorum and was forced offline — an LVM disk dropped
LVM_SA_STALEPP|a mirror copy went stale — the mirror is out of sync
LVM_SA_PVMISS|a physical volume in a volume group went missing
LVM_IO_FAIL|LVM detected an I/O failure to a disk
EPOW_SUS|environmental/power event (EPOW) — power, thermal, or fan; call IBM service
EPOW_RES_CHRP|environmental/power event on the platform — check power and cooling
SCAN_ERROR_CHRP|processor/memory scan error (often correctable ECC over threshold) — a DIMM or CPU is degrading
FIRMWARE_EVENT|platform firmware logged a service event — check the service processor
DMPCHK_SMALL|the configured dump device is too small for a full dump — a panic will truncate it
FWDMP_IFAIL|firmware-assisted dump initialization failed — a panic may not capture a usable dump
"

FACT_PAGING_SPACES=""
FACT_PAGING_MAX=""
FACT_PAGING_ROOT=""
FACT_PAGING_DUP=""
FACT_PAGING_READ=0
FACT_STORAGE_FS_ROWS=""
FACT_STORAGE_WORST_FS_PCT=""
FACT_STORAGE_WORST_FS_MOUNT=""
FACT_STORAGE_WORST_VG_PCT=""
FACT_STORAGE_WORST_VG=""
FACT_STORAGE_MAX_INODE=""
FACT_STORAGE_FS_USED_UNREAD=0
FACT_STORAGE_FS_IUSED_UNREAD=0
FACT_STORAGE_DF_READ=0
FACT_STORAGE_VG_READ=0

function standalone_initialize {
  typeset today_overridden
  today_overridden=0
  if [ "${AIXRAY_TODAY+x}" = x ]; then
    TODAY=$AIXRAY_TODAY
    today_overridden=1
  else
    TODAY=$(date +%Y-%m-%d)
  fi
  if [ "$(valid_ymd "$TODAY")" != 1 ]; then
    if [ "$today_overridden" -eq 1 ]; then
      echo "$AIXRAY_TOOL: AIXRAY_TODAY must be a real calendar date in YYYY-MM-DD format" >&2
    else
      echo "$AIXRAY_TOOL: system date must be a real calendar date in YYYY-MM-DD format" >&2
    fi
    return 2
  fi
  TODAY_J=$(d2j "$TODAY") || return 1
  C7=$(errpt_cutoff 7) || return 1
  C30=$(errpt_cutoff 30) || return 1
  MYUID=$(aix id_u id -u)
  [ -n "$MYUID" ] || MYUID=1
  if [ "$today_overridden" -eq 1 ]; then
    NOW=$TODAY
  else
    NOW=$(date '+%Y-%m-%d %H:%M %Z')
  fi
}

function standalone_emit {
  typeset i sep
  printf '{\n'
  printf '  "generated": "%s",\n' "$(printf '%s' "$NOW" | jesc)"
  printf '  "version": "%s",\n' "$AIXRAY_STANDALONE_VERSION"
  printf '  "tool": "%s",\n' "$AIXRAY_TOOL"
  printf '  "findings": ['
  if [ "$NFIND" -gt 0 ]; then
    printf '\n'
  fi
  i=0
  while [ "$i" -lt "$NFIND" ]; do
    sep=','
    [ "$i" -eq $((NFIND - 1)) ] && sep=''
    printf '    { "id": "%s", "category": "%s", "status": "%s", "severity": "%s", "observed": "%s", "meaning": "%s", "fix": "%s" }%s\n' \
      "$(printf '%s' "${F_ID[$i]}" | jesc)" \
      "$(printf '%s' "${F_CAT[$i]}" | jesc)" \
      "${F_ST[$i]}" \
      "$(printf '%s' "${F_SEV[$i]}" | jesc)" \
      "$(printf '%s' "${F_OBS[$i]}" | jesc)" \
      "$(printf '%s' "${F_MEAN[$i]}" | jesc)" \
      "$(printf '%s' "${F_FIX[$i]}" | jesc)" \
      "$sep"
    i=$((i + 1))
  done
  printf '  ]\n}\n'
}

function standalone_main {
  typeset i assessed initialize_rc run_rc
  if [ "$#" -ne 1 ] || [ "$1" != "--json" ]; then
    echo "usage: $0 --json" >&2
    return 2
  fi
  if [ -z "${AIXRAY_FIXTURES:-}" ] && [ "$(uname -s 2>/dev/null)" != "AIX" ]; then
    echo "$AIXRAY_TOOL: this standalone check runs on AIX/VIOS" >&2
    return 2
  fi
  standalone_initialize
  initialize_rc=$?
  [ "$initialize_rc" -eq 0 ] || return "$initialize_rc"
  standalone_run
  run_rc=$?
  [ "$run_rc" -eq 0 ] || return 1
  standalone_emit || return 1
  assessed=0
  i=0
  while [ "$i" -lt "$NFIND" ]; do
    [ "${F_ST[$i]}" != "NOT_ASSESSED" ] && assessed=1
    i=$((i + 1))
  done
  [ "$assessed" -eq 1 ] && return 0
  return 3
}

AIXRAY_TOOL=ck-shell-timeout-readonly


function standalone_check {
_AIXRAY_SESSION_KEYS=""

  # shell_timeout_readonly — verify TMOUT/TIMEOUT are bounded and readonly.
  # The probe reads /etc/profile (the file the CIS standard's Remediation
  # section names) and keeps every line matching TMOUT or TIMEOUT.  It reads
  # the file, not the scanner's own shell: the scanner runs as a
  # non-interactive, non-login ksh that never sources /etc/profile, so the
  # readonly attribute configured there is simply absent from the scanner's
  # shell.  On a compliant system /etc/profile carries bounded numeric
  # assignments for both variables and a readonly declaration that covers
  # both and appears after the assignments, per the standard text.
  typeset STR_RAW STR_RC STR_PARSED STR_STATE STR_REST
  typeset STR_TMO_CLS STR_TMO_VAL STR_TO_CLS STR_TO_VAL STR_MISSING STR_TMP STR_BAD
  STR_RAW=$(aix shell_timeout_readonly grep -E 'TMOUT|TIMEOUT' /etc/profile); STR_RC=$?
  if [ "$STR_RC" -ge 2 ]; then
    add security shell_timeout_readonly "Interactive shell inactivity timeout" \
        NOT_ASSESSED low \
        "not assessed — /etc/profile TMOUT/TIMEOUT capture failed (rc=$STR_RC)" \
        "Could not read TMOUT/TIMEOUT evidence from /etc/profile, so idle-shell readonly-timeout enforcement is unknown." \
        "restore read access to /etc/profile, then rerun AIXray." "cis-l2"
  elif [ "$STR_RC" -eq 1 ]; then
    add security shell_timeout_readonly "Interactive shell inactivity timeout" FAIL high \
        "no TMOUT, TIMEOUT, or readonly declaration in /etc/profile (grep rc=1)" \
        "No idle-shell timeout is enforced; interactive shell sessions can remain open indefinitely." \
        "set TMOUT=900, TIMEOUT=900, and readonly TMOUT TIMEOUT in /etc/profile, then rerun AIXray." "cis-l2"
  else
    # Parse assignments and readonly declarations.  Comments are stripped;
    # inline trailing shell comments are removed from values.  Assignment
    # ordering matters: the standard requires the readonly statement to be
    # the last statement among these lines, so an assignment that appears
    # after a readonly declaration is an ordering violation.  A readonly or
    # typeset -r declaration may carry its own assignments (for example
    # "readonly TMOUT=900"), which are parsed and also mark the variable
    # readonly.  A line that does not name TMOUT or TIMEOUT as the exact
    # variable being set or declared is neighbour noise (for example
    # LOGIN_TIMEOUT=60) and never voids determinate evidence.
    STR_PARSED=$(printf '%s\n' "$STR_RAW" | awk '
      function trim(s) {
        sub(/^[ \t]+/, "", s)
        sub(/[ \t]+$/, "", s)
        return s
      }
      function strip_quotes(v,   q) {
        q = sprintf("%c", 39)
        if (v ~ /^"[^"]*"$/) v = substr(v, 2, length("" v) - 2)
        else if (length("" v) >= 2 && substr(v, 1, 1) == q && substr(v, length("" v), 1) == q) v = substr(v, 2, length("" v) - 2)
        return v
      }
      function classify(val,   canon) {
        val = strip_quotes(val)
        if (val == "") return "empty"
        if (val !~ /^[0-9]+$/) return "nonnum"
        canon = val
        sub(/^0+/, "", canon)
        if (canon == "") return "zero"
        if (length("" canon) > 3) return "over"
        if (canon + 0 > 900) return "over"
        return "ok"
      }
      function record_assign(name, raw,   sep, suffix) {
        sep = index(raw, ";")
        if (sep > 0) {
          suffix = substr(raw, sep + 1)
          suffix = trim(suffix)
          raw = substr(raw, 1, sep - 1)
          raw = trim(raw)
          gsub(/[ \t]+/, " ", suffix)
          if (suffix != "" && suffix != "export " name) { malformed = 1; return }
        }
        raw = trim(raw)
        raw = strip_quotes(raw)
        raw = trim(raw)
        if (name == "TMOUT") {
          if (tmo_seen && tmo_val != raw) { tmo_conflict = 1 }
          tmo_seen = 1; tmo_val = raw; tmo_cls = classify(raw)
        } else if (name == "TIMEOUT") {
          if (tmoout_seen && tmoout_val != raw) { tmoout_conflict = 1 }
          tmoout_seen = 1; tmoout_val = raw; tmoout_cls = classify(raw)
        }
      }
      function parse_ro_operand(tok,   nm, vv, hit) {
        hit = 0
        if (tok ~ /^(TMOUT|TIMEOUT)[ \t]*=/) {
          nm = tok
          sub(/[=].*/, "", nm)
          sub(/[ \t]+$/, "", nm)
          vv = tok
          sub(/^[^=]*=/, "", vv)
          if (nm == "TMOUT") { tmo_readonly = 1; hit = 1 }
          else if (nm == "TIMEOUT") { tmoout_readonly = 1; hit = 1 }
          record_assign(nm, vv)
        } else {
          # Bare operand: tolerate a trailing statement terminator ("TMOUT;"
          # on "readonly TMOUT;").  Assignments keep their semicolons for
          # record_assign, which owns the separator handling.
          sub(/;+$/, "", tok)
          if (tok == "TMOUT") { tmo_readonly = 1; hit = 1 }
          else if (tok == "TIMEOUT") { tmoout_readonly = 1; hit = 1 }
        }
        return hit
      }
      {
        line = $0
        sub(/^[ \t]+/, "", line)
        if (line ~ /^#/) next
        sub(/[ \t]+#.*/, "", line)
        line = trim(line)
        if (line == "") next

        # readonly declaration — names and/or assigns one or both variables.
        if (line ~ /^readonly[ \t]/) {
          work = line
          sub(/^readonly[ \t]+/, "", work)
          n = split(work, tok, /[ \t]+/)
          for (i = 1; i <= n; i++) {
            if (tok[i] == "") continue
            if (parse_ro_operand(tok[i])) readonly_seen = 1
          }
          next
        }

        # typeset with a -r flag is the ksh88 spelling of readonly.
        if (line ~ /^typeset[ \t]+-/) {
          work = line
          sub(/^typeset[ \t]+/, "", work)
          flags = work
          sub(/[ \t].*/, "", flags)
          if (substr(flags, 1, 1) == "-" && flags ~ /r/) {
            rest = work
            sub(/^[^ \t]+[ \t]+/, "", rest)
            n = split(rest, tok, /[ \t]+/)
            for (i = 1; i <= n; i++) {
              if (tok[i] == "") continue
              if (parse_ro_operand(tok[i])) readonly_seen = 1
            }
          } else if (line ~ /(^|[^A-Za-z0-9_])(TMOUT|TIMEOUT)([^A-Za-z0-9_]|$)/) {
            malformed = 1
          }
          next
        }

        # Bare export of TMOUT and/or TIMEOUT — declares the export, assigns no value.
        if (line ~ /^export[ \t]+/) {
          work = line
          sub(/^export[ \t]+/, "", work)
          n = split(work, tok, /[ \t]+/)
          all_ok = 1
          for (i = 1; i <= n; i++) {
            if (tok[i] == "") continue
            if (tok[i] != "TMOUT" && tok[i] != "TIMEOUT") { all_ok = 0; break }
          }
          if (all_ok) next
        }

        # Assignment: optional export prefix, variable name, equal sign, value.
        # The bracket class in the sub regex defeats the AIX awk /= lexer trap.
        if (line ~ /^(export[ \t]+)?(TMOUT|TIMEOUT)[ \t]*=/) {
          if (readonly_seen) order_bad = 1
          name = line
          sub(/[=].*/, "", name)
          sub(/^export[ \t]+/, "", name)
          name = trim(name)
          val = line
          sub(/^[^=]*=/, "", val)
          record_assign(name, val)
          next
        }

        # Unrecognised line.  If it names TMOUT or TIMEOUT as the exact variable
        # being set or declared, the evidence is malformed (refusal).  Otherwise
        # it is neighbour noise (for example LOGIN_TIMEOUT=60) and must not void
        # determinate TMOUT/TIMEOUT evidence.
        if (line ~ /(^|[^A-Za-z0-9_])(TMOUT|TIMEOUT)([^A-Za-z0-9_]|$)/) malformed = 1
      }
      END {
        if (malformed) print "malformed|"
        else if (tmo_conflict || tmoout_conflict) print "value_conflict|"
        else if (!tmo_seen && !tmoout_seen) print "absent|"
        else if (tmo_seen && !tmoout_seen) print "missing|TIMEOUT"
        else if (!tmo_seen && tmoout_seen) print "missing|TMOUT"
        else if (!readonly_seen) print "no_readonly|" tmo_cls "|" tmo_val "|" tmoout_cls "|" tmoout_val
        else if (tmo_readonly && !tmoout_readonly) print "partial_readonly|TIMEOUT|" tmo_cls "|" tmo_val "|" tmoout_cls "|" tmoout_val
        else if (!tmo_readonly && tmoout_readonly) print "partial_readonly|TMOUT|" tmo_cls "|" tmo_val "|" tmoout_cls "|" tmoout_val
        else if (order_bad) print "order|" tmo_cls "|" tmo_val "|" tmoout_cls "|" tmoout_val
        else print "both|" tmo_cls "|" tmo_val "|" tmoout_cls "|" tmoout_val
      }
    ')
    STR_STATE=${STR_PARSED%%\|*}
    STR_REST=${STR_PARSED#*\|}
    case "$STR_STATE" in
      malformed)
        add security shell_timeout_readonly "Interactive shell inactivity timeout" \
            NOT_ASSESSED low \
            "not assessed — /etc/profile TMOUT/TIMEOUT lines are not parseable" \
            "AIXray found lines matching TMOUT/TIMEOUT in /etc/profile but none parse as an assignment or readonly declaration, so timeout enforcement cannot be established." \
            "inspect TMOUT/TIMEOUT lines in /etc/profile, correct malformed entries, and rerun AIXray." "cis-l2"
        ;;
      value_conflict)
        add security shell_timeout_readonly "Interactive shell inactivity timeout" \
            NOT_ASSESSED low \
            "not assessed — conflicting assignments for the same variable in /etc/profile" \
            "AIXray observed different values assigned to TMOUT or TIMEOUT across multiple lines in /etc/profile; the effective value cannot be determined from grep output alone." \
            "consolidate TMOUT and TIMEOUT to one assignment each in /etc/profile, then rerun AIXray." "cis-l2"
        ;;
      absent)
        add security shell_timeout_readonly "Interactive shell inactivity timeout" FAIL high \
            "no active TMOUT or TIMEOUT assignment in /etc/profile" \
            "No idle-shell timeout is enforced; interactive shell sessions can remain open indefinitely." \
            "set TMOUT=900, TIMEOUT=900, and readonly TMOUT TIMEOUT in /etc/profile, then rerun AIXray." "cis-l2"
        ;;
      missing)
        STR_MISSING=$STR_REST
        add security shell_timeout_readonly "Interactive shell inactivity timeout" FAIL high \
            "$STR_MISSING is not configured in /etc/profile; both TMOUT and TIMEOUT must be set" \
            "Only one timeout variable is configured in /etc/profile; both are required by the standard." \
            "add a $STR_MISSING assignment (1–900) and a readonly declaration covering both variables in /etc/profile, then rerun AIXray." "cis-l2"
        ;;
      no_readonly)
        STR_TMO_CLS=${STR_REST%%\|*}
        STR_TMP=${STR_REST#*\|}
        STR_TMO_VAL=${STR_TMP%%\|*}
        STR_TMP=${STR_TMP#*\|}
        STR_TO_CLS=${STR_TMP%%\|*}
        STR_TO_VAL=${STR_TMP#*\|}
        add security shell_timeout_readonly "Interactive shell inactivity timeout" FAIL high \
            "TMOUT and TIMEOUT are set but not readonly; the interactive user can alter or unset them" \
            "Without readonly, an interactive user can change or unset the timeout, defeating the inactivity lock." \
            "add \"readonly TMOUT TIMEOUT\" as the last relevant statement in /etc/profile, then rerun AIXray." "cis-l2"
        ;;
      partial_readonly)
        STR_MISSING=${STR_REST%%\|*}
        STR_TMP=${STR_REST#*\|}
        STR_TMO_CLS=${STR_TMP%%\|*}
        STR_TMP=${STR_TMP#*\|}
        STR_TMO_VAL=${STR_TMP%%\|*}
        STR_TMP=${STR_TMP#*\|}
        STR_TO_CLS=${STR_TMP%%\|*}
        STR_TO_VAL=${STR_TMP#*\|}
        add security shell_timeout_readonly "Interactive shell inactivity timeout" FAIL high \
            "$STR_MISSING is not readonly; both TMOUT and TIMEOUT must be readonly" \
            "Only one timeout variable carries the readonly marker; the other can still be altered or unset by the interactive user." \
            "add $STR_MISSING to the readonly declaration in /etc/profile, then rerun AIXray." "cis-l2"
        ;;
      order)
        STR_TMO_CLS=${STR_REST%%\|*}
        STR_TMP=${STR_REST#*\|}
        STR_TMO_VAL=${STR_TMP%%\|*}
        STR_TMP=${STR_TMP#*\|}
        STR_TO_CLS=${STR_TMP%%\|*}
        STR_TO_VAL=${STR_TMP#*\|}
        add security shell_timeout_readonly "Interactive shell inactivity timeout" FAIL high \
            "readonly declaration precedes TMOUT/TIMEOUT assignment; the standard requires readonly to be the last statement" \
            "A readonly declaration that appears before an assignment line is ineffective: the later assignment would fail at shell parse time, or the readonly would not cover it." \
            "move \"readonly TMOUT TIMEOUT\" to be the last statement among the timeout lines in /etc/profile, then rerun AIXray." "cis-l2"
        ;;
      both)
        STR_TMO_CLS=${STR_REST%%\|*}
        STR_TMP=${STR_REST#*\|}
        STR_TMO_VAL=${STR_TMP%%\|*}
        STR_TMP=${STR_TMP#*\|}
        STR_TO_CLS=${STR_TMP%%\|*}
        STR_TO_VAL=${STR_TMP#*\|}
        if [ "$STR_TMO_CLS" = over ] || [ "$STR_TO_CLS" = over ]; then
          STR_BAD=""
          if [ "$STR_TMO_CLS" = over ]; then STR_BAD="TMOUT=${STR_TMO_VAL}"; fi
          if [ "$STR_TO_CLS" = over ]; then
            if [ -n "$STR_BAD" ]; then STR_BAD="${STR_BAD} and TIMEOUT=${STR_TO_VAL}"; else STR_BAD="TIMEOUT=${STR_TO_VAL}"; fi
          fi
          add security shell_timeout_readonly "Interactive shell inactivity timeout" WARN low \
              "${STR_BAD} above the 900-second cap" \
              "A readonly timeout above 900 seconds still leaves an idle session open for an excessive period." \
              "lower TMOUT and TIMEOUT to 900 seconds or less, keep both readonly, and rerun AIXray." "cis-l2"
        elif [ "$STR_TMO_CLS" = empty ] || [ "$STR_TMO_CLS" = nonnum ] || [ "$STR_TMO_CLS" = zero ] ||
             [ "$STR_TO_CLS" = empty ] || [ "$STR_TO_CLS" = nonnum ] || [ "$STR_TO_CLS" = zero ]; then
          STR_BAD=""
          if [ "$STR_TMO_CLS" = empty ]; then STR_BAD="TMOUT has no value"
          elif [ "$STR_TMO_CLS" = zero ]; then STR_BAD="TMOUT=0"
          elif [ "$STR_TMO_CLS" = nonnum ]; then STR_BAD="TMOUT is not a positive integer"
          fi
          if [ "$STR_TO_CLS" = empty ]; then
            if [ -n "$STR_BAD" ]; then STR_BAD="${STR_BAD} and TIMEOUT has no value"; else STR_BAD="TIMEOUT has no value"; fi
          elif [ "$STR_TO_CLS" = zero ]; then
            if [ -n "$STR_BAD" ]; then STR_BAD="${STR_BAD} and TIMEOUT=0"; else STR_BAD="TIMEOUT=0"; fi
          elif [ "$STR_TO_CLS" = nonnum ]; then
            if [ -n "$STR_BAD" ]; then STR_BAD="${STR_BAD} and TIMEOUT is not a positive integer"; else STR_BAD="TIMEOUT is not a positive integer"; fi
          fi
          add security shell_timeout_readonly "Interactive shell inactivity timeout" FAIL high \
              "${STR_BAD}; idle-shell auto-logout is disabled or unreadable" \
              "A zero, empty, or non-numeric timeout value breaks the enforced inactivity logout even when readonly is set." \
              "set TMOUT and TIMEOUT to a positive integer from 1 through 900, keep both readonly, and rerun AIXray." "cis-l2"
        else
          add security shell_timeout_readonly "Interactive shell inactivity timeout" PASS low \
              "TMOUT=${STR_TMO_VAL} and TIMEOUT=${STR_TO_VAL}, both readonly" \
              "Both timeout variables are readonly with a bounded positive value, so an idle interactive shell auto-logs out." \
              "n/a" "cis-l2"
        fi
        ;;
      *)
        add security shell_timeout_readonly "Interactive shell inactivity timeout" \
            NOT_ASSESSED low \
            "not assessed — /etc/profile TMOUT/TIMEOUT parse returned unrecognised state" \
            "The parsed TMOUT/TIMEOUT evidence from /etc/profile did not map to a known shape, so timeout enforcement is unknown." \
            "inspect /etc/profile TMOUT/TIMEOUT configuration and rerun AIXray." "cis-l2"
        ;;
    esac
  fi
}

function standalone_run {
  standalone_check
}

standalone_main "$@"
exit $?
