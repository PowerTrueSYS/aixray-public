#!/bin/ksh
# Generated standalone AIXray check support. READ-ONLY: captures only; no
# remediation, service control, network access, or durable target-host writes.
set -u

# Match the monolith's guarded AIX command search path and parsing locale.
PATH=/usr/bin:/etc:/usr/sbin:/usr/ucb:/usr/bin/X11:/sbin:/usr/ios/cli:${PATH:-}
export PATH
LC_ALL=C
export LC_ALL

AIXRAY_STANDALONE_VERSION="1.0.0"

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

AIXRAY_TOOL=ck-shell-timeout


function standalone_check {
_AIXRAY_SESSION_KEYS=""

  # shell_timeout — ensure an idle-shell auto-logout timeout is bounded.
  # A positive TMOUT set in /etc/profile or /etc/environment forces the shell
  # to log out after N seconds of inactivity; without it, an abandoned session
  # remains open indefinitely. /etc/security/.profile is intentionally excluded:
  # it is a mkuser skeleton copied into new home directories, not a login-time
  # source, and its permissions also make the otherwise non-root check unreadable.
  typeset ST_RAW ST_RC ST_PARSED ST_STATE ST_DETAIL ST_VAL
  ST_RAW=$(aix profile_tmout grep -E 'TMOUT|TIMEOUT' /etc/profile /etc/environment); ST_RC=$?
  if [ "$ST_RC" -ge 2 ]; then
    add security shell_timeout "Idle-shell auto-logout timeout" \
        NOT_ASSESSED low \
        "not assessed — TMOUT/TIMEOUT capture failed (rc=$ST_RC)" \
        "Could not read TMOUT/TIMEOUT evidence from /etc/profile and /etc/environment, so idle-shell enforcement is unknown." \
        "restore read access to /etc/profile and /etc/environment, then rerun AIXray." "cis-l1"
  elif [ "$ST_RC" -eq 1 ]; then
    add security shell_timeout "Idle-shell auto-logout timeout" FAIL med \
        "no active TMOUT/TIMEOUT match (grep rc=1)" \
        "No idle-shell timeout is enforced; interactive shell sessions can remain open indefinitely." \
        "set TMOUT=900 (or less) in /etc/profile (for example, TMOUT=900; export TMOUT), make TMOUT readonly with the approved AIX shell syntax, then rerun AIXray." "cis-l1"
  else
    # A leading comment is not evidence; a shell-style trailing comment is
    # removed before the numeric shape check. Because assignments are
    # sequential and grep output across both files is not a trustworthy
    # effective-precedence model, PASS requires every active assignment to be
    # numeric, positive, and bounded. Values above 900 are classified without
    # feeding an arbitrarily large attacker-controlled integer into arithmetic.
    ST_PARSED=$(printf '%s\n' "$ST_RAW" | awk '
      function trim(value) {
        sub(/^[ \t]+/, "", value)
        sub(/[ \t]+$/, "", value)
        return value
      }
      function remember(value) {
        if (!seen_value[value]++) {
          if (values != "") values=values ", "
          values=values value
          distinct_values++
        }
      }
      {
        line=$0
        sub(/^[ \t]+/, "", line)
        # grep prefixes matches with a filename when both declared files are
        # read. Strip only those two trusted capture-source prefixes.
        sub(/^\/etc\/profile:/, "", line)
        sub(/^\/etc\/environment:/, "", line)
        sub(/^[ \t]+/, "", line)
        if (line ~ /^#/) next
        sub(/[ \t]+#.*/, "", line)
        line=trim(line)
        if (line == "") next
        low=tolower(line)

        if (low ~ /^unset[ \t]+/) {
          target=low
          sub(/^unset[ \t]+/, "", target)
          if (target ~ /^-v[ \t]+/) sub(/^-v[ \t]+/, "", target)
          target=trim(target)
          if (target == "tmout" || target == "timeout") {
            unsets++
          } else {
            invalid=1
          }
          next
        }

        if (low ~ /^export[ \t]+(tmout|timeout)[ \t]*$/) {
          exports++
          next
        }

        if (low ~ /^(export[ \t]+)?(tmout|timeout)[ \t]*=/) {
          assignments++
          work=low
          sub(/^export[ \t]+/, "", work)
          variable=work
          sub(/[ \t]*=.*/, "", variable)
          variable=trim(variable)
          sub(/^[^=]*=[ \t]*/, "", work)
          work=trim(work)

          separator=index(work, ";")
          if (separator > 0) {
            suffix=trim(substr(work, separator+1))
            work=trim(substr(work, 1, separator-1))
            sub(/[ \t]*;[ \t]*$/, "", suffix)
            suffix=trim(suffix)
            gsub(/[ \t]+/, " ", suffix)
            if (suffix != "export " variable) invalid=1
          }

          if (work !~ /^[0-9]+$/) {
            invalid=1
            next
          }
          canon=work
          sub(/^0+/, "", canon)
          if (canon == "") canon="0"
          remember(canon)
          next
        }

        if (low ~ /^readonly[ \t]+/) {
          # A readonly declaration assigns nothing, so it is compliance-neutral:
          # naming the timeout variables -- or any other variable -- must not
          # poison otherwise determinate evidence. A tmout/timeout=VALUE inside
          # the declaration is a real assignment and is classified exactly like a
          # plain one, with the same conflict tracking.
          work=low
          sub(/^readonly[ \t]+/, "", work)
          work=trim(work)
          if (work == "") next
          gsub(/[ \t,]+/, " ", work)
          tcount=split(work, tokens, " ")
          for (tidx=1; tidx<=tcount; tidx++) {
            token=tokens[tidx]
            if (token ~ /^(tmout|timeout)=/) {
              assignments++
              aval=token
              sub(/^[^=]*=[ \t]*/, "", aval)
              if (aval !~ /^[0-9]+$/) {
                invalid=1
                next
              }
              canon=aval
              sub(/^0+/, "", canon)
              if (canon == "") canon="0"
              remember(canon)
            }
          }
          next
        }

        invalid=1
      }
      END {
        if (invalid) {
          print "invalid|"
        } else if (assignments > 0 && unsets > 0) {
          print "assignment_unset_conflict|"
        } else if (distinct_values > 1) {
          print "value_conflict|" values
        } else if (unsets > 0) {
          print "unset|"
        } else if (assignments == 0) {
          print "empty|"
        } else if (values == "0") {
          print "zero|0"
        } else if (length("" values) > 3 ||
                   (length("" values) == 3 && values + 0 > 900)) {
          print "over|" values
        } else {
          print "safe|" values
        }
      }
    ')
    ST_STATE=${ST_PARSED%%\|*}
    ST_DETAIL=${ST_PARSED#*\|}
    case "$ST_STATE" in
      over)
        ST_VAL=$ST_DETAIL
        add security shell_timeout "Idle-shell auto-logout timeout" WARN low "${ST_VAL}s" \
            "TMOUT is set to ${ST_VAL} seconds, which exceeds the 900-second bounded-session cap." \
            "reduce TMOUT to 900 seconds or less in /etc/profile or /etc/environment." "cis-l1"
        ;;
      assignment_unset_conflict)
        add security shell_timeout "Idle-shell auto-logout timeout" NOT_ASSESSED low \
            "not assessed — TMOUT/TIMEOUT assignment conflicts with unset directive" \
            "AIXray observed both an assignment and an unset directive, but concatenated grep output from two files does not establish effective shell precedence." \
            "inspect active TMOUT/TIMEOUT directives in /etc/profile and /etc/environment, remove the conflict, and rerun AIXray." "cis-l1"
        ;;
      value_conflict)
        add security shell_timeout "Idle-shell auto-logout timeout" NOT_ASSESSED low \
            "not assessed — conflicting TMOUT/TIMEOUT assignments (values: $ST_DETAIL)" \
            "AIXray observed different timeout values, but concatenated grep output from two files does not establish which assignment is effective." \
            "converge /etc/profile and /etc/environment on one bounded value from 1 through 900, then rerun AIXray." "cis-l1"
        ;;
      invalid)
        add security shell_timeout "Idle-shell auto-logout timeout" NOT_ASSESSED low \
            "not assessed — TMOUT/TIMEOUT capture unparseable (rc=0)" \
            "AIXray did not obtain one active numeric TMOUT/TIMEOUT assignment, so it cannot claim an idle-shell timeout is enforced." \
            "inspect active TMOUT/TIMEOUT assignments in /etc/profile and /etc/environment, correct malformed or commented settings, and rerun AIXray." "cis-l1"
        ;;
      empty)
        add security shell_timeout "Idle-shell auto-logout timeout" FAIL med \
            "no active TMOUT/TIMEOUT directive in successful capture (rc=0)" \
            "No idle-shell timeout is enforced; interactive shell sessions can remain open indefinitely." \
            "set TMOUT=900 (or less) in /etc/profile (for example, TMOUT=900; export TMOUT), make TMOUT readonly with the approved AIX shell syntax, then rerun AIXray." "cis-l1"
        ;;
      unset)
        add security shell_timeout "Idle-shell auto-logout timeout" FAIL med \
            "TMOUT/TIMEOUT explicitly unset" \
            "An active unset directive removes the idle-shell timeout, so an abandoned session can remain open indefinitely." \
            "replace the unset directive with one bounded TMOUT assignment from 1 through 900." "cis-l1"
        ;;
      zero)
        add security shell_timeout "Idle-shell auto-logout timeout" FAIL med "0s" \
            "TMOUT is zero, so idle-shell auto-logout is disabled." \
            "set TMOUT to a value from 1 through 900 in /etc/profile or /etc/environment." "cis-l1"
        ;;
      safe)
        ST_VAL=$ST_DETAIL
        add security shell_timeout "Idle-shell auto-logout timeout" PASS med "${ST_VAL}s" \
            "An idle session auto-logs out after ${ST_VAL} seconds of inactivity." \
            "n/a" "cis-l1"
        ;;
    esac
  fi
}

function standalone_run {
  standalone_check
}

standalone_main "$@"
exit $?
