#!/bin/ksh
# Generated standalone PTxray check support. READ-ONLY: captures only; no
# remediation, service control, network access, or durable target-host writes.
set -u

# Match the monolith's guarded AIX command search path and parsing locale.
PATH=/usr/bin:/etc:/usr/sbin:/usr/ucb:/usr/bin/X11:/sbin:/usr/ios/cli:${PATH:-}
export PATH
LC_ALL=C
export LC_ALL

AIXRAY_STANDALONE_VERSION="1.3.0"

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
# substitution. Byte-for-byte the monolith's semantics (src/ptxray-aix.sh.in);
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
LIFECYCLE_VINTAGE=""

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
  if [ -z "${AIXRAY_FIXTURES:-}" ]; then
    _os=$(uname -s 2>/dev/null)
    if [ "$_os" = "AIX" ]; then
      :
    elif [ "$_os" = "OS400" ] && [ "${IBMI_PROBES:-0}" = 1 ]; then
      :
    else
      echo "$AIXRAY_TOOL: this standalone check runs on AIX/VIOS" >&2
      return 2
    fi
  fi
  standalone_initialize
  initialize_rc=$?
  [ "$initialize_rc" -eq 0 ] || return "$initialize_rc"
  if [ "${IBMI_PROBES:-0}" = 1 ]; then
    if ! ibmi_require_qsecofr; then
      echo "$AIXRAY_TOOL requires SESSION_USER=QSECOFR and SYSTEM_USER=QSECOFR; no scan was run." >&2
      return 2
    fi
  elif [ -z "${AIXRAY_FIXTURES:-}" ] && [ "${MYUID:-}" != 0 ]; then
    echo "$AIXRAY_TOOL requires root; no scan was run." >&2
    return 2
  fi
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

AIXRAY_TOOL=ck-nfs-exports


function standalone_check {
_AIXRAY_SESSION_KEYS=""
  # nfs_exports — unsafe root/anonymous mappings and unrestricted writable exports.
  # All reads are fixture-routed and side-effect free. In particular, exportfs is
  # deliberately invoked without arguments: that form only lists /etc/xtab.
  typeset NFS_CONFIG_EXISTS_OUT NFS_CONFIG_EXISTS_RC
  typeset NFS_CONFIG NFS_CONFIG_RC NFS_LIVE NFS_LIVE_RC
  typeset NFS_CONFIG_LINES NFS_LIVE_LINES NFS_CONFIG_COUNT NFS_LIVE_COUNT
  typeset NFS_LINES NFS_ASSESS NFS_HIGH_COUNT NFS_MED_COUNT NFS_RO_COUNT
  typeset NFS_RO_UNRESTRICTED_COUNT NFS_GAP_COUNT
  typeset NFS_TOTAL_COUNT NFS_EVIDENCE NFS_GAP_EVIDENCE
  typeset NFS_CONFIGURED_ONLY NFS_LIVE_NO_EXPORTS NFS_LIVE_COMMENT_ONLY
  typeset NFS_LIVE_UNASSESSED NFS_CONFIG_ABSENT NFS_CONFIG_UNREADABLE
  typeset NFS_LIVE_GAP_REASON NFS_OBS NFS_PARTIAL_NOTE

  # test -e also returns 1 for some stat failures (for example an inaccessible
  # parent or dangling symlink); the exact live exportfs sentinel below is the
  # independent backstop that prevents active exports from being called clean.
  NFS_CONFIG_EXISTS_OUT=$(aix etc_exports_exists test -e /etc/exports)
  NFS_CONFIG_EXISTS_RC=$?
  NFS_CONFIG=$(aix etc_exports cat /etc/exports); NFS_CONFIG_RC=$?
  NFS_LIVE=$(aix exportfs exportfs); NFS_LIVE_RC=$?
  NFS_CONFIG_ABSENT=0
  NFS_CONFIG_UNREADABLE=0
  if [ "$NFS_CONFIG_RC" -ne 0 ]; then
    if [ "$NFS_CONFIG_EXISTS_RC" -eq 1 ]; then
      NFS_CONFIG_ABSENT=1
    elif [ "$NFS_CONFIG_EXISTS_RC" -eq 0 ]; then
      NFS_CONFIG_UNREADABLE=1
    fi
  fi
  NFS_LIVE_NO_EXPORTS=0
  if [ "$NFS_LIVE_RC" -eq 0 ] &&
      [ "$NFS_LIVE" = "exportfs: nothing exported" ]; then
    NFS_LIVE_NO_EXPORTS=1
  fi

  NFS_CONFIG_LINES=""
  if [ "$NFS_CONFIG_RC" -eq 0 ]; then
    NFS_CONFIG_LINES=$(printf '%s\n' "$NFS_CONFIG" | awk '
      {
        raw=$0
        parsed=$0
        sub(/[ \t]*#.*/, "", parsed)
        if (parsed !~ /^[ \t]*$/) print raw
      }
    ')
  fi
  NFS_LIVE_LINES=""
  if [ "$NFS_LIVE_RC" -eq 0 ] && [ "$NFS_LIVE_NO_EXPORTS" -ne 1 ]; then
    NFS_LIVE_LINES=$(printf '%s\n' "$NFS_LIVE" | awk '
      {
        raw=$0
        parsed=$0
        sub(/[ \t]*#.*/, "", parsed)
        if (parsed !~ /^[ \t]*$/) print raw
      }
    ')
  fi

  NFS_CONFIG_COUNT=$(printf '%s\n' "$NFS_CONFIG_LINES" \
    | awk 'NF {n++} END {print n+0}')
  NFS_LIVE_COUNT=$(printf '%s\n' "$NFS_LIVE_LINES" \
    | awk 'NF {n++} END {print n+0}')
  NFS_LIVE_COMMENT_ONLY=0
  if [ "$NFS_LIVE_RC" -eq 0 ] && [ "$NFS_LIVE_NO_EXPORTS" -ne 1 ] &&
      [ "$NFS_LIVE_COUNT" -eq 0 ]; then
    NFS_LIVE_COMMENT_ONLY=$(printf '%s\n' "$NFS_LIVE" | awk '
      {
        text=$0
        sub(/^[ \t]*/, "", text)
        if (text == "") next
        nonblank=1
        if (text !~ /^#/) noncomment=1
      }
      END {print (nonblank && !noncomment) ? 1 : 0}
    ')
  fi
  NFS_LIVE_UNASSESSED=0
  NFS_LIVE_GAP_REASON=""
  if [ "$NFS_LIVE_RC" -eq 0 ] && [ "$NFS_LIVE_NO_EXPORTS" -ne 1 ] &&
      [ "$NFS_LIVE_COMMENT_ONLY" -ne 1 ] && [ "$NFS_LIVE_COUNT" -eq 0 ]; then
    NFS_LIVE_UNASSESSED=1
    if [ -z "$NFS_LIVE" ]; then
      NFS_LIVE_GAP_REASON="not assessed — current exportfs listing was empty (rc=0)"
    else
      NFS_LIVE_GAP_REASON="not assessed — current exportfs listing contained no classifiable export rows (rc=0)"
    fi
  fi
  NFS_LINES=$(printf '%s\n%s\n' "$NFS_CONFIG_LINES" "$NFS_LIVE_LINES" \
    | awk 'NF && !seen[$0]++ {print}')

  NFS_ASSESS=$(printf '%s\n' "$NFS_LINES" | awk '
    function valid_ipv4(value, octet, count, i) {
      count=split(value, octet, ".")
      if (count != 4) return 0
      for (i=1; i<=4; i++) {
        if (octet[i] !~ /^[0-9][0-9]*$/) return 0
        if ((octet[i] + 0) < 0 || (octet[i] + 0) > 255) return 0
      }
      return 1
    }
    function unsafe_root_list(value, client, count, i) {
      if (value == "") return 1
      count=split(value, client, ":")
      for (i=1; i<=count; i++) {
        if (client[i] == "") return 1
        # AIX subnet designators begin with @ and include a mask. Prefix-@
        # netgroup forms are likewise not a specific, locally-proven host.
        if (client[i] ~ /^@/ || client[i] ~ /\//) return 1
        if (client[i] ~ /[*?]/) return 1
        if (client[i] ~ /^[0-9.]+$/) {
          if (!valid_ipv4(client[i])) return 1
        } else if (client[i] !~ /^[a-z0-9][a-z0-9_.-]*$/) {
          return 1
        }
      }
      return 0
    }
    {
      row++
      raw[row]=$0
      text=$0
      sub(/[ \t]*#.*/, "", text)
      if (text ~ /^[ \t]*$/) next
      sub(/^[ \t]+/, "", text)
      sub(/[ \t]+$/, "", text)
      gsub(/[ \t]*=[ \t]*/, "=", text)
      normalized[row]=text
      if (text !~ /^\/[^ \t]*([ \t]+-[^ \t].*)?$/) {
        grade[row]="U"
        next
      }

      count=split(text, field, /[ \t]+/)
      path[row]=field[1]
      if (definition[path[row]] != "" &&
          definition[path[row]] != normalized[row]) {
        conflict[path[row]]=1
      } else {
        definition[path[row]]=normalized[row]
      }

      option_text=tolower(text)
      count=split(option_text, option, /[[:space:],]+/)
      has_ro=0
      has_rw=0
      has_access=0
      unsafe_root=0
      unsafe_anon=0
      malformed=0
      for (i=1; i<=count; i++) {
        item=option[i]
        sub(/^-+/, "", item)
        if (item == "ro" || item ~ /^ro=/) has_ro=1
        if (item == "rw" || item ~ /^rw=/) has_rw=1
        if (item ~ /^access=/) {
          if (substr(item, 8) == "") malformed=1
          else has_access=1
        }
        if (item == "anon=0") unsafe_anon=1
        if (item ~ /^root=/ && unsafe_root_list(substr(item, 6))) {
          unsafe_root=1
        }
      }
      if (malformed || (has_ro && has_rw)) grade[row]="U"
      else if (unsafe_root || unsafe_anon) grade[row]="H"
      else if (has_ro && !has_access) grade[row]="O"
      else if ((has_rw || !has_ro) && !has_access) grade[row]="M"
      else if (has_ro) grade[row]="R"
      else grade[row]="W"
    }
    END {
      for (i=1; i<=row; i++) {
        if (path[i] != "" && conflict[path[i]]) grade[i]="C"
        if (grade[i] != "") print grade[i] "\t" raw[i]
      }
    }
  ')

  NFS_HIGH_COUNT=$(printf '%s\n' "$NFS_ASSESS" \
    | awk -F '\t' '$1=="H" {n++} END {print n+0}')
  NFS_MED_COUNT=$(printf '%s\n' "$NFS_ASSESS" \
    | awk -F '\t' '$1=="M" {n++} END {print n+0}')
  NFS_RO_COUNT=$(printf '%s\n' "$NFS_ASSESS" \
    | awk -F '\t' '$1=="R" {n++} END {print n+0}')
  NFS_RO_UNRESTRICTED_COUNT=$(printf '%s\n' "$NFS_ASSESS" \
    | awk -F '\t' '$1=="O" {n++} END {print n+0}')
  NFS_GAP_COUNT=$(printf '%s\n' "$NFS_ASSESS" \
    | awk -F '\t' '$1=="U" || $1=="C" {n++} END {print n+0}')
  NFS_TOTAL_COUNT=$(printf '%s\n' "$NFS_ASSESS" \
    | awk -F '\t' '$1=="H" || $1=="M" || $1=="O" ||
        $1=="R" || $1=="W" {n++} END {print n+0}')
  NFS_EVIDENCE=$(printf '%s\n' "$NFS_ASSESS" | awk -F '\t' '
    $1=="H" || $1=="M" || $1=="O" {
      total++
      if (shown < 20) {
        print substr($0, 3)
        shown++
      }
    }
    END {
      if (total > 20) {
        printf "%d additional offending line(s) omitted (cap 20)", total-20
      }
    }
  ')
  NFS_GAP_EVIDENCE=$(printf '%s\n' "$NFS_ASSESS" | awk -F '\t' '
    $1=="C" {
      raw=substr($0, 3)
      split(raw, field, /[ \t]+/)
      if (!conflict_seen[field[1]]++) {
        print "conflicting NFS export definitions for " field[1]
      }
      print raw
      next
    }
    $1=="U" {
      print "unclassified NFS export line: " substr($0, 3)
    }
  ')

  NFS_CONFIGURED_ONLY=0
  if [ "$NFS_CONFIG_RC" -eq 0 ] && [ "$NFS_LIVE_RC" -eq 0 ] \
      && [ "$NFS_CONFIG_COUNT" -gt 0 ] &&
      { [ "$NFS_LIVE_NO_EXPORTS" -eq 1 ] ||
        [ "$NFS_LIVE_COMMENT_ONLY" -eq 1 ]; }; then
    NFS_CONFIGURED_ONLY=1
  fi

  NFS_PARTIAL_NOTE=""
  if [ "$NFS_CONFIG_ABSENT" -eq 1 ] && [ "$NFS_LIVE_RC" -eq 0 ]; then
    NFS_PARTIAL_NOTE="partially assessed — /etc/exports is absent; live exportfs evidence follows"
  elif [ "$NFS_CONFIG_UNREADABLE" -eq 1 ] && [ "$NFS_LIVE_RC" -eq 0 ]; then
    NFS_PARTIAL_NOTE="partially assessed — /etc/exports read failed; live exportfs evidence follows"
  elif [ "$NFS_CONFIG_RC" -ne 0 ] && [ "$NFS_LIVE_RC" -eq 0 ]; then
    NFS_PARTIAL_NOTE="partially assessed — /etc/exports existence and read state could not be established; live exportfs evidence follows"
  elif [ "$NFS_CONFIG_RC" -eq 0 ] && [ "$NFS_LIVE_RC" -ne 0 ]; then
    NFS_PARTIAL_NOTE="partially assessed — current exportfs listing failed; configured /etc/exports evidence follows"
  elif [ "$NFS_CONFIG_RC" -eq 0 ] && [ "$NFS_LIVE_UNASSESSED" -eq 1 ]; then
    NFS_PARTIAL_NOTE="partially assessed — current exportfs listing had no classifiable evidence (rc=0); configured /etc/exports evidence follows"
  fi

  if [ "$NFS_GAP_COUNT" -gt 0 ]; then
    NFS_OBS="not assessed — NFS export evidence was conflicting or unparseable (etc_exports rc=$NFS_CONFIG_RC; exportfs rc=$NFS_LIVE_RC)"
    NFS_OBS="${NFS_OBS}:
${NFS_GAP_EVIDENCE}"
    add security nfs_exports "NFS exports" NOT_ASSESSED high \
        "$NFS_OBS" \
        "At least one non-comment evidence line was not exactly a /path [-options] export definition, or the same path had conflicting definitions, so PTxray cannot claim the export set was safely assessed." \
        "inspect /etc/exports and the no-argument exportfs listing, resolve conflicting definitions or diagnostics, then rerun PTxray." "cis-l1"
  elif [ "$NFS_HIGH_COUNT" -gt 0 ]; then
    NFS_OBS=$NFS_EVIDENCE
    if [ -n "$NFS_PARTIAL_NOTE" ]; then
      NFS_OBS="${NFS_PARTIAL_NOTE}
${NFS_OBS}"
    fi
    if [ "$NFS_CONFIGURED_ONLY" -eq 1 ]; then
      NFS_OBS="${NFS_OBS}
configured-but-not-live: $NFS_CONFIG_COUNT uncommented /etc/exports line(s); exportfs listed no current exports"
    fi
    add security nfs_exports "NFS exports" FAIL high "$NFS_OBS" \
        "One or more NFS export definitions map anonymous requests to UID 0 or grant root privileges beyond a specific host or IP address." \
        "remove anon=0 and restrict every root= list to explicit trusted hostnames or IP addresses; then re-export the corrected definitions during an approved change." "cis-l1"
  elif [ "$NFS_MED_COUNT" -gt 0 ] ||
      [ "$NFS_RO_UNRESTRICTED_COUNT" -gt 0 ]; then
    NFS_OBS=$NFS_EVIDENCE
    if [ -n "$NFS_PARTIAL_NOTE" ]; then
      NFS_OBS="${NFS_PARTIAL_NOTE}
${NFS_OBS}"
    fi
    if [ "$NFS_CONFIGURED_ONLY" -eq 1 ]; then
      NFS_OBS="${NFS_OBS}
configured-but-not-live: $NFS_CONFIG_COUNT uncommented /etc/exports line(s); exportfs listed no current exports"
    fi
    add security nfs_exports "NFS exports" WARN med "$NFS_OBS" \
        "One or more exports have no access= client restriction. Writable or default-mode exports expose writes, while read-only exports remain mountable by any client that can reach the NFS service." \
        "add an explicit access= host list and use ro unless the clients genuinely require writes; re-export only through the normal approved change process." "cis-l1"
  elif [ "$NFS_CONFIG_ABSENT" -eq 1 ] &&
      [ "$NFS_LIVE_RC" -eq 0 ] && [ "$NFS_LIVE_NO_EXPORTS" -eq 1 ]; then
    add security nfs_exports "NFS exports" PASS high \
        "this host exports no filesystems" \
        "No /etc/exports definition file exists and the current exportfs listing confirms that nothing is exported." \
        "n/a" "cis-l1"
  elif [ "$NFS_CONFIG_UNREADABLE" -eq 1 ] &&
      [ "$NFS_LIVE_RC" -ne 0 ]; then
    add security nfs_exports "NFS exports" NOT_ASSESSED high \
        "not assessed — both NFS evidence reads failed (/etc/exports exit=$NFS_CONFIG_RC; exportfs exit=$NFS_LIVE_RC)" \
        "Neither configured nor current NFS export evidence was readable, so absence of exports and safe export options cannot be established." \
        "restore read access to /etc/exports and the no-argument exportfs listing, then re-run PTxray." "cis-l1"
  elif [ "$NFS_CONFIG_ABSENT" -eq 1 ] && [ "$NFS_LIVE_RC" -ne 0 ]; then
    add security nfs_exports "NFS exports" NOT_ASSESSED high \
        "not assessed — /etc/exports is absent and the current exportfs listing failed (exit=$NFS_LIVE_RC)" \
        "Neither dormant export definitions nor the active export set could be established." \
        "determine whether this host should have an /etc/exports definition file, restore access to the no-argument exportfs listing, and re-run PTxray." "cis-l1"
  elif [ "$NFS_CONFIG_RC" -ne 0 ] && [ "$NFS_LIVE_RC" -ne 0 ]; then
    add security nfs_exports "NFS exports" NOT_ASSESSED high \
        "not assessed — /etc/exports existence and read state could not be established (existence exit=$NFS_CONFIG_EXISTS_RC; read exit=$NFS_CONFIG_RC), and exportfs failed (exit=$NFS_LIVE_RC)" \
        "The definition-file state and current NFS export set are both unknown." \
        "verify whether /etc/exports exists, establish the no-argument exportfs listing, and re-run PTxray." "cis-l1"
  elif [ "$NFS_CONFIG_ABSENT" -eq 1 ] && [ "$NFS_LIVE_COUNT" -gt 0 ]; then
    add security nfs_exports "NFS exports" NOT_ASSESSED high \
        "not assessed — /etc/exports is absent while the current exportfs listing contains $NFS_LIVE_COUNT active export line(s)" \
        "Active exports were observed, but without the definition file PTxray cannot establish whether dormant exports exist or whether definitions are managed elsewhere." \
        "determine how this host's active NFS exports are managed; restore or recreate /etc/exports if appropriate, then re-run PTxray." "cis-l1"
  elif [ "$NFS_CONFIG_ABSENT" -eq 1 ]; then
    add security nfs_exports "NFS exports" NOT_ASSESSED high \
        "not assessed — /etc/exports is absent; the current exportfs evidence did not establish the exact no-export state" \
        "The definition file is missing and the live evidence was not sufficient to prove that this host exports no filesystems." \
        "determine whether this host should have an /etc/exports definition file, verify the complete no-argument exportfs output, and re-run PTxray." "cis-l1"
  elif [ "$NFS_CONFIG_UNREADABLE" -eq 1 ]; then
    add security nfs_exports "NFS exports" NOT_ASSESSED high \
        "not assessed — /etc/exports read failed (exit=$NFS_CONFIG_RC); no unsafe option was established from the current exportfs listing" \
        "The live listing alone did not establish an unsafe export, but unreadable configuration can contain dormant definitions that later become active." \
        "restore read access to /etc/exports and re-run PTxray." "cis-l1"
  elif [ "$NFS_CONFIG_RC" -ne 0 ]; then
    add security nfs_exports "NFS exports" NOT_ASSESSED high \
        "not assessed — /etc/exports existence and read state could not be established (existence exit=$NFS_CONFIG_EXISTS_RC; read exit=$NFS_CONFIG_RC)" \
        "The live listing alone did not establish an unsafe export, and the configured export state remains unknown." \
        "verify whether /etc/exports exists and can be captured, then re-run PTxray." "cis-l1"
  elif [ "$NFS_LIVE_RC" -ne 0 ]; then
    add security nfs_exports "NFS exports" NOT_ASSESSED high \
        "not assessed — current exportfs listing failed (exit=$NFS_LIVE_RC); no unsafe option was established from /etc/exports" \
        "The configuration alone did not establish an unsafe export, but the unreadable live listing can contain currently exported state not represented by that file." \
        "restore access to the no-argument exportfs listing and re-run PTxray." "cis-l1"
  elif [ "$NFS_LIVE_UNASSESSED" -eq 1 ]; then
    add security nfs_exports "NFS exports" NOT_ASSESSED high \
        "$NFS_LIVE_GAP_REASON; no unsafe option was established from /etc/exports" \
        "A successful live-listing capture must contain export rows or the exact AIX no-export sentinel before absence of current exports can be established." \
        "rerun the no-argument exportfs listing, verify its complete stdout and return code, then re-run PTxray." "cis-l1"
  elif [ "$NFS_CONFIGURED_ONLY" -eq 1 ]; then
    add security nfs_exports "NFS exports" WARN low \
        "configured-but-not-live: $NFS_CONFIG_COUNT uncommented /etc/exports line(s); exportfs listed no current exports" \
        "NFS exports are configured but were not present in the current exportfs listing; the configuration can become live when NFS is started or exports are refreshed." \
        "confirm whether these exports are intentionally dormant; remove stale definitions or activate only the intended host-restricted exports during an approved change." "cis-l1"
  elif [ "$NFS_TOTAL_COUNT" -eq 0 ] &&
      { [ "$NFS_LIVE_NO_EXPORTS" -eq 1 ] ||
        [ "$NFS_LIVE_COMMENT_ONLY" -eq 1 ]; }; then
    add security nfs_exports "NFS exports" PASS high \
        "NFS server not exporting" \
        "No uncommented configured export and no current exportfs entry was observed." \
        "n/a" "cis-l1"
  elif [ "$NFS_RO_COUNT" -eq "$NFS_TOTAL_COUNT" ]; then
    add security nfs_exports "NFS exports" PASS high \
        "$NFS_TOTAL_COUNT export line(s) assessed; read-only and host-restricted by parsed access= lists" \
        "Every observed export is read-only, client-restricted, and has no unsafe root or anonymous UID 0 mapping." \
        "n/a" "cis-l1"
  else
    add security nfs_exports "NFS exports" PASS high \
        "$NFS_TOTAL_COUNT export line(s) assessed; host-restricted by parsed access= lists; $NFS_RO_COUNT read-only" \
        "Every observed export has a non-empty access= client list, and no export grants root broadly or maps anonymous requests to UID 0." \
        "n/a" "cis-l1"
  fi
}

function standalone_run {
  standalone_check
}

standalone_main "$@"
exit $?
