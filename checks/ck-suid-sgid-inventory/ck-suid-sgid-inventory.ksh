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

AIXRAY_TOOL=ck-suid-sgid-inventory


function standalone_check {
_AIXRAY_SESSION_KEYS=""
  # Control 4.1.1.19 — every setuid/setgid file on the box must be authorized.
  #
  # Two stages, strictly in this order:
  #   1. The live inventory. One `find` restricted to the two privilege bits,
  #      with a `mount` read picking the whole-tree or JFS/JFS2 capture path.
  #      It ALWAYS runs, before any baseline decision. Until 2026-08-06 the
  #      "no baseline" branch returned first, so on every real box the find
  #      never executed and no capture ever carried suid_sgid_local /
  #      suid_sgid_all at all.
  #   2. Authorization, decided by the first layer that applies:
  #        a. site baseline   /etc/security/aixray-suid-sgid-baseline
  #        b. not-maintained  /etc/security/aixray-suid-sgid-baseline.override
  #                           (consulted only when no site baseline exists)
  #        c. shipped default: vendor ownership read from AIX's own package
  #           database, one `lslpp -w <path>` probe per discovered path.
  #      Site exceptions (…-baseline.allow) are authorized additions on top of
  #      whichever of (a) or (c) applied.
  #
  # No list of "stock AIX suid binaries" is hard-coded here. The only vendor
  # fact used is what lslpp reports on the box being assessed, and a path whose
  # ownership lslpp does not resolve is counted as unresolved, never as
  # authorized. This fragment never mutates the system and never manufactures
  # a clean result.
  typeset SSI_BASELINE SSI_ALLOW SSI_ALLOW_SRC SSI_OVERRIDE SSI_OVR
  typeset SSI_STATUS SSI_OBSERVED SSI_MEANING SSI_FIX SSI_SEV SSI_NOTE
  typeset SSI_MODE SSI_RAW SSI_RC SSI_ALL SSI_ALL_RC SSI_LOC SSI_LOC_RC SSI_MNT SSI_MNT_RC
  typeset SSI_SHAPE SSI_DELTA SSI_DRIFT SSI_EXC SSI_TOTAL SSI_UNSAFE
  typeset SSI_PATHS SSI_P SSI_KEY SSI_LW SSI_LW_RC SSI_CLASS
  typeset SSI_UNOWNED SSI_UNKNOWN

  SSI_BASELINE=/etc/security/aixray-suid-sgid-baseline
  SSI_ALLOW=${SSI_BASELINE}.allow
  SSI_OVERRIDE=${SSI_BASELINE}.override
  SSI_ALLOW_SRC=/dev/null
  SSI_OVR=""
  SSI_STATUS=NOT_ASSESSED
  SSI_OBSERVED=""
  SSI_NOTE=""
  SSI_MODE=local
  SSI_RAW=""
  SSI_RC=0
  SSI_ALL=""
  SSI_ALL_RC=0
  SSI_LOC=""
  SSI_LOC_RC=0
  SSI_SHAPE=""
  SSI_DELTA=0
  SSI_DRIFT=0
  SSI_EXC=0
  SSI_TOTAL=0
  SSI_UNSAFE=0
  SSI_PATHS=""
  SSI_P=""
  SSI_KEY=""
  SSI_LW=""
  SSI_LW_RC=0
  SSI_CLASS=unknown
  SSI_UNOWNED=0
  SSI_UNKNOWN=0

  if [ "${MYUID:-0}" != "0" ]; then
    SSI_STATUS=NOT_ASSESSED
    SSI_OBSERVED="not assessed - suid/sgid inventory probe requires root"
  else
    SSI_MNT=$(aix mount mount); SSI_MNT_RC=$?
    SSI_MODE=local
    if [ "$SSI_MNT_RC" -eq 0 ] && [ -n "$SSI_MNT" ]; then
      SSI_MODE=$(printf '%s\n' "$SSI_MNT" | awk '
        NR <= 2 { next }
        $1 ~ /^-+$/ { next }
        NF >= 3 && $3 != "jfs" && $3 != "jfs2" { nl = 1 }
        END { print (nl ? "local" : "all") }')
    fi
    [ -n "$SSI_MODE" ] || SSI_MODE=local
    # Stage 1 — the inventory probe is unconditional. A pure read.
    if [ "$SSI_MODE" = "all" ]; then
      SSI_ALL=$(aix suid_sgid_all find / \( -perm -04000 -o -perm -02000 \) -type f -ls); SSI_ALL_RC=$?
      if [ "$SSI_ALL_RC" -eq 0 ]; then
        SSI_RAW=$SSI_ALL
      fi
      SSI_RC=$SSI_ALL_RC
    else
      SSI_LOC=$(aix suid_sgid_local find / \( -fstype jfs -o -fstype jfs2 \) \( -perm -04000 -o -perm -02000 \) -type f -ls); SSI_LOC_RC=$?
      if [ "$SSI_LOC_RC" -eq 0 ]; then
        SSI_RAW=$SSI_LOC
      fi
      SSI_RC=$SSI_LOC_RC
    fi

    SSI_TOTAL=$(printf '%s\n' "$SSI_RAW" | awk 'NF && $NF ~ /^\// { n++ } END { print n+0 }')
    [ -n "$SSI_TOTAL" ] || SSI_TOTAL=0
    if [ "$SSI_RC" -ne 0 ]; then
      SSI_STATUS=NOT_ASSESSED
      SSI_OBSERVED="not assessed - suid/sgid find probe failed (rc=$SSI_RC)"
    elif [ "$SSI_TOTAL" -eq 0 ]; then
      SSI_STATUS=NOT_ASSESSED
      SSI_OBSERVED="not assessed - suid/sgid inventory returned no rows; a running AIX system always carries setuid/sgid files, so an empty inventory is not evidence"
    else
      if [ -f "$SSI_ALLOW" ] && [ -r "$SSI_ALLOW" ]; then
        SSI_ALLOW_SRC=$SSI_ALLOW
      fi
      # Stage 2 — layer precedence: site baseline, then the recorded
      # not-maintained decision, then the shipped fileset-ownership default.
      if [ -f "$SSI_BASELINE" ] && [ ! -r "$SSI_BASELINE" ]; then
        SSI_STATUS=NOT_ASSESSED
        SSI_OBSERVED="not assessed - suid/sgid inventory baseline exists but is not readable"
      elif [ -f "$SSI_BASELINE" ]; then
        # Layer (a). The baseline and the exception file are read as awk file
        # operands, dispatched by FILENAME; the live inventory arrives last on
        # stdin. An absent exception file is replaced by /dev/null so the
        # operand list never changes shape.
        SSI_SHAPE=$(printf '%s\n' "$SSI_RAW" | awk -v bl="$SSI_BASELINE" -v al="$SSI_ALLOW_SRC" '
          function clean(v) {
            sub(/^[ \t]+/, "", v)
            sub(/[ \t]+$/, "", v)
            return v
          }
          FILENAME == bl {
            if ($0 ~ /^[ \t]*$/ || $0 ~ /^[ \t]*#/) next
            entry = clean($0)
            if (entry != "") base[entry] = 1
            next
          }
          FILENAME == al {
            if ($0 ~ /^[ \t]*$/ || $0 ~ /^[ \t]*#/) next
            entry = clean($0)
            if (entry != "") allow[entry] = 1
            next
          }
          {
            if ($0 ~ /^[ \t]*$/) next
            live[$NF] = 1
            if (!($NF in base)) {
              if ($NF in allow) exc[$NF] = 1
              else delta[$NF] = 1
            }
          }
          END {
            nd = 0
            for (p in delta) nd++
            ne = 0
            for (p in exc) ne++
            ndr = 0
            for (p in base) if (!(p in live)) ndr++
            printf "delta:%d:exc:%d:drift:%d", nd, ne, ndr
          }' "$SSI_BASELINE" "$SSI_ALLOW_SRC" -)
        case "$SSI_SHAPE" in
          delta:*:exc:*:drift:*)
            SSI_DELTA=${SSI_SHAPE#delta:}
            SSI_DELTA=${SSI_DELTA%%:exc:*}
            SSI_EXC=${SSI_SHAPE#*:exc:}
            SSI_EXC=${SSI_EXC%%:drift:*}
            SSI_DRIFT=${SSI_SHAPE##*:drift:}
            if [ "$SSI_EXC" -gt 0 ]; then
              SSI_NOTE="$SSI_NOTE; +$SSI_EXC site exception(s)"
            fi
            if [ "$SSI_DRIFT" -gt 0 ]; then
              SSI_NOTE="$SSI_NOTE; $SSI_DRIFT baseline path(s) absent"
            fi
            if [ "$SSI_DELTA" -gt 0 ]; then
              SSI_STATUS=FAIL
              SSI_OBSERVED="$SSI_DELTA of $SSI_TOTAL setuid/sgid file(s) are not in the approved baseline$SSI_NOTE"
            else
              SSI_STATUS=PASS
              SSI_OBSERVED="all $SSI_TOTAL setuid/sgid file(s) are in the approved baseline$SSI_NOTE"
            fi
            ;;
          *)
            SSI_STATUS=NOT_ASSESSED
            SSI_OBSERVED="not assessed - suid/sgid baseline comparison produced no result"
            ;;
        esac
      else
        if [ -f "$SSI_OVERRIDE" ]; then
          SSI_OVR=$(awk '!/^[ \t]*$/ && !/^[ \t]*#/ { print $0; exit }' "$SSI_OVERRIDE" 2>/dev/null)
        fi
        if [ "$SSI_OVR" = "not-maintained" ]; then
          # Layer (b).
          SSI_STATUS=NOT_APPLICABLE
          SSI_OBSERVED="not applicable - a recorded decision states no suid/sgid inventory baseline is maintained"
        else
          # Layer (c). Candidates are the discovered paths minus the site
          # exceptions. A path carrying shell glob metacharacters cannot be
          # handed to the per-path probe safely, so it is counted unresolved
          # rather than dropped.
          SSI_PATHS=$(printf '%s\n' "$SSI_RAW" | awk -v al="$SSI_ALLOW_SRC" '
            FILENAME == al {
              if ($0 ~ /^[ \t]*$/ || $0 ~ /^[ \t]*#/) next
              entry = $0
              sub(/^[ \t]+/, "", entry)
              sub(/[ \t]+$/, "", entry)
              if (entry != "") allow[entry] = 1
              next
            }
            NF && $NF ~ /^\// && $NF !~ /[][*?]/ && !($NF in allow) { print $NF }' "$SSI_ALLOW_SRC" -)
          SSI_EXC=$(printf '%s\n' "$SSI_RAW" | awk -v al="$SSI_ALLOW_SRC" '
            FILENAME == al {
              if ($0 ~ /^[ \t]*$/ || $0 ~ /^[ \t]*#/) next
              entry = $0
              sub(/^[ \t]+/, "", entry)
              sub(/[ \t]+$/, "", entry)
              if (entry != "") allow[entry] = 1
              next
            }
            NF && $NF ~ /^\// && ($NF in allow) { n++ }
            END { print n+0 }' "$SSI_ALLOW_SRC" -)
          SSI_UNSAFE=$(printf '%s\n' "$SSI_RAW" | awk 'NF && $NF ~ /^\// && $NF ~ /[][*?]/ { n++ } END { print n+0 }')
          [ -n "$SSI_EXC" ] || SSI_EXC=0
          [ -n "$SSI_UNSAFE" ] || SSI_UNSAFE=0
          SSI_UNKNOWN=$SSI_UNSAFE
          for SSI_P in $SSI_PATHS; do
            # Probe keys become fixture FILENAMES and fixture directories are
            # case-insensitive on macOS, so the whole key is lowercased: two
            # keys differing only in case would silently destroy each other.
            SSI_KEY=$(printf '%s\n' "$SSI_P" | awk '{ k = $0; gsub(/[^A-Za-z0-9]/, "_", k); k = tolower(k); sub(/^_+/, "", k); print "lslpp_w_" k }')
            # aixv, not aix: lslpp reports "not installed" on stderr, and that
            # diagnostic is exactly what separates a determinate "no fileset
            # owns this" from a probe that never answered.
            SSI_LW=$(aixv "$SSI_KEY" lslpp -w "$SSI_P"); SSI_LW_RC=$?
            if [ "$SSI_LW_RC" -eq 0 ] || [ "$SSI_LW_RC" -eq 1 ]; then
              SSI_CLASS=$(printf '%s\n' "$SSI_LW" | awk -v p="$SSI_P" '
                $1 == p && NF >= 2 && $2 ~ /^[A-Za-z][A-Za-z0-9_.+-]*$/ { owned = 1 }
                $1 == "File" && $2 == "Fileset" { answered = 1 }
                /^[ \t]*-----/ { answered = 1 }
                /^[ \t]*lslpp:/ { answered = 1 }
                END {
                  if (owned) print "owned"
                  else if (answered) print "unowned"
                  else print "unknown"
                }')
            else
              SSI_CLASS=unknown
            fi
            case "$SSI_CLASS" in
              owned) : ;;
              unowned) SSI_UNOWNED=$((SSI_UNOWNED + 1)) ;;
              *) SSI_UNKNOWN=$((SSI_UNKNOWN + 1)) ;;
            esac
          done
          if [ "$SSI_EXC" -gt 0 ]; then
            SSI_NOTE="$SSI_NOTE; +$SSI_EXC site exception(s)"
          fi
          if [ "$SSI_UNKNOWN" -gt 0 ]; then
            SSI_NOTE="$SSI_NOTE; $SSI_UNKNOWN unresolved"
          fi
          if [ "$SSI_UNOWNED" -gt 0 ]; then
            SSI_STATUS=FAIL
            SSI_OBSERVED="$SSI_UNOWNED of $SSI_TOTAL setuid/sgid file(s) are not owned by any installed fileset$SSI_NOTE"
          elif [ "$SSI_UNKNOWN" -gt 0 ]; then
            SSI_STATUS=NOT_ASSESSED
            SSI_OBSERVED="not assessed - fileset ownership unresolved for $SSI_UNKNOWN of $SSI_TOTAL setuid/sgid file(s)"
          else
            SSI_STATUS=PASS
            SSI_OBSERVED="all $SSI_TOTAL setuid/sgid file(s) are owned by an installed fileset, no site baseline$SSI_NOTE"
          fi
        fi
      fi
    fi
  fi

  case "$SSI_STATUS" in
    PASS)
      SSI_MEANING="Every setuid/setgid file found on this system is authorized, either by the site baseline or by ownership in an installed fileset."
      SSI_FIX="n/a"
      SSI_SEV=high
      ;;
    FAIL)
      SSI_MEANING="At least one setuid/setgid file exists on disk that no approved baseline entry, site exception, or installed fileset accounts for; it may be unauthorized."
      SSI_FIX="review each unaccounted file, approve or remove it, then record approvals in the baseline or the .allow exception file; AIXray only recommends this action."
      SSI_SEV=high
      ;;
    NOT_APPLICABLE)
      SSI_MEANING="A recorded decision states that no setuid/setgid inventory baseline is maintained, so the control is not applied."
      SSI_FIX="n/a"
      SSI_SEV=med
      ;;
    *)
      SSI_MEANING="AIXray could not resolve every setuid/setgid file to an authorization: either the inventory probe failed or fileset ownership could not be read for at least one path."
      SSI_FIX="rerun as root, confirm lslpp can query the software vital product database, or provision a readable baseline at /etc/security/aixray-suid-sgid-baseline, then rerun AIXray."
      SSI_SEV=med
      ;;
  esac

  add security suid_sgid "setuid/sgid inventory baseline" \
    "$SSI_STATUS" "$SSI_SEV" "$SSI_OBSERVED" "$SSI_MEANING" "$SSI_FIX" "cis-l1"
}

function standalone_run {
  standalone_check
}

standalone_main "$@"
exit $?
