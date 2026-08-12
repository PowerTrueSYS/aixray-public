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

AIXRAY_TOOL=ck-remote-rcmd-filesets


function standalone_check {
_AIXRAY_SESSION_KEYS=""
  # remote_rcmd_filesets — mode boundary on the legacy r-command client and
  # server filesets. The client (bos.net.tcp.rcmd) and server
  # (bos.net.tcp.rcmd_server) filesets must be uninstalled, or every file they
  # own must carry no permission bits: regular files `----------`, directories
  # `d---------`. Symlinks are tolerated with a distinct meaning; vanished paths refuse.
  # Presence is keyed on lslpp -L rc (0 installed, 1 absent), never on stdout
  # emptiness — an absent-fileset query still prints column headers.
  typeset RRFS_SRV_RAW RRFS_SRV_RC RRFS_CLI_RAW RRFS_CLI_RC
  typeset RRFS_SRV_F_RAW RRFS_SRV_F_RC RRFS_SRV_F_LIST
  typeset RRFS_CLI_F_RAW RRFS_CLI_F_RC RRFS_CLI_F_LIST
  typeset RRFS_FILE_LIST RRFS_PATH RRFS_KEY
  typeset RRFS_LS_RAW RRFS_LS_RC RRFS_MODE
  typeset RRFS_STATUS RRFS_REASON RRFS_OBSERVED RRFS_MEANING RRFS_FIX
  typeset RRFS_VIOLATIONS RRFS_INSPECTED RRFS_BAD_PATH RRFS_BAD_MODE
  typeset RRFS_UNASSESSED RRFS_UNASSESSED_PATH RRFS_VANISHED RRFS_VANISHED_PATH RRFS_SYMLINKS RRFS_TOTAL
  typeset RRFS_MEANING_OVERRIDE
  RRFS_STATUS=""
  RRFS_REASON=""
  RRFS_OBSERVED=""
  RRFS_BAD_PATH=""
  RRFS_BAD_MODE=""
  RRFS_FILE_LIST=""
  RRFS_MEANING_OVERRIDE=""

  RRFS_SRV_RAW=$(aix lslpp_L_rcmd_server lslpp -L bos.net.tcp.rcmd_server)
  RRFS_SRV_RC=$?
  RRFS_CLI_RAW=$(aix lslpp_L_rcmd lslpp -L bos.net.tcp.rcmd)
  RRFS_CLI_RC=$?

  case "$RRFS_SRV_RC" in
    0|1) ;;
    *) RRFS_STATUS=NOT_ASSESSED
       RRFS_REASON="lslpp -L bos.net.tcp.rcmd_server exited $RRFS_SRV_RC (expected 0 or 1)"
       ;;
  esac
  if [ -z "$RRFS_STATUS" ]; then
    case "$RRFS_CLI_RC" in
      0|1) ;;
      *) RRFS_STATUS=NOT_ASSESSED
         RRFS_REASON="lslpp -L bos.net.tcp.rcmd exited $RRFS_CLI_RC (expected 0 or 1)"
         ;;
    esac
  fi

  if [ -z "$RRFS_STATUS" ]; then
    if [ "$RRFS_SRV_RC" -eq 1 ] && [ "$RRFS_CLI_RC" -eq 1 ]; then
      RRFS_STATUS=PASS
      RRFS_OBSERVED="neither bos.net.tcp.rcmd nor bos.net.tcp.rcmd_server is installed (lslpp -L rc=1 for both)"
    else
      # At least one fileset is installed; enumerate the files it owns.
      if [ "$RRFS_SRV_RC" -eq 0 ]; then
        RRFS_SRV_F_RAW=$(aix lslpp_f_rcmd_server lslpp -f bos.net.tcp.rcmd_server)
        RRFS_SRV_F_RC=$?
        if [ "$RRFS_SRV_F_RC" -ne 0 ]; then
          RRFS_STATUS=NOT_ASSESSED
          RRFS_REASON="lslpp -f bos.net.tcp.rcmd_server exited $RRFS_SRV_F_RC for a fileset reported installed"
        else
          RRFS_SRV_F_LIST=$(printf '%s\n' "$RRFS_SRV_F_RAW" | awk '$0 ~ /^ +\// { print $1 }')
          if [ -n "$RRFS_SRV_F_LIST" ]; then
            RRFS_FILE_LIST="$RRFS_SRV_F_LIST"
          fi
        fi
      fi
      if [ -z "$RRFS_STATUS" ] && [ "$RRFS_CLI_RC" -eq 0 ]; then
        RRFS_CLI_F_RAW=$(aix lslpp_f_rcmd lslpp -f bos.net.tcp.rcmd)
        RRFS_CLI_F_RC=$?
        if [ "$RRFS_CLI_F_RC" -ne 0 ]; then
          RRFS_STATUS=NOT_ASSESSED
          RRFS_REASON="lslpp -f bos.net.tcp.rcmd exited $RRFS_CLI_F_RC for a fileset reported installed"
        else
          RRFS_CLI_F_LIST=$(printf '%s\n' "$RRFS_CLI_F_RAW" | awk '$0 ~ /^ +\// { print $1 }')
          if [ -n "$RRFS_CLI_F_LIST" ]; then
            if [ -z "$RRFS_FILE_LIST" ]; then
              RRFS_FILE_LIST="$RRFS_CLI_F_LIST"
            else
              RRFS_FILE_LIST="$RRFS_FILE_LIST
$RRFS_CLI_F_LIST"
            fi
          fi
        fi
      fi
    fi
  fi

  if [ -z "$RRFS_STATUS" ] && [ -n "$RRFS_FILE_LIST" ]; then
    RRFS_VIOLATIONS=0
    RRFS_INSPECTED=0
    RRFS_UNASSESSED=0
    RRFS_UNASSESSED_PATH=""
    RRFS_VANISHED=0
    RRFS_VANISHED_PATH=""
    RRFS_SYMLINKS=0
    RRFS_TOTAL=0
    while read RRFS_PATH; do
      [ -n "$RRFS_PATH" ] || continue
      RRFS_TOTAL=$((RRFS_TOTAL+1))
      # A probe key becomes a FIXTURE FILENAME (<set>/<key>.out), so an
      # interpolated absolute path makes the key name a nested directory that
      # does not exist: capture mode cannot write it and replay cannot read
      # it, so aix() returns 127 and this check refuses on a file it has
      # ALREADY proven exists. Flatten the path the same way
      # ck-cron-command-paths does. The 'ls_led_' key namespace is unused
      # elsewhere in this repo, so no sanitized key can collide with an
      # existing one.
      RRFS_KEY=$(printf '%s' "$RRFS_PATH" | tr '/' '_')

      # Classify from the capture alone — never probe the scanning host.
      if aix_capture_missing "ls_led_$RRFS_KEY"; then
        RRFS_UNASSESSED=$((RRFS_UNASSESSED+1))
        if [ -z "$RRFS_UNASSESSED_PATH" ]; then
          RRFS_UNASSESSED_PATH="$RRFS_PATH"
        fi
        continue
      fi

      RRFS_LS_RAW=$(aix "ls_led_$RRFS_KEY" ls -led "$RRFS_PATH")
      RRFS_LS_RC=$?

      if [ "$RRFS_LS_RC" -ne 0 ]; then
        if [ "$RRFS_VANISHED" -eq 0 ]; then
          RRFS_VANISHED_PATH="$RRFS_PATH"
        fi
        RRFS_VANISHED=$((RRFS_VANISHED+1))
        continue
      fi

      RRFS_MODE=$(printf '%s\n' "$RRFS_LS_RAW" | awk '
        NF {
          if (mode == "") mode = $1
        }
        END { print mode }')

      if [ -z "$RRFS_MODE" ]; then
        # Genuinely corrupted capture — no mode field. If violations have
        # already been found, do not suppress them; just skip this path.
        if [ "$RRFS_VIOLATIONS" -eq 0 ]; then
          RRFS_STATUS=NOT_ASSESSED
          RRFS_REASON="ls -led on $RRFS_PATH returned empty output"
          break
        fi
        continue
      fi

      case "$RRFS_MODE" in
        l*)
          RRFS_SYMLINKS=$((RRFS_SYMLINKS+1))
          ;;
        d---------*|----------*)
          RRFS_INSPECTED=$((RRFS_INSPECTED+1))
          ;;
        *)
          if [ "$RRFS_VIOLATIONS" -eq 0 ]; then
            RRFS_BAD_PATH="$RRFS_PATH"
            RRFS_BAD_MODE="$RRFS_MODE"
          fi
          RRFS_VIOLATIONS=$((RRFS_VIOLATIONS+1))
          ;;
      esac
    done <<EOF
$RRFS_FILE_LIST
EOF
    if [ -z "$RRFS_STATUS" ]; then
      # Adverse evidence always stands — a gap must never suppress a
      # violation that was actually observed.
      if [ "$RRFS_VIOLATIONS" -gt 0 ]; then
        RRFS_STATUS=FAIL
        RRFS_OBSERVED="$RRFS_VIOLATIONS r-command file(s) carry a mode outside the 000 boundary (first: $RRFS_BAD_MODE $RRFS_BAD_PATH)"
        if [ "$RRFS_UNASSESSED" -gt 0 ]; then
          RRFS_OBSERVED="$RRFS_OBSERVED; $RRFS_UNASSESSED further path(s) had no captured evidence and were not assessed"
        fi
      elif [ "$RRFS_UNASSESSED" -gt 0 ]; then
        RRFS_STATUS=NOT_ASSESSED
        RRFS_OBSERVED="not assessed — $RRFS_UNASSESSED of $RRFS_TOTAL r-command file(s) have no captured evidence (first: $RRFS_UNASSESSED_PATH)"
      elif [ "$RRFS_INSPECTED" -gt 0 ]; then
        RRFS_STATUS=PASS
        RRFS_OBSERVED="$RRFS_INSPECTED r-command file(s) inspected, all mode 000"
        if [ "$RRFS_VANISHED" -gt 0 ]; then
          RRFS_OBSERVED="$RRFS_OBSERVED; $RRFS_VANISHED vanished path(s) excluded"
        fi
        if [ "$RRFS_SYMLINKS" -gt 0 ]; then
          if [ "$RRFS_VANISHED" -gt 0 ]; then
            RRFS_OBSERVED="$RRFS_OBSERVED, $RRFS_SYMLINKS symlink(s)"
          else
            RRFS_OBSERVED="$RRFS_OBSERVED; $RRFS_SYMLINKS symlink(s) excluded"
          fi
        fi
      elif [ "$RRFS_VANISHED" -gt 0 ]; then
        RRFS_STATUS=NOT_ASSESSED
        RRFS_OBSERVED="not assessed — $RRFS_VANISHED of $RRFS_TOTAL r-command file(s) owned by an installed fileset could not be stat'd (ls -led exited nonzero; first: $RRFS_VANISHED_PATH), so no mode was measured for any of them"
      elif [ "$RRFS_SYMLINKS" -gt 0 ]; then
        RRFS_STATUS=PASS
        RRFS_OBSERVED="$RRFS_SYMLINKS of $RRFS_TOTAL owned path(s) are symbolic links and none is a regular file or directory — no in-scope file to inspect"
        RRFS_MEANING_OVERRIDE="Every path owned by the installed r-command fileset(s) is a symbolic link. This control's mode boundary constrains regular files and directories, and the fileset owns none at these paths; the link targets belong to other filesets and were not inspected."
      else
        RRFS_STATUS=NOT_ASSESSED
        RRFS_OBSERVED="not assessed — no inspectable files, symlinks, or vanished paths accounted for in the r-command filesets"
      fi
    fi
  fi

  if [ -z "$RRFS_STATUS" ]; then
    RRFS_STATUS=NOT_ASSESSED
    RRFS_OBSERVED="not assessed — installed r-command fileset(s) reported no files"
  fi

  if [ "$RRFS_STATUS" = "NOT_ASSESSED" ] && [ -z "$RRFS_OBSERVED" ]; then
    RRFS_OBSERVED="not assessed — $RRFS_REASON"
  fi

  case "$RRFS_STATUS" in
    PASS)
      if [ -n "$RRFS_MEANING_OVERRIDE" ]; then
        RRFS_MEANING="$RRFS_MEANING_OVERRIDE"
      else
        RRFS_MEANING="No legacy r-command client or server file is readable, writable, or executable: the filesets are uninstalled, or every file they own carries no permission bits."
      fi
      RRFS_FIX="n/a"
      ;;
    FAIL)
      RRFS_MEANING="At least one file owned by the legacy r-command filesets exposes a read, write, or execute permission bit, so the r-command attack surface may be reachable."
      RRFS_FIX="after validating each path, remove every permission bit with 'chmod 000 <path>', or uninstall the filesets with 'installp -ug bos.net.tcp.rcmd' and 'installp -ug bos.net.tcp.rcmd_server' once no workload needs them; AIXray recommends these commands and never executes them."
      ;;
    *)
      RRFS_MEANING="AIXray did not obtain trustworthy package-inventory or mode evidence for the legacy r-command filesets."
      RRFS_FIX="run 'lslpp -L bos.net.tcp.rcmd_server' and 'lslpp -L bos.net.tcp.rcmd' as root, resolve the probe or output-shape problem, and rerun AIXray."
      ;;
  esac

  add security remote_rcmd_filesets "r-command client/server filesets mode" \
    "$RRFS_STATUS" low "$RRFS_OBSERVED" \
    "$RRFS_MEANING" "$RRFS_FIX" "cis-l1"
}

function standalone_run {
  standalone_check
}

standalone_main "$@"
exit $?
