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

AIXRAY_TOOL=ck-rctcpip-hostmibd

# Shared, read-only /etc/rc.tcpip boot-inventory capture for the CIS rc.tcpip
# service checks. Emits one "daemon|boot_start" row per uncommented start
# invocation, including guarded forms such as
#   [ -z "$portmap_pid" ] && start /usr/sbin/portmap "${src_running}"
# Commented lines and the start() helper body never match.
function capture_cap_cis_rctcpip {
  typeset RCTCPIP_PARSE_RC
  RCTCPIP_CAPTURED=1
  RCTCPIP_RAW=$(aix cis_rctcpip cat /etc/rc.tcpip)
  RCTCPIP_RC=$?
  RCTCPIP_ROWS=""
  RCTCPIP_REASON=""
  RCTCPIP_READY=0

  if [ "$RCTCPIP_RC" -ne 0 ]; then
    RCTCPIP_REASON="capture failed (rc=$RCTCPIP_RC)"
    return 0
  fi
  if [ -z "$RCTCPIP_RAW" ]; then
    RCTCPIP_REASON="capture returned empty output"
    return 0
  fi
  case "$RCTCPIP_RAW" in
    *tcpip*) : ;;
    *)
      RCTCPIP_REASON="capture does not look like /etc/rc.tcpip"
      return 0
      ;;
  esac

  RCTCPIP_ROWS=$(printf '%s\n' "$RCTCPIP_RAW" | awk '
    {
      line = $0
      sub(/^[ \t]+/, "", line)
      if (line == "" || line ~ /^#/) next
      n = split(line, w, /[ \t]+/)
      for (i = 1; i < n; i++) {
        if (w[i] == "start" && w[i + 1] ~ /^\//) {
          m = split(w[i + 1], seg, "/")
          if (seg[m] != "") print seg[m] "|boot_start"
        }
      }
    }')
  RCTCPIP_PARSE_RC=$?
  if [ "$RCTCPIP_PARSE_RC" -ne 0 ]; then
    RCTCPIP_ROWS=""
    RCTCPIP_REASON="capture was unparseable"
    return 0
  fi
  RCTCPIP_READY=1
  return 0
}

# Shared, read-only SRC inventory capture for the CIS service checks.
function capture_cap_cis_services_lssrc_a {
  typeset CIS_SERVICES_PARSE_RC
  CIS_SERVICES_CAPTURED=1
  CIS_SERVICES_RAW=$(aix cis_services_lssrc_a lssrc -a)
  CIS_SERVICES_RC=$?
  CIS_SERVICES_ROWS=""
  CIS_SERVICES_REASON=""
  CIS_SERVICES_READY=0

  if [ "$CIS_SERVICES_RC" -ne 0 ]; then
    CIS_SERVICES_REASON="capture failed (rc=$CIS_SERVICES_RC)"
    return 0
  fi
  if [ -z "$CIS_SERVICES_RAW" ]; then
    CIS_SERVICES_REASON="capture returned empty output"
    return 0
  fi

  CIS_SERVICES_ROWS=$(printf '%s\n' "$CIS_SERVICES_RAW" | awk '
    NR == 1 {
      if (NF != 4 || $1 != "Subsystem" || $2 != "Group" ||
          $3 != "PID" || $4 != "Status") bad = 1
      next
    }
    # The Group column is OPTIONAL. `lssrc -a` on stock AIX emits group-less
    # subsystems -- aso, pfcdaemon, pmperfrec are present on both 7.2 and 7.3 --
    # so rows legitimately arrive with 2, 3 or 4 fields:
    #   name group pid active | name pid active | name group inoperative | name inoperative
    # Keying on a fixed field count rejected 9 of 74 real rows and, because this
    # parser fails closed, took the whole SRC inventory down with it. That made
    # CIS_SERVICES_READY=0 and refused 13 CIS controls (4.3.1.x/4.3.2.x) on every
    # real box, while the hand-authored fixture -- which happened to give every
    # subsystem a group -- parsed cleanly. Read positionally from the RIGHT, where
    # the layout is stable, and keep the shape strict so garbage still refuses.
    # Status vocabulary (R6.2): /usr/include/spc.h (the "Valid SRC status
    # ids" block, read on the AIX 7.2 lab LPAR, 2026-08-11) closes the
    # documented code set at 16. Only active, stopping and starting are
    # classified in_use here: active and stopping have been observed in
    # real subsystem rows holding a numeric PID, and starting is the
    # documented start-side twin of stopping in the same lifecycle. All
    # three are in_use for the CIS 4.3.1.x/4.3.2.x "ensure the service is
    # not in use" controls: a daemon that is starting or stopping is still
    # a running process in the scan window, and SRC itself refuses to start
    # a `stopping` subsystem with 0513-029 "already active". `inoperative`
    # is the only documented no-process rest state ever observed and stays
    # not_in_use. Every other token still discards the whole inventory: the
    # remaining documented codes have never been observed in a subsystem
    # row (several are multi-word and cannot survive this
    # whitespace-tokenized table), so classifying them would mean guessing
    # a shape never seen, and an inventory holding an unrecognised status
    # is not trustworthy evidence. No consumer may be handed a fabricated
    # PASS.
    NF {
      rows++
      name = $1
      state = $NF
      running = (state == "active" || state == "stopping" || state == "starting")
      if (running) {
        # a running or transitional subsystem always reports a numeric PID
        # immediately before its status word
        if (NF < 3 || $(NF - 1) !~ /^[0-9][0-9]*$/) bad = 1
      } else if (state == "inoperative") {
        if (NF < 2 || NF > 3) bad = 1
      } else bad = 1
      if (!bad) {
        if (running) normalized = "in_use"
        else normalized = "not_in_use"
        print name "|" normalized
      }
    }
    END { if (rows == 0 || bad) exit 1 }
  ')
  CIS_SERVICES_PARSE_RC=$?
  if [ "$CIS_SERVICES_PARSE_RC" -ne 0 ]; then
    CIS_SERVICES_ROWS=""
    CIS_SERVICES_REASON="capture was unparseable"
    return 0
  fi
  CIS_SERVICES_READY=1
  return 0
}


function standalone_check {
_AIXRAY_SESSION_KEYS=""
  # rctcpip_hostmibd — CIS IBM AIX 7 v1.2.0 4.3.2.6: hostmibd must not be in use.
  # Reuses the shared rc.tcpip boot inventory (RCTCPIP_*) and the shared SRC
  # inventory (CIS_SERVICES_*). Either trustworthy in-use side alone is
  # sufficient to FAIL; a clean PASS needs both sides trustworthy.
  typeset RT_HOSTMIBD_BOOT RT_HOSTMIBD_SRC RT_HOSTMIBD_DETAIL RT_HOSTMIBD_BOOT_RC RT_HOSTMIBD_SRC_RC
  typeset RT_HOSTMIBD_STATUS RT_HOSTMIBD_SEV RT_HOSTMIBD_OBS RT_HOSTMIBD_MEAN RT_HOSTMIBD_FIX
  if [ "${RCTCPIP_READY:-0}" -eq 1 ]; then
    RT_HOSTMIBD_BOOT=$(printf '%s\n' "$RCTCPIP_ROWS" | awk -F'|' '
      $1 == "hostmibd" { found = 1 }
      END { if (found) print "boot"; else print "no-boot" }')
    RT_HOSTMIBD_BOOT_RC=$?
    [ "$RT_HOSTMIBD_BOOT_RC" -ne 0 ] && RT_HOSTMIBD_BOOT=unknown
  else
    RT_HOSTMIBD_BOOT=unknown
  fi
  if [ "${CIS_SERVICES_READY:-0}" -eq 1 ]; then
    RT_HOSTMIBD_SRC=$(printf '%s\n' "$CIS_SERVICES_ROWS" | awk -F'|' '
      $1 == "hostmibd" { n++; if ($2 == "in_use") active = 1 }
      END {
        if (n > 1) print "duplicate"
        else if (active) print "in_use"
        else if (n > 0) print "not_in_use"
        else print "absent"
      }')
    RT_HOSTMIBD_SRC_RC=$?
    [ "$RT_HOSTMIBD_SRC_RC" -ne 0 ] && RT_HOSTMIBD_SRC=unknown
  else
    RT_HOSTMIBD_SRC=unknown
  fi

  RT_HOSTMIBD_DETAIL=""
  [ "$RT_HOSTMIBD_BOOT" = boot ] && RT_HOSTMIBD_DETAIL="starts at boot in /etc/rc.tcpip"
  if [ "$RT_HOSTMIBD_SRC" = in_use ]; then
    if [ -n "$RT_HOSTMIBD_DETAIL" ]; then
      RT_HOSTMIBD_DETAIL="$RT_HOSTMIBD_DETAIL and is active in the SRC inventory"
    else
      RT_HOSTMIBD_DETAIL="is active in the SRC inventory"
    fi
  fi

  if [ -n "$RT_HOSTMIBD_DETAIL" ]; then
    RT_HOSTMIBD_STATUS=FAIL
    RT_HOSTMIBD_SEV=high
    RT_HOSTMIBD_OBS="hostmibd $RT_HOSTMIBD_DETAIL"
    RT_HOSTMIBD_MEAN="The hostmibd dpi2 SNMP sub-agent serves RFC 2790 MIB variables and adds avoidable exposure where SNMP is not required."
    RT_HOSTMIBD_FIX="after service-owner approval, disable the boot entry ('chrctcp -d hostmibd') and stop the subsystem ('stopsrc -s hostmibd'); AIXray only recommends these actions."
  elif [ "$RT_HOSTMIBD_BOOT" = unknown ] || [ "$RT_HOSTMIBD_SRC" = unknown ] || [ "$RT_HOSTMIBD_SRC" = duplicate ]; then
    RT_HOSTMIBD_STATUS=NOT_ASSESSED
    RT_HOSTMIBD_SEV=low
    if [ "$RT_HOSTMIBD_SRC" = duplicate ]; then
      RT_HOSTMIBD_OBS="not assessed - hostmibd has duplicate SRC inventory rows"
    elif [ "$RT_HOSTMIBD_BOOT" = unknown ]; then
      RT_HOSTMIBD_OBS="not assessed - hostmibd rc.tcpip evidence $RCTCPIP_REASON"
    else
      RT_HOSTMIBD_OBS="not assessed - hostmibd SRC inventory $CIS_SERVICES_REASON"
    fi
    RT_HOSTMIBD_MEAN="AIXray did not obtain trustworthy service evidence from both /etc/rc.tcpip and the SRC inventory."
    RT_HOSTMIBD_FIX="make /etc/rc.tcpip readable and 'lssrc -a' return one complete inventory, then rerun AIXray."
  else
    RT_HOSTMIBD_STATUS=PASS
    RT_HOSTMIBD_SEV=low
    RT_HOSTMIBD_OBS="hostmibd not started in /etc/rc.tcpip and not active in the SRC inventory"
    RT_HOSTMIBD_MEAN="The hostmibd service is not in use."
    RT_HOSTMIBD_FIX="n/a"
  fi

  add security rctcpip_hostmibd "hostmibd service" \
    "$RT_HOSTMIBD_STATUS" "$RT_HOSTMIBD_SEV" \
    "$RT_HOSTMIBD_OBS" \
    "$RT_HOSTMIBD_MEAN" \
    "$RT_HOSTMIBD_FIX" \
    "cis-l1"
}

function standalone_run {
  capture_cap_cis_rctcpip || return 1
  capture_cap_cis_services_lssrc_a || return 1
  standalone_check
}

standalone_main "$@"
exit $?
