#!/bin/ksh
# Generated standalone AIXray check support. READ-ONLY: captures only; no
# remediation, service control, network access, or durable target-host writes.
set -u

# Match the monolith's guarded AIX command search path and parsing locale.
PATH=/usr/bin:/etc:/usr/sbin:/usr/ucb:/usr/bin/X11:/sbin:/usr/ios/cli:${PATH:-}
export PATH
LC_ALL=C
export LC_ALL

AIXRAY_STANDALONE_VERSION="1.2.0"

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

AIXRAY_TOOL=ck-sec-apars


function standalone_check {
_AIXRAY_SESSION_KEYS=""
SEC_APARS="
IJ55897|7300-03|CVE-2025-36250|NIM nimesis remote command execution
IJ56113|7300-02|CVE-2025-36250|NIM nimesis remote command execution
IJ56230|7300-01|CVE-2025-36250|NIM nimesis remote command execution
IJ55968|7200-05|CVE-2025-36250|NIM nimesis remote command execution
IJ59563|7300-04|CVE-2026-16923|AIX bos.mp64 local privilege escalation
IJ59564|7300-03|CVE-2026-16923|AIX bos.mp64 local privilege escalation
IJ59565|7300-02|CVE-2026-16923|AIX bos.mp64 local privilege escalation
IJ59566|7200-05|CVE-2026-16923|AIX bos.mp64 local privilege escalation
IJ57378|7300-04|HIPER-7278066|HIPER fix for devices.pciex.7710612214105006.com
IJ57303|7300-03|HIPER-7278066|HIPER fix for devices.pciex.7710612214105006.com
IJ57855|7200-05|HIPER-7278066|HIPER fix for devices.pciex.7710612214105006.com
"
OSLEVEL=$(aix oslevel_s oslevel -s); OSLEVEL_RC=$?
if [ "$OSLEVEL_RC" -eq 0 ] && [ -n "$OSLEVEL" ]; then FACT_OS_SOURCE_READ=1; fi
if [ "$OSLEVEL_RC" -eq 0 ]; then
  OSLEVEL=$(printf '%s\n' "$OSLEVEL" | awk -F- '
    NF==4 && $1 ~ /^[0-9][0-9][0-9][0-9]$/ && $2 ~ /^[0-9][0-9]$/ &&
      $3 ~ /^[0-9][0-9]$/ && $4 ~ /^[0-9][0-9][0-9][0-9]$/ {print; exit}')
else
  OSLEVEL=""
fi
REL=$(printf '%s' "$OSLEVEL" | awk -F- '{print $1}')
TLLEVEL=$(printf '%s' "$OSLEVEL" | awk -F- 'NF>=2{print $1"-"$2}')
  # sec_apars — tracked security APARs (bundled set, per-source vintage).
  # The established FLRT flow credits an APAR two ways: shipped in a fileset/SP (instfix -ik),
  # OR delivered as an interim fix. An ifix-delivered APAR is NOT in the installp fix
  # database, so instfix -ik alone FALSE-FAILS a box that applied the emergency ifix
  # but not yet the SP. emgr ifixes carry their APAR number in the LABEL (e.g.
  # IJ55968mAa) and ABSTRACT ("Fix for APAR IJ55968"); emgr -lv3 exposes both. We
  # extract that APAR set and count an APAR as addressed if an installed ifix covers it.
  # (Grounded on the real emgr LABEL/ABSTRACT shape; the lab LPAR has no efixes -> empty set.)
  EMGRV3=$(aix emgr_lv3 emgr -lv3); EMGRV3_RC=$?   # exit status kept: both the bundled-APAR
  # credit path and FLRTVC invoke path below must refuse this evidence when capture FAILED.
  # A silently-empty -e input reads to flrtvc.ksh as "no ifixes installed", so every
  # ifix-covered CVE would be reported as a false exposure
  # (adversarial review round 5, item 3). A genuinely efix-free box is rc=0 with EMPTY stdout (verified
  # live on both lab boxes: emgr prints "There is no efix data on this system." on STDERR, rc 0).
  IFIX_APARS=""
  if [ "$EMGRV3_RC" -eq 0 ]; then
    # Credit only APARs from complete, successfully-captured STABLE efix
    # sections.  A BROKEN (or otherwise non-STABLE) efix is not evidence that
    # its APAR is installed, and stdout from a failed capture is not evidence
    # at all.  Buffer LABEL/ABSTRACT candidates until STATE is known because
    # emgr prints LABEL before STATE in each section.
    IFIX_APARS=$(printf '%s\n' "$EMGRV3" | awk '
      function scan(s){
        while(match(s, /[A-Z][A-Z][0-9][0-9][0-9][0-9][0-9]/)){
          candidates=candidates substr(s,RSTART,7) "\n"
          s=substr(s,RSTART+RLENGTH)
        }
      }
      function flush(){
        if(state=="STABLE") printf "%s",candidates
        candidates=""; state=""; in_efix=0
      }
      /^[ \t]*EFIX ID:/ { flush(); in_efix=1; next }
      in_efix && /^[ \t]*LABEL:/    { scan($0); next }
      in_efix && /^[ \t]*ABSTRACT:/ { scan($0); next }
      in_efix && /^[ \t]*STATE:/ {
        state=$0
        sub(/^[^:]*:[ \t]*/,"",state)
        sub(/[ \t\r]+$/,"",state)
      }
      END{flush()}
    ' | sort -u | tr '\n' ' ')
  fi
  NAPP=0; MISS=""; VIA_IFIX=""; IOUT_EMPTY=""
  # ksh88-safe: a `cmd | while` runs the loop in a subshell on /bin/sh, discarding
  # NAPP/MISS. Feed SEC_APARS via a here-doc so the loop runs in THIS shell.
  while IFS='|' read APAR PREF CVE TITLE; do
    [ -z "$APAR" ] && continue
    [ "$PREF" = "$TLLEVEL" ] || continue
    NAPP=$((NAPP+1))
    IOUT=$(aix "instfix_ik_$APAR" instfix -ik "$APAR"); IOUT_RC=$?
    # instfix rc 249 with real stdout is ordinary "not installed".
    # Empty stdout is a failed capture — not evidence the APAR is missing.
    if [ -z "$IOUT" ]; then
      IOUT_EMPTY="$IOUT_EMPTY $APAR"
    elif [ "$IOUT_RC" -eq 0 ] || [ -n "$IOUT" ]; then
      # instfix says "All filesets for <APAR> were found." only when fully installed.
      # "Not all filesets for <APAR> were found." (and "no data ... in the fix
      # database.") both mean NOT installed — a bare "were found" match false-PASSes
      # on the "Not all" wording, so require "All filesets" AND reject "Not all".
      if printf '%s' "$IOUT" | grep -q "All filesets" && ! printf '%s' "$IOUT" | grep -q "Not all"; then
        :  # installed via fileset / Service Pack
      else
        case " $IFIX_APARS " in
          *" $APAR "*) VIA_IFIX="$VIA_IFIX $APAR" ;;   # addressed by an installed ifix
          *)           MISS="$MISS $APAR ($CVE)" ;;
        esac
      fi
    fi
  done <<SEC_APARS_EOF
$SEC_APARS
SEC_APARS_EOF
  if [ "$NAPP" -eq 0 ]; then
    add patch sec_apars "Tracked security APARs" NOT_ASSESSED high \
        "not assessed — no bundled security APAR rows apply to $TLLEVEL" \
        "Absence of a bundled row provides no evidence that the system has no CVE exposure." \
        "run current IBM flrtvc.ksh with a current apar.csv and pass the report via --flrtvc-report; review IBM PSIRT." \
        "ffiec:II.C.10"
  elif [ -n "$IOUT_EMPTY" ]; then
    add patch sec_apars "Tracked security APARs" NOT_ASSESSED high \
        "not assessed — instfix -ik produced no stdout for$IOUT_EMPTY" \
        "AIXray could not verify fileset coverage because instfix -ik returned empty stdout; that output was not used as evidence that the APAR is missing." \
        "rerun 'instfix -ik <APAR>' successfully, then rerun AIXray before treating tracked APAR coverage as complete." \
        "ffiec:II.C.10"
  elif [ "$EMGRV3_RC" -ne 0 ]; then
    add patch sec_apars "Tracked security APARs" NOT_ASSESSED high \
        "not assessed — emgr -lv3 capture failed (rc=$EMGRV3_RC)" \
        "AIXray could not verify interim-fix coverage because emgr -lv3 did not complete successfully; its stdout was not used as evidence." \
        "rerun 'emgr -lv3' successfully, then rerun AIXray before treating tracked APAR coverage as complete." \
        "ffiec:II.C.10"
  elif [ -n "$MISS" ]; then
    add patch sec_apars "Tracked security APARs" FAIL high "missing:$MISS" \
        "This box is exposed to published, fixed vulnerabilities — the fix exists and is not applied." \
        "apply the listed APARs (ifix or SP) from IBM Fix Central / PSIRT bulletin." "ffiec:II.C.10"
  else
    IFIXNOTE=""
    [ -n "$VIA_IFIX" ] && IFIXNOTE=" ($(printf '%s' "$VIA_IFIX" | wc -w | awk '{print $1}') via installed ifix:$VIA_IFIX)"
    add patch sec_apars "Tracked security APARs" PASS high "$NAPP of $NAPP tracked APARs present$IFIXNOTE" \
        "All tracked security APARs for this level are installed — by Service Pack or by an installed interim fix." "n/a" "ffiec:II.C.10"
  fi
}

function standalone_run {
  standalone_check
}

standalone_main "$@"
exit $?
