#!/bin/ksh
# Generated standalone AIXray check support. READ-ONLY: captures only; no
# remediation, service control, network access, or durable target-host writes.
set -u

# Match the monolith's guarded AIX command search path and parsing locale.
PATH=/usr/bin:/etc:/usr/sbin:/usr/ucb:/usr/bin/X11:/sbin:/usr/ios/cli:${PATH:-}
export PATH
LC_ALL=C
export LC_ALL

AIXRAY_STANDALONE_VERSION="0.1.0"

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
    PASS|WARN|FAIL|NOT_ASSESSED) ;;
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

function d2j {
  typeset y m d a
  y=${1%%-*}
  m=${1#*-}; m=${m%%-*}
  d=${1##*-}
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
  TODAY=${AIXRAY_TODAY:-$(date +%Y-%m-%d)}
  TODAY_J=$(d2j "$TODAY")
  C7=$(errpt_cutoff 7)
  C30=$(errpt_cutoff 30)
  MYUID=$(aix id_u id -u)
  [ -n "$MYUID" ] || MYUID=1
  if [ -n "${AIXRAY_TODAY:-}" ]; then
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
  typeset i assessed run_rc
  if [ "$#" -ne 1 ] || [ "$1" != "--json" ]; then
    echo "usage: $0 --json" >&2
    return 2
  fi
  if [ -z "${AIXRAY_FIXTURES:-}" ] && [ "$(uname -s 2>/dev/null)" != "AIX" ]; then
    echo "$AIXRAY_TOOL: this standalone check runs on AIX/VIOS" >&2
    return 2
  fi
  standalone_initialize || return 1
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

AIXRAY_TOOL=ck-fc-errors


function standalone_check {

  # fc_errors — Fibre Channel adapter error counters (cumulative since boot)
  LSADP=$(aix lsdev_adapter lsdev -c adapter)
  FCS=$(printf '%s\n' "$LSADP" | awk '$1 ~ /^fcs[0-9]+$/ {print $1}')
  if [ -n "$FCS" ]; then
    FCBAD=0; FCTXT=""; FCNR=0; FCN=0; FCUR=0
    for A in $FCS; do
      FCN=$((FCN+1))
      FST=$(aix "fcstat_$A" fcstat "$A"); FRC=$?
      # $2+0 keeps the sign: virtual FC (PowerVS/NPIV) reports counters as -1 = "not available".
      # END-emitted "NA" marks a counter line that was ABSENT (distinct from a zero value).
      LF=$(printf '%s\n' "$FST" | awk -F: '/Link Failure Count/{print $2+0; f=1; exit} END{if(!f)print "NA"}')
      LS=$(printf '%s\n' "$FST" | awk -F: '/Loss of Sync Count/{print $2+0; f=1; exit} END{if(!f)print "NA"}')
      CRC=$(printf '%s\n' "$FST" | awk -F: '/Invalid CRC Count/{print $2+0; f=1; exit} END{if(!f)print "NA"}')
      # unreadable: fcstat failed, or NONE of the three counter lines were present.
      # This must not synthesize a clean PASS the way "$2+0 of empty = 0" used to.
      if [ "$FRC" -ne 0 ] || { [ "$LF" = NA ] && [ "$LS" = NA ] && [ "$CRC" = NA ]; }; then
        FCTXT="$FCTXT${FCTXT:+; }$A: counters unreadable"
        FCUR=$((FCUR+1))
        continue
      fi
      [ "$LF" = NA ] && LF=0; [ "$LS" = NA ] && LS=0; [ "$CRC" = NA ] && CRC=0
      if [ "$CRC" -lt 0 ] && [ "$LF" -lt 0 ] && [ "$LS" -lt 0 ]; then
        FCTXT="$FCTXT${FCTXT:+; }$A: counters not reported (virtual FC)"
        FCNR=$((FCNR+1))
        continue
      fi
      [ "$CRC" -lt 0 ] && CRC=0
      [ "$LF" -lt 0 ] && LF=0
      [ "$LS" -lt 0 ] && LS=0
      FCTXT="$FCTXT${FCTXT:+; }$A: CRC ${CRC:-0}, link-fail ${LF:-0}, loss-sync ${LS:-0}"
      { [ "${CRC:-0}" -gt 0 ] || [ "${LF:-0}" -gt 10 ]; } && FCBAD=1
    done
    if [ "$FCBAD" -eq 1 ]; then
      add storage fc_errors "Fibre Channel adapter errors" WARN med "$FCTXT" \
          "A Fibre Channel adapter reports CRC errors or repeated link failures. These counts are cumulative since boot, so confirm whether they are still climbing." \
          "check SAN cabling, the SFP, and the switch port for the flagged adapter; compare 'fcstat <fcs>' over time."
    elif [ "$FCUR" -gt 0 ]; then
      add storage fc_errors "Fibre Channel adapter errors" WARN low "$FCTXT" \
          "One or more FC adapters returned no readable error counters — a clean pass cannot be claimed for them (a healthy adapter reports zeros, not nothing)." \
          "run 'fcstat <fcs>' as root; on virtual FC the counters live on the VIOS."
    elif [ "$FCNR" -eq "$FCN" ]; then
      # Believability review 2026-07-13 (review-queue #62, finding #9): this used to PASS
      # here — but "counters not reported" means the CRC/link-failure observation was
      # never captured at all (virtual FC never exposes it in-LPAR), the same gap the
      # FCUR>0 branch above already correctly treats as NOT a clean pass. A missing
      # observation must render NOT_ASSESSED, never PASS, regardless of WHY it is missing.
      add storage fc_errors "Fibre Channel adapter errors" NOT_ASSESSED low "$FCTXT" \
          "Virtual FC adapters do not expose error counters inside the LPAR, so CRC/link-failure health could not be observed from here at all — this is not evidence of a clean adapter, just an architectural blind spot. Check path health on the VIOS side." "n/a"
    else
      add storage fc_errors "Fibre Channel adapter errors" PASS low "$FCTXT" \
          "No CRC or excessive link errors on the FC adapters (cumulative since boot)." "n/a"
    fi
  fi
}

function standalone_run {
  standalone_check
}

standalone_main "$@"
exit $?
