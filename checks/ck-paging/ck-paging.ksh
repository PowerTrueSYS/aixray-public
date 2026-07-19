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

AIXRAY_TOOL=ck-paging


function standalone_check {

  # online volume groups (used by paging layout, vg_capacity, and the VG loop below)
  VGL=$(aix lsvg_o lsvg -o); VGLRC=$?
  VGL_OK=0; VGLWHY=""
  if [ "$VGLRC" -ne 0 ]; then
    VGLWHY="not assessed — lsvg -o capture failed (rc=$VGLRC)"
  elif [ -z "$VGL" ]; then
    VGLWHY="not assessed — lsvg -o capture empty (rc=0)"
  elif printf '%s\n' "$VGL" | awk '
      NF {
        n++
        if (NF != 1 || $1 !~ /^[A-Za-z0-9_.-][A-Za-z0-9_.-]*$/) bad=1
      }
      END { if (n == 0 || bad) exit 1 }
    '
  then
    VGL_OK=1
    FACT_STORAGE_VG_READ=1
  else
    VGLWHY="not assessed — lsvg -o capture unparseable (rc=0)"
  fi
  if [ "$VGL_OK" -eq 1 ]; then
    NVG=$(printf '%s\n' "$VGL" | awk 'NF{n++} END{print n+0}')
  else
    VGL=""; NVG=0
  fi

  # paging space
  LSPS=$(aix lsps_a lsps -a); LSPSRC=$?
  LSPS_OK=0; LSPSWHY=""
  if [ "$LSPSRC" -ne 0 ]; then
    LSPSWHY="not assessed — lsps -a capture failed (rc=$LSPSRC)"
  elif [ -z "$LSPS" ]; then
    LSPSWHY="not assessed — lsps -a capture empty (rc=0)"
  elif printf '%s\n' "$LSPS" | awk -v max_pct="$STOR_FACT_MAX_USED_PCT" '
      NR == 1 {
        if ($1 != "Page" || $2 != "Space" || $3 != "Physical" ||
            $4 != "Volume" || $5 != "Volume" || $6 != "Group" ||
            $7 != "Size" || $8 != "%Used" || $9 != "Active" ||
            $10 != "Auto" || $11 != "Type" || $12 != "Chksum") bad=1
        next
      }
      NF {
        n++
        if (NF < 9 ||
            $1 !~ /^[A-Za-z0-9_.-][A-Za-z0-9_.-]*$/ ||
            $2 !~ /^[A-Za-z0-9_.-][A-Za-z0-9_.-]*$/ ||
            $3 !~ /^[A-Za-z0-9_.-][A-Za-z0-9_.-]*$/ ||
            $4 !~ /^[0-9][0-9]*(MB|GB)$/ ||
            $5 !~ /^[0-9][0-9]*$/ || $5 + 0 > max_pct ||
            $6 !~ /^(yes|no)$/ || $7 !~ /^(yes|no)$/ ||
            $8 !~ /^[A-Za-z0-9_.-][A-Za-z0-9_.-]*$/ ||
            $9 !~ /^[0-9][0-9]*$/) bad=1
      }
      END { if (n == 0 || bad) exit 1 }
    '
  then
    LSPS_OK=1
    FACT_PAGING_READ=1
  else
    LSPSWHY="not assessed — lsps -a capture unparseable (rc=0)"
  fi
  if [ "$LSPS_OK" -eq 1 ]; then
    NPS=$(printf '%s\n' "$LSPS" | awk 'NR>1 && NF>1 {n++} END{print n+0}')
    MAXU=$(printf '%s\n' "$LSPS" | awk 'NR>1 && NF>1 {u=$5+0; if (u>mx) mx=u} END{print mx+0}')
    ALLROOT=$(printf '%s\n' "$LSPS" | awk 'NR>1 && NF>1 {t++; if ($3=="rootvg") r++} END{print (t>0 && r==t)?1:0}')
    DUPPV=$(printf '%s\n' "$LSPS" | awk 'NR>1 && NF>1 {c[$2]++} END{d=0; for (k in c) if (c[k]>1) d=1; print d}')
    NPS=$(printf '%s\n' "$LSPS" | awk 'NR>1 && NF>1{n++} END{if(n>0)print n}')
    if valid_json_number "$NPS"; then FACT_PAGING_SPACES="$NPS"; fi
    if [ -n "$FACT_PAGING_SPACES" ]; then
      MAXU_FACT=$(printf '%s\n' "$LSPS" | awk '
        NR>1 && NF>1 {n++; if($5 !~ /^[0-9][0-9]*$/) bad=1; else if(!seen || $5+0>mx){mx=$5+0; out=$5; seen=1}}
        END{if(n>0 && !bad && seen)print out}')
      if valid_json_number "$MAXU_FACT"; then FACT_PAGING_MAX="$MAXU_FACT"; fi
      [ "$ALLROOT" -eq 1 ] && FACT_PAGING_ROOT=true || FACT_PAGING_ROOT=false
      [ "$DUPPV" -eq 1 ] && FACT_PAGING_DUP=true || FACT_PAGING_DUP=false
    fi
    PGNOTE=""
    if [ "${NVG:-0}" -gt 1 ] && [ "$ALLROOT" -eq 1 ]; then
      PGNOTE=" Every paging space sits in rootvg while another VG is online — spreading paging onto another VG's disks avoids a rootvg I/O bottleneck."
    elif [ "$DUPPV" -eq 1 ]; then
      PGNOTE=" Multiple paging spaces share one physical volume — they contend for the same disk, so the extra space buys little."
    fi
    if [ "$MAXU" -ge 70 ]; then
      add storage paging "Paging space" FAIL high "$NPS space(s), ${MAXU}% used" \
          "The box is paging heavily — performance is suffering now, and paging-space-full kills processes.$PGNOTE" \
          "find the memory consumer (svmon -P | head); add RAM or paging space as a stopgap."
    elif [ "$MAXU" -ge 40 ]; then
      add storage paging "Paging space" WARN med "$NPS space(s), ${MAXU}% used" \
          "Sustained paging use signals memory pressure.$PGNOTE" "investigate memory consumers; review sizing."
    else
      add storage paging "Paging space" PASS low "$NPS space(s), ${MAXU}% used" "Memory pressure is low.$PGNOTE" "n/a"
    fi
  else
    add storage paging "Paging space" NOT_ASSESSED med "$LSPSWHY" \
        "Paging-space use could not be assessed because lsps -a failed, returned no evidence, or did not match the expected AIX output shape." \
        "run 'lsps -a' manually, then rerun AIXray before treating paging-space use as healthy."
  fi
}

function standalone_run {
  standalone_check
}

standalone_main "$@"
exit $?
