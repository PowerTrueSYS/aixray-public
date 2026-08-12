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

AIXRAY_TOOL=ck-errpt-signatures

# Shared detailed seven-day error-log capture used by signature analysis.
function capture_cap_errpt_a7 {
  ERA=$(aix errpt_a7 errpt -a -s "$C7"); ERA_RC=$?
  return "$ERA_RC"
}


function standalone_check {
_AIXRAY_SESSION_KEYS=""

  # errpt_signatures (LEVEL 3) — scan for the classic PRE-FAILURE signatures a veteran watches
  # for: disk media/hardware errors (drive about to fail), SCSI/FC path errors, EPOW power or
  # thermal events, memory/CPU ECC scan errors (a DIMM dying), adapter resets, LVM disk loss
  # (QUORCLOSE/PVMISS), and dump-device faults. Veteran signal: these are the patterns that mean
  # a component is degrading NOW, before it fails hard — the "it caught my disk before it died"
  # check. A genuine signature (PERM, recurring, power/memory/LVM/dump) FAILs high; a single
  # recovered (TEMP) event WARNs.
  typeset ERA_OK ERAWHY ERA_SHAPE_RC
  ERA_OK=0; ERAWHY=""
  if [ "${ERA_RC:-127}" -ne 0 ]; then
    ERAWHY="not assessed — errpt -a capture failed (rc=${ERA_RC:-127})"
  elif [ -z "$ERA" ]; then
    # A quiet AIX error log is valid evidence when errpt itself returned rc=0.
    ERA_OK=1
  else
    printf '%s\n' "$ERA" | awk '
    function begin_stanza() {
      label=identifier=date_time=sequence=machine=node=class=type=description=0
      in_stanza=1
    }
    function end_stanza() {
      if (!in_stanza) return
      if (label != 1 || identifier != 1 || date_time != 1 ||
          sequence != 1 || machine != 1 || node != 1 || class != 1 ||
          type != 1 || description != 1) bad=1
      in_stanza=0
    }
    /^----------[-]*$/ {
      end_stanza()
      separator=1
      next
    }
    $1 == "LABEL:" {
      if (in_stanza) {
        bad=1
        end_stanza()
      }
      if (!separator) bad=1
      begin_stanza()
      stanzas++
      separator=0
      label++
      if (NF != 2 || $2 !~ /^[A-Z0-9_][A-Z0-9_]*$/) bad=1
      next
    }
    !in_stanza {
      if (NF) bad=1
      next
    }
    $1 == "IDENTIFIER:" {
      identifier++
      if (NF != 2 || length($2) != 8 ||
          $2 !~ /^[0-9A-Fa-f][0-9A-Fa-f]*$/) bad=1
      next
    }
    $1 == "Date/Time:" {
      date_time++
      if (NF < 5) bad=1
      next
    }
    $1 == "Sequence" && $2 == "Number:" {
      sequence++
      if (NF != 3 || $3 !~ /^[0-9][0-9]*$/) bad=1
      next
    }
    $1 == "Machine" && $2 == "Id:" {
      machine++
      if (NF != 3 || $3 !~ /^[0-9A-Fa-f][0-9A-Fa-f]*$/) bad=1
      next
    }
    $1 == "Node" && $2 == "Id:" {
      node++
      if (NF != 3) bad=1
      next
    }
    $1 == "Class:" {
      class++
      if (NF != 2 || $2 !~ /^(H|S|O|U)$/) bad=1
      next
    }
    $1 == "Type:" {
      type++
      if (NF != 2 || $2 !~ /^[A-Z][A-Z]*$/) bad=1
      next
    }
    $1 == "Description" {
      description++
      if (NF != 1) bad=1
      next
    }
    END {
      end_stanza()
      if (stanzas == 0 || bad) exit 1
    }
  '
    ERA_SHAPE_RC=$?
    if [ "$ERA_SHAPE_RC" -eq 0 ]; then
      ERA_OK=1
    else
      ERAWHY="not assessed — errpt -a capture unparseable (rc=0)"
    fi
  fi

  if [ "$ERA_OK" -ne 1 ]; then
    add errors errpt_signatures "Pre-failure signatures" NOT_ASSESSED high "$ERAWHY" \
        "The detailed seven-day error-log capture could not be trusted, so AIXray did not infer that no pre-failure signatures were present." \
        "run 'errpt -a -s <MMDDhhmmyy>'; resolve the reported capture failure or malformed output, then rerun AIXray."
  else
    SIGS=$(printf '%s\n' "$ERA" | awk '
    function rec(){
      if(!have) return
      have=0
      if(typ=="INFO") return
      fam=""
      if(lab ~ /DISK_ERR/) fam="disk"
      else if(lab ~ /SCSI_ERR|SCSI_ARRAY|FCP_|FSCSI|FCS_ERR|SAS_/) fam="fc_scsi"
      else if(lab ~ /EPOW/) fam="power"
      else if(lab ~ /SCAN_ERROR|CACHE|MEMORY|_MEM/ && cls=="H") fam="memory"
      else if(lab ~ /LVM_SA_QUORCLOSE|LVM_SA_PVMISS|LVM_IO_FAIL/) fam="lvm"
      else if(lab ~ /ADAP/) fam="adapter"
      else if(lab ~ /DMPCHK|FWDMP|FWADUMP|PLAT_DUMP_ERR/) fam="dump"
      if(fam=="") return
      cnt[fam]++; ex[fam]=lab
      if(typ=="PERM") perm[fam]=1
      if(cnt[fam]>1) recur[fam]=1
    }
    BEGIN{
      NM["disk"]="disk pre-failure"; NM["fc_scsi"]="SAN/SCSI path errors"
      NM["power"]="environmental/power (EPOW)"; NM["memory"]="memory/CPU (ECC)"
      NM["lvm"]="LVM disk loss"; NM["adapter"]="adapter reset/error"; NM["dump"]="dump-device fault"
    }
    $1=="LABEL:"{ rec(); lab=$2; have=1; cls=""; typ="" }
    $1=="Class:"{ cls=$2 }
    $1=="Type:"{ typ=$2 }
    END{
      rec()
      m=split("disk fc_scsi power memory lvm adapter dump", FO, " ")
      out=""; hi=0
      for(i=1;i<=m;i++){ f=FO[i]; if(f in cnt){
        out=out (out==""?"":"; ") NM[f] ": " ex[f] " x" cnt[f]
        if(perm[f] || recur[f] || f=="power" || f=="memory" || f=="lvm" || f=="dump") hi=1
      }}
      printf "%d\t%s", hi, out
    }')
  SHI=$(printf '%s' "$SIGS" | awk -F'\t' '{print $1+0}')
  SLIST=$(printf '%s' "$SIGS" | awk -F'\t' '{print $2}')
  if [ -n "$SLIST" ]; then
    if [ "$SHI" -eq 1 ]; then
      add errors errpt_signatures "Pre-failure signatures" FAIL high "$SLIST" \
          "The error log carries classic pre-failure hardware signatures — the patterns a veteran watches for that mean a component is degrading now, before it fails hard: $SLIST." \
          "inspect each with 'errpt -a -j <IDENTIFIER>', run 'diag' against the named resource, and engage hardware/SAN support before it fails outright."
    else
      add errors errpt_signatures "Pre-failure signatures" WARN med "$SLIST" \
          "A pre-failure signature appeared, but so far only as a single recovered (TEMP) event — worth watching, not yet an emergency: $SLIST." \
          "keep an eye on it with 'errpt -a -j <IDENTIFIER>'; if it recurs or turns PERM, treat the named resource as failing."
    fi
  else
    add errors errpt_signatures "Pre-failure signatures" PASS high "none in 7 days" \
        "None of the classic pre-failure patterns a veteran hunts for — disk/adapter errors, SAN/SCSI path faults, EPOW power or thermal events, memory ECC errors, LVM disk loss, or dump-device faults — appear in the error log for the last 7 days." "n/a"
  fi
  fi
}

function standalone_run {
  capture_cap_errpt_a7 || :
  standalone_check
}

standalone_main "$@"
exit $?
