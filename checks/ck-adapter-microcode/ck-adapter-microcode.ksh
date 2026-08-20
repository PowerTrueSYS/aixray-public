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

AIXRAY_TOOL=ck-adapter-microcode

_AIXRAY_SESSION_KEYS=""
# Standalone fact and finding producer for AIX adapter firmware and microcode
# inventory. Include-safe: integration calls the fact emitter from the facts
# renderer and the check from the assessment spine.

function adapter_microcode_json_escape {
  awk '
    {
      s=$0
      gsub(/\\/, "\\\\", s)
      gsub(/"/, "\\\"", s)
      gsub(/\t/, "\\t", s)
      gsub(/\r/, "\\r", s)
      gsub(/[\001-\010\013\014\016-\037]/, "", s)
      if (seen++) printf "\\n"
      printf "%s", s
    }
  '
}

function adapter_microcode_lsdev_shape {
  awk '
    function is_location(value) {
      return value ~ /^[0-9][0-9]-[0-9][0-9](-[0-9][0-9])*$/ ||
        value ~ /^[A-Z][0-9][A-Za-z0-9.]*-[A-Za-z0-9][A-Za-z0-9.\/-]*$/
    }
    NF {
      rows++
      if (NF < 3 || $1 !~ /^[A-Za-z][A-Za-z0-9_.-]*$/ ||
          $2 !~ /^[A-Za-z][A-Za-z0-9_-]*$/ || seen[$1]++) {
        bad=1
        next
      }
      first=3
      if (is_location($3)) first=4
      description=""
      for (i=first; i<=NF; i++)
        description=description (description=="" ? "" : " ") $i
      if (description=="") bad=1
    }
    END { if (rows==0 || bad) exit 1 }
  '
}

function adapter_microcode_parse_lsdev {
  awk '
    function is_location(value) {
      return value ~ /^[0-9][0-9]-[0-9][0-9](-[0-9][0-9])*$/ ||
        value ~ /^[A-Z][0-9][A-Za-z0-9.]*-[A-Za-z0-9][A-Za-z0-9.\/-]*$/
    }
    NF {
      first=3
      if (is_location($3)) first=4
      description=""
      for (i=first; i<=NF; i++)
        description=description (description=="" ? "" : " ") $i
      category=$1
      sub(/[0-9][0-9]*$/, "", category)
      if (category=="") category="adapter"
      printf "%s\t%s\t%s\n", $1, category, description
    }
  '
}

# Validate the whole lsmcode capture and print its recognized layout. Bang
# records may have typed continuation rows (for example raid-dasd); columnar
# records require only a device token plus a nonempty remainder, never a fixed
# number of fields.
function adapter_microcode_lsmcode_shape {
  awk '
    function trim(value) {
      sub(/^[ \t]+/, "", value)
      sub(/[ \t]+$/, "", value)
      return value
    }
    function valid_name(value) {
      return value ~ /^[A-Za-z][A-Za-z0-9_.-]*$/
    }
    {
      line=$0
      sub(/\r$/, "", line)
      line=trim(line)
      if (line=="") next

      if (mode=="") {
        bang=index(line, "!")
        if (bang>1) {
          mode="bang"
        } else {
          count=split(line, header, /[ \t]+/)
          has_level=0
          for (i=2; i<=count; i++)
            if (tolower(header[i]) ~ /level/) has_level=1
          if (tolower(header[1])=="device" && has_level) {
            mode="column"
            next
          }
          bad=1
          next
        }
      }

      if (mode=="bang") {
        bang=index(line, "!")
        if (bang>1) {
          name=substr(line, 1, bang-1)
          level=trim(substr(line, bang+1))
          if (!valid_name(name) || level=="" || seen[name]++) bad=1
          else records++
          have_record=1
        } else if (!(have_record && line ~ /^[A-Za-z][A-Za-z0-9-]*:[^ \t]/)) {
          bad=1
        }
      } else {
        if (line ~ /^-+[ \t]+-+/) next
        name=line
        sub(/[ \t].*$/, "", name)
        level=line
        sub(/^[^ \t][^ \t]*[ \t][ \t]*/, "", level)
        level=trim(level)
        if (!valid_name(name) || tolower(name)=="device" ||
            level==line || level=="" || seen[name]++) bad=1
        else records++
      }
    }
    END {
      if (bad || records==0) exit 1
      print mode
    }
  '
}

function adapter_microcode_lsmcode_level {
  typeset wanted layout
  wanted=$1
  layout=$2
  awk -v wanted="$wanted" -v layout="$layout" '
    function trim(value) {
      sub(/^[ \t]+/, "", value)
      sub(/[ \t]+$/, "", value)
      return value
    }
    function unavailable(value, normalized) {
      value=trim(value)
      normalized=tolower(value)
      gsub(/[ _-]/, "", normalized)
      if (normalized=="unknown" || normalized=="notavailable" ||
          normalized=="notapplicable" || normalized=="none" ||
          normalized=="n/a") return 1
      return 0
    }
    function usable(value) {
      value=trim(value)
      if (unavailable(value)) return 0
      if (value !~ /[0-9]/ || value ~ /[^A-Za-z0-9_.:+#|() \/-]/) return 0
      return 1
    }
    {
      line=$0
      sub(/\r$/, "", line)
      line=trim(line)
      if (line=="") next

      if (layout=="bang") {
        bang=index(line, "!")
        if (bang>1) {
          current=substr(line, 1, bang-1)
          if (current==wanted) {
            if (found) bad=1
            value=trim(substr(line, bang+1))
            found=1
          }
        } else if (current==wanted && line ~ /^[A-Za-z][A-Za-z0-9-]*:/) {
          value=value "|" line
        }
      } else {
        if (!header_seen) {
          header_seen=1
          next
        }
        if (line ~ /^-+[ \t]+-+/) next
        name=line
        sub(/[ \t].*$/, "", name)
        rest=line
        sub(/^[^ \t][^ \t]*[ \t][ \t]*/, "", rest)
        rest=trim(rest)
        if (name==wanted) {
          if (found) bad=1
          value=rest
          found=1
        }
      }
    }
    END {
      if (!found) exit 1
      gsub(/[ \t]+/, " ", value)
      value=trim(value)
      if (bad) exit 3
      if (unavailable(value)) {
        print value
        exit 2
      }
      if (!usable(value)) exit 3
      print value
    }
  '
}

function adapter_microcode_lscfg_shape {
  typeset wanted
  wanted=$1
  awk -v wanted="$wanted" '
    function trim(value) {
      sub(/^[ \t]+/, "", value)
      sub(/[ \t]+$/, "", value)
      return value
    }
    {
      line=$0
      sub(/\r$/, "", line)
      if (line ~ /^[ \t]*$/) next

      nonblank++
      if (nonblank==1) {
        header=line
        sub(/^[ \t]+/, "", header)
        name=header
        sub(/[ \t].*$/, "", name)
        remainder=header
        sub(/^[^ \t][^ \t]*[ \t][ \t]*/, "", remainder)
        if (name!=wanted || remainder==header || trim(remainder)=="") bad=1
        next
      }

      if (line ~ /^[ \t]+[^ \t].*[.][.][.]/) {
        label=line
        sub(/^[ \t]+/, "", label)
        sub(/[.][.][.].*$/, "", label)
        if (trim(label)=="") bad=1
        else vpd++
      }
    }
    END { if (bad || nonblank==0 || vpd==0) exit 1 }
  '
}

function adapter_microcode_lscfg_level {
  awk '
    function trim(value) {
      sub(/^[ \t]+/, "", value)
      sub(/[ \t]+$/, "", value)
      return value
    }
    function label_type(value) {
      value=tolower(value)
      if (value ~ /rom level[.][(]alterable[)]/) return 1
      if (value ~ /microcode([ \t]*level)?/) return 2
      if (value ~ /firmware[ \t]*level/) return 3
      if (value ~ /device specific[.][(]z9[)]/) return 4
      return 0
    }
    function field_value(value) {
      if (value ~ /[.][.][.]/)
        sub(/^.*[.][.][.][.]*[ \t]*/, "", value)
      else if (value ~ /:/)
        sub(/^[^:]*:[ \t]*/, "", value)
      else
        return ""
      return trim(value)
    }
    function usable(value, normalized) {
      value=trim(value)
      normalized=tolower(value)
      gsub(/[ _-]/, "", normalized)
      if (normalized=="unknown" || normalized=="notavailable" ||
          normalized=="notapplicable" || normalized=="none" ||
          normalized=="n/a") return 0
      if (value !~ /[0-9]/ || value ~ /[^A-Za-z0-9_.:+#|() \/-]/) return 0
      return 1
    }
    {
      kind=label_type($0)
      candidate=field_value($0)
      if (kind && usable(candidate) && (!found || kind<best)) {
        best=kind
        value=candidate
        found=1
      }
    }
    END {
      if (!found) exit 1
      gsub(/[ \t]+/, " ", value)
      print trim(value)
    }
  '
}

function adapter_microcode_emit_unavailable {
  typeset reason escaped
  reason=$1
  escaped=$(printf '%s' "$reason" | adapter_microcode_json_escape)
  printf '%s' '"adapter_microcode": { "status": "NOT_ASSESSED", "platform": "AIX", '
  printf '%s' '"inventory_source_cmd": "lsdev -Cc adapter", "primary_source_cmd": "lsmcode -A", '
  printf '"capture_gaps": ["%s"], "reason": "%s", "adapters": null }' \
    "$escaped" "$escaped"
}

function emit_fact_adapter_microcode {
  typeset LSDEV_OUT LSDEV_RC LSDEV_ROWS LSDEV_WHY
  typeset LSMCODE_OUT LSMCODE_RC LSMCODE_LAYOUT LSMCODE_SHAPE_RC LSMCODE_WHY
  typeset DEV CATEGORY DESCRIPTION LEVEL SOURCE STATUS REASON
  typeset LSM_LEVEL LSM_LEVEL_RC LSM_REASON LSCFG_OUT LSCFG_RC LSCFG_WHY
  typeset ITEMS ITEM KNOWN UNKNOWN TOP_STATUS TOP_REASON
  typeset EDEV ECATEGORY EDESCRIPTION ELEVEL ESOURCE EREASON ETOP_REASON EGAP

  LSDEV_OUT=$(aix lsdev_adapter lsdev -Cc adapter)
  LSDEV_RC=$?
  if [ "$LSDEV_RC" -ne 0 ]; then
    LSDEV_WHY="lsdev -Cc adapter capture failed (rc=$LSDEV_RC)"
    adapter_microcode_emit_unavailable "$LSDEV_WHY"
    return
  fi
  if [ -z "$LSDEV_OUT" ]; then
    adapter_microcode_emit_unavailable "lsdev -Cc adapter capture empty (rc=0)"
    return
  fi
  if ! printf '%s\n' "$LSDEV_OUT" | adapter_microcode_lsdev_shape; then
    adapter_microcode_emit_unavailable "lsdev -Cc adapter capture unparseable (rc=0)"
    return
  fi
  LSDEV_ROWS=$(printf '%s\n' "$LSDEV_OUT" | adapter_microcode_parse_lsdev)

  LSMCODE_OUT=$(aix lsmcode_A lsmcode -A)
  LSMCODE_RC=$?
  LSMCODE_LAYOUT=""
  LSMCODE_WHY=""
  if [ "$LSMCODE_RC" -ne 0 ]; then
    LSMCODE_WHY="lsmcode -A capture failed (rc=$LSMCODE_RC)"
  elif [ -z "$LSMCODE_OUT" ]; then
    LSMCODE_WHY="lsmcode -A capture empty (rc=0)"
  else
    LSMCODE_LAYOUT=$(printf '%s\n' "$LSMCODE_OUT" | adapter_microcode_lsmcode_shape)
    LSMCODE_SHAPE_RC=$?
    if [ "$LSMCODE_SHAPE_RC" -ne 0 ] || [ -z "$LSMCODE_LAYOUT" ]; then
      LSMCODE_LAYOUT=""
      LSMCODE_WHY="lsmcode -A capture unparseable (rc=0)"
    fi
  fi

  ITEMS=""
  KNOWN=0
  UNKNOWN=0
  while IFS='	' read -r DEV CATEGORY DESCRIPTION
  do
    [ -n "$DEV" ] || continue
    LEVEL=""
    SOURCE=""
    STATUS="NOT_ASSESSED"
    REASON=""
    LSM_REASON="$LSMCODE_WHY"

    if [ -n "$LSMCODE_LAYOUT" ]; then
      LSM_LEVEL=$(printf '%s\n' "$LSMCODE_OUT" |
        adapter_microcode_lsmcode_level "$DEV" "$LSMCODE_LAYOUT")
      LSM_LEVEL_RC=$?
      case "$LSM_LEVEL_RC" in
        0)
          LEVEL=$LSM_LEVEL
          SOURCE="lsmcode -A"
          STATUS="OBSERVED"
          ;;
        1)
          LSM_REASON="lsmcode -A did not report $DEV"
          ;;
        2)
          LSM_REASON="lsmcode -A device reported microcode level $LSM_LEVEL for $DEV"
          ;;
        *)
          LSM_REASON="lsmcode -A record for $DEV unparseable (rc=0)"
          ;;
      esac
    fi

    if [ "$STATUS" != "OBSERVED" ]; then
      LSCFG_OUT=$(aix "lscfg_vpl_$DEV" lscfg -vpl "$DEV")
      LSCFG_RC=$?
      LSCFG_WHY=""
      if [ "$LSCFG_RC" -ne 0 ]; then
        LSCFG_WHY="lscfg -vpl $DEV capture failed (rc=$LSCFG_RC)"
      elif [ -z "$LSCFG_OUT" ]; then
        LSCFG_WHY="lscfg -vpl $DEV capture empty (rc=0)"
      elif ! printf '%s\n' "$LSCFG_OUT" |
          adapter_microcode_lscfg_shape "$DEV"; then
        LSCFG_WHY="lscfg -vpl $DEV capture unparseable (rc=0)"
      else
        LEVEL=$(printf '%s\n' "$LSCFG_OUT" | adapter_microcode_lscfg_level)
        if [ -n "$LEVEL" ]; then
          SOURCE="lscfg -vpl $DEV"
          STATUS="OBSERVED"
        else
          LSCFG_WHY="lscfg -vpl $DEV: no microcode/firmware level reported by device (no usable ROM/MicroCode/Firmware/Z9 VPD value)"
        fi
      fi
      if [ "$STATUS" != "OBSERVED" ]; then
        REASON="$LSM_REASON${LSM_REASON:+; }$LSCFG_WHY"
        SOURCE="lsmcode -A; lscfg -vpl $DEV"
      fi
    fi

    EDEV=$(printf '%s' "$DEV" | adapter_microcode_json_escape)
    ECATEGORY=$(printf '%s' "$CATEGORY" | adapter_microcode_json_escape)
    EDESCRIPTION=$(printf '%s' "$DESCRIPTION" | adapter_microcode_json_escape)
    ESOURCE=$(printf '%s' "$SOURCE" | adapter_microcode_json_escape)
    if [ "$STATUS" = "OBSERVED" ]; then
      ELEVEL=$(printf '%s' "$LEVEL" | adapter_microcode_json_escape)
      ITEM=$(printf '%s' "{ \"name\": \"$EDEV\", \"category\": \"$ECATEGORY\", \"description\": \"$EDESCRIPTION\", \"microcode_level\": \"$ELEVEL\", \"source_cmd\": \"$ESOURCE\", \"status\": \"OBSERVED\", \"reason\": null }")
      KNOWN=$((KNOWN + 1))
    else
      EREASON=$(printf '%s' "$REASON" | adapter_microcode_json_escape)
      ITEM=$(printf '%s' "{ \"name\": \"$EDEV\", \"category\": \"$ECATEGORY\", \"description\": \"$EDESCRIPTION\", \"microcode_level\": null, \"source_cmd\": \"$ESOURCE\", \"status\": \"NOT_ASSESSED\", \"reason\": \"$EREASON\" }")
      UNKNOWN=$((UNKNOWN + 1))
    fi
    if [ -n "$ITEMS" ]; then ITEMS="$ITEMS, $ITEM"; else ITEMS=$ITEM; fi
  done <<EOF
$LSDEV_ROWS
EOF

  TOP_REASON=""
  if [ "$KNOWN" -eq 0 ]; then
    TOP_STATUS="NOT_ASSESSED"
    TOP_REASON="no enumerated adapter had a trustworthy microcode level; see per-adapter reasons"
  elif [ "$UNKNOWN" -eq 0 ]; then
    TOP_STATUS="COMPLETE"
  else
    TOP_STATUS="PARTIAL"
  fi

  printf '"adapter_microcode": { "status": "%s", "platform": "AIX", ' "$TOP_STATUS"
  printf '%s' '"inventory_source_cmd": "lsdev -Cc adapter", "primary_source_cmd": "lsmcode -A", '
  if [ -n "$LSMCODE_WHY" ]; then
    EGAP=$(printf '%s' "$LSMCODE_WHY" | adapter_microcode_json_escape)
    printf '"capture_gaps": ["%s"], ' "$EGAP"
  else
    printf '%s' '"capture_gaps": [], '
  fi
  if [ -n "$TOP_REASON" ]; then
    ETOP_REASON=$(printf '%s' "$TOP_REASON" | adapter_microcode_json_escape)
    printf '"reason": "%s", ' "$ETOP_REASON"
  else
    printf '%s' '"reason": null, '
  fi
  printf '"adapters": [%s] }' "$ITEMS"
}

# A finding is the assessment surface for this tool. Inventory facts remain
# available separately, but they must never be the only evidence that the
# adapter-microcode topic ran.
function check_adapter_microcode {
  typeset AM_OUT AM_RC AM_PHYSICAL AM_NOUN AM_VERB AM_OBS AM_MEAN AM_FIX

  AM_OUT=$(aix lsdev_adapter lsdev -Cc adapter); AM_RC=$?
  if [ "$AM_RC" -ne 0 ]; then
    AM_OBS="not assessed — lsdev -Cc adapter inventory failed (rc=$AM_RC)"
    AM_MEAN="Adapter inventory was unavailable, so this LPAR's physical-adapter microcode ownership and currency could not be assessed."
    AM_FIX="restore access to 'lsdev -Cc adapter', then rerun AIXray; review any physical adapter levels against the current hardware-specific reference."
  elif [ -z "$AM_OUT" ]; then
    AM_OBS="not assessed — lsdev -Cc adapter reported no adapters (rc=0)"
    AM_MEAN="An empty adapter inventory cannot establish whether this LPAR owns physical adapter microcode."
    AM_FIX="verify the complete output of 'lsdev -Cc adapter' and rerun AIXray."
  elif ! printf '%s\n' "$AM_OUT" | adapter_microcode_lsdev_shape; then
    AM_OBS="not assessed — lsdev -Cc adapter inventory was unparseable (rc=0)"
    AM_MEAN="The adapter inventory did not match the expected AIX lsdev structure, so physical-adapter ownership and microcode currency could not be assessed."
    AM_FIX="capture the complete output of 'lsdev -Cc adapter', correct the replay source if needed, and rerun AIXray."
  else
    AM_PHYSICAL=$(printf '%s\n' "$AM_OUT" |
      awk 'NF && /PCI/{n++} END{print n+0}')
    if [ "$AM_PHYSICAL" -eq 0 ]; then
      AM_OBS="not assessed — no physical adapters were reported by lsdev -Cc adapter; virtual and pseudo-device inventory alone has no LPAR-owned adapter microcode to assess"
      AM_MEAN="This LPAR reported only virtual or pseudo adapters; their physical firmware is owned by the VIOS, hypervisor, or cloud provider rather than by this LPAR."
      AM_FIX="review adapter firmware and microcode on the owning VIOS, hypervisor, or provider control plane."
    else
      AM_NOUN=adapters; AM_VERB=were
      if [ "$AM_PHYSICAL" -eq 1 ]; then
        AM_NOUN=adapter; AM_VERB=was
      fi
      AM_OBS="not assessed — $AM_PHYSICAL physical $AM_NOUN $AM_VERB inventoried, but installed levels were not compared with current hardware-specific reference data"
      AM_MEAN="Physical adapters are present, but inventory alone cannot establish whether their installed microcode is current."
      AM_FIX="collect each physical adapter's installed level and compare it with the current IBM hardware-specific microcode guidance."
    fi
  fi

  add lifecycle adapter_microcode "Adapter microcode currency" \
    NOT_ASSESSED high "$AM_OBS" "$AM_MEAN" "$AM_FIX"
}

function standalone_run {
  check_adapter_microcode
}

standalone_main "$@"
exit $?
