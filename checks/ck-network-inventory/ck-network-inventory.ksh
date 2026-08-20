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

AIXRAY_TOOL=ck-network-inventory

_AIXRAY_SESSION_KEYS=""
# Standalone fact and finding producer for AIX interface, route, and resolver
# inventory. Include-safe: integration calls the fact emitter from the facts
# renderer and the check from the assessment spine.

function network_inventory_json_escape {
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

function network_inventory_ifconfig_shape {
  awk '
    function ipv4(value, part, count, i) {
      count=split(value, part, ".")
      if (count!=4) return 0
      for (i=1; i<=4; i++)
        if (part[i] !~ /^[0-9][0-9]*$/ || part[i]+0>255) return 0
      return 1
    }
    function netmask(value, raw) {
      if (ipv4(value)) return 1
      raw=value
      sub(/^0[xX]/, "", raw)
      return substr(raw,8,1)!="" && substr(raw,9,1)=="" &&
        raw ~ /^[0-9A-Fa-f][0-9A-Fa-f]*$/
    }
    function ipv6_component(value, allow_ipv4) {
      if (index(value, ".")>0) {
        if (!allow_ipv4 || !ipv4(value)) return 0
        return 2
      }
      if (substr(value,1,1)=="" || substr(value,5,1)!="" ||
          value !~ /^[0-9A-Fa-f][0-9A-Fa-f]*$/) return 0
      return 1
    }
    function ipv6_side(value, allow_ipv4, part, count, i, units, size) {
      count=split(value, part, ":")
      units=0
      for (i=1; i<=count; i++) {
        size=ipv6_component(part[i], allow_ipv4 && i==count)
        if (size==0) return -1
        units+=size
      }
      return units
    }
    function ipv6(value, percent, zone, compression, remainder, left,
                  right, left_units, right_units, total) {
      percent=index(value, "%")
      if (percent>0) {
        zone=substr(value, percent+1)
        if (zone=="" || index(zone, "%")>0 ||
            zone !~ /^[A-Za-z0-9_.-][A-Za-z0-9_.-]*$/) return 0
        value=substr(value, 1, percent-1)
      }
      if (value=="" || index(value, ":")==0) return 0
      compression=index(value, "::")
      if (compression>0) {
        remainder=substr(value, compression+2)
        if (index(remainder, "::")>0) return 0
        left=substr(value, 1, compression-1)
        right=remainder
        left_units=0
        right_units=0
        if (left!="") left_units=ipv6_side(left, 0)
        if (right!="") right_units=ipv6_side(right, 1)
        if (left_units<0 || right_units<0) return 0
        total=left_units+right_units
        return total<8
      }
      if (value ~ /^:/ || value ~ /:$/) return 0
      total=ipv6_side(value, 1)
      return total==8
    }
    function ipv6_prefix(value, slash, address, prefix) {
      slash=index(value, "/")
      if (slash==0) return ipv6(value)
      address=substr(value, 1, slash-1)
      prefix=substr(value, slash+1)
      if (address=="" || prefix !~ /^[0-9][0-9]*$/ ||
          prefix+0>128 || index(prefix, "/")>0) return 0
      return ipv6(address)
    }
    /^[ \t\r]*$/ { next }
    /^[^ \t]/ {
      if ($0 !~ /^[A-Za-z][A-Za-z0-9_.-]*:[ \t]*flags=[^<]*<[^>]*>/) {
        bad=1
        next
      }
      name=$1
      sub(/:.*/, "", name)
      if (name !~ /^[A-Za-z][A-Za-z0-9_.-]*$/ || seen[name]++) bad=1
      current=name
      headers++
      for (i=1; i<=NF; i++) {
        if ($i=="mtu") {
          mtu++
          if (i==NF || $(i+1) !~ /^[1-9][0-9]*$/) bad=1
        }
      }
      next
    }
    {
      if (current=="") { bad=1; next }
      if ($1=="inet") {
        if (!ipv4($2)) { bad=1; next }
        masks=0
        for (i=3; i<=NF; i++) {
          if ($i=="netmask") {
            masks++
            if (i==NF || !netmask($(i+1))) bad=1
          }
        }
        if (masks!=1) bad=1
      } else if ($1=="inet6") {
        if (!ipv6_prefix($2)) bad=1
      } else if ($1=="tcp_sendspace" || $1=="tcp_recvspace" ||
                 $1=="rfc1323") {
        if (NF<2 || NF%2!=0) { bad=1; next }
        for (i=1; i<=NF; i+=2) {
          if (($i!="tcp_sendspace" && $i!="tcp_recvspace" &&
               $i!="rfc1323") ||
              $(i+1) !~ /^[0-9][0-9]*$/) bad=1
        }
      } else {
        bad=1
      }
    }
    END { if (bad || headers==0) exit 1 }
  '
}

function network_inventory_parse_ifconfig {
  awk '
    /^[ \t\r]*$/ { next }
    /^[^ \t]/ {
      name=$1
      sub(/:.*/, "", name)
      flags=$0
      sub(/^[^<]*</, "", flags)
      sub(/>.*/, "", flags)
      count=split(flags, flag, ",")
      state="down"
      for (i=1; i<=count; i++) if (flag[i]=="UP") state="up"
      mtu=""
      for (i=1; i<=NF; i++) if ($i=="mtu") mtu=$(i+1)
      current=name
      printf "I\t%s\t%s\t%s\n", name, state, mtu
      next
    }
    $1=="inet" {
      mask=""
      for (i=3; i<=NF; i++) if ($i=="netmask") mask=$(i+1)
      printf "A\t%s\t%s\t%s\n", current, $2, mask
    }
  '
}

function network_inventory_lsattr_shape {
  awk '
    /^[ \t\r]*$/ { next }
    $1=="mtu" {
      seen++
      if (NF<2 || $2 !~ /^[1-9][0-9]*$/) bad=1
    }
    END { if (bad || seen!=1) exit 1 }
  '
}

function network_inventory_entstat_shape {
  typeset NI_ES_WANTED
  NI_ES_WANTED=$1
  awk -v wanted="$NI_ES_WANTED" '
    function trim(value) {
      sub(/^[ \t]+/, "", value)
      sub(/[ \t]+$/, "", value)
      return value
    }
    /^ETHERNET STATISTICS \(/ {
      value=$0
      sub(/^[^(]*\(/, "", value)
      sub(/\).*/, "", value)
      headers++
      if (value!=wanted) bad=1
    }
    /^Device Type:/ {
      value=$0
      sub(/^[^:]*:[ \t]*/, "", value)
      types++
      if (trim(value)=="") bad=1
    }
    END { if (bad || headers!=1 || types!=1) exit 1 }
  '
}

function network_inventory_entstat_type {
  awk '
    /^Device Type:/ {
      sub(/^[^:]*:[ \t]*/, "")
      sub(/[ \t]+$/, "")
      print
      exit
    }
  '
}

function network_inventory_entstat_speed {
  awk '
    function trim(value) {
      sub(/^[ \t]+/, "", value)
      sub(/[ \t]+$/, "", value)
      return value
    }
    function label(kind) {
      if (kind=="media") return "Media Speed Running"
      return "Adapter Data Rate"
    }
    function parse_speed(value, kind, part, unit, shown, number) {
      value=trim(value)
      split(value, part, /[ \t]+/)
      rows[kind]++
      shown=part[1]
      if (part[2]!="") shown=shown " " part[2]
      if (shown_values[kind]!="") shown_values[kind]=shown_values[kind] ", "
      shown_values[kind]=shown_values[kind] shown

      if (part[1] !~ /^[1-9][0-9]*$/) {
        reason[kind]=label(kind) " reported a non-numeric value"
        return
      }
      if (part[2]=="") {
        reason[kind]=label(kind) " value lacked a unit"
        return
      }
      number=part[1]
      unit=tolower(part[2])
      if (unit=="mbps") {
        converted[kind]=number
      } else if (unit=="gbps") {
        converted[kind]=(number * 1000)
      } else {
        reason[kind]=label(kind) " reported an unrecognized unit"
      }
    }
    /^Media Speed Running:/ {
      value=$0
      sub(/^[^:]*:[ \t]*/, "", value)
      parse_speed(value, "media")
    }
    /^Adapter Data Rate:/ {
      value=$0
      sub(/^[^:]*:[ \t]*/, "", value)
      parse_speed(value, "rate")
    }
    END {
      if (rows["media"]>0) kind="media"
      else if (rows["rate"]>0) kind="rate"
      else {
        print "NOT_ASSESSED|did not report media speed or adapter data rate"
        exit
      }

      if (rows[kind]!=1) {
        print "NOT_ASSESSED|" label(kind) " reported multiple rows (values: " shown_values[kind] ")"
      } else if (reason[kind]!="") {
        print "NOT_ASSESSED|" reason[kind]
      } else {
        print "OBSERVED|" converted[kind]
      }
    }
  '
}

function network_inventory_netstat_shape {
  awk '
    function ipv4(value, part, count, i) {
      count=split(value, part, ".")
      if (count!=4) return 0
      for (i=1; i<=4; i++)
        if (part[i] !~ /^[0-9][0-9]*$/ || part[i]+0>255) return 0
      return 1
    }
    function ipv6_component(value, allow_ipv4) {
      if (index(value, ".")>0) {
        if (!allow_ipv4 || !ipv4(value)) return 0
        return 2
      }
      if (substr(value,1,1)=="" || substr(value,5,1)!="" ||
          value !~ /^[0-9A-Fa-f][0-9A-Fa-f]*$/) return 0
      return 1
    }
    function ipv6_side(value, allow_ipv4, part, count, i, units, size) {
      count=split(value, part, ":")
      units=0
      for (i=1; i<=count; i++) {
        size=ipv6_component(part[i], allow_ipv4 && i==count)
        if (size==0) return -1
        units+=size
      }
      return units
    }
    function ipv6(value, percent, zone, compression, remainder, left,
                  right, left_units, right_units, total) {
      percent=index(value, "%")
      if (percent>0) {
        zone=substr(value, percent+1)
        if (zone=="" || index(zone, "%")>0 ||
            zone !~ /^[A-Za-z0-9_.-][A-Za-z0-9_.-]*$/) return 0
        value=substr(value, 1, percent-1)
      }
      if (value=="" || index(value, ":")==0) return 0
      compression=index(value, "::")
      if (compression>0) {
        remainder=substr(value, compression+2)
        if (index(remainder, "::")>0) return 0
        left=substr(value, 1, compression-1)
        right=remainder
        left_units=0
        right_units=0
        if (left!="") left_units=ipv6_side(left, 0)
        if (right!="") right_units=ipv6_side(right, 1)
        if (left_units<0 || right_units<0) return 0
        total=left_units+right_units
        return total<8
      }
      if (value ~ /^:/ || value ~ /:$/) return 0
      total=ipv6_side(value, 1)
      return total==8
    }
    {
      lower=tolower($0)
      if ($1=="Routing" && $2=="tables") headers++
      if (lower ~ /protocol family[ \t]+24([ \t(:]|$)/ ||
          lower ~ /internet v6/) {
        family="ipv6"
        families++
        next
      }
      if (lower ~ /protocol family[ \t]+2([ \t(:]|$)/) {
        family="ipv4"
        families++
        next
      }
      if ($1=="default" || $1=="0.0.0.0" ||
          $1=="::/0" || $1=="::0/0") {
        route_family=family
        if ($1=="0.0.0.0") route_family="ipv4"
        if ($1=="::/0" || $1=="::0/0") route_family="ipv6"
        defaults++
        if (NF<3 || $3 !~ /^[A-Za-z][A-Za-z]*$/ || route_family=="" ||
            (route_family=="ipv4" && !ipv4($2)) ||
            (route_family=="ipv6" && !ipv6($2))) bad=1
      }
    }
    END { if (bad || headers!=1 || families==0) exit 1 }
  '
}

function network_inventory_parse_netstat {
  awk '
    {
      lower=tolower($0)
      if (lower ~ /protocol family[ \t]+24([ \t(:]|$)/ ||
          lower ~ /internet v6/) {
        family="ipv6"
        next
      }
      if (lower ~ /protocol family[ \t]+2([ \t(:]|$)/) {
        family="ipv4"
        next
      }
      if ($1=="default" || $1=="0.0.0.0" ||
          $1=="::/0" || $1=="::0/0") {
        route_family=family
        if ($1=="0.0.0.0") route_family="ipv4"
        if ($1=="::/0" || $1=="::0/0") route_family="ipv6"
        iface=""
        for (i=3; i<=NF; i++)
          if ($i ~ /^[A-Za-z][A-Za-z_.-]*[0-9][0-9]*$/) iface=$i
        if (iface=="")
          printf "%s\t%s\t\tPARTIAL\tnetstat -rn default route did not expose an interface\n", route_family, $2
        else
          printf "%s\t%s\t%s\tOBSERVED\t\n", route_family, $2, iface
      }
    }
  '
}

function network_inventory_resolv_shape {
  awk '
    function ipv4(value, part, count, i) {
      count=split(value, part, ".")
      if (count!=4) return 0
      for (i=1; i<=4; i++)
        if (part[i] !~ /^[0-9][0-9]*$/ || part[i]+0>255) return 0
      return 1
    }
    function ipv6_component(value, allow_ipv4) {
      if (index(value, ".")>0) {
        if (!allow_ipv4 || !ipv4(value)) return 0
        return 2
      }
      if (substr(value,1,1)=="" || substr(value,5,1)!="" ||
          value !~ /^[0-9A-Fa-f][0-9A-Fa-f]*$/) return 0
      return 1
    }
    function ipv6_side(value, allow_ipv4, part, count, i, units, size) {
      count=split(value, part, ":")
      units=0
      for (i=1; i<=count; i++) {
        size=ipv6_component(part[i], allow_ipv4 && i==count)
        if (size==0) return -1
        units+=size
      }
      return units
    }
    function ipv6(value, percent, zone, compression, remainder, left,
                  right, left_units, right_units, total) {
      percent=index(value, "%")
      if (percent>0) {
        zone=substr(value, percent+1)
        if (zone=="" || index(zone, "%")>0 ||
            zone !~ /^[A-Za-z0-9_.-][A-Za-z0-9_.-]*$/) return 0
        value=substr(value, 1, percent-1)
      }
      if (value=="" || index(value, ":")==0) return 0
      compression=index(value, "::")
      if (compression>0) {
        remainder=substr(value, compression+2)
        if (index(remainder, "::")>0) return 0
        left=substr(value, 1, compression-1)
        right=remainder
        left_units=0
        right_units=0
        if (left!="") left_units=ipv6_side(left, 0)
        if (right!="") right_units=ipv6_side(right, 1)
        if (left_units<0 || right_units<0) return 0
        total=left_units+right_units
        return total<8
      }
      if (value ~ /^:/ || value ~ /:$/) return 0
      total=ipv6_side(value, 1)
      return total==8
    }
    /^[ \t\r]*$/ { next }
    /^[ \t]*[#;]/ { next }
    {
      if ($1=="nameserver") {
        if (NF<2 || (!ipv4($2) && !ipv6($2))) { bad=1; next }
        for (i=3; i<=NF; i++) {
          if (substr($i,1,1)=="#" || substr($i,1,1)==";") break
          bad=1
        }
      } else if ($1=="domain" || $1=="search" || $1=="sortlist" ||
                 $1=="options" || $1=="lookup") {
        if (NF<2) bad=1
      } else {
        bad=1
      }
    }
    END { if (bad) exit 1 }
  '
}

function network_inventory_parse_resolv {
  awk '
    /^[ \t]*nameserver[ \t]+/ { print $2 }
  '
}

function network_inventory_append_gap {
  typeset NI_AG_CURRENT NI_AG_REASON NI_AG_ESCAPED
  NI_AG_CURRENT=$1
  NI_AG_REASON=$2
  NI_AG_ESCAPED=$(printf '%s' "$NI_AG_REASON" |
    network_inventory_json_escape)
  if [ -n "$NI_AG_CURRENT" ]; then
    printf '%s, "%s"' "$NI_AG_CURRENT" "$NI_AG_ESCAPED"
  else
    printf '"%s"' "$NI_AG_ESCAPED"
  fi
}

function emit_fact_network_inventory {
  typeset NI_IFCONFIG NI_IFCONFIG_RC NI_IF_WHY NI_IF_SOURCE NI_PARSED
  typeset NI_NAMES NI_IF_ITEMS NI_IF_PARTIAL NI_IF NI_STATE NI_HEADER_MTU
  typeset NI_IPV4 NI_MTU NI_MTU_STATUS NI_MTU_REASON NI_MTU_REASON_JSON
  typeset NI_LSATTR NI_LSATTR_RC NI_ADAPTER NI_ADAPTER_TYPE
  typeset NI_ADAPTER_STATUS NI_ADAPTER_REASON NI_ADAPTER_REASON_JSON
  typeset NI_SPEED NI_SPEED_RESULT NI_SPEED_STATUS NI_SPEED_REASON
  typeset NI_SPEED_REASON_JSON
  typeset NI_ENTSTAT NI_ENTSTAT_RC NI_SUFFIX NI_ADAPTER_CANDIDATE
  typeset NI_ITEM_STATUS NI_ITEM_REASON
  typeset NI_ITEM_REASON_ESC NI_ITEM_REASON_JSON NI_ADAPTER_JSON NI_TYPE_ESC
  typeset NI_TYPE_JSON NI_SPEED_JSON NI_MTU_JSON NI_ITEM
  typeset NI_INTERFACES_STATUS NI_INTERFACES_REASON NI_INTERFACES_REASON_JSON
  typeset NI_NETSTAT NI_NETSTAT_RC NI_ROUTE_WHY NI_ROUTE_SOURCE NI_ROUTE_ROWS
  typeset NI_ROUTE_ITEMS NI_ROUTE_STATUS NI_ROUTE_REASON NI_ROUTE_REASON_JSON
  typeset NI_DNS_RAW NI_DNS_RC NI_DNS_WHY NI_DNS_SOURCE NI_DNS_ITEMS
  typeset NI_DNS_STATUS NI_DNS_REASON_JSON NI_GAPS NI_OBSERVED NI_COMPLETE
  typeset NI_TOP_STATUS NI_TOP_REASON NI_TOP_REASON_JSON

  NI_GAPS=""
  NI_IF_ITEMS=""
  NI_IF_PARTIAL=0

  NI_IFCONFIG=$(aix network_ifconfig_a ifconfig -a)
  NI_IFCONFIG_RC=$?
  NI_IF_SOURCE="{ \"capture\": \"network_ifconfig_a\", \"command\": \"ifconfig -a\", \"rc\": $NI_IFCONFIG_RC }"
  NI_IF_WHY=""
  if [ "$NI_IFCONFIG_RC" -ne 0 ]; then
    NI_IF_WHY="ifconfig -a capture failed (rc=$NI_IFCONFIG_RC)"
  elif [ -z "$NI_IFCONFIG" ]; then
    NI_IF_WHY="ifconfig -a capture empty (rc=0)"
  elif ! printf '%s\n' "$NI_IFCONFIG" | network_inventory_ifconfig_shape; then
    NI_IF_WHY="ifconfig -a capture unparseable (rc=0)"
  fi

  if [ -n "$NI_IF_WHY" ]; then
    NI_INTERFACES_STATUS="NOT_ASSESSED"
    NI_INTERFACES_REASON=$NI_IF_WHY
    NI_GAPS=$(network_inventory_append_gap "$NI_GAPS" "$NI_IF_WHY")
  else
    NI_PARSED=$(printf '%s\n' "$NI_IFCONFIG" |
      network_inventory_parse_ifconfig)
    NI_NAMES=$(printf '%s\n' "$NI_PARSED" |
      awk -F '\t' '$1=="I" { print $2 }')

    while IFS= read -r NI_IF
    do
      [ -n "$NI_IF" ] || continue
      NI_STATE=$(printf '%s\n' "$NI_PARSED" |
        awk -F '\t' -v wanted="$NI_IF" \
          '$1=="I" && $2==wanted { print $3; exit }')
      NI_HEADER_MTU=$(printf '%s\n' "$NI_PARSED" |
        awk -F '\t' -v wanted="$NI_IF" \
          '$1=="I" && $2==wanted { print $4; exit }')
      NI_IPV4=$(printf '%s\n' "$NI_PARSED" |
        awk -F '\t' -v wanted="$NI_IF" '
          $1=="A" && $2==wanted {
            if (seen++) printf ", "
            printf "{ \"address\": \"%s\", \"netmask\": \"%s\" }", $3, $4
          }')

      NI_MTU=""
      NI_MTU_STATUS="OBSERVED"
      NI_MTU_REASON=""
      if [ -n "$NI_HEADER_MTU" ]; then
        NI_MTU=$NI_HEADER_MTU
      else
        NI_LSATTR=$(aix "network_lsattr_$NI_IF" lsattr -El "$NI_IF")
        NI_LSATTR_RC=$?
        if [ "$NI_LSATTR_RC" -ne 0 ]; then
          NI_MTU_REASON="lsattr -El $NI_IF capture failed (rc=$NI_LSATTR_RC)"
        elif [ -z "$NI_LSATTR" ]; then
          NI_MTU_REASON="lsattr -El $NI_IF capture empty (rc=0)"
        elif ! printf '%s\n' "$NI_LSATTR" |
            network_inventory_lsattr_shape; then
          NI_MTU_REASON="lsattr -El $NI_IF capture unparseable (rc=0)"
        else
          NI_MTU=$(printf '%s\n' "$NI_LSATTR" |
            awk '$1=="mtu" { print $2; exit }')
        fi
        if [ -n "$NI_MTU_REASON" ]; then
          NI_MTU_STATUS="NOT_ASSESSED"
          NI_IF_PARTIAL=1
          NI_GAPS=$(network_inventory_append_gap "$NI_GAPS" "$NI_MTU_REASON")
        fi
      fi

      NI_ADAPTER=""
      NI_ADAPTER_TYPE=""
      NI_ADAPTER_STATUS="NOT_APPLICABLE"
      NI_ADAPTER_REASON="$NI_IF is not an Ethernet interface"
      NI_SPEED=""
      NI_SPEED_STATUS="NOT_APPLICABLE"
      NI_SPEED_REASON="$NI_IF is not an Ethernet interface"
      NI_SUFFIX=""
      NI_ADAPTER_CANDIDATE=""
      case "$NI_IF" in
        ent*) NI_SUFFIX=${NI_IF#ent} ;;
        en*) NI_SUFFIX=${NI_IF#en} ;;
        et*) NI_SUFFIX=${NI_IF#et} ;;
      esac
      case "$NI_SUFFIX" in
        ''|*[!0-9]*) ;;
        *)
          NI_ADAPTER_CANDIDATE="ent$NI_SUFFIX"
          NI_ENTSTAT=$(aix "network_entstat_$NI_ADAPTER_CANDIDATE" \
            entstat -d "$NI_ADAPTER_CANDIDATE")
          NI_ENTSTAT_RC=$?
          NI_ADAPTER_STATUS="NOT_ASSESSED"
          if [ "$NI_ENTSTAT_RC" -ne 0 ]; then
            NI_ADAPTER_REASON="entstat -d $NI_ADAPTER_CANDIDATE capture failed (rc=$NI_ENTSTAT_RC)"
          elif [ -z "$NI_ENTSTAT" ]; then
            NI_ADAPTER_REASON="entstat -d $NI_ADAPTER_CANDIDATE capture empty (rc=0)"
          elif ! printf '%s\n' "$NI_ENTSTAT" |
              network_inventory_entstat_shape "$NI_ADAPTER_CANDIDATE"; then
            NI_ADAPTER_REASON="entstat -d $NI_ADAPTER_CANDIDATE capture unparseable (rc=0)"
          else
            NI_ADAPTER=$NI_ADAPTER_CANDIDATE
            NI_ADAPTER_TYPE=$(printf '%s\n' "$NI_ENTSTAT" |
              network_inventory_entstat_type)
            NI_ADAPTER_STATUS="OBSERVED"
            NI_ADAPTER_REASON=""
            NI_SPEED_RESULT=$(printf '%s\n' "$NI_ENTSTAT" |
              network_inventory_entstat_speed)
          fi

          if [ "$NI_ADAPTER_STATUS" = "OBSERVED" ]; then
            NI_SPEED_STATUS=${NI_SPEED_RESULT%%\|*}
            NI_SPEED=${NI_SPEED_RESULT#*\|}
            if [ "$NI_SPEED_STATUS" = "OBSERVED" ]; then
              NI_SPEED_STATUS="OBSERVED"
              NI_SPEED_REASON=""
            else
              NI_SPEED_REASON=$NI_SPEED
              NI_SPEED=""
              NI_SPEED_STATUS="NOT_ASSESSED"
              if [ "$NI_SPEED_REASON" = \
                  "did not report media speed or adapter data rate" ]; then
                NI_SPEED_REASON="entstat -d $NI_ADAPTER_CANDIDATE $NI_SPEED_REASON"
              fi
            fi
          else
            NI_SPEED_STATUS="NOT_ASSESSED"
            NI_SPEED_REASON=$NI_ADAPTER_REASON
            NI_IF_PARTIAL=1
            NI_GAPS=$(network_inventory_append_gap "$NI_GAPS" "$NI_ADAPTER_REASON")
          fi
          ;;
      esac

      NI_ITEM_STATUS="OBSERVED"
      NI_ITEM_REASON=""
      if [ "$NI_MTU_STATUS" = "NOT_ASSESSED" ]; then
        NI_ITEM_STATUS="PARTIAL"
        NI_ITEM_REASON="MTU: $NI_MTU_REASON"
      fi
      if [ "$NI_ADAPTER_STATUS" = "NOT_ASSESSED" ]; then
        NI_ITEM_STATUS="PARTIAL"
        if [ -n "$NI_ITEM_REASON" ]; then
          NI_ITEM_REASON="$NI_ITEM_REASON; adapter: $NI_ADAPTER_REASON"
        else
          NI_ITEM_REASON="adapter: $NI_ADAPTER_REASON"
        fi
      fi

      if [ -n "$NI_MTU" ]; then NI_MTU_JSON=$NI_MTU; else NI_MTU_JSON=null; fi
      if [ -n "$NI_ADAPTER" ]; then
        NI_ADAPTER_JSON="\"$NI_ADAPTER\""
      else
        NI_ADAPTER_JSON=null
      fi
      if [ -n "$NI_ADAPTER_TYPE" ]; then
        NI_TYPE_ESC=$(printf '%s' "$NI_ADAPTER_TYPE" |
          network_inventory_json_escape)
        NI_TYPE_JSON="\"$NI_TYPE_ESC\""
      else
        NI_TYPE_JSON=null
      fi
      if [ -n "$NI_SPEED" ]; then NI_SPEED_JSON=$NI_SPEED; else NI_SPEED_JSON=null; fi

      if [ -n "$NI_MTU_REASON" ]; then
        NI_ITEM_REASON_ESC=$(printf '%s' "$NI_MTU_REASON" |
          network_inventory_json_escape)
        NI_MTU_REASON_JSON="\"$NI_ITEM_REASON_ESC\""
      else
        NI_MTU_REASON_JSON=null
      fi
      if [ -n "$NI_ADAPTER_REASON" ]; then
        NI_ITEM_REASON_ESC=$(printf '%s' "$NI_ADAPTER_REASON" |
          network_inventory_json_escape)
        NI_ADAPTER_REASON_JSON="\"$NI_ITEM_REASON_ESC\""
      else
        NI_ADAPTER_REASON_JSON=null
      fi
      if [ -n "$NI_SPEED_REASON" ]; then
        NI_ITEM_REASON_ESC=$(printf '%s' "$NI_SPEED_REASON" |
          network_inventory_json_escape)
        NI_SPEED_REASON_JSON="\"$NI_ITEM_REASON_ESC\""
      else
        NI_SPEED_REASON_JSON=null
      fi
      if [ -n "$NI_ITEM_REASON" ]; then
        NI_ITEM_REASON_ESC=$(printf '%s' "$NI_ITEM_REASON" |
          network_inventory_json_escape)
        NI_ITEM_REASON_JSON="\"$NI_ITEM_REASON_ESC\""
      else
        NI_ITEM_REASON_JSON=null
      fi

      NI_ITEM="{ \"name\": \"$NI_IF\", \"ipv4\": [$NI_IPV4], \"ipv4_status\": \"OBSERVED\", \"ipv4_reason\": null, \"state\": \"$NI_STATE\", \"state_status\": \"OBSERVED\", \"state_reason\": null, \"mtu\": $NI_MTU_JSON, \"mtu_status\": \"$NI_MTU_STATUS\", \"mtu_reason\": $NI_MTU_REASON_JSON, \"adapter\": $NI_ADAPTER_JSON, \"adapter_type\": $NI_TYPE_JSON, \"adapter_status\": \"$NI_ADAPTER_STATUS\", \"adapter_reason\": $NI_ADAPTER_REASON_JSON, \"media_speed_mbps\": $NI_SPEED_JSON, \"media_speed_status\": \"$NI_SPEED_STATUS\", \"media_speed_reason\": $NI_SPEED_REASON_JSON, \"status\": \"$NI_ITEM_STATUS\", \"reason\": $NI_ITEM_REASON_JSON }"
      if [ -n "$NI_IF_ITEMS" ]; then
        NI_IF_ITEMS="$NI_IF_ITEMS, $NI_ITEM"
      else
        NI_IF_ITEMS=$NI_ITEM
      fi
    done <<EOF
$NI_NAMES
EOF

    if [ "$NI_IF_PARTIAL" -eq 1 ]; then
      NI_INTERFACES_STATUS="PARTIAL"
      NI_INTERFACES_REASON="one or more interface attributes were not assessed; see per-interface reasons"
    else
      NI_INTERFACES_STATUS="COMPLETE"
      NI_INTERFACES_REASON=""
    fi
  fi

  if [ -n "$NI_INTERFACES_REASON" ]; then
    NI_ITEM_REASON_ESC=$(printf '%s' "$NI_INTERFACES_REASON" |
      network_inventory_json_escape)
    NI_INTERFACES_REASON_JSON="\"$NI_ITEM_REASON_ESC\""
  else
    NI_INTERFACES_REASON_JSON=null
  fi

  NI_NETSTAT=$(aix network_netstat_rn netstat -rn)
  NI_NETSTAT_RC=$?
  NI_ROUTE_SOURCE="{ \"capture\": \"network_netstat_rn\", \"command\": \"netstat -rn\", \"rc\": $NI_NETSTAT_RC }"
  NI_ROUTE_WHY=""
  NI_ROUTE_ITEMS=""
  if [ "$NI_NETSTAT_RC" -ne 0 ]; then
    NI_ROUTE_WHY="netstat -rn capture failed (rc=$NI_NETSTAT_RC)"
  elif [ -z "$NI_NETSTAT" ]; then
    NI_ROUTE_WHY="netstat -rn capture empty (rc=0)"
  elif ! printf '%s\n' "$NI_NETSTAT" | network_inventory_netstat_shape; then
    NI_ROUTE_WHY="netstat -rn capture unparseable (rc=0)"
  fi

  if [ -n "$NI_ROUTE_WHY" ]; then
    NI_ROUTE_STATUS="NOT_ASSESSED"
    NI_ROUTE_REASON=$NI_ROUTE_WHY
    NI_GAPS=$(network_inventory_append_gap "$NI_GAPS" "$NI_ROUTE_WHY")
  else
    NI_ROUTE_ROWS=$(printf '%s\n' "$NI_NETSTAT" |
      network_inventory_parse_netstat)
    NI_ROUTE_ITEMS=$(printf '%s\n' "$NI_ROUTE_ROWS" | awk -F '\t' '
      NF {
        if (seen++) printf ", "
        if ($3=="") iface="null"; else iface="\"" $3 "\""
        if ($5=="") reason="null"; else reason="\"" $5 "\""
        printf "{ \"family\": \"%s\", \"gateway\": \"%s\", \"interface\": %s, \"status\": \"%s\", \"reason\": %s }", $1, $2, iface, $4, reason
      }')
    if printf '%s\n' "$NI_ROUTE_ROWS" |
        awk -F '\t' '$4=="PARTIAL" { found=1 } END { exit !found }'; then
      NI_ROUTE_STATUS="PARTIAL"
      NI_ROUTE_REASON="one or more default routes did not expose an interface"
      NI_GAPS=$(network_inventory_append_gap "$NI_GAPS" \
        "netstat -rn default route did not expose an interface")
    else
      NI_ROUTE_STATUS="COMPLETE"
      NI_ROUTE_REASON=""
    fi
  fi
  if [ -n "$NI_ROUTE_REASON" ]; then
    NI_ITEM_REASON_ESC=$(printf '%s' "$NI_ROUTE_REASON" |
      network_inventory_json_escape)
    NI_ROUTE_REASON_JSON="\"$NI_ITEM_REASON_ESC\""
  else
    NI_ROUTE_REASON_JSON=null
  fi

  NI_DNS_RAW=$(aix network_resolv_conf cat /etc/resolv.conf)
  NI_DNS_RC=$?
  NI_DNS_SOURCE="{ \"capture\": \"network_resolv_conf\", \"command\": \"cat /etc/resolv.conf\", \"rc\": $NI_DNS_RC }"
  NI_DNS_WHY=""
  NI_DNS_ITEMS=""
  if [ "$NI_DNS_RC" -ne 0 ]; then
    NI_DNS_WHY="cat /etc/resolv.conf capture failed (rc=$NI_DNS_RC)"
  elif [ -z "$NI_DNS_RAW" ]; then
    NI_DNS_WHY="cat /etc/resolv.conf capture empty (rc=0)"
  elif ! printf '%s\n' "$NI_DNS_RAW" | network_inventory_resolv_shape; then
    NI_DNS_WHY="cat /etc/resolv.conf capture unparseable (rc=0)"
  fi

  if [ -n "$NI_DNS_WHY" ]; then
    NI_DNS_STATUS="NOT_ASSESSED"
    NI_GAPS=$(network_inventory_append_gap "$NI_GAPS" "$NI_DNS_WHY")
  else
    NI_DNS_STATUS="COMPLETE"
    NI_DNS_ITEMS=$(printf '%s\n' "$NI_DNS_RAW" |
      network_inventory_parse_resolv |
      awk '{ if (seen++) printf ", "; printf "\"%s\"", $0 }')
  fi
  if [ -n "$NI_DNS_WHY" ]; then
    NI_ITEM_REASON_ESC=$(printf '%s' "$NI_DNS_WHY" |
      network_inventory_json_escape)
    NI_DNS_REASON_JSON="\"$NI_ITEM_REASON_ESC\""
  else
    NI_DNS_REASON_JSON=null
  fi

  NI_OBSERVED=0
  NI_COMPLETE=0
  for NI_ITEM_STATUS in \
    "$NI_INTERFACES_STATUS" "$NI_ROUTE_STATUS" "$NI_DNS_STATUS"
  do
    [ "$NI_ITEM_STATUS" != "NOT_ASSESSED" ] && NI_OBSERVED=$((NI_OBSERVED + 1))
    [ "$NI_ITEM_STATUS" = "COMPLETE" ] && NI_COMPLETE=$((NI_COMPLETE + 1))
  done
  if [ "$NI_OBSERVED" -eq 0 ]; then
    NI_TOP_STATUS="NOT_ASSESSED"
    NI_TOP_REASON="no network fact source produced trustworthy output; see capture_gaps"
  elif [ "$NI_COMPLETE" -eq 3 ]; then
    NI_TOP_STATUS="COMPLETE"
    NI_TOP_REASON=""
  else
    NI_TOP_STATUS="PARTIAL"
    NI_TOP_REASON="one or more network fact sources or fields were not assessed; see sub-block reasons and capture_gaps"
  fi
  if [ -n "$NI_TOP_REASON" ]; then
    NI_ITEM_REASON_ESC=$(printf '%s' "$NI_TOP_REASON" |
      network_inventory_json_escape)
    NI_TOP_REASON_JSON="\"$NI_ITEM_REASON_ESC\""
  else
    NI_TOP_REASON_JSON=null
  fi

  printf '"network": { "status": "%s", "platform": "AIX", ' "$NI_TOP_STATUS"
  printf '"reason": %s, "capture_gaps": [%s], ' "$NI_TOP_REASON_JSON" "$NI_GAPS"
  if [ "$NI_INTERFACES_STATUS" = "NOT_ASSESSED" ]; then
    printf '"interfaces": { "status": "%s", "reason": %s, "source": %s, "interfaces": null }, ' \
      "$NI_INTERFACES_STATUS" "$NI_INTERFACES_REASON_JSON" "$NI_IF_SOURCE"
  else
    printf '"interfaces": { "status": "%s", "reason": %s, "source": %s, "interfaces": [%s] }, ' \
      "$NI_INTERFACES_STATUS" "$NI_INTERFACES_REASON_JSON" "$NI_IF_SOURCE" "$NI_IF_ITEMS"
  fi
  if [ "$NI_ROUTE_STATUS" = "NOT_ASSESSED" ]; then
    printf '"routing": { "status": "%s", "reason": %s, "source": %s, "default_gateways": null }, ' \
      "$NI_ROUTE_STATUS" "$NI_ROUTE_REASON_JSON" "$NI_ROUTE_SOURCE"
  else
    printf '"routing": { "status": "%s", "reason": %s, "source": %s, "default_gateways": [%s] }, ' \
      "$NI_ROUTE_STATUS" "$NI_ROUTE_REASON_JSON" "$NI_ROUTE_SOURCE" "$NI_ROUTE_ITEMS"
  fi
  if [ "$NI_DNS_STATUS" = "NOT_ASSESSED" ]; then
    printf '"dns": { "status": "%s", "reason": %s, "source": %s, "resolvers": null } }' \
      "$NI_DNS_STATUS" "$NI_DNS_REASON_JSON" "$NI_DNS_SOURCE"
  else
    printf '"dns": { "status": "%s", "reason": %s, "source": %s, "resolvers": [%s] } }' \
      "$NI_DNS_STATUS" "$NI_DNS_REASON_JSON" "$NI_DNS_SOURCE" "$NI_DNS_ITEMS"
  fi
}

# Network discovery is useful evidence, but without an approved expected-state
# baseline it is not itself a configuration assessment.
function check_network_inventory {
  typeset NI_CHECK_OUT NI_CHECK_RC NI_CHECK_COUNT NI_CHECK_NOUN NI_CHECK_VERB
  typeset NI_CHECK_OBS NI_CHECK_MEAN NI_CHECK_FIX

  NI_CHECK_OUT=$(aix network_ifconfig_a ifconfig -a); NI_CHECK_RC=$?
  if [ "$NI_CHECK_RC" -ne 0 ]; then
    NI_CHECK_OBS="not assessed — ifconfig -a interface inventory failed (rc=$NI_CHECK_RC)"
    NI_CHECK_MEAN="The interface inventory source was unavailable, so expected interfaces, addresses, routes, and resolvers could not be assessed."
    NI_CHECK_FIX="restore access to 'ifconfig -a', provide the site-approved network baseline, and rerun AIXray."
  elif [ -z "$NI_CHECK_OUT" ]; then
    NI_CHECK_OBS="not assessed — ifconfig -a reported no interface inventory (rc=0)"
    NI_CHECK_MEAN="An empty interface capture cannot establish the system's network configuration or compare it with expected state."
    NI_CHECK_FIX="verify the complete output of 'ifconfig -a', provide the site-approved network baseline, and rerun AIXray."
  elif ! printf '%s\n' "$NI_CHECK_OUT" |
      network_inventory_ifconfig_shape; then
    NI_CHECK_OBS="not assessed — ifconfig -a interface inventory was unparseable (rc=0)"
    NI_CHECK_MEAN="The interface capture did not match the expected AIX ifconfig structure, so network configuration could not be assessed."
    NI_CHECK_FIX="capture the complete output of 'ifconfig -a', correct the replay source if needed, provide the site-approved network baseline, and rerun AIXray."
  else
    NI_CHECK_COUNT=$(printf '%s\n' "$NI_CHECK_OUT" |
      network_inventory_parse_ifconfig |
      awk -F '	' '$1=="I" {n++} END{print n+0}')
    NI_CHECK_NOUN=interfaces
    NI_CHECK_VERB=were
    if [ "$NI_CHECK_COUNT" -eq 1 ]; then
      NI_CHECK_NOUN=interface
      NI_CHECK_VERB=was
    fi
    NI_CHECK_OBS="not assessed — $NI_CHECK_COUNT $NI_CHECK_NOUN $NI_CHECK_VERB inventoried from ifconfig -a, but no site-approved expected interface, address, route, and DNS baseline was available"
    NI_CHECK_MEAN="Observed network inventory alone cannot distinguish an intended configuration from a missing, unexpected, or misaddressed interface, route, or resolver."
    NI_CHECK_FIX="provide a site-approved expected interface, address, route, and DNS baseline, compare it with this inventory, and rerun AIXray."
  fi

  add config network_inventory "Network inventory baseline" \
    NOT_ASSESSED med "$NI_CHECK_OBS" "$NI_CHECK_MEAN" "$NI_CHECK_FIX"
}

function standalone_run {
  check_network_inventory
}

standalone_main "$@"
exit $?
