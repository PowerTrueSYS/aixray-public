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

AIXRAY_TOOL=ck-software-inventory

# Shared software-inventory capture for the facts-only standalone slice.
function capture_cap_lslpp_qcl {
  LSLPPQ=$(aix lslpp_qcL lslpp -qcL); LSLPPQ_RC=$?
}

# Emit one JSON member named "software" from the lslpp -qcL capture already
# held by the patch checks. This module defines the emitter only; the separate
# integration build owns the spine include and facts-emitter call.
function emit_fact_software {
  typeset SI_FILESET_LIMIT SI_WORKLOAD_LIMIT SI_EVIDENCE_LIMIT
  typeset SI_RC SI_CONFIRMED SI_AWK_RC

  SI_FILESET_LIMIT=${1:-1000}
  case "$SI_FILESET_LIMIT" in
    [1-9]|[1-9][0-9]|[1-9][0-9][0-9]|1000) ;;
    *) SI_FILESET_LIMIT=1000 ;;
  esac

  SI_WORKLOAD_LIMIT=${2:-100}
  case "$SI_WORKLOAD_LIMIT" in
    [1-9]|[1-9][0-9]|100) ;;
    *) SI_WORKLOAD_LIMIT=100 ;;
  esac

  SI_EVIDENCE_LIMIT=${3:-25}
  case "$SI_EVIDENCE_LIMIT" in
    [1-9]|1[0-9]|2[0-5]) ;;
    *) SI_EVIDENCE_LIMIT=25 ;;
  esac

  SI_RC=${LSLPPQ_RC:-}
  case "$SI_RC" in
    [0-9]|[0-9][0-9]|[0-9][0-9][0-9])
      SI_CONFIRMED=1
      SI_AWK_RC=$SI_RC
      ;;
    *)
      SI_CONFIRMED=0
      SI_AWK_RC=0
      ;;
  esac

  printf '%s\n' "${LSLPPQ:-}" | awk -F: \
    -v confirmed="$SI_CONFIRMED" -v capture_rc="$SI_AWK_RC" \
    -v max_rows="$SI_FILESET_LIMIT" \
    -v max_workloads="$SI_WORKLOAD_LIMIT" \
    -v max_evidence="$SI_EVIDENCE_LIMIT" '
    BEGIN {
      state_name["A"] = "APPLIED"
      state_name["B"] = "BROKEN"
      state_name["C"] = "COMMITTED"
      state_name["E"] = "EFIX_LOCKED"
      state_name["O"] = "OBSOLETE"
      state_name["?"] = "INCONSISTENT"

      classification_gap = "ISV/workload classification uses explicit IBM Java, Python, and Perl lpp_source/name-pair heuristics; every other fileset remains UNCLASSIFIED."
      unmanaged_gap = "Software not registered with lslpp -Lc is not assessed."
      business_gap = "Business criticality, active use, and workload coupling are not established by lslpp -Lc and remain NOT_ASSESSED."
      workload_gap = "Only package-managed IBM Java, Python, and Perl runtimes matched by explicit lpp_source/name-pair heuristics are normalized; package publisher/provenance remains NOT_ASSESSED, and absence does not prove that no other ISV or workload software exists."
    }

    function usable_field(value) {
      return value != "" && value !~ /[[:cntrl:]]/
    }

    function json_escape(value, result, character) {
      result = ""
      while (value != "") {
        character = substr(value, 1, 1)
        value = substr(value, 2)
        if (character == "\\") {
          result = result "\\\\"
        } else if (character == "\"") {
          result = result "\\\""
        } else {
          result = result character
        }
      }
      return result
    }

    function remember_workload(product_id, product_name, category,
                               version, fileset, key, evidence_key, number) {
      key = product_id SUBSEP version
      if (!(key in workload_seen)) {
        workload_seen[key] = 1
        workload_order[++workload_count] = key
        workload_id[key] = product_id
        workload_name[key] = product_name
        workload_category[key] = category
        workload_version[key] = version
      }

      evidence_key = key SUBSEP fileset
      if (!(evidence_key in evidence_seen)) {
        evidence_seen[evidence_key] = 1
        number = ++workload_evidence_count[key]
        workload_evidence[key SUBSEP number] = fileset
      }
    }

    function classify(row, lpp_source, fileset, version, product_id) {
      product_id = ""
      if (lpp_source ~ /^Java[0-9_]+\.(jre|sdk)$/ &&
          fileset == lpp_source) {
        product_id = "ibm-java"
        remember_workload(product_id, "IBM Java", "runtime", version, fileset)
      } else if ((lpp_source ~ /^python[0-9]+$/ ||
                  lpp_source ~ /^python[0-9]+\.[0-9]+$/ ||
                  lpp_source ~ /^python[0-9]+\.[0-9]+\.base$/) &&
                 (fileset == lpp_source ||
                  index(fileset, lpp_source "-") == 1)) {
        product_id = "python"
        remember_workload(product_id, "Python", "runtime", version, fileset)
      } else if (lpp_source == "perl.rte" && fileset == lpp_source) {
        product_id = "perl"
        remember_workload(product_id, "Perl", "runtime", version, fileset)
      }

      if (product_id == "") {
        row_class[row] = "UNCLASSIFIED"
        row_product[row] = ""
      } else {
        row_class[row] = "WORKLOAD_RUNTIME"
        row_product[row] = product_id
      }
    }

    function emit_gaps() {
      printf "\"gaps\":[\"%s\",\"%s\",\"%s\"]", classification_gap, unmanaged_gap, business_gap
    }

    function emit_not_assessed(reason, rc_json) {
      printf "\"software\":{"
      printf "\"status\":\"NOT_ASSESSED\",\"platform\":\"AIX\","
      printf "\"reason\":\"%s\",", reason
      printf "\"source\":{\"capture\":\"lslpp_qcL\",\"command\":\"lslpp -qcL\","
      printf "\"format\":\"lslpp -Lc colon-delimited (headings suppressed)\",\"rc\":%s},", rc_json

      printf "\"filesets\":{"
      printf "\"status\":\"NOT_ASSESSED\",\"reason\":\"%s\",", reason
      printf "\"captured_count\":null,\"emitted_count\":null,"
      printf "\"invalid_row_count\":null,\"invalid_row_marker\":null,"
      printf "\"omitted_count\":null,\"truncated\":null,"
      printf "\"truncation_marker\":null,\"items\":null},"

      printf "\"isv_workloads\":{"
      printf "\"status\":\"NOT_ASSESSED\",\"reason\":\"%s\",", reason
      printf "\"basis\":null,\"detected_count\":null,"
      printf "\"emitted_count\":null,\"omitted_count\":null,"
      printf "\"truncated\":null,\"truncation_marker\":null,\"items\":null,"
      printf "\"gap\":\"%s\"},", workload_gap
      emit_gaps()
      printf "}"
    }

    /^[ \t\r]*$/ { next }

    {
      saw_nonblank++
      if ($0 !~ /^[ \t]*#/ && NF >= 6 && usable_field($1) && usable_field($2) &&
          usable_field($3) && ($6 in state_name)) {
        row = ++valid_count
        row_lpp[row] = $1
        row_name[row] = $2
        row_version[row] = $3
        row_state_code[row] = $6
        row_state[row] = state_name[$6]
        if ($2 ~ /^bos\.rte(\.|$)/ && !($2 in bos_family_seen)) {
          bos_family_seen[$2] = 1
          bos_family_count++
        }
        classify(row, $1, $2, $3)
      } else {
        invalid_count++
      }
    }

    END {
      if (!confirmed) {
        emit_not_assessed("lslpp -qcL capture return code was not confirmed",
                          "null")
        exit
      }
      if ((capture_rc + 0) != 0) {
        reason = "lslpp -qcL capture failed (rc=" (capture_rc + 0) ")"
        emit_not_assessed(reason, capture_rc + 0)
        exit
      }
      if (valid_count == 0) {
        if (saw_nonblank == 0) {
          reason = "lslpp -qcL capture was empty"
        } else {
          reason = "lslpp -qcL capture had no structurally valid rows (" invalid_count " malformed)"
        }
        emit_not_assessed(reason, "0")
        exit
      }
      if (valid_count < 50 || bos_family_count < 3) {
        reason = "lslpp -qcL capture was implausibly small (" valid_count " structurally valid rows; minimum 50, " (bos_family_count + 0) " distinct bos.rte filesets)"
        emit_not_assessed(reason, "0")
        exit
      }

      emitted_count = valid_count
      if (emitted_count > max_rows) emitted_count = max_rows
      omitted_count = valid_count - emitted_count
      fileset_status = "COMPLETE"
      if (invalid_count > 0 || omitted_count > 0) fileset_status = "PARTIAL"

      fileset_reason = "null"
      if (invalid_count > 0 && omitted_count > 0) {
        fileset_reason = "\"capture contained " invalid_count " malformed rows and output omitted " omitted_count " valid rows\""
      } else if (invalid_count > 0) {
        fileset_reason = "\"capture contained " invalid_count " malformed rows\""
      } else if (omitted_count > 0) {
        fileset_reason = "\"output bounded at " emitted_count " of " valid_count " valid rows\""
      }

      printf "\"software\":{"
      printf "\"status\":\"PARTIAL\",\"platform\":\"AIX\",\"reason\":null,"
      printf "\"source\":{\"capture\":\"lslpp_qcL\",\"command\":\"lslpp -qcL\","
      printf "\"format\":\"lslpp -Lc colon-delimited (headings suppressed)\",\"rc\":0},"

      printf "\"filesets\":{"
      printf "\"status\":\"%s\",\"reason\":%s,", fileset_status, fileset_reason
      printf "\"captured_count\":%d,\"emitted_count\":%d,", valid_count, emitted_count
      printf "\"invalid_row_count\":%d,", invalid_count
      if (invalid_count > 0) {
        if (invalid_count == 1) {
          printf "\"invalid_row_marker\":\"1 malformed row not emitted\","
        } else {
          printf "\"invalid_row_marker\":\"%d malformed rows not emitted\",", invalid_count
        }
      } else {
        printf "\"invalid_row_marker\":null,"
      }
      printf "\"omitted_count\":%d,", omitted_count
      if (omitted_count > 0) {
        printf "\"truncated\":true,"
        if (omitted_count == 1) {
          printf "\"truncation_marker\":\"1 more fileset not emitted (limit %d)\",", max_rows
        } else {
          printf "\"truncation_marker\":\"%d more filesets not emitted (limit %d)\",", omitted_count, max_rows
        }
      } else {
        printf "\"truncated\":false,\"truncation_marker\":null,"
      }

      printf "\"items\":["
      for (row = 1; row <= emitted_count; row++) {
        if (row > 1) printf ","
        printf "{\"lpp_source\":\"%s\",\"name\":\"%s\",", json_escape(row_lpp[row]), json_escape(row_name[row])
        printf "\"version\":\"%s\",\"state_code\":\"%s\",", json_escape(row_version[row]), row_state_code[row]
        printf "\"state\":\"%s\",\"classification\":\"%s\",", row_state[row], row_class[row]
        if (row_product[row] == "") {
          printf "\"normalized_product_id\":null}"
        } else {
          printf "\"normalized_product_id\":\"%s\"}", row_product[row]
        }
      }
      printf "]},"

      printf "\"isv_workloads\":{"
      printf "\"status\":\"PARTIAL\",\"reason\":null,"
      printf "\"basis\":\"package_name_pair_heuristics\","
      workload_emitted = workload_count
      if (workload_emitted > max_workloads) workload_emitted = max_workloads
      workload_omitted = workload_count - workload_emitted
      printf "\"detected_count\":%d,\"emitted_count\":%d,", workload_count, workload_emitted
      printf "\"omitted_count\":%d,", workload_omitted
      if (workload_omitted > 0) {
        printf "\"truncated\":true,"
        if (workload_omitted == 1) {
          printf "\"truncation_marker\":\"1 more workload product not emitted (limit %d)\",", max_workloads
        } else {
          printf "\"truncation_marker\":\"%d more workload products not emitted (limit %d)\",", workload_omitted, max_workloads
        }
      } else {
        printf "\"truncated\":false,\"truncation_marker\":null,"
      }
      printf "\"items\":["
      for (workload = 1; workload <= workload_emitted; workload++) {
        key = workload_order[workload]
        if (workload > 1) printf ","
        printf "{\"product_id\":\"%s\",\"name\":\"%s\",", workload_id[key], workload_name[key]
        printf "\"vendor\":null,\"category\":\"%s\",", workload_category[key]
        evidence_count = workload_evidence_count[key]
        evidence_emitted = evidence_count
        if (evidence_emitted > max_evidence) evidence_emitted = max_evidence
        evidence_omitted = evidence_count - evidence_emitted
        printf "\"version\":\"%s\",", json_escape(workload_version[key])
        printf "\"evidence_count\":%d,\"evidence_emitted_count\":%d,", evidence_count, evidence_emitted
        printf "\"evidence_omitted_count\":%d,", evidence_omitted
        if (evidence_omitted > 0) {
          printf "\"evidence_truncated\":true,"
          if (evidence_omitted == 1) {
            printf "\"evidence_truncation_marker\":\"1 more evidence fileset not emitted (limit %d)\",", max_evidence
          } else {
            printf "\"evidence_truncation_marker\":\"%d more evidence filesets not emitted (limit %d)\",", evidence_omitted, max_evidence
          }
        } else {
          printf "\"evidence_truncated\":false,\"evidence_truncation_marker\":null,"
        }
        printf "\"evidence_filesets\":["
        for (evidence = 1; evidence <= evidence_emitted; evidence++) {
          if (evidence > 1) printf ","
          printf "\"%s\"", json_escape(workload_evidence[key SUBSEP evidence])
        }
        printf "]}"
      }
      printf "],\"gap\":\"%s\"},", workload_gap
      emit_gaps()
      printf "}"
    }
  '
}

function standalone_run {
  capture_cap_lslpp_qcl || return 1
  :
}

standalone_main "$@"
exit $?
