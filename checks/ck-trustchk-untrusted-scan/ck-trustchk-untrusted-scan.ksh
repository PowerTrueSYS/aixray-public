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

AIXRAY_TOOL=ck-trustchk-untrusted-scan


function standalone_check {
_AIXRAY_SESSION_KEYS=""
  # trustchk_untrusted_scan (CIS control 2.6, Level 2) — does every installed
  # file match the system's trusted signature database? AIX ships trustchk,
  # which compares the installed software inventory against a trusted signature
  # database and writes any unmatched (untrusted) file report to stderr. A
  # compliant system has an empty untrusted list. Read-only: the scan only reads
  # state; it never modifies the inventory or the signature database.
  #
  # trustchk exits NON-ZERO when it finds violations: rc=114 with an empty
  # stdout and the whole report on stderr is what BOTH healthy lab boxes
  # returned on 2026-08-06 (117 report lines on aix73, 167 on aix72). Refusing
  # on any non-zero rc therefore rendered NOT_ASSESSED on every real machine —
  # a refusal, not coverage. The rc is classified only AFTER the report is
  # parsed: a parsed violation line is determinate evidence of FAIL whatever
  # the rc, and only a non-zero rc with nothing parseable is genuinely unknown.
  typeset TRUSTCHK_AVAILABLE_RC TRUSTCHK_SCAN_RC
  typeset TRUSTCHK_PATH TRUSTCHK_SCAN_OUT TRUSTCHK_SUMMARY TRUSTCHK_DIAG
  TRUSTCHK_AVAILABLE_RC=127
  TRUSTCHK_SCAN_RC=127
  TRUSTCHK_PATH=""
  TRUSTCHK_SCAN_OUT=""
  TRUSTCHK_SUMMARY=""
  TRUSTCHK_DIAG=""

  # Probe 1: is the scan tool present? whence is the ksh builtin lookup; its rc
  # is 0 when trustchk resolves and non-zero when it does not.
  TRUSTCHK_PATH=$(aix trustchk_available whence trustchk)
  TRUSTCHK_AVAILABLE_RC=$?

  if [ "$TRUSTCHK_AVAILABLE_RC" -ne 0 ]; then
    add security trustchk_untrusted_scan "Untrusted file scan" NOT_ASSESSED low \
        "not assessed — trustchk not found (rc=$TRUSTCHK_AVAILABLE_RC)" \
        "The trusted-signature scan tool is not present on this system, so the installed software inventory could not be compared against the trusted signature database." \
        "install the trustchk tool and its trusted signature database, then rerun AIXray." \
        "cis-l2"
  else
    # Probe 2: run the scan. trustchk writes its report to stderr, so capture
    # stdout and stderr merged and read the combined stream.
    TRUSTCHK_SCAN_OUT=$(aixv trustchk_scan trustchk -i -n tree /)
    TRUSTCHK_SCAN_RC=$?

    # Parse the report BEFORE looking at the rc. Two verified message shapes
    # name an offending file: the unregistered set-UID/set-GID form and the
    # per-attribute verification-failure form (the attribute name varies, so it
    # is matched generically). Anything else is not treated as a violation.
    # Prints one bounded summary line, or nothing at all when no violation line
    # was recognised — emptiness is the discriminator the verdict branches on.
    # Evidence is counts and file paths only; no other capture content escapes.
    TRUSTCHK_SUMMARY=$(printf '%s\n' "$TRUSTCHK_SCAN_OUT" | awk '
      {
        path = ""
        if ($0 ~ /^trustchk: The untrusted file .* is an unregistered set-[UG]ID program$/) {
          path = $0
          sub(/^trustchk: The untrusted file /, "", path)
          sub(/ is an unregistered set-[UG]ID program$/, "", path)
        } else if ($0 ~ /^trustchk: Verification of [^ ]* attribute is failing for the file \//) {
          path = $0
          sub(/^trustchk: Verification of [^ ]* attribute is failing for the file /, "", path)
        }
        if (path !~ /^\//) next
        lines++
        if (!(path in seen)) {
          seen[path] = 1
          files++
          order[files] = path
        }
      }
      END {
        if (lines == 0) exit 0
        report_noun = "reports"
        if (lines == 1) report_noun = "report"
        file_noun = "files"
        if (files == 1) file_noun = "file"
        head = lines " untrusted-file " report_noun ", " files " " file_noun
        list = ""
        shown = 0
        for (i = 1; i <= files; i++) {
          if (shown >= 3) break
          p = order[i]
          if (length("" p) > 40) p = substr(p, 1, 37) "..."
          if (shown == 0) cand = p
          else cand = list ", " p
          more = files - (shown + 1)
          suffix = ""
          if (more > 0) suffix = " +" more " more"
          if (length("" head) + 2 + length("" cand) + length("" suffix) > 120) break
          list = cand
          shown++
        }
        if (shown == 0) { print head; exit 0 }
        more = files - shown
        if (more > 0) print head ": " list " +" more " more"
        else print head ": " list
      }')

    if [ "$TRUSTCHK_SCAN_RC" -eq 0 ] && [ -z "$TRUSTCHK_SUMMARY" ]; then
      add security trustchk_untrusted_scan "Untrusted file scan" PASS low \
          "no untrusted files reported" \
          "The trusted-signature scan completed and every installed file matched the trusted signature database; no untrusted file was reported." \
          "n/a" \
          "cis-l2"
    elif [ -n "$TRUSTCHK_SUMMARY" ]; then
      # Determinate: the scan ran far enough to name at least one file that
      # failed the trusted-signature comparison, whatever exit code it chose.
      add security trustchk_untrusted_scan "Untrusted file scan" FAIL high \
          "$TRUSTCHK_SUMMARY" \
          "At least one installed file did not match the trusted signature database. The installed inventory deviates from the system's trusted signatures and must be investigated and remediated." \
          "review the untrusted files named by 'trustchk -i -n tree /', verify their provenance, and restore or remove them, then rerun AIXray." \
          "cis-l2"
    else
      # Non-zero rc and nothing parseable: the scan did not get far enough to
      # name a file, so the state is genuinely unknown. Carry the real rc and
      # the first diagnostic line so the refusal is actionable, not opaque.
      TRUSTCHK_DIAG=$(printf '%s\n' "$TRUSTCHK_SCAN_OUT" | awk 'NF { gsub(/[ \t]+/, " "); sub(/^ /, ""); sub(/ $/, ""); if (length("" $0) > 40) $0 = substr($0, 1, 37) "..."; print; exit }')
      if [ -n "$TRUSTCHK_DIAG" ]; then
        TRUSTCHK_DIAG=": $TRUSTCHK_DIAG"
      fi
      add security trustchk_untrusted_scan "Untrusted file scan" NOT_ASSESSED low \
          "not assessed — trustchk scan failed (rc=$TRUSTCHK_SCAN_RC)$TRUSTCHK_DIAG" \
          "The trusted-signature scan itself failed without naming a single file, so whether any installed file is untrusted is unknown." \
          "run 'trustchk -i -n tree /' with the needed authority, resolve the scan failure, then rerun AIXray." \
          "cis-l2"
    fi
  fi
}

function standalone_run {
  standalone_check
}

standalone_main "$@"
exit $?
