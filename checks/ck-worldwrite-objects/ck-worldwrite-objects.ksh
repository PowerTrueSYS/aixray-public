#!/bin/ksh
# Generated standalone PTxray check support. READ-ONLY: captures only; no
# remediation, service control, network access, or durable target-host writes.
set -u

# Match the monolith's guarded AIX command search path and parsing locale.
PATH=/usr/bin:/etc:/usr/sbin:/usr/ucb:/usr/bin/X11:/sbin:/usr/ios/cli:${PATH:-}
export PATH
LC_ALL=C
export LC_ALL

AIXRAY_STANDALONE_VERSION="1.3.0"

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
# substitution. Byte-for-byte the monolith's semantics (src/ptxray-aix.sh.in);
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
  if [ -z "${AIXRAY_FIXTURES:-}" ]; then
    _os=$(uname -s 2>/dev/null)
    if [ "$_os" = "AIX" ]; then
      :
    elif [ "$_os" = "OS400" ] && [ "${IBMI_PROBES:-0}" = 1 ]; then
      :
    else
      echo "$AIXRAY_TOOL: this standalone check runs on AIX/VIOS" >&2
      return 2
    fi
  fi
  standalone_initialize
  initialize_rc=$?
  [ "$initialize_rc" -eq 0 ] || return "$initialize_rc"
  if [ "${IBMI_PROBES:-0}" = 1 ]; then
    if ! ibmi_require_qsecofr; then
      echo "$AIXRAY_TOOL requires SESSION_USER=QSECOFR and SYSTEM_USER=QSECOFR; no scan was run." >&2
      return 2
    fi
  elif [ -z "${AIXRAY_FIXTURES:-}" ] && [ "${MYUID:-}" != 0 ]; then
    echo "$AIXRAY_TOOL requires root; no scan was run." >&2
    return 2
  fi
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

AIXRAY_TOOL=ck-worldwrite-objects


function standalone_check {
_AIXRAY_SESSION_KEYS=""
  # worldwrite_objects — group-writable non-directory objects on local (jfs/jfs2)
  # filesystems owned by an administrative group (control 3.3, L2). Absence is the
  # compliant state; each hit is an unreviewed group-write that needs operator triage.
  typeset WWO_RAW WWO_RC ADM_RAW ADM_RC ADM_LIST WWO_RESULT WWO_PARSE_RC
  typeset WWO_HITS WWO_PATHS

  WWO_RAW=$(aix ww_objects find -L / \( -fstype jfs -o -fstype jfs2 \) ! -type d -perm -g+w -ls)
  WWO_RC=$?
  ADM_RAW=$(aix admin_groups lsgroup -a admin ALL)
  ADM_RC=$?

  # `find -L` exits non-zero on any unreadable path or dangling symlink, which every
  # real AIX box has: on a lab LPAR the scan exits 1 while still emitting a complete
  # 120KB listing (verified 2026-08-05). Refusing on rc alone threw that evidence away
  # and made this control refuse on every real system.
  #
  # The two directions are not symmetric. An object the scan DID observe is conclusive
  # evidence of a violation, and a partial traversal cannot un-observe it -- so a hit
  # still FAILs. Absence is not provable from an incomplete traversal, so the PASS
  # direction must still refuse when the scan did not complete. That asymmetry is
  # handled at the verdict sites below; only a scan that produced nothing at all is
  # refused up front.
  if [ "$WWO_RC" -ne 0 ] && [ -z "$WWO_RAW" ]; then
    add security worldwrite_objects "group-writable admin-group objects" NOT_ASSESSED low \
        "not assessed — ww_objects failed (rc=$WWO_RC) and produced no listing" \
        "The group-writable-object scan did not complete and returned nothing, so PTxray cannot enumerate the objects that would need group-write review." \
        "Confirm the group-writable-object scan completes without error, then rerun PTxray." \
        "cis-l2"
  elif [ "$ADM_RC" -ne 0 ]; then
    add security worldwrite_objects "group-writable admin-group objects" NOT_ASSESSED low \
        "not assessed — admin_groups failed (rc=$ADM_RC)" \
        "The administrative-group enumeration did not complete, so PTxray cannot identify which objects' group-write would require review." \
        "Confirm the administrative-group enumeration completes without error, then rerun PTxray." \
        "cis-l2"
  elif [ -z "$WWO_RAW" ]; then
    # Reached only when the scan completed (rc=0), so empty output is a determinate
    # absence and PASS is earned rather than assumed.
    add security worldwrite_objects "group-writable admin-group objects" PASS low \
        "no group-writable admin-group objects on local filesystems" \
        "No non-directory group-writable object exists on a local jfs/jfs2 filesystem, so nothing requires group-write review." \
        "n/a" "cis-l2"
  elif [ -z "$ADM_RAW" ]; then
    add security worldwrite_objects "group-writable admin-group objects" PASS low \
        "no group-writable admin-group objects on local filesystems" \
        "No administrative group is defined, so no object's group-write can belong to an administrative group." \
        "n/a" "cis-l2"
  else
    ADM_LIST=$(printf '%s\n' "$ADM_RAW" | awk 'index($0,"true") {if (n++) printf " "; printf "%s", $1}')
    WWO_RESULT=$(printf '%s\n' "$WWO_RAW" | awk -v admins="$ADM_LIST" '
      BEGIN {
        na = split(admins, atmp, " ")
        for (i = 1; i <= na; i++) admin[atmp[i]] = 1
        nhits = 0
        npaths = 0
      }
      {
        # `find -ls` fields are fixed only through $6:
        #   $1 inode  $2 blocks  $3 perms  $4 links  $5 OWNER  $6 GROUP
        # After that the layout varies: a regular file has one size field, but a
        # device file has a "major," "minor" PAIR, which shifts everything right by
        # one. On a lab LPAR that is 345 of 1243 lines. So the path cannot be read
        # from a fixed index -- it is located as the first field beginning with "/",
        # and for a symlink it ends before the " -> " target.
        #
        # The group is $6. This previously tested $5, the OWNER, which is a different
        # thing entirely: on a lab LPAR it matched 40 objects where the correct
        # group test matches 1242 -- a 30x undercount on a security control, i.e. a
        # silent false NEGATIVE, the worst direction for this check to be wrong in.
        if (NF < 7) next
        if (!($6 in admin)) next
        pstart = 0
        for (i = 7; i <= NF; i++) {
          if (substr($i, 1, 1) == "/") { pstart = i; break }
        }
        if (pstart == 0) next
        nhits++
        if (npaths < 10) {
          path = $pstart
          for (i = pstart + 1; i <= NF; i++) {
            if ($i == "->") break
            path = path " " $i
          }
          paths[npaths++] = path
        }
      }
      END {
        out = ""
        for (i = 0; i < npaths; i++) {
          if (i > 0) out = out ", "
          out = out paths[i]
        }
        remaining = nhits - npaths
        if (remaining > 0) out = out " +" remaining " more"
        printf "%d|%s", nhits, out
      }')
    WWO_PARSE_RC=$?
    WWO_HITS=${WWO_RESULT%%\|*}
    WWO_PATHS=${WWO_RESULT#*\|}
    if [ "$WWO_PARSE_RC" -ne 0 ]; then
      add security worldwrite_objects "group-writable admin-group objects" NOT_ASSESSED low \
          "not assessed — worldwrite_objects parse failed (rc=$WWO_PARSE_RC)" \
          "The group-writable-object listing could not be parsed, so PTxray cannot enumerate the objects that would need group-write review." \
          "Rerun PTxray and report the parse failure." \
          "cis-l2"
    elif [ "$WWO_HITS" -eq 0 ] && [ "$WWO_RC" -ne 0 ]; then
      # Nothing found, but the traversal did not complete. Absence is exactly what an
      # incomplete scan cannot establish, so this must refuse rather than PASS.
      add security worldwrite_objects "group-writable admin-group objects" NOT_ASSESSED low \
          "not assessed — scan incomplete (rc=$WWO_RC) and no admin-group object was observed" \
          "No administratively-owned group-writable object was seen, but the filesystem traversal did not complete, so their absence is not established." \
          "Resolve the traversal errors (commonly unreadable paths or dangling symlinks under 'find -L'), then rerun PTxray." \
          "cis-l2"
    elif [ "$WWO_HITS" -eq 0 ]; then
      add security worldwrite_objects "group-writable admin-group objects" PASS low \
          "no group-writable admin-group objects on local filesystems" \
          "No non-directory group-writable object on a local jfs/jfs2 filesystem is owned by an administrative group, so none requires group-write review." \
          "n/a" "cis-l2"
    else
      add security worldwrite_objects "group-writable admin-group objects" FAIL high \
          "$WWO_PATHS" \
          "$WWO_HITS group-writable non-directory object(s) on local jfs/jfs2 filesystems are owned by an administrative group; their group-write permission has not been shown reviewed and approved." \
          "Review each listed object and either remove group-write where it is not required or record the approval. PTxray recommends the chmod command and never executes it." \
          "cis-l2"
    fi
  fi
}

function standalone_run {
  standalone_check
}

standalone_main "$@"
exit $?
