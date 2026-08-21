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

AIXRAY_TOOL=ck-secure-by-default


function standalone_check {
_AIXRAY_SESSION_KEYS=""
  # secure_by_default — CIS IBM AIX 7 v1.2.0 1.3.4.1 (Level 1): was Secure by
  # Default (SbD) selected when this system was installed? SbD installs a
  # minimal software set in a secure configuration: LIGHTER bos.net.tcp.client
  # and bos.net.tcp.server filesets that exclude telnet, ftp, rsh, rcp and # network-lint: allow -- prose comment, no network call
  # sendmail, followed at first boot by # network-lint: allow -- prose comment, no network call
  #   /usr/sbin/aixpert -f /etc/security/aixpert/core/SbD.xml -p \
  #     2>/etc/security/aixpert/log/firstboot.log
  #
  # THE BENCHMARK SPECIFIES NO AUDIT PROCEDURE FOR THIS CONTROL — its Audit
  # section is empty. Everything below is PowerTrue-authored inference from the
  # control's Description; see this check's README before trusting a verdict.
  #
  # Two independent evidence classes:
  #   class 1 (applied-profile, the DISCRIMINATOR) — did the SbD firstboot step
  #     run? /etc/security/aixpert/log/firstboot.log is created by nothing else,
  #     and /etc/firstboot carries the aixpert SbD.xml invocation itself.
  #   class 2 (fileset content, CORROBORATING) — are the excluded binaries and
  #     the filesets that own them absent from the installed software set?
  # Class 2 can never establish the control on its own: an administrator who
  # removed telnet by hand after a normal install produces exactly the same # network-lint: allow -- prose comment, no network call
  # binary-absence picture as SbD. Class 2 therefore only DISPROVES (excluded
  # software found -> not SbD) or corroborates; only class 1 can produce PASS.
  #
  # aix vs aixv: probes 1-3 all need stderr, because the diagnostic is the only
  # thing separating "determinately absent" from "unreadable to this identity",
  # and those two states carry different verdicts. Probe 4 goes through aix():
  # the fileset inventory needs no diagnostic (lslpp -L rc alone settles it) and
  # the lslpp_L_all key is shared with ck-nfs-server-absent, which captures it
  # through aix() — using aixv() here would not change replay but would make the
  # shared key's capture contract ambiguous.
  typeset SBD_LOGDIR_RAW SBD_LOGDIR_RC SBD_LOGDIR_HIT
  typeset SBD_FIRSTBOOT_RAW SBD_FIRSTBOOT_RC SBD_FIRSTBOOT_HIT
  typeset SBD_BIN_RAW SBD_BIN_RC SBD_BIN_RAN SBD_BIN_TOKEN SBD_BIN_REST
  typeset SBD_BIN_PRESENT_N SBD_BIN_LIST
  typeset SBD_LPP_RAW SBD_LPP_RC SBD_LPP_TOKEN SBD_LPP_REST
  typeset SBD_LPP_N SBD_LPP_PAIR SBD_LPP_LIST
  typeset SBD_BIN_ABSENT_N SBD_BIN_UNKNOWN_N
  typeset SBD_CLASS1 SBD_CLASS1_WHY SBD_CLASS2
  typeset SBD_EXCL_N SBD_EXCL_LIST SBD_EVIDENCE
  typeset SBD_STATUS SBD_OBS SBD_MEAN SBD_FIX

  SBD_LOGDIR_RAW=""
  SBD_LOGDIR_RC=127
  SBD_LOGDIR_HIT=0
  SBD_FIRSTBOOT_RAW=""
  SBD_FIRSTBOOT_RC=127
  SBD_FIRSTBOOT_HIT=0
  SBD_BIN_RAW=""
  SBD_BIN_RC=127
  SBD_BIN_RAN=0
  SBD_BIN_TOKEN=""
  SBD_BIN_REST=""
  SBD_BIN_PRESENT_N=0
  SBD_BIN_ABSENT_N=0
  SBD_BIN_UNKNOWN_N=0
  SBD_BIN_LIST=""
  SBD_LPP_RAW=""
  SBD_LPP_RC=127
  SBD_LPP_TOKEN=""
  SBD_LPP_REST=""
  SBD_LPP_N=0
  SBD_LPP_PAIR=0
  SBD_LPP_LIST=""
  SBD_CLASS1=UNKNOWN
  SBD_CLASS1_WHY=""
  SBD_CLASS2=UNKNOWN
  SBD_EXCL_N=0
  SBD_EXCL_LIST=""
  SBD_EVIDENCE=""
  SBD_STATUS=""
  SBD_OBS=""
  SBD_MEAN=""
  SBD_FIX=""

  # Probe 1 — the aixpert log DIRECTORY, not the log file. Listing the parent
  # is what makes an absent firstboot.log trustworthy: if the directory itself
  # is unreadable, ls on the file inside it can report "not found" for a file
  # that exists, and that would manufacture a determinate negative out of a
  # permission problem.
  SBD_LOGDIR_RAW=$(aixv sbd_aixpert_log_dir ls -l /etc/security/aixpert/log)
  SBD_LOGDIR_RC=$?

  # Probe 2 — the firstboot script that runs the SbD profile. grep separates
  # "read it, no aixpert step" (rc 1) from "could not read it" (rc 2), and the
  # merged stderr names which of the two a non-zero rc actually was.
  SBD_FIRSTBOOT_RAW=$(aixv sbd_firstboot_aixpert grep -n aixpert /etc/firstboot)
  SBD_FIRSTBOOT_RC=$?

  # Probe 3 — the excluded binaries. ls exits non-zero when ANY operand is
  # missing, which on a compliant SbD box is the expected case, so the per-path
  # verdict is read out of the merged stream and never off the rc.
  SBD_BIN_RAW=$(aixv sbd_cleartext_binaries ls -l /usr/bin/telnet /usr/bin/ftp /usr/bin/rsh /usr/bin/rcp /usr/sbin/sendmail) # network-lint: allow -- aixv() runs the LOCAL ls on excluded binary paths; ls makes no network call
  SBD_BIN_RC=$?
  # ls itself only ever exits 0, 1 or 2. Any other value means the probe never
  # ran (127 under fixture replay of a key this capture does not carry), and
  # nothing may be concluded from its empty output.
  SBD_BIN_RAN=0
  case "$SBD_BIN_RC" in
    0|1|2) SBD_BIN_RAN=1 ;;
  esac

  # Probe 4 — the installed software inventory. Modern AIX splits the TCP/IP
  # client and server into per-application filesets (bos.net.tcp.telnet, # network-lint: allow -- prose comment, no network call
  # .ftp, .rcmd, .sendmail, ...); on the 2026-08-06 lab captures the 7.2 box # network-lint: allow -- prose comment, no network call
  # carries all seven excluded filesets and the 7.3 box carries
  # bos.net.tcp.sendmail. An installed excluded fileset is inventory-level # network-lint: allow -- prose comment, no network call
  # proof the excluded applications are in the software set.
  SBD_LPP_RAW=$(aix lslpp_L_all lslpp -L)
  SBD_LPP_RC=$?

  # ---- class 1: applied-profile evidence ----------------------------------
  if [ "$SBD_LOGDIR_RC" -eq 0 ]; then
    SBD_LOGDIR_HIT=$(printf '%s\n' "$SBD_LOGDIR_RAW" | awk '
      $NF == "firstboot.log" { hit = 1 }
      END { print hit ? 1 : 0 }')
    if [ "$SBD_LOGDIR_HIT" -eq 1 ]; then
      SBD_CLASS1=POSITIVE
      SBD_CLASS1_WHY="firstboot.log present in /etc/security/aixpert/log"
    else
      SBD_CLASS1=NEGATIVE
      SBD_CLASS1_WHY="firstboot.log absent from /etc/security/aixpert/log"
    fi
  else
    # A non-zero rc is only determinate when the diagnostic says the directory
    # is genuinely absent. Anything else (permission, unknown) stays UNKNOWN.
    case "$SBD_LOGDIR_RAW" in
      *"not found"*|*"No such file"*|*"does not exist"*)
        SBD_CLASS1=NEGATIVE
        SBD_CLASS1_WHY="/etc/security/aixpert/log does not exist"
        ;;
    esac
  fi

  # Probe 2 can raise UNKNOWN or NEGATIVE to POSITIVE, and can settle an
  # UNKNOWN as NEGATIVE, but never overrides a positive artifact: an SbD
  # artifact that is present is stronger evidence than another one missing.
  if [ "$SBD_FIRSTBOOT_RC" -eq 0 ]; then
    SBD_FIRSTBOOT_HIT=$(printf '%s\n' "$SBD_FIRSTBOOT_RAW" | awk '
      index($0, "SbD.xml") > 0 { hit = 1 }
      END { print hit ? 1 : 0 }')
    if [ "$SBD_FIRSTBOOT_HIT" -eq 1 ]; then
      SBD_CLASS1=POSITIVE
      SBD_CLASS1_WHY="/etc/firstboot runs aixpert with SbD.xml"
    elif [ "$SBD_CLASS1" = UNKNOWN ]; then
      SBD_CLASS1=NEGATIVE
      SBD_CLASS1_WHY="/etc/firstboot runs aixpert with a profile other than SbD.xml"
    fi
  elif [ "$SBD_FIRSTBOOT_RC" -eq 1 ] && [ "$SBD_CLASS1" = UNKNOWN ]; then
    # grep rc 1 is a determinate "the file was read and nothing matched".
    SBD_CLASS1=NEGATIVE
    SBD_CLASS1_WHY="/etc/firstboot contains no aixpert step"
  fi

  # ---- class 2: fileset-content evidence -----------------------------------
  # Per-path tri-state out of the merged ls stream. A path counts as present
  # only on a mode-prefixed listing line and as absent only on a line whose
  # diagnostic names it; everything else stays unknown for that path.
  # network-lint: allow-next=3 -- the awk program below matches the excluded binary pathnames in captured ls text; no network call
  SBD_BIN_TOKEN=$(printf '%s\n' "$SBD_BIN_RAW" | awk '
    BEGIN {
      n = split("/usr/bin/telnet /usr/bin/ftp /usr/bin/rsh /usr/bin/rcp /usr/sbin/sendmail", want, " ")
      for (i = 1; i <= n; i++) wanted[want[i]] = 1
    }
    {
      if (index($0, "not found") > 0 || index($0, "No such file") > 0 ||
          index($0, "does not exist") > 0) {
        for (f = 1; f <= NF; f++) {
          token = $f
          sub(/[.,:]+$/, "", token)
          if (token in wanted) absent[token] = 1
        }
        next
      }
      if (NF >= 5 && $1 ~ /^[-dlbcps]/) {
        for (f = 1; f <= NF; f++) {
          if ($f in wanted) present[$f] = 1
        }
      }
    }
    END {
      np = 0
      na = 0
      nu = 0
      list = ""
      for (i = 1; i <= n; i++) {
        p = want[i]
        if (p in present) {
          np++
          if (np <= 2) list = (list == "" ? p : list "," p)
        } else if (p in absent) {
          na++
        } else {
          nu++
        }
      }
      print np ":" na ":" nu ":" list
    }')
  SBD_BIN_PRESENT_N=${SBD_BIN_TOKEN%%:*}
  SBD_BIN_REST=${SBD_BIN_TOKEN#*:}
  SBD_BIN_ABSENT_N=${SBD_BIN_REST%%:*}
  SBD_BIN_REST=${SBD_BIN_REST#*:}
  SBD_BIN_UNKNOWN_N=${SBD_BIN_REST%%:*}
  SBD_BIN_LIST=${SBD_BIN_REST#*:}

  # The inventory is trusted only on rc 0; a failed lslpp says nothing.
  if [ "$SBD_LPP_RC" -eq 0 ]; then
    # network-lint: allow-next=3 -- the awk program below matches the excluded fileset names in captured lslpp text; no network call
    SBD_LPP_TOKEN=$(printf '%s\n' "$SBD_LPP_RAW" | awk '
      BEGIN {
        n = split("bos.net.tcp.telnet bos.net.tcp.telnetd bos.net.tcp.ftp bos.net.tcp.ftpd bos.net.tcp.rcmd bos.net.tcp.rcmd_server bos.net.tcp.sendmail", want, " ")
        for (i = 1; i <= n; i++) wanted[want[i]] = 1
      }
      $1 == "bos.net.tcp.client" || $1 == "bos.net.tcp.client_core" { cli = 1 }
      $1 == "bos.net.tcp.server" || $1 == "bos.net.tcp.server_core" { srv = 1 }
      $1 in wanted { found[$1] = 1 }
      END {
        nf = 0
        list = ""
        for (i = 1; i <= n; i++) {
          if (want[i] in found) {
            nf++
            if (nf <= 2) list = (list == "" ? want[i] : list "," want[i])
          }
        }
        print nf ":" ((cli && srv) ? 1 : 0) ":" list
      }')
    SBD_LPP_N=${SBD_LPP_TOKEN%%:*}
    SBD_LPP_REST=${SBD_LPP_TOKEN#*:}
    SBD_LPP_PAIR=${SBD_LPP_REST%%:*}
    SBD_LPP_LIST=${SBD_LPP_REST#*:}
  fi

  SBD_EXCL_N=$((SBD_BIN_PRESENT_N + SBD_LPP_N))
  if [ -n "$SBD_BIN_LIST" ] && [ -n "$SBD_LPP_LIST" ]; then
    SBD_EXCL_LIST="$SBD_BIN_LIST,$SBD_LPP_LIST"
  else
    SBD_EXCL_LIST="$SBD_BIN_LIST$SBD_LPP_LIST"
  fi

  if [ "$SBD_BIN_RAN" -eq 1 ] && [ "$SBD_BIN_PRESENT_N" -gt 0 ]; then
    SBD_CLASS2=PRESENT
  elif [ "$SBD_LPP_RC" -eq 0 ] && [ "$SBD_LPP_N" -gt 0 ]; then
    SBD_CLASS2=PRESENT
  elif [ "$SBD_BIN_RAN" -eq 1 ] && [ "$SBD_BIN_ABSENT_N" -eq 5 ] && \
       [ "$SBD_LPP_RC" -eq 0 ] && [ "$SBD_LPP_PAIR" -eq 1 ]; then
    # Every excluded binary determinately absent, no excluded fileset
    # installed, and the TCP/IP client and server software IS installed — so
    # the absence is an exclusion from the installed set, not an absence of
    # TCP/IP altogether. Corroborating only; this never reaches PASS alone.
    SBD_CLASS2=ABSENT
  fi

  # ---- verdict -------------------------------------------------------------
  # Order matters. Disproof first: excluded software found settles the control
  # whatever the applied-profile evidence says, because an SbD system never
  # carries it. PASS second, and only on class 1. Determinate class-1 absence
  # third — that is the hand-hardened normal install, and it is a FAIL, not a
  # refusal. NOT_ASSESSED last, only when nothing was established.
  if [ "$SBD_CLASS2" = PRESENT ]; then
    SBD_EVIDENCE=$(printf '%s\n' "$SBD_EXCL_LIST" | awk -v total="$SBD_EXCL_N" '
      {
        n = split($0, item, ",")
        shown = 0
        list = ""
        for (i = 1; i <= n; i++) {
          if (item[i] == "") continue
          if (shown >= 2) break
          list = (list == "" ? item[i] : list ", " item[i])
          shown++
        }
        more = total - shown
        text = "SbD-excluded software installed (" total "): " list
        if (more > 0) text = text " +" more " more"
        print text
      }')
    SBD_STATUS=FAIL
    SBD_OBS="$SBD_EVIDENCE"
    SBD_MEAN="Software that a Secure by Default installation never installs is present on this system, so this system was not installed with Secure by Default."
    SBD_FIX="Secure by Default is an installation-time option and cannot be enabled afterwards: rebuild the system with Secure by Default selected, or remove the excluded software and apply /etc/security/aixpert/core/SbD.xml through the approved change process. PTxray recommends these actions and never performs them."
  elif [ "$SBD_CLASS1" = POSITIVE ]; then
    SBD_STATUS=PASS
    SBD_OBS="SbD applied at install: $SBD_CLASS1_WHY"
    SBD_MEAN="The Secure by Default profile was applied by this system's installation, and no software that Secure by Default excludes was found installed."
    SBD_FIX="n/a"
  elif [ "$SBD_CLASS1" = NEGATIVE ]; then
    SBD_STATUS=FAIL
    SBD_OBS="no SbD install evidence: $SBD_CLASS1_WHY"
    SBD_MEAN="No artifact of the Secure by Default first-boot step exists on this system, so Secure by Default was not selected when it was installed. Absence of the excluded binaries alone does not satisfy this control: a normal install hardened by hand looks identical."
    SBD_FIX="Secure by Default is an installation-time option and cannot be enabled afterwards: rebuild the system with Secure by Default selected, or accept the residual risk on the record after confirming the excluded applications are removed and the AIX Security Expert high-level profile is applied. PTxray recommends these actions and never performs them."
  else
    SBD_STATUS=NOT_ASSESSED
    SBD_OBS="not assessed — SbD install evidence unreadable (aixpert log rc=$SBD_LOGDIR_RC, /etc/firstboot rc=$SBD_FIRSTBOOT_RC)"
    SBD_MEAN="Neither the aixpert first-boot log directory nor /etc/firstboot could be read, and no excluded software was found, so whether Secure by Default was selected at installation is unknown."
    SBD_FIX="rerun PTxray with an identity that can read /etc/security/aixpert/log and /etc/firstboot, then rerun the check."
  fi

  add security secure_by_default "Secure by Default installation" \
    "$SBD_STATUS" med "$SBD_OBS" "$SBD_MEAN" "$SBD_FIX" "cis-l1"
}

function standalone_run {
  standalone_check
}

standalone_main "$@"
exit $?
