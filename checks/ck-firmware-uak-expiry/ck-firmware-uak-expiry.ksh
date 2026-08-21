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

AIXRAY_TOOL=ck-firmware-uak-expiry


function standalone_check {
_AIXRAY_SESSION_KEYS=""
HW_GEN="
8202-*|POWER7|2019-09-30
8205-*|POWER7|2019-09-30
8231-*|POWER7|2019-09-30
8284-*|POWER8|2024-10-31
8286-*|POWER8|2024-10-31
9008-*|POWER9|2026-01-31
9009-*|POWER9|2026-01-31
9223-*|POWER9|2026-01-31
9080-M9S|POWER9|2026-01-31
9080-HEX|POWER10|SUPPORTED
9105-*|POWER10|SUPPORTED
9043-*|POWER10|SUPPORTED
"

function yyyymmdd2iso {
  typeset raw=$1 y md m d
  y=${raw%????}
  md=${raw#????}
  m=${md%??}
  d=${raw#??????}
  echo "${y}-${m}-${d}"
}

PRTCONF=$(aix prtconf prtconf); PRTCONF_RC=$?
if [ "$PRTCONF_RC" -ne 0 ]; then PRTCONF=""; fi

  # Hardware-generation lookup, computed here (ahead of the hw_gen check below, which
  # re-derives its own ROW/HWEOS for the lifecycle finding) so aix_uak_expiry can gate its
  # own "genuinely inapplicable" fallback on it. UAKGEN is intentionally coarse: only the
  # generations
  # this codebase can currently NAME as pre-Power10 (POWER7/8/9) count as confirmed-not-
  # applicable; a POWER10+ box or any unrecognized machine type falls through as unknown.
  # Only trust a generation classification derived from a 'prtconf' capture that itself
  # succeeded (adversarial review, M5, round 3, finding #3 residual: a failed prtconf
  # invocation must never let plausible-looking leftover model text drive a confident
  # hardware-inapplicability verdict downstream, same failed-source-to-verdict class as
  # the UAK/hd5 fixes above). UAKGEN stays empty (falls through as unknown) whenever
  # PRTCONF_RC is nonzero, regardless of what $PRTCONF happens to contain.
  UAKGEN=""
  if [ "$PRTCONF_RC" -eq 0 ]; then
    UAKGEN_TM=$(printf '%s\n' "$PRTCONF" | awk -F': *' '/^System Model/{m=$2; sub(/^IBM,/,"",m); print m; exit}')
    UAKGEN=$(printf '%s\n' "$HW_GEN" | awk -F'|' -v tm="$UAKGEN_TM" 'NF>=3 {p=$1; gsub(/\./,"\\.",p); gsub(/\*/,".*",p); if (tm ~ "^"p"$") {print $2; exit}}')
  fi

  # firmware_uak_expiry / aix_uak_expiry — Update Access Key expiry (spec v2 docs/aixray-spec-v2.md
  # Sec 5/Sec 15 M5, cap-firmware). Ranked the single most-missed check in the sourced research's
  # own "5 hidden-risk checks" list: an expired UAK silently blocks applying any firmware/AIX level
  # RELEASED AFTER the expiry date — discovered only at the worst moment (an emergency update).
  # Sourced two ways, NEITHER requiring a new HMC credential surface (spec Sec 5: the HMC-observable
  # 'lslic' path is captured only when an HMC session is already part of the engagement — not
  # assumed here):
  #   - 'lparstat -u': "FW Update Access Key Expiration (YYYYMMDD)" + "AIX Update Access Key
  #     Expiration (YYYYMMDD)" — live-verified on a real POWER9 PowerVS lab LPAR (AIX 7.2):
  #     the FW field reads a real date, the AIX field reads "-" (AIX UAK is Power10+ only, per
  #     spec) — correctly rendered NOT_APPLICABLE below, never PASS or WARN for an
  #     inapplicable fact.
  #   - 'lscfg -vpl sysplanar0': "Update Access Key Exp Date.." (variable dot-padding) — fallback/
  #     cross-check for the firmware UAK specifically, consulted only if lparstat's own field is
  #     unreadable. Same real box confirms an identical date from both commands.
  LPU=$(aix lparstat_u lparstat -u); LPU_RC=$?
  FACT_FW_UAK_COMMANDS="lparstat -u"
  FWUAKRAW=""; FWUAKROWS=0; FWUAK_SRC_OK=0; FWUAK_STATE=NOT_ASSESSED
  if [ "$LPU_RC" -eq 0 ]; then
    FWUAKPARSED=$(printf '%s\n' "$LPU" | awk -F: '/^FW Update Access Key Expiration/{n++; v=$2; gsub(/[ \t]/,"",v)} END{printf "%d:%s\n",n+0,v}')
    FWUAKROWS=${FWUAKPARSED%%:*}
    FWUAKRAW=${FWUAKPARSED#*:}
    [ "$FWUAKROWS" -eq 1 ] || FWUAKRAW=""
    case "$FWUAKRAW" in
      [0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]) FWUAK_SRC_OK=1;;
    esac
  fi
  # Fall back to lscfg whenever lparstat's own field does not (successfully) look like a
  # real 8-digit date -- not just when it's empty or exactly "-". A malformed/unexpected
  # value (a changed output shape, stray text) previously skipped the fallback silently,
  # so the result below could claim "could not read from lparstat -u or lscfg" while lscfg
  # was never actually consulted (adversarial review, M5, round 1). Only a source that
  # itself SUCCEEDED (rc=0) AND produced a value that already looks like a valid date
  # short-circuits the fallback -- neither lparstat's rc nor lscfg's rc is ignored here
  # (adversarial review, M5, round 2, finding #3: a nonzero-rc command's stdout, even
  # if it happens to contain plausible-looking text, must never be trusted as a source).
  if [ "$FWUAK_SRC_OK" -ne 1 ]; then
    FACT_FW_UAK_COMMANDS="$FACT_FW_UAK_COMMANDS|lscfg -vpl sysplanar0"
    LSCFG_SYSPLANAR=$(aix lscfg_sysplanar lscfg -vpl sysplanar0); LSCFG_RC=$?
    if [ "$LSCFG_RC" -eq 0 ]; then
      FWUAKRAW=$(printf '%s\n' "$LSCFG_SYSPLANAR" | awk -F'\\.\\.+' '/Update Access Key Exp Date/{v=$NF; gsub(/[ \t]/,"",v); print v; exit}')
      case "$FWUAKRAW" in
        [0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]) FWUAK_SRC_OK=1;;
        *) FWUAK_SRC_OK=0;;
      esac
    else
      FWUAK_SRC_OK=0
    fi
  fi
  FWUAKISO=""
  [ "$FWUAK_SRC_OK" -eq 1 ] && FWUAKISO=$(yyyymmdd2iso "$FWUAKRAW")
  if [ -n "$FWUAKISO" ] && [ "$(valid_ymd "$FWUAKISO")" -eq 1 ]; then
    FACT_FW_UAK_EXPIRY="$FWUAKISO"
    FWUAKJ=$(d2j "$FWUAKISO")
    if [ "$TODAY_J" -gt "$FWUAKJ" ]; then
      FWUAK_STATE=EXPIRED
      add lifecycle firmware_uak_expiry "Firmware Update Access Key" FAIL high "expired $FWUAKISO" \
          "The firmware Update Access Key expired $FWUAKISO — IBM firmware whose release date is after this expiry date cannot be applied with this key until it is renewed (firmware released BEFORE the expiry date remains eligible; IBM also documents narrow HIPER exceptions). This can block an emergency firmware update at the worst possible moment." \
          "renew the Update Access Key (IBM My Entitled Systems, or via the HMC) before the next firmware update." "ffiec:II.C.11"
    elif [ "$TODAY_J" -ge "$(( FWUAKJ - 30 ))" ]; then
      FWUAK_STATE=EXPIRING
      # Near-expiry, not yet expired -- IBM's own UAK guidance frames the 30 days before
      # expiry as the renewal window; a PASS on the day before expiry would be technically
      # true and practically useless (adversarial review, M5, round 2, finding #5).
      add lifecycle firmware_uak_expiry "Firmware Update Access Key" WARN med "expires $FWUAKISO (within 30 days)" \
          "The firmware Update Access Key expires within 30 days ($FWUAKISO) — IBM's own guidance is to renew a UAK in the 30 days before it lapses, to avoid it expiring before the next firmware update is needed." \
          "renew the Update Access Key (IBM My Entitled Systems, or via the HMC) now, before it expires." "ffiec:II.C.11"
    else
      FWUAK_STATE=VALID
      add lifecycle firmware_uak_expiry "Firmware Update Access Key" PASS low "valid through $FWUAKISO" \
          "The firmware Update Access Key is current — firmware released before its expiry date can be applied." "n/a"
    fi
  else
    case "$UAKGEN" in
      POWER7)
        # Firmware UAKs are a POWER8-and-later entitlement (IBM: "Management of POWER8
        # and Later Update Access Keys") -- a POWER7 box genuinely does not carry this
        # field; never a WARN for a fact this hardware does not have in the first place
        # (adversarial review, M5, round 2, finding #7).
        FACT_FW_UAK_COMMANDS="$FACT_FW_UAK_COMMANDS|prtconf"
        FACT_FW_UAK_EXPIRY=NOT_APPLICABLE; FWUAK_STATE=NOT_APPLICABLE
        add lifecycle firmware_uak_expiry "Firmware Update Access Key" NOT_APPLICABLE low "n/a (POWER8+ only)" \
            "The firmware Update Access Key is a POWER8-and-later entitlement; this is POWER7 hardware, which does not carry one." "n/a"
        ;;
      *)
        FWUAK_STATE=NOT_ASSESSED
        add lifecycle firmware_uak_expiry "Firmware Update Access Key" NOT_ASSESSED low "unreadable" \
            "Could not read the firmware Update Access Key expiry from 'lparstat -u' or 'lscfg -vpl sysplanar0' (or the command that would have supplied it did not itself succeed)." \
            "check 'lparstat -u' (FW Update Access Key Expiration) or the HMC directly."
        ;;
    esac
  fi
}

function standalone_run {
  standalone_check
}

standalone_main "$@"
exit $?
