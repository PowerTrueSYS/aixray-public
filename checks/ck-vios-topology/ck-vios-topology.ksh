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

AIXRAY_TOOL=ck-vios-topology


function standalone_check {
_AIXRAY_SESSION_KEYS=""
  # ---- shared signals: CAA cluster presence + per-SEA HA config --------------------
  # Read cluster -status ONCE (used by ssp_cluster below AND by the SEA no-control-channel
  # logic: a CAA/SSP cluster enables the newer control-channel-less SEA failover, so a
  # missing ctl_chan is NOT a hard FAIL when a cluster is present).
  # documentation-grounded; validate on a live VIOS (IBM Partner Silver test box).
  CLST=$(aix cluster_status cluster -status); RC=$?
  CLPRESENT=0
  if [ "$RC" -eq 0 ] && [ -n "$CLST" ] && printf '%s\n' "$CLST" | grep -qi 'Cluster'; then CLPRESENT=1; fi

  RAW_SEA=$(aix lsdev_sea lsdev -t sea); RC_SEA=$?
  SEAS=$(printf '%s\n' "$RAW_SEA" | awk 'NR>1 && $1 ~ /^ent[0-9]+$/{print $1}')
  if [ -n "$SEAS" ] && [ "$RC_SEA" -eq 0 ]; then
    SEACNT=0; BADHA=0; NOCTL=0; NOPRIO=0; NOLSA=0; SEADET=""
    for SEA in $SEAS; do
      SEACNT=$((SEACNT+1))
      LSA=$(aix "lsattr_sea_$SEA" lsattr -El "$SEA"); RC_LSA=$?
      if [ "$RC_LSA" -ne 0 ]; then NOLSA=$((NOLSA+1)); LSAFAIL_RC=$RC_LSA; continue; fi
      HAM=$(printf '%s\n' "$LSA" | awk '$1=="ha_mode"{print $2; exit}')
      CTL=$(printf '%s\n' "$LSA" | awk '$1=="ctl_chan"{print $2; exit}')
      PRIO=$(printf '%s\n' "$LSA" | awk '$1=="priority"{print $2; exit}')
      [ -z "$HAM" ] && HAM="unknown"
      # ctl_chan is a control-channel adapter (entN) when set; anything else = unset (an
      # empty attr value makes awk read the description word, so anchor on the entN shape).
      case "$CTL" in (ent[0-9]*) : ;; (*) CTL="";; esac
      case "$PRIO" in (''|*[!0-9]*) PRIO="";; esac
      case "$HAM" in (auto|standby) : ;; (*) BADHA=$((BADHA+1));; esac
      [ -z "$CTL" ] && NOCTL=$((NOCTL+1))
      [ -z "$PRIO" ] && NOPRIO=$((NOPRIO+1))
      ESTAT=$(aix "entstat_sea_$SEA" entstat -d "$SEA"); RC_ESTAT=$?
      SST=$(printf '%s\n' "$ESTAT" | awk -F: '/^[ \t]*State:/{v=$2; gsub(/^[ \t]+|[ \t]+$/,"",v); print v; exit}')
      [ -z "$SST" ] && SST="?"
      if [ "$RC_ESTAT" -ne 0 ]; then SST="?"; fi
      SEADET="$SEADET${SEADET:+; }$SEA ha_mode=$HAM ctl_chan=${CTL:-none} priority=${PRIO:-unset} state=$SST"
    done
    if [ "$NOLSA" -gt 0 ]; then
      add resilience sea_failover "SEA failover posture" NOT_ASSESSED low \
          "not assessed — the SEA attribute probe failed for $NOLSA SEA(s) (rc=$LSAFAIL_RC)" \
          "The SEA list was read, but 'lsattr -El <sea>' failed for one or more SEAs — an empty ha_mode from a failed probe must not be read as 'not configured for failover'." \
          "re-run 'lsattr -El <sea>' on the box and inspect its error before grading SEA failover posture."
    elif [ "$BADHA" -gt 0 ]; then
      add resilience sea_failover "SEA failover posture" FAIL high "$SEADET" \
          "A Shared Ethernet Adapter on this VIOS is not configured for failover (ha_mode not auto/standby) — a second VIOS cannot take over the bridge, so every client LPAR bridged through this SEA loses its network the moment this VIOS goes down. This is not a redundant network." \
          "set the SEA for failover ('chdev -dev <sea> -attr ha_mode=auto ctl_chan=<ent> priority=<n>'), give the pair distinct priorities, and confirm the partner VIOS's SEA ('entstat -d <sea>' on both)."
    elif [ "$NOCTL" -gt 0 ] && [ "$CLPRESENT" -eq 0 ]; then
      add resilience sea_failover "SEA failover posture" FAIL high "$SEADET" \
          "A Shared Ethernet Adapter is set to fail over but has no control channel (ctl_chan) and no CAA cluster to replace it — the two VIOS cannot arbitrate primary/backup, so a failover can leave both bridging at once (split-brain: duplicated frames, a broadcast storm) or neither." \
          "add a control-channel adapter/VLAN ('mkvdev -sea ...'/'chdev -dev <sea> -attr ctl_chan=<ent>'), or adopt the CAA control-channel-less method on a supported VIOS level; verify on both VIOS."
    elif [ "$NOCTL" -gt 0 ]; then
      add resilience sea_failover "SEA failover posture" WARN med "$SEADET" \
          "A Shared Ethernet Adapter has no ctl_chan, but a CAA cluster is present — the newer control-channel-less SEA failover uses the cluster instead. Likely intentional; confirm it is actually the CAA method and not a half-removed control channel." \
          "confirm the SEA uses CAA-based failover (supported VIOS level + cluster) rather than a lost control channel; check the partner VIOS's SEA config too."
    elif [ "$NOPRIO" -gt 0 ]; then
      add resilience sea_failover "SEA failover posture" WARN med "$SEADET" \
          "The SEA is set for failover with a control channel, but a priority is unset/unreadable — without distinct priorities across the pair the primary/backup roles are undefined and can flap." \
          "set a priority on each side ('chdev -dev <sea> -attr priority=<n>'), distinct between the two VIOS (e.g. 1 and 2)."
    else
      add resilience sea_failover "SEA failover posture" PASS low "$SEADET" \
          "This VIOS's Shared Ethernet Adapter(s) are configured for failover (ha_mode auto/standby, a control channel set, a priority set) — the network bridge is set up to survive this VIOS. Single-box scan: confirm the partner VIOS's SEA (priority + state on the other LPAR) to prove the pair actually fails over." \
          "n/a"
    fi
  fi

  # vios_topology — single-vs-dual VIOS & the box-level SPOF verdict (NEW).
  # documentation-grounded; validate on a live VIOS (IBM Partner Silver test box).
  # A single VIOS is a single point of failure for EVERY client LPAR it serves — both disk
  # AND network. Inherited shops are full of "dual VIOS" that is really one working side (the
  # second was never wired, or was wired and left broken). We infer HA topology from what one
  # box can see: a SEA configured for failover (ha_mode auto/standby + a control channel) OR
  # a CAA/SSP cluster implies a partner VIOS exists. A lone SEA with no HA config, and no
  # cluster, means either a genuinely standalone VIOS or a broken pair — both a SPOF worth
  # flagging. Conservative: WARN when we simply cannot see a partner (an inference, not a
  # confident FAIL); FAIL only when a SEA is present but demonstrably unable to fail over.
  # Verified: reuses the sea_failover attr reads above, which are documented per IBM
  # mkvdev command reference (see sea_failover comment for field sources).
  if { [ -n "$SEAS" ] && [ "$RC_SEA" -eq 0 ]; } || [ "$CLPRESENT" -eq 1 ]; then
    if [ "${NOLSA:-0}" -gt 0 ] && [ "$CLPRESENT" -eq 0 ]; then
      add resilience vios_topology "VIOS redundancy topology" NOT_ASSESSED low \
          "SEA attribute probe failed for $NOLSA SEA(s) (rc=$LSAFAIL_RC); no CAA cluster" \
          "The SEA list was read, but 'lsattr -El <sea>' failed, so HA attributes cannot be graded — a failed probe must not be read as a missing partner or as a failover-ready pair." \
          "re-run 'lsattr -El <sea>' on the box and inspect its error before grading VIOS topology."
    elif [ -n "$SEAS" ] && { [ "$BADHA" -gt 0 ] || [ "$NOCTL" -gt 0 ]; } && [ "$CLPRESENT" -eq 0 ]; then
      add resilience vios_topology "VIOS redundancy topology" FAIL high "SEA present, not failover-ready; no CAA cluster" \
          "This VIOS bridges the network but its SEA is not able to fail over to a partner (no control channel / ha_mode not set) and there is no CAA cluster — so a second VIOS cannot cleanly take over the network. Either this is a standalone VIOS (a single point of failure for every client's disk and network) or a broken pair where the second side was never fully wired." \
          "decide the intent: if it is meant to be an HA pair, wire the SEA control channel + ha_mode on BOTH VIOS and confirm the partner is serving; if it is genuinely standalone, treat this VIOS as a known SPOF (single client outage domain) in the runbook."
    elif { [ -n "$SEAS" ] && [ "$BADHA" -eq 0 ] && [ "$NOCTL" -eq 0 ]; } || [ "$CLPRESENT" -eq 1 ]; then
      add resilience vios_topology "VIOS redundancy topology" PASS low "HA config present (SEA failover / CAA cluster) — partner VIOS implied" \
          "This VIOS carries HA configuration (a failover-ready SEA and/or a CAA cluster), which implies a partner VIOS exists to take over. A single-box scan cannot PROVE the partner is healthy and actually serving — that lives on the other LPAR." \
          "confirm the second VIOS exists, is on a different physical path, and is genuinely serving clients (its own ptxray/entstat/lsmap) — do not assume 'configured for failover' means the partner is up."
    else
      add resilience vios_topology "VIOS redundancy topology" WARN high "no SEA HA config and no CAA cluster visible from this box" \
          "Nothing on this box indicates a partner VIOS — no failover-ready SEA, no CAA cluster. This may be a genuinely single VIOS, in which case every client LPAR's disk AND network depends on this one server: a single point of failure whose loss takes down all its clients." \
          "confirm whether a second VIOS exists and is actually serving; if not, this is a real SPOF — plan a partner VIOS, or document the single-VIOS risk and its blast radius explicitly."
    fi
  fi

  # RULING addition (2026-08-15) — precondition absent: no SEA and no CAA cluster. Emit one
  # determinate NOT_APPLICABLE finding (rc 0), not an empty envelope (rc 3). Mirrors the
  # ck-vios-level else-branch (role=aix reason string). Appended AFTER the frozen fragment.
  # RC_SEA distinguishes a probe that genuinely found no SEA (rc 0) from one that failed
  # (rc != 0): both are NOT_APPLICABLE (this box is outside the control's scope), but the
  # observed string exposes which case produced the empty SEA list, so a failed probe cannot
  # launder itself into a clean "no SEA" reading.
  if { [ -z "$SEAS" ] || [ "$RC_SEA" -ne 0 ]; } && [ "$CLPRESENT" -eq 0 ]; then
    if [ "$RC_SEA" -ne 0 ]; then
      add resilience vios_topology "VIOS redundancy topology" NOT_APPLICABLE low \
          "SEA probe failed (rc=$RC_SEA); no CAA cluster (cluster probe rc=$RC)" \
          "The SEA probe failed and no CAA cluster is visible on this box, so there is no VIOS redundancy topology to assess — a plain AIX LPAR, or a VIOS with no SEA and no cluster, is outside this control's scope." \
          "n/a"
    else
      add resilience vios_topology "VIOS redundancy topology" NOT_APPLICABLE low \
          "no SEA, no CAA cluster (sea probe rc=$RC_SEA, cluster probe rc=$RC)" \
          "No Shared Ethernet Adapter and no CAA cluster are visible on this box, so there is no VIOS redundancy topology to assess — a plain AIX LPAR, or a VIOS with no SEA and no cluster, is outside this control's scope." \
          "n/a"
    fi
  fi
}

function standalone_run {
  standalone_check
}

standalone_main "$@"
exit $?
