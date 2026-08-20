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

AIXRAY_TOOL=ck-multibos-residue

# Shared rootvg logical-volume capture used by the multibos residue check.
function capture_cap_lsvg_l_rootvg {
  ROOTVG_LVL=$(aix lsvg_l_rootvg lsvg -l rootvg); ROOTVG_LVL_RC=$?
  ROOTVG_LVL_OK=0
}


function standalone_check {
_AIXRAY_SESSION_KEYS=""

  # multibos_residue — leftover standby-BOS state from a prior multibos operation (docs/aixray-
  # spec-v2.md Sec 5 cap-filesets row; the multibos+nimadm version-dependent interaction, Sec 4,
  # is Blueprint sequencing's concern — this check only detects PRESENCE, informational, never a
  # verdict on whether it's safe to proceed with a specific migration method). Sourced two ways,
  # both IBM-documented: 'bos_'-prefixed LV names in the SAME rootvg LV list already captured
  # above (ROOTVG_LVL), and a mounted '/bos_inst' filesystem. Live-verified clean (neither present
  # — a real, not hypothetical, stock-image negative) on both lab LPARs (AIX 7.2 and 7.1), 2026-07-13.
  # Presence is only trusted from a source that itself SUCCEEDED -- gating BOSLV/BOSMNT
  # on their own rc BEFORE using them as signal (rather than gating the overall verdict
  # afterward) closes a failed-source-to-verdict path the adversarial confirming review caught:
  # a failed 'lsvg -l rootvg' or 'mount' capture that nonetheless leaves plausible partial
  # text behind must never be able to manufacture a confident "present" finding (adversarial
  # primary review, M5, round 3, new-bug finding on multibos_residue).
  BOSLV=""
  [ "$ROOTVG_LVL_RC" -eq 0 ] && BOSLV=$(printf '%s\n' "$ROOTVG_LVL" | awk '$1 ~ /^bos_/{printf "%s%s",(n++?",":""),$1}')
  MNT_MULTIBOS=$(aix mount mount); MOUNT_RC=$?
  # Exact whitespace-delimited field match, not a substring search across the whole line
  # (adversarial review, M5, round 2, finding #8): an unanchored '/bos_inst' pattern
  # also matches '/bos_inst.old', '/bos_inst_backup', or the string appearing in some
  # other column (e.g. the options field) -- none of which is the real "mounted over"
  # path this check is actually looking for. Search starts at field 2, never field 1:
  # in 'mount' output the FIRST field is always either the remote node or the local
  # mounted-FROM device/path, never the mounted-over path -- so field 1 can never be a
  # legitimate "mounted over /bos_inst" match regardless of node-column shift between
  # local and NFS-mounted rows (adversarial review, M5, round 3, finding #8 residual).
  BOSMNT=""
  [ "$MOUNT_RC" -eq 0 ] && BOSMNT=$(printf '%s\n' "$MNT_MULTIBOS" | awk '{for (i=2;i<=NF;i++) if ($i=="/bos_inst") {print; exit}}')
  # Structural validation, not just rc+nonemptiness -- a nonempty rc=0 capture that doesn't
  # even resemble real 'lsvg -l'/'mount' output (garbled, truncated, or the wrong command
  # entirely) must never be trusted into a confident "none" PASS just because it happened to
  # contain no bos_/bos_inst token (adversarial review, M5, HIGH finding #3: reproduced
  # in-memory with garbled rootvg+mount captures -- output was 'multibos_residue PASS none').
  # Recognizable shape checked here is deliberately minimal, not a full re-parse: 'lsvg -l's
  # own 'rootvg:' vg-name header line plus its 'LV NAME'/'TYPE' column header; 'mount's own
  # 'mounted over' column header -- both are stable, documented output shapes on a real box.
  # Header-shape alone is not enough: a capture truncated right after its header line(s)
  # (present, rc=0, non-empty, and header-shape-valid) still passes the shape check above
  # while carrying ZERO of the actual LV/mount data rows that would show real residue --
  # reproduced live (a headers-only 'lsvg -l rootvg'/'mount' capture rendered PASS "none").
  # A bare LINE-COUNT floor (an earlier version of this fix) is insufficient on its own
  # (adversarial review, 2026-07-14, HIGH: any fixed count is defeated by truncating
  # one row LATER -- e.g. after 3 ordinary LVs but before a later bos_-prefixed one).
  # Tightened to validate the SPECIFIC mandatory rows every supported real AIX capture has:
  # rootvg's hd5/hd6/hd8/hd4/hd2/hd9var rows, including their real type, positive LP/PP/PV
  # columns, state token and mount point; plus mount's /dev/hd4->/, /dev/hd2->/usr and
  # /dev/hd9var->/var rows, including jfs2 and real date/time columns. This raises the bar
  # from bare-token presence to actual per-row command grammar.
  # Disclosed, not silently accepted as a full fix (same honesty standard as this
  # codebase's own FLRT apar_scan floor, which documents itself as "a bound-and-disclose
  # floor against failed/truncated captures, not a completeness proof"): a capture
  # truncated AFTER all the mandatory rows above but BEFORE a real bos_/bos_inst residue
  # row remains accepted-open. Likewise, this is structural plausibility, not source
  # authentication: a deliberately fabricated payload that reproduces every full valid-
  # shaped mandatory row (not merely bare tokens or coincidental words) can still satisfy
  # it. Both residuals require a true completion/authenticity signal (checksum, independent
  # expected row count, or terminating sentinel) that this capture model does not provide.
  ROOTVG_ROWS_OK=0
  if [ "$ROOTVG_LVL_RC" -eq 0 ]; then
    printf '%s\n' "$ROOTVG_LVL" | awk '
        function pos(v){return v ~ /^[1-9][0-9]*$/}
        function state(v){return v=="open/syncd"||v=="open/stale"||v=="closed/syncd"||v=="closed/stale"}
        $1=="hd5"{n5++; if(NF==7&&$2=="boot"&&pos($3)&&pos($4)&&pos($5)&&state($6)&&$7=="N/A")h5++; else bad=1}
        $1=="hd6"{n6++; if(NF==7&&$2=="paging"&&pos($3)&&pos($4)&&pos($5)&&state($6)&&$7=="N/A")h6++; else bad=1}
        $1=="hd8"{n8++; if(NF==7&&$2=="jfs2log"&&pos($3)&&pos($4)&&pos($5)&&state($6)&&$7=="N/A")h8++; else bad=1}
        $1=="hd4"{n4++; if(NF==7&&$2=="jfs2"&&pos($3)&&pos($4)&&pos($5)&&state($6)&&$7=="/")h4++; else bad=1}
        $1=="hd2"{n2++; if(NF==7&&$2=="jfs2"&&pos($3)&&pos($4)&&pos($5)&&state($6)&&$7=="/usr")h2++; else bad=1}
        $1=="hd9var"{n9++; if(NF==7&&$2=="jfs2"&&pos($3)&&pos($4)&&pos($5)&&state($6)&&$7=="/var")h9++; else bad=1}
        END{exit !(h5==1&&h6==1&&h8==1&&h4==1&&h2==1&&h9==1&&n5==1&&n6==1&&n8==1&&n4==1&&n2==1&&n9==1&&!bad)}' && ROOTVG_ROWS_OK=1
  fi
  MOUNT_ROWS_OK=0
  if [ "$MOUNT_RC" -eq 0 ]; then
    printf '%s\n' "$MNT_MULTIBOS" | awk '
        function month(v){return v=="Jan"||v=="Feb"||v=="Mar"||v=="Apr"||v=="May"||v=="Jun"||v=="Jul"||v=="Aug"||v=="Sep"||v=="Oct"||v=="Nov"||v=="Dec"}
        function dated(mon,day,tim){if(!month(mon)||day !~ /^[0-9][0-9]*$/||day+0<1||day+0>31)return 0; split(tim,hm,":"); return tim ~ /^[0-9][0-9]:[0-9][0-9]$/&&hm[1]+0<24&&hm[2]+0<60}
        $1=="/dev/hd4"{n4++; if(NF>=7&&$2=="/"&&$3=="jfs2"&&dated($4,$5,$6))h4++; else bad=1}
        $1=="/dev/hd2"{n2++; if(NF>=7&&$2=="/usr"&&$3=="jfs2"&&dated($4,$5,$6))h2++; else bad=1}
        $1=="/dev/hd9var"{n9++; if(NF>=7&&$2=="/var"&&$3=="jfs2"&&dated($4,$5,$6))h9++; else bad=1}
        END{exit !(h4==1&&h2==1&&h9==1&&n4==1&&n2==1&&n9==1&&!bad)}' && MOUNT_ROWS_OK=1
  fi
  ROOTVG_LVL_OK=0
  if [ "$ROOTVG_LVL_RC" -eq 0 ]; then
    printf '%s\n' "$ROOTVG_LVL" | awk '
        NR==1 && $0 ~ /^rootvg:/ {h1=1}
        $0 ~ /LV NAME/ && $0 ~ /TYPE/ {h2=1}
        END{exit !(h1&&h2)}' && ROOTVG_LVL_OK=1
  fi
  MOUNT_OK=0
  if [ "$MOUNT_RC" -eq 0 ]; then
    printf '%s\n' "$MNT_MULTIBOS" | awk '$0 ~ /mounted over/{h=1} END{exit !h}' && MOUNT_OK=1
  fi
  if [ -n "$BOSLV" ] || [ -n "$BOSMNT" ]; then
    add storage multibos_residue "multibos/alt_disk standby-BOS residue" WARN med "present: ${BOSLV:-none} ${BOSMNT:+ /bos_inst mounted}" \
        "A standby Base Operating System from a prior 'multibos' operation is still present. Through AIX 7.1 NIM masters this ALWAYS blocks nimadm (full removal required first); from 7.2 NIM masters it's supported per-scenario but changes the required sequencing (mount/unmount the standby first, depending on boot state) — never assume it's safe to ignore." \
        "confirm this is intentional; if not, remove it ('multibos -R', then manual /bos_inst cleanup if it survives) before running nimadm — check the NIM master's own oslevel first to know which rule applies."
  elif [ "$ROOTVG_LVL_RC" -ne 0 ] || [ "$MOUNT_RC" -ne 0 ] || [ -z "$ROOTVG_LVL" ] || [ -z "$MNT_MULTIBOS" ]; then
    # EITHER source failing/empty is enough to WARN, not just both together -- these are
    # two DIFFERENT, complementary residue signals (a bos_-prefixed LV vs a mounted
    # /bos_inst), and a real box always returns nonempty output for both a successful
    # 'lsvg -l rootvg' (rootvg always has LVs) and 'mount' (always at least '/'). PASSing
    # when only ONE source actually returned clean data was the exact NOT_ASSESSED-
    # laundered-into-a-verdict class this repo's own discipline forbids -- caught only
    # because the adversarial review on this milestone checked the individual-source
    # failure case explicitly, not just the both-empty case self-review had already
    # covered.
    add storage multibos_residue "multibos/alt_disk standby-BOS residue" WARN low "unreadable" \
        "Could not read 'lsvg -l rootvg' (rc=$ROOTVG_LVL_RC) and/or 'mount' (rc=$MOUNT_RC) to check for multibos/alt_disk residue -- both sources must be readable to assert none is present." \
        "check 'lsvg -l rootvg' (bos_-prefixed LVs) and 'mount' (/bos_inst) manually."
  elif [ "$ROOTVG_LVL_OK" -ne 1 ] || [ "$MOUNT_OK" -ne 1 ] || [ "$ROOTVG_ROWS_OK" -ne 1 ] || [ "$MOUNT_ROWS_OK" -ne 1 ]; then
    add storage multibos_residue "multibos/alt_disk standby-BOS residue" WARN low "not assessed" \
        "'lsvg -l rootvg' and/or 'mount' returned rc=0 with nonempty output, but that output either does not match the command's stable header shape or does not contain one complete, valid-shaped copy of every mandatory base row (rootvg hd5/hd6/hd8/hd4/hd2/hd9var rows valid: $ROOTVG_ROWS_OK; mount /dev/hd4->/, /dev/hd2->/usr, /dev/hd9var->/var rows with vfs/date columns valid: $MOUNT_ROWS_OK) -- a garbled, truncated, bare-token/token-coincidence, or wrong-command capture must never be trusted into asserting NO residue is present." \
        "run 'lsvg -l rootvg' and 'mount' manually and check for bos_-prefixed LVs or a mounted /bos_inst filesystem."
  else
    add storage multibos_residue "multibos/alt_disk standby-BOS residue" PASS low "none" \
        "No leftover multibos standby-BOS state (bos_-prefixed LVs or a mounted /bos_inst)." "n/a"
  fi
}

function standalone_run {
  capture_cap_lsvg_l_rootvg || return 1
  standalone_check
}

standalone_main "$@"
exit $?
