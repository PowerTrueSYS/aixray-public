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

AIXRAY_TOOL=ck-lppchk-consistency


function standalone_check {
_AIXRAY_SESSION_KEYS=""
function aixv_confirmed {
  typeset key rc
  key=$1; shift
  if [ -n "${AIXRAY_FIXTURES:-}" ]; then
    if [ -r "$AIXRAY_FIXTURES/$key.out" ] || [ -r "$AIXRAY_FIXTURES/$key.err" ]; then
      [ -r "$AIXRAY_FIXTURES/$key.out" ] && cat "$AIXRAY_FIXTURES/$key.out"
      [ -r "$AIXRAY_FIXTURES/$key.err" ] && cat "$AIXRAY_FIXTURES/$key.err"
      if [ -r "$AIXRAY_FIXTURES/$key.rc" ]; then
        read rc < "$AIXRAY_FIXTURES/$key.rc"
      else
        rc=126
      fi
      return $rc
    fi
    return 127
  fi
  # Capture mode — same gap as aixv(), but the .rc rule is DIFFERENT and the
  # difference is the whole point of this wrapper. aix()/aixv() omit .rc on
  # success as a space optimisation, and their replay defaults a missing .rc to
  # rc=0. This function deliberately treats a missing .rc as 126 ("no completion
  # signal was ever recorded"), so borrowing that optimisation would make every
  # successful capture replay as an unconfirmed one. Always write .rc here.
  if [ -n "${AIXRAY_CAPTURE_DIR:-}" ]; then
    "$@" > "$AIXRAY_CAPTURE_DIR/$key.out" 2> "$AIXRAY_CAPTURE_DIR/$key.err"
    rc=$?
    echo "$rc" > "$AIXRAY_CAPTURE_DIR/$key.rc"
    cat "$AIXRAY_CAPTURE_DIR/$key.out"
    cat "$AIXRAY_CAPTURE_DIR/$key.err"
    return $rc
  fi
  "$@" 2>&1
}
  LSLPPQ=$(aixv_confirmed lslpp_qcL lslpp -qcL); LSLPPQ_RC=$?   # colon form drives the fileset-state parse; the
    TOTALFS=$(printf '%s\n' "$LSLPPQ" | awk -F: 'NF>=6 && $1!="" && $2!="" && $3 ~ /^[0-9]/ && $6 ~ /^[ABCO]$/ {n++} END{print n+0}')
  # lppchk_consistency — a DIFFERENT, complementary signal from fileset_state above:
  # fileset_state reads lslpp's own recorded STATE column (catches a fileset already marked
  # BROKEN); lppchk -v independently verifies REQUISITE/dependency consistency across the whole
  # installed set (catches a fileset whose prerequisites are missing/mismatched even though its
  # own STATE looks fine) — docs/aixray-spec-v2.md Sec 5 cap-filesets row, IBM-sourced
  # (upgrade-readiness-checks.md Sec 4). Escalates to 'lppchk -m3 -v' (Sec 5's own escalation
  # rule) for full detail on any inconsistency — never asserts a specific IBM error-message
  # shape (real failure text was not observable on the read-only, currently-clean lab boxes);
  # bounded raw output IS the finding, not a re-parsed summary. Live-verified clean (rc=0, no
  # output — the documented "no output" success shape) on a lab LPAR (AIX 7.2) and a lab LPAR (AIX 7.1),
  # 2026-07-13. Uses 'aixv' (not the shared 'aix()') so a real stderr diagnostic is actually
  # captured instead of silently discarded (adversarial review, M5, HIGH finding #2: this
  # call spelled '2>&1' but 'aix()' had already redirected the real command's stderr to
  # /dev/null internally before that '2>&1' ever ran, so an rc=0 stderr-only diagnostic was
  # laundered into a false clean PASS -- see 'aixv's own header comment).
  LPPCHKOUT=$(aixv_confirmed lppchk_v lppchk -v); LPPCHK_RC=$?
  # rc 127 means "command/fixture absent" (this codebase's established convention, e.g. the
  # 'ifixes' check above) -- a MISSING result must degrade to WARN "not assessed," never a
  # confident FAIL. Caught live during this check's own test-suite run (round 1 self-review):
  # every fixture set that has no 'lppchk_v.out' fixture file initially reported a false FAIL
  # "inconsistent (rc=127)" instead of the honest "could not run" -- exactly the NOT_ASSESSED-
  # laundered-into-a-verdict defect class this repo's own discipline exists to catch before
  # shipping, not after. Uses 'aixv_confirmed' (not the plain 'aixv') so an rc=0 that was only
  # EVER assumed (no <key>.rc file recorded at all) can never be treated identically to a
  # GENUINELY confirmed rc=0 -- see 'aixv_confirmed's own header comment (adversarial confirming
  # review, 2026-07-14, HIGH: 'rc=0 + empty output' is genuinely ambiguous between a real
  # clean result and a wholesale capture-session failure, and no purely-textual corroboration
  # -- however many independent-looking signals -- can rule out a failure mode that empties
  # ALL of them identically; only a genuine, distinctly-recorded completion signal closes
  # this, on the CAPTURE THIS CHECK ITSELF DEPENDS ON, not merely a related one).
  if [ "$LPPCHK_RC" -eq 127 ]; then
    add patch lppchk_consistency "Fileset dependency consistency (lppchk -v)" WARN low "unreadable" \
        "Could not run 'lppchk -v' on this box." "check 'lppchk -v' manually."
  elif [ "$LPPCHK_RC" -eq 0 ] && [ -z "$LPPCHKOUT" ]; then
    # rc=0 here is a GENUINELY CONFIRMED reading (aixv_confirmed's 126 sentinel, meaning "no
    # completion signal was ever recorded," would already have failed this exact equality
    # test) -- "rc=0, no output" is lppchk -v's own documented clean-success shape, and this
    # is now a real completion signal for THIS capture, not an assumption. A second,
    # independent invocation ('lppchk -m3 -v', the documented escalation), ALSO required to
    # be genuinely confirmed rc=0 with empty output (not merely assumed), plus the box's own
    # fileset inventory clearing a small floor, corroborate further -- raising the bar over
    # trusting a single confirmed reading alone, though not a mathematical completeness proof
    # (disclosed honestly, same as this codebase's own FLRT apar_scan floor gate discloses
    # its own floor is "not a completeness proof").
    LPPCHKM3=$(aixv_confirmed lppchk_m3v lppchk -m3 -v); LPPCHKM3_RC=$?
    if [ "$LPPCHKM3_RC" -eq 0 ] && [ -z "$LPPCHKM3" ] && [ "${LSLPPQ_RC:-1}" -eq 0 ] && [ "${TOTALFS:-0}" -ge 5 ]; then
      add patch lppchk_consistency "Fileset dependency consistency (lppchk -v)" PASS low "consistent" \
          "'lppchk -v' AND the independent 'lppchk -m3 -v' escalation both returned a genuinely confirmed clean result (rc=0, stdout and stderr both empty), and the fileset inventory itself ($TOTALFS filesets) is a real, populated AIX system, not an empty/truncated capture." "n/a"
    else
      add patch lppchk_consistency "Fileset dependency consistency (lppchk -v)" WARN low "not assessed — capture empty or unconfirmed" \
          "'lppchk -v' reported no output, which is its documented clean-success shape -- but this cannot be credited as a clean scan without independent corroboration: the 'lppchk -m3 -v' cross-check returned rc=$LPPCHKM3_RC${LPPCHKM3:+ with output}, and/or the fileset inventory ('lslpp -qcL', confirmed rc=${LSLPPQ_RC:-unknown}, ${TOTALFS:-0} structurally valid row(s)) is empty, failed, token-shaped, unconfirmed, or implausibly small. Neither signal alone proves 'lppchk -v' itself actually completed; disagreement or an unconfirmed/implausible inventory means this cannot be assumed a genuine clean result." \
          "run 'lppchk -v 2>&1' and 'lppchk -m3 -v 2>&1' manually as root, and confirm 'lslpp -qcL' returns the full fileset inventory, before treating this as a clean scan."
    fi
  else
    # Never a confident FAIL here: real lppchk -v inconsistency output has never been
    # observed on the currently-clean lab boxes, so nonzero rc WITH output (or rc=0 with
    # unexpected output, now that 'aixv' actually captures stderr) cannot be reliably told
    # apart from a permission/ODM/usage error by shape alone (adversarial review, M5). A
    # genuine inconsistency and a plain execution failure both route to the SAME WARN
    # (medium, since it may well be real) rather than gambling a confident FAIL on an
    # unverified pattern-match, or a confident PASS on any output at all — per the sourced
    # rule (upgrade-readiness-checks.md Sec 4), ANY 'lppchk -v' output, stdout or stderr,
    # is adverse; PASS above requires rc=0 AND genuinely empty output, nothing looser.
    # Escalates to 'lppchk -m3 -v' when there IS output, for a human to actually look at.
    if [ -n "$LPPCHKOUT" ]; then
      # Escalation rc is tracked (not just its output) so a FAILED '-m3 -v' escalation
      # never silently substitutes for the primary '-v' evidence -- fall back to the
      # primary output when the escalation itself didn't succeed (adversarial review,
      # M5, round 3, low-severity finding: evidence provenance must stay honest even
      # though the status here is already safely WARN either way). Also uses 'aixv' so the
      # escalation's own stderr diagnostic (if any) is captured in the detail text too.
      LPPCHKDETAIL=$(aixv lppchk_m3v lppchk -m3 -v); LPPCHKDETAIL_RC=$?
      [ "$LPPCHKDETAIL_RC" -eq 0 ] || LPPCHKDETAIL=""
      LPPCHKBOUNDED=$(printf '%s\n' "${LPPCHKDETAIL:-$LPPCHKOUT}" | awk 'NR<=5{print} END{if(NR>5)printf "… (%d more line(s))\n",NR-5}' | tr '\n' ' ')
      # rc=$LPPCHK_RC here may be either 0 (unexpected output on an otherwise-successful
      # run) or nonzero -- never assert "exited nonzero" unconditionally in the wording
      # (adversarial review, M5, round 3, low-severity finding).
      add patch lppchk_consistency "Fileset dependency consistency (lppchk -v)" WARN med "rc=$LPPCHK_RC, output: $LPPCHKBOUNDED" \
          "'lppchk -v' produced output (stdout and/or stderr, both captured) that doesn't match its documented clean-success shape (rc=0, no output) — rc=$LPPCHK_RC here. This MAY be a real fileset requisite/dependency inconsistency (which can block 'update_all'/'install_all_updates' the same way a BROKEN STATE does), or it may be a permission/ODM/usage error, or unexpected output on an otherwise-successful run; this tool has never observed a confirmed real-inconsistency sample and cannot reliably tell these apart from output shape alone, so this is never asserted as a confident FAIL." \
          "run 'lppchk -v 2>&1' and 'lppchk -m3 -v 2>&1' manually as root to see the actual result before treating this as a real inconsistency."
    else
      add patch lppchk_consistency "Fileset dependency consistency (lppchk -v)" WARN med "ambiguous (rc=$LPPCHK_RC, no captured output)" \
          "'lppchk -v' exited nonzero with no output captured on either stdout or stderr — this looks like a bare execution problem (permissions, ODM access) rather than a real diagnostic, but cannot be asserted as a confident FAIL from this alone." \
          "run 'lppchk -v 2>&1' manually as root to see the actual result."
    fi
  fi
}

function standalone_run {
  standalone_check
}

standalone_main "$@"
exit $?
