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

AIXRAY_TOOL=ck-stig-secattr


function standalone_check {
_AIXRAY_SESSION_KEYS=""
R_SECATTR="
V-215171|/etc/security/user|default|loginretries|le|3
V-215172|/etc/security/user|default|maxulogs|le|10
V-215217|/etc/security/user|default|minupperalpha|ge|1
V-215218|/etc/security/user|default|minloweralpha|ge|1
V-215219|/etc/security/user|default|mindigit|ge|1
V-215220|/etc/security/user|default|mindiff|ge|8
V-215222|/etc/security/user|default|minage|ge|1
V-215223|/etc/security/user|default|maxage|le|8
V-215226|/etc/security/user|default|minlen|ge|15
V-215227|/etc/security/user|default|minspecialchar|ge|1
V-215232|/etc/security/user|default|maxrepeats|le|3
V-215337|/etc/security/login.cfg|default|logindelay|ge|4
"

# R_NETTUNE — static network-tunable rules (Family 3, WP-H3).
#   V-ID|command|tunable|op|value   (command = no; op eq/le/ge, numeric)
#   Each row is one DISA STIG for IBM AIX 7.x control that mandates a kernel network option
#   read via 'no -a'. op eq = must equal; ge/le = numeric floor/ceiling. Unlike R_SECATTR,
#   op le does NOT special-case 0: for a network tunable 0 is normally the SECURE (disabled)
#   value, so it is compared literally. A tunable absent from the capture is NA; 'no -a' is a
#   NON-root read (listing a tunable never needs privilege — only setting one does — so there
#   is no root gate). SCOPE (honest count): the AIX 7.x STIG defines exactly FOUR 'no' rules
#   and ZERO 'nfso' rules. Verified rule-by-rule against ALL 283 V3R3 STIG rules' Check/Fix
#   text via the cyber.trackr.live structured API (verbatim DISA XCCDF content).
#   Source-routing / redirect / directed-broadcast / path-MTU / TCP-secure /
#   rfc1323 tunables (ipsrcroute*, ipsendredirects, directed_broadcast, tcp/udp_pmtu_discover,
#   tcp_tcpsecure) have NO STIG rule — a term scan of every rule found zero hits; none is
#   invented here. V-215429 ("must not process ICMP timestamp requests") is a genfilt/IPsec
#   IP-filter rule (lsfilt deny of ICMP type 13/14), NOT a 'no' tunable, so it is deferred.
#   See docs/COVERAGE.md for the full transcribed/deferred accounting.

# eval_secattr — evaluate every R_SECATTR row and emit one grouped finding (stig_secattr)
# plus per-rule detail (F_RULES). Attributes are grouped by (file,stanza): ONE lssec call
# captures a whole stanza's attribute list (fewest commands, and lssec aborts the entire
# call if any one attribute is invalid for the stanza — so only real attributes are grouped).
# A stanza that cannot be read (non-root: rc!=0/empty) makes its rules NA; a missing/empty
# attribute value is NA. Numeric compare only; op le treats an observed 0 as a FAIL (0 =
# disabled/unlimited on AIX). If nothing was readable at all (NAPPLIC=0) the finding is a
# root-gated WARN rather than a hollow PASS.
function eval_secattr {
  typeset PAIRS CAP RAW DETAIL SUM CTLS NPASS NFAIL NNA NAPPLIC FLIST ST SEV OBS MEAN FIX

  # distinct file|stanza pairs in first-seen (deterministic) order
  PAIRS=$(printf '%s\n' "$R_SECATTR" | awk -F'|' 'NF>=6 && $1 !~ /^#/ && $2!="" && !seen[$2 FS $3]++{print $2"|"$3}')
  [ -z "$PAIRS" ] && return 0

  # one lssec per stanza; parse "stanza attr=val attr=val" into "file|stanza|attr|value"
  # lines. An unreadable stanza (rc!=0 or empty) emits nothing -> its rules fall to NA.
  # KEEP the per-stanza attribute lists in tools/capture-fixtures.sh in sync with R_SECATTR.
  CAP=$(printf '%s\n' "$PAIRS" | while IFS='|' read SA_F SA_S; do
    [ -z "$SA_F" ] && continue
    SA_ATTRS=$(printf '%s\n' "$R_SECATTR" | awk -F'|' -v f="$SA_F" -v s="$SA_S" '$2==f && $3==s{printf " -a %s", $4}')
    SA_SLUG=$(printf '%s' "$SA_F" | sed 's|.*/||; s|\.cfg$||')_$SA_S
    SA_RAW=$(aix "stig_secattr_$SA_SLUG" lssec -f "$SA_F" -s "$SA_S" $SA_ATTRS)
    if [ $? -eq 0 ] && [ -n "$SA_RAW" ]; then
      printf '%s\n' "$SA_RAW" | awk -v f="$SA_F" -v s="$SA_S" \
        '{for(i=1;i<=NF;i++){e=index($i,"="); if(e>1) print f "|" s "|" substr($i,1,e-1) "|" substr($i,e+1)}}'
    fi
  done)

  # one awk pass: rules then captured values -> per-rule verdict + summary
  RAW=$({ printf '%s\n' "$R_SECATTR"; echo "AIXRAY_CAP"; printf '%s\n' "$CAP"; } | awk -F'|' '
    function isnum(x){ return (x ~ /^-?[0-9]+$/) }
    BEGIN{ phase=0; nr=0 }
    $0=="AIXRAY_CAP"{ phase=1; next }
    phase==0{
      if($0 ~ /^#/ || $0=="" || NF<6) next
      nr++; R_id[nr]=$1; R_file[nr]=$2; R_st[nr]=$3; R_attr[nr]=$4; R_op[nr]=$5; R_val[nr]=$6
      next
    }
    phase==1{
      if(NF<4) next
      key=$1 SUBSEP $2 SUBSEP $3; M[key]=$4; P[key]=1
      next
    }
    END{
      npass=0; nfail=0; nna=0; nf=0
      for(i=1;i<=nr;i++){
        key=R_file[i] SUBSEP R_st[i] SUBSEP R_attr[i]
        if(!(key in P) || M[key]==""){ st="NA"; obs=R_attr[i]" unset"; nna++ }
        else if(!isnum(M[key])){ st="NA"; obs=R_attr[i]"="M[key]" non-numeric"; nna++ }
        else{
          v=M[key]+0; req=R_val[i]+0; op=R_op[i]; ok=0
          if(op=="ge") ok=(v>=req)
          else if(op=="le") ok=(v!=0 && v<=req)
          else if(op=="eq") ok=(v==req)
          obs=R_attr[i]"="M[key]" (need "op" "req")"
          if(ok){ st="PASS"; npass++ } else { st="FAIL"; nfail++; nf++; fl[nf]=R_id[i]" "R_attr[i]"="M[key]" (needs "op" "req")" }
        }
        print "stig:" R_id[i] "|" st "|" obs
      }
      flist=""; for(i=1;i<=nf && i<=5;i++) flist=flist (i>1?", ":"") fl[i]
      if(nf>5) flist=flist ", +" (nf-5) " more"
      printf "SUMMARY\t%d\t%d\t%d\t%s\n", npass, nfail, nna, flist
    }
  ')

  DETAIL=$(printf '%s\n' "$RAW" | grep -v '^SUMMARY')
  SUM=$(printf '%s\n' "$RAW" | awk -F'\t' '$1=="SUMMARY"{print; exit}')
  NPASS=$(printf '%s' "$SUM" | awk -F'\t' '{print $2+0}')
  NFAIL=$(printf '%s' "$SUM" | awk -F'\t' '{print $3+0}')
  NNA=$(printf '%s' "$SUM" | awk -F'\t' '{print $4+0}')
  FLIST=$(printf '%s' "$SUM" | awk -F'\t' '{print $5}')
  NAPPLIC=$(( NPASS + NFAIL ))
  CTLS=$(printf '%s\n' "$DETAIL" | awk -F'|' 'NF>=3 && $1!=""{printf "%s%s",(n++?" ":""),$1}')

  if [ "$NAPPLIC" -eq 0 ]; then
    ST=WARN; SEV=med
    OBS="n/a"
    MEAN="Could not read the /etc/security account-policy stanzas (needs root); no STIG account/attribute rule could be assessed on this run."
    FIX="re-run ptxray as root to evaluate the account-policy controls; or inspect 'lssec -f /etc/security/user -s default' manually."
  elif [ "$NFAIL" -gt 0 ]; then
    ST=FAIL; SEV=high
    OBS="$NPASS of $NAPPLIC rules compliant, $NNA n/a; failing: $FLIST"
    MEAN="One or more account/password-policy attributes in /etc/security are weaker than the DISA STIG for IBM AIX 7.x mandates — each is a documented hardening gap an auditor will flag, and it applies to every account inheriting the default stanza."
    FIX="tighten the failing attributes with chsec (chsec -f <file> -s default -a <attr>=<value>); the compliance report lists every rule, the required value, and the observed value."
  else
    ST=PASS; SEV=med
    OBS="$NPASS of $NAPPLIC rules compliant, $NNA n/a"
    MEAN="Every applicable STIG account/password-policy attribute meets the DISA STIG for IBM AIX 7.x required value."
    FIX="n/a"
  fi
  add security stig_secattr "STIG account policy" "$ST" "$SEV" "$OBS" "$MEAN" "$FIX" "$CTLS"
  F_RULES[$((NFIND-1))]="$DETAIL"
}
  # stig_secattr — data-driven STIG account/attribute policy rule engine (R_SECATTR)
  eval_secattr
}

function standalone_run {
  standalone_check
}

standalone_main "$@"
exit $?
