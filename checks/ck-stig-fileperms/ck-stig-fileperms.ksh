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

AIXRAY_TOOL=ck-stig-fileperms


function standalone_check {
_AIXRAY_SESSION_KEYS=""
R_FILEPERM="
V-215269|/etc/inetd.conf|0||
V-215272|/etc/ntp.conf|0||
V-215273|/etc/ntp.conf||0|
V-215281|/etc/ntp.conf|||0640
V-215274|/etc/group|0||
V-215275|/etc/group||7|
V-215282|/etc/group|||0644
V-245558|/etc/hosts||0|
V-245559|/etc/hosts|||0640
V-245562|/etc/syslog.conf||0|
V-245563|/etc/syslog.conf|||0640
V-245564|/etc/inetd.conf||0|
V-245565|/etc/inetd.conf|||0640
"

# R_SECATTR — static account/attribute policy rules (Family 2, WP-H2).
#   V-ID|file|stanza|attribute|op|value
#   Each row is one DISA STIG for IBM AIX 7.x control that mandates a single attribute of
#   an /etc/security stanza read via lssec. op is the required numeric relation:
#     ge = observed must be >= value ; le = observed must be <= value ; eq = must equal.
#   op le with an observed value of 0 is a FAIL: on AIX 0 means "disabled / unlimited"
#   (maxage 0 = never expires, loginretries 0 = no account lockout, maxrepeats 0 = no
#   limit, maxulogs 0 = unlimited concurrent logins) — every STIG Check text treats that 0
#   as a finding, so 0 is never <= the ceiling. A stanza that cannot be read (non-root, or
#   absent) makes its rules NA; a missing/empty attribute value is NA — never FAIL.
#   Reconciled against the cyber.trackr.live V3R3 structured API. V-215224 was withdrawn
#   by DISA at V3R1, so histsize is deliberately absent here; the independent pw_policy
#   CIS/hardening assessment remains. See docs/COVERAGE.md for provenance and accounting.

# eval_fileperms — evaluate every R_FILEPERM row against ONE evidence capture and emit
# one grouped finding plus the per-rule detail (F_RULES). A single wrapped command
# (aix stig_fileperm_ls ls -ldn <all paths>) preserves the per-path association: a
# missing path simply produces no line (NA), and ls's nonzero rc for missing paths is
# expected. Owner/group are compared by numeric id (ls -n); mode by mask, not equality.
function eval_fileperms {
  typeset PATHS LS RAW SUM DETAIL CTLS NPASS NFAIL NNA NAPPLIC FLIST ST SEV OBS MEAN FIX

  PATHS=$(printf '%s\n' "$R_FILEPERM" | awk -F'|' 'NF>=5 && $1 !~ /^#/ && $2!="" && !seen[$2]++{printf "%s ", $2}')
  [ -z "$PATHS" ] && return 0
  # ls -ldn on every distinct rule path in one shot. rc is ignored: missing paths are
  # expected and simply yield no line (parsed as NA below).
  LS=$(aix stig_fileperm_ls ls -ldn $PATHS)

  # One awk pass: build path -> (mode,uid,gid) from the ls lines, then evaluate each rule.
  RAW=$({ printf '%s\n' "$R_FILEPERM"; echo "AIXRAY_LS"; printf '%s\n' "$LS"; } | awk '
    # rwx string (10 chars, incl. suid/sgid/sticky) -> mode as decimal-octal digits (e.g. 0644->644)
    function permoct(s,  o,g,ot,sp,c){
      sp=0;o=0;g=0;ot=0
      if(substr(s,2,1)=="r")o+=4; if(substr(s,3,1)=="w")o+=2
      c=substr(s,4,1); if(c=="x")o+=1; else if(c=="s"){o+=1;sp+=4} else if(c=="S")sp+=4
      if(substr(s,5,1)=="r")g+=4; if(substr(s,6,1)=="w")g+=2
      c=substr(s,7,1); if(c=="x")g+=1; else if(c=="s"){g+=1;sp+=2} else if(c=="S")sp+=2
      if(substr(s,8,1)=="r")ot+=4; if(substr(s,9,1)=="w")ot+=2
      c=substr(s,10,1); if(c=="x")ot+=1; else if(c=="t"){ot+=1;sp+=1} else if(c=="T")sp+=1
      return sp*1000 + o*100 + g*10 + ot
    }
    # is 3-bit octal digit a a subset of b (no bit set in a that is unset in b)
    function bitle(a,b){ return (int(a/4)%2<=int(b/4)%2) && (int(a/2)%2<=int(b/2)%2) && (a%2<=b%2) }
    # does file mode fm (decimal-octal) satisfy the maxmode ceiling mm (decimal-octal)?
    function modeok(fm,mm){
      return bitle(int(fm/1000)%10,int(mm/1000)%10) && bitle(int(fm/100)%10,int(mm/100)%10) \
          && bitle(int(fm/10)%10,int(mm/10)%10) && bitle(fm%10,mm%10)
    }
    function oct4(m){ return sprintf("%04d", m) }
    BEGIN{ phase=0; nr=0 }
    $0=="AIXRAY_LS"{ phase=1; next }
    phase==0{
      if($0 ~ /^#/ || $0=="") next
      n=split($0,r,"|"); if(n<5) next
      nr++; R_id[nr]=r[1]; R_path[nr]=r[2]; R_own[nr]=r[3]; R_grp[nr]=r[4]; R_max[nr]=r[5]
      next
    }
    phase==1{
      if(NF<9) next
      p=$NF; seen[p]=1; M_mode[p]=permoct($1); M_uid[p]=$3+0; M_gid[p]=$4+0
      next
    }
    END{
      npass=0; nfail=0; nna=0; nf=0
      for(i=1;i<=nr;i++){
        p=R_path[i]
        req=""
        if(R_own[i]!="") req="owner=" R_own[i]
        if(R_grp[i]!="") req=req (req!=""?"; ":"") "group=" R_grp[i]
        if(R_max[i]!="") req=req (req!=""?"; ":"") "no mode bits beyond " oct4(R_max[i]+0)
        if(!(p in seen)){ st="NA"; obs=p" absent"; nna++ }
        else{
          fm=M_mode[p]; ok=1
          if(R_max[i]!="" && !modeok(fm,R_max[i]+0)) ok=0
          if(R_own[i]!="" && M_uid[p]!=R_own[i]+0) ok=0
          if(R_grp[i]!="" && M_gid[p]!=R_grp[i]+0) ok=0
          obs=p" "oct4(fm)" u="M_uid[p]" g="M_gid[p]
          if(ok){ st="PASS"; npass++ } else { st="FAIL"; nfail++; nf++; fl[nf]=R_id[i]" "p" ("oct4(fm)")" }
        }
        if(req!="") obs=obs " (required: " req ")"
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
  # controls = every rule id evaluated (stig: tag grammar), space-separated
  CTLS=$(printf '%s\n' "$DETAIL" | awk -F'|' 'NF>=3 && $1!=""{printf "%s%s",(n++?" ":""),$1}')

  if [ "$NFAIL" -gt 0 ]; then
    ST=FAIL; SEV=high
    OBS="$NPASS of $NAPPLIC rules compliant, $NNA not applicable; failing: $FLIST"
    MEAN="One or more files mandated by the DISA STIG for IBM AIX 7.x are more permissive, or wrong-owned, than the rule allows — each is a documented hardening gap an auditor will flag."
    FIX="chmod/chown the failing files to the required mode/owner per the rule list (chmod <maxmode> <path>; chown <owner>:<group> <path>); the compliance report lists every rule and its evidence."
  else
    ST=PASS; SEV=med
    OBS="$NPASS of $NAPPLIC rules compliant, $NNA not applicable"
    MEAN="Every applicable STIG file-permission/ownership rule (DISA STIG for IBM AIX 7.x) passes on this box — the mandated files are no more permissive than required."
    FIX="n/a"
  fi
  add security stig_fileperms "STIG file permissions" "$ST" "$SEV" "$OBS" "$MEAN" "$FIX" "$CTLS"
  F_RULES[$((NFIND-1))]="$DETAIL"
}

  # stig_fileperms — data-driven STIG file permission/ownership rule engine (R_FILEPERM)
  eval_fileperms
}

function standalone_run {
  standalone_check
}

standalone_main "$@"
exit $?
