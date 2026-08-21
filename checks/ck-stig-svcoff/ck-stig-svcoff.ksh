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

AIXRAY_TOOL=ck-stig-svcoff


function standalone_check {
_AIXRAY_SESSION_KEYS=""
# STIG service-name DATA table (V-ID|type|service-token) below: read-only reference text this
# script checks against local /etc/inetd.conf and /etc/rc.tcpip captures; never a network call.
# Trailing comments on the data lines themselves would corrupt the table.
# network-lint: allow-next=39 -- embedded STIG service-name data table immediately below
R_SVCOFF="
V-215257|inetd|exec
V-215258|inetd|telnet
V-215259|inetd|ftp
V-215334|inetd|tftp
V-215346|inetd|shell
V-215347|inetd|login
V-215369|inetd|daytime
V-215370|inetd|cmsd
V-215371|inetd|ttdbserver
V-215372|inetd|uucp
V-215373|inetd|time
V-215374|inetd|talk
V-215375|inetd|ntalk
V-215376|inetd|chargen
V-215377|inetd|discard
V-215378|inetd|dtspc
V-215379|inetd|pcnfsd
V-215380|inetd|rstatd
V-215381|inetd|rusersd
V-215382|inetd|sprayd
V-215383|inetd|klogin
V-215384|inetd|kshell
V-215385|inetd|rquotad
V-215386|inetd|tftp
V-215387|inetd|imap2
V-215388|inetd|pop3
V-215389|inetd|finger
V-215390|inetd|instsrv
V-215391|inetd|echo
V-215406|inetd|rwalld
V-215353|rctcp|sendmail
V-215354|rctcp|snmpd
V-215365|rctcp|snmpmibd
V-215358|rctcp|gated
V-215361|rctcp|routed
V-215362|rctcp|rwhod
V-215363|rctcp|timed
"
# eval_svcoff — evaluate every R_SVCOFF row and emit one grouped finding (stig_svcoff) plus
# per-rule detail (F_RULES). Three captures: the uncommented /etc/inetd.conf service lines
# (type inetd: the service token must NOT appear enabled), the uncommented start commands in
# /etc/rc.tcpip (type rctcp: the daemon must not start at boot), and 'lssrc -a' (type lssrc:
# the SRC subsystem must be inoperative, not active). All are non-root reads. For a
# disable-service rule the STIG treats "service enabled/running" as the finding, so a token or
# start command that is absent/commented (inetd/rctcp), or a subsystem that is inoperative/
# undefined (lssrc), is compliant = PASS, not NA. Guard: if lssrc -a yields no subsystem rows
# at all, lssrc-type rules are NA (can't assess) rather than a hollow PASS. This is the broad
# per-V-ID STIG service list; it does NOT duplicate the inetd_cleartext check (which flags
# cleartext-LOGIN daemons enabled).
function eval_svcoff {
  typeset TYPES CAP INE LSS RCT RAW DETAIL SUM CTLS NPASS NFAIL NNA NAPPLIC FLIST ST SEV OBS MEAN FIX

  [ -z "$R_SVCOFF" ] && return 0
  # space-separated (not newline): the `case " $TYPES "` tests below match on
  # spaces, so with >1 type a newline-joined list would match none of them.
  TYPES=$(printf '%s\n' "$R_SVCOFF" | awk -F'|' 'NF>=3 && $1 !~ /^#/{print $2}' | sort -u | tr '\n' ' ')
  [ -z "$TYPES" ] && return 0

  # Build the evidence: enabled inetd tokens and SRC subsystem states.
  CAP=$(
    case " $TYPES " in
      (*" inetd "*)
        INE=$(aix stig_inetd_active grep -v '^#' /etc/inetd.conf)
        printf '%s\n' "$INE" | awk 'NF>=1 && $1 !~ /^#/{print "inetd|" $1 "|on"}'
        ;;
    esac
    case " $TYPES " in
      (*" lssrc "*)
        LSS=$(aix stig_lssrc_a lssrc -a)
        printf '%s\n' "$LSS" | awk 'NR>1 && NF>=2 && $1!="Subsystem"{print "lssrc|" $1 "|" $NF}'
        ;;
    esac
    case " $TYPES " in
      (*" rctcp "*)
        # uncommented "start /path/daemon ..." lines in /etc/rc.tcpip = the daemon boots.
        # A commented rule (#start ...) does not match the anchored grep.
        RCT=$(aix stig_rctcp grep -E '^[	 ]*start ' /etc/rc.tcpip)
        printf '%s\n' "$RCT" | awk '$1=="start" && $2!=""{n=split($2,a,"/"); print "rctcp|" a[n] "|on"}'
        ;;
    esac
  )

  RAW=$({ printf '%s\n' "$R_SVCOFF"; echo "AIXRAY_CAP"; printf '%s\n' "$CAP"; } | awk -F'|' '
    BEGIN{ phase=0; nr=0; nlssrc=0 }
    $0=="AIXRAY_CAP"{ phase=1; next }
    phase==0{
      if($0 ~ /^#/ || $0=="" || NF<3) next
      nr++; R_id[nr]=$1; R_type[nr]=$2; R_name[nr]=$3
      next
    }
    phase==1{
      if(NF<3) next
      if($1=="inetd"){ enabled[$2]=1 }
      else if($1=="lssrc"){ state[$2]=$3; nlssrc++ }
      else if($1=="rctcp"){ rctcp_on[$2]=1; nrctcp++ }
      next
    }
    END{
      npass=0; nfail=0; nna=0; nf=0
      for(i=1;i<=nr;i++){
        t=R_type[i]; n=R_name[i]
        if(t=="inetd"){
          if(n in enabled){ st="FAIL"; obs=n" enabled in inetd.conf"; nfail++; nf++; fl[nf]=R_id[i]" "n }
          else { st="PASS"; obs=n" not enabled in inetd.conf"; npass++ }
        }
        else if(t=="lssrc"){
          if(nlssrc==0){ st="NA"; obs=n" (lssrc unreadable)"; nna++ }
          else if(n in state){
            if(state[n]=="active"){ st="FAIL"; obs=n" active"; nfail++; nf++; fl[nf]=R_id[i]" "n }
            else { st="PASS"; obs=n" "state[n]; npass++ }
          }
          else { st="PASS"; obs=n" not defined"; npass++ }
        }
        else if(t=="rctcp"){
          if(n in rctcp_on){ st="FAIL"; obs=n" starts at boot in /etc/rc.tcpip"; nfail++; nf++; fl[nf]=R_id[i]" "n }
          else { st="PASS"; obs=n" not started in /etc/rc.tcpip"; npass++ }
        }
        else { st="NA"; obs=n" unknown type"; nna++ }
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
    MEAN="Could not read the service inventory (/etc/inetd.conf, /etc/rc.tcpip, and lssrc -a); no STIG disabled-service rule could be assessed on this run."
    FIX="verify /etc/inetd.conf and /etc/rc.tcpip are readable and the SRC is running; or inspect 'lssrc -a' manually."
  elif [ "$NFAIL" -gt 0 ]; then
    ST=FAIL; SEV=high
    OBS="$NPASS of $NAPPLIC rules compliant, $NNA n/a; failing: $FLIST"
    MEAN="One or more legacy network services the DISA STIG for IBM AIX 7.x requires disabled are still enabled or running — each is an unneeded, often unauthenticated, network-facing daemon an auditor will flag."
    FIX="comment the service out of /etc/inetd.conf and 'refresh -s inetd' (inetd services), use 'chrctcp -d <daemon>' (/etc/rc.tcpip daemons), or 'stopsrc -s <subsystem>' and disable it at boot (SRC subsystems); the compliance report lists every rule and its evidence."
  else
    ST=PASS; SEV=med
    OBS="$NPASS of $NAPPLIC rules compliant, $NNA n/a"
    MEAN="Every legacy network service the DISA STIG for IBM AIX 7.x requires disabled is off on this box."
    FIX="n/a"
  fi
  add security stig_svcoff "STIG disabled services" "$ST" "$SEV" "$OBS" "$MEAN" "$FIX" "$CTLS"
  F_RULES[$((NFIND-1))]="$DETAIL"
}
  # stig_svcoff — data-driven STIG disabled-service rule engine (R_SVCOFF)
  eval_svcoff
}

function standalone_run {
  standalone_check
}

standalone_main "$@"
exit $?
