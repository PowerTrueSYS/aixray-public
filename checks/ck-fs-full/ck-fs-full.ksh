#!/bin/ksh
# Generated standalone AIXray check support. READ-ONLY: captures only; no
# remediation, service control, network access, or durable target-host writes.
set -u

# Match the monolith's guarded AIX command search path and parsing locale.
PATH=/usr/bin:/etc:/usr/sbin:/usr/ucb:/usr/bin/X11:/sbin:/usr/ios/cli:${PATH:-}
export PATH
LC_ALL=C
export LC_ALL

AIXRAY_STANDALONE_VERSION="0.1.0"

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
    PASS|WARN|FAIL|NOT_ASSESSED) ;;
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

AIXRAY_TOOL=ck-fs-full

function checks_storage {
  typeset DFRAW DFG DFRC DFROWS DFPARSE_OK DFNOTE M U OTH LSPS LSPSRC LSPS_OK LSPSWHY NPS MAXU MAXU_FACT VGL VGLRC VGL_OK VGLWHY VG LVOUT LVRC PVOUT PVRC S MP STALE MISSPV VG_STALE_GAP VG_PVS_GAP ROOTVG_LVL_OK VG_PVLIST VG_PVLIST_RC VG_PVLIST_OK VG_PVLIST_WHY LSP RC BAD DIS SINGLE NP ND
  typeset INHI NVG ALLROOT DUPPV PGNOTE VGO TOT FRE P WORSTP LOWVG ANYLOW LSADP FCS A FST LF LS CRC FCBAD FCTXT
  typeset FCNR FCN FCUR FRC VSCSI VSNOTE FSO NFAIL NWARN NBAD FAILLIST WARNLIST REPOLIST BADLIST OBS PHYS
  typeset INODESTATE INBAD INSEV
  typeset GWORST GEOOBS GEOVG GSUM PPSZ TPP TPV PPPV VGSZMB REALMB VGORC FACTVGBAD FACTVGSEEN WORSTFSFACT MAXINODEFACT UCLASS
  typeset LVPFLAG LVPMIR CPY LVNAME LVLPS LVPPS LVPVS LSLVO IPOL SEPPV LVPEXTRA
  typeset LSFSQ SLKMP SLKBLK SLKLV SLKFS SLKMB SLKPCT JFSLEG MNT TMPSEP NJFS2 ATIMEN NOLOG
  typeset PLNPS PLDUP PLROOT PLTOTMB PLOBS PLNOTE

  # Pre-join df -g continuation lines once, where DFG is captured: a long
  # Filesystem name (NFS/mapped) wraps onto its own line (NF==1) and its numbers
  # land on the next line — column parsing keys on $4 ~ /%/ and $NF==mount, so an
  # un-joined wrap silently drops the row. Rejoin the held name onto its numbers.
  DFRAW=$(aix df_g df -g); DFRC=$?
  if [ "$DFRC" -eq 0 ] && [ -n "$DFRAW" ]; then FACT_STORAGE_DF_READ=1; fi
  DFG=$(printf '%s\n' "$DFRAW" | awk '
    NR==1 { print; next }
    hold != "" { print hold " " $0; hold=""; next }
    NF==1 { hold=$1; next }
    { print }')
  # Structured filesystem rows are a deterministic, mount-sorted reparse of the
  # same df capture. Pseudo filesystems with '-' capacity are not numeric facts.
  DFROWS=0; DFPARSE_OK=0
  if [ "$DFRC" -eq 0 ]; then
    FACT_STORAGE_FS_USED_UNREAD=0; FACT_STORAGE_FS_IUSED_UNREAD=0
    FACT_STORAGE_FS_ROWS=$(printf '%s\n' "$DFG" | awk -v max_mb="$STOR_FACT_MAX_FS_MB" -v max_pct="$STOR_FACT_MAX_USED_PCT" '
      function nfmt(v, s){
        if(v>max_mb){bad_size=1; return ""}
        if(v==int(v)) return sprintf("%d",v)
        s=sprintf("%.6f",v); sub(/0+$/,"",s); sub(/[.]$/,"",s); return s
      }
      NR>1 && $4 ~ /^-?[0-9][0-9]*([.][0-9][0-9]*)?%$/ {
        pct=$4; sub(/%$/,"",pct)
        if(substr(pct,1,1)=="-" || pct+0>max_pct) bad_used=1
      }
      NR>1 && $2 ~ /^[0-9][0-9]*([.][0-9][0-9]*)?$/ {
          size=nfmt($2*1024)
          if(size=="") next
          u="?"; i="?"
          if($4 ~ /^-?[0-9][0-9]*([.][0-9][0-9]*)?%$/){
            uraw=$4; sub(/%$/,"",uraw)
            if(substr(uraw,1,1)!="-" && uraw+0<=max_pct) u=nfmt(uraw+0)
          } else bad_used_token=1
          if($6 ~ /^-?[0-9][0-9]*([.][0-9][0-9]*)?%$/){
            iraw=$6; sub(/%$/,"",iraw)
            if(substr(iraw,1,1)=="-" || iraw+0>max_pct) bad_iused=1
            else i=nfmt(iraw+0)
          } else bad_iused=1
          printf "%s\t%s\t%s\t%s\n",$NF,size,u,i
        }
      END{
        if(bad_size) print "__AIXRAY_INVALID_FS_SIZE__"
        if(bad_used) print "__AIXRAY_INVALID_FS_USED_PCT__"
        if(bad_used_token) print "__AIXRAY_INVALID_FS_USED_TOKEN__"
        if(bad_iused) print "__AIXRAY_INVALID_FS_IUSED_PCT__"
      }' | sort)
    # Preserve whether parsing produced any data rows before the facts validator
    # may clear them wholesale for an invalid token.  Those malformed-row cases
    # retain their dedicated unreadable findings; a genuinely rowless capture
    # must not enter any finding loop at all.
    DFROWS=$(printf '%s\n' "$FACT_STORAGE_FS_ROWS" |
      awk '$0 !~ /^__AIXRAY_INVALID_FS_/ && NF {n++} END{print n+0}')
    case "$FACT_STORAGE_FS_ROWS" in
      *"__AIXRAY_INVALID_FS_SIZE__"*|*"__AIXRAY_INVALID_FS_USED_PCT__"*)
        FACT_STORAGE_FS_ROWS="";;
      *)
        case "$FACT_STORAGE_FS_ROWS" in
          *"__AIXRAY_INVALID_FS_USED_TOKEN__"*) FACT_STORAGE_FS_USED_UNREAD=1;;
        esac
        case "$FACT_STORAGE_FS_ROWS" in
          *"__AIXRAY_INVALID_FS_IUSED_PCT__"*) FACT_STORAGE_FS_IUSED_UNREAD=1;;
        esac
        FACT_STORAGE_FS_ROWS=$(printf '%s\n' "$FACT_STORAGE_FS_ROWS" |
          awk '$0 !~ /^__AIXRAY_INVALID_FS_/ {print}')
        DFPARSE_OK=1
        ;;
    esac
  fi
  if [ -n "$FACT_STORAGE_FS_ROWS" ]; then
    if [ "$FACT_STORAGE_FS_USED_UNREAD" -eq 0 ]; then
      WORSTFSFACT=$(printf '%s\n' "$FACT_STORAGE_FS_ROWS" | awk -F'\t' 'NR==1 || $3+0>mx{mx=$3+0; out=$3} END{print out}')
      if valid_json_number "$WORSTFSFACT"; then
        FACT_STORAGE_WORST_FS_PCT="$WORSTFSFACT"
        FACT_STORAGE_WORST_FS_MOUNT=$(printf '%s\n' "$FACT_STORAGE_FS_ROWS" | awk -F'\t' 'NR==1 || $3+0>mx{mx=$3+0; out=$1} END{print out}')
      fi
    fi
    if [ "$FACT_STORAGE_FS_IUSED_UNREAD" -eq 0 ]; then
      MAXINODEFACT=$(printf '%s\n' "$FACT_STORAGE_FS_ROWS" | awk -F'\t' 'NR==1 || $4+0>mx{mx=$4+0; out=$4} END{print out}')
      if valid_json_number "$MAXINODEFACT"; then FACT_STORAGE_MAX_INODE="$MAXINODEFACT"; fi
    fi
  fi
  # A failed, empty, or rowless capture is not evidence.  Use the structured
  # facts' parsed-row gate for every df-derived finding too: rc=0 with zero rows
  # must never fall through to a clean assessment any more than rc!=0 may.
  if [ "$FACT_STORAGE_DF_READ" -ne 1 ] || [ "$DFROWS" -eq 0 ] || [ "$DFPARSE_OK" -ne 1 ]; then
    if [ "$DFRC" -ne 0 ]; then
      OBS="not assessed — df -g capture failed (rc=$DFRC)"
      DFNOTE="df -g did not complete successfully; its stdout was not used as evidence"
    elif [ "$FACT_STORAGE_DF_READ" -ne 1 ]; then
      OBS="not assessed — df -g capture empty (rc=0)"
      DFNOTE="df -g completed with no output; zero filesystem rows were available as evidence"
    elif [ "$DFPARSE_OK" -ne 1 ]; then
      OBS="not assessed — df -g capture unparseable (rc=0)"
      DFNOTE="df -g contained an invalid or implausible filesystem row, so its filesystem table could not be parsed reliably"
    else
      OBS="not assessed — df -g contained no parseable data rows (rc=0)"
      DFNOTE="df -g completed without any parseable data rows; zero filesystem rows were available as evidence"
    fi
    for M in / /var /tmp; do
      add storage "fs_$M" "Filesystem $M" NOT_ASSESSED high \
          "$OBS" \
          "Filesystem use could not be assessed because $DFNOTE." \
          "rerun 'df -g' successfully, then rerun AIXray before treating filesystem capacity as healthy."
    done
    add storage fs_other "Other filesystems" NOT_ASSESSED med \
        "$OBS" \
        "Other-filesystem use could not be assessed because $DFNOTE." \
        "rerun 'df -g' successfully, then rerun AIXray before treating other filesystems as healthy."
    add storage fs_inodes "Inode usage (JFS2)" NOT_ASSESSED med \
        "$OBS" \
        "Inode use could not be assessed because $DFNOTE." \
        "rerun 'df -g' successfully, then rerun AIXray before relying on inode headroom."
  else
  for M in / /var /tmp; do
    U=$(printf '%s\n' "$DFG" | awk -v m="$M" '
      $NF==m {
        raw=$4
        if(raw !~ /%$/ || raw=="%") print "__AIXRAY_UNREADABLE__"
        else {sub(/%$/,"",raw); print raw}
        exit
      }')
    if [ -z "$U" ]; then
      add storage "fs_$M" "Filesystem $M" NOT_ASSESSED high \
          "not assessed — no complete df -g row for $M" \
          "Filesystem use could not be assessed because df -g did not contain a complete row for $M; the capture may be incomplete or the mount may be absent." \
          "verify 'df -g $M' returns a complete row, then rerun AIXray before relying on this filesystem assessment."
      continue
    fi
    UCLASS=$(printf '%s\n' "$U" | awk -v max_pct="$STOR_FACT_MAX_USED_PCT" '
      NR==1 && $0 ~ /^-?[0-9]+([.][0-9]+)?$/ {
        seen=1; u=$0+0
        if(substr($0,1,1)=="-" || u>max_pct) print "unreadable"
        else if(u>=90) print "fail"
        else if(u>=80) print "warn"
        else print "pass"
      }
      END{if(!seen) print "unreadable"}')
    if [ "$UCLASS" = unreadable ]; then
      add storage "fs_$M" "Filesystem $M" NOT_ASSESSED low "not assessed — unreadable %Used" \
          "Filesystem use not assessed — df returned an unreadable or implausible %Used token." \
          "check 'df -g $M' manually and correct the reporting source before relying on this result."
    elif [ "$UCLASS" = fail ]; then
      add storage "fs_$M" "Filesystem $M" FAIL high "${U}% used" \
          "Critically low free space — a full $M stops logging, spooling, even login." \
          "free space now or extend the filesystem (chfs -a size=+1G $M); add an 80% alert."
    elif [ "$UCLASS" = warn ]; then
      add storage "fs_$M" "Filesystem $M" WARN med "${U}% used" \
          "Getting tight — risk of a fill-up outage." "clean up or extend; set an 80% alert."
    else
      add storage "fs_$M" "Filesystem $M" PASS low "${U}% used" "Healthy free space." "n/a"
    fi
  done
  # Other filesystems >=90%. inst.images mounts are deliberately-full install
  # repos (informational, not a FAIL). /usr is sized tight on AIX, so >=90% is a
  # WARN and only >=98% a FAIL; every other non-system mount >=90% is a FAIL.
  FSO=$(printf '%s\n' "$DFG" | awk -v max_pct="$STOR_FACT_MAX_USED_PCT" '
    NR>1 && $2 ~ /^[0-9][0-9]*([.][0-9][0-9]*)?$/ {
      m=$NF
      if (m=="/"||m=="/var"||m=="/tmp") next
      raw=$4
      if (raw !~ /^-?[0-9][0-9]*([.][0-9][0-9]*)?%$/) {
        bad=bad (bn++?", ":"") m; nbad++; next
      }
      p=raw; sub(/%$/,"",p)
      if (substr(p,1,1)=="-" || p+0>max_pct) {
        bad=bad (bn++?", ":"") m; nbad++; next
      }
      p=p+0
      if (p<90) next
      if (index(m,"inst.images")>0) { repo=repo (rn++?", ":"") m " " p "%"; next }
      if (m=="/usr" && p<98) { warn=warn (wn++?", ":"") m " " p "%"; nwarn++ }
      else { fail=fail (fn++?", ":"") m " " p "%"; nfail++ }
    }
    END{ printf "%d\t%d\t%s\t%s\t%s\t%d\t%s", nfail+0, nwarn+0, fail, warn, repo, nbad+0, bad }')
  NFAIL=$(printf '%s' "$FSO" | awk -F'\t' '{print $1+0}')
  NWARN=$(printf '%s' "$FSO" | awk -F'\t' '{print $2+0}')
  FAILLIST=$(printf '%s' "$FSO" | awk -F'\t' '{print $3}')
  WARNLIST=$(printf '%s' "$FSO" | awk -F'\t' '{print $4}')
  REPOLIST=$(printf '%s' "$FSO" | awk -F'\t' '{print $5}')
  NBAD=$(printf '%s' "$FSO" | awk -F'\t' '{print $6+0}')
  BADLIST=$(printf '%s' "$FSO" | awk -F'\t' '{print $7}')
  if [ "$NBAD" -gt 0 ]; then
    OBS="not assessed — unreadable %Used: $BADLIST"
    [ -n "$FAILLIST" ] && OBS="$OBS; critical: $FAILLIST"
    [ -n "$WARNLIST" ] && OBS="$OBS; watch: $WARNLIST"
    [ -n "$REPOLIST" ] && OBS="$OBS; repo (informational): $REPOLIST"
    add storage fs_other "Other filesystems" NOT_ASSESSED med "$OBS" \
        "Other-filesystem use was not assessed completely — df returned an unreadable or implausible %Used token for: $BADLIST." \
        "check 'df -g' manually for the named mount(s) and correct the reporting source before treating other filesystems as healthy."
  elif [ "$NFAIL" -gt 0 ]; then
    OBS="$FAILLIST"
    [ -n "$WARNLIST" ] && OBS="$OBS; watch: $WARNLIST"
    [ -n "$REPOLIST" ] && OBS="$OBS; repo (informational): $REPOLIST"
    add storage fs_other "Other filesystems" FAIL med "$OBS" \
        "One or more non-system filesystems are critically full." "free space or extend them; add monitoring."
  elif [ "$NWARN" -gt 0 ]; then
    OBS="$WARNLIST"
    [ -n "$REPOLIST" ] && OBS="$OBS; repo (informational): $REPOLIST"
    add storage fs_other "Other filesystems" WARN med "$OBS" \
        "/usr is often sized tight on AIX — over 90% is worth watching, but only critical at 98%." \
        "review /usr growth (installed filesets; clear /usr/sys/inst.images repos); extend it if it keeps climbing."
  else
    OBS="none above 90%"
    [ -n "$REPOLIST" ] && OBS="$OBS; repo (informational): $REPOLIST"
    add storage fs_other "Other filesystems" PASS low "$OBS" "No other filesystem is critically full." "n/a"
  fi

  # fs_inodes — JFS2 inode headroom (df -g column 6, %Iused)
  INODESTATE=$(printf '%s\n' "$DFG" | awk -v max_pct="$STOR_FACT_MAX_USED_PCT" '
    NR>1 && $2 ~ /^[0-9][0-9]*([.][0-9][0-9]*)?$/ {
      if($6 ~ /^-?[0-9][0-9]*([.][0-9][0-9]*)?%$/){
        raw=$6; sub(/%$/,"",raw)
        if(substr(raw,1,1)=="-" || raw+0>max_pct)
          bad=bad (bn++?", ":"") $NF
        else if(raw+0>=90)
          hi=hi (hn++?", ":"") $NF " " $6
      } else bad=bad (bn++?", ":"") $NF
    }
    END{printf "%s\t%s",hi,bad}')
  INHI=$(printf '%s' "$INODESTATE" | awk -F'\t' '{print $1}')
  INBAD=$(printf '%s' "$INODESTATE" | awk -F'\t' '{print $2}')
  if [ -n "$INBAD" ]; then
    OBS="unreadable %Iused: $INBAD"
    [ -n "$INHI" ] && OBS="$INHI; $OBS"
    if [ -n "$INHI" ]; then INSEV=med; else INSEV=low; fi
    add storage fs_inodes "Inode usage (JFS2)" NOT_ASSESSED "$INSEV" "not assessed — $OBS" \
        "Inode use not assessed for every real filesystem — df returned an unreadable or implausible %Iused token for: $INBAD." \
        "check 'df -g' manually for the named mount(s) and correct the reporting source before relying on inode headroom."
  elif [ -n "$INHI" ]; then
    add storage fs_inodes "Inode usage (JFS2)" WARN med "$INHI" \
        "One or more JFS2 filesystems are past 90% inodes used. JFS2 grows inodes dynamically, so sustained 90%+ is usually fine — but it is still worth a look." \
        "check the mount for a flood of tiny files (find <mount> -xdev | wc -l); clean up or plan to extend if it keeps climbing."
  else
    add storage fs_inodes "Inode usage (JFS2)" PASS low "no filesystem above 90% inodes" \
        "JFS2 inode usage has headroom on every filesystem." "n/a"
  fi
  fi

}

function standalone_run {
  checks_storage
}

standalone_main "$@"
exit $?
