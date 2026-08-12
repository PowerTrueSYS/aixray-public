#!/bin/ksh
# Generated standalone AIXray check support. READ-ONLY: captures only; no
# remediation, service control, network access, or durable target-host writes.
set -u

# Match the monolith's guarded AIX command search path and parsing locale.
PATH=/usr/bin:/etc:/usr/sbin:/usr/ucb:/usr/bin/X11:/sbin:/usr/ios/cli:${PATH:-}
export PATH
LC_ALL=C
export LC_ALL

AIXRAY_STANDALONE_VERSION="1.1.0"

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

AIXRAY_TOOL=ck-account-inventory-delta


function standalone_check {
_AIXRAY_SESSION_KEYS=""
  # account_inventory_delta — the change in administrator and user accounts
  # since the previous scan that wrote into the same report output directory.
  #
  # This finding carries NO control tag, deliberately. CIS IBM AIX 7 v1.2.0
  # 5.1.4 and 5.1.5 are organizational: "established and maintained" is a fact
  # about a process, and no host scan can establish it. Those two controls are
  # accounted for as manual-review interview questions in the compliance
  # report. This check does not cover them and must never be presented as if
  # it did — it is new operator value that helps maintain an inventory that
  # someone else owns.
  #
  # Both probes go through aix(), which discards stderr, rather than aixv().
  # They reuse the two account-database capture keys the monolith already owns
  # (lsuser_priv, passwd_uid0) so no new capture is introduced; their exit
  # status alone settles whether the account database was readable, and there
  # is no diagnostic string this check needs to tell two failures apart. A
  # differently-keyed aixv() capture of the same database would buy nothing.
  #
  # Account classes are the same definition stale_privileged_accounts already
  # uses in the monolith — this check does not invent a third one:
  #   system = the fixed AIX/VIOS service-account name list below
  #   admin  = every UID-0 account, plus every non-system account with
  #            admin=true
  #   user   = every other non-system account
  # admin and user are disjoint by construction, so the two counts add up and
  # an account promoted to administrator reads as one admin addition and one
  # user removal. RBAC role assignments (lsuser -a roles) are NOT in scope:
  # covering them would need a capture key that no fixture or live capture
  # carries, and the admin attribute plus UID 0 is the privileged definition
  # the rest of AIXray already reasons about.
  #
  # The snapshot lives with the report, in the operator's --out directory, and
  # never inside the audited system's configuration; writing to /etc/security
  # would mutate the customer's box and falsify the report's own READ-ONLY
  # banner. This fragment performs no write at all: check source may not
  # redirect output (tools/ci/check-tool-command-allowlist.py enforces that),
  # so it computes the snapshot body into AID_SNAPSHOT_BODY and its
  # destination into AID_SNAPSHOT_FILE, and the report writer persists them.
  # With no output directory — a stdout run — no history can be kept at all,
  # and the finding says so rather than pretending the sets matched.
  typeset AID_SNAP_DIR AID_SNAPSHOT_FILE AID_SNAPSHOT_BODY AID_HOSTKEY
  typeset AID_UID0 AID_UID0_RC AID_LSUSER AID_LSUSER_RC
  typeset AID_PREV AID_PREV_RC AID_CMP AID_TOKEN AID_DETAIL
  typeset AID_STATUS AID_SEV AID_OBS AID_MEAN AID_FIX

  AID_SNAP_DIR=""
  AID_SNAPSHOT_FILE=""
  AID_SNAPSHOT_BODY=""
  AID_HOSTKEY=""
  AID_UID0=""
  AID_UID0_RC=126
  AID_LSUSER=""
  AID_LSUSER_RC=126
  AID_PREV=""
  AID_PREV_RC=126
  AID_CMP=""
  AID_TOKEN=""
  AID_DETAIL=""
  AID_STATUS=""
  AID_SEV=""
  AID_OBS=""
  AID_MEAN=""
  AID_FIX=""

  # Snapshot name is host-scoped the same way the report file name is, so a
  # fleet run collecting several hosts into one --out directory compares each
  # host against its own history instead of against whichever host ran last.
  AID_HOSTKEY=${HOST:-}
  AID_HOSTKEY=${AID_HOSTKEY%%.*}
  AID_HOSTKEY=$(printf '%s\n' "$AID_HOSTKEY" | awk 'NR==1{gsub(/[^A-Za-z0-9_-]/,"_"); print; exit}')
  [ -n "$AID_HOSTKEY" ] || AID_HOSTKEY=unknown
  AID_SNAP_DIR=${AIXRAY_ACCOUNT_SNAPSHOT_DIR:-${OUT_DIR:-}}
  if [ -n "$AID_SNAP_DIR" ]; then
    AID_SNAPSHOT_FILE="$AID_SNAP_DIR/aixray-account-inventory-$AID_HOSTKEY.snapshot"
  fi

  AID_UID0=$(aix passwd_uid0 awk -F: '$3==0 {print $1}' /etc/passwd)
  AID_UID0_RC=$?
  AID_LSUSER=$(aix lsuser_priv lsuser -a admin maxage account_locked time_last_login ALL)
  AID_LSUSER_RC=$?

  if [ "$AID_LSUSER_RC" -ne 0 ]; then
    AID_STATUS=NOT_ASSESSED
    AID_OBS="not assessed — account database unreadable (lsuser rc=$AID_LSUSER_RC)"
  elif [ "$AID_UID0_RC" -ne 0 ]; then
    AID_STATUS=NOT_ASSESSED
    AID_OBS="not assessed — UID-0 account list unreadable (/etc/passwd rc=$AID_UID0_RC)"
  else
    # Current inventory, sorted so the snapshot body and every name list this
    # check prints are byte-stable across runs.
    AID_SNAPSHOT_BODY=$(printf '%s\n@@ACCOUNTS@@\n%s\n' "$AID_UID0" "$AID_LSUSER" | awk '
      BEGIN {
        n = split("daemon bin sys adm uucp guest nobody lpd lp invscout snapp ipsec nuucp pconsole sshd esaadmin slotd ragent smmsp", s, " ")
        for (i = 1; i <= n; i++) sysu[s[i]] = 1
        phase = 0
      }
      $0 == "@@ACCOUNTS@@" { phase = 1; next }
      phase == 0 {
        if ($1 ~ /^[A-Za-z0-9._-]+$/ && !($1 in uid0)) {
          uid0[$1] = 1
          n0++
          u0[n0] = $1
        }
        next
      }
      {
        if (NF < 2) next
        if ($1 !~ /^[A-Za-z0-9._-]+$/) next
        seen[$1] = 1
        adm = "false"
        for (i = 2; i <= NF; i++) if (index($i, "admin=") == 1) adm = substr($i, 7)
        if ($1 in uid0) { print "admin " $1; next }
        if ($1 in sysu) next
        if (adm == "true") print "admin " $1
        else print "user " $1
      }
      END {
        # A UID-0 account the account-attribute listing never mentioned is the
        # most dangerous one this check could miss, so /etc/passwd carries it
        # into the inventory on its own.
        for (i = 1; i <= n0; i++) if (!(u0[i] in seen)) print "admin " u0[i]
      }' | sort)

    if [ -z "$AID_SNAPSHOT_BODY" ]; then
      AID_STATUS=NOT_ASSESSED
      AID_OBS="not assessed — account database read back no usable account record"
    else
      # Previous snapshot. It is the tool's own prior output, read directly
      # rather than through aix(): it is not a target-host command, and under
      # AIXRAY_FIXTURES it must stay the real file the operator carries
      # forward. Any malformed line voids the whole comparison — a snapshot
      # that is partly garbage cannot prove a set matched.
      if [ -n "$AID_SNAPSHOT_FILE" ] && [ -r "$AID_SNAPSHOT_FILE" ]; then
        AID_PREV=$(awk '
          /^[ \t]*$/ { next }
          /^[ \t]*#/ { next }
          {
            if (NF != 2) { bad = 1; exit }
            if ($1 != "admin" && $1 != "user") { bad = 1; exit }
            if ($2 !~ /^[A-Za-z0-9._-]+$/) { bad = 1; exit }
            print $1 " " $2
            rows++
          }
          END { if (bad || !rows) exit 1 }
        ' "$AID_SNAPSHOT_FILE" 2>/dev/null)
        AID_PREV_RC=$?
        if [ "$AID_PREV_RC" -eq 0 ]; then
          AID_PREV=$(printf '%s\n' "$AID_PREV" | sort)
        else
          AID_PREV=""
        fi
      fi

      # Both streams arrive sorted, and every list is built by walking them in
      # order, so the names printed below are deterministic rather than
      # whatever order awk happens to hash them into.
      AID_CMP=$(printf '%s\n@@NOW@@\n%s\n' "$AID_PREV" "$AID_SNAPSHOT_BODY" | awk '
        function cap(t) {
          if (substr(t, 118, 1) != "") t = substr(t, 1, 117) "..."
          return t
        }
        function names(list, extra) {
          return (extra > 0) ? list " (+" extra " more)" : list
        }
        BEGIN { phase = 0 }
        $0 == "@@NOW@@" { phase = 1; next }
        /^[ \t]*$/ { next }
        phase == 0 { k = $1 " " $2; prev[k] = 1; np++; pline[np] = k; next }
        {
          k = $1 " " $2
          now[k] = 1
          nn++
          nline[nn] = k
          if ($1 == "admin") na++; else nu++
        }
        END {
          for (i = 1; i <= nn; i++) {
            k = nline[i]
            if (k in prev) continue
            split(k, f, " ")
            if (f[1] == "admin") {
              aa++
              if (aa <= 3) aal = aal (aal == "" ? "" : ", ") f[2]
            } else {
              ua++
              if (ua <= 3) ual = ual (ual == "" ? "" : ", ") f[2]
            }
          }
          for (i = 1; i <= np; i++) {
            k = pline[i]
            if (k in now) continue
            split(k, f, " ")
            if (f[1] == "admin") {
              ar++
              if (ar <= 3) arl = arl (arl == "" ? "" : ", ") f[2]
            } else {
              ur++
              if (ur <= 3) url = url (url == "" ? "" : ", ") f[2]
            }
          }
          counts = (na + 0) " admin, " (nu + 0) " user account(s)"
          if (np == 0) { printf "FIRST\t%s\n", counts; exit }
          if (aa + ar + ua + ur == 0) {
            printf "NOCHANGE\t%s\n", cap(counts "; unchanged since the previous scan")
            exit
          }
          detail = ""
          if (aa > 0) detail = "admin added: " names(aal, aa - 3)
          if (ar > 0) detail = detail (detail == "" ? "" : "; ") "admin removed: " names(arl, ar - 3)
          if (ua > 0) detail = detail (detail == "" ? "" : "; ") "user added: " names(ual, ua - 3)
          if (ur > 0) detail = detail (detail == "" ? "" : "; ") "user removed: " names(url, ur - 3)
          printf "%s\t%s\n", (aa > 0 ? "ADMIN_ADDED" : "CHANGED"), cap(detail "; now " counts)
        }')
      AID_TOKEN=$(printf '%s\n' "$AID_CMP" | awk -F '\t' 'NR==1{print $1}')
      AID_DETAIL=$(printf '%s\n' "$AID_CMP" | awk -F '\t' 'NR==1{print $2}')

      case "$AID_TOKEN" in
        NOCHANGE)
          AID_STATUS=PASS
          AID_OBS=$AID_DETAIL
          ;;
        ADMIN_ADDED)
          AID_STATUS=FAIL
          AID_OBS=$AID_DETAIL
          ;;
        CHANGED)
          AID_STATUS=WARN
          AID_OBS=$AID_DETAIL
          ;;
        FIRST)
          AID_STATUS=NOT_APPLICABLE
          if [ -z "$AID_SNAPSHOT_FILE" ]; then
            AID_OBS="no --out directory, so no scan history is kept; observed now: $AID_DETAIL"
          elif [ -f "$AID_SNAPSHOT_FILE" ]; then
            AID_OBS="prior snapshot unusable; reference re-established: $AID_DETAIL"
          else
            AID_OBS="first scan into this output directory; reference established: $AID_DETAIL"
          fi
          ;;
        *)
          AID_STATUS=NOT_ASSESSED
          AID_OBS="not assessed — account inventory comparison produced no verdict"
          ;;
      esac
    fi
  fi

  case "$AID_STATUS" in
    PASS)
      AID_SEV=low
      AID_MEAN="The set of administrator and user accounts is identical to the one recorded in this output directory by the previous scan."
      AID_FIX="n/a"
      ;;
    FAIL)
      AID_SEV=high
      AID_MEAN="At least one account has gained administrator standing since the previous scan. A new administrator is new standing privilege on this host, and it is the one account change that is an access grant rather than a bookkeeping event."
      AID_FIX="attribute each added administrator to an approved request, remove any that has none, and record the survivors in the account inventory; AIXray recommends this, it never changes an account."
      ;;
    WARN)
      AID_SEV=med
      AID_MEAN="The set of accounts has changed since the previous scan without any account gaining administrator standing. Nothing here grants new privilege, but the inventory is now out of date until each change is attributed."
      AID_FIX="attribute each added or removed account to an approved joiner, mover or leaver record and bring the account inventory back into line; AIXray recommends this, it never changes an account."
      ;;
    NOT_APPLICABLE)
      AID_SEV=low
      AID_MEAN="There is no prior account snapshot in this output directory to compare against, so there is no delta to report. This is the determinate first-scan state, not a failed check: the counts above are the reference this run establishes."
      AID_FIX="reuse the same --out directory for the next scan so the delta can be computed, and confirm the counts above match the account inventory of record."
      ;;
    *)
      AID_SEV=med
      AID_MEAN="AIXray did not obtain a trustworthy read of the account database, so it cannot say which accounts exist, let alone which of them changed."
      AID_FIX="rerun AIXray as an identity that can read the account database (root), then rerun to establish the comparison."
      ;;
  esac

  add security account_inventory_delta "Account inventory delta" \
    "$AID_STATUS" "$AID_SEV" "$AID_OBS" "$AID_MEAN" "$AID_FIX" ""
  if [ "$AID_STATUS" = "NOT_APPLICABLE" ]; then
    F_EVIDENCE_COMMANDS[$((NFIND-1))]="awk -F: '\$3==0 {print \$1}' /etc/passwd|lsuser -a admin maxage account_locked time_last_login ALL"
  fi
}

function standalone_run {
  standalone_check
}

standalone_main "$@"
exit $?
