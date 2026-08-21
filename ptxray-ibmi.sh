#!/QOpenSys/usr/bin/ksh
# PTxray IBM i edition. Read-only; assembled into one inspectable PASE script.
set -u
PATH=/QOpenSys/usr/bin:/usr/bin:/QOpenSys/pkgs/bin:${PATH:-}
export PATH
LC_ALL=C
export LC_ALL

PTXRAY_VERSION=1.3.0
FORMAT=text
COMPLIANCE=cis-l1
while [ "$#" -gt 0 ]; do
  case "$1" in
    --text) FORMAT=text ;;
    --json) FORMAT=json ;;
    --html) FORMAT=html ;;
    --compliance)
      shift
      [ "$#" -gt 0 ] || { echo "ptxray-ibmi.sh: --compliance requires cis-l1 or cis-l2" >&2; exit 2; }
      case "$1" in cis-l1|cis-l2) COMPLIANCE=$1 ;; *) echo "ptxray-ibmi.sh: unsupported compliance profile: $1" >&2; exit 2;; esac
      ;;
    --help|-h)
      echo "usage: ptxray-ibmi.sh [--text|--json|--html] [--compliance cis-l1|cis-l2]"
      exit 0
      ;;
    *) echo "ptxray-ibmi.sh: unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done

function jesc {
  awk 'BEGIN{ORS=""} {gsub(/\\/,"\\\\");gsub(/"/,"\\\"");gsub(/\t/,"\\t");gsub(/\r/,"\\r");if(NR>1)printf "\\n";print}'
}
function hesc {
  awk 'BEGIN{ORS=""} {gsub(/&/,"\\&amp;");gsub(/</,"\\&lt;");gsub(/>/,"\\&gt;");gsub(/"/,"\\&quot;");if(NR>1)print "&#10;";print}'
}
function is_leap_year {
  typeset y=$1
  if [ $((y % 400)) -eq 0 ]; then return 0
  elif [ $((y % 100)) -eq 0 ]; then return 1
  elif [ $((y % 4)) -eq 0 ]; then return 0
  fi
  return 1
}
function valid_ymd {
  typeset value=$1 year month day rest max
  case "$value" in [0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]) ;; *) return 1;; esac
  year=${value%%-*}; rest=${value#*-}; month=${rest%%-*}; day=${rest#*-}
  month=${month#0}; day=${day#0}; [ -n "$month" ] || month=0; [ -n "$day" ] || day=0
  case "$month" in 1|3|5|7|8|10|12) max=31;; 4|6|9|11) max=30;; 2) if is_leap_year "$year"; then max=29; else max=28; fi;; *) return 1;; esac
  [ "$day" -ge 1 ] && [ "$day" -le "$max" ]
}
function d2j {
  printf '%s\n' "$1" | awk -F- '{y=$1+0;m=$2+0;d=$3+0;a=int((14-m)/12);y=y+4800-a;m=m+12*a-3;print d+int((153*m+2)/5)+365*y+int(y/4)-int(y/100)+int(y/400)-32045}'
}

set -A F_CAT F_ID F_LABEL F_ST F_SEV F_OBS F_MEAN F_FIX F_TAG
NFIND=0
function add {
  F_CAT[$NFIND]=$1; F_ID[$NFIND]=$2; F_LABEL[$NFIND]=$3
  F_ST[$NFIND]=$4; F_SEV[$NFIND]=$5; F_OBS[$NFIND]=$6
  F_MEAN[$NFIND]=$7; F_FIX[$NFIND]=$8; F_TAG[$NFIND]=${9:-}
  NFIND=$((NFIND + 1))
}

TODAY=${AIXRAY_TODAY:-$(date +%Y-%m-%d 2>/dev/null)}
valid_ymd "$TODAY" || { echo "ptxray-ibmi.sh: invalid assessment date" >&2; exit 2; }
TODAY_J=$(d2j "$TODAY")

# IBM i probe verbs. Checks never call qsh/db2/system directly.
IBMI_PROBES=1
# Fixture hook matches aix(): AIXRAY_FIXTURES/<key>.out + optional .rc.

function ibmi_capture_missing {
  if [ -n "${AIXRAY_FIXTURES:-}" ]; then
    if [ -r "$AIXRAY_FIXTURES/$1.out" ] || [ -r "$AIXRAY_FIXTURES/$1.err" ]; then
      return 1
    fi
    return 0
  fi
  return 1
}

# ibmi_sql <key> <sql...> — Qshell db2 first; pipe-delimited rows only.
# Live db2 wraps columns; callers SELECT VARCHAR(... ) CONCAT '|' ... so data
# rows contain '|'. Header/dashes/RECORD(S) are dropped here.
function ibmi_sql {
  typeset key rc out
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
  out=$(/QOpenSys/usr/bin/qsh -c "db2 \"$*\"" 2>/dev/null)
  rc=$?
  printf '%s\n' "$out" | awk '/\|/ && $0 !~ /RECORD/ { gsub(/[ \t]+$/, ""); print }'
  return $rc
}

# Return the IBM i major.minor release. The monolith's lifecycle check sets REL
# before security checks run; a standalone check falls back to the same
# ENV_SYS_INFO query so release-specific CIS predicates remain exact.
function ibmi_release {
  typeset raw rc line version release
  case "${REL:-}" in
    [0-9]*.[0-9]*) printf '%s\n' "$REL"; return 0 ;;
  esac
  raw=$(ibmi_sql os_vrm "SELECT 'OS' CONCAT '|' CONCAT VARCHAR(TRIM(COALESCE(OS_VERSION,'-')),10) CONCAT '|' CONCAT VARCHAR(TRIM(COALESCE(OS_RELEASE,'-')),10) FROM SYSIBMADM.ENV_SYS_INFO")
  rc=$?
  [ "$rc" -eq 0 ] || { printf '%s\n' unknown; return 1; }
  line=$(printf '%s\n' "$raw" | awk -F'|' '$1=="OS"{n++; line=$0} END{if(n==1) print line}')
  [ -n "$line" ] || { printf '%s\n' unknown; return 1; }
  version=$(printf '%s\n' "$line" | awk -F'|' '{gsub(/^[ \t]+|[ \t]+$/, "", $2); print $2}')
  release=$(printf '%s\n' "$line" | awk -F'|' '{gsub(/^[ \t]+|[ \t]+$/, "", $3); print $3}')
  case "$version.$release" in
    [0-9].[0-9]) printf '%s\n' "$version.$release" ;;
    *) printf '%s\n' unknown; return 1 ;;
  esac
}

# A supported IBM i assessment must begin and remain QSECOFR. CURRENT_USER is
# deliberately excluded: adopted authority does not make another signed-on
# profile an honest QSECOFR scan identity.
function ibmi_require_qsecofr {
  typeset identity identity_rc
  identity=$(ibmi_sql scan_identity "SELECT VARCHAR(TRIM(SESSION_USER),128) CONCAT '|' CONCAT VARCHAR(TRIM(SYSTEM_USER),128) FROM SYSIBM.SYSDUMMY1")
  identity_rc=$?
  [ "$identity_rc" -eq 0 ] || return 2
  printf '%s\n' "$identity" | awk '
    {
      row=$0
      sub(/^[ \t]+/, "", row)
      sub(/[ \t]+$/, "", row)
      if (row != "") { count++; value=row }
    }
    END { exit !(count == 1 && value == "QSECOFR|QSECOFR") }
  ' >/dev/null 2>&1 || return 2
  return 0
}

# ibmi_cl <key> <cl-command...> — CL via system(3). Callers must not treat
# spool banners as evidence. Genuine lab captures remain verbatim; keep private
# identifiers out of operational code, administrative hostnames, and paths.
function ibmi_cl {
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
  system "$*" 2>/dev/null
}

if ! ibmi_require_qsecofr; then
  echo 'PTxray IBM i requires SESSION_USER=QSECOFR and SYSTEM_USER=QSECOFR; no scan was run.' >&2
  exit 2
fi
# Shared SECURITY_INFO capture. Empty or refused is D-i6 evidence.

function capture_cap_security_info {
  SECINFO_RAW=$(ibmi_sql security_info "SELECT COUNT(*) FROM QSYS2.SECURITY_INFO")
  SECINFO_RC=$?
  SECINFO_OK=0
  SECINFO_WHY=""
  if [ "$SECINFO_RC" -ne 0 ]; then
    SECINFO_WHY="capture failed (rc=$SECINFO_RC)"
  elif [ -z "$SECINFO_RAW" ]; then
    SECINFO_WHY="capture empty (rc=0)"
  else
    SECINFO_OK=1
  fi
  return 0
}

# Shared SYSTEM_VALUE_INFO capture. Every ck-sv-* parses this one dump.
# SQL emits pipe rows so ibmi_sql can drop db2 headers. *NOTAVL is a real
# value meaning the scan profile cannot read that sysval (D-i6) — not empty.

function capture_cap_system_values {
  SYSVAL_RAW=$(ibmi_sql system_value_info "SELECT VARCHAR(SYSTEM_VALUE_NAME,10) CONCAT '|' CONCAT VARCHAR(COALESCE(TRIM(CHAR(CURRENT_NUMERIC_VALUE)),''),20) CONCAT '|' CONCAT VARCHAR(COALESCE(TRIM(CURRENT_CHARACTER_VALUE),''),256) FROM QSYS2.SYSTEM_VALUE_INFO ORDER BY SYSTEM_VALUE_NAME")
  SYSVAL_RC=$?
  SYSVAL_OK=0
  SYSVAL_WHY=""
  if [ "$SYSVAL_RC" -ne 0 ]; then
    SYSVAL_WHY="capture failed (rc=$SYSVAL_RC)"
  elif [ -z "$SYSVAL_RAW" ]; then
    SYSVAL_WHY="capture empty (rc=0)"
  else
    SYSVAL_OK=1
  fi
  return 0
}

# Shared USER_INFO capture for ck-usr-*. A one-row result is a profile-scope
# finding about PTSCAN, not proof the box has one user.

function capture_cap_user_info {
  USERINFO_RAW=$(ibmi_sql user_info "SELECT COUNT(*) FROM QSYS2.USER_INFO")
  USERINFO_RC=$?
  USERINFO_OK=0
  USERINFO_WHY=""
  if [ "$USERINFO_RC" -ne 0 ]; then
    USERINFO_WHY="capture failed (rc=$USERINFO_RC)"
  elif [ -z "$USERINFO_RAW" ]; then
    USERINFO_WHY="capture empty (rc=0)"
  else
    USERINFO_OK=1
  fi
  return 0
}

capture_cap_system_values
capture_cap_security_info
capture_cap_user_info
  # cur_firmware — IBM i SYSTOOLS.FIRMWARE_CURRENCY
  # Edition decision: docs/ibmi-systools-currency-exception.md
  # (D-i8). This IBM-shipped SYSTOOLS view may reach IBM FLRT;
  # offline degrades.
  # Phase 5 currency, not CIS 5.5.1 (that is
  # ck-cur-ptf-groups / GROUP_PTF_CURRENCY).
  # INSTALLED LEVEL IS CURRENT is PASS.
  # UPGRADE AVAILABLE is WARN med.
  # UPDATE AVAILABLE / UPDATE AND UPGRADE
  # AVAILABLE is WARN high (general currency;
  # security-group FAIL is the sibling).
  # rc 1 + empty is NOT_APPLICABLE (zero-row
  # SELECT). rc 0 + empty is swallowed
  # mid-fetch NOT_ASSESSED.
  # One finding. Calls ibmi_sql only.
  # Does not call ibmi_cl / DSPFMWSTS /
  # DSPHDWRSC. Does not SELECT MTM or UAK.
  # Does not COUNT(*) (that would HTTP twice).
  FW_RAW=$(ibmi_sql fw_currency "SELECT 'FW' CONCAT '|' CONCAT VARCHAR(TRIM(COALESCE(FW_CURRENCY, '-')), 28) CONCAT '|' CONCAT VARCHAR(TRIM(COALESCE(FW_CURRENTFIXPACK, '-')), 20) CONCAT '|' CONCAT VARCHAR(TRIM(COALESCE(FW_RECOMMENDED_UPDATE, '-')), 20) CONCAT '|' CONCAT VARCHAR(TRIM(COALESCE(FW_RECOMMENDED_UPGRADE, '-')), 20) CONCAT '|' CONCAT VARCHAR(TRIM(COALESCE(FW_UPDATE_POLICY, '-')), 5) CONCAT '|' CONCAT VARCHAR(TRIM(COALESCE(FW_IPL_REQUIRED, '-')), 3) FROM SYSTOOLS.FIRMWARE_CURRENCY")
  FW_RC=$?
  if [ "$FW_RC" -eq 1 ] && [ -z "$FW_RAW" ]; then
    add lifecycle cur_firmware "IBM i firmware currency" NOT_APPLICABLE low \
        "firmware row empty (zero-row SELECT)" \
        "SYSTOOLS.FIRMWARE_CURRENCY returned no row for this partition, so no IBM FLRT firmware-currency grade is available from this partition." \
        "review firmware on the HMC or the provider control plane. This scanner never changes firmware."
  elif [ "$FW_RC" -ne 0 ]; then
    add lifecycle cur_firmware "IBM i firmware currency" NOT_ASSESSED low \
        "not assessed — capture failed (rc=$FW_RC)" \
        "The firmware-currency probe did not yield a readable FIRMWARE_CURRENCY dump, so firmware currency cannot be graded. The view reaches IBM FLRT when it runs." \
        "compare the firmware level from DSPFMWSTS or the HMC or provider control plane against IBM FLRT or Fix Central, confirm job CCSID is not 65535 and Java is present, then re-run when the partition can reach the FLRT feed. This scanner never changes firmware."
  elif [ -z "$FW_RAW" ]; then
    add lifecycle cur_firmware "IBM i firmware currency" NOT_ASSESSED low \
        "not assessed — capture empty (rc=0)" \
        "The firmware-currency probe returned no pipe row after a successful rc, so the FLRT fetch may have failed mid-query and firmware currency cannot be graded." \
        "compare the firmware level from DSPFMWSTS or the HMC or provider control plane against IBM FLRT or Fix Central, then re-run when the partition can reach the FLRT feed. This scanner never changes firmware."
  else
    FW_PARSE=$(printf '%s\n' "$FW_RAW" | awk -F'|' '
      function fxok(s) {
        return (s ~ /^[A-Za-z0-9._-]{1,20}$/ && s != "-")
      }
      function recok(s) {
        return (s == "-" || fxok(s))
      }
      $1=="FW" {
        tok=$2; sub(/[ \t]+$/, "", tok)
        cur=$3; sub(/[ \t]+$/, "", cur)
        upd=$4; sub(/[ \t]+$/, "", upd)
        upg=$5; sub(/[ \t]+$/, "", upg)
        pol=$6; sub(/[ \t]+$/, "", pol)
        ipl=$7; sub(/[ \t]+$/, "", ipl)
        if (tok != "INSTALLED LEVEL IS CURRENT" && tok != "UPDATE AVAILABLE" && tok != "UPGRADE AVAILABLE" && tok != "UPDATE AND UPGRADE AVAILABLE") { junk=1; next }
        if (!fxok(cur)) { junk=1; next }
        if (!recok(upd)) { junk=1; next }
        if (!recok(upg)) { junk=1; next }
        if (pol != "HMC" && pol != "OPSYS" && pol != "-") { junk=1; next }
        if (ipl != "YES" && ipl != "NO" && ipl != "-") { junk=1; next }
        got = tok "|" cur "|" upd "|" upg "|" pol "|" ipl
        if (seen) {
          if (attr != got) junk=1
          next
        }
        seen=1
        attr=got
        n++
        next
      }
      END {
        if (junk) { print "JUNK"; exit }
        if (n != 1) { print "JUNK"; exit }
        print "OK " attr
      }')
    if [ "$FW_PARSE" = "JUNK" ]; then
      add lifecycle cur_firmware "IBM i firmware currency" NOT_ASSESSED low \
          "not assessed — FIRMWARE_CURRENCY value unreadable" \
          "The firmware-currency dump was readable, but a row carried a currency token, fixpack, or update-policy value that could not be graded." \
          "inspect SYSTOOLS.FIRMWARE_CURRENCY FW_CURRENCY, FW_CURRENTFIXPACK, FW_RECOMMENDED_UPDATE, FW_RECOMMENDED_UPGRADE, and FW_UPDATE_POLICY."
    else
      FW_TOK=$(printf '%s\n' "$FW_PARSE" | awk -F'|' '{ print $1 }' | awk '{ print substr($0,4) }')
      FW_CUR=$(printf '%s\n' "$FW_PARSE" | awk -F'|' '{ print $2 }')
      FW_UPD=$(printf '%s\n' "$FW_PARSE" | awk -F'|' '{ print $3 }')
      FW_UPG=$(printf '%s\n' "$FW_PARSE" | awk -F'|' '{ print $4 }')
      FW_POL=$(printf '%s\n' "$FW_PARSE" | awk -F'|' '{ print $5 }')
      if [ "$FW_TOK" = "INSTALLED LEVEL IS CURRENT" ]; then
        add lifecycle cur_firmware "IBM i firmware currency" PASS low \
            "current=$FW_CUR policy=$FW_POL" \
            "The installed firmware fix level matches the current IBM FLRT recommendation, so this partition is not behind on server firmware." \
            "n/a"
      elif [ "$FW_TOK" = "UPGRADE AVAILABLE" ]; then
        add lifecycle cur_firmware "IBM i firmware currency" WARN med \
            "current=$FW_CUR upgrade=$FW_UPG policy=$FW_POL" \
            "A newer firmware family is available from IBM. The installed stream is not reported behind, but the upgrade path should be planned." \
            "plan the firmware family upgrade on the HMC or provider control plane (policy HMC) or with PTFs for the firmware product (policy OPSYS). This scanner never changes firmware."
      else
        add lifecycle cur_firmware "IBM i firmware currency" WARN high \
            "current=$FW_CUR available=$FW_UPD upgrade=$FW_UPG policy=$FW_POL" \
            "IBM FLRT reports a firmware update is available, so this partition is behind on server firmware and newly published firmware fixes are not installed here." \
            "apply the recommended firmware update from the HMC or provider control plane (policy HMC) or with PTFs for the firmware product (policy OPSYS). This scanner never changes firmware."
      fi
    fi
  fi

  # cur_os_lifecycle — IBM i OS release vs embedded EOS table.
  # Authority: IBM Release life cycle as of DATA_VINTAGE.
  # Not a CIS rec. One finding. Calls ibmi_sql for
  # SYSIBMADM.ENV_SYS_INFO OS_VERSION / OS_RELEASE.
  # Does not call ibmi_cl / DSPPTF / GO LICPGM.
  # Does not SELECT HOST_NAME (D82). Does not query
  # SYSTOOLS.GROUP_PTF_CURRENCY (ck-cur-ptf-groups) or
  # SYSTOOLS.FIRMWARE_CURRENCY (ck-cur-firmware).
  # 7.6/7.5 SUPPORTED is PASS. 7.4 EOS 2026-09-30. 7.3/7.2/7.1/6.1/5.4 past.
  DATA_VINTAGE="2026-08-20"
  EOS_IBMI="
5.4|2013-09-30
6.1|2015-09-30
7.1|2018-04-30
7.2|2021-04-30
7.3|2023-09-30
7.4|2026-09-30
7.5|SUPPORTED
7.6|SUPPORTED
"
  OS_RAW=$(ibmi_sql os_vrm "SELECT 'OS' CONCAT '|' CONCAT VARCHAR(TRIM(COALESCE(OS_VERSION,'-')),10) CONCAT '|' CONCAT VARCHAR(TRIM(COALESCE(OS_RELEASE,'-')),10) FROM SYSIBMADM.ENV_SYS_INFO")
  OS_RC=$?
  if [ "$OS_RC" -ne 0 ]; then
    add lifecycle cur_os_lifecycle "IBM i release support" NOT_ASSESSED low \
        "not assessed — capture failed (rc=$OS_RC)" \
        "The IBM i OS-release probe did not yield a readable ENV_SYS_INFO dump, so the support window cannot be graded." \
        "re-run the scan as the scan profile and confirm SYSIBMADM.ENV_SYS_INFO returns OS_VERSION and OS_RELEASE. This scanner never changes the operating system."
  elif [ -z "$OS_RAW" ]; then
    add lifecycle cur_os_lifecycle "IBM i release support" NOT_ASSESSED low \
        "not assessed — capture empty (rc=0)" \
        "The IBM i OS-release probe returned no pipe row, so the support window cannot be graded." \
        "re-run the scan as the scan profile and confirm SYSIBMADM.ENV_SYS_INFO returns OS_VERSION and OS_RELEASE. This scanner never changes the operating system."
  else
    OS_LINE=$(printf '%s\n' "$OS_RAW" | awk -F'|' '$1=="OS"{n++; line=$0} END{if(n==1) print line}')
    if [ -z "$OS_LINE" ]; then
      add lifecycle cur_os_lifecycle "IBM i release support" NOT_ASSESSED low \
          "not assessed — OS row missing or not unique in ENV_SYS_INFO" \
          "The IBM i OS-release dump was readable, but it did not contain exactly one OS row, so the release cannot be graded." \
          "inspect SYSIBMADM.ENV_SYS_INFO for OS_VERSION and OS_RELEASE."
    else
      OS_VER=$(printf '%s\n' "$OS_LINE" | awk -F'|' '{ v=$2; sub(/^[ \t]+/, "", v); sub(/[ \t]+$/, "", v); print v }')
      OS_REL=$(printf '%s\n' "$OS_LINE" | awk -F'|' '{ v=$3; sub(/^[ \t]+/, "", v); sub(/[ \t]+$/, "", v); print v }')
      case "$OS_VER" in
        ''|*[!0-9]*) OS_VER="" ;;
      esac
      case "$OS_REL" in
        ''|*[!0-9]*) OS_REL="" ;;
      esac
      if [ -z "$OS_VER" ] || [ -z "$OS_REL" ]; then
        add lifecycle cur_os_lifecycle "IBM i release support" NOT_ASSESSED low \
            "not assessed — OS_VERSION or OS_RELEASE unreadable" \
            "The OS row was present, but OS_VERSION or OS_RELEASE was not a decimal digit string, so it is not graded." \
            "inspect SYSIBMADM.ENV_SYS_INFO OS_VERSION and OS_RELEASE."
      else
        REL="$OS_VER.$OS_REL"
        EOS=$(printf '%s\n' "$EOS_IBMI" | awk -F'|' -v r="$REL" '$1==r{print $2; exit}')
        if [ -z "$EOS" ]; then
          add lifecycle cur_os_lifecycle "IBM i release support" WARN med "$REL" \
              "Release $REL is not in the bundled reference data (vintage $DATA_VINTAGE)." \
              "check IBM Release life cycle for this IBM i release."
        elif [ "$EOS" = "SUPPORTED" ]; then
          add lifecycle cur_os_lifecycle "IBM i release support" PASS low "$REL — no announced end of support" \
              "This IBM i release is in active support and still receives security fixes." "n/a"
        else
          EOSJ=$(d2j "$EOS")
          if [ "$TODAY_J" -gt "$EOSJ" ]; then
            add lifecycle cur_os_lifecycle "IBM i release support" FAIL high "$REL — support ended $EOS" \
                "This IBM i release is past standard support — without an IBM i Service Extension, it no longer receives IBM security fixes, so newly disclosed CVEs remain open here." \
                "plan the upgrade to a supported IBM i release now; consider an IBM i Service Extension only as a bridge."
          elif [ $(( EOSJ - TODAY_J )) -le 365 ]; then
            add lifecycle cur_os_lifecycle "IBM i release support" WARN high "$REL — support ends $EOS" \
                "IBM standard support for this release ends within a year — after that, security fixes require an IBM i Service Extension." \
                "plan and schedule the upgrade to a supported IBM i release before $EOS."
          else
            add lifecycle cur_os_lifecycle "IBM i release support" PASS low "$REL — supported until $EOS" \
                "This IBM i release is in active support." "n/a"
          fi
        fi
      fi
    fi
  fi

  # cur_ptf_groups — IBM i PTF group currency
  # (SYSTOOLS.GROUP_PTF_CURRENCY).
  # Authority: CIS IBM i V7R5M0/V7R4M0 5.5.1 (L1).
  # No L2 rec. One finding. Calls ibmi_sql for compact
  # GRP rows. Does not call ibmi_cl / WRKPTFGRP / DSPPTF.
  # Does not query GROUP_PTF_INFO (would guess staleness).
  # Does not hardcode SF-numbers. Title class from the
  # view: SEC JAVA HTTP HIP OTH. CAST integer levels.
  # All current plus four classes is PASS. Behind,
  # pending IPL, not installed, or missing class is WARN.
  # PSP INFORMATION NOT AVAILABLE is NOT_ASSESSED (D-i8).
  PTF_RAW=$(ibmi_sql grpptfcur "SELECT 'GRP' CONCAT '|' CONCAT VARCHAR(TRIM(COALESCE(PTF_GROUP_ID, '')),7) CONCAT '|' CONCAT VARCHAR(TRIM(COALESCE(PTF_GROUP_CURRENCY, '')),46) CONCAT '|' CONCAT COALESCE(CAST(PTF_GROUP_LEVEL_INSTALLED AS VARCHAR(10)), '-') CONCAT '|' CONCAT COALESCE(CAST(PTF_GROUP_LEVEL_AVAILABLE AS VARCHAR(10)), '-') CONCAT '|' CONCAT VARCHAR(TRIM(COALESCE(PTF_GROUP_STATUS_ON_SYSTEM, '')),20) CONCAT '|' CONCAT CAST(CASE WHEN POSSTR(COALESCE(PTF_GROUP_TITLE, ''), 'Group Security') > 0 THEN 'SEC' WHEN POSSTR(COALESCE(PTF_GROUP_TITLE, ''), 'Group Hiper') > 0 THEN 'HIP' WHEN POSSTR(COALESCE(PTF_GROUP_TITLE, ''), 'HIPER') > 0 THEN 'HIP' WHEN POSSTR(COALESCE(PTF_GROUP_TITLE, ''), 'HTTP Server') > 0 THEN 'HTTP' WHEN POSSTR(COALESCE(PTF_GROUP_TITLE, ''), 'Java') > 0 THEN 'JAVA' ELSE 'OTH' END AS VARCHAR(4)) FROM SYSTOOLS.GROUP_PTF_CURRENCY")
  PTF_RC=$?
  if [ "$PTF_RC" -eq 0 ] && [ -z "$PTF_RAW" ]; then
    add patch cur_ptf_groups "PTF group currency" NOT_ASSESSED low \
        "not assessed — capture empty (rc=0)" \
        "The PTF group currency probe returned no pipe row, so PTF group currency cannot be graded." \
        "re-run the scan as the scan profile and confirm SYSTOOLS.GROUP_PTF_CURRENCY returns PTF_GROUP_CURRENCY rows. This scanner never applies PTFs." \
        "cis-l1"
  elif [ "$PTF_RC" -eq 1 ] && [ -z "$PTF_RAW" ]; then
    add patch cur_ptf_groups "PTF group currency" WARN med \
        "groups=0 current=0 behind=0 pending=0 missing=4" \
        "No PTF group currency rows were returned, so the security, HIPER, Java, and HTTP Server groups are not current on this partition." \
        "install the IBM i PTF groups and re-run. This scanner never applies PTFs." \
        "cis-l1"
  elif [ "$PTF_RC" -ne 0 ]; then
    add patch cur_ptf_groups "PTF group currency" NOT_ASSESSED low \
        "not assessed — capture failed (rc=$PTF_RC)" \
        "The PTF group currency probe did not yield a readable GROUP_PTF_CURRENCY dump, so PTF group currency cannot be graded." \
        "re-run the scan as the scan profile and confirm SYSTOOLS.GROUP_PTF_CURRENCY returns PTF_GROUP_CURRENCY rows. Job CCSID must not be 65535. This scanner never applies PTFs." \
        "cis-l1"
  else
    PTF_PARSE=$(printf '%s\n' "$PTF_RAW" | awk -F'|' '
      $1=="GRP" {
        id=$2; sub(/[ \t]+$/, "", id); sub(/^[ \t]+/, "", id)
        cur=$3; sub(/[ \t]+$/, "", cur); sub(/^[ \t]+/, "", cur)
        inst=$4; sub(/[ \t]+$/, "", inst); sub(/^[ \t]+/, "", inst)
        avail=$5; sub(/[ \t]+$/, "", avail); sub(/^[ \t]+/, "", avail)
        sts=$6; sub(/[ \t]+$/, "", sts); sub(/^[ \t]+/, "", sts)
        cls=$7; sub(/[ \t]+$/, "", cls); sub(/^[ \t]+/, "", cls)
        if (id !~ /^[A-Z][A-Z0-9]{6}$/) { junk=1; next }
        if (inst != "-" && inst !~ /^[0-9]+$/) { junk=1; next }
        if (avail != "-" && avail !~ /^[0-9]+$/) { junk=1; next }
        if (sts != "INSTALLED" && sts != "NOT INSTALLED") { junk=1; next }
        if (cls != "SEC" && cls != "JAVA" && cls != "HTTP" && cls != "HIP" && cls != "OTH") { junk=1; next }
        if (cur != "INSTALLED LEVEL IS CURRENT" && cur != "CURRENT AT THE NEXT IPL" && cur != "UPDATE AVAILABLE" && cur != "PSP INFORMATION NOT AVAILABLE") { junk=1; next }
        key=id
        val=cur "|" sts "|" cls
        if (seen[key] && seen[key] != val) { junk=1; next }
        if (seen[key]) next
        seen[key]=val
        n++
        if (cur == "PSP INFORMATION NOT AVAILABLE") psp=1
        else if (cur == "UPDATE AVAILABLE") b++
        else if (cur == "CURRENT AT THE NEXT IPL") p++
        else if (sts == "NOT INSTALLED") p++
        else c++
        if (cls=="SEC") has_sec=1
        if (cls=="JAVA") has_java=1
        if (cls=="HTTP") has_http=1
        if (cls=="HIP") has_hip=1
        next
      }
      END {
        if (junk) { print "JUNK"; exit }
        if (n+0 == 0) { print "JUNK"; exit }
        if (psp) { print "PSP"; exit }
        m = (has_sec?0:1)+(has_java?0:1)+(has_http?0:1)+(has_hip?0:1)
        printf "OK %d %d %d %d %d\n", n+0, c+0, b+0, p+0, m+0
      }')
    if [ "$PTF_PARSE" = "JUNK" ]; then
      add patch cur_ptf_groups "PTF group currency" NOT_ASSESSED low \
          "not assessed — GROUP_PTF_CURRENCY value unreadable" \
          "The PTF group currency dump was readable, but a row carried a group id, currency token, status, or title class that could not be graded." \
          "inspect SYSTOOLS.GROUP_PTF_CURRENCY PTF_GROUP_ID, PTF_GROUP_CURRENCY, PTF_GROUP_STATUS_ON_SYSTEM, and PTF_GROUP_TITLE." \
          "cis-l1"
    elif [ "$PTF_PARSE" = "PSP" ]; then
      add patch cur_ptf_groups "PTF group currency" NOT_ASSESSED low \
          "not assessed — PSP information not available" \
          "The PTF group currency probe could not reach IBM Preventive Service Planning, so PTF group currency cannot be graded." \
          "compare WRKPTFGRP installed levels against the IBM Preventive Service Planning group PTF page. This scanner never applies PTFs." \
          "cis-l1"
    else
      PTF_N=$(printf '%s\n' "$PTF_PARSE" | awk '{ print $2 }')
      PTF_C=$(printf '%s\n' "$PTF_PARSE" | awk '{ print $3 }')
      PTF_B=$(printf '%s\n' "$PTF_PARSE" | awk '{ print $4 }')
      PTF_P=$(printf '%s\n' "$PTF_PARSE" | awk '{ print $5 }')
      PTF_M=$(printf '%s\n' "$PTF_PARSE" | awk '{ print $6 }')
      if [ "$PTF_B" -eq 0 ] && [ "$PTF_P" -eq 0 ] && [ "$PTF_M" -eq 0 ]; then
        add patch cur_ptf_groups "PTF group currency" PASS low \
            "groups=$PTF_N current=$PTF_C behind=0 pending=0 missing=0" \
            "Every IBM i PTF group on this partition matches the IBM Preventive Service Planning level, including the security, HIPER, Java, and HTTP Server groups." \
            "n/a" \
            "cis-l1"
      else
        add patch cur_ptf_groups "PTF group currency" WARN med \
            "groups=$PTF_N current=$PTF_C behind=$PTF_B pending=$PTF_P missing=$PTF_M" \
            "One or more IBM i PTF groups are behind the IBM Preventive Service Planning level, pending the next IPL, not fully applied, or the security, HIPER, Java, or HTTP Server group is not present." \
            "download and apply the current PTF group levels. This scanner never applies PTFs." \
            "cis-l1"
      fi
    fi
  fi

  # ibmi_ssh_banner — IBM i OpenSSH Banner in sshd_config.
  # Authority: CIS IBM i V7R5M0/V7R4M0 5.4.2 (L1=approved Banner path).
  # No L2 rec. One finding. Calls ibmi_sql for IFS_OBJECT_STATISTICS on
  # OpenSSH etc and IFS_READ of sshd_config. Does not call ibmi_cl /
  # DSPF / EDTF / sshd / cat. Does not read the banner file.
  # Exact approved path is PASS. Commented/missing Banner (ship default)
  # or Banner none is FAIL.
  BANNER_PRES=$(ibmi_sql sshd_config_present "SELECT 'PRESENT' CONCAT '|' CONCAT VARCHAR(PATH_NAME,1024) CONCAT '|' CONCAT VARCHAR(OBJECT_TYPE,10) FROM TABLE(QSYS2.IFS_OBJECT_STATISTICS(START_PATH_NAME => '/QOpenSys/QIBM/UserData/SC1/OpenSSH/etc', SUBTREE_DIRECTORIES => 'NO', IGNORE_ERRORS => 'NO')) WHERE PATH_NAME = '/QOpenSys/QIBM/UserData/SC1/OpenSSH/etc/sshd_config'")
  BANNER_PRES_RC=$?
  if [ "$BANNER_PRES_RC" -ge 2 ]; then
    add security ibmi_ssh_banner "SSH banner configuration" NOT_ASSESSED low \
        "not assessed — capture failed (rc=$BANNER_PRES_RC)" \
        "The IFS_OBJECT_STATISTICS probe did not yield a readable OpenSSH etc listing, so the SSH Banner setting cannot be graded." \
        "re-run the scan as the scan profile and confirm QSYS2.IFS_OBJECT_STATISTICS can list /QOpenSys/QIBM/UserData/SC1/OpenSSH/etc. This scanner never changes SSH configuration." \
        "cis-l1"
  elif [ "$BANNER_PRES_RC" -eq 0 ] && [ -z "$BANNER_PRES" ]; then
    add security ibmi_ssh_banner "SSH banner configuration" NOT_ASSESSED low \
        "not assessed — capture empty (rc=0)" \
        "The IFS_OBJECT_STATISTICS probe returned no pipe row at rc 0, which is the swallowed mid-fetch-error signature, so the SSH Banner setting cannot be graded." \
        "re-run the scan as the scan profile and confirm QSYS2.IFS_OBJECT_STATISTICS can list /QOpenSys/QIBM/UserData/SC1/OpenSSH/etc. This scanner never changes SSH configuration." \
        "cis-l1"
  elif [ "$BANNER_PRES_RC" -eq 1 ] && [ -z "$BANNER_PRES" ]; then
    add security ibmi_ssh_banner "SSH banner configuration" NOT_ASSESSED low \
        "not assessed — sshd_config missing" \
        "The OpenSSH etc listing did not name sshd_config, so the SSH Banner setting cannot be graded." \
        "inspect /QOpenSys/QIBM/UserData/SC1/OpenSSH/etc/sshd_config and confirm the SSH server configuration file is present." \
        "cis-l1"
  else
    BANNER_PLINE=$(printf '%s\n' "$BANNER_PRES" | awk -F'|' '$1=="PRESENT" && $2=="/QOpenSys/QIBM/UserData/SC1/OpenSSH/etc/sshd_config"{n++; line=$0} END{if(n==1) print line}')
    if [ -z "$BANNER_PLINE" ]; then
      add security ibmi_ssh_banner "SSH banner configuration" NOT_ASSESSED low \
          "not assessed — sshd_config missing" \
          "The OpenSSH etc listing did not name sshd_config, so the SSH Banner setting cannot be graded." \
          "inspect /QOpenSys/QIBM/UserData/SC1/OpenSSH/etc/sshd_config and confirm the SSH server configuration file is present." \
          "cis-l1"
    else
      BANNER_TYPE=$(printf '%s\n' "$BANNER_PLINE" | awk -F'|' '{ v=$3; sub(/[ \t]+$/, "", v); print v }')
      if [ "$BANNER_TYPE" != "*STMF" ]; then
        add security ibmi_ssh_banner "SSH banner configuration" NOT_ASSESSED low \
            "not assessed — sshd_config is not a stream file" \
            "The OpenSSH etc listing named sshd_config, but the object type was not *STMF, so the SSH Banner setting cannot be graded." \
            "inspect /QOpenSys/QIBM/UserData/SC1/OpenSSH/etc/sshd_config and confirm it is an IFS stream file." \
            "cis-l1"
      else
        BANNER_RAW=$(ibmi_sql sshd_config "SELECT 'LINE' CONCAT '|' CONCAT VARCHAR(LINE,1024) FROM TABLE(QSYS2.IFS_READ(PATH_NAME => '/QOpenSys/QIBM/UserData/SC1/OpenSSH/etc/sshd_config', IGNORE_ERRORS => 'NO'))")
        BANNER_RC=$?
        if [ "$BANNER_RC" -ge 2 ]; then
          add security ibmi_ssh_banner "SSH banner configuration" NOT_ASSESSED low \
              "not assessed — capture failed (rc=$BANNER_RC)" \
              "The IFS_READ probe did not yield a readable sshd_config, so the SSH Banner setting cannot be graded." \
              "re-run the scan as the scan profile and confirm the scan profile has *R on /QOpenSys/QIBM/UserData/SC1/OpenSSH/etc/sshd_config. This scanner never changes SSH configuration." \
              "cis-l1"
        elif [ "$BANNER_RC" -eq 0 ] && [ -z "$BANNER_RAW" ]; then
          add security ibmi_ssh_banner "SSH banner configuration" NOT_ASSESSED low \
              "not assessed — capture empty (rc=0)" \
              "The IFS_READ probe returned no pipe row at rc 0, which is the swallowed mid-fetch-error signature, so the SSH Banner setting cannot be graded." \
              "re-run the scan as the scan profile and confirm the scan profile has *R on /QOpenSys/QIBM/UserData/SC1/OpenSSH/etc/sshd_config. This scanner never changes SSH configuration." \
              "cis-l1"
        elif [ "$BANNER_RC" -eq 1 ] && [ -z "$BANNER_RAW" ]; then
          add security ibmi_ssh_banner "SSH banner configuration" FAIL high \
              "Banner not set" \
              "sshd_config has no uncommented Banner path, so SSH does not display a pre-authentication warning message." \
              "set Banner to /QOpenSys/QIBM/UserData/SC1/OpenSSH/etc/ssh_banner in sshd_config and recycle sshd. This scanner never changes SSH configuration." \
              "cis-l1"
        else
          BANNER_VAL=$(printf '%s\n' "$BANNER_RAW" | awk '
            function trim(s) {
              sub(/\r$/, "", s)
              sub(/^[ \t]+/, "", s)
              sub(/[ \t]+$/, "", s)
              return s
            }
            {
              raw = $0
              sub(/^LINE\|/, "", raw)
              raw = trim(raw)
              if (raw == "" || raw ~ /^#/) next
              low = tolower(raw)
              if (low ~ /^banner([ \t]|=|$)/) {
                if (n == 0) {
                  val = raw
                  sub(/^[Bb][Aa][Nn][Nn][Ee][Rr][ \t]*=?[ \t]*/, "", val)
                  val = trim(val)
                  value = val
                }
                n++
              }
            }
            END {
              if (n+0 == 0) print "__UNSET__"
              else print value
            }')
          if [ "$BANNER_VAL" = "__UNSET__" ] || [ -z "$BANNER_VAL" ]; then
            add security ibmi_ssh_banner "SSH banner configuration" FAIL high \
                "Banner not set" \
                "sshd_config has no uncommented Banner path, so SSH does not display a pre-authentication warning message." \
                "set Banner to /QOpenSys/QIBM/UserData/SC1/OpenSSH/etc/ssh_banner in sshd_config and recycle sshd. This scanner never changes SSH configuration." \
                "cis-l1"
          elif [ "$BANNER_VAL" = "none" ] || [ "$BANNER_VAL" = "None" ] || [ "$BANNER_VAL" = "NONE" ]; then
            add security ibmi_ssh_banner "SSH banner configuration" FAIL high \
                "Banner=none" \
                "sshd_config sets Banner to none, so SSH does not display a pre-authentication warning message." \
                "set Banner to /QOpenSys/QIBM/UserData/SC1/OpenSSH/etc/ssh_banner in sshd_config and recycle sshd. This scanner never changes SSH configuration." \
                "cis-l1"
          elif [ "$BANNER_VAL" = "/QOpenSys/QIBM/UserData/SC1/OpenSSH/etc/ssh_banner" ]; then
            add security ibmi_ssh_banner "SSH banner configuration" PASS low \
                "Banner=/QOpenSys/QIBM/UserData/SC1/OpenSSH/etc/ssh_banner" \
                "sshd_config sets Banner to the approved SSH banner path, so SSH can display a pre-authentication warning message." \
                "n/a" \
                "cis-l1"
          else
            add security ibmi_ssh_banner "SSH banner configuration" FAIL high \
                "Banner is not the approved SSH banner path" \
                "sshd_config sets Banner to a path other than the approved SSH banner file, so the pre-authentication warning is not the configured standard banner." \
                "set Banner to /QOpenSys/QIBM/UserData/SC1/OpenSSH/etc/ssh_banner in sshd_config and recycle sshd. This scanner never changes SSH configuration." \
                "cis-l1"
          fi
        fi
      fi
    fi
  fi

  # ibmi_ssh_ciphers — IBM i OpenSSH Ciphers in sshd_config.
  # Authority: CIS IBM i V7R5M0/V7R4M0 5.4.7
  # (L1=Ciphers aes256-ctr,aes192-ctr,aes128-ctr).
  # No L2 rec. One finding. Calls ibmi_sql for IFS_READ_UTF8 of UserData
  # sshd_config. Does not call ibmi_cl / DSPF / EDTF / sshd / NETSTAT.
  # Does not SELECT Banner, AllowUsers, Protocol, MACs, or MaxAuthTries.
  # Exact aes256-ctr,aes192-ctr,aes128-ctr is PASS. Any other list
  # (including CBC/3DES extra or reverse order) or absent is FAIL.
  CIPH_RAW=$(ibmi_sql sshd_cfg "SELECT 'CIPHERS' CONCAT '|' CONCAT VARCHAR(COALESCE(TRIM(LINE),''),256) FROM TABLE(QSYS2.IFS_READ_UTF8(PATH_NAME => '/QOpenSys/QIBM/UserData/SC1/OpenSSH/etc/sshd_config', IGNORE_ERRORS => 'NO')) WHERE UPPER(TRIM(LINE)) = 'CIPHERS' OR UPPER(TRIM(LINE)) LIKE 'CIPHERS %' OR UPPER(TRIM(LINE)) LIKE 'CIPHERS=%'")
  CIPH_RC=$?
  if [ "$CIPH_RC" -ge 2 ]; then
    add security ibmi_ssh_ciphers "SSH cipher list" NOT_ASSESSED low \
        "not assessed — capture failed (rc=$CIPH_RC)" \
        "The sshd_config probe did not yield a readable Ciphers line, so the SSH cipher list cannot be graded." \
        "re-run the scan as the scan profile and confirm QSYS2.IFS_READ_UTF8 returns the UserData sshd_config. This scanner never edits sshd_config." \
        "cis-l1"
  elif [ "$CIPH_RC" -eq 0 ] && [ -z "$CIPH_RAW" ]; then
    add security ibmi_ssh_ciphers "SSH cipher list" NOT_ASSESSED low \
        "not assessed — capture empty (rc=0)" \
        "The sshd_config probe returned no pipe row at rc 0, which is the swallowed mid-fetch-error signature, so the SSH cipher list cannot be graded." \
        "re-run the scan as the scan profile and confirm QSYS2.IFS_READ_UTF8 returns the UserData sshd_config. This scanner never edits sshd_config." \
        "cis-l1"
  elif [ "$CIPH_RC" -eq 1 ] && [ -z "$CIPH_RAW" ]; then
    add security ibmi_ssh_ciphers "SSH cipher list" FAIL high \
        "Ciphers=(absent)" \
        "SSH Ciphers is not explicitly set to aes256-ctr,aes192-ctr,aes128-ctr, so the server can offer weaker ciphers." \
        "set Ciphers aes256-ctr,aes192-ctr,aes128-ctr in /QOpenSys/QIBM/UserData/SC1/OpenSSH/etc/sshd_config and recycle the SSH server. This scanner never edits sshd_config." \
        "cis-l1"
  else
    CIPH_LINE=$(printf '%s\n' "$CIPH_RAW" | awk -F'|' '$1=="CIPHERS"{n++; line=$0} END{if(n==1) print line}')
    if [ -z "$CIPH_LINE" ]; then
      CIPH_CNT=$(printf '%s\n' "$CIPH_RAW" | awk -F'|' '$1=="CIPHERS"{n++} END{print n+0}')
      if [ "$CIPH_CNT" -eq 0 ]; then
        add security ibmi_ssh_ciphers "SSH cipher list" FAIL high \
            "Ciphers=(absent)" \
            "SSH Ciphers is not explicitly set to aes256-ctr,aes192-ctr,aes128-ctr, so the server can offer weaker ciphers." \
            "set Ciphers aes256-ctr,aes192-ctr,aes128-ctr in /QOpenSys/QIBM/UserData/SC1/OpenSSH/etc/sshd_config and recycle the SSH server. This scanner never edits sshd_config." \
            "cis-l1"
      else
        add security ibmi_ssh_ciphers "SSH cipher list" NOT_ASSESSED low \
            "not assessed — Ciphers row missing or not unique in sshd_config" \
            "The sshd_config dump was readable, but it did not contain exactly one uncommented Ciphers line, so the value cannot be graded." \
            "inspect /QOpenSys/QIBM/UserData/SC1/OpenSSH/etc/sshd_config for a single uncommented Ciphers line." \
            "cis-l1"
      fi
    else
      CIPH_VAL=$(printf '%s\n' "$CIPH_LINE" | awk -F'|' '{
        v=$2
        sub(/[ \t]+$/, "", v)
        sub(/#.*$/, "", v)
        sub(/[ \t]+$/, "", v)
        low = tolower(v)
        if (low !~ /^ciphers([ \t]|=|$)/) { print ""; exit }
        sub(/^[Cc][Ii][Pp][Hh][Ee][Rr][Ss][ \t]*=?[ \t]*/, "", v)
        sub(/^[ \t]+/, "", v)
        sub(/[ \t]+$/, "", v)
        print v
      }')
      if [ -z "$CIPH_VAL" ]; then
        add security ibmi_ssh_ciphers "SSH cipher list" NOT_ASSESSED low \
            "not assessed — Ciphers value unreadable" \
            "The Ciphers line was present, but the value was empty, so it is not graded." \
            "inspect Ciphers on /QOpenSys/QIBM/UserData/SC1/OpenSSH/etc/sshd_config." \
            "cis-l1"
      elif [ "$CIPH_VAL" = "aes256-ctr,aes192-ctr,aes128-ctr" ]; then
        add security ibmi_ssh_ciphers "SSH cipher list" PASS low \
            "Ciphers=aes256-ctr,aes192-ctr,aes128-ctr" \
            "sshd_config restricts SSH ciphers to aes256-ctr, aes192-ctr, and aes128-ctr, so CBC and 3DES ciphers are not offered." \
            "n/a" \
            "cis-l1"
      else
        add security ibmi_ssh_ciphers "SSH cipher list" FAIL high \
            "Ciphers=$CIPH_VAL" \
            "sshd_config does not restrict SSH ciphers to aes256-ctr, aes192-ctr, and aes128-ctr, so weaker ciphers can be offered." \
            "set Ciphers aes256-ctr,aes192-ctr,aes128-ctr in /QOpenSys/QIBM/UserData/SC1/OpenSSH/etc/sshd_config and recycle the SSH server. This scanner never edits sshd_config." \
            "cis-l1"
      fi
    fi
  fi

  # ibmi_ssh_maxauthtries — IBM i OpenSSH MaxAuthTries
  # (sshd_config MaxAuthTries).
  # Authority: CIS IBM i V7R5M0/V7R4M0 5.4.5 (L1=MaxAuthTries 4 or less).
  # No L2 rec. One finding. Calls ibmi_sql for IFS_READ_UTF8 of UserData
  # sshd_config. Does not call ibmi_cl / DSPF / EDTF / sshd / NETSTAT.
  # Does not SELECT Banner, AllowUsers, MaxStartups, or Protocol.
  # Integer 0-4 inclusive is PASS. Integer >4 (including 6) or absent is FAIL.
  MAT_RAW=$(ibmi_sql sshd_cfg "SELECT 'MAXAUTH' CONCAT '|' CONCAT VARCHAR(COALESCE(TRIM(LINE),''),64) FROM TABLE(QSYS2.IFS_READ_UTF8(PATH_NAME => '/QOpenSys/QIBM/UserData/SC1/OpenSSH/etc/sshd_config', IGNORE_ERRORS => 'NO')) WHERE UPPER(TRIM(REPLACE(LINE, CHR(9), ' '))) = 'MAXAUTHTRIES' OR UPPER(TRIM(REPLACE(LINE, CHR(9), ' '))) LIKE 'MAXAUTHTRIES %' OR UPPER(TRIM(REPLACE(LINE, CHR(9), ' '))) LIKE 'MAXAUTHTRIES=%'")
  MAT_RC=$?
  if [ "$MAT_RC" -ge 2 ]; then
    add security ibmi_ssh_maxauthtries "SSH MaxAuthTries" NOT_ASSESSED low \
        "not assessed — capture failed (rc=$MAT_RC)" \
        "The sshd_config probe did not yield a readable MaxAuthTries line, so SSH authentication-attempt limit cannot be graded." \
        "re-run the scan as the scan profile and confirm QSYS2.IFS_READ_UTF8 returns the UserData sshd_config. This scanner never edits sshd_config." \
        "cis-l1"
  elif [ "$MAT_RC" -eq 0 ] && [ -z "$MAT_RAW" ]; then
    add security ibmi_ssh_maxauthtries "SSH MaxAuthTries" NOT_ASSESSED low \
        "not assessed — capture empty (rc=0)" \
        "The sshd_config probe returned no pipe row at rc 0, which is the swallowed mid-fetch-error signature, so SSH authentication-attempt limit cannot be graded." \
        "re-run the scan as the scan profile and confirm QSYS2.IFS_READ_UTF8 returns the UserData sshd_config. This scanner never edits sshd_config." \
        "cis-l1"
  elif [ "$MAT_RC" -eq 1 ] && [ -z "$MAT_RAW" ]; then
    add security ibmi_ssh_maxauthtries "SSH MaxAuthTries" FAIL high \
        "MaxAuthTries=(absent)" \
        "SSH MaxAuthTries is not explicitly set to 4 or less, so the server can allow more than 4 authentication attempts per connection." \
        "set MaxAuthTries 4 or less in /QOpenSys/QIBM/UserData/SC1/OpenSSH/etc/sshd_config and recycle the SSH server. This scanner never edits sshd_config." \
        "cis-l1"
  else
    MAT_LINE=$(printf '%s\n' "$MAT_RAW" | awk -F'|' '$1=="MAXAUTH"{n++; line=$0} END{if(n==1) print line}')
    if [ -z "$MAT_LINE" ]; then
      MAT_CNT=$(printf '%s\n' "$MAT_RAW" | awk -F'|' '$1=="MAXAUTH"{n++} END{print n+0}')
      if [ "$MAT_CNT" -eq 0 ]; then
        add security ibmi_ssh_maxauthtries "SSH MaxAuthTries" FAIL high \
            "MaxAuthTries=(absent)" \
            "SSH MaxAuthTries is not explicitly set to 4 or less, so the server can allow more than 4 authentication attempts per connection." \
            "set MaxAuthTries 4 or less in /QOpenSys/QIBM/UserData/SC1/OpenSSH/etc/sshd_config and recycle the SSH server. This scanner never edits sshd_config." \
            "cis-l1"
      else
        add security ibmi_ssh_maxauthtries "SSH MaxAuthTries" NOT_ASSESSED low \
            "not assessed — MaxAuthTries row missing or not unique in sshd_config" \
            "The sshd_config dump was readable, but it did not contain exactly one uncommented MaxAuthTries line, so the value cannot be graded." \
            "inspect /QOpenSys/QIBM/UserData/SC1/OpenSSH/etc/sshd_config for a single uncommented MaxAuthTries line." \
            "cis-l1"
      fi
    else
      MAT_VAL=$(printf '%s\n' "$MAT_LINE" | awk -F'|' '{
        v=$2
        sub(/[ \t]+$/, "", v)
        sub(/#.*$/, "", v)
        sub(/[ \t]+$/, "", v)
        low = tolower(v)
        if (low !~ /^maxauthtries([ \t]|=|$)/) { print ""; exit }
        sub(/^[Mm][Aa][Xx][Aa][Uu][Tt][Hh][Tt][Rr][Ii][Ee][Ss][ \t]*=?[ \t]*/, "", v)
        sub(/^[ \t]+/, "", v)
        sub(/[ \t]+$/, "", v)
        n=split(v, a, /[ \t]+/)
        if (n != 1) { print ""; exit }
        print a[1]
      }')
      if [ -z "$MAT_VAL" ]; then
        add security ibmi_ssh_maxauthtries "SSH MaxAuthTries" NOT_ASSESSED low \
            "not assessed — MaxAuthTries value unreadable" \
            "The MaxAuthTries line was present, but the value was empty, so it is not graded." \
            "inspect MaxAuthTries on /QOpenSys/QIBM/UserData/SC1/OpenSSH/etc/sshd_config." \
            "cis-l1"
      else
        MAT_N=$(printf '%s\n' "$MAT_VAL" | awk '/^[0-9]+$/{ if ($0 ~ /^0+$/) print 0; else { sub(/^0+/,""); print } }')
        if [ -z "$MAT_N" ]; then
          add security ibmi_ssh_maxauthtries "SSH MaxAuthTries" NOT_ASSESSED low \
              "not assessed — MaxAuthTries value unreadable" \
              "The MaxAuthTries line was present, but the value was not an integer, so it is not graded." \
              "inspect MaxAuthTries on /QOpenSys/QIBM/UserData/SC1/OpenSSH/etc/sshd_config." \
              "cis-l1"
        else
          case "$MAT_N" in
            0|1|2|3|4)
              add security ibmi_ssh_maxauthtries "SSH MaxAuthTries" PASS low \
                  "MaxAuthTries=$MAT_N" \
                  "MaxAuthTries is $MAT_N, so one SSH connection is limited to 4 or fewer authentication attempts." \
                  "n/a" \
                  "cis-l1"
              ;;
            *)
              add security ibmi_ssh_maxauthtries "SSH MaxAuthTries" FAIL high \
                  "MaxAuthTries=$MAT_N" \
                  "MaxAuthTries is $MAT_N, so one SSH connection allows more than 4 authentication attempts." \
                  "set MaxAuthTries 4 or less in /QOpenSys/QIBM/UserData/SC1/OpenSSH/etc/sshd_config and recycle the SSH server. This scanner never edits sshd_config." \
                  "cis-l1"
              ;;
          esac
        fi
      fi
    fi
  fi

# net_ddm_sna — IBM i QAPPNRMT SECURELOC (DDM SNA).
# Authority: CIS IBM i V7R5M0/V7R4M0 5.2.2 (L1=*VFYENCPWD). No L2 rec.
# One finding. Pre-probes QSYS2.OBJECT_STATISTICS for CFGL QAPPNRMT,
# then calls ibmi_cl for DSPCFGL CFGL(QAPPNRMT) only when the list exists.
# Does not call DSPNETA / WRKCFGL / CHGCFGL.
# Does not copy location names or System: banners into observed.
# Presence is a COUNT(*) row: rc 0 with count 0 is determinate absence
# (NOT_APPLICABLE); any nonzero rc is a probe error (NOT_ASSESSED).
# DSPCFGL failure is NOT_ASSESSED; not-found (CPF260F) is not graded as
# NOT_APPLICABLE because ibmi_cl discards stderr and the escape text never
# reaches SNA_RAW.
# Exact *VFYENCPWD on every entry is PASS. Exact *YES or *NO is FAIL.
CFGL_RAW=$(ibmi_sql cfgl_qappnrmt "SELECT 'QAPPNRMT' CONCAT '|' CONCAT VARCHAR(COUNT(*)) FROM TABLE(QSYS2.OBJECT_STATISTICS('QSYS','CFGL')) WHERE OBJNAME='QAPPNRMT'")
CFGL_RC=$?
if [ "$CFGL_RC" -ne 0 ]; then
  add security net_ddm_sna "DDM SNA secure location" NOT_ASSESSED low \
      "not assessed — capture failed (rc=$CFGL_RC)" \
      "The OBJECT_STATISTICS probe did not yield a readable QAPPNRMT presence row, so DDM SNA SECURELOC cannot be graded." \
      "re-run the scan as the scan profile and confirm QSYS2.OBJECT_STATISTICS can list QSYS CFGL objects. This scanner never changes configuration lists." \
      "cis-l1"
elif [ -z "$CFGL_RAW" ]; then
  add security net_ddm_sna "DDM SNA secure location" NOT_ASSESSED low \
      "not assessed — capture empty (rc=0)" \
      "The OBJECT_STATISTICS probe returned no pipe row, so DDM SNA SECURELOC cannot be graded." \
      "re-run the scan as the scan profile and confirm QSYS2.OBJECT_STATISTICS can list QSYS CFGL objects. This scanner never changes configuration lists." \
      "cis-l1"
else
  CFGL_N=$(printf '%s\n' "$CFGL_RAW" | awk -F'|' '$1 == "QAPPNRMT" { gsub(/[ \t]+$/, "", $2); n=$2 } END { print n+0 }')
  if [ "$CFGL_N" -eq 0 ]; then
    add security net_ddm_sna "DDM SNA secure location" NOT_APPLICABLE low \
        "QAPPNRMT not found" \
        "QAPPNRMT is absent, so this system is not configured for DDM over SNA and SECURELOC is not graded." \
        "n/a" \
        "cis-l1"
  else
    SNA_RAW=$(ibmi_cl qappnrmt "DSPCFGL CFGL(QAPPNRMT)")
    SNA_RC=$?
    if [ "$SNA_RC" -ne 0 ]; then
      add security net_ddm_sna "DDM SNA secure location" NOT_ASSESSED low \
          "not assessed — capture failed (rc=$SNA_RC)" \
          "The DSPCFGL probe did not yield a readable QAPPNRMT dump, so DDM SNA SECURELOC cannot be graded." \
          "re-run the scan as the scan profile and confirm DSPCFGL CFGL(QAPPNRMT) returns the APPN remote configuration list or CPF260F. This scanner never changes configuration lists." \
          "cis-l1"
    elif [ -z "$SNA_RAW" ]; then
      add security net_ddm_sna "DDM SNA secure location" NOT_ASSESSED low \
          "not assessed — capture empty (rc=0)" \
          "The DSPCFGL probe returned no text, so DDM SNA SECURELOC cannot be graded." \
          "re-run the scan as the scan profile and confirm DSPCFGL CFGL(QAPPNRMT) returns the APPN remote configuration list or CPF260F. This scanner never changes configuration lists." \
          "cis-l1"
    else
      SNA_TOKS=$(printf '%s\n' "$SNA_RAW" | awk '
          tolower($0) ~ /secure loc/ && index($0, ":") > 0 {
            v = $0
            sub(/^[^:]*:[ \t]*/, "", v)
            sub(/[ \t\r]+$/, "", v)
            if (v ~ /^\*[A-Z][A-Z0-9]*$/) print v
          }')
      SNA_N=$(printf '%s\n' "$SNA_TOKS" | awk 'NF { c++ } END { print c+0 }')
      SNA_UNIQ=$(printf '%s\n' "$SNA_TOKS" | awk 'NF && !seen[$0]++ { u = (u == "" ? $0 : u "," $0) } END { print u }')
      SNA_JUNK=$(printf '%s\n' "$SNA_TOKS" | awk 'NF && $0 != "*YES" && $0 != "*NO" && $0 != "*VFYENCPWD" { j=1 } END { if (j) print 1 }')
      SNA_ISLIST=$(printf '%s\n' "$SNA_RAW" | awk '/\*APPNRMT/ { h=1 } END { if (h) print 1 }')
      SNA_HASROW=$(printf '%s\n' "$SNA_RAW" | awk 'tolower($0) ~ /remote location/ { h=1 } END { if (h) print 1 }')
      if [ -n "$SNA_JUNK" ]; then
        add security net_ddm_sna "DDM SNA secure location" NOT_ASSESSED low \
            "not assessed — SECURELOC value unreadable" \
            "The DSPCFGL dump was readable, but a remote-location row carried a SECURELOC token that was not *YES, *NO, or *VFYENCPWD, so the list is not graded." \
            "inspect DSPCFGL CFGL(QAPPNRMT) Secure Loc values." \
            "cis-l1"
      elif [ "$SNA_N" -gt 0 ]; then
        if [ "$SNA_UNIQ" = "*VFYENCPWD" ]; then
          add security net_ddm_sna "DDM SNA secure location" PASS low \
              "QAPPNRMT entries=$SNA_N SECURELOC=*VFYENCPWD" \
              "Every QAPPNRMT remote-location entry sets SECURELOC to *VFYENCPWD, so SNA DDM program-start requests must verify the same user ID and encrypted password on both systems." \
              "n/a" \
              "cis-l1"
        else
          add security net_ddm_sna "DDM SNA secure location" FAIL high \
              "QAPPNRMT entries=$SNA_N SECURELOC=$SNA_UNIQ" \
              "One or more QAPPNRMT remote-location entries do not set SECURELOC to *VFYENCPWD, so SNA DDM program-start requests can run without verifying an encrypted password on both systems." \
              "set every QAPPNRMT Secure Loc value to *VFYENCPWD using WRKCFGL CFGL(QAPPNRMT). This scanner never changes configuration lists." \
              "cis-l1"
        fi
      elif [ -n "$SNA_ISLIST" ] && [ -z "$SNA_HASROW" ]; then
        add security net_ddm_sna "DDM SNA secure location" PASS low \
            "QAPPNRMT entries=0" \
            "QAPPNRMT exists and has no remote-location entries, so there is no SNA DDM remote location with a weak SECURELOC." \
            "n/a" \
            "cis-l1"
      else
        add security net_ddm_sna "DDM SNA secure location" NOT_ASSESSED low \
            "not assessed — QAPPNRMT SECURELOC rows missing in DSPCFGL dump" \
            "The DSPCFGL dump was readable, but it did not establish that QAPPNRMT is a zero-entry list or carry a readable SECURELOC value, so DDM SNA SECURELOC cannot be graded." \
            "inspect DSPCFGL CFGL(QAPPNRMT)." \
            "cis-l1"
      fi
    fi
  fi
fi

  # net_ddm_tcp — IBM i DDM TCP/IP attributes (CHGDDMTCPA PWDRQD/ENCALG).
  # Authority: CIS IBM i V7R5M0/V7R4M0 5.2.3 (L1=*USRENCPWD+*AES) / 5.2.4 (L2=*ENCUSRPWD+*AES).
  # One finding. Calls ibmi_sql for QSYS.QADBXRDBD *LOCAL LAND decode.
  # Does not call ibmi_cl / CHGDDMTCPA / DSPRDBDIRE. Does not SELECT RDB name.
  # *USRENCPWD or *ENCUSRPWD with *AES is PASS. *USRIDPWD (IBM default) is FAIL.
  DDMTCP_RAW=$(ibmi_sql qadbxrdbd "SELECT 'DDM_TCP' CONCAT '|' CONCAT VARCHAR(CASE LAND(DBXRSEC, X'E0') WHEN X'00' THEN '*USRID' WHEN X'20' THEN '*VLDONLY' WHEN X'40' THEN '*USRIDPWD' WHEN X'C0' THEN '*USRENCPWD' WHEN X'80' THEN '*ENCUSRPWD' WHEN X'A0' THEN '*KERBEROS' ELSE '*UNKNOWN' END, 11) CONCAT '|' CONCAT VARCHAR(CASE WHEN LAND(DBTFLGS, X'01') = X'01' THEN '*AES' ELSE '*DES' END, 4) FROM QSYS.QADBXRDBD WHERE DBXRMTN = '*LOCAL'")
  DDMTCP_RC=$?
  if [ "$DDMTCP_RC" -ne 0 ]; then
    add security net_ddm_tcp "DDM TCP/IP attributes" NOT_ASSESSED low \
        "not assessed — capture failed (rc=$DDMTCP_RC)" \
        "The QADBXRDBD probe did not yield a readable *LOCAL DDM TCP/IP attribute row, so PWDRQD and ENCALG cannot be graded." \
        "re-run the scan as the scan profile and confirm QSYS.QADBXRDBD returns the *LOCAL row. This scanner never changes DDM TCP/IP attributes." \
        "cis-l1 cis-l2"
  elif [ -z "$DDMTCP_RAW" ]; then
    add security net_ddm_tcp "DDM TCP/IP attributes" NOT_ASSESSED low \
        "not assessed — capture empty (rc=0)" \
        "The QADBXRDBD probe returned no pipe row, so PWDRQD and ENCALG cannot be graded." \
        "re-run the scan as the scan profile and confirm QSYS.QADBXRDBD returns the *LOCAL row. This scanner never changes DDM TCP/IP attributes." \
        "cis-l1 cis-l2"
  else
    DDMTCP_LINE=$(printf '%s\n' "$DDMTCP_RAW" | awk -F'|' '$1=="DDM_TCP"{n++; line=$0} END{if(n==1) print line}')
    if [ -z "$DDMTCP_LINE" ]; then
      add security net_ddm_tcp "DDM TCP/IP attributes" NOT_ASSESSED low \
          "not assessed — DDM_TCP row missing or not unique in QADBXRDBD" \
          "The QADBXRDBD dump was readable, but it did not contain exactly one DDM_TCP row, so the values cannot be graded." \
          "inspect QSYS.QADBXRDBD for DBXRMTN = *LOCAL." \
          "cis-l1 cis-l2"
    else
      DDMTCP_AUT=$(printf '%s\n' "$DDMTCP_LINE" | awk -F'|' '{ v=$2; sub(/[ \t]+$/, "", v); print v }')
      DDMTCP_ENC=$(printf '%s\n' "$DDMTCP_LINE" | awk -F'|' '{ v=$3; sub(/[ \t]+$/, "", v); print v }')
      if [ -z "$DDMTCP_AUT" ] || [ -z "$DDMTCP_ENC" ]; then
        add security net_ddm_tcp "DDM TCP/IP attributes" NOT_ASSESSED low \
            "not assessed — DDM TCP/IP attribute value unreadable" \
            "The DDM_TCP row was present, but a catalog value was empty, so it is not graded." \
            "inspect the *LOCAL row of QSYS.QADBXRDBD and CHGDDMTCPA." \
            "cis-l1 cis-l2"
      elif { [ "$DDMTCP_AUT" = "*USRENCPWD" ] || [ "$DDMTCP_AUT" = "*ENCUSRPWD" ]; } && [ "$DDMTCP_ENC" = "*AES" ]; then
        add security net_ddm_tcp "DDM TCP/IP attributes" PASS low \
            "PWDRQD=$DDMTCP_AUT ENCALG=$DDMTCP_ENC" \
            "DDM TCP/IP lowest authentication requires an encrypted password and lowest encryption is AES, so a DDM connection cannot send a clear-text password or use DES." \
            "n/a" \
            "cis-l1 cis-l2"
      elif { [ "$DDMTCP_AUT" = "*USRID" ] || [ "$DDMTCP_AUT" = "*VLDONLY" ] || [ "$DDMTCP_AUT" = "*USRIDPWD" ]; } && { [ "$DDMTCP_ENC" = "*AES" ] || [ "$DDMTCP_ENC" = "*DES" ]; }; then
        add security net_ddm_tcp "DDM TCP/IP attributes" FAIL high \
            "PWDRQD=$DDMTCP_AUT ENCALG=$DDMTCP_ENC" \
            "DDM TCP/IP lowest authentication does not require an encrypted password, so a DDM connection can authenticate with no password or a clear-text password." \
            "set DDM TCP/IP attributes to PWDRQD(*USRENCPWD) ENCALG(*AES) using CHGDDMTCPA PWDRQD(*USRENCPWD) ENCALG(*AES). This scanner never changes DDM TCP/IP attributes." \
            "cis-l1 cis-l2"
      elif { [ "$DDMTCP_AUT" = "*USRENCPWD" ] || [ "$DDMTCP_AUT" = "*ENCUSRPWD" ]; } && [ "$DDMTCP_ENC" = "*DES" ]; then
        add security net_ddm_tcp "DDM TCP/IP attributes" FAIL high \
            "PWDRQD=$DDMTCP_AUT ENCALG=$DDMTCP_ENC" \
            "DDM TCP/IP lowest encryption is DES, so a DDM connection can use a weaker algorithm than AES." \
            "set DDM TCP/IP attributes to PWDRQD(*USRENCPWD) ENCALG(*AES) using CHGDDMTCPA PWDRQD(*USRENCPWD) ENCALG(*AES). This scanner never changes DDM TCP/IP attributes." \
            "cis-l1 cis-l2"
      else
        add security net_ddm_tcp "DDM TCP/IP attributes" NOT_ASSESSED low \
            "not assessed — PWDRQD=$DDMTCP_AUT ENCALG=$DDMTCP_ENC is not a pair this check grades" \
            "The DDM_TCP row was present, but the catalog values were not a documented PWDRQD/ENCALG pair that this check grades, so they are not graded." \
            "review PWDRQD and ENCALG against CIS 5.2.3/5.2.4 manually; this pair is outside the set this check grades." \
            "cis-l1 cis-l2"
      fi
    fi
  fi

  # net_exit_points — IBM i host-server exit program registration.
  # Authority: CIS IBM i V7R5M0/V7R4M0 5.2.7 (L1=EXIT_PROGRAMS>0
  # on every REGISTERED=YES CIS-prefixed name). No L2 rec.
  # One finding. Calls ibmi_sql for EXIT_POINT_INFO.
  # Does not call ibmi_cl / WRKREGINF / ADDEXITPGM.
  # Does not SELECT EXIT_PROGRAM_INFO (program names are shop-specific).
  # Name grain: unused empty formats do not uncover a name that has a program.
  # Exact REGISTERED=YES with summed programs>0 on every name is PASS.
  # Any YES name with summed programs=0 is FAIL (IBM default).
  EP_RAW=$(ibmi_sql exit_point "SELECT 'EXIT' CONCAT '|' CONCAT VARCHAR(TRIM(EXIT_POINT_NAME),20) CONCAT '|' CONCAT VARCHAR(TRIM(EXIT_POINT_FORMAT),8) CONCAT '|' CONCAT VARCHAR(REGISTERED,3) CONCAT '|' CONCAT TRIM(CHAR(EXIT_PROGRAMS)) FROM QSYS2.EXIT_POINT_INFO WHERE EXIT_POINT_NAME LIKE 'QIBM_QTMF%' OR EXIT_POINT_NAME LIKE 'QIBM_QZRC_RMT%' OR EXIT_POINT_NAME LIKE 'QIBM_QMF_MESSAGE%' OR EXIT_POINT_NAME LIKE 'QIBM_QZDA%' OR EXIT_POINT_NAME LIKE 'QIBM_QZRC%' OR EXIT_POINT_NAME LIKE 'QIBM_QDB_OPEN%' OR EXIT_POINT_NAME LIKE 'QIBM_QDB_CLOSE%' OR EXIT_POINT_NAME LIKE 'QIBM_QZHQ_DATA_QUEUE%' OR EXIT_POINT_NAME LIKE 'QIBM_QJO_DLT_JRNRCV%' OR EXIT_POINT_NAME LIKE 'QIBM_QNPS_ENTRY%' OR EXIT_POINT_NAME LIKE 'QIBM_QNPS_SPLF%' OR EXIT_POINT_NAME LIKE 'QIBM_QPWFS_FILE_SERV%' OR EXIT_POINT_NAME LIKE 'QIBM_QP0L_SCAN_CLOSE%' OR EXIT_POINT_NAME LIKE 'QIBM_QP0L_SCAN_OPEN%' OR EXIT_POINT_NAME LIKE 'QIBM_QRQ_SQL%' OR EXIT_POINT_NAME LIKE 'QIBM_QSO_ACCEPT%' OR EXIT_POINT_NAME LIKE 'QIBM_QSO_CONNECT%' OR EXIT_POINT_NAME LIKE 'QIBM_QSO_LISTEN%' OR EXIT_POINT_NAME LIKE 'QIBM_QTF_TRANSFER%' OR EXIT_POINT_NAME LIKE 'QIBM_QTG_DEVINIT%' OR EXIT_POINT_NAME LIKE 'QIBM_QTG_DEVTERM%' OR EXIT_POINT_NAME LIKE 'QIBM_QTMX%' OR EXIT_POINT_NAME LIKE 'QIBM_QTOD_SERVER_REQ%' OR EXIT_POINT_NAME LIKE 'QIBM_QVP_PRINTERS%' OR EXIT_POINT_NAME LIKE 'QIBM_QWC_PWRDWNSYS%' OR EXIT_POINT_NAME LIKE 'QIBM_QZSC%' OR EXIT_POINT_NAME LIKE 'QIBM_QZSO_SIGNONSRV%'")
  EP_RC=$?
  if [ "$EP_RC" -ne 0 ]; then
    add security net_exit_points "Host server exit programs" NOT_ASSESSED low \
        "not assessed — capture failed (rc=$EP_RC)" \
        "The EXIT_POINT_INFO probe did not yield a readable host-server exit-point dump, so exit programs cannot be graded." \
        "re-run the scan as the scan profile and confirm QSYS2.EXIT_POINT_INFO returns EXIT_POINT_NAME rows. This scanner never changes exit-point registration." \
        "cis-l1"
  elif [ -z "$EP_RAW" ]; then
    add security net_exit_points "Host server exit programs" NOT_ASSESSED low \
        "not assessed — capture empty (rc=0)" \
        "The EXIT_POINT_INFO probe returned no pipe row, so exit programs cannot be graded." \
        "re-run the scan as the scan profile and confirm QSYS2.EXIT_POINT_INFO returns EXIT_POINT_NAME rows. This scanner never changes exit-point registration." \
        "cis-l1"
  else
    EP_PARSE=$(printf '%s\n' "$EP_RAW" | awk -F'|' '
      $1=="EXIT" {
        name=$2; sub(/[ \t]+$/, "", name)
        fmt=$3; sub(/[ \t]+$/, "", fmt)
        reg=$4; sub(/[ \t]+$/, "", reg)
        n=$5; sub(/[ \t]+$/, "", n)
        if (name !~ /^QIBM_[A-Z0-9_]+$/ || fmt !~ /^[A-Z0-9]+$/ || (reg != "YES" && reg != "NO") || n !~ /^[0-9]+$/) {
          junk=1
          next
        }
        if (reg != "YES") next
        pgm[name] += n+0
        names[name]=1
      }
      END {
        if (junk) { print "JUNK"; exit }
        for (nm in names) {
          c++
          if (pgm[nm] > 0) yes++
          else no++
        }
        printf "OK %d %d %d\n", c+0, yes+0, no+0
      }')
    if [ "$EP_PARSE" = "JUNK" ]; then
      add security net_exit_points "Host server exit programs" NOT_ASSESSED low \
          "not assessed — EXIT_POINT_INFO value unreadable" \
          "The exit-point dump was readable, but a row carried a name, format, REGISTERED token, or program count that could not be graded." \
          "inspect QSYS2.EXIT_POINT_INFO EXIT_POINT_NAME, EXIT_POINT_FORMAT, REGISTERED, and EXIT_PROGRAMS." \
          "cis-l1"
    else
      EP_N=$(printf '%s\n' "$EP_PARSE" | awk '{ print $2 }')
      EP_YES=$(printf '%s\n' "$EP_PARSE" | awk '{ print $3 }')
      EP_NO=$(printf '%s\n' "$EP_PARSE" | awk '{ print $4 }')
      if [ -z "$EP_N" ] || [ "$EP_N" -eq 0 ]; then
        add security net_exit_points "Host server exit programs" NOT_ASSESSED low \
            "not assessed — registered host-server exit point rows missing in EXIT_POINT_INFO" \
            "The exit-point dump was readable, but it did not contain any REGISTERED=YES host-server exit point, so exit programs cannot be graded." \
            "inspect QSYS2.EXIT_POINT_INFO for the IBM i Access family host-server exit points." \
            "cis-l1"
      elif [ "$EP_NO" -eq 0 ]; then
        add security net_exit_points "Host server exit programs" PASS low \
            "exit points=$EP_N with programs=$EP_YES without=$EP_NO" \
            "Every listed host-server exit point that is registered has at least one exit program, so FTP, ODBC, remote command, file server, and related IBM i Access family requests can be gated by a user exit." \
            "n/a" \
            "cis-l1"
      else
        add security net_exit_points "Host server exit programs" FAIL high \
            "exit points=$EP_N with programs=$EP_YES without=$EP_NO" \
            "One or more registered host-server exit points have no exit program, so FTP, ODBC, remote command, or related IBM i Access family requests can run without a user exit gating them." \
            "register a user exit program on every host-server exit point that currently has none using WRKREGINF and ADDEXITPGM. This scanner never changes exit-point registration." \
            "cis-l1"
      fi
    fi
  fi

  # net_function_usage — IBM i default function usage on the CIS-listed IDs.
  # Authority: CIS IBM i V7R5M0/V7R4M0 5.2.8 (L1=DEFAULT_USAGE=DENIED
  # on every listed FUNCTION_ID that exists). No L2 rec.
  # One finding. Calls ibmi_sql for FUNCTION_INFO.
  # Does not call ibmi_cl / WRKFCNUSG / CHGFCNUSG.
  # Does not SELECT FUNCTION_USAGE (user/group names are shop-specific).
  # Missing listed IDs are skipped, not FAIL.
  # Exact DENIED on every remaining listed ID is PASS.
  # Any listed ID with ALLOWED is FAIL (IBM default for DDM/ZDA/ENVVAR).
  FU_RAW=$(ibmi_sql function_info "SELECT 'FCN' CONCAT '|' CONCAT VARCHAR(TRIM(FUNCTION_ID),30) CONCAT '|' CONCAT VARCHAR(DEFAULT_USAGE,7) FROM QSYS2.FUNCTION_INFO WHERE FUNCTION_ID IN ('QIBM_ACCESS_ALLOBJ_JOBLOG','QIBM_ACS_HTTP_PROXY','QIBM_ACS_HTTP_PROXY_OSPM','QIBM_ALLOBJ_TRACE_ANY_USER','QIBM_DB_DDMDRDA','QIBM_DB_ZDA','QIBM_DB_SECADM','QIBM_DB_SQLADM','QIBM_DB_SYSMON','QIBM_DIRSRV_ADMIN','QIBM_ENVVAR_SYS','QIBM_LIST_ALL_OBJS','QIBM_LIST_ALL_OBJS_SQL','QIBM_QSY_SYSTEM_CERT_STORE','QIBM_QYAS_SERVICE_DISKMGMT','QIBM_SERVICE_DISK_WATCHER','QIBM_SERVICE_DUMP','QIBM_SERVICE_JOB_WATCHER','QIBM_SERVICE_THREAD','QIBM_SERVICE_TRACE','QIBM_SERVICE_WATCH','QIBM_WATCH_ANY_JOB','QIBM_DB2_MIRROR')")
  FU_RC=$?
  if [ "$FU_RC" -ne 0 ]; then
    add security net_function_usage "Function usage defaults" NOT_ASSESSED low \
        "not assessed — capture failed (rc=$FU_RC)" \
        "The FUNCTION_INFO probe did not yield a readable function-usage dump, so default usage cannot be graded." \
        "re-run the scan as the scan profile and confirm QSYS2.FUNCTION_INFO returns FUNCTION_ID rows. This scanner never changes function usage." \
        "cis-l1"
  elif [ -z "$FU_RAW" ]; then
    add security net_function_usage "Function usage defaults" NOT_ASSESSED low \
        "not assessed — capture empty (rc=0)" \
        "The FUNCTION_INFO probe returned no pipe row, so default usage cannot be graded." \
        "re-run the scan as the scan profile and confirm QSYS2.FUNCTION_INFO returns FUNCTION_ID rows. This scanner never changes function usage." \
        "cis-l1"
  else
    FU_PARSE=$(printf '%s\n' "$FU_RAW" | awk -F'|' '
      $1=="FCN" {
        id=$2; sub(/[ \t]+$/, "", id)
        usg=$3; sub(/[ \t]+$/, "", usg)
        if (id !~ /^QIBM_[A-Z0-9_]+$/ || (usg != "DENIED" && usg != "ALLOWED")) {
          junk=1
          next
        }
        if (seen[id] && usage[id] != usg) { junk=1; next }
        if (seen[id]) next
        seen[id]=1
        usage[id]=usg
        c++
        if (usg == "DENIED") den++
        else allw++
      }
      END {
        if (junk) { print "JUNK"; exit }
        printf "OK %d %d %d\n", c+0, den+0, allw+0
      }')
    if [ "$FU_PARSE" = "JUNK" ]; then
      add security net_function_usage "Function usage defaults" NOT_ASSESSED low \
          "not assessed — FUNCTION_INFO value unreadable" \
          "The function-usage dump was readable, but a row carried a function ID or DEFAULT_USAGE token that could not be graded." \
          "inspect QSYS2.FUNCTION_INFO FUNCTION_ID and DEFAULT_USAGE." \
          "cis-l1"
    else
      FU_N=$(printf '%s\n' "$FU_PARSE" | awk '{ print $2 }')
      FU_DEN=$(printf '%s\n' "$FU_PARSE" | awk '{ print $3 }')
      FU_ALL=$(printf '%s\n' "$FU_PARSE" | awk '{ print $4 }')
      if [ -z "$FU_N" ] || [ "$FU_N" -eq 0 ]; then
        add security net_function_usage "Function usage defaults" NOT_ASSESSED low \
            "not assessed — listed function usage rows missing in FUNCTION_INFO" \
            "The function-usage dump was readable, but it did not contain any of the listed function IDs, so default usage cannot be graded." \
            "inspect QSYS2.FUNCTION_INFO for the listed host, database, ACS, and service function IDs." \
            "cis-l1"
      elif [ "$FU_ALL" -eq 0 ]; then
        add security net_function_usage "Function usage defaults" PASS low \
            "functions=$FU_N denied=$FU_DEN allowed=$FU_ALL" \
            "Every listed function usage identifier that exists has default usage DENIED, so users without an explicit allow cannot use those database, ACS, or service functions." \
            "n/a" \
            "cis-l1"
      else
        add security net_function_usage "Function usage defaults" FAIL high \
            "functions=$FU_N denied=$FU_DEN allowed=$FU_ALL" \
            "One or more listed function usage identifiers have default usage ALLOWED, so users without an explicit deny can use those database, ACS, or service functions." \
            "set DEFAULT(*DENIED) on every listed function using CHGFCNUSG. This scanner never changes function usage." \
            "cis-l1"
      fi
    fi
  fi

  # net_jobacn — IBM i JOBACN (network job action).
  # Authority: CIS IBM i V7R5M0/V7R4M0 5.2.1 (L1=*REJECT). No L2 rec.
  # One finding. Calls ibmi_sql for NETWORK_ATTRIBUTE_INFO JOB_ACTION.
  # Does not call ibmi_cl / DSPNETA / CHGNETA. Does not SELECT HOST_NAME.
  # Exact *REJECT is PASS. Exact *FILE (IBM default) or *SEARCH is FAIL.
  JOBACN_RAW=$(ibmi_sql net_attr "SELECT 'JOB_ACTION' CONCAT '|' CONCAT VARCHAR(COALESCE(TRIM(JOB_ACTION),''),7) FROM QSYS2.NETWORK_ATTRIBUTE_INFO")
  JOBACN_RC=$?
  if [ "$JOBACN_RC" -ne 0 ]; then
    add security net_jobacn "Network job action" NOT_ASSESSED low \
        "not assessed — capture failed (rc=$JOBACN_RC)" \
        "The NETWORK_ATTRIBUTE_INFO probe did not yield a readable JOB_ACTION value, so JOBACN cannot be graded." \
        "re-run the scan as the scan profile and confirm QSYS2.NETWORK_ATTRIBUTE_INFO returns JOB_ACTION. This scanner never changes network attributes." \
        "cis-l1"
  elif [ -z "$JOBACN_RAW" ]; then
    add security net_jobacn "Network job action" NOT_ASSESSED low \
        "not assessed — capture empty (rc=0)" \
        "The NETWORK_ATTRIBUTE_INFO probe returned no pipe row, so JOBACN cannot be graded." \
        "re-run the scan as the scan profile and confirm QSYS2.NETWORK_ATTRIBUTE_INFO returns JOB_ACTION. This scanner never changes network attributes." \
        "cis-l1"
  else
    JOBACN_LINE=$(printf '%s\n' "$JOBACN_RAW" | awk -F'|' '$1=="JOB_ACTION"{n++; line=$0} END{if(n==1) print line}')
    if [ -z "$JOBACN_LINE" ]; then
      add security net_jobacn "Network job action" NOT_ASSESSED low \
          "not assessed — JOB_ACTION row missing or not unique in NETWORK_ATTRIBUTE_INFO" \
          "The network-attribute dump was readable, but it did not contain exactly one JOB_ACTION row, so the value cannot be graded." \
          "inspect QSYS2.NETWORK_ATTRIBUTE_INFO for JOB_ACTION." \
          "cis-l1"
    else
      JOBACN_VAL=$(printf '%s\n' "$JOBACN_LINE" | awk -F'|' '{ v=$2; sub(/[ \t]+$/, "", v); print v }')
      if [ -z "$JOBACN_VAL" ]; then
        add security net_jobacn "Network job action" NOT_ASSESSED low \
            "not assessed — JOBACN value unreadable" \
            "The JOB_ACTION row was present, but the catalog value was empty, so it is not graded." \
            "inspect JOB_ACTION on QSYS2.NETWORK_ATTRIBUTE_INFO and DSPNETA." \
            "cis-l1"
      elif [ "$JOBACN_VAL" = "*REJECT" ]; then
        add security net_jobacn "Network job action" PASS low \
            "JOBACN=*REJECT" \
            "JOBACN is *REJECT, so incoming SNA distribution job streams are refused." \
            "n/a" \
            "cis-l1"
      elif [ "$JOBACN_VAL" = "*FILE" ] || [ "$JOBACN_VAL" = "*SEARCH" ]; then
        add security net_jobacn "Network job action" FAIL high \
            "JOBACN=$JOBACN_VAL" \
            "JOBACN is not *REJECT, so incoming SNA distribution job streams can be filed or auto-submitted without authenticating the remote sender." \
            "set JOBACN to *REJECT using CHGNETA JOBACN(*REJECT). This scanner never changes network attributes." \
            "cis-l1"
      else
        add security net_jobacn "Network job action" NOT_ASSESSED low \
            "not assessed — JOBACN value unreadable" \
            "The JOB_ACTION row was present, but the catalog value was not *REJECT, *FILE, or *SEARCH, so it is not graded." \
            "inspect JOB_ACTION on QSYS2.NETWORK_ATTRIBUTE_INFO and DSPNETA." \
            "cis-l1"
      fi
    fi
  fi

  # net_netserver_shares — IBM i NetServer FILE shares and QPWFSERVER.
  # Authority: CIS IBM i V7R5M0/V7R4M0 5.3.5 (L1=no FILE path /,
  # QPWFSERVER *PUBLIC=*EXCLUDE). No L2 rec.
  # One finding. Calls ibmi_sql for SERVER_SHARE_INFO FILE rows and
  # AUTHORIZATION_LIST_USER_INFO QPWFSERVER *PUBLIC.
  # Does not call ibmi_cl / GO NETS / QZLSRMS / EDTAUTL / NETSTAT.
  # Does not SELECT share name, text, encryption, or *R/*RW.
  # ROOT=0 with *EXCLUDE is PASS. Path / or non-exclude AUTL is FAIL.
  NS_RAW=$(ibmi_sql ns_shares "SELECT 'SHARE' CONCAT '|' CONCAT VARCHAR(COALESCE(TRIM(SHARE_TYPE),''),5) CONCAT '|' CONCAT VARCHAR(COALESCE(TRIM(CAST(PATH_NAME AS VARCHAR(500))),''),500) FROM QSYS2.SERVER_SHARE_INFO WHERE SHARE_TYPE = 'FILE'")
  NS_RC=$?
  if [ "$NS_RC" -ge 2 ]; then
    add security net_netserver_shares "NetServer shares" NOT_ASSESSED low \
        "not assessed — capture failed (rc=$NS_RC)" \
        "The SERVER_SHARE_INFO probe did not yield a readable FILE-share list, so NetServer share posture cannot be graded." \
        "re-run the scan as the scan profile and confirm QSYS2.SERVER_SHARE_INFO returns FILE rows. This scanner never changes NetServer shares." \
        "cis-l1"
  elif [ "$NS_RC" -eq 0 ] && [ -z "$NS_RAW" ]; then
    add security net_netserver_shares "NetServer shares" NOT_ASSESSED low \
        "not assessed — capture empty (rc=0)" \
        "The SERVER_SHARE_INFO probe returned no pipe row at rc 0, which is the swallowed mid-fetch-error signature, so NetServer share posture cannot be graded." \
        "re-run the scan as the scan profile and confirm QSYS2.SERVER_SHARE_INFO returns FILE rows. This scanner never changes NetServer shares." \
        "cis-l1"
  else
    if [ "$NS_RC" -eq 1 ] && [ -z "$NS_RAW" ]; then
      NS_N=0
      NS_ROOT=0
      NS_JUNK=0
    else
      NS_COUNTS=$(printf '%s\n' "$NS_RAW" | awk -F'|' '
        {
          if ( $1=="SHARE" && $2=="FILE" ) {
            n++
            p=$3
            sub(/[ \t]+$/, "", p)
            if (p=="/") root++
          } else {
            junk++
          }
        }
        END { printf "%d %d %d\n", n+0, root+0, junk+0 }')
      NS_N=$(printf '%s\n' "$NS_COUNTS" | awk '{ print $1 }')
      NS_ROOT=$(printf '%s\n' "$NS_COUNTS" | awk '{ print $2 }')
      NS_JUNK=$(printf '%s\n' "$NS_COUNTS" | awk '{ print $3 }')
    fi
    if [ "$NS_JUNK" -gt 0 ]; then
      add security net_netserver_shares "NetServer shares" NOT_ASSESSED low \
          "not assessed — unexpected SERVER_SHARE_INFO row shape" \
          "The SERVER_SHARE_INFO probe returned rows that are not SHARE|FILE|path rows, so the FILE-share counts cannot be trusted and NetServer share posture cannot be graded." \
          "re-run the scan as the scan profile and confirm QSYS2.SERVER_SHARE_INFO returns only SHARE|FILE|<path> pipe rows. This scanner never changes NetServer shares." \
          "cis-l1"
    else
    NS_AUTL_RAW=$(ibmi_sql ns_qpwfserver "SELECT 'QPWFSERVER' CONCAT '|' CONCAT VARCHAR(COALESCE(TRIM(OBJECT_AUTHORITY),''),12) FROM QSYS2.AUTHORIZATION_LIST_USER_INFO WHERE AUTHORIZATION_LIST = 'QPWFSERVER' AND AUTHORIZATION_NAME = '*PUBLIC'")
    NS_AUTL_RC=$?
    if [ "$NS_AUTL_RC" -ne 0 ]; then
      add security net_netserver_shares "NetServer shares" NOT_ASSESSED low \
          "not assessed — capture failed (rc=$NS_AUTL_RC)" \
          "The AUTHORIZATION_LIST_USER_INFO probe did not yield a readable QPWFSERVER *PUBLIC value, so NetServer share posture cannot be graded." \
          "re-run the scan as the scan profile and confirm QSYS2.AUTHORIZATION_LIST_USER_INFO returns QPWFSERVER *PUBLIC. This scanner never changes authorization lists." \
          "cis-l1"
    elif [ -z "$NS_AUTL_RAW" ]; then
      add security net_netserver_shares "NetServer shares" NOT_ASSESSED low \
          "not assessed — capture empty (rc=0)" \
          "The AUTHORIZATION_LIST_USER_INFO probe returned no pipe row, so QPWFSERVER *PUBLIC cannot be graded." \
          "re-run the scan as the scan profile and confirm QSYS2.AUTHORIZATION_LIST_USER_INFO returns QPWFSERVER *PUBLIC. This scanner never changes authorization lists." \
          "cis-l1"
    else
      NS_AUTL_LINE=$(printf '%s\n' "$NS_AUTL_RAW" | awk -F'|' '$1=="QPWFSERVER"{n++; line=$0} END{if(n==1) print line}')
      if [ -z "$NS_AUTL_LINE" ]; then
        add security net_netserver_shares "NetServer shares" NOT_ASSESSED low \
            "not assessed — QPWFSERVER row missing or not unique in AUTHORIZATION_LIST_USER_INFO" \
            "The authorization-list dump was readable, but it did not contain exactly one QPWFSERVER *PUBLIC row, so the value cannot be graded." \
            "inspect QSYS2.AUTHORIZATION_LIST_USER_INFO for QPWFSERVER and *PUBLIC. The scan profile may only see its own AUTL row." \
            "cis-l1"
      else
        NS_AUTL=$(printf '%s\n' "$NS_AUTL_LINE" | awk -F'|' '{ v=$2; sub(/[ \t]+$/, "", v); print v }')
        if [ -z "$NS_AUTL" ] || { [ "$NS_AUTL" != "*EXCLUDE" ] && [ "$NS_AUTL" != "*USE" ] && [ "$NS_AUTL" != "*CHANGE" ] && [ "$NS_AUTL" != "*ALL" ] && [ "$NS_AUTL" != "USER DEFINED" ]; }; then
          add security net_netserver_shares "NetServer shares" NOT_ASSESSED low \
              "not assessed — QPWFSERVER value unreadable" \
              "The QPWFSERVER row was present, but the catalog value was not *EXCLUDE, *USE, *CHANGE, *ALL, or USER DEFINED, so it is not graded." \
              "inspect OBJECT_AUTHORITY for QPWFSERVER *PUBLIC on QSYS2.AUTHORIZATION_LIST_USER_INFO." \
              "cis-l1"
        elif [ "$NS_ROOT" -eq 0 ] && [ "$NS_AUTL" = "*EXCLUDE" ]; then
          add security net_netserver_shares "NetServer shares" PASS low \
              "FILE shares=$NS_N ROOT=0 QPWFSERVER=*EXCLUDE" \
              "No NetServer FILE share maps to the IFS root, and QPWFSERVER *PUBLIC is *EXCLUDE, so SMB clients cannot reach the whole IFS tree or QSYS.LIB as *PUBLIC." \
              "n/a" \
              "cis-l1"
        elif [ "$NS_ROOT" -gt 0 ]; then
          add security net_netserver_shares "NetServer shares" FAIL high \
              "FILE shares=$NS_N ROOT=$NS_ROOT QPWFSERVER=$NS_AUTL" \
              "One or more NetServer FILE shares map to the IFS root, so an SMB client can reach every IFS directory including QSYS.LIB." \
              "remove every NetServer file share whose path is the IFS root. This scanner never changes NetServer shares." \
              "cis-l1"
        else
          add security net_netserver_shares "NetServer shares" FAIL high \
              "FILE shares=$NS_N ROOT=0 QPWFSERVER=$NS_AUTL" \
              "QPWFSERVER *PUBLIC is not *EXCLUDE, so an SMB client can reach QSYS.LIB objects with *PUBLIC authority." \
              "set *PUBLIC authority on authorization list QPWFSERVER to *EXCLUDE. This scanner never changes authorization lists." \
              "cis-l1"
        fi
      fi
    fi
    fi
  fi

  # net_nfs_shares — IBM i NFS export anonymous mapping.
  # Authority: CIS IBM i V7R5M0/V7R4M0 5.2.5 (L1=ANON=-1) and 5.2.6
  # (L2=VERS=4,SEC=KRB5 tag). One finding. Calls ibmi_sql for
  # IFS_OBJECT_STATISTICS on /etc and IFS_READ of /etc/exports.
  # Does not call ibmi_cl / QZNFRTVE / CHGNFSEXP / EXPORTFS / cat.
  # Missing /etc/exports is PASS. Any export without anon=-1 is FAIL.
  NFS_PRES=$(ibmi_sql nfs_exports_present "SELECT 'PRESENT' CONCAT '|' CONCAT VARCHAR(PATH_NAME,1024) CONCAT '|' CONCAT VARCHAR(OBJECT_TYPE,10) FROM TABLE(QSYS2.IFS_OBJECT_STATISTICS(START_PATH_NAME => '/etc', SUBTREE_DIRECTORIES => 'NO', IGNORE_ERRORS => 'NO')) WHERE PATH_NAME = '/etc/exports'")
  NFS_PRES_RC=$?
  if [ "$NFS_PRES_RC" -ge 2 ]; then
    add security net_nfs_shares "NFS shares" NOT_ASSESSED low \
        "not assessed — capture failed (rc=$NFS_PRES_RC)" \
        "The IFS_OBJECT_STATISTICS probe did not yield a readable /etc listing, so NFS exports cannot be graded." \
        "re-run the scan as the scan profile and confirm QSYS2.IFS_OBJECT_STATISTICS can list /etc. This scanner never changes NFS exports." \
        "cis-l1 cis-l2"
  elif [ "$NFS_PRES_RC" -eq 0 ] && [ -z "$NFS_PRES" ]; then
    add security net_nfs_shares "NFS shares" NOT_ASSESSED low \
        "not assessed — capture empty (rc=0)" \
        "The IFS_OBJECT_STATISTICS probe returned no pipe row at rc 0, which is the swallowed mid-fetch-error signature, so NFS exports cannot be graded." \
        "re-run the scan as the scan profile and confirm QSYS2.IFS_OBJECT_STATISTICS can list /etc. This scanner never changes NFS exports." \
        "cis-l1 cis-l2"
  elif [ "$NFS_PRES_RC" -eq 1 ] && [ -z "$NFS_PRES" ]; then
    add security net_nfs_shares "NFS shares" PASS low \
        "no NFS exports" \
        "No NFS export is configured, so this host does not share IFS directories over NFS." \
        "n/a" \
        "cis-l1 cis-l2"
  else
    NFS_PLINE=$(printf '%s\n' "$NFS_PRES" | awk -F'|' '$1=="PRESENT" && $2=="/etc/exports"{n++; line=$0} END{if(n==1) print line}')
    if [ -z "$NFS_PLINE" ]; then
      add security net_nfs_shares "NFS shares" PASS low \
          "no NFS exports" \
          "No NFS export is configured, so this host does not share IFS directories over NFS." \
          "n/a" \
          "cis-l1 cis-l2"
    else
      NFS_TYPE=$(printf '%s\n' "$NFS_PLINE" | awk -F'|' '{ v=$3; sub(/[ \t]+$/, "", v); print v }')
      if [ "$NFS_TYPE" != "*STMF" ]; then
        add security net_nfs_shares "NFS shares" NOT_ASSESSED low \
            "not assessed — /etc/exports is not a stream file" \
            "The /etc listing named /etc/exports, but the object type was not *STMF, so NFS exports cannot be graded." \
            "inspect /etc/exports and confirm it is an IFS stream file." \
            "cis-l1 cis-l2"
      else
        NFS_RAW=$(ibmi_sql nfs_exports "SELECT 'EXPORT' CONCAT '|' CONCAT VARCHAR(LINE,1024) FROM TABLE(QSYS2.IFS_READ(PATH_NAME => '/etc/exports', IGNORE_ERRORS => 'NO'))")
        NFS_RC=$?
        if [ "$NFS_RC" -ne 0 ]; then
          add security net_nfs_shares "NFS shares" NOT_ASSESSED low \
              "not assessed — capture failed (rc=$NFS_RC)" \
              "The IFS_READ probe did not yield a readable /etc/exports, so NFS exports cannot be graded." \
              "re-run the scan as the scan profile and confirm the scan profile has *R on /etc/exports. This scanner never changes NFS exports." \
              "cis-l1 cis-l2"
        else
          NFS_COUNTS=$(printf '%s\n' "$NFS_RAW" | awk '
            function trim(s) {
              sub(/\r$/, "", s)
              sub(/^[ \t]+/, "", s)
              sub(/[ \t]+$/, "", s)
              return s
            }
            {
              raw = $0
              sub(/^EXPORT\|/, "", raw)
              raw = trim(raw)
              if (raw == "" || raw ~ /^#/) next
              n++
              l = tolower(raw)
              if (l ~ /(^|[, \t]|-)anon=-1([, \t]|$)/ || l ~ /(^|[, \t]|-)anon=4294967295([, \t]|$)/) none++
              if (l ~ /(^|[, \t]|-)vers=4([, \t]|$)/ && l ~ /(^|[, \t]|-)sec=krb5(i|p)?([, \t:]|$)/) l2++
            }
            END { printf "%d %d %d\n", n+0, none+0, l2+0 }')
          NFS_N=$(printf '%s\n' "$NFS_COUNTS" | awk '{ print $1 }')
          NFS_NONE=$(printf '%s\n' "$NFS_COUNTS" | awk '{ print $2 }')
          NFS_L2=$(printf '%s\n' "$NFS_COUNTS" | awk '{ print $3 }')
          if [ "$NFS_N" -eq 0 ]; then
            add security net_nfs_shares "NFS shares" PASS low \
                "no NFS exports" \
                "No NFS export is configured, so this host does not share IFS directories over NFS." \
                "n/a" \
                "cis-l1 cis-l2"
          elif [ "$NFS_NONE" -eq "$NFS_N" ]; then
            add security net_nfs_shares "NFS shares" PASS low \
                "NFS exports=$NFS_N ANON=*NONE=$NFS_NONE VERS4_KRB5=$NFS_L2" \
                "Every NFS export sets ANON=-1, so unknown NFS users are not mapped to QNFSANON or another UID." \
                "n/a" \
                "cis-l1 cis-l2"
          else
            add security net_nfs_shares "NFS shares" FAIL high \
                "NFS exports=$NFS_N ANON=*NONE=$NFS_NONE VERS4_KRB5=$NFS_L2" \
                "One or more NFS exports omit ANON=-1, so unknown NFS users can be mapped to QNFSANON or another UID and reach shared objects without a matching user profile." \
                "set ANON=-1 on every NFS export using CHGNFSEXP or by adding -anon=-1 on each /etc/exports line. This scanner never changes NFS exports." \
                "cis-l1 cis-l2"
          fi
        fi
      fi
    fi
  fi

  # net_telnet — IBM i Telnet attributes (CHGTELNA ALWSSL).
  # Authority: CIS IBM i V7R5M0/V7R4M0 5.2.10 (L1=*ONLY). No L2 rec.
  # One finding. Calls ibmi_sql for TELNET_SERVER_ATTRIBUTES ALWSSL.
  # Does not call ibmi_cl / DSPTELNA / CHGTELNA / NETSTAT. Does not SELECT AUTOSTART.
  # Exact *ONLY is PASS. Exact *YES (IBM default) or *NO is FAIL.
  TELNET_RAW=$(ibmi_sql tn_attr "SELECT 'ALWSSL' CONCAT '|' CONCAT VARCHAR(COALESCE(TRIM(ALLOW_TRANSPORT_LAYER_SECURITY),''),5) FROM QSYS2.TELNET_SERVER_ATTRIBUTES")
  TELNET_RC=$?
  if [ "$TELNET_RC" -ne 0 ]; then
    add security net_telnet "Telnet protocol" NOT_ASSESSED low \
        "not assessed — capture failed (rc=$TELNET_RC)" \
        "The TELNET_SERVER_ATTRIBUTES probe did not yield a readable ALWSSL value, so Telnet TLS posture cannot be graded." \
        "re-run the scan as the scan profile and confirm QSYS2.TELNET_SERVER_ATTRIBUTES returns ALLOW_TRANSPORT_LAYER_SECURITY. This scanner never changes Telnet attributes." \
        "cis-l1"
  elif [ -z "$TELNET_RAW" ]; then
    add security net_telnet "Telnet protocol" NOT_ASSESSED low \
        "not assessed — capture empty (rc=0)" \
        "The TELNET_SERVER_ATTRIBUTES probe returned no pipe row, so Telnet TLS posture cannot be graded." \
        "re-run the scan as the scan profile and confirm QSYS2.TELNET_SERVER_ATTRIBUTES returns ALLOW_TRANSPORT_LAYER_SECURITY. This scanner never changes Telnet attributes." \
        "cis-l1"
  else
    TELNET_LINE=$(printf '%s\n' "$TELNET_RAW" | awk -F'|' '$1=="ALWSSL"{n++; line=$0} END{if(n==1) print line}')
    if [ -z "$TELNET_LINE" ]; then
      add security net_telnet "Telnet protocol" NOT_ASSESSED low \
          "not assessed — ALWSSL row missing or not unique in TELNET_SERVER_ATTRIBUTES" \
          "The Telnet-attribute dump was readable, but it did not contain exactly one ALWSSL row, so the value cannot be graded." \
          "inspect QSYS2.TELNET_SERVER_ATTRIBUTES for ALLOW_TRANSPORT_LAYER_SECURITY." \
          "cis-l1"
    else
      TELNET_VAL=$(printf '%s\n' "$TELNET_LINE" | awk -F'|' '{ v=$2; sub(/[ \t]+$/, "", v); print v }')
      if [ -z "$TELNET_VAL" ]; then
        add security net_telnet "Telnet protocol" NOT_ASSESSED low \
            "not assessed — ALWSSL value unreadable" \
            "The ALWSSL row was present, but the catalog value was empty, so it is not graded." \
            "inspect ALLOW_TRANSPORT_LAYER_SECURITY on QSYS2.TELNET_SERVER_ATTRIBUTES and DSPTELNA." \
            "cis-l1"
      elif [ "$TELNET_VAL" = "*ONLY" ]; then
        add security net_telnet "Telnet protocol" PASS low \
            "ALWSSL=*ONLY" \
            "Telnet Allow Transport Layer Security is *ONLY, so a Telnet login cannot send a clear-text password." \
            "n/a" \
            "cis-l1"
      elif [ "$TELNET_VAL" = "*YES" ] || [ "$TELNET_VAL" = "*NO" ]; then
        add security net_telnet "Telnet protocol" FAIL high \
            "ALWSSL=$TELNET_VAL" \
            "Telnet Allow Transport Layer Security is not *ONLY, so a Telnet login can send a clear-text password." \
            "set Telnet Allow Transport Layer Security to *ONLY using CHGTELNA ALWSSL(*ONLY). This scanner never changes Telnet attributes." \
            "cis-l1"
      else
        add security net_telnet "Telnet protocol" NOT_ASSESSED low \
            "not assessed — ALWSSL value unreadable" \
            "The ALWSSL row was present, but the catalog value was not *ONLY, *YES, or *NO, so it is not graded." \
            "inspect ALLOW_TRANSPORT_LAYER_SECURITY on QSYS2.TELNET_SERVER_ATTRIBUTES and DSPTELNA." \
            "cis-l1"
      fi
    fi
  fi

  # sec_bulletin_vintage — vintage of the embedded
  # IBM i security-data table. WARN when as_of is
  # older than 30 days (AIX registry as_of STALE
  # rule). v1 does not ship a per-CVE bulletin
  # table (no verified feed). Not a CIS rec.
  # One finding. Does not call ibmi_sql / ibmi_cl.
  # Does not query GROUP_PTF_CURRENCY
  # (ck-sec-group-currency) or FIRMWARE_CURRENCY
  # or ENV_SYS_INFO. Does not emit one row per CVE.
  # Stamp variable is SEC_BULLETIN_VINTAGE, not
  # DATA_VINTAGE (that name is ck-cur-os-lifecycle).
  SEC_BULLETIN_VINTAGE="2026-08-20"
  SEC_BULLETIN_THRESHOLD=30
  BV_TODAY_OK=1
  case "$TODAY_J" in
    ''|*[!0-9]*) BV_TODAY_OK=0 ;;
  esac
  if [ "$BV_TODAY_OK" -eq 0 ]; then
    add patch sec_bulletin_vintage "IBM i security-data vintage" NOT_ASSESSED low \
        "not assessed — scan date unreadable" \
        "The scan date was not a Julian day, so the scanner build/release date cannot be graded." \
        "re-run the scan so the prelude can set a calendar date. This scanner never applies PTFs."
  else
    BV_J=$(d2j "$SEC_BULLETIN_VINTAGE")
    BV_RC=$?
    if [ "$BV_RC" -ne 0 ] || [ -z "$BV_J" ]; then
      add patch sec_bulletin_vintage "IBM i security-data vintage" NOT_ASSESSED low \
          "not assessed — security-data as_of unreadable" \
          "The scanner build/release date was not a calendar date, so it cannot be graded." \
          "refresh the scanner from a current release so the security-data stamp is a YYYY-MM-DD date. This scanner never applies PTFs."
    elif [ "$TODAY_J" -lt "$BV_J" ]; then
      add patch sec_bulletin_vintage "IBM i security-data vintage" NOT_ASSESSED low \
          "not assessed — security-data as_of $SEC_BULLETIN_VINTAGE is after today $TODAY" \
          "The scanner build/release date is later than the scan date, so age cannot be graded." \
          "re-run with a real calendar date, or refresh the scanner if the stamp is wrong. This scanner never applies PTFs."
    else
      BV_AGE=$(( TODAY_J - BV_J ))
      if [ "$BV_AGE" -gt "$SEC_BULLETIN_THRESHOLD" ]; then
        add patch sec_bulletin_vintage "IBM i security-data vintage" WARN high \
            "as_of=$SEC_BULLETIN_VINTAGE today=$TODAY age=$BV_AGE threshold=$SEC_BULLETIN_THRESHOLD" \
            "The scanner build/release date is older than 30 days, so security findings from this scanner may not reflect current IBM bulletins." \
            "refresh the scanner from a current release so the security-data stamp is current. This scanner never applies PTFs."
      else
        add patch sec_bulletin_vintage "IBM i security-data vintage" PASS low \
            "as_of=$SEC_BULLETIN_VINTAGE today=$TODAY age=$BV_AGE threshold=$SEC_BULLETIN_THRESHOLD" \
            "The scanner build/release date is within the 30-day freshness window. This scanner does not enumerate IBM i CVEs from a bulletin feed." \
            "n/a"
      fi
    fi
  fi

  # sec_group_currency — IBM i Security and HIPER
  # rows of SYSTOOLS.GROUP_PTF_CURRENCY vs IBM PSP
  # (D-i8 network exception).
  # Phase 6 security-fixes, not CIS 5.5.1 (that is
  # ck-cur-ptf-groups / WARN on every group).
  # INSTALLED LEVEL IS CURRENT + INSTALLED on
  # both Security and HIPER titles is PASS.
  # UPDATE AVAILABLE / CURRENT AT THE NEXT IPL /
  # NOT INSTALLED / missing title is FAIL high.
  # PSP INFORMATION NOT AVAILABLE is
  # NOT_ASSESSED unless a FAIL class is also
  # present. rc 1 + empty is FAIL missing
  # (not firmware N/A). rc 0 + empty is
  # swallowed mid-fetch NOT_ASSESSED.
  # Identify groups by title substring
  # " Group Security" / " Group Hiper".
  # Never hardcode SF-numbers.
  # One finding. Calls ibmi_sql only.
  # Does not call ibmi_cl / WRKPTFGRP / DSPPTF.
  # Does not SELECT * / COUNT(*) (second HTTP).
  # Does not WHERE title LIKE (0-row rc 1 trap).
  SC_RAW=$(ibmi_sql sec_grp_currency "SELECT 'GRP' CONCAT '|' CONCAT VARCHAR(TRIM(COALESCE(PTF_GROUP_ID, '-')), 7) CONCAT '|' CONCAT VARCHAR(TRIM(COALESCE(PTF_GROUP_TITLE, '-')), 80) CONCAT '|' CONCAT VARCHAR(TRIM(COALESCE(PTF_GROUP_CURRENCY, '-')), 46) CONCAT '|' CONCAT VARCHAR(COALESCE(CHAR(PTF_GROUP_LEVEL_INSTALLED), '-'), 11) CONCAT '|' CONCAT VARCHAR(COALESCE(CHAR(PTF_GROUP_LEVEL_AVAILABLE), '-'), 11) CONCAT '|' CONCAT VARCHAR(TRIM(COALESCE(PTF_GROUP_STATUS_ON_SYSTEM, '-')), 20) FROM SYSTOOLS.GROUP_PTF_CURRENCY")
  SC_RC=$?
  if [ "$SC_RC" -eq 1 ] && [ -z "$SC_RAW" ]; then
    add patch sec_group_currency "Security and HIPER group PTF currency" FAIL high \
        "sec=missing hiper=missing" \
        "No group-PTF currency rows are visible, so the IBM i Security and HIPER group PTFs are not present to grade as current." \
        "install the current IBM i Security and HIPER group PTFs from IBM Fix Central or the PSP page, then IPL if required. Offline, compare WRKPTFGRP levels to the IBM PSP page. This scanner never applies PTFs."
  elif [ "$SC_RC" -ne 0 ]; then
    add patch sec_group_currency "Security and HIPER group PTF currency" NOT_ASSESSED low \
        "not assessed — capture failed (rc=$SC_RC)" \
        "The group-PTF currency probe did not yield a readable GROUP_PTF_CURRENCY dump, so Security and HIPER group currency cannot be graded. The view reaches IBM PSP when it runs." \
        "compare WRKPTFGRP Security and HIPER group levels to the IBM PSP page, confirm job CCSID is not 65535 and Java is present, then re-run when the partition can reach the IBM PSP feed. This scanner never applies PTFs."
  elif [ -z "$SC_RAW" ]; then
    add patch sec_group_currency "Security and HIPER group PTF currency" NOT_ASSESSED low \
        "not assessed — capture empty (rc=0)" \
        "The group-PTF currency probe returned no pipe row after a successful rc, so the PSP fetch may have failed mid-query and Security and HIPER group currency cannot be graded." \
        "compare WRKPTFGRP Security and HIPER group levels to the IBM PSP page, then re-run when the partition can reach the IBM PSP feed. This scanner never applies PTFs."
  else
    SC_PARSE=$(printf '%s\n' "$SC_RAW" | awk -F'|' '
      function trim(s) {
        sub(/^[ \t]+/, "", s)
        sub(/[ \t]+$/, "", s)
        return s
      }
      function rank(c) {
        if (c == "behind") return 5
        if (c == "pending-ipl") return 4
        if (c == "not-applied") return 3
        if (c == "psp-unavailable") return 2
        if (c == "current") return 1
        return 0
      }
      function setkind(kind, c, inst, avail) {
        obs = c
        if (c == "behind" || c == "current" || c == "pending-ipl" || c == "not-applied")
          obs = c ":" inst "/" avail
        if (kind == "sec") {
          if (rank(c) > rank(sec_c)) { sec_c = c; sec_obs = obs }
          sec_n++
        } else {
          if (rank(c) > rank(hip_c)) { hip_c = c; hip_obs = obs }
          hip_n++
        }
      }
      $1 == "GRP" {
        title = trim($3)
        cur = trim($4)
        inst = trim($5)
        avail = trim($6)
        sts = trim($7)
        is_sec = (index(title, " Group Security") > 0)
        is_hip = (index(title, " Group Hiper") > 0)
        if (is_sec && is_hip) { junk = 1; next }
        if (!is_sec && !is_hip) next
        if (cur == "UPDATE AVAILABLE") c = "behind"
        else if (cur == "CURRENT AT THE NEXT IPL") c = "pending-ipl"
        else if (cur == "PSP INFORMATION NOT AVAILABLE") c = "psp-unavailable"
        else if (cur == "INSTALLED LEVEL IS CURRENT") {
          if (sts == "INSTALLED") c = "current"
          else if (sts == "NOT INSTALLED") c = "not-applied"
          else { junk = 1; next }
        } else { junk = 1; next }
        if (inst == "") inst = "-"
        if (avail == "") avail = "-"
        if (is_sec) setkind("sec", c, inst, avail)
        else setkind("hiper", c, inst, avail)
        next
      }
      END {
        if (junk) { print "JUNK"; exit }
        if (sec_n == 0) { sec_c = "missing"; sec_obs = "missing" }
        if (hip_n == 0) { hip_c = "missing"; hip_obs = "missing" }
        fail = 0
        psp = 0
        if (sec_c == "behind" || sec_c == "pending-ipl" || sec_c == "not-applied" || sec_c == "missing") fail = 1
        if (hip_c == "behind" || hip_c == "pending-ipl" || hip_c == "not-applied" || hip_c == "missing") fail = 1
        if (sec_c == "psp-unavailable" || hip_c == "psp-unavailable") psp = 1
        if (fail) print "OK|FAIL|" sec_obs "|" hip_obs
        else if (psp) print "OK|NOT_ASSESSED|" sec_obs "|" hip_obs
        else print "OK|PASS|" sec_obs "|" hip_obs
      }')
    if [ "$SC_PARSE" = "JUNK" ]; then
      add patch sec_group_currency "Security and HIPER group PTF currency" NOT_ASSESSED low \
          "not assessed — GROUP_PTF_CURRENCY value unreadable" \
          "The group-PTF currency dump was readable, but a Security or HIPER row carried a currency or status token that could not be graded." \
          "inspect SYSTOOLS.GROUP_PTF_CURRENCY PTF_GROUP_TITLE, PTF_GROUP_CURRENCY, and PTF_GROUP_STATUS_ON_SYSTEM for the Security and HIPER groups."
    else
      SC_KIND=$(printf '%s\n' "$SC_PARSE" | awk -F'|' '{ print $2 }')
      SC_SEC=$(printf '%s\n' "$SC_PARSE" | awk -F'|' '{ print $3 }')
      SC_HIP=$(printf '%s\n' "$SC_PARSE" | awk -F'|' '{ print $4 }')
      if [ "$SC_KIND" = "FAIL" ]; then
        add patch sec_group_currency "Security and HIPER group PTF currency" FAIL high \
            "sec=$SC_SEC hiper=$SC_HIP" \
            "The IBM i Security or HIPER group PTF is behind IBM PSP, pending the next IPL, not fully applied, or not present, so published HIPER or security fixes are not active on this partition." \
            "apply the current IBM i Security and HIPER group PTFs from IBM Fix Central or the PSP page, then IPL if required. Offline, compare WRKPTFGRP levels to the IBM PSP page. This scanner never applies PTFs."
      elif [ "$SC_KIND" = "NOT_ASSESSED" ]; then
        add patch sec_group_currency "Security and HIPER group PTF currency" NOT_ASSESSED low \
            "not assessed — sec=$SC_SEC hiper=$SC_HIP" \
            "The Security or HIPER group PTF row could not reach IBM PSP, so Security and HIPER group currency cannot be graded." \
            "compare WRKPTFGRP Security and HIPER group levels to the IBM PSP page, then re-run when the partition can reach the IBM PSP feed. This scanner never applies PTFs."
      else
        add patch sec_group_currency "Security and HIPER group PTF currency" PASS low \
            "sec=$SC_SEC hiper=$SC_HIP" \
            "The IBM i Security and HIPER group PTFs are installed at the current IBM PSP level, so published HIPER and security fixes in those groups are on this partition." \
            "n/a"
      fi
    fi
  fi

  # ssh_hostbased_auth — IBM i OpenSSH host-based authentication
  # (sshd_config HostbasedAuthentication).
  # Authority: CIS IBM i V7R5M0/V7R4M0 5.4.3 (L1=HostbasedAuthentication no).
  # No L2 rec. One finding. Calls ibmi_sql for IFS_READ_UTF8 of UserData
  # sshd_config. Does not call ibmi_cl / DSPF / EDTF / sshd / NETSTAT.
  # Does not SELECT Banner, AllowUsers, IgnoreRhosts, or Protocol.
  # Exact HostbasedAuthentication no is PASS. Exact yes or absent is FAIL.
  HBA_RAW=$(ibmi_sql sshd_cfg "SELECT 'HOSTBASED' CONCAT '|' CONCAT VARCHAR(COALESCE(TRIM(LINE),''),64) FROM TABLE(QSYS2.IFS_READ_UTF8(PATH_NAME => '/QOpenSys/QIBM/UserData/SC1/OpenSSH/etc/sshd_config', IGNORE_ERRORS => 'NO')) WHERE UPPER(TRIM(REPLACE(LINE, CHR(9), ' '))) = 'HOSTBASEDAUTHENTICATION' OR UPPER(TRIM(REPLACE(LINE, CHR(9), ' '))) LIKE 'HOSTBASEDAUTHENTICATION %' OR UPPER(TRIM(REPLACE(LINE, CHR(9), ' '))) LIKE 'HOSTBASEDAUTHENTICATION=%'")
  HBA_RC=$?
  if [ "$HBA_RC" -ge 2 ]; then
    add security ssh_hostbased_auth "SSH host-based authentication" NOT_ASSESSED low \
        "not assessed — capture failed (rc=$HBA_RC)" \
        "The sshd_config probe did not yield a readable HostbasedAuthentication line, so SSH host-based authentication cannot be graded." \
        "re-run the scan as the scan profile and confirm QSYS2.IFS_READ_UTF8 returns the UserData sshd_config. This scanner never edits sshd_config." \
        "cis-l1"
  elif [ "$HBA_RC" -eq 0 ] && [ -z "$HBA_RAW" ]; then
    add security ssh_hostbased_auth "SSH host-based authentication" NOT_ASSESSED low \
        "not assessed — capture empty (rc=0)" \
        "The sshd_config probe returned no pipe row at rc 0, which is the swallowed mid-fetch-error signature, so SSH host-based authentication cannot be graded." \
        "re-run the scan as the scan profile and confirm QSYS2.IFS_READ_UTF8 returns the UserData sshd_config. This scanner never edits sshd_config." \
        "cis-l1"
  elif [ "$HBA_RC" -eq 1 ] && [ -z "$HBA_RAW" ]; then
    add security ssh_hostbased_auth "SSH host-based authentication" FAIL high \
        "HostbasedAuthentication=(absent)" \
        "SSH host-based authentication is not explicitly set to no, so a login can still trust the source host instead of the user." \
        "set HostbasedAuthentication no in /QOpenSys/QIBM/UserData/SC1/OpenSSH/etc/sshd_config and recycle the SSH server. This scanner never edits sshd_config." \
        "cis-l1"
  else
    HBA_LINE=$(printf '%s\n' "$HBA_RAW" | awk -F'|' '$1=="HOSTBASED"{n++; line=$0} END{if(n==1) print line}')
    if [ -z "$HBA_LINE" ]; then
      HBA_N=$(printf '%s\n' "$HBA_RAW" | awk -F'|' '$1=="HOSTBASED"{n++} END{print n+0}')
      if [ "$HBA_N" -eq 0 ]; then
        add security ssh_hostbased_auth "SSH host-based authentication" FAIL high \
            "HostbasedAuthentication=(absent)" \
            "SSH host-based authentication is not explicitly set to no, so a login can still trust the source host instead of the user." \
            "set HostbasedAuthentication no in /QOpenSys/QIBM/UserData/SC1/OpenSSH/etc/sshd_config and recycle the SSH server. This scanner never edits sshd_config." \
            "cis-l1"
      else
        add security ssh_hostbased_auth "SSH host-based authentication" NOT_ASSESSED low \
            "not assessed — HostbasedAuthentication row missing or not unique in sshd_config" \
            "The sshd_config dump was readable, but it did not contain exactly one uncommented HostbasedAuthentication line, so the value cannot be graded." \
            "inspect /QOpenSys/QIBM/UserData/SC1/OpenSSH/etc/sshd_config for a single uncommented HostbasedAuthentication line." \
            "cis-l1"
      fi
    else
      HBA_VAL=$(printf '%s\n' "$HBA_LINE" | awk -F'|' '{
        v=$2
        sub(/[ \t]+$/, "", v)
        sub(/#.*$/, "", v)
        sub(/[ \t]+$/, "", v)
        low = tolower(v)
        if (low !~ /^hostbasedauthentication([ \t]|=|$)/) { print ""; exit }
        sub(/^[Hh][Oo][Ss][Tt][Bb][Aa][Ss][Ee][Dd][Aa][Uu][Tt][Hh][Ee][Nn][Tt][Ii][Cc][Aa][Tt][Ii][Oo][Nn][ \t]*=?[ \t]*/, "", v)
        sub(/^[ \t]+/, "", v)
        sub(/[ \t]+$/, "", v)
        n=split(v, a, /[ \t]+/)
        if (n != 1) { print ""; exit }
        print a[1]
      }')
      if [ -z "$HBA_VAL" ]; then
        add security ssh_hostbased_auth "SSH host-based authentication" NOT_ASSESSED low \
            "not assessed — HostbasedAuthentication value unreadable" \
            "The HostbasedAuthentication line was present, but the value was empty, so it is not graded." \
            "inspect HostbasedAuthentication on /QOpenSys/QIBM/UserData/SC1/OpenSSH/etc/sshd_config." \
            "cis-l1"
      elif [ "$HBA_VAL" = "no" ] || [ "$HBA_VAL" = "No" ] || [ "$HBA_VAL" = "NO" ]; then
        add security ssh_hostbased_auth "SSH host-based authentication" PASS low \
            "HostbasedAuthentication=no" \
            "SSH host-based authentication is no, so a login must prove the user rather than trust the source host." \
            "n/a" \
            "cis-l1"
      elif [ "$HBA_VAL" = "yes" ] || [ "$HBA_VAL" = "Yes" ] || [ "$HBA_VAL" = "YES" ]; then
        add security ssh_hostbased_auth "SSH host-based authentication" FAIL high \
            "HostbasedAuthentication=$HBA_VAL" \
            "SSH host-based authentication is yes, so a user on a trusted host can log in without that users credentials." \
            "set HostbasedAuthentication no in /QOpenSys/QIBM/UserData/SC1/OpenSSH/etc/sshd_config and recycle the SSH server. This scanner never edits sshd_config." \
            "cis-l1"
      else
        add security ssh_hostbased_auth "SSH host-based authentication" NOT_ASSESSED low \
            "not assessed — HostbasedAuthentication value unreadable" \
            "The HostbasedAuthentication line was present, but the value was not no or yes, so it is not graded." \
            "inspect HostbasedAuthentication on /QOpenSys/QIBM/UserData/SC1/OpenSSH/etc/sshd_config." \
            "cis-l1"
      fi
    fi
  fi

  # ssh_idle_timeout — IBM i OpenSSH idle timeout in sshd_config
  # (ClientAliveInterval + ClientAliveCountMax).
  # Authority: CIS IBM i V7R5M0/V7R4M0 5.4.6 (L1=Interval 1-300 and
  # CountMax 0). No L2 rec. One finding. Calls ibmi_sql for
  # IFS_OBJECT_STATISTICS on OpenSSH etc and IFS_READ_UTF8 of
  # sshd_config. Does not call ibmi_cl / DSPF / EDTF / sshd / cat.
  # Does not WHERE-filter ClientAlive lines (stock comments must
  # still yield LINE rows). Interval 1-300 with CountMax 0 is PASS.
  # Commented/missing ClientAlive (ship default) or Interval 0 is FAIL.
  IDLE_PRES=$(ibmi_sql sshd_config_present "SELECT 'PRESENT' CONCAT '|' CONCAT VARCHAR(PATH_NAME,1024) CONCAT '|' CONCAT VARCHAR(OBJECT_TYPE,10) FROM TABLE(QSYS2.IFS_OBJECT_STATISTICS(START_PATH_NAME => '/QOpenSys/QIBM/UserData/SC1/OpenSSH/etc', SUBTREE_DIRECTORIES => 'NO', IGNORE_ERRORS => 'NO')) WHERE PATH_NAME = '/QOpenSys/QIBM/UserData/SC1/OpenSSH/etc/sshd_config'")
  IDLE_PRES_RC=$?
  if [ "$IDLE_PRES_RC" -ne 0 ]; then
    add security ssh_idle_timeout "SSH idle timeout" NOT_ASSESSED low \
        "not assessed — capture failed (rc=$IDLE_PRES_RC)" \
        "The IFS_OBJECT_STATISTICS probe did not yield a readable OpenSSH etc listing, so the SSH idle timeout cannot be graded." \
        "re-run the scan as the scan profile and confirm QSYS2.IFS_OBJECT_STATISTICS can list /QOpenSys/QIBM/UserData/SC1/OpenSSH/etc. This scanner never changes SSH configuration." \
        "cis-l1"
  else
    IDLE_PLINE=$(printf '%s\n' "$IDLE_PRES" | awk -F'|' '$1=="PRESENT" && $2=="/QOpenSys/QIBM/UserData/SC1/OpenSSH/etc/sshd_config"{n++; line=$0} END{if(n==1) print line}')
    if [ -z "$IDLE_PLINE" ]; then
      add security ssh_idle_timeout "SSH idle timeout" NOT_ASSESSED low \
          "not assessed — sshd_config missing" \
          "The OpenSSH etc listing did not name sshd_config, so the SSH idle timeout cannot be graded." \
          "inspect /QOpenSys/QIBM/UserData/SC1/OpenSSH/etc/sshd_config and confirm the SSH server configuration file is present." \
          "cis-l1"
    else
      IDLE_TYPE=$(printf '%s\n' "$IDLE_PLINE" | awk -F'|' '{ v=$3; sub(/[ \t]+$/, "", v); print v }')
      if [ "$IDLE_TYPE" != "*STMF" ]; then
        add security ssh_idle_timeout "SSH idle timeout" NOT_ASSESSED low \
            "not assessed — sshd_config is not a stream file" \
            "The OpenSSH etc listing named sshd_config, but the object type was not *STMF, so the SSH idle timeout cannot be graded." \
            "inspect /QOpenSys/QIBM/UserData/SC1/OpenSSH/etc/sshd_config and confirm it is an IFS stream file." \
            "cis-l1"
      else
        IDLE_RAW=$(ibmi_sql sshd_config "SELECT 'LINE' CONCAT '|' CONCAT VARCHAR(LINE,1024) FROM TABLE(QSYS2.IFS_READ_UTF8(PATH_NAME => '/QOpenSys/QIBM/UserData/SC1/OpenSSH/etc/sshd_config', IGNORE_ERRORS => 'NO'))")
        IDLE_RC=$?
        if [ "$IDLE_RC" -ne 0 ]; then
          add security ssh_idle_timeout "SSH idle timeout" NOT_ASSESSED low \
              "not assessed — capture failed (rc=$IDLE_RC)" \
              "The IFS_READ_UTF8 probe did not yield a readable sshd_config, so the SSH idle timeout cannot be graded." \
              "re-run the scan as the scan profile and confirm the scan profile has *R on /QOpenSys/QIBM/UserData/SC1/OpenSSH/etc/sshd_config. This scanner never changes SSH configuration." \
              "cis-l1"
        else
          IDLE_PARSED=$(printf '%s\n' "$IDLE_RAW" | awk '
            function trim(s) {
              sub(/\r$/, "", s)
              sub(/^[ \t]+/, "", s)
              sub(/[ \t]+$/, "", s)
              return s
            }
            function kwval(raw, kw,    val, n, a) {
              val = raw
              sub("^" kw "[ \t]*=?[ \t]*", "", val)
              val = trim(val)
              n = split(val, a, /[ \t]+/)
              if (n != 1) return ""
              return a[1]
            }
            {
              raw = $0
              sub(/^LINE\|/, "", raw)
              raw = trim(raw)
              if (raw == "" || raw ~ /^#/) next
              low = tolower(raw)
              if (low ~ /^clientaliveinterval([ \t]|=|$)/) {
                if (ni == 0) ival = kwval(raw, "[Cc][Ll][Ii][Ee][Nn][Tt][Aa][Ll][Ii][Vv][Ee][Ii][Nn][Tt][Ee][Rr][Vv][Aa][Ll]")
                ni++
              }
              if (low ~ /^clientalivecountmax([ \t]|=|$)/) {
                if (nm == 0) mval = kwval(raw, "[Cc][Ll][Ii][Ee][Nn][Tt][Aa][Ll][Ii][Vv][Ee][Cc][Oo][Uu][Nn][Tt][Mm][Aa][Xx]")
                nm++
              }
            }
            END {
              if (ni+0 == 0) ival = "__UNSET__"
              if (nm+0 == 0) mval = "__UNSET__"
              print ival "|" mval
            }')
          IDLE_INT=${IDLE_PARSED%%\|*}
          IDLE_MAX=${IDLE_PARSED#*\|}
          if [ -z "$IDLE_INT" ] || [ -z "$IDLE_MAX" ]; then
            add security ssh_idle_timeout "SSH idle timeout" NOT_ASSESSED low \
                "not assessed — ClientAlive value unreadable" \
                "The ClientAliveInterval or ClientAliveCountMax line was present, but the value was not a single integer, so it is not graded." \
                "inspect ClientAliveInterval and ClientAliveCountMax on /QOpenSys/QIBM/UserData/SC1/OpenSSH/etc/sshd_config." \
                "cis-l1"
          elif [ "$IDLE_INT" = "__UNSET__" ] || [ "$IDLE_MAX" = "__UNSET__" ]; then
            if [ "$IDLE_INT" = "__UNSET__" ]; then
              IDLE_INT_OBS="(absent)"
            else
              IDLE_INT_OBS=$IDLE_INT
            fi
            if [ "$IDLE_MAX" = "__UNSET__" ]; then
              IDLE_MAX_OBS="(absent)"
            else
              IDLE_MAX_OBS=$IDLE_MAX
            fi
            add security ssh_idle_timeout "SSH idle timeout" FAIL high \
                "ClientAliveInterval=$IDLE_INT_OBS ClientAliveCountMax=$IDLE_MAX_OBS" \
                "sshd_config does not set both an idle interval of 1 to 300 seconds and ClientAliveCountMax 0, so idle SSH sessions are not required to disconnect." \
                "set ClientAliveInterval to a value from 1 to 300 and ClientAliveCountMax to 0 in /QOpenSys/QIBM/UserData/SC1/OpenSSH/etc/sshd_config and recycle the SSH server. This scanner never edits sshd_config." \
                "cis-l1"
          elif [ "$IDLE_MAX" != "0" ]; then
            add security ssh_idle_timeout "SSH idle timeout" FAIL high \
                "ClientAliveInterval=$IDLE_INT ClientAliveCountMax=$IDLE_MAX" \
                "sshd_config idle timeout is not ClientAliveInterval 1 to 300 with ClientAliveCountMax 0, so idle SSH sessions can stay open longer than five minutes." \
                "set ClientAliveInterval to a value from 1 to 300 and ClientAliveCountMax to 0 in /QOpenSys/QIBM/UserData/SC1/OpenSSH/etc/sshd_config and recycle the SSH server. This scanner never edits sshd_config." \
                "cis-l1"
          else
            IDLE_INT_OK=$(printf '%s\n' "$IDLE_INT" | awk '/^[1-9][0-9]*$/ && $1+0>=1 && $1+0<=300 { print "yes" }')
            if [ "$IDLE_INT_OK" = "yes" ]; then
              add security ssh_idle_timeout "SSH idle timeout" PASS low \
                  "ClientAliveInterval=$IDLE_INT ClientAliveCountMax=0" \
                  "sshd_config sets ClientAliveInterval between 1 and 300 and ClientAliveCountMax to 0, so idle SSH sessions disconnect within five minutes." \
                  "n/a" \
                  "cis-l1"
            else
              IDLE_INT_NUM=$(printf '%s\n' "$IDLE_INT" | awk '/^(0|[1-9][0-9]*)$/ { print "yes" }')
              if [ "$IDLE_INT_NUM" = "yes" ]; then
                add security ssh_idle_timeout "SSH idle timeout" FAIL high \
                    "ClientAliveInterval=$IDLE_INT ClientAliveCountMax=$IDLE_MAX" \
                    "sshd_config idle timeout is not ClientAliveInterval 1 to 300 with ClientAliveCountMax 0, so idle SSH sessions can stay open longer than five minutes." \
                    "set ClientAliveInterval to a value from 1 to 300 and ClientAliveCountMax to 0 in /QOpenSys/QIBM/UserData/SC1/OpenSSH/etc/sshd_config and recycle the SSH server. This scanner never edits sshd_config." \
                    "cis-l1"
              else
                add security ssh_idle_timeout "SSH idle timeout" NOT_ASSESSED low \
                    "not assessed — ClientAlive value unreadable" \
                    "The ClientAliveInterval or ClientAliveCountMax line was present, but the value was not a single integer, so it is not graded." \
                    "inspect ClientAliveInterval and ClientAliveCountMax on /QOpenSys/QIBM/UserData/SC1/OpenSSH/etc/sshd_config." \
                    "cis-l1"
              fi
            fi
          fi
        fi
      fi
    fi
  fi

  # ssh_limit_access — IBM i OpenSSH access limits
  # (sshd_config AllowUsers / AllowGroups / DenyUsers / DenyGroups).
  # Authority: CIS IBM i V7R5M0/V7R4M0 5.4.8 (L1=at least one with a value).
  # No L2 rec. One finding. Calls ibmi_sql for IFS_READ_UTF8 of UserData
  # sshd_config. Does not call ibmi_cl / DSPF / EDTF / sshd / NETSTAT / lslpp.
  # Does not SELECT LINE, Banner, Ciphers, HostbasedAuthentication, or Protocol.
  # At least one SET keyword is PASS. Absent or EMPTY-only is FAIL.
  # Probe rc: the IBM i db2 CLI returns 1 for a zero-row SELECT (no data) and
  # a genuine SQL error code otherwise. Zero rows is a readable absence of an
  # access-limit line, so rc=1 falls through to the FAIL branches; only a real
  # SQL error (observed rc=4, e.g. missing function) refuses.
  ACL_RAW=$(ibmi_sql sshd_cfg "SELECT 'ACL' CONCAT '|' CONCAT KW CONCAT '|' CONCAT FLAG FROM (SELECT CASE WHEN UPPER(W) LIKE 'ALLOWUSERS%' THEN 'AllowUsers' WHEN UPPER(W) LIKE 'ALLOWGROUPS%' THEN 'AllowGroups' WHEN UPPER(W) LIKE 'DENYUSERS%' THEN 'DenyUsers' WHEN UPPER(W) LIKE 'DENYGROUPS%' THEN 'DenyGroups' END AS KW, CASE WHEN UPPER(W) LIKE 'ALLOWUSERS %' AND LENGTH(TRIM(STRIP(TRIM(SUBSTR(W, 11)), LEADING, '='))) > 0 THEN 'SET' WHEN UPPER(W) LIKE 'ALLOWUSERS=%' AND LENGTH(TRIM(STRIP(TRIM(SUBSTR(W, 12)), LEADING, '='))) > 0 THEN 'SET' WHEN UPPER(W) LIKE 'ALLOWGROUPS %' AND LENGTH(TRIM(STRIP(TRIM(SUBSTR(W, 12)), LEADING, '='))) > 0 THEN 'SET' WHEN UPPER(W) LIKE 'ALLOWGROUPS=%' AND LENGTH(TRIM(STRIP(TRIM(SUBSTR(W, 13)), LEADING, '='))) > 0 THEN 'SET' WHEN UPPER(W) LIKE 'DENYUSERS %' AND LENGTH(TRIM(STRIP(TRIM(SUBSTR(W, 10)), LEADING, '='))) > 0 THEN 'SET' WHEN UPPER(W) LIKE 'DENYUSERS=%' AND LENGTH(TRIM(STRIP(TRIM(SUBSTR(W, 11)), LEADING, '='))) > 0 THEN 'SET' WHEN UPPER(W) LIKE 'DENYGROUPS %' AND LENGTH(TRIM(STRIP(TRIM(SUBSTR(W, 11)), LEADING, '='))) > 0 THEN 'SET' WHEN UPPER(W) LIKE 'DENYGROUPS=%' AND LENGTH(TRIM(STRIP(TRIM(SUBSTR(W, 12)), LEADING, '='))) > 0 THEN 'SET' ELSE 'EMPTY' END AS FLAG FROM (SELECT TRIM(CASE WHEN LOCATE('#', TRIM(LINE)) > 1 THEN SUBSTR(TRIM(LINE), 1, LOCATE('#', TRIM(LINE)) - 1) ELSE TRIM(LINE) END) AS W FROM TABLE(QSYS2.IFS_READ_UTF8(PATH_NAME => '/QOpenSys/QIBM/UserData/SC1/OpenSSH/etc/sshd_config', IGNORE_ERRORS => 'NO')) WHERE UPPER(TRIM(LINE)) = 'ALLOWUSERS' OR UPPER(TRIM(LINE)) LIKE 'ALLOWUSERS %' OR UPPER(TRIM(LINE)) LIKE 'ALLOWUSERS=%' OR UPPER(TRIM(LINE)) = 'ALLOWGROUPS' OR UPPER(TRIM(LINE)) LIKE 'ALLOWGROUPS %' OR UPPER(TRIM(LINE)) LIKE 'ALLOWGROUPS=%' OR UPPER(TRIM(LINE)) = 'DENYUSERS' OR UPPER(TRIM(LINE)) LIKE 'DENYUSERS %' OR UPPER(TRIM(LINE)) LIKE 'DENYUSERS=%' OR UPPER(TRIM(LINE)) = 'DENYGROUPS' OR UPPER(TRIM(LINE)) LIKE 'DENYGROUPS %' OR UPPER(TRIM(LINE)) LIKE 'DENYGROUPS=%') AS T1) AS T2")
  ACL_RC=$?
  if [ "$ACL_RC" -ne 0 ] && [ "$ACL_RC" -ne 1 ]; then
    add security ssh_limit_access "SSH limit access" NOT_ASSESSED low \
        "not assessed — capture failed (rc=$ACL_RC)" \
        "The sshd_config probe did not yield a readable SSH access-limit line, so SSH access limits cannot be graded." \
        "re-run the scan as the scan profile and confirm QSYS2.IFS_READ_UTF8 returns the UserData sshd_config. This scanner never edits sshd_config." \
        "cis-l1"
  elif [ -z "$ACL_RAW" ]; then
    add security ssh_limit_access "SSH limit access" FAIL high \
        "no AllowUsers/AllowGroups/DenyUsers/DenyGroups value in sshd_config" \
        "sshd_config does not limit which users or groups can log in over SSH." \
        "set at least one of AllowUsers, AllowGroups, DenyUsers, or DenyGroups with a non-empty value in /QOpenSys/QIBM/UserData/SC1/OpenSSH/etc/sshd_config and recycle the SSH server. This scanner never edits sshd_config." \
        "cis-l1"
  else
    ACL_LIST=$(printf '%s\n' "$ACL_RAW" | awk -F'|' '
      $1=="ACL" && $3=="SET" {
        if ($2=="AllowUsers") au=1
        else if ($2=="AllowGroups") ag=1
        else if ($2=="DenyUsers") du=1
        else if ($2=="DenyGroups") dg=1
      }
      END {
        n=0
        s=""
        if (au) { if (n++) s=s ", "; s=s "AllowUsers" }
        if (ag) { if (n++) s=s ", "; s=s "AllowGroups" }
        if (du) { if (n++) s=s ", "; s=s "DenyUsers" }
        if (dg) { if (n++) s=s ", "; s=s "DenyGroups" }
        print s
      }')
    if [ -z "$ACL_LIST" ]; then
      add security ssh_limit_access "SSH limit access" FAIL high \
          "no AllowUsers/AllowGroups/DenyUsers/DenyGroups value in sshd_config" \
          "sshd_config does not limit which users or groups can log in over SSH." \
          "set at least one of AllowUsers, AllowGroups, DenyUsers, or DenyGroups with a non-empty value in /QOpenSys/QIBM/UserData/SC1/OpenSSH/etc/sshd_config and recycle the SSH server. This scanner never edits sshd_config." \
          "cis-l1"
    else
      add security ssh_limit_access "SSH limit access" PASS low \
          "sshd_config restricts SSH access via: $ACL_LIST" \
          "sshd_config limits which users or groups can log in over SSH." \
          "n/a" \
          "cis-l1"
    fi
  fi

  # ssh_privsep — IBM i OpenSSH privilege separation
  # (sshd_config UsePrivilegeSeparation).
  # Authority: CIS IBM i V7R5M0/V7R4M0 5.4.4 (L1=UsePrivilegeSeparation yes).
  # No L2 rec. One finding. Calls ibmi_sql for IFS_READ_UTF8 of UserData
  # sshd_config. Does not call ibmi_cl / DSPF / EDTF / sshd / NETSTAT / lslpp.
  # Does not SELECT Banner, AllowUsers, HostbasedAuthentication, or Protocol.
  # Exact UsePrivilegeSeparation yes or sandbox is PASS. Exact no or absent
  # is FAIL. OpenSSH 8.0p1 deprecation does not make absence PASS.
  # DB2 TRIM strips blanks, not tabs. X'05' is the EBCDIC tab; translate tabs
  # to spaces before the match so UsePrivilegeSeparation<TAB>yes (and a
  # tab-indented line) reaches the parser's [ \t] value handling instead of
  # grading absent.
  PRIVSEP_RAW=$(ibmi_sql sshd_cfg "SELECT 'PRIVSEP' CONCAT '|' CONCAT VARCHAR(COALESCE(TRIM(LINE),''),64) FROM TABLE(QSYS2.IFS_READ_UTF8(PATH_NAME => '/QOpenSys/QIBM/UserData/SC1/OpenSSH/etc/sshd_config', IGNORE_ERRORS => 'NO')) WHERE UPPER(TRIM(REPLACE(LINE, X'05', ' '))) = 'USEPRIVILEGESEPARATION' OR UPPER(TRIM(REPLACE(LINE, X'05', ' '))) LIKE 'USEPRIVILEGESEPARATION %' OR UPPER(TRIM(REPLACE(LINE, X'05', ' '))) LIKE 'USEPRIVILEGESEPARATION=%'")
  PRIVSEP_RC=$?
  # IBM i db2 CLI returns rc=1 for a successful SELECT that matches zero rows.
  # That is the absent UsePrivilegeSeparation case (graded FAIL below), not a
  # capture failure; genuine probe errors (missing function / bad SQL) are rc>1.
  if [ "$PRIVSEP_RC" -ne 0 ] && [ "$PRIVSEP_RC" -ne 1 ]; then
    add security ssh_privsep "SSH privilege separation" NOT_ASSESSED low \
        "not assessed — capture failed (rc=$PRIVSEP_RC)" \
        "The sshd_config probe did not yield a readable UsePrivilegeSeparation line, so SSH privilege separation cannot be graded." \
        "re-run the scan as the scan profile and confirm QSYS2.IFS_READ_UTF8 returns the UserData sshd_config. This scanner never edits sshd_config." \
        "cis-l1"
  elif [ -z "$PRIVSEP_RAW" ]; then
    add security ssh_privsep "SSH privilege separation" FAIL high \
        "UsePrivilegeSeparation=(absent)" \
        "SSH privilege separation is not explicitly set to yes, so sshd_config does not require an unprivileged child process for network traffic." \
        "set UsePrivilegeSeparation yes in /QOpenSys/QIBM/UserData/SC1/OpenSSH/etc/sshd_config and recycle the SSH server. This scanner never edits sshd_config." \
        "cis-l1"
  else
    PRIVSEP_LINE=$(printf '%s\n' "$PRIVSEP_RAW" | awk -F'|' '$1=="PRIVSEP"{n++; line=$0} END{if(n==1) print line}')
    if [ -z "$PRIVSEP_LINE" ]; then
      PRIVSEP_N=$(printf '%s\n' "$PRIVSEP_RAW" | awk -F'|' '$1=="PRIVSEP"{n++} END{print n+0}')
      if [ "$PRIVSEP_N" -eq 0 ]; then
        add security ssh_privsep "SSH privilege separation" FAIL high \
            "UsePrivilegeSeparation=(absent)" \
            "SSH privilege separation is not explicitly set to yes, so sshd_config does not require an unprivileged child process for network traffic." \
            "set UsePrivilegeSeparation yes in /QOpenSys/QIBM/UserData/SC1/OpenSSH/etc/sshd_config and recycle the SSH server. This scanner never edits sshd_config." \
            "cis-l1"
      else
        add security ssh_privsep "SSH privilege separation" NOT_ASSESSED low \
            "not assessed — UsePrivilegeSeparation row missing or not unique in sshd_config" \
            "The sshd_config dump was readable, but it did not contain exactly one uncommented UsePrivilegeSeparation line, so the value cannot be graded." \
            "inspect /QOpenSys/QIBM/UserData/SC1/OpenSSH/etc/sshd_config for a single uncommented UsePrivilegeSeparation line." \
            "cis-l1"
      fi
    else
      PRIVSEP_VAL=$(printf '%s\n' "$PRIVSEP_LINE" | awk -F'|' '{
        v=$2
        sub(/[ \t]+$/, "", v)
        sub(/#.*$/, "", v)
        sub(/[ \t]+$/, "", v)
        low = tolower(v)
        if (low !~ /^useprivilegeseparation([ \t]|=|$)/) { print ""; exit }
        sub(/^[Uu][Ss][Ee][Pp][Rr][Ii][Vv][Ii][Ll][Ee][Gg][Ee][Ss][Ee][Pp][Aa][Rr][Aa][Tt][Ii][Oo][Nn][ \t]*=?[ \t]*/, "", v)
        sub(/^[ \t]+/, "", v)
        sub(/[ \t]+$/, "", v)
        n=split(v, a, /[ \t]+/)
        if (n != 1) { print ""; exit }
        print a[1]
      }')
      if [ -z "$PRIVSEP_VAL" ]; then
        add security ssh_privsep "SSH privilege separation" NOT_ASSESSED low \
            "not assessed — UsePrivilegeSeparation value unreadable" \
            "The UsePrivilegeSeparation line was present, but the value was empty, so it is not graded." \
            "inspect UsePrivilegeSeparation on /QOpenSys/QIBM/UserData/SC1/OpenSSH/etc/sshd_config." \
            "cis-l1"
      elif [ "$PRIVSEP_VAL" = "yes" ] || [ "$PRIVSEP_VAL" = "Yes" ] || [ "$PRIVSEP_VAL" = "YES" ]; then
        add security ssh_privsep "SSH privilege separation" PASS low \
            "UsePrivilegeSeparation=yes" \
            "SSH privilege separation is yes, so the daemon handles network traffic in an unprivileged child process." \
            "n/a" \
            "cis-l1"
      elif [ "$PRIVSEP_VAL" = "sandbox" ] || [ "$PRIVSEP_VAL" = "Sandbox" ] || [ "$PRIVSEP_VAL" = "SANDBOX" ]; then
        add security ssh_privsep "SSH privilege separation" PASS low \
            "UsePrivilegeSeparation=sandbox" \
            "SSH privilege separation is sandbox, so the daemon handles network traffic in a restricted unprivileged child process." \
            "n/a" \
            "cis-l1"
      elif [ "$PRIVSEP_VAL" = "no" ] || [ "$PRIVSEP_VAL" = "No" ] || [ "$PRIVSEP_VAL" = "NO" ]; then
        add security ssh_privsep "SSH privilege separation" FAIL high \
            "UsePrivilegeSeparation=$PRIVSEP_VAL" \
            "SSH privilege separation is no, so the daemon handles network traffic in the privileged listener process." \
            "set UsePrivilegeSeparation yes in /QOpenSys/QIBM/UserData/SC1/OpenSSH/etc/sshd_config and recycle the SSH server. This scanner never edits sshd_config." \
            "cis-l1"
      else
        add security ssh_privsep "SSH privilege separation" NOT_ASSESSED low \
            "not assessed — UsePrivilegeSeparation value unreadable" \
            "The UsePrivilegeSeparation line was present, but the value was not yes, sandbox, or no, so it is not graded." \
            "inspect UsePrivilegeSeparation on /QOpenSys/QIBM/UserData/SC1/OpenSSH/etc/sshd_config." \
            "cis-l1"
      fi
    fi
  fi

  # ssh_protocol — IBM i OpenSSH server protocol (sshd_config Protocol).
  # Authority: CIS IBM i V7R5M0/V7R4M0 5.4.1 (L1=Protocol 2). No L2 rec.
  # One finding. Calls ibmi_sql for IFS_READ_UTF8 of UserData sshd_config.
  # Does not call ibmi_cl / DSPF / EDTF / sshd / NETSTAT. Does not SELECT Banner.
  # Exact Protocol 2 is PASS. Exact 1 / 2,1 / 1,2 or absent is FAIL.
  PROTO_RAW=$(ibmi_sql sshd_cfg "SELECT 'PROTOCOL' CONCAT '|' CONCAT VARCHAR(COALESCE(TRIM(REPLACE(LINE, CHR(9), ' ')),''),64) FROM TABLE(QSYS2.IFS_READ_UTF8(PATH_NAME => '/QOpenSys/QIBM/UserData/SC1/OpenSSH/etc/sshd_config', IGNORE_ERRORS => 'NO')) WHERE UPPER(TRIM(REPLACE(LINE, CHR(9), ' '))) = 'PROTOCOL' OR UPPER(TRIM(REPLACE(LINE, CHR(9), ' '))) LIKE 'PROTOCOL %'")
  PROTO_RC=$?
  if [ "$PROTO_RC" -ge 2 ]; then
    add security ssh_protocol "SSH protocol" NOT_ASSESSED low \
        "not assessed — capture failed (rc=$PROTO_RC)" \
        "The sshd_config probe did not yield a readable Protocol line, so SSH server protocol cannot be graded." \
        "re-run the scan as the scan profile and confirm QSYS2.IFS_READ_UTF8 returns the UserData sshd_config. This scanner never edits sshd_config." \
        "cis-l1"
  elif [ "$PROTO_RC" -eq 0 ] && [ -z "$PROTO_RAW" ]; then
    add security ssh_protocol "SSH protocol" NOT_ASSESSED low \
        "not assessed — capture empty (rc=0)" \
        "The sshd_config probe returned no pipe row at rc 0, which is the swallowed mid-fetch-error signature, so SSH server protocol cannot be graded." \
        "re-run the scan as the scan profile and confirm QSYS2.IFS_READ_UTF8 returns the UserData sshd_config. This scanner never edits sshd_config." \
        "cis-l1"
  elif [ "$PROTO_RC" -eq 1 ] && [ -z "$PROTO_RAW" ]; then
    add security ssh_protocol "SSH protocol" FAIL high \
        "Protocol=(absent)" \
        "SSH server protocol is not explicitly set to 2, so SSH protocol 1 is not ruled out by sshd_config." \
        "set Protocol 2 in /QOpenSys/QIBM/UserData/SC1/OpenSSH/etc/sshd_config and recycle the SSH server. This scanner never edits sshd_config." \
        "cis-l1"
  else
    PROTO_LINE=$(printf '%s\n' "$PROTO_RAW" | awk -F'|' '$1=="PROTOCOL"{n++; line=$0} END{if(n==1) print line}')
    if [ -z "$PROTO_LINE" ]; then
      PROTO_N=$(printf '%s\n' "$PROTO_RAW" | awk -F'|' '$1=="PROTOCOL"{n++} END{print n+0}')
      if [ "$PROTO_N" -eq 0 ]; then
        add security ssh_protocol "SSH protocol" FAIL high \
            "Protocol=(absent)" \
            "SSH server protocol is not explicitly set to 2, so SSH protocol 1 is not ruled out by sshd_config." \
            "set Protocol 2 in /QOpenSys/QIBM/UserData/SC1/OpenSSH/etc/sshd_config and recycle the SSH server. This scanner never edits sshd_config." \
            "cis-l1"
      else
        add security ssh_protocol "SSH protocol" NOT_ASSESSED low \
            "not assessed — Protocol row missing or not unique in sshd_config" \
            "The sshd_config dump was readable, but it did not contain exactly one uncommented Protocol line, so the value cannot be graded." \
            "inspect /QOpenSys/QIBM/UserData/SC1/OpenSSH/etc/sshd_config for a single uncommented Protocol line." \
            "cis-l1"
      fi
    else
      PROTO_VAL=$(printf '%s\n' "$PROTO_LINE" | awk -F'|' '{
        v=$2
        sub(/[ \t]+$/, "", v)
        sub(/#.*$/, "", v)
        sub(/[ \t]+$/, "", v)
        n=split(v, a, /[ \t]+/)
        if (n < 2) { print ""; exit }
        print a[2]
      }')
      if [ -z "$PROTO_VAL" ]; then
        add security ssh_protocol "SSH protocol" NOT_ASSESSED low \
            "not assessed — Protocol value unreadable" \
            "The Protocol line was present, but the value was empty, so it is not graded." \
            "inspect Protocol on /QOpenSys/QIBM/UserData/SC1/OpenSSH/etc/sshd_config." \
            "cis-l1"
      elif [ "$PROTO_VAL" = "2" ]; then
        add security ssh_protocol "SSH protocol" PASS low \
            "Protocol=2" \
            "SSH server protocol is 2, so the daemon does not offer SSH protocol 1." \
            "n/a" \
            "cis-l1"
      elif [ "$PROTO_VAL" = "1" ] || [ "$PROTO_VAL" = "2,1" ] || [ "$PROTO_VAL" = "1,2" ]; then
        add security ssh_protocol "SSH protocol" FAIL high \
            "Protocol=$PROTO_VAL" \
            "SSH server protocol is not 2, so the daemon can offer SSH protocol 1." \
            "set Protocol 2 in /QOpenSys/QIBM/UserData/SC1/OpenSSH/etc/sshd_config and recycle the SSH server. This scanner never edits sshd_config." \
            "cis-l1"
      else
        add security ssh_protocol "SSH protocol" NOT_ASSESSED low \
            "not assessed — Protocol value unreadable" \
            "The Protocol line was present, but the value was not 2, 1, 2,1, or 1,2, so it is not graded." \
            "inspect Protocol on /QOpenSys/QIBM/UserData/SC1/OpenSSH/etc/sshd_config." \
            "cis-l1"
      fi
    fi
  fi

  # sst_dup_password — IBM i SST duplicate password control
  # (CHGSSTSECA DUPPWDCTL).
  # Authority: CIS IBM i V7R5M0/V7R4M0 5.6.3 (L1=18). No L2 rec.
  # One finding. Calls ibmi_cl sst_sec DSPSSTSECA. Parses the
  # Duplicate password control line (token after last colon).
  # Does not call ibmi_sql. Does not query SST_SECURITY_INFO
  # (BANNED) or SECURITY_INFO (that QPWDRQDDIF column is
  # ck-sv-qpwdrqddif). Does not CHGSSTSECA / STRSST.
  # Exact 18 is PASS. *NONE, 0, or any other integer 0-32 is
  # FAIL. IBM ship default 18 is PASS. IBM max 32 is FAIL.
  # Exact 18 only.
  SST_RAW=$(ibmi_cl sst_sec "DSPSSTSECA")
  SST_RC=$?
  if [ "$SST_RC" -ne 0 ]; then
    add security sst_dup_password "SST duplicate password control" NOT_ASSESSED low \
        "not assessed — capture failed (rc=$SST_RC)" \
        "The SST security-attribute probe did not yield a readable duplicate password control, so the SST history cannot be graded." \
        "re-run the scan as the scan profile and confirm DSPSSTSECA returns Duplicate password control. This scanner never changes SST security attributes." \
        "cis-l1"
  elif [ -z "$SST_RAW" ]; then
    add security sst_dup_password "SST duplicate password control" NOT_ASSESSED low \
        "not assessed — capture empty (rc=0)" \
        "The SST security-attribute probe returned no attribute line, so the SST history cannot be graded." \
        "re-run the scan as the scan profile and confirm DSPSSTSECA returns Duplicate password control. This scanner never changes SST security attributes." \
        "cis-l1"
  else
    SST_LINE=$(printf '%s\n' "$SST_RAW" | awk 'index($0,"Duplicate password control"){n++; line=$0} END{if(n==1) print line}')
    if [ -z "$SST_LINE" ]; then
      add security sst_dup_password "SST duplicate password control" NOT_ASSESSED low \
          "not assessed — Duplicate password control line missing or not unique in DSPSSTSECA" \
          "The SST security-attribute dump was readable, but it did not contain exactly one Duplicate password control line, so the value cannot be graded." \
          "inspect DSPSSTSECA for Duplicate password control." \
          "cis-l1"
    else
      SST_VAL=$(printf '%s\n' "$SST_LINE" | awk -F: '{ v=$NF; sub(/^[ \t]+/, "", v); sub(/[ \t]+$/, "", v); print v }')
      if [ -z "$SST_VAL" ]; then
        add security sst_dup_password "SST duplicate password control" NOT_ASSESSED low \
            "not assessed — SST DUPPWDCTL value unreadable" \
            "The Duplicate password control line was present, but the value was empty, so it is not graded." \
            "inspect SST duplicate password control on DSPSSTSECA." \
            "cis-l1"
      elif [ "$SST_VAL" = "*NONE" ]; then
        add security sst_dup_password "SST duplicate password control" FAIL high \
            "DUPPWDCTL=*NONE" \
            "SST duplicate password control is not 18, so recently used SST passwords are not blocked for an 18-password history." \
            "set SST duplicate password control to 18 using CHGSSTSECA DUPPWDCTL(18). This scanner never changes SST security attributes." \
            "cis-l1"
      else
        SSTN=$(printf '%s\n' "$SST_VAL" | awk '/^[0-9]+$/{ if ($0 ~ /^0+$/) print 0; else { sub(/^0+/,""); print } }')
        if [ -z "$SSTN" ] || [ "$SSTN" -lt 0 ] || [ "$SSTN" -gt 32 ]; then
          add security sst_dup_password "SST duplicate password control" NOT_ASSESSED low \
              "not assessed — SST DUPPWDCTL value unreadable" \
              "The Duplicate password control line was present, but the value was not an integer 0-32 or *NONE, so it is not graded." \
              "inspect SST duplicate password control on DSPSSTSECA." \
              "cis-l1"
        elif [ "$SSTN" -eq 18 ]; then
          add security sst_dup_password "SST duplicate password control" PASS low \
              "DUPPWDCTL=18" \
              "SST duplicate password control is 18, so the previous 18 SST passwords cannot be reused." \
              "n/a" \
              "cis-l1"
        else
          add security sst_dup_password "SST duplicate password control" FAIL high \
              "DUPPWDCTL=$SSTN" \
              "SST duplicate password control is not 18, so SST password reuse is limited to a different history than the required 18." \
              "set SST duplicate password control to 18 using CHGSSTSECA DUPPWDCTL(18). This scanner never changes SST security attributes." \
              "cis-l1"
        fi
      fi
    fi
  fi

  # sst_lock_sysval — IBM i SST allow change of security-related
  # system values (CHGSSTSECA SECSYSVAL).
  # Authority: CIS IBM i V7R5M0/V7R4M0 5.6.7 (L1=NO / *NO). No L2 rec.
  # One finding. Calls ibmi_sql for SECURITY_INFO
  # ALLOW_SECURITY_SYSVAL_CHANGE. Does not call ibmi_cl /
  # DSPSSTSECA / CHGSSTSECA / STRSST / CHGSYSVAL. Does not
  # SELECT SST_SECURITY_INFO (that view is absent). Does not
  # SELECT ALLOW_DIGITAL_CERTIFICATE_ADD (ck-sst-new-certs) or
  # ALLOW_PASSWORD_EXIT_PROGRAM_ADD_REMOVE (5.6.9). Exact NO
  # is PASS. Exact YES is FAIL. IBM ship default YES is FAIL.
  # *NO / 0 are not catalog tokens.
  SST_RAW=$(ibmi_sql sst_sec "SELECT 'SECSYSVAL' CONCAT '|' CONCAT VARCHAR(COALESCE(TRIM(ALLOW_SECURITY_SYSVAL_CHANGE),''),3) FROM QSYS2.SECURITY_INFO")
  SST_RC=$?
  if [ "$SST_RC" -ne 0 ]; then
    add security sst_lock_sysval "SST lock security-related system values" NOT_ASSESSED low \
        "not assessed — capture failed (rc=$SST_RC)" \
        "The SST security-attribute probe did not yield a readable allow-change-of-security-related-system-values flag, so the SST sysval lock cannot be graded." \
        "re-run the scan as the scan profile and confirm QSYS2.SECURITY_INFO returns ALLOW_SECURITY_SYSVAL_CHANGE. This scanner never changes SST security attributes." \
        "cis-l1"
  elif [ -z "$SST_RAW" ]; then
    add security sst_lock_sysval "SST lock security-related system values" NOT_ASSESSED low \
        "not assessed — capture empty (rc=0)" \
        "The SST security-attribute probe returned no pipe row, so the SST sysval lock cannot be graded." \
        "re-run the scan as the scan profile and confirm QSYS2.SECURITY_INFO returns ALLOW_SECURITY_SYSVAL_CHANGE. This scanner never changes SST security attributes." \
        "cis-l1"
  else
    SST_LINE=$(printf '%s\n' "$SST_RAW" | awk -F'|' '$1=="SECSYSVAL"{n++; line=$0} END{if(n==1) print line}')
    if [ -z "$SST_LINE" ]; then
      add security sst_lock_sysval "SST lock security-related system values" NOT_ASSESSED low \
          "not assessed — SECSYSVAL row missing or not unique in SST security attributes" \
          "The SST security-attribute dump was readable, but it did not contain exactly one SECSYSVAL row, so the value cannot be graded." \
          "inspect QSYS2.SECURITY_INFO for ALLOW_SECURITY_SYSVAL_CHANGE." \
          "cis-l1"
    else
      SST_VAL=$(printf '%s\n' "$SST_LINE" | awk -F'|' '{ v=$2; sub(/[ \t]+$/, "", v); print v }')
      if [ -z "$SST_VAL" ]; then
        add security sst_lock_sysval "SST lock security-related system values" NOT_ASSESSED low \
            "not assessed — SST SECSYSVAL value unreadable" \
            "The SECSYSVAL row was present, but the catalog value was empty, so it is not graded." \
            "inspect SST allow security sysval changes on QSYS2.SECURITY_INFO and DSPSSTSECA." \
            "cis-l1"
      elif [ "$SST_VAL" = "NO" ]; then
        add security sst_lock_sysval "SST lock security-related system values" PASS low \
            "SECSYSVAL=NO" \
            "SST allow-change of security-related system values is NO, so CHGSYSVAL cannot change those lockable system values." \
            "n/a" \
            "cis-l1"
      elif [ "$SST_VAL" = "YES" ]; then
        add security sst_lock_sysval "SST lock security-related system values" FAIL high \
            "SECSYSVAL=YES" \
            "SST allow-change of security-related system values is YES, so CHGSYSVAL can change those lockable system values." \
            "set SST allow security sysval changes to *NO using CHGSSTSECA SECSYSVAL(*NO). This scanner never changes SST security attributes." \
            "cis-l1"
      else
        add security sst_lock_sysval "SST lock security-related system values" NOT_ASSESSED low \
            "not assessed — SST SECSYSVAL value unreadable" \
            "The SECSYSVAL row was present, but the catalog value was not YES or NO, so it is not graded." \
            "inspect SST allow security sysval changes on QSYS2.SECURITY_INFO and DSPSSTSECA." \
            "cis-l1"
      fi
    fi
  fi

  # sst_maxsign — IBM i SST maximum sign-on attempts (CHGSSTSECA MAXSGN).
  # Authority: CIS IBM i V7R5M0/V7R4M0 5.6.2 (L1=5). No L2 rec.
  # One finding. Calls ibmi_cl for DSPSSTSECA. Parses the
  # Maximum sign-on attempts line (token after last colon).
  # Does not call ibmi_sql. Does not query SST_SECURITY_INFO
  # (that view does not exist). Does not SELECT
  # SYSTEM_VALUE_INFO (the QMAXSIGN column is not yet covered by a check).
  # Does not CHGSSTSECA. Exact 5 is PASS. Any other integer
  # 2-15 is FAIL. IBM ship default 3 is FAIL. Lower is not
  # stricter on this control. PTSCAN CPFB304 / ibmi_cl rc
  # != 0 is NOT_ASSESSED, never PASS.
  SST_RAW=$(ibmi_cl sst_sec "DSPSSTSECA")
  SST_RC=$?
  SST_AUTH=$(printf '%s\n' "$SST_RAW" | awk 'tolower($0) ~ /cpfb304/ { n=1 } END { if (n) print 1 }')
  if [ -n "$SST_AUTH" ]; then
    add security sst_maxsign "SST maximum sign-on attempts" NOT_ASSESSED low \
        "not assessed — DSPSSTSECA CPFB304 (scan profile lacks *SECADM)" \
        "The scan profile cannot display SST security attributes (DSPSSTSECA CPFB304), so the SST max-signon limit cannot be graded." \
        "the profile running xray needs *SECADM to run DSPSSTSECA; grant: CHGUSRPRF USRPRF(scan-profile) SPCAUT(*SECADM). This scanner never changes SST security attributes or user profiles." \
        "cis-l1"
  elif [ "$SST_RC" -ne 0 ]; then
    add security sst_maxsign "SST maximum sign-on attempts" NOT_ASSESSED low \
        "not assessed — capture failed (rc=$SST_RC)" \
        "The SST security-attribute probe did not yield a readable maximum sign-on attempts value, so the SST max-signon limit cannot be graded." \
        "re-run the scan as a profile with *SECADM and confirm DSPSSTSECA returns the Maximum sign-on attempts line. A PTSCAN CPFB304 is this refusal. This scanner never changes SST security attributes." \
        "cis-l1"
  elif [ -z "$SST_RAW" ]; then
    add security sst_maxsign "SST maximum sign-on attempts" NOT_ASSESSED low \
        "not assessed — capture empty (rc=0)" \
        "The SST security-attribute probe returned no text, so the SST max-signon limit cannot be graded." \
        "re-run the scan as a profile with *SECADM and confirm DSPSSTSECA returns the Maximum sign-on attempts line. This scanner never changes SST security attributes." \
        "cis-l1"
  else
    SST_LINE=$(printf '%s\n' "$SST_RAW" | awk 'index($0, "Maximum sign-on attempts") { n++; line=$0 } END { if (n==1) print line }')
    if [ -z "$SST_LINE" ]; then
      add security sst_maxsign "SST maximum sign-on attempts" NOT_ASSESSED low \
          "not assessed — Maximum sign-on attempts line missing or not unique in DSPSSTSECA" \
          "The DSPSSTSECA dump was readable, but it did not contain exactly one Maximum sign-on attempts line, so the value cannot be graded." \
          "inspect DSPSSTSECA for the Maximum sign-on attempts line." \
          "cis-l1"
    else
      SST_VAL=$(printf '%s\n' "$SST_LINE" | awk -F: '{ v=$NF; gsub(/\r/, "", v); sub(/^[ \t]+/, "", v); sub(/[ \t]+$/, "", v); print v }')
      if [ -z "$SST_VAL" ]; then
        add security sst_maxsign "SST maximum sign-on attempts" NOT_ASSESSED low \
            "not assessed — SST MAXSGN value unreadable" \
            "The Maximum sign-on attempts line was present, but the value after the last colon was empty, so it is not graded." \
            "inspect SST maximum sign-on attempts on DSPSSTSECA." \
            "cis-l1"
      else
        SSTN=$(printf '%s\n' "$SST_VAL" | awk '/^[0-9]+$/{ if ($0 ~ /^0+$/) print 0; else { sub(/^0+/,""); print } }')
        if [ -z "$SSTN" ] || [ "$SSTN" -lt 2 ] || [ "$SSTN" -gt 15 ]; then
          add security sst_maxsign "SST maximum sign-on attempts" NOT_ASSESSED low \
              "not assessed — SST MAXSGN value unreadable" \
              "The Maximum sign-on attempts line was present, but the value was not an integer 2-15, so it is not graded." \
              "inspect SST maximum sign-on attempts on DSPSSTSECA." \
              "cis-l1"
        elif [ "$SSTN" -eq 5 ]; then
          add security sst_maxsign "SST maximum sign-on attempts" PASS low \
              "MAXSGN=5" \
              "SST maximum sign-on attempts is 5, so a service-tools user ID is disabled after 5 failed sign-on attempts." \
              "n/a" \
              "cis-l1"
        else
          add security sst_maxsign "SST maximum sign-on attempts" FAIL high \
              "MAXSGN=$SSTN" \
              "SST maximum sign-on attempts is not 5, so a service-tools user ID is not disabled after exactly 5 failed sign-on attempts." \
              "set SST maximum sign-on attempts to 5 using CHGSSTSECA MAXSGN(5). This scanner never changes SST security attributes." \
              "cis-l1"
        fi
      fi
    fi
  fi

  # sst_new_certs — IBM i SST allow add of digital certificates
  # (CHGSSTSECA ADDDIGCERT).
  # Authority: CIS IBM i V7R5M0/V7R4M0 5.6.5 (L1=NO / *NO). No L2 rec.
  # One finding. Calls ibmi_sql for SECURITY_INFO
  # ALLOW_DIGITAL_CERTIFICATE_ADD. Does not call ibmi_cl /
  # DSPSSTSECA / CHGSSTSECA / STRSST. Does not SELECT
  # SST_SECURITY_INFO (that view is absent). Does not SELECT
  # ALLOW_SECURITY_SYSVAL_CHANGE (ck-sst-lock-sysval) or
  # ALLOW_PASSWORD_EXIT_PROGRAM_ADD_REMOVE (5.6.9). Exact NO
  # is PASS. Exact YES is FAIL. *NO / 0 are not catalog tokens.
  SST_RAW=$(ibmi_sql sst_sec "SELECT 'ADDDIGCERT' CONCAT '|' CONCAT VARCHAR(COALESCE(TRIM(ALLOW_DIGITAL_CERTIFICATE_ADD),''),3) FROM QSYS2.SECURITY_INFO")
  SST_RC=$?
  if [ "$SST_RC" -ne 0 ]; then
    add security sst_new_certs "SST allow new digital certificates" NOT_ASSESSED low \
        "not assessed — capture failed (rc=$SST_RC)" \
        "The SST security-attribute probe did not yield a readable allow-add-of-digital-certificates flag, so the SST certificate-add control cannot be graded." \
        "re-run the scan as the scan profile and confirm QSYS2.SECURITY_INFO returns ALLOW_DIGITAL_CERTIFICATE_ADD. This scanner never changes SST security attributes." \
        "cis-l1"
  elif [ -z "$SST_RAW" ]; then
    add security sst_new_certs "SST allow new digital certificates" NOT_ASSESSED low \
        "not assessed — capture empty (rc=0)" \
        "The SST security-attribute probe returned no pipe row, so the SST certificate-add control cannot be graded." \
        "re-run the scan as the scan profile and confirm QSYS2.SECURITY_INFO returns ALLOW_DIGITAL_CERTIFICATE_ADD. This scanner never changes SST security attributes." \
        "cis-l1"
  else
    SST_LINE=$(printf '%s\n' "$SST_RAW" | awk -F'|' '$1=="ADDDIGCERT"{n++; line=$0} END{if(n==1) print line}')
    if [ -z "$SST_LINE" ]; then
      add security sst_new_certs "SST allow new digital certificates" NOT_ASSESSED low \
          "not assessed — ADDDIGCERT row missing or not unique in SST security attributes" \
          "The SST security-attribute dump was readable, but it did not contain exactly one ADDDIGCERT row, so the value cannot be graded." \
          "inspect QSYS2.SECURITY_INFO for ALLOW_DIGITAL_CERTIFICATE_ADD." \
          "cis-l1"
    else
      SST_VAL=$(printf '%s\n' "$SST_LINE" | awk -F'|' '{ v=$2; sub(/[ \t]+$/, "", v); print v }')
      if [ -z "$SST_VAL" ]; then
        add security sst_new_certs "SST allow new digital certificates" NOT_ASSESSED low \
            "not assessed — SST ADDDIGCERT value unreadable" \
            "The ADDDIGCERT row was present, but the catalog value was empty, so it is not graded." \
            "inspect SST allow add of digital certificates on QSYS2.SECURITY_INFO and DSPSSTSECA." \
            "cis-l1"
      elif [ "$SST_VAL" = "NO" ]; then
        add security sst_new_certs "SST allow new digital certificates" PASS low \
            "ADDDIGCERT=NO" \
            "SST allow-add of digital certificates is NO, so digital certificates cannot be added with the Add Verifier API and certificate-store passwords cannot be reset using Digital Certificate Manager." \
            "n/a" \
            "cis-l1"
      elif [ "$SST_VAL" = "YES" ]; then
        add security sst_new_certs "SST allow new digital certificates" FAIL high \
            "ADDDIGCERT=YES" \
            "SST allow-add of digital certificates is YES, so digital certificates can be added with the Add Verifier API and certificate-store passwords can be reset using Digital Certificate Manager." \
            "set SST allow add of digital certificates to *NO using CHGSSTSECA ADDDIGCERT(*NO). This scanner never changes SST security attributes." \
            "cis-l1"
      else
        add security sst_new_certs "SST allow new digital certificates" NOT_ASSESSED low \
            "not assessed — SST ADDDIGCERT value unreadable" \
            "The ADDDIGCERT row was present, but the catalog value was not YES or NO, so it is not graded." \
            "inspect SST allow add of digital certificates on QSYS2.SECURITY_INFO and DSPSSTSECA." \
            "cis-l1"
      fi
    fi
  fi

  # sst_pwdexpitv — IBM i SST password expiration interval (CHGSSTSECA PWDEXPITV).
  # Authority: CIS IBM i V7R5M0/V7R4M0 5.6.1 (L1=365). No L2 rec.
  # One finding. Calls ibmi_cl for DSPSSTSECA. Does not call
  # ibmi_sql / DSPSSTUSR / CHGSSTSECA / STRSST. Does not SELECT
  # SST_* views (they do not exist) or SECURITY_INFO
  # (that QPWDEXPITV column is ck-sv-qpwdexpitv). Exact 365 is PASS.
  # *NOMAX or any other integer 1-366 is FAIL. IBM ship default 180
  # is FAIL. Shorter is not stricter on this control.
  # CPFB304 / ibmi_cl rc != 0 is NOT_ASSESSED (profile needs *SECADM).
  SST_RAW=$(ibmi_cl sst_sec "DSPSSTSECA")
  SST_RC=$?
  SST_AUTH=$(printf '%s\n' "$SST_RAW" | awk 'tolower($0) ~ /cpfb304/ { n=1 } END { if (n) print 1 }')
  if [ "$SST_RC" -ne 0 ] || [ -n "$SST_AUTH" ]; then
    add security sst_pwdexpitv "SST password expiration interval" NOT_ASSESSED low \
        "not assessed — capture failed (rc=$SST_RC)" \
        "The profile running this scan needs *SECADM to read DSPSSTSECA, so the SST password expiration interval cannot be graded." \
        "grant *SECADM to the scan profile and re-run. This scanner never changes SST security attributes." \
        "cis-l1"
  elif [ -z "$SST_RAW" ]; then
    add security sst_pwdexpitv "SST password expiration interval" NOT_ASSESSED low \
        "not assessed — capture empty (rc=0)" \
        "The DSPSSTSECA probe returned no text, so the SST interval cannot be graded." \
        "re-run the scan as the scan profile and confirm DSPSSTSECA returns Password expiration interval. This scanner never changes SST security attributes." \
        "cis-l1"
  else
    SST_LINE=$(printf '%s\n' "$SST_RAW" | awk '/^[ \t]*Password expiration interval/ { n++; line=$0 } END { if (n==1) print line }')
    if [ -z "$SST_LINE" ]; then
      add security sst_pwdexpitv "SST password expiration interval" NOT_ASSESSED low \
          "not assessed — Password expiration interval line missing or not unique in DSPSSTSECA" \
          "The DSPSSTSECA dump was readable, but it did not contain exactly one Password expiration interval line, so the value cannot be graded." \
          "inspect DSPSSTSECA Password expiration interval." \
          "cis-l1"
    else
      SST_VAL=$(printf '%s\n' "$SST_LINE" | awk '{ sub(/.*:/, ""); gsub(/^[ \t]+|[ \t\r]+$/, ""); print }')
      if [ -z "$SST_VAL" ]; then
        add security sst_pwdexpitv "SST password expiration interval" NOT_ASSESSED low \
            "not assessed — SST PWDEXPITV value unreadable" \
            "The Password expiration interval line was present, but the value was empty, so it is not graded." \
            "inspect DSPSSTSECA Password expiration interval." \
            "cis-l1"
      elif [ "$SST_VAL" = "*NOMAX" ]; then
        add security sst_pwdexpitv "SST password expiration interval" FAIL high \
            "PWDEXPITV=*NOMAX" \
            "SST password expiration interval is not 365 days, so an SST password does not expire on the 365-day interval." \
            "set SST password expiration interval to 365 using CHGSSTSECA PWDEXPITV(365). This scanner never changes SST security attributes." \
            "cis-l1"
      else
        SSTN=$(printf '%s\n' "$SST_VAL" | awk '/^[0-9]+$/{ if ($0 ~ /^0+$/) print 0; else { sub(/^0+/,""); print } }')
        if [ -z "$SSTN" ] || [ "$SSTN" -lt 1 ] || [ "$SSTN" -gt 366 ]; then
          add security sst_pwdexpitv "SST password expiration interval" NOT_ASSESSED low \
              "not assessed — SST PWDEXPITV value unreadable" \
              "The Password expiration interval line was present, but the value was not an integer 1-366 or *NOMAX, so it is not graded." \
              "inspect DSPSSTSECA Password expiration interval." \
              "cis-l1"
        elif [ "$SSTN" -eq 365 ]; then
          add security sst_pwdexpitv "SST password expiration interval" PASS low \
              "PWDEXPITV=365" \
              "SST password expiration interval is 365 days, so an SST password expires on the 365-day interval." \
              "n/a" \
              "cis-l1"
        else
          add security sst_pwdexpitv "SST password expiration interval" FAIL high \
              "PWDEXPITV=$SSTN" \
              "SST password expiration interval is not 365 days, so an SST password does not expire on the 365-day interval." \
              "set SST password expiration interval to 365 using CHGSSTSECA PWDEXPITV(365). This scanner never changes SST security attributes." \
              "cis-l1"
        fi
      fi
    fi
  fi

  # sst_pwdlvl — IBM i SST password level (CHGSSTSECA SSTPWDLVL).
  # Authority: CIS IBM i V7R5M0/V7R4M0 5.6.4. The exact L1 value is 3
  # on 7.5 and 2 on 7.4. No L2 rec. One finding.
  # Calls ibmi_cl for DSPSSTSECA. Parses the
  # "Service tools password level" line (token after last colon).
  # Does not call ibmi_sql / QSYS2.SST_SECURITY_INFO /
  # CHGSSTSECA / STRSST. Does not SELECT SYSTEM_VALUE_INFO
  # or SECURITY_INFO (those PASSWORD_LEVEL / QPWDLVL columns
  # are ck-sv-qpwdlvl).
  # CPFB304 branch is fixture-reachable only because ibmi_cl
  # discards stderr.
  # Exact 3 is PASS. 1 or 2 is FAIL. IBM 7.5 ship default 2
  # is FAIL. 4 is unreadable (that is QPWDLVL, not SST).
  SST_RAW=$(ibmi_cl sst_sec "DSPSSTSECA")
  SST_RC=$?
  SST_NOAUTH=$(printf '%s\n' "$SST_RAW" | awk 'tolower($0) ~ /cpfb304/ { n=1 } END { if (n) print 1 }')
  if [ -n "$SST_NOAUTH" ]; then
    add security sst_pwdlvl "SST password level" NOT_ASSESSED low \
        "not assessed — DSPSSTSECA not authorized (CPFB304)" \
        "The scan profile is not authorized to display SST security attributes, so the SST password level cannot be graded." \
        "grant the scan profile *SERVICE (CHGUSRPRF SPCAUT(*SERVICE)) so DSPSSTSECA can display SST security attributes, then re-run. This scanner never changes SST security attributes." \
        "cis-l1"
  elif [ "$SST_RC" -ne 0 ]; then
    add security sst_pwdlvl "SST password level" NOT_ASSESSED low \
        "not assessed — capture failed (rc=$SST_RC)" \
        "The SST security-attribute probe did not yield a readable password level, so the SST password level cannot be graded." \
        "grant the scan profile *SERVICE (CHGUSRPRF SPCAUT(*SERVICE)) so DSPSSTSECA can display SST security attributes, then re-run. This scanner never changes SST security attributes." \
        "cis-l1"
  elif [ -z "$SST_RAW" ]; then
    add security sst_pwdlvl "SST password level" NOT_ASSESSED low \
        "not assessed — capture empty (rc=0)" \
        "The SST security-attribute probe returned no text, so the SST password level cannot be graded." \
        "grant the scan profile *SERVICE (CHGUSRPRF SPCAUT(*SERVICE)) so DSPSSTSECA can display SST security attributes, then re-run. This scanner never changes SST security attributes." \
        "cis-l1"
  else
    SST_LINE=$(printf '%s\n' "$SST_RAW" | awk 'index($0, "Service tools password level"){ n++; line=$0 } END{ if (n==1) print line }')
    if [ -z "$SST_LINE" ]; then
      add security sst_pwdlvl "SST password level" NOT_ASSESSED low \
          "not assessed — Service tools password level line missing or not unique in DSPSSTSECA dump" \
          "The DSPSSTSECA dump was readable, but it did not contain exactly one Service tools password level line, so the value cannot be graded." \
          "inspect DSPSSTSECA Service tools password level." \
          "cis-l1"
    else
      SST_VAL=$(printf '%s\n' "$SST_LINE" | awk '{ n=split($0, a, ":"); v=a[n]; sub(/^[ \t]+/, "", v); sub(/[ \t\r]+$/, "", v); print v }')
      if [ -z "$SST_VAL" ]; then
        add security sst_pwdlvl "SST password level" NOT_ASSESSED low \
            "not assessed — SST SSTPWDLVL value unreadable" \
            "The Service tools password level line was present, but the displayed value was empty, so it is not graded." \
            "inspect SST password level on DSPSSTSECA." \
            "cis-l1"
      else
        SSTN=$(printf '%s\n' "$SST_VAL" | awk '/^[0-9]+$/{ if ($0 ~ /^0+$/) print 0; else { sub(/^0+/,""); print } }')
        GRADE_RELEASE=$(ibmi_release 2>/dev/null || :)
        if [ "$GRADE_RELEASE" = 7.4 ]; then
          SST_EXPECTED=2
          SST_FIX="set SST password level to 2 using CHGSSTSECA SSTPWDLVL(2). This scanner never changes SST security attributes."
        else
          SST_EXPECTED=3
          SST_FIX="set SST password level to 3 using CHGSSTSECA SSTPWDLVL(3). The password level cannot be changed back to a lower level. This scanner never changes SST security attributes."
        fi
        if [ -z "$SSTN" ]; then
          add security sst_pwdlvl "SST password level" NOT_ASSESSED low \
              "not assessed — SST SSTPWDLVL value unreadable" \
              "The Service tools password level line was present, but the displayed value was not a documented SST password level 1-3, so it is not graded." \
              "inspect SST password level on DSPSSTSECA." \
              "cis-l1"
        elif [ "$SSTN" -eq "$SST_EXPECTED" ]; then
          add security sst_pwdlvl "SST password level" PASS low \
              "SSTPWDLVL=$SSTN" \
              "SST password level is $SSTN, matching the CIS IBM i $GRADE_RELEASE benchmark recommendation." \
              "n/a" \
              "cis-l1"
        elif [ "$SSTN" -eq 1 ] || [ "$SSTN" -eq 2 ] || [ "$SSTN" -eq 3 ]; then
          add security sst_pwdlvl "SST password level" FAIL high \
              "SSTPWDLVL=$SSTN" \
              "SST password level is not the CIS IBM i $GRADE_RELEASE benchmark value $SST_EXPECTED." \
              "$SST_FIX" \
              "cis-l1"
        else
          add security sst_pwdlvl "SST password level" NOT_ASSESSED low \
              "not assessed — SST SSTPWDLVL value unreadable" \
              "The Service tools password level line was present, but the displayed value was not a documented SST password level 1-3, so it is not graded." \
              "inspect SST password level on DSPSSTSECA." \
              "cis-l1"
        fi
      fi
    fi
  fi

  # sst_pwdrules — IBM i SST password rules (CHGSSTSECA PWDRULES).
  # Authority: CIS IBM i V7R5M0 5.6.8 (L1 composition set). No L2 rec.
  # The 7.4 and 7.5 v2.1.0 recommendations use the same composition set.
  # One finding.
  # Calls ibmi_cl once for DSPSSTSECA. Parses the SST password
  # rules block. Does not call ibmi_sql / DSPSSTUSR / CHGSSTSECA /
  # STRSST. Does not SELECT SST_* views (they do not exist) or
  # SECURITY_INFO (PASSWORD_RULES there is ck-sv-qpwdrules).
  # 7.5 set PASSes. IBM ship defaults FAIL. Placement *YES FAILs.
  # CPFB304 / ibmi_cl rc != 0 is NOT_ASSESSED (profile needs *SECADM).
  SST_RAW=$(ibmi_cl sst_sec "DSPSSTSECA")
  SST_RC=$?
  SST_AUTH=$(printf '%s\n' "$SST_RAW" | awk 'tolower($0) ~ /cpfb304/ { n=1 } END { if (n) print 1 }')
  if [ "$SST_RC" -ne 0 ] || [ -n "$SST_AUTH" ]; then
    add security sst_pwdrules "SST password rules" NOT_ASSESSED low \
        "not assessed — capture failed (rc=$SST_RC)" \
        "The profile running this scan needs *SECADM to read DSPSSTSECA, so the SST composition set cannot be graded." \
        "grant *SECADM to the scan profile and re-run. This scanner never changes SST security attributes." \
        "cis-l1"
  elif [ -z "$SST_RAW" ]; then
    add security sst_pwdrules "SST password rules" NOT_ASSESSED low \
        "not assessed — capture empty (rc=0)" \
        "The DSPSSTSECA probe returned no text, so the SST composition set cannot be graded." \
        "re-run the scan as the scan profile and confirm DSPSSTSECA returns the SST password rules block. This scanner never changes SST security attributes." \
        "cis-l1"
  else
    SST_PACK=$(printf '%s\n' "$SST_RAW" | awk '
      BEGIN {
        labs[1]="Limit profile name";             keys[1]="LMTPRF"
        labs[2]="Hours to block password change"; keys[2]="PWDBLKHRS"
        labs[3]="Minimum password length";        keys[3]="MINLEN"
        labs[4]="Maximum password length";        keys[4]="MAXLEN"
        labs[5]="Use chars from three groups";    keys[5]="REQANY3"
        labs[6]="Minimum digits";                 keys[6]="MINDGT"
        labs[7]="Limit adjacent digits";          keys[7]="LMTADJDGT"
        labs[8]="Limit digit first position";     keys[8]="LMTDGTFST"
        labs[9]="Limit digit last position";      keys[9]="LMTDGTLST"
        labs[10]="Limit adjacent special characters"; keys[10]="LMTADJSPC"
        labs[11]="Limit special character first position"; keys[11]="LMTSPCFST"
        labs[12]="Limit special character last position";  keys[12]="LMTSPCLST"
      }
      {
        if (index($0, "SST password rules:") > 0) { hdr++; inblk=1 }
        if (!inblk) next
        for (i=1; i<=12; i++) {
          if (index($0, labs[i]) > 0) {
            val=$0
            sub(/.*:/, "", val)
            gsub(/\r/, "", val)
            sub(/^[ \t]+/, "", val)
            sub(/[ \t]+$/, "", val)
            n[keys[i]]++
            v[keys[i]]=val
          }
        }
      }
      END {
        if (hdr<1 || n["LMTPRF"]!=1 || n["PWDBLKHRS"]!=1 || n["MINLEN"]!=1 || n["MAXLEN"]!=1 || n["REQANY3"]!=1 || n["MINDGT"]!=1 || n["LMTADJDGT"]!=1 || n["LMTDGTFST"]!=1 || n["LMTDGTLST"]!=1 || n["LMTADJSPC"]!=1 || n["LMTSPCFST"]!=1 || n["LMTSPCLST"]!=1)
          print ""
        else
          print v["LMTPRF"] "|" v["PWDBLKHRS"] "|" v["MINLEN"] "|" v["MAXLEN"] "|" v["REQANY3"] "|" v["MINDGT"] "|" v["LMTADJDGT"] "|" v["LMTDGTFST"] "|" v["LMTDGTLST"] "|" v["LMTADJSPC"] "|" v["LMTSPCFST"] "|" v["LMTSPCLST"]
      }')
    if [ -z "$SST_PACK" ]; then
      add security sst_pwdrules "SST password rules" NOT_ASSESSED low \
          "not assessed — SST password rules block missing or not unique in DSPSSTSECA" \
          "The DSPSSTSECA dump was readable, but it did not contain exactly one SST password rules block with exactly one line for each graded password-rule label, so the value cannot be graded." \
          "inspect DSPSSTSECA SST password rules." \
          "cis-l1"
    else
      LMTPRF=$(printf '%s\n' "$SST_PACK" | awk -F'|' '{print $1}')
      PWDBLKHRS=$(printf '%s\n' "$SST_PACK" | awk -F'|' '{print $2}')
      MINLEN=$(printf '%s\n' "$SST_PACK" | awk -F'|' '{print $3}')
      MAXLEN=$(printf '%s\n' "$SST_PACK" | awk -F'|' '{print $4}')
      REQANY3=$(printf '%s\n' "$SST_PACK" | awk -F'|' '{print $5}')
      MINDGT=$(printf '%s\n' "$SST_PACK" | awk -F'|' '{print $6}')
      LMTADJDGT=$(printf '%s\n' "$SST_PACK" | awk -F'|' '{print $7}')
      LMTDGTFST=$(printf '%s\n' "$SST_PACK" | awk -F'|' '{print $8}')
      LMTDGTLST=$(printf '%s\n' "$SST_PACK" | awk -F'|' '{print $9}')
      LMTADJSPC=$(printf '%s\n' "$SST_PACK" | awk -F'|' '{print $10}')
      LMTSPCFST=$(printf '%s\n' "$SST_PACK" | awk -F'|' '{print $11}')
      LMTSPCLST=$(printf '%s\n' "$SST_PACK" | awk -F'|' '{print $12}')
      if [ -z "$LMTPRF" ] || [ -z "$PWDBLKHRS" ] || [ -z "$MINLEN" ] || [ -z "$MAXLEN" ] || [ -z "$REQANY3" ] || [ -z "$MINDGT" ] || [ -z "$LMTADJDGT" ] || [ -z "$LMTDGTFST" ] || [ -z "$LMTDGTLST" ] || [ -z "$LMTADJSPC" ] || [ -z "$LMTSPCFST" ] || [ -z "$LMTSPCLST" ]; then
        add security sst_pwdrules "SST password rules" NOT_ASSESSED low \
            "not assessed — SST PWDRULES value unreadable" \
            "A PWDRULES line was present, but a displayed value was empty, so it is not graded." \
            "inspect DSPSSTSECA SST password rules." \
            "cis-l1"
      else
        HRSN=$(printf '%s\n' "$PWDBLKHRS" | awk '/^[0-9]+$/{ if ($0 ~ /^0+$/) print 0; else { sub(/^0+/,""); print } }')
        MINN=$(printf '%s\n' "$MINLEN" | awk '/^[0-9]+$/{ if ($0 ~ /^0+$/) print 0; else { sub(/^0+/,""); print } }')
        MAXN=$(printf '%s\n' "$MAXLEN" | awk '/^[0-9]+$/{ if ($0 ~ /^0+$/) print 0; else { sub(/^0+/,""); print } }')
        DGTN=$(printf '%s\n' "$MINDGT" | awk '/^[0-9]+$/{ if ($0 ~ /^0+$/) print 0; else { sub(/^0+/,""); print } }')
        SST_OBS="LMTPRF=$LMTPRF PWDBLKHRS=${HRSN:-$PWDBLKHRS} MINLEN=${MINN:-$MINLEN} MAXLEN=${MAXN:-$MAXLEN} REQANY3=$REQANY3 MINDGT=${DGTN:-$MINDGT} LMTADJDGT=$LMTADJDGT LMTDGTFST=$LMTDGTFST LMTDGTLST=$LMTDGTLST LMTADJSPC=$LMTADJSPC LMTSPCFST=$LMTSPCFST LMTSPCLST=$LMTSPCLST"
        if [ "$LMTPRF" != "*YES" ] && [ "$LMTPRF" != "*NO" ]; then
          add security sst_pwdrules "SST password rules" NOT_ASSESSED low \
              "not assessed — SST PWDRULES value unreadable" \
              "A PWDRULES line was present, but a displayed value was not a documented SST password-rule token, so it is not graded." \
              "inspect DSPSSTSECA SST password rules." \
              "cis-l1"
        elif [ "$REQANY3" != "*YES" ] && [ "$REQANY3" != "*NO" ]; then
          add security sst_pwdrules "SST password rules" NOT_ASSESSED low \
              "not assessed — SST PWDRULES value unreadable" \
              "A PWDRULES line was present, but a displayed value was not a documented SST password-rule token, so it is not graded." \
              "inspect DSPSSTSECA SST password rules." \
              "cis-l1"
        elif [ "$LMTADJDGT" != "*YES" ] && [ "$LMTADJDGT" != "*NO" ]; then
          add security sst_pwdrules "SST password rules" NOT_ASSESSED low \
              "not assessed — SST PWDRULES value unreadable" \
              "A PWDRULES line was present, but a displayed value was not a documented SST password-rule token, so it is not graded." \
              "inspect DSPSSTSECA SST password rules." \
              "cis-l1"
        elif [ "$LMTDGTFST" != "*YES" ] && [ "$LMTDGTFST" != "*NO" ]; then
          add security sst_pwdrules "SST password rules" NOT_ASSESSED low \
              "not assessed — SST PWDRULES value unreadable" \
              "A PWDRULES line was present, but a displayed value was not a documented SST password-rule token, so it is not graded." \
              "inspect DSPSSTSECA SST password rules." \
              "cis-l1"
        elif [ "$LMTDGTLST" != "*YES" ] && [ "$LMTDGTLST" != "*NO" ]; then
          add security sst_pwdrules "SST password rules" NOT_ASSESSED low \
              "not assessed — SST PWDRULES value unreadable" \
              "A PWDRULES line was present, but a displayed value was not a documented SST password-rule token, so it is not graded." \
              "inspect DSPSSTSECA SST password rules." \
              "cis-l1"
        elif [ "$LMTADJSPC" != "*YES" ] && [ "$LMTADJSPC" != "*NO" ]; then
          add security sst_pwdrules "SST password rules" NOT_ASSESSED low \
              "not assessed — SST PWDRULES value unreadable" \
              "A PWDRULES line was present, but a displayed value was not a documented SST password-rule token, so it is not graded." \
              "inspect DSPSSTSECA SST password rules." \
              "cis-l1"
        elif [ "$LMTSPCFST" != "*YES" ] && [ "$LMTSPCFST" != "*NO" ]; then
          add security sst_pwdrules "SST password rules" NOT_ASSESSED low \
              "not assessed — SST PWDRULES value unreadable" \
              "A PWDRULES line was present, but a displayed value was not a documented SST password-rule token, so it is not graded." \
              "inspect DSPSSTSECA SST password rules." \
              "cis-l1"
        elif [ "$LMTSPCLST" != "*YES" ] && [ "$LMTSPCLST" != "*NO" ]; then
          add security sst_pwdrules "SST password rules" NOT_ASSESSED low \
              "not assessed — SST PWDRULES value unreadable" \
              "A PWDRULES line was present, but a displayed value was not a documented SST password-rule token, so it is not graded." \
              "inspect DSPSSTSECA SST password rules." \
              "cis-l1"
        elif [ "$PWDBLKHRS" != "*NONE" ] && { [ -z "$HRSN" ] || [ "$HRSN" -lt 1 ] || [ "$HRSN" -gt 99 ]; }; then
          add security sst_pwdrules "SST password rules" NOT_ASSESSED low \
              "not assessed — SST PWDRULES value unreadable" \
              "A PWDRULES line was present, but a displayed value was not a documented SST password-rule token, so it is not graded." \
              "inspect DSPSSTSECA SST password rules." \
              "cis-l1"
        elif [ -z "$MINN" ] || [ "$MINN" -lt 1 ] || [ "$MINN" -gt 128 ]; then
          add security sst_pwdrules "SST password rules" NOT_ASSESSED low \
              "not assessed — SST PWDRULES value unreadable" \
              "A PWDRULES line was present, but a displayed value was not a documented SST password-rule token, so it is not graded." \
              "inspect DSPSSTSECA SST password rules." \
              "cis-l1"
        elif [ -z "$MAXN" ] || [ "$MAXN" -lt 1 ] || [ "$MAXN" -gt 128 ] || [ "$MAXN" -lt "$MINN" ]; then
          add security sst_pwdrules "SST password rules" NOT_ASSESSED low \
              "not assessed — SST PWDRULES value unreadable" \
              "A PWDRULES line was present, but a displayed value was not a documented SST password-rule token, so it is not graded." \
              "inspect DSPSSTSECA SST password rules." \
              "cis-l1"
        elif [ "$MINDGT" != "*NONE" ] && { [ -z "$DGTN" ] || [ "$DGTN" -lt 1 ] || [ "$DGTN" -gt 9 ]; }; then
          add security sst_pwdrules "SST password rules" NOT_ASSESSED low \
              "not assessed — SST PWDRULES value unreadable" \
              "A PWDRULES line was present, but a displayed value was not a documented SST password-rule token, so it is not graded." \
              "inspect DSPSSTSECA SST password rules." \
              "cis-l1"
        elif [ "$LMTPRF" = "*YES" ] && [ "$REQANY3" = "*YES" ] && [ -n "$HRSN" ] && [ "$HRSN" -ge 24 ] && [ "$MINN" -ge 14 ] && [ -n "$DGTN" ] && [ "$LMTADJDGT" = "*NO" ] && [ "$LMTDGTFST" = "*NO" ] && [ "$LMTDGTLST" = "*NO" ] && [ "$LMTADJSPC" = "*NO" ] && [ "$LMTSPCFST" = "*NO" ] && [ "$LMTSPCLST" = "*NO" ]; then
          add security sst_pwdrules "SST password rules" PASS low \
              "PWDRULES=$SST_OBS" \
              "SST password rules require the profile name off, at least 14 characters, characters from three groups, at least one digit, at least 24 hours between changes, and digit and special-character placement limits off." \
              "n/a" \
              "cis-l1"
        else
          add security sst_pwdrules "SST password rules" FAIL high \
              "PWDRULES=$SST_OBS" \
              "SST password rules are not the 7.5 composition set, so an SST password can contain the profile name, be shorter than 14 characters, skip mixed character classes, skip a digit, be changed again too soon, or apply digit and special-character placement limits." \
              "set SST password rules using CHGSSTSECA PWDRULES(*YES 24 14 128 *YES *SAME *SAME *SAME 1 *SAME *NO *NO *NO *SAME *SAME *SAME *SAME *SAME *SAME *SAME *SAME *NO *NO *NO). This scanner never changes SST security attributes." \
              "cis-l1"
        fi
      fi
    fi
  fi

  # sv_qalwobjrst — IBM i QALWOBJRST (allow restore of security-sensitive objects).
  # Authority: CIS IBM i V7R5M0/V7R4M0 5.1.1.1 (L1=*ALWPTF) and 5.1.2.1 (L2=*NONE).
  # One finding. Parses the shared cap-system-values dump. Does not call
  # ibmi_sql. Does not CHGSYSVAL. *NOTAVL is a refusal, never PASS.
  # Exact *NONE or exact *ALWPTF is PASS (*NONE is stricter than L1).
  # *ALL (IBM ship default) or any other documented token set is FAIL.
  # live Phase 0 dump is QALWOBJRST||*NONE.
  if [ "${SYSVAL_OK:-0}" -ne 1 ]; then
    add security sv_qalwobjrst "Allow restoration of security-sensitive objects" NOT_ASSESSED low \
        "not assessed — ${SYSVAL_WHY:-capture unavailable}" \
        "The SYSTEM_VALUE_INFO capture did not yield a readable dump, so QALWOBJRST cannot be graded." \
        "re-run the scan as the scan profile and confirm QSYS2.SYSTEM_VALUE_INFO returns rows. This scanner never changes system values." \
        "cis-l1 cis-l2"
  else
    QAL_LINE=$(printf '%s\n' "$SYSVAL_RAW" | awk -F'|' '$1=="QALWOBJRST"{n++; line=$0} END{if(n==1) print line}')
    QAL_RC=$?
    if [ "$QAL_RC" -ne 0 ] || [ -z "$QAL_LINE" ]; then
      add security sv_qalwobjrst "Allow restoration of security-sensitive objects" NOT_ASSESSED low \
          "not assessed — QALWOBJRST row missing or not unique in SYSTEM_VALUE_INFO" \
          "The system-value dump was readable, but it did not contain exactly one QALWOBJRST row, so the value cannot be graded." \
          "inspect QSYS2.SYSTEM_VALUE_INFO for SYSTEM_VALUE_NAME = QALWOBJRST." \
          "cis-l1 cis-l2"
    else
      QAL_VAL=$(printf '%s\n' "$QAL_LINE" | awk -F'|' '{ v=$3; if (v=="") v=$2; sub(/[ \t]+$/, "", v); print v }')
      QAL_TOK=$(printf '%s\n' "$QAL_VAL" | awk '
        {
          n=split($0, a, /[ \t]+/)
          for (i=1; i<=n; i++) {
            if (a[i]=="") continue
            nt++
            if (a[i]=="*NOTAVL") nv=1
            if (a[i]=="*NONE") none=1
            if (a[i]=="*ALWPTF") ptf=1
            if (a[i]=="*ALL" || a[i]=="*NONE" || a[i]=="*ALWSYSSTT" || a[i]=="*ALWPGMADP" || a[i]=="*ALWPTF" || a[i]=="*ALWSETUID" || a[i]=="*ALWSETGID" || a[i]=="*ALWVLDERR") d++
            else j++
          }
        }
        END {
          if (nv) print "NOTAVL"
          else if (j || nt<1) print "BAD"
          else if (nt==1 && none) print "PASS"
          else if (nt==1 && ptf) print "PASS"
          else print "FAIL"
        }')
      if [ "$QAL_TOK" = NOTAVL ]; then
        add security sv_qalwobjrst "Allow restoration of security-sensitive objects" NOT_ASSESSED low \
            "not assessed — QALWOBJRST=*NOTAVL (scan profile cannot read this system value)" \
            "The catalog returned *NOTAVL for QALWOBJRST — the scan profile lacks authority to read this system value, so the value is not graded." \
            "grant the scan profile read access to QALWOBJRST and re-take cap-system-values. Do not run this check as QSECOFR to paper over the gap." \
            "cis-l1 cis-l2"
      elif [ "$QAL_TOK" = PASS ]; then
        if [ "$QAL_VAL" = "*NONE" ]; then
          QAL_TAGS="cis-l1 cis-l2"
        else
          QAL_TAGS="cis-l1"
        fi
        add security sv_qalwobjrst "Allow restoration of security-sensitive objects" PASS low \
            "QALWOBJRST=$QAL_VAL" \
            "QALWOBJRST is *NONE or *ALWPTF, so security-sensitive objects cannot be restored except as part of a PTF install (or not at all)." \
            "n/a" \
            "$QAL_TAGS"
      elif [ "$QAL_TOK" = FAIL ]; then
        add security sv_qalwobjrst "Allow restoration of security-sensitive objects" FAIL high \
            "QALWOBJRST=$QAL_VAL" \
            "QALWOBJRST allows restore of security-sensitive objects (system-state programs, programs that adopt authority, setuid files, or objects with validation errors) outside a PTF install." \
            "set QALWOBJRST to *ALWPTF, or to *NONE, using CHGSYSVAL SYSVAL(QALWOBJRST) VALUE('*ALWPTF'). This scanner never changes system values." \
            "cis-l1 cis-l2"
      else
        add security sv_qalwobjrst "Allow restoration of security-sensitive objects" NOT_ASSESSED low \
            "not assessed — QALWOBJRST value unreadable" \
            "The QALWOBJRST row was present, but the catalog value was not a documented restore-allow token set, *NONE, *ALWPTF, or *NOTAVL, so it is not graded." \
            "inspect the QALWOBJRST row in QSYS2.SYSTEM_VALUE_INFO and DSPSYSVAL SYSVAL(QALWOBJRST)." \
            "cis-l1 cis-l2"
      fi
    fi
  fi

  # sv_qalwusrdmn — IBM i QALWUSRDMN (allow user domain objects
  # in libraries). Authority: CIS IBM i V7R5M0/V7R4M0 5.1.2.2
  # (L2=QTEMP). No L1 rec.
  # One finding. Parses the shared cap-system-values dump. Does not
  # call ibmi_sql. Does not CHGSYSVAL. *NOTAVL is a refusal, never
  # PASS. Catalog encoding is concatenated CHAR(10) names (or one
  # special *ALL / *DIR). Exact QTEMP is PASS (live dump). *ALL
  # (IBM ship default), *DIR, or any extra library is FAIL.
  # live Phase 0 dump is QALWUSRDMN||QTEMP.
  if [ "${SYSVAL_OK:-0}" -ne 1 ]; then
    add security sv_qalwusrdmn "Allow user domain objects in libraries" NOT_ASSESSED low \
        "not assessed — ${SYSVAL_WHY:-capture unavailable}" \
        "The SYSTEM_VALUE_INFO capture did not yield a readable dump, so QALWUSRDMN cannot be graded." \
        "re-run the scan as the scan profile and confirm QSYS2.SYSTEM_VALUE_INFO returns rows. This scanner never changes system values." \
        "cis-l2"
  else
    QUD_LINE=$(printf '%s\n' "$SYSVAL_RAW" | awk -F'|' '$1=="QALWUSRDMN"{n++; line=$0} END{if(n==1) print line}')
    QUD_RC=$?
    if [ -z "$QUD_LINE" ]; then
      add security sv_qalwusrdmn "Allow user domain objects in libraries" NOT_ASSESSED low \
          "not assessed — QALWUSRDMN row missing or not unique in SYSTEM_VALUE_INFO" \
          "The system-value dump was readable, but it did not contain exactly one QALWUSRDMN row, so the value cannot be graded." \
          "inspect QSYS2.SYSTEM_VALUE_INFO for SYSTEM_VALUE_NAME = QALWUSRDMN." \
          "cis-l2"
    else
      QUD_VAL=$(printf '%s\n' "$QUD_LINE" | awk -F'|' '{ v=$3; if (v=="") v=$2; sub(/[ \t]+$/, "", v); print v }')
      QUD_TOK=$(printf '%s\n' "$QUD_VAL" | awk '
        {
          s=$0
          sub(/[ \t]+$/, "", s)
          for (pos=1; (t=substr(s, pos, 10)) != ""; pos=pos+10) {
            sub(/[ \t]+$/, "", t)
            sub(/^[ \t]+/, "", t)
            if (t=="") continue
            nt++
            if (t=="*NOTAVL") nv=1
            if (t=="QTEMP") qt=1
            if (t=="*ALL" || t=="*DIR") continue
            if (t=="QTEMP") continue
            if (t ~ /^[A-Z$#@][A-Z0-9$#@_]*$/) continue
            j++
          }
        }
        END {
          if (nv) print "NOTAVL"
          else if (j || nt<1) print "BAD"
          else if (nt==1 && qt) print "PASS"
          else print "FAIL"
        }')
      if [ "$QUD_TOK" = NOTAVL ]; then
        add security sv_qalwusrdmn "Allow user domain objects in libraries" NOT_ASSESSED low \
            "not assessed — QALWUSRDMN=*NOTAVL (scan profile cannot read this system value)" \
            "The catalog returned *NOTAVL for QALWUSRDMN — the scan profile lacks authority to read this system value, so the value is not graded." \
            "grant the scan profile read access to QALWUSRDMN and re-take cap-system-values. Do not run this check as QSECOFR to paper over the gap." \
            "cis-l2"
      elif [ "$QUD_TOK" = PASS ]; then
        add security sv_qalwusrdmn "Allow user domain objects in libraries" PASS low \
            "QALWUSRDMN=$QUD_VAL" \
            "QALWUSRDMN is QTEMP, so unauditable user domain objects (*USRSPC, *USRIDX, *USRQ) are allowed only in QTEMP." \
            "n/a" \
            "cis-l2"
      elif [ "$QUD_TOK" = FAIL ]; then
        add security sv_qalwusrdmn "Allow user domain objects in libraries" FAIL high \
            "QALWUSRDMN=$QUD_VAL" \
            "QALWUSRDMN allows unauditable user domain objects (*USRSPC, *USRIDX, *USRQ) outside QTEMP, so data can move through those objects without an audit trail." \
            "set QALWUSRDMN to QTEMP using CHGSYSVAL SYSVAL(QALWUSRDMN) VALUE('QTEMP'). This scanner never changes system values." \
            "cis-l2"
      else
        add security sv_qalwusrdmn "Allow user domain objects in libraries" NOT_ASSESSED low \
            "not assessed — QALWUSRDMN value unreadable" \
            "The QALWUSRDMN row was present, but the catalog value was not QTEMP, a documented library list, *ALL, *DIR, or *NOTAVL, so it is not graded." \
            "inspect the QALWUSRDMN row in QSYS2.SYSTEM_VALUE_INFO and DSPSYSVAL SYSVAL(QALWUSRDMN)." \
            "cis-l2"
      fi
    fi
  fi

  # sv_qatnpgm — IBM i QATNPGM (attention program).
  # Authority: CIS IBM i V7R5M0 Benchmark v2.1.0 5.1.1.2 (L1=*NONE). No L2 rec.
  # One finding. Parses the shared cap-system-values dump. Does not call
  # ibmi_sql. Does not CHGSYSVAL. *NOTAVL is a refusal, never PASS.
  # Exact *NONE is PASS. *ASSIST or any named program is FAIL.
  # live Phase 0 dump is QATNPGM||*NONE.
  if [ "${SYSVAL_OK:-0}" -ne 1 ]; then
    add security sv_qatnpgm "Attention program" NOT_ASSESSED low \
        "not assessed — ${SYSVAL_WHY:-capture unavailable}" \
        "The SYSTEM_VALUE_INFO capture did not yield a readable dump, so QATNPGM cannot be graded." \
        "re-run the scan as the scan profile and confirm QSYS2.SYSTEM_VALUE_INFO returns rows. This scanner never changes system values." \
        "cis-l1"
  else
    QATN_LINE=$(printf '%s\n' "$SYSVAL_RAW" | awk -F'|' '$1=="QATNPGM"{n++; line=$0} END{if(n==1) print line}')
    QATN_RC=$?
    if [ -z "$QATN_LINE" ]; then
      add security sv_qatnpgm "Attention program" NOT_ASSESSED low \
          "not assessed — QATNPGM row missing or not unique in SYSTEM_VALUE_INFO" \
          "The system-value dump was readable, but it did not contain exactly one QATNPGM row, so the value cannot be graded." \
          "inspect QSYS2.SYSTEM_VALUE_INFO for SYSTEM_VALUE_NAME = QATNPGM." \
          "cis-l1"
    else
      QATN_NUM=$(printf '%s\n' "$QATN_LINE" | awk -F'|' '{print $2}')
      QATN_CHR=$(printf '%s\n' "$QATN_LINE" | awk -F'|' '{print $3}')
      if [ -n "$QATN_NUM" ]; then
        QATN_RAW=$QATN_NUM
      else
        QATN_RAW=$QATN_CHR
      fi
      if [ "$QATN_RAW" = "*NOTAVL" ]; then
        add security sv_qatnpgm "Attention program" NOT_ASSESSED low \
            "not assessed — QATNPGM=*NOTAVL (scan profile cannot read this system value)" \
            "The catalog returned *NOTAVL for QATNPGM — the scan profile lacks authority to read this system value, so the value is not graded." \
            "grant the scan profile read access to QATNPGM and re-take cap-system-values. Do not run this check as QSECOFR to paper over the gap." \
            "cis-l1"
      elif [ -z "$QATN_RAW" ]; then
        add security sv_qatnpgm "Attention program" NOT_ASSESSED low \
            "not assessed — QATNPGM value unreadable" \
            "The QATNPGM row was present, but the catalog value was empty, so it is not graded." \
            "inspect the QATNPGM row in QSYS2.SYSTEM_VALUE_INFO and DSPSYSVAL SYSVAL(QATNPGM)." \
            "cis-l1"
      elif [ "$QATN_RAW" = "*NONE" ]; then
        add security sv_qatnpgm "Attention program" PASS low \
            "QATNPGM=*NONE" \
            "QATNPGM is *NONE, so the Attention key does not call a program." \
            "n/a" \
            "cis-l1"
      else
        add security sv_qatnpgm "Attention program" FAIL high \
            "QATNPGM=$QATN_RAW" \
            "QATNPGM names a program, so the Attention key can call that program for every interactive job." \
            "set QATNPGM to *NONE using CHGSYSVAL SYSVAL(QATNPGM) VALUE('*NONE'). This scanner never changes system values." \
            "cis-l1"
      fi
    fi
  fi

  # sv_qaudctl — IBM i QAUDCTL auditing control (5.1.2.3 L2).
  # Parses cap-system-values SYSVAL_RAW. Never calls qsh/db2/system/ibmi_sql.
  # *NOTAVL is a missing-*AUDIT refusal, never PASS. Read-only.
  OK=${SYSVAL_OK:-0}
  WHY=${SYSVAL_WHY:-capture unset}
  if [ "$OK" -ne 1 ]; then
    add security sv_qaudctl "IBM i auditing control (QAUDCTL)" NOT_ASSESSED low \
        "not assessed — system-value capture $WHY" \
        "The shared system-value capture did not yield a usable QSYS2.SYSTEM_VALUE_INFO dump, so QAUDCTL cannot be scored." \
        "re-run as the scan profile after confirming Qshell db2 can select QSYS2.SYSTEM_VALUE_INFO; then re-take cap-system-values." \
        "cis-l2"
  else
    RAW=${SYSVAL_RAW:-}
    QAUDVAL=$(printf '%s\n' "$RAW" | awk -F'|' '
      $1=="QAUDCTL" {
        v=$3
        sub(/[ \t]+$/, "", v)
        print v
        found=1
        exit
      }
      END { if (!found) exit 1 }')
    if [ $? -ne 0 ]; then
      add security sv_qaudctl "IBM i auditing control (QAUDCTL)" NOT_ASSESSED low \
          "not assessed — QAUDCTL row absent from system-value capture" \
          "The system-value capture ran, but it did not contain a QAUDCTL row, so auditing control cannot be scored." \
          "confirm QSYS2.SYSTEM_VALUE_INFO returns a QAUDCTL row under the scan profile, then re-take cap-system-values." \
          "cis-l2"
    elif [ -z "$QAUDVAL" ]; then
      add security sv_qaudctl "IBM i auditing control (QAUDCTL)" NOT_ASSESSED low \
          "not assessed — QAUDCTL character value empty" \
          "The QAUDCTL row was present but its character value was empty, so the setting cannot be scored." \
          "confirm the QAUDCTL character column is populated in QSYS2.SYSTEM_VALUE_INFO, then re-take cap-system-values." \
          "cis-l2"
    else
      TOK=$(printf '%s\n' "$QAUDVAL" | awk '
        {
          n=split($0, a, /[ \t]+/)
          for (i=1; i<=n; i++) {
            if (a[i]=="*NOTAVL") nv=1
            if (a[i]=="*NONE") none=1
            if (a[i]=="*AUDLVL") aud=1
            if (a[i]=="*OBJAUD") obj=1
            if (a[i]=="*NOQTEMP") nqt=1
          }
        }
        END {
          if (nv) print "NOTAVL"
          else if (none) print "NONE"
          else if (aud && obj && nqt) print "PASS"
          else {
            miss = ""
            if (!aud) miss = miss " *AUDLVL"
            if (!obj) miss = miss " *OBJAUD"
            if (!nqt) miss = miss " *NOQTEMP"
            print "PARTIAL" miss
          }
        }')
      if [ "$TOK" = NOTAVL ]; then
        add security sv_qaudctl "IBM i auditing control (QAUDCTL)" NOT_ASSESSED low \
            "not assessed — QAUDCTL=*NOTAVL (scan profile lacks *AUDIT)" \
            "The scan profile cannot read QAUDCTL. IBM returns *NOTAVL when the job lacks *AUDIT (or equivalent catalog authority). That is not a configured value and is not a clean result." \
            "grant the scan profile *AUDIT (or the catalog authority to read QAUDCTL), re-take cap-system-values, and re-run. This scanner never grants authority and never changes QAUDCTL." \
            "cis-l2"
      elif [ "$TOK" = NONE ]; then
        add security sv_qaudctl "IBM i auditing control (QAUDCTL)" FAIL high \
            "QAUDCTL=$QAUDVAL" \
            "IBM i security auditing is not fully on. QAUDCTL is the on/off switch for action and object auditing; IBM ships it off, and an incident then leaves no security-audit-journal trail." \
            "from a profile that may change system values, set QAUDCTL so it includes *AUDLVL *OBJAUD *NOQTEMP (CHGSYSVAL SYSVAL(QAUDCTL) VALUE('*NOQTEMP *OBJAUD *AUDLVL')) and confirm with DSPSYSVAL SYSVAL(QAUDCTL). This scanner never changes QAUDCTL." \
            "cis-l2"
      elif [ "$TOK" = PASS ]; then
        add security sv_qaudctl "IBM i auditing control (QAUDCTL)" PASS low \
            "QAUDCTL=$QAUDVAL" \
            "QAUDCTL includes action auditing, object auditing, and the no-QTEMP flag, so IBM i security auditing is on." \
            "n/a" \
            "cis-l2"
      else
        MISSING=${TOK#PARTIAL}
        add security sv_qaudctl "IBM i auditing control (QAUDCTL)" FAIL medium \
            "QAUDCTL=$QAUDVAL" \
            "IBM i security auditing is only partially configured: QAUDCTL is missing:$MISSING. The required CIS token set is *AUDLVL *OBJAUD *NOQTEMP; *NOQTEMP suppresses audit-journal noise from QTEMP." \
            "from a profile that may change system values, set QAUDCTL so it includes *AUDLVL *OBJAUD *NOQTEMP (CHGSYSVAL SYSVAL(QAUDCTL) VALUE('*NOQTEMP *OBJAUD *AUDLVL')) and confirm with DSPSYSVAL SYSVAL(QAUDCTL). This scanner never changes QAUDCTL." \
            "cis-l2"
      fi
    fi
  fi

  # sv_qaudendacn — IBM i QAUDENDACN (auditing end action).
  # Authority: CIS IBM i V7R5M0/V7R4M0 5.1.1.4 (L1=*NOTIFY) and 5.1.2.4
  # (L2=*PWRDWNSYS, tag only). One finding. Parses the shared
  # cap-system-values dump. Does not call ibmi_sql. Does not CHGSYSVAL.
  # *NOTAVL is a missing-*AUDIT refusal, never PASS. Exact *NOTIFY is PASS.
  # Exact *PWRDWNSYS is FAIL (L2 token). live Phase 0 dump is
  # QAUDENDACN||*NOTAVL.
  if [ "${SYSVAL_OK:-0}" -ne 1 ]; then
    add security sv_qaudendacn "Auditing end action" NOT_ASSESSED low \
        "not assessed — ${SYSVAL_WHY:-capture unavailable}" \
        "The SYSTEM_VALUE_INFO capture did not yield a readable dump, so QAUDENDACN cannot be graded." \
        "re-run the scan as the scan profile and confirm QSYS2.SYSTEM_VALUE_INFO returns rows. This scanner never changes system values."
  else
    QEND_LINE=$(printf '%s\n' "$SYSVAL_RAW" | awk -F'|' '$1=="QAUDENDACN"{n++; line=$0} END{if(n==1) print line}')
    if [ -z "$QEND_LINE" ]; then
      add security sv_qaudendacn "Auditing end action" NOT_ASSESSED low \
          "not assessed — QAUDENDACN row missing or not unique in SYSTEM_VALUE_INFO" \
          "The system-value dump was readable, but it did not contain exactly one QAUDENDACN row, so the value cannot be graded." \
          "inspect QSYS2.SYSTEM_VALUE_INFO for SYSTEM_VALUE_NAME = QAUDENDACN."
    else
      QEND_RAW=$(printf '%s\n' "$QEND_LINE" | awk -F'|' '{ v=$3; if (v=="") v=$2; sub(/[ \t]+$/, "", v); print v }')
      if [ "$QEND_RAW" = "*NOTAVL" ]; then
        add security sv_qaudendacn "Auditing end action" NOT_ASSESSED low \
            "not assessed — QAUDENDACN=*NOTAVL (scan profile lacks *AUDIT)" \
            "The scan profile cannot read QAUDENDACN. IBM returns *NOTAVL when the job lacks *AUDIT (or equivalent catalog authority). That is not a configured value and is not a clean result." \
            "grant the scan profile *AUDIT (or the catalog authority to read QAUDENDACN), re-take cap-system-values, and re-run. This scanner never grants authority and never changes QAUDENDACN."
      elif [ -z "$QEND_RAW" ]; then
        add security sv_qaudendacn "Auditing end action" NOT_ASSESSED low \
            "not assessed — QAUDENDACN value unreadable" \
            "The QAUDENDACN row was present, but the catalog value was not *NOTIFY, *PWRDWNSYS, or *NOTAVL, so it is not graded." \
            "inspect the QAUDENDACN row in QSYS2.SYSTEM_VALUE_INFO and DSPSYSVAL SYSVAL(QAUDENDACN)."
      elif [ "$QEND_RAW" = "*NOTIFY" ]; then
        add security sv_qaudendacn "Auditing end action" PASS low \
            "QAUDENDACN=*NOTIFY" \
            "QAUDENDACN is *NOTIFY, so if the audit journal cannot be written the system keeps running and notifies the operator." \
            "n/a"
      elif [ "$QEND_RAW" = "*PWRDWNSYS" ]; then
        add security sv_qaudendacn "Auditing end action" FAIL high \
            "QAUDENDACN=*PWRDWNSYS" \
            "QAUDENDACN is *PWRDWNSYS, so if the audit journal cannot be written the system powers down immediately." \
            "set QAUDENDACN to *NOTIFY using CHGSYSVAL SYSVAL(QAUDENDACN) VALUE('*NOTIFY'). This scanner never changes system values."
      else
        add security sv_qaudendacn "Auditing end action" NOT_ASSESSED low \
            "not assessed — QAUDENDACN value unreadable" \
            "The QAUDENDACN row was present, but the catalog value was not *NOTIFY, *PWRDWNSYS, or *NOTAVL, so it is not graded." \
            "inspect the QAUDENDACN row in QSYS2.SYSTEM_VALUE_INFO and DSPSYSVAL SYSVAL(QAUDENDACN)."
      fi
    fi
  fi

  # sv_qaudfrclvl — IBM i QAUDFRCLVL (auditing force level).
  # Authority: CIS IBM i V7R5M0/V7R4M0 5.1.1.5 (L1=*SYS) and 5.1.2.5
  # (L2=*SYS, tag only). One finding. Parses the shared
  # cap-system-values dump. Does not call ibmi_sql. Does not CHGSYSVAL.
  # *NOTAVL is a refusal, never PASS. Exact *SYS or catalog -1/0 is PASS.
  # Integer 1-100 is FAIL. live Phase 0 dump is QAUDFRCLVL|-1|; live QSECOFR
  # dump is QAUDFRCLVL|0| (both encode *SYS).
  if [ "${SYSVAL_OK:-0}" -ne 1 ]; then
    add security sv_qaudfrclvl "Auditing force level" NOT_ASSESSED low \
        "not assessed — ${SYSVAL_WHY:-capture unavailable}" \
        "The SYSTEM_VALUE_INFO capture did not yield a readable dump, so QAUDFRCLVL cannot be graded." \
        "re-run the scan as the scan profile and confirm QSYS2.SYSTEM_VALUE_INFO returns rows. This scanner never changes system values." \
        "cis-l1 cis-l2"
  else
    QFRC_LINE=$(printf '%s\n' "$SYSVAL_RAW" | awk -F'|' '$1=="QAUDFRCLVL"{n++; line=$0} END{if(n==1) print line}')
    if [ -z "$QFRC_LINE" ]; then
      add security sv_qaudfrclvl "Auditing force level" NOT_ASSESSED low \
          "not assessed — QAUDFRCLVL row missing or not unique in SYSTEM_VALUE_INFO" \
          "The system-value dump was readable, but it did not contain exactly one QAUDFRCLVL row, so the value cannot be graded." \
          "inspect QSYS2.SYSTEM_VALUE_INFO for SYSTEM_VALUE_NAME = QAUDFRCLVL." \
          "cis-l1 cis-l2"
    else
      QFRC_RAW=$(printf '%s\n' "$QFRC_LINE" | awk -F'|' '{ v=$3; if (v=="") v=$2; sub(/[ \t]+$/, "", v); print v }')
      if [ "$QFRC_RAW" = "*NOTAVL" ]; then
        add security sv_qaudfrclvl "Auditing force level" NOT_ASSESSED low \
            "not assessed — QAUDFRCLVL=*NOTAVL (scan profile cannot read this system value)" \
            "The catalog returned *NOTAVL for QAUDFRCLVL — the scan profile lacks authority to read this system value, so the value is not graded." \
            "grant the scan profile read access to QAUDFRCLVL and re-take cap-system-values. Do not run this check as QSECOFR to paper over the gap." \
            "cis-l1 cis-l2"
      elif [ -z "$QFRC_RAW" ]; then
        add security sv_qaudfrclvl "Auditing force level" NOT_ASSESSED low \
            "not assessed — QAUDFRCLVL value unreadable" \
            "The QAUDFRCLVL row was present, but the catalog value was not *SYS, -1, an integer 1-100, or *NOTAVL, so it is not graded." \
            "inspect the QAUDFRCLVL row in QSYS2.SYSTEM_VALUE_INFO and DSPSYSVAL SYSVAL(QAUDFRCLVL)." \
            "cis-l1 cis-l2"
      elif [ "$QFRC_RAW" = "*SYS" ] || [ "$QFRC_RAW" = "-1" ] || [ "$QFRC_RAW" = "0" ]; then
        add security sv_qaudfrclvl "Auditing force level" PASS low \
            "QAUDFRCLVL=*SYS" \
            "QAUDFRCLVL is *SYS, so the system writes new audit journal entries to auxiliary storage as needed rather than waiting for a count." \
            "n/a" \
            "cis-l1 cis-l2"
      else
        QFRC_N=$(printf '%s\n' "$QFRC_RAW" | awk '/^[0-9]+$/{ if ($0 ~ /^0+$/) print 0; else { sub(/^0+/,""); print } }')
        if [ -n "$QFRC_N" ] && [ "$QFRC_N" -ge 1 ] && [ "$QFRC_N" -le 100 ]; then
          add security sv_qaudfrclvl "Auditing force level" FAIL high \
              "QAUDFRCLVL=$QFRC_N" \
              "QAUDFRCLVL is a record count, so new audit journal entries can sit in memory until that many accumulate and can be lost on a crash." \
              "set QAUDFRCLVL to *SYS using CHGSYSVAL SYSVAL(QAUDFRCLVL) VALUE('*SYS'). This scanner never changes system values." \
              "cis-l1 cis-l2"
        else
          add security sv_qaudfrclvl "Auditing force level" NOT_ASSESSED low \
              "not assessed — QAUDFRCLVL value unreadable" \
              "The QAUDFRCLVL row was present, but the catalog value was not *SYS, -1, an integer 1-100, or *NOTAVL, so it is not graded." \
              "inspect the QAUDFRCLVL row in QSYS2.SYSTEM_VALUE_INFO and DSPSYSVAL SYSVAL(QAUDFRCLVL)." \
              "cis-l1 cis-l2"
        fi
      fi
    fi
  fi

  # sv_qaudlvl — IBM i QAUDLVL (auditing level).
  # Authority: CIS IBM i V7R5M0 5.1.1.6 (L1). No L2 rec for this
  # control (5.1.2.6 is a different sysval). One finding. Parses the
  # shared cap-system-values dump. Does not call ibmi_sql. Does not
  # CHGSYSVAL. *NOTAVL is a missing-*AUDIT refusal, never PASS.
  # All nine required tokens must be present (extras allowed).
  # *NONE (IBM ship default) is FAIL. live Phase 0 dump is
  # QAUDLVL||*NOTAVL. Sibling ck-sv-qaudlvl2 owns QAUDLVL2.
  if [ "${SYSVAL_OK:-0}" -ne 1 ]; then
    add security sv_qaudlvl "Auditing level" NOT_ASSESSED low \
        "not assessed — ${SYSVAL_WHY:-capture unavailable}" \
        "The SYSTEM_VALUE_INFO capture did not yield a readable dump, so QAUDLVL cannot be graded." \
        "re-run the scan as the scan profile and confirm QSYS2.SYSTEM_VALUE_INFO returns rows. This scanner never changes system values." \
        "cis-l1"
  else
    QLVL_LINE=$(printf '%s\n' "$SYSVAL_RAW" | awk -F'|' '$1=="QAUDLVL"{n++; line=$0} END{if(n==1) print line}')
    QLVL_LINE_RC=$?
    if [ "$QLVL_LINE_RC" -ne 0 ] || [ -z "$QLVL_LINE" ]; then
      add security sv_qaudlvl "Auditing level" NOT_ASSESSED low \
          "not assessed — QAUDLVL row missing or not unique in SYSTEM_VALUE_INFO" \
          "The system-value dump was readable, but it did not contain exactly one QAUDLVL row, so the value cannot be graded." \
          "inspect QSYS2.SYSTEM_VALUE_INFO for SYSTEM_VALUE_NAME = QAUDLVL." \
          "cis-l1"
    else
      QLVL_VAL=$(printf '%s\n' "$QLVL_LINE" | awk -F'|' '{ v=$3; if (v=="") v=$2; sub(/[ \t]+$/, "", v); print v }')
      if [ -z "$QLVL_VAL" ]; then
        add security sv_qaudlvl "Auditing level" NOT_ASSESSED low \
            "not assessed — QAUDLVL value unreadable" \
            "The QAUDLVL row was present, but the catalog value was empty, so it is not graded." \
            "inspect the QAUDLVL row in QSYS2.SYSTEM_VALUE_INFO and DSPSYSVAL SYSVAL(QAUDLVL)." \
            "cis-l1"
      else
        QLVL_TOK=$(printf '%s\n' "$QLVL_VAL" | awk '
          {
            n=split($0, a, /[ \t]+/)
            for (i=1; i<=n; i++) {
              if (a[i]=="") continue
              if (a[i]=="*NOTAVL") nv=1
              if (a[i]=="*NONE") none=1
              if (a[i]=="*AUTFAIL") aut=1
              if (a[i]=="*CREATE") cre=1
              if (a[i]=="*DELETE") del=1
              if (a[i]=="*OBJMGT") obj=1
              if (a[i]=="*PGMFAIL") pgm=1
              if (a[i]=="*SAVRST") sav=1
              if (a[i]=="*SECURITY") sec=1
              if (a[i]=="*SERVICE") svc=1
              if (a[i]=="*SYSMGT") sys=1
            }
          }
          END {
            if (nv) print "NOTAVL"
            else if (none || !(aut && cre && del && obj && pgm && sav && sec && svc && sys)) print "FAIL"
            else print "PASS"
          }')
        if [ "$QLVL_TOK" = NOTAVL ]; then
          add security sv_qaudlvl "Auditing level" NOT_ASSESSED low \
              "not assessed — QAUDLVL=*NOTAVL (scan profile lacks *AUDIT)" \
              "The scan profile cannot read QAUDLVL. IBM returns *NOTAVL when the job lacks *AUDIT (or equivalent catalog authority). That is not a configured value and is not a clean result." \
              "grant the scan profile *AUDIT (or the catalog authority to read QAUDLVL), re-take cap-system-values, and re-run. This scanner never grants authority and never changes QAUDLVL." \
              "cis-l1"
        elif [ "$QLVL_TOK" = FAIL ]; then
          add security sv_qaudlvl "Auditing level" FAIL high \
              "QAUDLVL=$QLVL_VAL" \
              "QAUDLVL does not include every required action-auditing event, so some security-relevant activity is not written to the security audit journal." \
              "set QAUDLVL so it includes *AUTFAIL *CREATE *DELETE *OBJMGT *PGMFAIL *SAVRST *SECURITY *SERVICE *SYSMGT using CHGSYSVAL SYSVAL(QAUDLVL) VALUE('*AUTFAIL *CREATE *DELETE *OBJMGT *PGMFAIL *SAVRST *SECURITY *SERVICE *SYSMGT'). This scanner never changes system values." \
              "cis-l1"
        else
          add security sv_qaudlvl "Auditing level" PASS low \
              "QAUDLVL=$QLVL_VAL" \
              "QAUDLVL includes the required action-auditing events, so authority failures, object create and delete, object management, program failures, save and restore, security events, service-tool use, and system-management tasks are written to the security audit journal." \
              "n/a" \
              "cis-l1"
        fi
      fi
    fi
  fi

  # sv_qaudlvl2 — IBM i QAUDLVL2 (auditing level extension).
  # Authority: CIS IBM i V7R5M0/V7R4M0 5.1.1.7 (L1=*NONE). No L2 rec
  # for this control (5.1.2.6/5.1.2.7 are different sysvals). One
  # finding. Parses the shared cap-system-values dump. Does not call
  # ibmi_sql. Does not CHGSYSVAL. *NOTAVL is a missing-*AUDIT refusal,
  # never PASS. Exact *NONE (IBM ship default) is PASS. Extra tokens
  # are FAIL. live Phase 0 dump is QAUDLVL2||*NOTAVL. Sibling
  # ck-sv-qaudlvl owns QAUDLVL; do not inspect it here.
  if [ "${SYSVAL_OK:-0}" -ne 1 ]; then
    add security sv_qaudlvl2 "Auditing level extension" NOT_ASSESSED low \
        "not assessed — ${SYSVAL_WHY:-capture unavailable}" \
        "The SYSTEM_VALUE_INFO capture did not yield a readable dump, so QAUDLVL2 cannot be graded." \
        "re-run the scan as the scan profile and confirm QSYS2.SYSTEM_VALUE_INFO returns rows. This scanner never changes system values." \
        "cis-l1"
  else
    QL2_LINE=$(printf '%s\n' "$SYSVAL_RAW" | awk -F'|' '$1=="QAUDLVL2"{n++; line=$0} END{if(n==1) print line}')
    QL2_RC=$?
    if [ -z "$QL2_LINE" ]; then
      add security sv_qaudlvl2 "Auditing level extension" NOT_ASSESSED low \
          "not assessed — QAUDLVL2 row missing or not unique in SYSTEM_VALUE_INFO" \
          "The system-value dump was readable, but it did not contain exactly one QAUDLVL2 row, so the value cannot be graded." \
          "inspect QSYS2.SYSTEM_VALUE_INFO for SYSTEM_VALUE_NAME = QAUDLVL2." \
          "cis-l1"
    else
      QL2_VAL=$(printf '%s\n' "$QL2_LINE" | awk -F'|' '{ v=$3; if (v=="") v=$2; sub(/[ \t]+$/, "", v); print v }')
      if [ "$QL2_VAL" = "*NOTAVL" ]; then
        add security sv_qaudlvl2 "Auditing level extension" NOT_ASSESSED low \
            "not assessed — QAUDLVL2=*NOTAVL (scan profile lacks *AUDIT)" \
            "The scan profile cannot read QAUDLVL2. IBM returns *NOTAVL when the job lacks *AUDIT (or equivalent catalog authority). That is not a configured value and is not a clean result." \
            "grant the scan profile *AUDIT (or the catalog authority to read QAUDLVL2), re-take cap-system-values, and re-run. This scanner never grants authority and never changes QAUDLVL2." \
            "cis-l1"
      elif [ -z "$QL2_VAL" ]; then
        add security sv_qaudlvl2 "Auditing level extension" NOT_ASSESSED low \
            "not assessed — QAUDLVL2 value unreadable" \
            "The QAUDLVL2 row was present, but the catalog value was empty, so it is not graded." \
            "inspect the QAUDLVL2 row in QSYS2.SYSTEM_VALUE_INFO and DSPSYSVAL SYSVAL(QAUDLVL2)." \
            "cis-l1"
      elif [ "$QL2_VAL" = "*NONE" ]; then
        add security sv_qaudlvl2 "Auditing level extension" PASS low \
            "QAUDLVL2=*NONE" \
            "QAUDLVL2 is *NONE, so extra action-auditing events are not taken from the overflow list." \
            "n/a" \
            "cis-l1"
      else
        add security sv_qaudlvl2 "Auditing level extension" FAIL high \
            "QAUDLVL2=$QL2_VAL" \
            "QAUDLVL2 lists extra action-auditing events. The required events live on QAUDLVL; this overflow list must stay *NONE." \
            "set QAUDLVL2 to *NONE using CHGSYSVAL SYSVAL(QAUDLVL2) VALUE('*NONE'). This scanner never changes system values." \
            "cis-l1"
      fi
    fi
  fi

  # sv_qautocfg — IBM i QAUTOCFG (automatic device configuration).
  # Authority: CIS IBM i V7R5M0 Benchmark v2.1.0 5.1.1.8 (L1=0 / *NO). No L2 rec.
  # One finding. Parses the shared cap-system-values dump. Does not call
  # ibmi_sql. Does not CHGSYSVAL. *NOTAVL is a refusal, never PASS.
  # Exact 0 or *NO is PASS. Exact 1 or *YES is FAIL.
  # live Phase 0 dump is QAUTOCFG||1.
  if [ "${SYSVAL_OK:-0}" -ne 1 ]; then
    add security sv_qautocfg "Automatic device configuration" NOT_ASSESSED low \
        "not assessed — ${SYSVAL_WHY:-capture unavailable}" \
        "The SYSTEM_VALUE_INFO capture did not yield a readable dump, so QAUTOCFG cannot be graded." \
        "re-run the scan as the scan profile and confirm QSYS2.SYSTEM_VALUE_INFO returns rows. This scanner never changes system values." \
        "cis-l1"
  else
    QAC_LINE=$(printf '%s\n' "$SYSVAL_RAW" | awk -F'|' '$1=="QAUTOCFG"{n++; line=$0} END{if(n==1) print line}')
    QAC_RC=$?
    if [ -z "$QAC_LINE" ]; then
      add security sv_qautocfg "Automatic device configuration" NOT_ASSESSED low \
          "not assessed — QAUTOCFG row missing or not unique in SYSTEM_VALUE_INFO" \
          "The system-value dump was readable, but it did not contain exactly one QAUTOCFG row, so the value cannot be graded." \
          "inspect QSYS2.SYSTEM_VALUE_INFO for SYSTEM_VALUE_NAME = QAUTOCFG." \
          "cis-l1"
    else
      QAC_NUM=$(printf '%s\n' "$QAC_LINE" | awk -F'|' '{print $2}')
      QAC_CHR=$(printf '%s\n' "$QAC_LINE" | awk -F'|' '{print $3}')
      if [ -n "$QAC_NUM" ]; then
        QAC_RAW=$QAC_NUM
      else
        QAC_RAW=$QAC_CHR
      fi
      if [ "$QAC_RAW" = "*NOTAVL" ]; then
        add security sv_qautocfg "Automatic device configuration" NOT_ASSESSED low \
            "not assessed — QAUTOCFG=*NOTAVL (scan profile cannot read this system value)" \
            "The catalog returned *NOTAVL for QAUTOCFG — the scan profile lacks authority to read this system value, so the value is not graded." \
            "grant the scan profile read access to QAUTOCFG and re-take cap-system-values. Do not run this check as QSECOFR to paper over the gap." \
            "cis-l1"
      elif [ -z "$QAC_RAW" ]; then
        add security sv_qautocfg "Automatic device configuration" NOT_ASSESSED low \
            "not assessed — QAUTOCFG value unreadable" \
            "The QAUTOCFG row was present, but the catalog value was empty, so it is not graded." \
            "inspect the QAUTOCFG row in QSYS2.SYSTEM_VALUE_INFO and DSPSYSVAL SYSVAL(QAUTOCFG)." \
            "cis-l1"
      elif [ "$QAC_RAW" = "0" ] || [ "$QAC_RAW" = "*NO" ]; then
        add security sv_qautocfg "Automatic device configuration" PASS low \
            "QAUTOCFG=$QAC_RAW" \
            "QAUTOCFG is off (0 or *NO), so locally attached devices are not configured automatically." \
            "n/a" \
            "cis-l1"
      elif [ "$QAC_RAW" = "1" ] || [ "$QAC_RAW" = "*YES" ]; then
        add security sv_qautocfg "Automatic device configuration" FAIL high \
            "QAUTOCFG=$QAC_RAW" \
            "QAUTOCFG is on (1 or *YES), so locally attached devices are configured automatically when they appear." \
            "set QAUTOCFG to 0 using CHGSYSVAL SYSVAL(QAUTOCFG) VALUE('0'). This scanner never changes system values." \
            "cis-l1"
      else
        add security sv_qautocfg "Automatic device configuration" NOT_ASSESSED low \
            "not assessed — QAUTOCFG value unreadable" \
            "The QAUTOCFG row was present, but the catalog value was not 0, *NO, 1, *YES, or *NOTAVL, so it is not graded." \
            "inspect the QAUTOCFG row in QSYS2.SYSTEM_VALUE_INFO and DSPSYSVAL SYSVAL(QAUTOCFG)." \
            "cis-l1"
      fi
    fi
  fi

  # sv_qautormt — IBM i QAUTORMT (automatic remote controller configuration).
  # Authority: CIS IBM i V7R5M0 Benchmark v2.1.0 5.1.1.9 (L1=0). No L2 rec.
  # One finding. Parses the shared cap-system-values dump. Does not call
  # ibmi_sql. Does not CHGSYSVAL. *NOTAVL is a refusal, never PASS.
  # Exact 0 is PASS. Exact 1 (IBM ship default) is FAIL.
  # live Phase 0 dump is QAUTORMT||0.
  if [ "${SYSVAL_OK:-0}" -ne 1 ]; then
    add security sv_qautormt "Automatic remote controller configuration" NOT_ASSESSED low \
        "not assessed — ${SYSVAL_WHY:-capture unavailable}" \
        "The SYSTEM_VALUE_INFO capture did not yield a readable dump, so QAUTORMT cannot be graded." \
        "re-run the scan as the scan profile and confirm QSYS2.SYSTEM_VALUE_INFO returns rows. This scanner never changes system values." \
        "cis-l1"
  else
    QARM_LINE=$(printf '%s\n' "$SYSVAL_RAW" | awk -F'|' '$1=="QAUTORMT"{n++; line=$0} END{if(n==1) print line}')
    QARM_RC=$?
    if [ -z "$QARM_LINE" ]; then
      add security sv_qautormt "Automatic remote controller configuration" NOT_ASSESSED low \
          "not assessed — QAUTORMT row missing or not unique in SYSTEM_VALUE_INFO" \
          "The system-value dump was readable, but it did not contain exactly one QAUTORMT row, so the value cannot be graded." \
          "inspect QSYS2.SYSTEM_VALUE_INFO for SYSTEM_VALUE_NAME = QAUTORMT." \
          "cis-l1"
    else
      QARM_VAL=$(printf '%s\n' "$QARM_LINE" | awk -F'|' '{ v=$3; if (v=="") v=$2; sub(/[ \t]+$/, "", v); print v }')
      if [ "$QARM_VAL" = "*NOTAVL" ]; then
        add security sv_qautormt "Automatic remote controller configuration" NOT_ASSESSED low \
            "not assessed — QAUTORMT=*NOTAVL (scan profile cannot read this system value)" \
            "The catalog returned *NOTAVL for QAUTORMT — the scan profile lacks authority to read this system value, so the value is not graded." \
            "grant the scan profile read access to QAUTORMT and re-take cap-system-values. Do not run this check as QSECOFR to paper over the gap." \
            "cis-l1"
      elif [ -z "$QARM_VAL" ]; then
        add security sv_qautormt "Automatic remote controller configuration" NOT_ASSESSED low \
            "not assessed — QAUTORMT value unreadable" \
            "The QAUTORMT row was present, but the catalog value was empty, so it is not graded." \
            "inspect the QAUTORMT row in QSYS2.SYSTEM_VALUE_INFO and DSPSYSVAL SYSVAL(QAUTORMT)." \
            "cis-l1"
      elif [ "$QARM_VAL" = "0" ]; then
        add security sv_qautormt "Automatic remote controller configuration" PASS low \
            "QAUTORMT=0" \
            "QAUTORMT is 0, so remote controllers and devices are not configured automatically." \
            "n/a" \
            "cis-l1"
      elif [ "$QARM_VAL" = "1" ]; then
        add security sv_qautormt "Automatic remote controller configuration" FAIL high \
            "QAUTORMT=1" \
            "QAUTORMT is 1, so remote controllers and devices that connect to the system are configured automatically." \
            "set QAUTORMT to 0 using CHGSYSVAL SYSVAL(QAUTORMT) VALUE('0'). This scanner never changes system values." \
            "cis-l1"
      else
        add security sv_qautormt "Automatic remote controller configuration" NOT_ASSESSED low \
            "not assessed — QAUTORMT value unreadable" \
            "The QAUTORMT row was present, but the catalog value was not 0, 1, or *NOTAVL, so it is not graded." \
            "inspect the QAUTORMT row in QSYS2.SYSTEM_VALUE_INFO and DSPSYSVAL SYSVAL(QAUTORMT)." \
            "cis-l1"
      fi
    fi
  fi

  # sv_qautovrt — IBM i QAUTOVRT (automatic virtual device creation).
  # Authority: CIS IBM i V7R5M0/V7R4M0 5.1.1.10 (L1=32500 or less) and
  # 5.1.2.6 (L2=0). One finding. Parses the shared cap-system-values dump.
  # Does not call ibmi_sql. Does not CHGSYSVAL. *NOTAVL is a refusal,
  # never PASS. Integer 0-32500 inclusive is PASS (0 is stricter than L1).
  # *NOMAX or integer >32500 is FAIL. *REGFAC is unreadable, not 0.
  # live Phase 0 dump is QAUTOVRT|0| -> 0.
  if [ "${SYSVAL_OK:-0}" -ne 1 ]; then
    add security sv_qautovrt "Automatic virtual device creation" NOT_ASSESSED low \
        "not assessed — ${SYSVAL_WHY:-capture unavailable}" \
        "The SYSTEM_VALUE_INFO capture did not yield a readable dump, so QAUTOVRT cannot be graded." \
        "re-run the scan as the scan profile and confirm QSYS2.SYSTEM_VALUE_INFO returns rows. This scanner never changes system values." \
        "cis-l1 cis-l2"
  else
    QAV_LINE=$(printf '%s\n' "$SYSVAL_RAW" | awk -F'|' '$1=="QAUTOVRT"{n++; line=$0} END{if(n==1) print line}')
    QAV_RC=$?
    if [ -z "$QAV_LINE" ]; then
      add security sv_qautovrt "Automatic virtual device creation" NOT_ASSESSED low \
          "not assessed — QAUTOVRT row missing or not unique in SYSTEM_VALUE_INFO" \
          "The system-value dump was readable, but it did not contain exactly one QAUTOVRT row, so the value cannot be graded." \
          "inspect QSYS2.SYSTEM_VALUE_INFO for SYSTEM_VALUE_NAME = QAUTOVRT." \
          "cis-l1 cis-l2"
    else
      QAV_NUM=$(printf '%s\n' "$QAV_LINE" | awk -F'|' '{print $2}')
      QAV_CHR=$(printf '%s\n' "$QAV_LINE" | awk -F'|' '{print $3}')
      if [ -n "$QAV_NUM" ]; then
        QAV_RAW=$QAV_NUM
      else
        QAV_RAW=$QAV_CHR
      fi
      if [ "$QAV_RAW" = "*NOTAVL" ]; then
        add security sv_qautovrt "Automatic virtual device creation" NOT_ASSESSED low \
            "not assessed — QAUTOVRT=*NOTAVL (scan profile cannot read this system value)" \
            "The catalog returned *NOTAVL for QAUTOVRT — the scan profile lacks authority to read this system value, so the value is not graded." \
            "grant the scan profile read access to QAUTOVRT and re-take cap-system-values. Do not run this check as QSECOFR to paper over the gap." \
            "cis-l1 cis-l2"
      elif [ "$QAV_RAW" = "*NOMAX" ]; then
        add security sv_qautovrt "Automatic virtual device creation" FAIL high \
            "QAUTOVRT=*NOMAX" \
            "QAUTOVRT is *NOMAX or greater than 32500, so automatic virtual-device creation is not bounded to a finite count." \
            "set QAUTOVRT to 32500 or less, not *NOMAX, using CHGSYSVAL SYSVAL(QAUTOVRT) VALUE('0'). This scanner never changes system values." \
            "cis-l1 cis-l2"
      else
        QAVN=$(printf '%s\n' "$QAV_RAW" | awk '/^[0-9]+$/{ if ($0 ~ /^0+$/) print 0; else { sub(/^0+/,""); print } }')
        if [ -z "$QAVN" ]; then
          add security sv_qautovrt "Automatic virtual device creation" NOT_ASSESSED low \
              "not assessed — QAUTOVRT value unreadable" \
              "The QAUTOVRT row was present, but the catalog value was not an integer, *NOMAX, or *NOTAVL, so it is not graded." \
              "inspect the QAUTOVRT row in QSYS2.SYSTEM_VALUE_INFO and DSPSYSVAL SYSVAL(QAUTOVRT)." \
              "cis-l1 cis-l2"
        elif [ "$QAVN" -gt 32500 ]; then
          add security sv_qautovrt "Automatic virtual device creation" FAIL high \
              "QAUTOVRT=$QAVN" \
              "QAUTOVRT is *NOMAX or greater than 32500, so automatic virtual-device creation is not bounded to a finite count." \
              "set QAUTOVRT to 32500 or less, not *NOMAX, using CHGSYSVAL SYSVAL(QAUTOVRT) VALUE('0'). This scanner never changes system values." \
              "cis-l1 cis-l2"
        else
          add security sv_qautovrt "Automatic virtual device creation" PASS low \
              "QAUTOVRT=$QAVN" \
              "QAUTOVRT bounds automatic virtual-device creation to a finite count (at most 32500)." \
              "n/a" \
              "cis-l1 cis-l2"
        fi
      fi
    fi
  fi

  # sv_qcrtaut — IBM i QCRTAUT (create default public authority).
  # Authority: CIS IBM i V7R5M0/V7R4M0 5.1.1.11 (L1=*USE) and 5.1.2.7 (L2=*EXCLUDE).
  # One finding. Parses the shared cap-system-values dump. Does not call
  # ibmi_sql. Does not CHGSYSVAL. *NOTAVL is a refusal, never PASS.
  # Exact *USE or exact *EXCLUDE is PASS (*EXCLUDE is stricter than L1).
  # *CHANGE (IBM ship default) or *ALL is FAIL.
  # live Phase 0 dump is QCRTAUT||*USE.
  if [ "${SYSVAL_OK:-0}" -ne 1 ]; then
    add security sv_qcrtaut "Create authority" NOT_ASSESSED low \
        "not assessed — ${SYSVAL_WHY:-capture unavailable}" \
        "The SYSTEM_VALUE_INFO capture did not yield a readable dump, so QCRTAUT cannot be graded." \
        "re-run the scan as the scan profile and confirm QSYS2.SYSTEM_VALUE_INFO returns rows. This scanner never changes system values." \
        "cis-l1 cis-l2"
  else
    QCRT_LINE=$(printf '%s\n' "$SYSVAL_RAW" | awk -F'|' '$1=="QCRTAUT"{n++; line=$0} END{if(n==1) print line}')
    QCRT_RC=$?
    if [ -z "$QCRT_LINE" ]; then
      add security sv_qcrtaut "Create authority" NOT_ASSESSED low \
          "not assessed — QCRTAUT row missing or not unique in SYSTEM_VALUE_INFO" \
          "The system-value dump was readable, but it did not contain exactly one QCRTAUT row, so the value cannot be graded." \
          "inspect QSYS2.SYSTEM_VALUE_INFO for SYSTEM_VALUE_NAME = QCRTAUT." \
          "cis-l1 cis-l2"
    else
      QCRT_RAW=$(printf '%s\n' "$QCRT_LINE" | awk -F'|' '{ v=$3; if (v=="") v=$2; sub(/[ \t]+$/, "", v); print v }')
      if [ "$QCRT_RAW" = "*NOTAVL" ]; then
        add security sv_qcrtaut "Create authority" NOT_ASSESSED low \
            "not assessed — QCRTAUT=*NOTAVL (scan profile cannot read this system value)" \
            "The catalog returned *NOTAVL for QCRTAUT — the scan profile lacks authority to read this system value, so the value is not graded." \
            "grant the scan profile read access to QCRTAUT and re-take cap-system-values. Do not run this check as QSECOFR to paper over the gap." \
            "cis-l1 cis-l2"
      elif [ -z "$QCRT_RAW" ]; then
        add security sv_qcrtaut "Create authority" NOT_ASSESSED low \
            "not assessed — QCRTAUT value unreadable" \
            "The QCRTAUT row was present, but the catalog value was not *USE, *EXCLUDE, *CHANGE, *ALL, or *NOTAVL, so it is not graded." \
            "inspect the QCRTAUT row in QSYS2.SYSTEM_VALUE_INFO and DSPSYSVAL SYSVAL(QCRTAUT)." \
            "cis-l1 cis-l2"
      elif [ "$QCRT_RAW" = "*USE" ] || [ "$QCRT_RAW" = "*EXCLUDE" ]; then
        add security sv_qcrtaut "Create authority" PASS low \
            "QCRTAUT=$QCRT_RAW" \
            "QCRTAUT is *USE or *EXCLUDE, so *PUBLIC cannot change newly created objects that inherit the system value." \
            "n/a" \
            "cis-l1 cis-l2"
      elif [ "$QCRT_RAW" = "*CHANGE" ] || [ "$QCRT_RAW" = "*ALL" ]; then
        add security sv_qcrtaut "Create authority" FAIL high \
            "QCRTAUT=$QCRT_RAW" \
            "QCRTAUT is *CHANGE or *ALL, so *PUBLIC can change or fully control newly created objects that inherit the system value." \
            "set QCRTAUT to *USE, or to *EXCLUDE, using CHGSYSVAL SYSVAL(QCRTAUT) VALUE('*USE'). This scanner never changes system values." \
            "cis-l1 cis-l2"
      else
        add security sv_qcrtaut "Create authority" NOT_ASSESSED low \
            "not assessed — QCRTAUT value unreadable" \
            "The QCRTAUT row was present, but the catalog value was not *USE, *EXCLUDE, *CHANGE, *ALL, or *NOTAVL, so it is not graded." \
            "inspect the QCRTAUT row in QSYS2.SYSTEM_VALUE_INFO and DSPSYSVAL SYSVAL(QCRTAUT)." \
            "cis-l1 cis-l2"
      fi
    fi
  fi

  # sv_qcrtobjaud — IBM i QCRTOBJAUD (create object audit level).
  # Authority: CIS IBM i V7R5M0/V7R4M0 5.1.2.8 (L2=*ALL). No L1 rec.
  # One finding. Parses the shared cap-system-values dump. Does not call
  # ibmi_sql. Does not CHGSYSVAL. *NOTAVL is a refusal, never PASS.
  # Exact *ALL is PASS. Exact *NONE, *USRPRF, or *CHANGE is FAIL.
  # live Phase 0 dump is QCRTOBJAUD||*NOTAVL.
  if [ "${SYSVAL_OK:-0}" -ne 1 ]; then
    add security sv_qcrtobjaud "Create object audit level" NOT_ASSESSED low \
        "not assessed — ${SYSVAL_WHY:-capture unavailable}" \
        "The SYSTEM_VALUE_INFO capture did not yield a readable dump, so QCRTOBJAUD cannot be graded." \
        "re-run the scan as the scan profile and confirm QSYS2.SYSTEM_VALUE_INFO returns rows. This scanner never changes system values." \
        "cis-l2"
  else
    QCOA_LINE=$(printf '%s\n' "$SYSVAL_RAW" | awk -F'|' '$1=="QCRTOBJAUD"{n++; line=$0} END{if(n==1) print line}')
    QCOA_RC=$?
    if [ -z "$QCOA_LINE" ]; then
      add security sv_qcrtobjaud "Create object audit level" NOT_ASSESSED low \
          "not assessed — QCRTOBJAUD row missing or not unique in SYSTEM_VALUE_INFO" \
          "The system-value dump was readable, but it did not contain exactly one QCRTOBJAUD row, so the value cannot be graded." \
          "inspect QSYS2.SYSTEM_VALUE_INFO for SYSTEM_VALUE_NAME = QCRTOBJAUD." \
          "cis-l2"
    else
      QCOA_VAL=$(printf '%s\n' "$QCOA_LINE" | awk -F'|' '{ v=$3; if (v=="") v=$2; sub(/[ \t]+$/, "", v); print v }')
      if [ "$QCOA_VAL" = "*NOTAVL" ]; then
        add security sv_qcrtobjaud "Create object audit level" NOT_ASSESSED low \
            "not assessed — QCRTOBJAUD=*NOTAVL (scan profile cannot read this system value)" \
            "The catalog returned *NOTAVL for QCRTOBJAUD — the scan profile lacks *AUDIT or *ALLOBJ, so the value is not graded." \
            "grant the scan profile *AUDIT (or *ALLOBJ) and re-take cap-system-values. Do not run this check as QSECOFR to paper over the gap." \
            "cis-l2"
      elif [ -z "$QCOA_VAL" ]; then
        add security sv_qcrtobjaud "Create object audit level" NOT_ASSESSED low \
            "not assessed — QCRTOBJAUD value unreadable" \
            "The QCRTOBJAUD row was present, but the catalog value was not *ALL, *NONE, *USRPRF, *CHANGE, or *NOTAVL, so it is not graded." \
            "inspect the QCRTOBJAUD row in QSYS2.SYSTEM_VALUE_INFO and DSPSYSVAL SYSVAL(QCRTOBJAUD)." \
            "cis-l2"
      elif [ "$QCOA_VAL" = "*ALL" ]; then
        add security sv_qcrtobjaud "Create object audit level" PASS low \
            "QCRTOBJAUD=*ALL" \
            "QCRTOBJAUD is *ALL, so newly created objects that inherit the system value get object auditing for contents access and for security-relevant change." \
            "n/a" \
            "cis-l2"
      elif [ "$QCOA_VAL" = "*NONE" ] || [ "$QCOA_VAL" = "*USRPRF" ] || [ "$QCOA_VAL" = "*CHANGE" ]; then
        add security sv_qcrtobjaud "Create object audit level" FAIL high \
            "QCRTOBJAUD=$QCOA_VAL" \
            "QCRTOBJAUD is not *ALL, so newly created objects that inherit the system value are not fully object-audited." \
            "set QCRTOBJAUD to *ALL using CHGSYSVAL SYSVAL(QCRTOBJAUD) VALUE('*ALL'). This scanner never changes system values." \
            "cis-l2"
      else
        add security sv_qcrtobjaud "Create object audit level" NOT_ASSESSED low \
            "not assessed — QCRTOBJAUD value unreadable" \
            "The QCRTOBJAUD row was present, but the catalog value was not *ALL, *NONE, *USRPRF, *CHANGE, or *NOTAVL, so it is not graded." \
            "inspect the QCRTOBJAUD row in QSYS2.SYSTEM_VALUE_INFO and DSPSYSVAL SYSVAL(QCRTOBJAUD)." \
            "cis-l2"
      fi
    fi
  fi

  # sv_qdscjobitv — IBM i QDSCJOBITV (disconnected-job time-out interval).
  # Authority: CIS IBM i V7R5M0/V7R4M0 5.1.1.12 (L1=30) and 5.1.2.9 (L2=15).
  # Only the L1 threshold is graded; the L2 threshold (5.1.2.9, 15) is not.
  # One finding. Parses the shared cap-system-values dump. Does not call
  # ibmi_sql. Does not CHGSYSVAL. *NOTAVL is a refusal, never PASS.
  # Integer 5-30 inclusive is PASS (lower is stricter than L1). *NONE or
  # integer >30 is FAIL. live Phase 0 dump is QDSCJOBITV||0000000060 -> 60
  # and is FAIL (IBM recommended 60 is still over L1).
  if [ "${SYSVAL_OK:-0}" -ne 1 ]; then
    add security sv_qdscjobitv "Disconnect-job interval" NOT_ASSESSED low \
        "not assessed — ${SYSVAL_WHY:-capture unavailable}" \
        "The SYSTEM_VALUE_INFO capture did not yield a readable dump, so QDSCJOBITV cannot be graded." \
        "re-run the scan as the scan profile and confirm QSYS2.SYSTEM_VALUE_INFO returns rows. This scanner never changes system values." \
        "cis-l1"
  else
    QDSC_LINE=$(printf '%s\n' "$SYSVAL_RAW" | awk -F'|' '$1=="QDSCJOBITV"{n++; line=$0} END{if(n==1) print line}')
    QDSC_RC=$?
    if [ -z "$QDSC_LINE" ]; then
      add security sv_qdscjobitv "Disconnect-job interval" NOT_ASSESSED low \
          "not assessed — QDSCJOBITV row missing or not unique in SYSTEM_VALUE_INFO" \
          "The system-value dump was readable, but it did not contain exactly one QDSCJOBITV row, so the value cannot be graded." \
          "inspect QSYS2.SYSTEM_VALUE_INFO for SYSTEM_VALUE_NAME = QDSCJOBITV." \
          "cis-l1"
    else
      QDSC_NUM=$(printf '%s\n' "$QDSC_LINE" | awk -F'|' '{print $2}')
      QDSC_CHR=$(printf '%s\n' "$QDSC_LINE" | awk -F'|' '{print $3}')
      if [ -n "$QDSC_NUM" ]; then
        QDSC_RAW=$QDSC_NUM
      else
        QDSC_RAW=$QDSC_CHR
      fi
      if [ "$QDSC_RAW" = "*NOTAVL" ]; then
        add security sv_qdscjobitv "Disconnect-job interval" NOT_ASSESSED low \
            "not assessed — QDSCJOBITV=*NOTAVL (scan profile cannot read this system value)" \
            "The catalog returned *NOTAVL for QDSCJOBITV — the scan profile lacks authority to read this system value, so the value is not graded." \
            "grant the scan profile read access to QDSCJOBITV and re-take cap-system-values. Do not run this check as QSECOFR to paper over the gap." \
            "cis-l1"
      elif [ "$QDSC_RAW" = "*NONE" ]; then
        add security sv_qdscjobitv "Disconnect-job interval" FAIL high \
            "QDSCJOBITV=*NONE" \
            "QDSCJOBITV is *NONE or greater than 30 minutes, so a disconnected interactive job can stay allocated longer than a small interval." \
            "set QDSCJOBITV to 30 or less, not *NONE, using CHGSYSVAL SYSVAL(QDSCJOBITV) VALUE('30'). This scanner never changes system values." \
            "cis-l1"
      else
        QDSCN=$(printf '%s\n' "$QDSC_RAW" | awk '/^[0-9]+$/{ if ($0 ~ /^0+$/) print 0; else { sub(/^0+/,""); print } }')
        if [ -z "$QDSCN" ] || [ "$QDSCN" -lt 5 ]; then
          add security sv_qdscjobitv "Disconnect-job interval" NOT_ASSESSED low \
              "not assessed — QDSCJOBITV value unreadable" \
              "The QDSCJOBITV row was present, but the catalog value was not an integer 5-1440, *NONE, or *NOTAVL, so it is not graded." \
              "inspect the QDSCJOBITV row in QSYS2.SYSTEM_VALUE_INFO and DSPSYSVAL SYSVAL(QDSCJOBITV)." \
              "cis-l1"
        elif [ "$QDSCN" -gt 30 ]; then
          add security sv_qdscjobitv "Disconnect-job interval" FAIL high \
              "QDSCJOBITV=$QDSCN" \
              "QDSCJOBITV is *NONE or greater than 30 minutes, so a disconnected interactive job can stay allocated longer than a small interval." \
              "set QDSCJOBITV to 30 or less, not *NONE, using CHGSYSVAL SYSVAL(QDSCJOBITV) VALUE('30'). This scanner never changes system values." \
              "cis-l1"
        else
          add security sv_qdscjobitv "Disconnect-job interval" PASS low \
              "QDSCJOBITV=$QDSCN" \
              "QDSCJOBITV ends disconnected interactive jobs after a short interval (at most 30 minutes), so a disconnected job does not hold resources indefinitely." \
              "n/a" \
              "cis-l1"
        fi
      fi
    fi
  fi

  # sv_qdspsgninf — IBM i QDSPSGNINF (display sign-on information).
  # Authority: CIS IBM i V7R5M0 5.1.1.13 (L1=1). No L2 rec.
  # One finding. Parses the shared cap-system-values dump. Does not call
  # ibmi_sql. Does not CHGSYSVAL. *NOTAVL is a refusal, never PASS.
  # Exact 1 is PASS. Exact 0 (IBM ship default) is FAIL.
  # live Phase 0 dump is QDSPSGNINF||1.
  if [ "${SYSVAL_OK:-0}" -ne 1 ]; then
    add security sv_qdspsgninf "Display user sign-on information" NOT_ASSESSED low \
        "not assessed — ${SYSVAL_WHY:-capture unavailable}" \
        "The SYSTEM_VALUE_INFO capture did not yield a readable dump, so QDSPSGNINF cannot be graded." \
        "re-run the scan as the scan profile and confirm QSYS2.SYSTEM_VALUE_INFO returns rows. This scanner never changes system values." \
        "cis-l1"
  else
    QDSP_LINE=$(printf '%s\n' "$SYSVAL_RAW" | awk -F'|' '$1=="QDSPSGNINF"{n++; line=$0} END{if(n==1) print line}')
    QDSP_RC=$?
    if [ -z "$QDSP_LINE" ]; then
      add security sv_qdspsgninf "Display user sign-on information" NOT_ASSESSED low \
          "not assessed — QDSPSGNINF row missing or not unique in SYSTEM_VALUE_INFO" \
          "The system-value dump was readable, but it did not contain exactly one QDSPSGNINF row, so the value cannot be graded." \
          "inspect QSYS2.SYSTEM_VALUE_INFO for SYSTEM_VALUE_NAME = QDSPSGNINF." \
          "cis-l1"
    else
      QDSP_VAL=$(printf '%s\n' "$QDSP_LINE" | awk -F'|' '{ v=$3; if (v=="") v=$2; sub(/[ \t]+$/, "", v); print v }')
      if [ "$QDSP_VAL" = "*NOTAVL" ]; then
        add security sv_qdspsgninf "Display user sign-on information" NOT_ASSESSED low \
            "not assessed — QDSPSGNINF=*NOTAVL (scan profile cannot read this system value)" \
            "The catalog returned *NOTAVL for QDSPSGNINF — the scan profile lacks authority to read this system value, so the value is not graded." \
            "grant the scan profile read access to QDSPSGNINF and re-take cap-system-values. Do not run this check as QSECOFR to paper over the gap." \
            "cis-l1"
      elif [ -z "$QDSP_VAL" ]; then
        add security sv_qdspsgninf "Display user sign-on information" NOT_ASSESSED low \
            "not assessed — QDSPSGNINF value unreadable" \
            "The QDSPSGNINF row was present, but the catalog value was empty, so it is not graded." \
            "inspect the QDSPSGNINF row in QSYS2.SYSTEM_VALUE_INFO and DSPSYSVAL SYSVAL(QDSPSGNINF)." \
            "cis-l1"
      elif [ "$QDSP_VAL" = "1" ]; then
        add security sv_qdspsgninf "Display user sign-on information" PASS low \
            "QDSPSGNINF=1" \
            "QDSPSGNINF is 1, so after sign-on the system shows last sign-on time, invalid password counts, and days until password expiry." \
            "n/a" \
            "cis-l1"
      elif [ "$QDSP_VAL" = "0" ]; then
        add security sv_qdspsgninf "Display user sign-on information" FAIL high \
            "QDSPSGNINF=0" \
            "QDSPSGNINF is 0, so after sign-on the system does not show last sign-on time or invalid password counts." \
            "set QDSPSGNINF to 1 using CHGSYSVAL SYSVAL(QDSPSGNINF) VALUE('1'). This scanner never changes system values." \
            "cis-l1"
      else
        add security sv_qdspsgninf "Display user sign-on information" NOT_ASSESSED low \
            "not assessed — QDSPSGNINF value unreadable" \
            "The QDSPSGNINF row was present, but the catalog value was not 0, 1, or *NOTAVL, so it is not graded." \
            "inspect the QDSPSGNINF row in QSYS2.SYSTEM_VALUE_INFO and DSPSYSVAL SYSVAL(QDSPSGNINF)." \
            "cis-l1"
      fi
    fi
  fi

  # sv_qfrccvnrst — IBM i QFRCCVNRST (force conversion on restore).
  # Authority: CIS IBM i V7R5M0/V7R4M0 5.1.1.14 (L1=3) and 5.1.2.10 (L2=7).
  # One finding. Parses the shared cap-system-values dump. Does not call
  # ibmi_sql. Does not CHGSYSVAL. *NOTAVL is a refusal, never PASS.
  # Exact integer 3 or exact integer 7 is PASS (7 is stricter than L1).
  # Integer 0, 1 (IBM ship default), 2, 4, 5, or 6 is FAIL.
  # live Phase 0 dump is QFRCCVNRST||4 -> 4 (FAIL). Do not treat >=3 as PASS.
  if [ "${SYSVAL_OK:-0}" -ne 1 ]; then
    add security sv_qfrccvnrst "Force conversion on restore" NOT_ASSESSED low \
        "not assessed — ${SYSVAL_WHY:-capture unavailable}" \
        "The SYSTEM_VALUE_INFO capture did not yield a readable dump, so QFRCCVNRST cannot be graded." \
        "re-run the scan as the scan profile and confirm QSYS2.SYSTEM_VALUE_INFO returns rows. This scanner never changes system values." \
        "cis-l1 cis-l2"
  else
    QFRC_LINE=$(printf '%s\n' "$SYSVAL_RAW" | awk -F'|' '$1=="QFRCCVNRST"{n++; line=$0} END{if(n==1) print line}')
    QFRC_RC=$?
    if [ -z "$QFRC_LINE" ]; then
      add security sv_qfrccvnrst "Force conversion on restore" NOT_ASSESSED low \
          "not assessed — QFRCCVNRST row missing or not unique in SYSTEM_VALUE_INFO" \
          "The system-value dump was readable, but it did not contain exactly one QFRCCVNRST row, so the value cannot be graded." \
          "inspect QSYS2.SYSTEM_VALUE_INFO for SYSTEM_VALUE_NAME = QFRCCVNRST." \
          "cis-l1 cis-l2"
    else
      QFRC_NUM=$(printf '%s\n' "$QFRC_LINE" | awk -F'|' '{print $2}')
      QFRC_CHR=$(printf '%s\n' "$QFRC_LINE" | awk -F'|' '{print $3}')
      if [ -n "$QFRC_NUM" ]; then
        QFRC_RAW=$QFRC_NUM
      else
        QFRC_RAW=$QFRC_CHR
      fi
      if [ "$QFRC_RAW" = "*NOTAVL" ]; then
        add security sv_qfrccvnrst "Force conversion on restore" NOT_ASSESSED low \
            "not assessed — QFRCCVNRST=*NOTAVL (scan profile cannot read this system value)" \
            "The catalog returned *NOTAVL for QFRCCVNRST — the scan profile lacks authority to read this system value, so the value is not graded." \
            "grant the scan profile read access to QFRCCVNRST and re-take cap-system-values. Do not run this check as QSECOFR to paper over the gap." \
            "cis-l1 cis-l2"
      else
        QFRN=$(printf '%s\n' "$QFRC_RAW" | awk '/^[0-9]+$/{ if ($0 ~ /^0+$/) print 0; else { sub(/^0+/,""); print } }')
        if [ -z "$QFRN" ] || [ "$QFRN" -gt 7 ]; then
          add security sv_qfrccvnrst "Force conversion on restore" NOT_ASSESSED low \
              "not assessed — QFRCCVNRST value unreadable" \
              "The QFRCCVNRST row was present, but the catalog value was not an integer 0-7 or *NOTAVL, so it is not graded." \
              "inspect the QFRCCVNRST row in QSYS2.SYSTEM_VALUE_INFO and DSPSYSVAL SYSVAL(QFRCCVNRST)." \
              "cis-l1 cis-l2"
        elif [ "$QFRN" -eq 3 ] || [ "$QFRN" -eq 7 ]; then
          add security sv_qfrccvnrst "Force conversion on restore" PASS low \
              "QFRCCVNRST=$QFRN" \
              "QFRCCVNRST is 3 or 7, so restored objects that look tampered, that have validation errors, or that need conversion are converted, or every object is converted." \
              "n/a" \
              "cis-l1 cis-l2"
        elif [ "$QFRN" -le 2 ]; then
          add security sv_qfrccvnrst "Force conversion on restore" FAIL high \
              "QFRCCVNRST=$QFRN" \
              "QFRCCVNRST is not 3 or 7, so restore does not force conversion of tampered objects, objects with validation errors, and objects that need conversion, and it does not convert every object." \
              "set QFRCCVNRST to 3, or to 7, using CHGSYSVAL SYSVAL(QFRCCVNRST) VALUE('3'). This scanner never changes system values." \
              "cis-l1 cis-l2"
        else
          add security sv_qfrccvnrst "Force conversion on restore" FAIL high \
              "QFRCCVNRST=$QFRN" \
              "QFRCCVNRST is $QFRN, which is not the CIS-specified value 3 (L1) or 7 (L2), so the benchmark's force-conversion policy is not in effect." \
              "set QFRCCVNRST to 3, or to 7, using CHGSYSVAL SYSVAL(QFRCCVNRST) VALUE('3'). This scanner never changes system values." \
              "cis-l1 cis-l2"
        fi
      fi
    fi
  fi

  # sv_qinactitv — IBM i QINACTITV (inactive job time-out interval).
  # Authority: CIS IBM i V7R5M0 Benchmark v2.1.0 5.1.1.15 (L1=30).
  # One finding. Parses the shared cap-system-values dump. Does not call
  # ibmi_sql. Does not CHGSYSVAL. *NOTAVL is a refusal, never PASS.
  # Integer 5-30 inclusive is PASS (below 5 is NOT_ASSESSED). *NONE or
  # integer >30 is FAIL. live Phase 0 dump is QINACTITV||0000000015 -> 15.
  if [ "${SYSVAL_OK:-0}" -ne 1 ]; then
    add security sv_qinactitv "Inactivity time-out interval" NOT_ASSESSED low \
        "not assessed — capture rc=$SYSVAL_RC (${SYSVAL_WHY:-capture unavailable})" \
        "The SYSTEM_VALUE_INFO capture did not yield a readable dump, so QINACTITV cannot be graded." \
        "re-run the scan as the scan profile and confirm QSYS2.SYSTEM_VALUE_INFO returns rows. This scanner never changes system values." \
        "cis-l1"
  else
    QIN_LINE=$(printf '%s\n' "$SYSVAL_RAW" | awk -F'|' '$1=="QINACTITV"{n++; line=$0} END{if(n==1) print line}')
    QIN_PARSE_RC=$?   # record this fragment's own capture-parse exit status; non-zero empties QIN_LINE -> row-missing below
    if [ -z "$QIN_LINE" ]; then
      add security sv_qinactitv "Inactivity time-out interval" NOT_ASSESSED low \
          "not assessed — QINACTITV row missing or not unique in SYSTEM_VALUE_INFO" \
          "The system-value dump was readable, but it did not contain exactly one QINACTITV row, so the value cannot be graded." \
          "inspect QSYS2.SYSTEM_VALUE_INFO for SYSTEM_VALUE_NAME = QINACTITV." \
          "cis-l1"
    else
      QIN_NUM=$(printf '%s\n' "$QIN_LINE" | awk -F'|' '{print $2}')
      QIN_CHR=$(printf '%s\n' "$QIN_LINE" | awk -F'|' '{print $3}')
      if [ -n "$QIN_NUM" ]; then
        QIN_RAW=$QIN_NUM
      else
        QIN_RAW=$QIN_CHR
      fi
      if [ "$QIN_RAW" = "*NOTAVL" ]; then
        add security sv_qinactitv "Inactivity time-out interval" NOT_ASSESSED low \
            "not assessed — QINACTITV=*NOTAVL (scan profile cannot read this system value)" \
            "The catalog returned *NOTAVL for QINACTITV — the scan profile lacks authority to read this system value, so the value is not graded." \
            "grant the scan profile read access to QINACTITV and re-take cap-system-values. Do not run this check as QSECOFR to paper over the gap." \
            "cis-l1"
      elif [ "$QIN_RAW" = "*NONE" ]; then
        add security sv_qinactitv "Inactivity time-out interval" FAIL high \
            "QINACTITV=*NONE" \
            "QINACTITV is *NONE or greater than 30 minutes, so an inactive interactive job can stay signed on longer than a small interval." \
            "set QINACTITV to 30 or less, not *NONE, using CHGSYSVAL SYSVAL(QINACTITV) VALUE('30'). This scanner never changes system values." \
            "cis-l1"
      else
        QINN=$(printf '%s\n' "$QIN_RAW" | awk '/^[0-9]+$/{ if ($0 ~ /^0+$/) print 0; else { sub(/^0+/,""); print } }')
        if [ -z "$QINN" ] || [ "$QINN" -lt 5 ]; then
          add security sv_qinactitv "Inactivity time-out interval" NOT_ASSESSED low \
              "not assessed — QINACTITV value unreadable" \
              "The QINACTITV row was present, but the catalog value was not an integer 5-30, *NONE, or *NOTAVL, so it is not graded." \
              "inspect the QINACTITV row in QSYS2.SYSTEM_VALUE_INFO and DSPSYSVAL SYSVAL(QINACTITV)." \
              "cis-l1"
        elif [ "$QINN" -gt 30 ]; then
          add security sv_qinactitv "Inactivity time-out interval" FAIL high \
              "QINACTITV=$QINN" \
              "QINACTITV is *NONE or greater than 30 minutes, so an inactive interactive job can stay signed on longer than a small interval." \
              "set QINACTITV to 30 or less, not *NONE, using CHGSYSVAL SYSVAL(QINACTITV) VALUE('30'). This scanner never changes system values." \
              "cis-l1"
        else
          add security sv_qinactitv "Inactivity time-out interval" PASS low \
              "QINACTITV=$QINN" \
              "QINACTITV times out inactive interactive jobs after a short interval (at most 30 minutes), so a signed-on workstation is not left open indefinitely." \
              "n/a" \
              "cis-l1"
        fi
      fi
    fi
  fi

  # sv_qinactmsgq — IBM i QINACTMSGQ (inactive job time-out action).
  # Authority: CIS IBM i V7R5M0/V7R4M0 5.1.1.16 (L1=*DSCJOB) and 5.1.2.12 (L2=*ENDJOB).
  # One finding. Parses the shared cap-system-values dump. Does not call
  # ibmi_sql. Does not CHGSYSVAL. *NOTAVL is a refusal, never PASS.
  # Exact *DSCJOB or exact *ENDJOB is PASS (*ENDJOB is stricter than L1).
  # A named message queue is FAIL (job stays signed on). live Phase 0 dump
  # is QINACTMSGQ||*DSCJOB.
  if [ "${SYSVAL_OK:-0}" -ne 1 ]; then
    add security sv_qinactmsgq "Inactivity message queue" NOT_ASSESSED low \
        "not assessed — ${SYSVAL_WHY:-capture unavailable}" \
        "The SYSTEM_VALUE_INFO capture did not yield a readable dump, so QINACTMSGQ cannot be graded." \
        "re-run the scan as the scan profile and confirm QSYS2.SYSTEM_VALUE_INFO returns rows. This scanner never changes system values." \
        "cis-l1 cis-l2"
  else
    QIM_LINE=$(printf '%s\n' "$SYSVAL_RAW" | awk -F'|' '$1=="QINACTMSGQ"{n++; line=$0} END{if(n==1) print line}')
    if [ -z "$QIM_LINE" ]; then
      add security sv_qinactmsgq "Inactivity message queue" NOT_ASSESSED low \
          "not assessed — QINACTMSGQ row missing or not unique in SYSTEM_VALUE_INFO" \
          "The system-value dump was readable, but it did not contain exactly one QINACTMSGQ row, so the value cannot be graded." \
          "inspect QSYS2.SYSTEM_VALUE_INFO for SYSTEM_VALUE_NAME = QINACTMSGQ." \
          "cis-l1 cis-l2"
    else
      QIM_RAW=$(printf '%s\n' "$QIM_LINE" | awk -F'|' '{ v=$3; if (v=="") v=$2; sub(/[ \t]+$/, "", v); print v }')
      if [ "$QIM_RAW" = "*NOTAVL" ]; then
        add security sv_qinactmsgq "Inactivity message queue" NOT_ASSESSED low \
            "not assessed — QINACTMSGQ=*NOTAVL (scan profile cannot read this system value)" \
            "The catalog returned *NOTAVL for QINACTMSGQ — the scan profile lacks authority to read this system value, so the value is not graded." \
            "grant the scan profile read access to QINACTMSGQ and re-take cap-system-values. Do not run this check as QSECOFR to paper over the gap." \
            "cis-l1 cis-l2"
      elif [ -z "$QIM_RAW" ]; then
        add security sv_qinactmsgq "Inactivity message queue" NOT_ASSESSED low \
            "not assessed — QINACTMSGQ value unreadable" \
            "The QINACTMSGQ row was present, but the catalog value was not *DSCJOB, *ENDJOB, *NOTAVL, or a message-queue name, so it is not graded." \
            "inspect the QINACTMSGQ row in QSYS2.SYSTEM_VALUE_INFO and DSPSYSVAL SYSVAL(QINACTMSGQ)." \
            "cis-l1 cis-l2"
      elif [ "$QIM_RAW" = "*DSCJOB" ] || [ "$QIM_RAW" = "*ENDJOB" ]; then
        add security sv_qinactmsgq "Inactivity message queue" PASS low \
            "QINACTMSGQ=$QIM_RAW" \
            "QINACTMSGQ is *DSCJOB or *ENDJOB, so an inactive interactive job is disconnected or ended rather than left signed on." \
            "n/a" \
            "cis-l1 cis-l2"
      elif [ "${QIM_RAW#\*}" != "$QIM_RAW" ]; then
        add security sv_qinactmsgq "Inactivity message queue" NOT_ASSESSED low \
            "not assessed — QINACTMSGQ value unreadable" \
            "The QINACTMSGQ row was present, but the catalog value was not *DSCJOB, *ENDJOB, *NOTAVL, or a message-queue name, so it is not graded." \
            "inspect the QINACTMSGQ row in QSYS2.SYSTEM_VALUE_INFO and DSPSYSVAL SYSVAL(QINACTMSGQ)." \
            "cis-l1 cis-l2"
      else
        add security sv_qinactmsgq "Inactivity message queue" FAIL high \
            "QINACTMSGQ=$QIM_RAW" \
            "QINACTMSGQ names a message queue, so an inactive interactive job stays signed on and only a message is sent." \
            "set QINACTMSGQ to *DSCJOB, or to *ENDJOB, using CHGSYSVAL SYSVAL(QINACTMSGQ) VALUE('*DSCJOB'). This scanner never changes system values." \
            "cis-l1 cis-l2"
      fi
    fi
  fi

  # sv_qlmtdevssn — IBM i QLMTDEVSSN (limit concurrent device sessions).
  # Authority: CIS IBM i V7R5M0/V7R4M0 5.1.1.17 (L1=1-9) and 5.1.2.13 (L2=1).
  # One finding. Parses the shared cap-system-values dump. Does not call
  # ibmi_sql. Does not CHGSYSVAL. *NOTAVL is a refusal, never PASS.
  # Integer 1-9 inclusive is PASS (lower is stricter than L1). 0 (IBM ship
  # default, unbounded) is FAIL. live Phase 0 dump is QLMTDEVSSN||1.
  if [ "${SYSVAL_OK:-0}" -ne 1 ]; then
    add security sv_qlmtdevssn "Limit device sessions" NOT_ASSESSED low \
        "not assessed — ${SYSVAL_WHY:-capture unavailable}" \
        "The SYSTEM_VALUE_INFO capture did not yield a readable dump, so QLMTDEVSSN cannot be graded." \
        "re-run the scan as the scan profile and confirm QSYS2.SYSTEM_VALUE_INFO returns rows. This scanner never changes system values." \
        "cis-l1 cis-l2"
  else
    QLMT_LINE=$(printf '%s\n' "$SYSVAL_RAW" | awk -F'|' '$1=="QLMTDEVSSN"{n++; line=$0} END{if(n==1) print line}')
    QLMT_RC=$?
    if [ -z "$QLMT_LINE" ]; then
      add security sv_qlmtdevssn "Limit device sessions" NOT_ASSESSED low \
          "not assessed — QLMTDEVSSN row missing or not unique in SYSTEM_VALUE_INFO" \
          "The system-value dump was readable, but it did not contain exactly one QLMTDEVSSN row, so the value cannot be graded." \
          "inspect QSYS2.SYSTEM_VALUE_INFO for SYSTEM_VALUE_NAME = QLMTDEVSSN." \
          "cis-l1 cis-l2"
    else
      QLMT_VAL=$(printf '%s\n' "$QLMT_LINE" | awk -F'|' '{ v=$3; if (v=="") v=$2; sub(/[ \t]+$/, "", v); print v }')
      if [ "$QLMT_VAL" = "*NOTAVL" ]; then
        add security sv_qlmtdevssn "Limit device sessions" NOT_ASSESSED low \
            "not assessed — QLMTDEVSSN=*NOTAVL (scan profile cannot read this system value)" \
            "The catalog returned *NOTAVL for QLMTDEVSSN — the scan profile lacks authority to read this system value, so the value is not graded." \
            "grant the scan profile read access to QLMTDEVSSN and re-take cap-system-values. Do not run this check as QSECOFR to paper over the gap." \
            "cis-l1 cis-l2"
      elif [ -z "$QLMT_VAL" ]; then
        add security sv_qlmtdevssn "Limit device sessions" NOT_ASSESSED low \
            "not assessed — QLMTDEVSSN value unreadable" \
            "The QLMTDEVSSN row was present, but the catalog value was empty, so it is not graded." \
            "inspect the QLMTDEVSSN row in QSYS2.SYSTEM_VALUE_INFO and DSPSYSVAL SYSVAL(QLMTDEVSSN)." \
            "cis-l1 cis-l2"
      else
        QLMTN=$(printf '%s\n' "$QLMT_VAL" | awk '/^[0-9]+$/{ if ($0 ~ /^0+$/) print 0; else { sub(/^0+/,""); print } }')
        if [ -z "$QLMTN" ]; then
          add security sv_qlmtdevssn "Limit device sessions" NOT_ASSESSED low \
              "not assessed — QLMTDEVSSN value unreadable" \
              "The QLMTDEVSSN row was present, but the catalog value was not an integer 0-9 or *NOTAVL, so it is not graded." \
              "inspect the QLMTDEVSSN row in QSYS2.SYSTEM_VALUE_INFO and DSPSYSVAL SYSVAL(QLMTDEVSSN)." \
              "cis-l1 cis-l2"
        elif [ "$QLMTN" -eq 0 ]; then
          add security sv_qlmtdevssn "Limit device sessions" FAIL high \
              "QLMTDEVSSN=0" \
              "QLMTDEVSSN is 0, so a profile can hold an unbounded number of concurrent device sessions." \
              "set QLMTDEVSSN to 1, or to an integer 1 through 9, using CHGSYSVAL SYSVAL(QLMTDEVSSN) VALUE('1'). This scanner never changes system values." \
              "cis-l1 cis-l2"
        elif [ "$QLMTN" -le 9 ]; then
          add security sv_qlmtdevssn "Limit device sessions" PASS low \
              "QLMTDEVSSN=$QLMTN" \
              "QLMTDEVSSN limits concurrent device sessions to a small count (at most 9), so one profile cannot hold an unbounded number of signed-on devices." \
              "n/a" \
              "cis-l1 cis-l2"
        else
          add security sv_qlmtdevssn "Limit device sessions" NOT_ASSESSED low \
              "not assessed — QLMTDEVSSN value unreadable" \
              "The QLMTDEVSSN row was present, but the catalog value was not an integer 0-9 or *NOTAVL, so it is not graded." \
              "inspect the QLMTDEVSSN row in QSYS2.SYSTEM_VALUE_INFO and DSPSYSVAL SYSVAL(QLMTDEVSSN)." \
              "cis-l1 cis-l2"
        fi
      fi
    fi
  fi

  # sv_qlmtsecofr — IBM i QLMTSECOFR (limit security officer workstations).
  # Authority: CIS IBM i V7R5M0/V7R4M0 5.1.1.18 (L1) and 5.1.2.14 (L2).
  # One finding. Parses the shared cap-system-values dump. Does not call
  # ibmi_sql. Does not CHGSYSVAL. *NOTAVL is a refusal, never PASS.
  # Exact 1 is PASS (IBM recommended / L2 / live dump). Exact 0 (IBM
  # ship default) is FAIL. CIS L1 and L2 both remediate to 1;
  # grade the security-on value.
  # live Phase 0 dump is QLMTSECOFR||1.
  if [ "${SYSVAL_OK:-0}" -ne 1 ]; then
    add security sv_qlmtsecofr "Limit security officer access to workstations" NOT_ASSESSED low \
        "not assessed — ${SYSVAL_WHY:-capture unavailable}" \
        "The SYSTEM_VALUE_INFO capture did not yield a readable dump, so QLMTSECOFR cannot be graded." \
        "re-run the scan as the scan profile and confirm QSYS2.SYSTEM_VALUE_INFO returns rows. This scanner never changes system values." \
        "cis-l1 cis-l2"
  else
    QLS_LINE=$(printf '%s\n' "$SYSVAL_RAW" | awk -F'|' '$1=="QLMTSECOFR"{n++; line=$0} END{if(n==1) print line}')
    QLS_RC=$?
    if [ -z "$QLS_LINE" ]; then
      add security sv_qlmtsecofr "Limit security officer access to workstations" NOT_ASSESSED low \
          "not assessed — QLMTSECOFR row missing or not unique in SYSTEM_VALUE_INFO" \
          "The system-value dump was readable, but it did not contain exactly one QLMTSECOFR row, so the value cannot be graded." \
          "inspect QSYS2.SYSTEM_VALUE_INFO for SYSTEM_VALUE_NAME = QLMTSECOFR." \
          "cis-l1 cis-l2"
    else
      QLS_VAL=$(printf '%s\n' "$QLS_LINE" | awk -F'|' '{ v=$3; if (v=="") v=$2; sub(/[ \t]+$/, "", v); print v }')
      if [ "$QLS_VAL" = "*NOTAVL" ]; then
        add security sv_qlmtsecofr "Limit security officer access to workstations" NOT_ASSESSED low \
            "not assessed — QLMTSECOFR=*NOTAVL (scan profile cannot read this system value)" \
            "The catalog returned *NOTAVL for QLMTSECOFR — the scan profile lacks authority to read this system value, so the value is not graded." \
            "grant the scan profile read access to QLMTSECOFR and re-take cap-system-values. Do not run this check as QSECOFR to paper over the gap." \
            "cis-l1 cis-l2"
      elif [ -z "$QLS_VAL" ]; then
        add security sv_qlmtsecofr "Limit security officer access to workstations" NOT_ASSESSED low \
            "not assessed — QLMTSECOFR value unreadable" \
            "The QLMTSECOFR row was present, but the catalog value was empty, so it is not graded." \
            "inspect the QLMTSECOFR row in QSYS2.SYSTEM_VALUE_INFO and DSPSYSVAL SYSVAL(QLMTSECOFR)." \
            "cis-l1 cis-l2"
      elif [ "$QLS_VAL" = "1" ]; then
        add security sv_qlmtsecofr "Limit security officer access to workstations" PASS low \
            "QLMTSECOFR=1" \
            "QLMTSECOFR is 1, so a profile with *ALLOBJ or *SERVICE can sign on at a workstation only when that profile, or QSECOFR, has private *CHANGE authority to the device." \
            "n/a" \
            "cis-l1 cis-l2"
      elif [ "$QLS_VAL" = "0" ]; then
        add security sv_qlmtsecofr "Limit security officer access to workstations" FAIL high \
            "QLMTSECOFR=0" \
            "QLMTSECOFR is 0, so a profile with *ALLOBJ or *SERVICE can sign on at any workstation." \
            "set QLMTSECOFR to 1 using CHGSYSVAL SYSVAL(QLMTSECOFR) VALUE('1'). This scanner never changes system values." \
            "cis-l1 cis-l2"
      else
        add security sv_qlmtsecofr "Limit security officer access to workstations" NOT_ASSESSED low \
            "not assessed — QLMTSECOFR value unreadable" \
            "The QLMTSECOFR row was present, but the catalog value was not 0, 1, or *NOTAVL, so it is not graded." \
            "inspect the QLMTSECOFR row in QSYS2.SYSTEM_VALUE_INFO and DSPSYSVAL SYSVAL(QLMTSECOFR)." \
            "cis-l1 cis-l2"
      fi
    fi
  fi

  # sv_qmaxsgnacn — IBM i QMAXSGNACN (action when max sign-on attempts reached).
  # Authority: CIS IBM i V7R5M0/V7R4M0 5.1.1.19 (L1=2) and 5.1.2.15 (L2=3).
  # One finding. Parses the shared cap-system-values dump. Does not call
  # ibmi_sql. Does not CHGSYSVAL. *NOTAVL is a refusal, never PASS.
  # Exact 2 or exact 3 is PASS (3 is stricter than L1; IBM ship default).
  # Exact 1 (device only, profile left enabled) is FAIL.
  # live Phase 0 dump is QMAXSGNACN||3.
  if [ "${SYSVAL_OK:-0}" -ne 1 ]; then
    add security sv_qmaxsgnacn "Maximum sign-on action" NOT_ASSESSED low \
        "not assessed — ${SYSVAL_WHY:-capture unavailable}" \
        "The SYSTEM_VALUE_INFO capture did not yield a readable dump, so QMAXSGNACN cannot be graded." \
        "re-run the scan as the scan profile and confirm QSYS2.SYSTEM_VALUE_INFO returns rows. This scanner never changes system values." \
        "cis-l1"
  else
    QACN_LINE=$(printf '%s\n' "$SYSVAL_RAW" | awk -F'|' '$1=="QMAXSGNACN"{n++; line=$0} END{if(n==1) print line}')
    QACN_RC=$?
    if [ -z "$QACN_LINE" ]; then
      add security sv_qmaxsgnacn "Maximum sign-on action" NOT_ASSESSED low \
          "not assessed — QMAXSGNACN row missing or not unique in SYSTEM_VALUE_INFO" \
          "The system-value dump was readable, but it did not contain exactly one QMAXSGNACN row, so the value cannot be graded." \
          "inspect QSYS2.SYSTEM_VALUE_INFO for SYSTEM_VALUE_NAME = QMAXSGNACN." \
          "cis-l1"
    else
      QACN_VAL=$(printf '%s\n' "$QACN_LINE" | awk -F'|' '{ v=$3; if (v=="") v=$2; sub(/[ \t]+$/, "", v); print v }')
      if [ "$QACN_VAL" = "*NOTAVL" ]; then
        add security sv_qmaxsgnacn "Maximum sign-on action" NOT_ASSESSED low \
            "not assessed — QMAXSGNACN=*NOTAVL (scan profile cannot read this system value)" \
            "The catalog returned *NOTAVL for QMAXSGNACN — the scan profile lacks authority to read this system value, so the value is not graded." \
            "grant the scan profile read access to QMAXSGNACN and re-take cap-system-values. Do not run this check as QSECOFR to paper over the gap." \
            "cis-l1"
      elif [ -z "$QACN_VAL" ]; then
        add security sv_qmaxsgnacn "Maximum sign-on action" NOT_ASSESSED low \
            "not assessed — QMAXSGNACN value unreadable" \
            "The QMAXSGNACN row was present, but the catalog value was empty, so it is not graded." \
            "inspect the QMAXSGNACN row in QSYS2.SYSTEM_VALUE_INFO and DSPSYSVAL SYSVAL(QMAXSGNACN)." \
            "cis-l1"
      elif [ "$QACN_VAL" = "1" ]; then
        add security sv_qmaxsgnacn "Maximum sign-on action" FAIL high \
            "QMAXSGNACN=1" \
            "QMAXSGNACN is 1, so reaching the invalid sign-on limit varies off the device only and leaves the profile enabled for further attempts from other devices." \
            "set QMAXSGNACN to 2, or to 3, using CHGSYSVAL SYSVAL(QMAXSGNACN) VALUE('2'). This scanner never changes system values." \
            "cis-l1"
      elif [ "$QACN_VAL" = "2" ] || [ "$QACN_VAL" = "3" ]; then
        add security sv_qmaxsgnacn "Maximum sign-on action" PASS low \
            "QMAXSGNACN=$QACN_VAL" \
            "QMAXSGNACN is 2 or 3, so reaching the invalid sign-on limit disables the user profile (and, when 3, also varies off the device)." \
            "n/a" \
            "cis-l1"
      else
        add security sv_qmaxsgnacn "Maximum sign-on action" NOT_ASSESSED low \
            "not assessed — QMAXSGNACN value unreadable" \
            "The QMAXSGNACN row was present, but the catalog value was not 1, 2, 3, or *NOTAVL, so it is not graded." \
            "inspect the QMAXSGNACN row in QSYS2.SYSTEM_VALUE_INFO and DSPSYSVAL SYSVAL(QMAXSGNACN)." \
            "cis-l1"
      fi
    fi
  fi

  # sv_qmaxsign — IBM i QMAXSIGN (maximum invalid sign-on attempts).
  # Authority: CIS IBM i V7R5M0/V7R4M0 5.1.1.20 (L1=5) and 5.1.2.16 (L2=3).
  # One finding. Parses the shared cap-system-values dump. Does not call
  # ibmi_sql. Does not CHGSYSVAL. *NOTAVL is a refusal, never PASS.
  # Integer 1-5 inclusive is PASS (lower is stricter than L1). *NOMAX or
  # integer >5 is FAIL. live Phase 0 dump is QMAXSIGN||000003 -> 3.
  if [ "${SYSVAL_OK:-0}" -ne 1 ]; then
    add security sv_qmaxsign "Maximum sign-on attempts" NOT_ASSESSED low \
        "not assessed — ${SYSVAL_WHY:-capture unavailable}" \
        "The SYSTEM_VALUE_INFO capture did not yield a readable dump, so QMAXSIGN cannot be graded." \
        "re-run the scan as the scan profile and confirm QSYS2.SYSTEM_VALUE_INFO returns rows. This scanner never changes system values." \
        "cis-l1"
  else
    QMAX_LINE=$(printf '%s\n' "$SYSVAL_RAW" | awk -F'|' '$1=="QMAXSIGN"{n++; line=$0} END{if(n==1) print line}')
    if [ -z "$QMAX_LINE" ]; then
      add security sv_qmaxsign "Maximum sign-on attempts" NOT_ASSESSED low \
          "not assessed — QMAXSIGN row missing or not unique in SYSTEM_VALUE_INFO" \
          "The system-value dump was readable, but it did not contain exactly one QMAXSIGN row, so the value cannot be graded." \
          "inspect QSYS2.SYSTEM_VALUE_INFO for SYSTEM_VALUE_NAME = QMAXSIGN." \
          "cis-l1"
    else
      QMAX_NUM=$(printf '%s\n' "$QMAX_LINE" | awk -F'|' '{print $2}')
      QMAX_CHR=$(printf '%s\n' "$QMAX_LINE" | awk -F'|' '{print $3}')
      if [ -n "$QMAX_NUM" ]; then
        QMAX_RAW=$QMAX_NUM
      else
        QMAX_RAW=$QMAX_CHR
      fi
      if [ "$QMAX_RAW" = "*NOTAVL" ]; then
        add security sv_qmaxsign "Maximum sign-on attempts" NOT_ASSESSED low \
            "not assessed — QMAXSIGN=*NOTAVL (scan profile cannot read this system value)" \
            "The catalog returned *NOTAVL for QMAXSIGN — the scan profile lacks authority to read this system value, so the value is not graded." \
            "grant the scan profile read access to QMAXSIGN and re-take cap-system-values. Do not run this check as QSECOFR to paper over the gap." \
            "cis-l1"
      elif [ "$QMAX_RAW" = "*NOMAX" ]; then
        add security sv_qmaxsign "Maximum sign-on attempts" FAIL high \
            "QMAXSIGN=*NOMAX" \
            "QMAXSIGN is *NOMAX or greater than 5, so invalid sign-on attempts are not bounded to a small count before the sign-on action runs." \
            "set QMAXSIGN to 5 or less, not *NOMAX, using CHGSYSVAL SYSVAL(QMAXSIGN) VALUE('5'). This scanner never changes system values." \
            "cis-l1"
      else
        QMAXN=$(printf '%s\n' "$QMAX_RAW" | awk '/^[0-9]+$/{ if ($0 ~ /^0+$/) print 0; else { sub(/^0+/,""); print } }')
        if [ -z "$QMAXN" ] || [ "$QMAXN" -lt 1 ]; then
          add security sv_qmaxsign "Maximum sign-on attempts" NOT_ASSESSED low \
              "not assessed — QMAXSIGN value unreadable" \
              "The QMAXSIGN row was present, but the catalog value was not an integer, *NOMAX, or *NOTAVL, so it is not graded." \
              "inspect the QMAXSIGN row in QSYS2.SYSTEM_VALUE_INFO and DSPSYSVAL SYSVAL(QMAXSIGN)." \
              "cis-l1"
        elif [ "$QMAXN" -gt 5 ]; then
          add security sv_qmaxsign "Maximum sign-on attempts" FAIL high \
              "QMAXSIGN=$QMAXN" \
              "QMAXSIGN is *NOMAX or greater than 5, so invalid sign-on attempts are not bounded to a small count before the sign-on action runs." \
              "set QMAXSIGN to 5 or less, not *NOMAX, using CHGSYSVAL SYSVAL(QMAXSIGN) VALUE('5'). This scanner never changes system values." \
              "cis-l1"
        else
          add security sv_qmaxsign "Maximum sign-on attempts" PASS low \
              "QMAXSIGN=$QMAXN" \
              "QMAXSIGN limits invalid sign-on attempts to a small count (at most 5) before the sign-on action runs." \
              "n/a" \
              "cis-l1"
        fi
      fi
    fi
  fi

  # sv_qpwdexpitv — IBM i QPWDEXPITV (password expiration interval).
  # Authority: CIS IBM i V7R5M0/V7R4M0 5.1.1.22 (L1=45) and 5.1.2.18 (L2=365).
  # One finding. Parses the shared cap-system-values dump. Does not call
  # ibmi_sql. Does not CHGSYSVAL. *NOTAVL is a refusal, never PASS.
  # Integer 1-45 inclusive is PASS (lower is stricter than L1). *NOMAX or
  # integer 46-366 is FAIL. L2 365 is looser than L1 and is FAIL.
  # live Phase 0 dump is QPWDEXPITV||000090 -> 90 and is FAIL (IBM
  # recommended 30-90 is still over L1).
  if [ "${SYSVAL_OK:-0}" -ne 1 ]; then
    add security sv_qpwdexpitv "Password expiration interval" NOT_ASSESSED low \
        "not assessed — ${SYSVAL_WHY:-capture unavailable}" \
        "The SYSTEM_VALUE_INFO capture did not yield a readable dump, so QPWDEXPITV cannot be graded." \
        "re-run the scan as the scan profile and confirm QSYS2.SYSTEM_VALUE_INFO returns rows. This scanner never changes system values." \
        "cis-l1 cis-l2"
  else
    QPWD_LINE=$(printf '%s\n' "$SYSVAL_RAW" | awk -F'|' '$1=="QPWDEXPITV"{n++; line=$0} END{if(n==1) print line}')
    QPWD_RC=$?
    if [ -z "$QPWD_LINE" ]; then
      add security sv_qpwdexpitv "Password expiration interval" NOT_ASSESSED low \
          "not assessed — QPWDEXPITV row missing or not unique in SYSTEM_VALUE_INFO" \
          "The system-value dump was readable, but it did not contain exactly one QPWDEXPITV row, so the value cannot be graded." \
          "inspect QSYS2.SYSTEM_VALUE_INFO for SYSTEM_VALUE_NAME = QPWDEXPITV." \
          "cis-l1 cis-l2"
    else
      QPWD_NUM=$(printf '%s\n' "$QPWD_LINE" | awk -F'|' '{print $2}')
      QPWD_CHR=$(printf '%s\n' "$QPWD_LINE" | awk -F'|' '{print $3}')
      if [ -n "$QPWD_NUM" ]; then
        QPWD_RAW=$QPWD_NUM
      else
        QPWD_RAW=$QPWD_CHR
      fi
      if [ "$QPWD_RAW" = "*NOTAVL" ]; then
        add security sv_qpwdexpitv "Password expiration interval" NOT_ASSESSED low \
            "not assessed — QPWDEXPITV=*NOTAVL (scan profile cannot read this system value)" \
            "The catalog returned *NOTAVL for QPWDEXPITV — the scan profile lacks authority to read this system value, so the value is not graded." \
            "grant the scan profile read access to QPWDEXPITV and re-take cap-system-values. Do not run this check as QSECOFR to paper over the gap." \
            "cis-l1 cis-l2"
      elif [ "$QPWD_RAW" = "*NOMAX" ]; then
        add security sv_qpwdexpitv "Password expiration interval" FAIL high \
            "QPWDEXPITV=*NOMAX" \
            "QPWDEXPITV is *NOMAX or greater than 45 days, so a password can stay valid longer than a short interval." \
            "set QPWDEXPITV to 45 or less, not *NOMAX, using CHGSYSVAL SYSVAL(QPWDEXPITV) VALUE('45'). This scanner never changes system values." \
            "cis-l1 cis-l2"
      else
        QPWDN=$(printf '%s\n' "$QPWD_RAW" | awk '/^[0-9]+$/{ if ($0 ~ /^0+$/) print 0; else { sub(/^0+/,""); print } }')
        if [ -z "$QPWDN" ] || [ "$QPWDN" -lt 1 ] || [ "$QPWDN" -gt 366 ]; then
          add security sv_qpwdexpitv "Password expiration interval" NOT_ASSESSED low \
              "not assessed — QPWDEXPITV value unreadable" \
              "The QPWDEXPITV row was present, but the catalog value was not an integer 1-366, *NOMAX, or *NOTAVL, so it is not graded." \
              "inspect the QPWDEXPITV row in QSYS2.SYSTEM_VALUE_INFO and DSPSYSVAL SYSVAL(QPWDEXPITV)." \
              "cis-l1 cis-l2"
        elif [ "$QPWDN" -gt 45 ]; then
          add security sv_qpwdexpitv "Password expiration interval" FAIL high \
              "QPWDEXPITV=$QPWDN" \
              "QPWDEXPITV is *NOMAX or greater than 45 days, so a password can stay valid longer than a short interval." \
              "set QPWDEXPITV to 45 or less, not *NOMAX, using CHGSYSVAL SYSVAL(QPWDEXPITV) VALUE('45'). This scanner never changes system values." \
              "cis-l1 cis-l2"
        else
          add security sv_qpwdexpitv "Password expiration interval" PASS low \
              "QPWDEXPITV=$QPWDN" \
              "QPWDEXPITV expires passwords after a short interval (at most 45 days), so a password cannot stay valid indefinitely." \
              "n/a" \
              "cis-l1 cis-l2"
        fi
      fi
    fi
  fi

  # sv_qpwdexpwrn — IBM i QPWDEXPWRN (password expiration warning).
  # Authority: CIS IBM i V7R5M0/V7R4M0 5.1.1.23 (L1=7). No L2 rec
  # (5.1.2.19 is QPWDRQDDIF). One finding. Parses the shared
  # cap-system-values dump. Does not call ibmi_sql. Does not CHGSYSVAL.
  # *NOTAVL is a refusal, never PASS. Integer 7-99 inclusive is PASS
  # (higher is more warning than L1). Integer 1-6 is FAIL. IBM ship
  # default 7 PASSes. live Phase 0 dump is QPWDEXPWRN|14| and PASSes.
  if [ "${SYSVAL_OK:-0}" -ne 1 ]; then
    add security sv_qpwdexpwrn "Password expiration warning" NOT_ASSESSED low \
        "not assessed — ${SYSVAL_WHY:-capture unavailable}" \
        "The SYSTEM_VALUE_INFO capture did not yield a readable dump, so QPWDEXPWRN cannot be graded." \
        "re-run the scan as the scan profile and confirm QSYS2.SYSTEM_VALUE_INFO returns rows. This scanner never changes system values." \
        "cis-l1"
  else
    QWRN_LINE=$(printf '%s\n' "$SYSVAL_RAW" | awk -F'|' '$1=="QPWDEXPWRN"{n++; line=$0} END{if(n==1) print line}')
    QWRN_RC=$?
    if [ -z "$QWRN_LINE" ]; then
      add security sv_qpwdexpwrn "Password expiration warning" NOT_ASSESSED low \
          "not assessed — QPWDEXPWRN row missing or not unique in SYSTEM_VALUE_INFO" \
          "The system-value dump was readable, but it did not contain exactly one QPWDEXPWRN row, so the value cannot be graded." \
          "inspect QSYS2.SYSTEM_VALUE_INFO for SYSTEM_VALUE_NAME = QPWDEXPWRN." \
          "cis-l1"
    else
      QWRN_VAL=$(printf '%s\n' "$QWRN_LINE" | awk -F'|' '{ v=$3; if (v=="") v=$2; sub(/[ \t]+$/, "", v); print v }')
      if [ "$QWRN_VAL" = "*NOTAVL" ]; then
        add security sv_qpwdexpwrn "Password expiration warning" NOT_ASSESSED low \
            "not assessed — QPWDEXPWRN=*NOTAVL (scan profile cannot read this system value)" \
            "The catalog returned *NOTAVL for QPWDEXPWRN — the scan profile lacks authority to read this system value, so the value is not graded." \
            "grant the scan profile read access to QPWDEXPWRN and re-take cap-system-values. Do not run this check as QSECOFR to paper over the gap." \
            "cis-l1"
      elif [ -z "$QWRN_VAL" ]; then
        add security sv_qpwdexpwrn "Password expiration warning" NOT_ASSESSED low \
            "not assessed — QPWDEXPWRN value unreadable" \
            "The QPWDEXPWRN row was present, but the catalog value was empty, so it is not graded." \
            "inspect the QPWDEXPWRN row in QSYS2.SYSTEM_VALUE_INFO and DSPSYSVAL SYSVAL(QPWDEXPWRN)." \
            "cis-l1"
      else
        QWRNN=$(printf '%s\n' "$QWRN_VAL" | awk '/^[0-9]+$/{ if ($0 ~ /^0+$/) print 0; else { sub(/^0+/,""); print } }')
        if [ -z "$QWRNN" ]; then
          add security sv_qpwdexpwrn "Password expiration warning" NOT_ASSESSED low \
              "not assessed — QPWDEXPWRN value unreadable" \
              "The QPWDEXPWRN row was present, but the catalog value was not an integer 1-99 or *NOTAVL, so it is not graded." \
              "inspect the QPWDEXPWRN row in QSYS2.SYSTEM_VALUE_INFO and DSPSYSVAL SYSVAL(QPWDEXPWRN)." \
              "cis-l1"
        elif [ "$QWRNN" -eq 0 ] || [ "$QWRNN" -gt 99 ]; then
          add security sv_qpwdexpwrn "Password expiration warning" NOT_ASSESSED low \
              "not assessed — QPWDEXPWRN value unreadable" \
              "The QPWDEXPWRN row was present, but the catalog value was not an integer 1-99 or *NOTAVL, so it is not graded." \
              "inspect the QPWDEXPWRN row in QSYS2.SYSTEM_VALUE_INFO and DSPSYSVAL SYSVAL(QPWDEXPWRN)." \
              "cis-l1"
        elif [ "$QWRNN" -lt 7 ]; then
          add security sv_qpwdexpwrn "Password expiration warning" FAIL high \
              "QPWDEXPWRN=$QWRNN" \
              "QPWDEXPWRN warns fewer than 7 days before a password expires, so a user may not have time to change it." \
              "set QPWDEXPWRN to 7, or to an integer 7 through 99, using CHGSYSVAL SYSVAL(QPWDEXPWRN) VALUE('7'). This scanner never changes system values." \
              "cis-l1"
        else
          add security sv_qpwdexpwrn "Password expiration warning" PASS low \
              "QPWDEXPWRN=$QWRNN" \
              "QPWDEXPWRN warns at least 7 days before a password expires, so a user has time to change it." \
              "n/a" \
              "cis-l1"
        fi
      fi
    fi
  fi

  # sv_qpwdlvl — IBM i password level QPWDLVL.
  # Authority: CIS IBM i V7R5M0/V7R4M0 Benchmark v2.1.0 rec 5.1.1.24.
  # Expected numeric 4 on 7.5 and 3 on 7.4. One finding. Read-only.
  # Never CHGSYSVAL. Parse cap-system-values; do not call ibmi_sql.
  if [ "${SYSVAL_OK:-0}" -ne 1 ]; then
    add security sv_qpwdlvl "Password level" NOT_ASSESSED low \
        "not assessed — system-value catalog ${SYSVAL_WHY:-unavailable}" \
        "The shared SYSTEM_VALUE_INFO capture did not yield a readable QPWDLVL row, so the password level cannot be graded." \
        "re-run the scan as the scan profile after confirming QSYS2.SYSTEM_VALUE_INFO is readable, then re-assess." \
        "cis-l1"
  else
    PARSE=$(printf '%s\n' "$SYSVAL_RAW" | awk -F'|' '
      $1=="QPWDLVL" { num=$2; char=$3; found=1 }
      END {
        if (!found) { print "ABSENT||"; exit }
        print "ROW|" num "|" char
      }')
    KIND=${PARSE%%"|"*}
    REST=${PARSE#*"|"}
    NUM=${REST%%"|"*}
    CHAR=${REST#*"|"}
    if [ "$KIND" = ABSENT ]; then
      add security sv_qpwdlvl "Password level" NOT_ASSESSED low \
          "not assessed — QPWDLVL row absent from the system-value catalog" \
          "The shared catalog was readable, but it did not contain a QPWDLVL row — absence of the row is not proof the password level is compliant." \
          "confirm QSYS2.SYSTEM_VALUE_INFO contains QPWDLVL, then re-assess." \
          "cis-l1"
    elif [ "$CHAR" = "*NOTAVL" ]; then
      add security sv_qpwdlvl "Password level" NOT_ASSESSED low \
          "not assessed — QPWDLVL is *NOTAVL to this scan profile" \
          "The scan profile cannot read QPWDLVL — *NOTAVL is a missing-authority token, not a password-level value, and must not become a clean result." \
          "grant the scan profile authority to read QPWDLVL from QSYS2.SYSTEM_VALUE_INFO, recapture, then re-assess." \
          "cis-l1"
    else
      GRADE_RELEASE=$(ibmi_release 2>/dev/null || :)
      if [ "$GRADE_RELEASE" = 7.4 ]; then EXPECTED=3; else EXPECTED=4; fi
      case "$NUM" in
        "$EXPECTED")
          if [ "$EXPECTED" -eq 4 ]; then
            PASS_MEANING="The password level is 4 — IBM i stores passwords with PBKDF2 HMAC-SHA512 and does not keep the older decryptable hashes used at levels 0 and 1."
          else
            PASS_MEANING="The password level is 3, matching the CIS IBM i 7.4 benchmark recommendation."
          fi
          add security sv_qpwdlvl "Password level" PASS med "QPWDLVL=$NUM" \
              "$PASS_MEANING" \
              "n/a" "cis-l1"
          ;;
        0|1|2|3|4)
          add security sv_qpwdlvl "Password level" FAIL high "QPWDLVL=$NUM" \
              "The password level is $NUM, not the CIS IBM i $GRADE_RELEASE benchmark value $EXPECTED." \
              "during a planned window, set QPWDLVL to $EXPECTED (CHGSYSVAL SYSVAL(QPWDLVL) VALUE($EXPECTED)) and confirm users can still sign on. This scanner never changes system values." \
              "cis-l1"
          ;;
        *)
          add security sv_qpwdlvl "Password level" NOT_ASSESSED low \
              "not assessed — QPWDLVL value is not a documented numeric level (numeric='$NUM' character='$CHAR')" \
              "The QPWDLVL catalog row was present but not a documented password level 0-4, so it cannot be graded." \
              "inspect the QPWDLVL row in QSYS2.SYSTEM_VALUE_INFO, then re-assess." \
              "cis-l1"
          ;;
      esac
    fi
  fi

  # sv_qpwdrqddif — IBM i QPWDRQDDIF (required difference in passwords).
  # Authority: CIS IBM i V7R5M0/V7R4M0 5.1.1.25 (L1=2, 24 previous)
  # and 5.1.2.19 (L2=1, 32 previous). One finding. Parses the shared
  # cap-system-values dump. Does not call ibmi_sql. Does not CHGSYSVAL.
  # *NOTAVL is a refusal, never PASS. Token 1 or 2 is PASS (1 is
  # stricter than L1). Token 0 (IBM ship default) or 3-8 is FAIL.
  # Token 5 (IBM Docs recommended) is FAIL — 10 previous is under L1.
  # live Phase 0 dump is QPWDRQDDIF||1 and PASSes. Token is a history
  # code, not a character-count.
  if [ "${SYSVAL_OK:-0}" -ne 1 ]; then
    add security sv_qpwdrqddif "Required difference in passwords" NOT_ASSESSED low \
        "not assessed — ${SYSVAL_WHY:-capture unavailable}" \
        "The SYSTEM_VALUE_INFO capture did not yield a readable dump, so QPWDRQDDIF cannot be graded." \
        "re-run the scan as the scan profile and confirm QSYS2.SYSTEM_VALUE_INFO returns rows. This scanner never changes system values." \
        "cis-l1 cis-l2"
  else
    QDIF_LINE=$(printf '%s\n' "$SYSVAL_RAW" | awk -F'|' '$1=="QPWDRQDDIF"{n++; line=$0} END{if(n==1) print line}')
    QDIF_RC=$?
    if [ -z "$QDIF_LINE" ]; then
      add security sv_qpwdrqddif "Required difference in passwords" NOT_ASSESSED low \
          "not assessed — QPWDRQDDIF row missing or not unique in SYSTEM_VALUE_INFO" \
          "The system-value dump was readable, but it did not contain exactly one QPWDRQDDIF row, so the value cannot be graded." \
          "inspect QSYS2.SYSTEM_VALUE_INFO for SYSTEM_VALUE_NAME = QPWDRQDDIF." \
          "cis-l1 cis-l2"
    else
      QDIF_VAL=$(printf '%s\n' "$QDIF_LINE" | awk -F'|' '{ v=$3; if (v=="") v=$2; sub(/[ \t]+$/, "", v); print v }')
      if [ "$QDIF_VAL" = "*NOTAVL" ]; then
        add security sv_qpwdrqddif "Required difference in passwords" NOT_ASSESSED low \
            "not assessed — QPWDRQDDIF=*NOTAVL (scan profile cannot read this system value)" \
            "The catalog returned *NOTAVL for QPWDRQDDIF — the scan profile lacks authority to read this system value, so the value is not graded." \
            "grant the scan profile read access to QPWDRQDDIF and re-take cap-system-values. Do not run this check as QSECOFR to paper over the gap." \
            "cis-l1 cis-l2"
      elif [ -z "$QDIF_VAL" ]; then
        add security sv_qpwdrqddif "Required difference in passwords" NOT_ASSESSED low \
            "not assessed — QPWDRQDDIF value unreadable" \
            "The QPWDRQDDIF row was present, but the catalog value was empty, so it is not graded." \
            "inspect the QPWDRQDDIF row in QSYS2.SYSTEM_VALUE_INFO and DSPSYSVAL SYSVAL(QPWDRQDDIF)." \
            "cis-l1 cis-l2"
      else
        QDIFN=$(printf '%s\n' "$QDIF_VAL" | awk '/^[0-9]+$/{ if ($0 ~ /^0+$/) print 0; else { sub(/^0+/,""); print } }')
        case "$QDIFN" in
          1|2)
            add security sv_qpwdrqddif "Required difference in passwords" PASS low \
                "QPWDRQDDIF=$QDIFN" \
                "QPWDRQDDIF is $QDIFN (1 remembers 32 previous passwords, 2 remembers 24), so a recently used password cannot be reused immediately." \
                "n/a" \
                "cis-l1 cis-l2"
            ;;
          0|3|4|5|6|7|8)
            add security sv_qpwdrqddif "Required difference in passwords" FAIL high \
                "QPWDRQDDIF=$QDIFN" \
                "QPWDRQDDIF is $QDIFN, which remembers fewer than 24 previous passwords (or none), so a password can be reused too soon." \
                "set QPWDRQDDIF to 2, or to 1, using CHGSYSVAL SYSVAL(QPWDRQDDIF) VALUE('2'). This scanner never changes system values." \
                "cis-l1 cis-l2"
            ;;
          *)
            add security sv_qpwdrqddif "Required difference in passwords" NOT_ASSESSED low \
                "not assessed — QPWDRQDDIF value unreadable" \
                "The QPWDRQDDIF row was present, but the catalog value was not an integer 0-8 or *NOTAVL, so it is not graded." \
                "inspect the QPWDRQDDIF row in QSYS2.SYSTEM_VALUE_INFO and DSPSYSVAL SYSVAL(QPWDRQDDIF)." \
                "cis-l1 cis-l2"
            ;;
        esac
      fi
    fi
  fi

  # sv_qpwdrules — IBM i QPWDRULES (password composition rules).
  # Authority: CIS IBM i V7R5M0/V7R4M0 5.1.1.26 (L1 nine flags + MINLEN>=8)
  # and 5.1.2.20 (L2 *MINLEN14 set; scores FAIL under L1).
  # One finding. Parses the shared cap-system-values dump. Does not call
  # ibmi_sql. Does not CHGSYSVAL. *NOTAVL is a refusal, never PASS.
  # *PWDSYSVAL (IBM ship default) is FAIL. L2 token set is FAIL (missing
  # L1 placement flags). live Phase 0 dump is
  # QPWDRULES||*ALLCRTCHG     *LMTPRFNAME    *MINLEN15 and is FAIL.
  if [ "${SYSVAL_OK:-0}" -ne 1 ]; then
    add security sv_qpwdrules "Password rules" NOT_ASSESSED low \
        "not assessed — ${SYSVAL_WHY:-capture unavailable}" \
        "The SYSTEM_VALUE_INFO capture did not yield a readable dump, so QPWDRULES cannot be graded." \
        "re-run the scan as the scan profile and confirm QSYS2.SYSTEM_VALUE_INFO returns rows. This scanner never changes system values." \
        "cis-l1 cis-l2"
  else
    QPWD_LINE=$(printf '%s\n' "$SYSVAL_RAW" | awk -F'|' '$1=="QPWDRULES"{n++; line=$0} END{if(n==1) print line}')
    QPWD_RC=$?
    if [ -z "$QPWD_LINE" ]; then
      add security sv_qpwdrules "Password rules" NOT_ASSESSED low \
          "not assessed — QPWDRULES row missing or not unique in SYSTEM_VALUE_INFO" \
          "The system-value dump was readable, but it did not contain exactly one QPWDRULES row, so the value cannot be graded." \
          "inspect QSYS2.SYSTEM_VALUE_INFO for SYSTEM_VALUE_NAME = QPWDRULES." \
          "cis-l1 cis-l2"
    else
      QPWD_VAL=$(printf '%s\n' "$QPWD_LINE" | awk -F'|' '{ v=$3; if (v=="") v=$2; sub(/[ \t]+$/, "", v); print v }')
      if [ -z "$QPWD_VAL" ]; then
        add security sv_qpwdrules "Password rules" NOT_ASSESSED low \
            "not assessed — QPWDRULES value unreadable" \
            "The QPWDRULES row was present, but the catalog value was empty, so it is not graded." \
            "inspect the QPWDRULES row in QSYS2.SYSTEM_VALUE_INFO and DSPSYSVAL SYSVAL(QPWDRULES)." \
            "cis-l1 cis-l2"
      else
        QPWD_TOK=$(printf '%s\n' "$QPWD_VAL" | awk '
          {
            n=split($0, a, /[ \t]+/)
            for (i=1; i<=n; i++) {
              t=a[i]
              if (t=="") continue
              nt++
              if (t=="*NOTAVL") nv=1
              if (t=="*PWDSYSVAL") ps=1
              if (t=="*ALLCRTCHG") allc=1
              if (t=="*DGTLMTAJC") dajc=1
              if (t=="*DGTLMTFST") dfst=1
              if (t=="*DGTLMTLST") dlst=1
              if (t=="*LMTPRFNAME") lprf=1
              if (t=="*REQANY3") req3=1
              if (t=="*SPCCHRLMTAJC") sajc=1
              if (t=="*SPCCHRLMTFST") sfst=1
              if (t=="*SPCCHRLMTLST") slst=1
              if (t ~ /^\*MINLEN[0-9]+$/) {
                nmin++
                m=t
                sub(/^\*MINLEN/, "", m)
                if (m ~ /^0+$/) minn=0
                else { sub(/^0+/, "", m); minn=m+0 }
              }
              if (t ~ /^\*MAXLEN[0-9]+$/) {
                nmax++
                x=t
                sub(/^\*MAXLEN/, "", x)
                if (x ~ /^0+$/) maxn=0
                else { sub(/^0+/, "", x); maxn=x+0 }
              }
            }
          }
          END {
            if (nv) print "NOTAVL"
            else if (nt<1) print "BAD"
            else if (nmin>1 || nmax>1) print "BAD"
            else if (nmin==1 && (minn<1 || minn>128)) print "BAD"
            else if (nmax==1 && (maxn<1 || maxn>128)) print "BAD"
            else if (nmin==1 && nmax==1 && maxn<minn) print "BAD"
            else if (ps) print "FAIL"
            else if (!allc || !dajc || !dfst || !dlst || !lprf || !req3 || !sajc || !sfst || !slst) print "FAIL"
            else if (nmin==0 || minn<8) print "FAIL"
            else print "PASS"
          }')
        if [ "$QPWD_TOK" = NOTAVL ]; then
          add security sv_qpwdrules "Password rules" NOT_ASSESSED low \
              "not assessed — QPWDRULES=*NOTAVL (scan profile cannot read this system value)" \
              "The catalog returned *NOTAVL for QPWDRULES — the scan profile lacks authority to read this system value, so the value is not graded." \
              "grant the scan profile read access to QPWDRULES and re-take cap-system-values. Do not run this check as QSECOFR to paper over the gap." \
              "cis-l1 cis-l2"
        elif [ "$QPWD_TOK" = PASS ]; then
          add security sv_qpwdrules "Password rules" PASS low \
              "QPWDRULES=$QPWD_VAL" \
              "QPWDRULES applies composition rules on create and change, requires at least 8 characters and three character classes, blocks the profile name, and limits digit and special-character placement." \
              "n/a" \
              "cis-l1 cis-l2"
        elif [ "$QPWD_TOK" = FAIL ]; then
          add security sv_qpwdrules "Password rules" FAIL high \
              "QPWDRULES=$QPWD_VAL" \
              "QPWDRULES is *PWDSYSVAL or is missing a required composition rule, so a password can skip create/change enforcement, be shorter than 8 characters, reuse the profile name, skip mixed character classes, or skip digit and special-character placement limits." \
              "set QPWDRULES to include *ALLCRTCHG *DGTLMTAJC *DGTLMTFST *DGTLMTLST *LMTPRFNAME *MINLEN8 *REQANY3 *SPCCHRLMTAJC *SPCCHRLMTFST *SPCCHRLMTLST using CHGSYSVAL SYSVAL(QPWDRULES) VALUE('*ALLCRTCHG *DGTLMTAJC *DGTLMTFST *DGTLMTLST *LMTPRFNAME *MAXLEN10 *MINLEN8 *REQANY3 *SPCCHRLMTAJC *SPCCHRLMTFST *SPCCHRLMTLST'). This scanner never changes system values." \
              "cis-l1 cis-l2"
        else
          add security sv_qpwdrules "Password rules" NOT_ASSESSED low \
              "not assessed — QPWDRULES value unreadable" \
              "The QPWDRULES row was present, but a *MINLEN or *MAXLEN token was not a documented length 1-128, so it is not graded." \
              "inspect the QPWDRULES row in QSYS2.SYSTEM_VALUE_INFO and DSPSYSVAL SYSVAL(QPWDRULES)." \
              "cis-l1 cis-l2"
        fi
      fi
    fi
  fi

  # sv_qpwdvldpgm — IBM i QPWDVLDPGM (password validation program).
  # Authority: CIS IBM i V7R5M0/V7R4M0 5.1.2.21 (L2=*REGFAC or a
  # program specification, not *NONE). No L1 rec.
  # One finding. Parses the shared cap-system-values dump. Does not call
  # ibmi_sql. Does not CHGSYSVAL. Does not ADDEXITPGM. Does not read
  # QPWDLVL. *NOTAVL is a refusal, never PASS. Exact *NONE is FAIL
  # (IBM ship default). *REGFAC or a documented program spec is PASS.
  # live Phase 0 dump is QPWDVLDPGM||*NONE and is FAIL.
  if [ "${SYSVAL_OK:-0}" -ne 1 ]; then
    add security sv_qpwdvldpgm "Password validation program" NOT_ASSESSED low \
        "not assessed — ${SYSVAL_WHY:-capture unavailable}" \
        "The SYSTEM_VALUE_INFO capture did not yield a readable dump, so QPWDVLDPGM cannot be graded." \
        "re-run the scan as the scan profile and confirm QSYS2.SYSTEM_VALUE_INFO returns rows. This scanner never changes system values." \
        "cis-l2"
  else
    QVLD_LINE=$(printf '%s\n' "$SYSVAL_RAW" | awk -F'|' '$1=="QPWDVLDPGM"{n++; line=$0} END{if(n==1) print line}')
    QVLD_RC=$?
    if [ -z "$QVLD_LINE" ]; then
      add security sv_qpwdvldpgm "Password validation program" NOT_ASSESSED low \
          "not assessed — QPWDVLDPGM row missing or not unique in SYSTEM_VALUE_INFO" \
          "The system-value dump was readable, but it did not contain exactly one QPWDVLDPGM row, so the value cannot be graded." \
          "inspect QSYS2.SYSTEM_VALUE_INFO for SYSTEM_VALUE_NAME = QPWDVLDPGM." \
          "cis-l2"
    else
      QVLD_VAL=$(printf '%s\n' "$QVLD_LINE" | awk -F'|' '{ v=$3; if (v=="") v=$2; sub(/[ \t]+$/, "", v); print v }')
      QVLD_TOK=$(printf '%s\n' "$QVLD_VAL" | awk '
        function nm(s) {
          return (length(s)>=1 && length(s)<=10 && s ~ /^[A-Z$#@][A-Z0-9$#@_]*$/)
        }
        function lb(s) {
          return (s=="*LIBL" || s=="*CURLIB" || nm(s))
        }
        {
          if ($0=="*NOTAVL") { print "NOTAVL"; exit }
          if ($0=="") { print "BAD"; exit }
          if ($0=="*NONE") { print "FAIL"; exit }
          if ($0=="*REGFAC") { print "PASS"; exit }
          sl=index($0, "/")
          if (sl>0) {
            lib=substr($0, 1, sl-1)
            pgm=substr($0, sl+1)
            if (index(pgm, "/")==0 && lb(lib) && nm(pgm)) { print "PASS"; exit }
            print "BAD"; exit
          }
          n=split($0, a, /[ \t]+/)
          c=0
          for (i=1; i<=n; i++) if (a[i]!="") { c++; t[c]=a[i] }
          if (c==1 && nm(t[1])) { print "PASS"; exit }
          if (c==2 && lb(t[1]) && nm(t[2])) { print "PASS"; exit }
          if (c==2 && nm(t[1]) && lb(t[2])) { print "PASS"; exit }
          print "BAD"
        }')
      if [ "$QVLD_TOK" = NOTAVL ]; then
        add security sv_qpwdvldpgm "Password validation program" NOT_ASSESSED low \
            "not assessed — QPWDVLDPGM=*NOTAVL (scan profile cannot read this system value)" \
            "The catalog returned *NOTAVL for QPWDVLDPGM — the scan profile lacks authority to read this system value, so the value is not graded." \
            "grant the scan profile read access to QPWDVLDPGM and re-take cap-system-values. Do not run this check as QSECOFR to paper over the gap." \
            "cis-l2"
      elif [ "$QVLD_TOK" = PASS ]; then
        add security sv_qpwdvldpgm "Password validation program" PASS low \
            "QPWDVLDPGM=$QVLD_VAL" \
            "QPWDVLDPGM names a password validation program or *REGFAC, so IBM i calls extra checking on a new password after the password-rule system values." \
            "n/a" \
            "cis-l2"
      elif [ "$QVLD_TOK" = FAIL ]; then
        add security sv_qpwdvldpgm "Password validation program" FAIL high \
            "QPWDVLDPGM=*NONE" \
            "QPWDVLDPGM is *NONE, so IBM i does not call a user-written program or a registration-facility exit to check a new password beyond the password-rule system values." \
            "set QPWDVLDPGM to *REGFAC using CHGSYSVAL SYSVAL(QPWDVLDPGM) VALUE('*REGFAC') and register a password validation program on exit point QIBM_QSY_VLD_PASSWRD. This scanner never changes system values." \
            "cis-l2"
      else
        add security sv_qpwdvldpgm "Password validation program" NOT_ASSESSED low \
            "not assessed — QPWDVLDPGM value unreadable" \
            "The QPWDVLDPGM row was present, but the catalog value was not *NONE, *REGFAC, a program specification, or *NOTAVL, so it is not graded." \
            "inspect the QPWDVLDPGM row in QSYS2.SYSTEM_VALUE_INFO and DSPSYSVAL SYSVAL(QPWDVLDPGM)." \
            "cis-l2"
      fi
    fi
  fi

  # sv_qretsvrsec — IBM i QRETSVRSEC (retain server security data).
  # Authority: CIS IBM i V7R5M0/V7R4M0 5.1.1.27 (L1=1). No L2 rec.
  # One finding. Parses the shared cap-system-values dump. Does not call
  # ibmi_sql. Does not CHGSYSVAL. *NOTAVL is a refusal, never PASS.
  # Exact 1 is PASS. Exact 0 (IBM ship default) is FAIL.
  # live Phase 0 dump is QRETSVRSEC||1.
  if [ "${SYSVAL_OK:-0}" -ne 1 ]; then
    add security sv_qretsvrsec "Retain server security" NOT_ASSESSED low \
        "not assessed — ${SYSVAL_WHY:-capture unavailable}" \
        "The SYSTEM_VALUE_INFO capture did not yield a readable dump, so QRETSVRSEC cannot be graded." \
        "re-run the scan as the scan profile and confirm QSYS2.SYSTEM_VALUE_INFO returns rows. This scanner never changes system values." \
        "cis-l1"
  else
    QRS_LINE=$(printf '%s\n' "$SYSVAL_RAW" | awk -F'|' '$1=="QRETSVRSEC"{n++; line=$0} END{if(n==1) print line}')
    QRS_RC=$?
    if [ -z "$QRS_LINE" ]; then
      add security sv_qretsvrsec "Retain server security" NOT_ASSESSED low \
          "not assessed — QRETSVRSEC row missing or not unique in SYSTEM_VALUE_INFO" \
          "The system-value dump was readable, but it did not contain exactly one QRETSVRSEC row, so the value cannot be graded." \
          "inspect QSYS2.SYSTEM_VALUE_INFO for SYSTEM_VALUE_NAME = QRETSVRSEC." \
          "cis-l1"
    else
      QRS_VAL=$(printf '%s\n' "$QRS_LINE" | awk -F'|' '{ v=$3; if (v=="") v=$2; sub(/[ \t]+$/, "", v); print v }')
      if [ "$QRS_VAL" = "*NOTAVL" ]; then
        add security sv_qretsvrsec "Retain server security" NOT_ASSESSED low \
            "not assessed — QRETSVRSEC=*NOTAVL (scan profile cannot read this system value)" \
            "The catalog returned *NOTAVL for QRETSVRSEC — the scan profile lacks authority to read this system value, so the value is not graded." \
            "grant the scan profile read access to QRETSVRSEC and re-take cap-system-values. Do not run this check as QSECOFR to paper over the gap." \
            "cis-l1"
      elif [ -z "$QRS_VAL" ]; then
        add security sv_qretsvrsec "Retain server security" NOT_ASSESSED low \
            "not assessed — QRETSVRSEC value unreadable" \
            "The QRETSVRSEC row was present, but the catalog value was empty, so it is not graded." \
            "inspect the QRETSVRSEC row in QSYS2.SYSTEM_VALUE_INFO and DSPSYSVAL SYSVAL(QRETSVRSEC)." \
            "cis-l1"
      elif [ "$QRS_VAL" = "1" ]; then
        add security sv_qretsvrsec "Retain server security" PASS low \
            "QRETSVRSEC=1" \
            "QRETSVRSEC is 1, so decryptable server authentication data for server authentication entries and validation lists can be retained." \
            "n/a" \
            "cis-l1"
      elif [ "$QRS_VAL" = "0" ]; then
        add security sv_qretsvrsec "Retain server security" FAIL high \
            "QRETSVRSEC=0" \
            "QRETSVRSEC is 0, so decryptable server authentication data is not retained." \
            "set QRETSVRSEC to 1 using CHGSYSVAL SYSVAL(QRETSVRSEC) VALUE('1'). This scanner never changes system values." \
            "cis-l1"
      else
        add security sv_qretsvrsec "Retain server security" NOT_ASSESSED low \
            "not assessed — QRETSVRSEC value unreadable" \
            "The QRETSVRSEC row was present, but the catalog value was not 0, 1, or *NOTAVL, so it is not graded." \
            "inspect the QRETSVRSEC row in QSYS2.SYSTEM_VALUE_INFO and DSPSYSVAL SYSVAL(QRETSVRSEC)." \
            "cis-l1"
      fi
    fi
  fi

  # sv_qrmtipl — IBM i QRMTIPL (remote power-on and restart).
  # Authority: CIS IBM i V7R5M0/V7R4M0 5.1.1.28 (L1=0). No L2 rec.
  # One finding. Parses the shared cap-system-values dump. Does not call
  # ibmi_sql. Does not CHGSYSVAL. *NOTAVL is a refusal, never PASS.
  # Exact 0 is PASS. Exact 1 (remote restart allowed) is FAIL.
  # live Phase 0 dump is QRMTIPL||0.
  if [ "${SYSVAL_OK:-0}" -ne 1 ]; then
    add security sv_qrmtipl "Remote IPL" NOT_ASSESSED low \
        "not assessed — ${SYSVAL_WHY:-capture unavailable}" \
        "The SYSTEM_VALUE_INFO capture did not yield a readable dump, so QRMTIPL cannot be graded." \
        "re-run the scan as the scan profile and confirm QSYS2.SYSTEM_VALUE_INFO returns rows. This scanner never changes system values." \
        "cis-l1"
  else
    QRIP_LINE=$(printf '%s\n' "$SYSVAL_RAW" | awk -F'|' '$1=="QRMTIPL"{n++; line=$0} END{if(n==1) print line}')
    QRIP_RC=$?
    if [ -z "$QRIP_LINE" ]; then
      add security sv_qrmtipl "Remote IPL" NOT_ASSESSED low \
          "not assessed — QRMTIPL row missing or not unique in SYSTEM_VALUE_INFO" \
          "The system-value dump was readable, but it did not contain exactly one QRMTIPL row, so the value cannot be graded." \
          "inspect QSYS2.SYSTEM_VALUE_INFO for SYSTEM_VALUE_NAME = QRMTIPL." \
          "cis-l1"
    else
      QRIP_VAL=$(printf '%s\n' "$QRIP_LINE" | awk -F'|' '{ v=$3; if (v=="") v=$2; sub(/[ \t]+$/, "", v); print v }')
      if [ "$QRIP_VAL" = "*NOTAVL" ]; then
        add security sv_qrmtipl "Remote IPL" NOT_ASSESSED low \
            "not assessed — QRMTIPL=*NOTAVL (scan profile cannot read this system value)" \
            "The catalog returned *NOTAVL for QRMTIPL — the scan profile lacks authority to read this system value, so the value is not graded." \
            "grant the scan profile read access to QRMTIPL and re-take cap-system-values. Do not run this check as QSECOFR to paper over the gap." \
            "cis-l1"
      elif [ -z "$QRIP_VAL" ]; then
        add security sv_qrmtipl "Remote IPL" NOT_ASSESSED low \
            "not assessed — QRMTIPL value unreadable" \
            "The QRMTIPL row was present, but the catalog value was empty, so it is not graded." \
            "inspect the QRMTIPL row in QSYS2.SYSTEM_VALUE_INFO and DSPSYSVAL SYSVAL(QRMTIPL)." \
            "cis-l1"
      elif [ "$QRIP_VAL" = "0" ]; then
        add security sv_qrmtipl "Remote IPL" PASS low \
            "QRMTIPL=0" \
            "QRMTIPL is 0, so remote power-on and restart over a telephone line or SPCN signal is not allowed." \
            "n/a" \
            "cis-l1"
      elif [ "$QRIP_VAL" = "1" ]; then
        add security sv_qrmtipl "Remote IPL" FAIL high \
            "QRMTIPL=1" \
            "QRMTIPL is 1, so a telephone call or SPCN signal can restart the system." \
            "set QRMTIPL to 0 using CHGSYSVAL SYSVAL(QRMTIPL) VALUE('0'). This scanner never changes system values." \
            "cis-l1"
      else
        add security sv_qrmtipl "Remote IPL" NOT_ASSESSED low \
            "not assessed — QRMTIPL value unreadable" \
            "The QRMTIPL row was present, but the catalog value was not 0, 1, or *NOTAVL, so it is not graded." \
            "inspect the QRMTIPL row in QSYS2.SYSTEM_VALUE_INFO and DSPSYSVAL SYSVAL(QRMTIPL)." \
            "cis-l1"
      fi
    fi
  fi

  # sv_qrmtsign — IBM i QRMTSIGN (remote sign-on control).
  # Authority: CIS IBM i V7R5M0 5.1.1.29 (L1=*VERIFY) and 5.1.2.22
  # (L2=*FRCSIGNON); V7R4M0 L2 rec number is 5.1.2.23.
  # One finding. Parses the shared cap-system-values dump. Does not call
  # ibmi_sql. Does not CHGSYSVAL. *NOTAVL is a refusal, never PASS.
  # Exact *VERIFY, *FRCSIGNON, *REJECT, or *SAMEPRF is PASS
  # (*FRCSIGNON is stricter than L1; *REJECT is stricter still).
  # (*SAMEPRF permits a strict subset of *VERIFY: bypass only on
  # matching profile names.)
  # A named program or any other token is FAIL.
  # live Phase 0 dump is QRMTSIGN||*FRCSIGNON.
  if [ "${SYSVAL_OK:-0}" -ne 1 ]; then
    add security sv_qrmtsign "Remote sign-on value" NOT_ASSESSED low \
        "not assessed — ${SYSVAL_WHY:-capture unavailable}" \
        "The SYSTEM_VALUE_INFO capture did not yield a readable dump, so QRMTSIGN cannot be graded." \
        "re-run the scan as the scan profile and confirm QSYS2.SYSTEM_VALUE_INFO returns rows. This scanner never changes system values." \
        "cis-l1 cis-l2"
  else
    QRM_LINE=$(printf '%s\n' "$SYSVAL_RAW" | awk -F'|' '$1=="QRMTSIGN"{n++; line=$0} END{if(n==1) print line}')
    QRM_RC=$?
    if [ -z "$QRM_LINE" ]; then
      add security sv_qrmtsign "Remote sign-on value" NOT_ASSESSED low \
          "not assessed — QRMTSIGN row missing or not unique in SYSTEM_VALUE_INFO" \
          "The system-value dump was readable, but it did not contain exactly one QRMTSIGN row, so the value cannot be graded." \
          "inspect QSYS2.SYSTEM_VALUE_INFO for SYSTEM_VALUE_NAME = QRMTSIGN." \
          "cis-l1 cis-l2"
    else
      QRM_VAL=$(printf '%s\n' "$QRM_LINE" | awk -F'|' '{ v=$3; if (v=="") v=$2; sub(/[ \t]+$/, "", v); print v }')
      if [ "$QRM_VAL" = "*NOTAVL" ]; then
        add security sv_qrmtsign "Remote sign-on value" NOT_ASSESSED low \
            "not assessed — QRMTSIGN=*NOTAVL (scan profile cannot read this system value)" \
            "The catalog returned *NOTAVL for QRMTSIGN — the scan profile lacks authority to read this system value, so the value is not graded." \
            "grant the scan profile read access to QRMTSIGN and re-take cap-system-values. Do not run this check as QSECOFR to paper over the gap." \
            "cis-l1 cis-l2"
      elif [ -z "$QRM_VAL" ]; then
        add security sv_qrmtsign "Remote sign-on value" NOT_ASSESSED low \
            "not assessed — QRMTSIGN value unreadable" \
            "The QRMTSIGN row was present, but the catalog value was empty, so it is not graded." \
            "inspect the QRMTSIGN row in QSYS2.SYSTEM_VALUE_INFO and DSPSYSVAL SYSVAL(QRMTSIGN)." \
            "cis-l1 cis-l2"
      elif [ "$QRM_VAL" = "*VERIFY" ] || [ "$QRM_VAL" = "*FRCSIGNON" ] || [ "$QRM_VAL" = "*REJECT" ] || [ "$QRM_VAL" = "*SAMEPRF" ]; then
        add security sv_qrmtsign "Remote sign-on value" PASS low \
            "QRMTSIGN=$QRM_VAL" \
            "QRMTSIGN is a documented special value (*VERIFY, *FRCSIGNON, *REJECT, or *SAMEPRF), so remote automatic sign-on is verified, forced through the sign-on display, rejected, or limited to matching user profiles." \
            "n/a" \
            "cis-l1 cis-l2"
      else
        add security sv_qrmtsign "Remote sign-on value" FAIL high \
            "QRMTSIGN=$QRM_VAL" \
            "QRMTSIGN names a program or other non-special value, so remote sign-on is controlled by an ungraded user program instead of a documented special value." \
            "set QRMTSIGN to *VERIFY, or to *FRCSIGNON, using CHGSYSVAL SYSVAL(QRMTSIGN) VALUE('*VERIFY'). This scanner never changes system values." \
            "cis-l1 cis-l2"
      fi
    fi
  fi

  # sv_qrmtsrvatr — IBM i QRMTSRVATR (remote service attribute).
  # Authority: CIS IBM i V7R5M0/V7R4M0 5.1.1.30 (L1=0). No L2 rec.
  # One finding. Parses the shared cap-system-values dump. Does not call
  # ibmi_sql. Does not CHGSYSVAL. Does not CHGSRVA. *NOTAVL is a
  # refusal, never PASS. Exact 0 is PASS. Exact 1 (remote service on)
  # is FAIL. live Phase 0 dump is QRMTSRVATR||0.
  if [ "${SYSVAL_OK:-0}" -ne 1 ]; then
    add security sv_qrmtsrvatr "Remote service attribute" NOT_ASSESSED low \
        "not assessed — ${SYSVAL_WHY:-capture unavailable}" \
        "The SYSTEM_VALUE_INFO capture did not yield a readable dump, so QRMTSRVATR cannot be graded." \
        "re-run the scan as the scan profile and confirm QSYS2.SYSTEM_VALUE_INFO returns rows. This scanner never changes system values." \
        "cis-l1"
  else
    QRSA_LINE=$(printf '%s\n' "$SYSVAL_RAW" | awk -F'|' '$1=="QRMTSRVATR"{n++; line=$0} END{if(n==1) print line}')
    QRSA_RC=$?
    if [ -z "$QRSA_LINE" ]; then
      add security sv_qrmtsrvatr "Remote service attribute" NOT_ASSESSED low \
          "not assessed — QRMTSRVATR row missing or not unique in SYSTEM_VALUE_INFO" \
          "The system-value dump was readable, but it did not contain exactly one QRMTSRVATR row, so the value cannot be graded." \
          "inspect QSYS2.SYSTEM_VALUE_INFO for SYSTEM_VALUE_NAME = QRMTSRVATR." \
          "cis-l1"
    else
      QRSA_VAL=$(printf '%s\n' "$QRSA_LINE" | awk -F'|' '{ v=$3; if (v=="") v=$2; sub(/[ \t]+$/, "", v); print v }')
      if [ "$QRSA_VAL" = "*NOTAVL" ]; then
        add security sv_qrmtsrvatr "Remote service attribute" NOT_ASSESSED low \
            "not assessed — QRMTSRVATR=*NOTAVL (scan profile cannot read this system value)" \
            "The catalog returned *NOTAVL for QRMTSRVATR — the scan profile lacks authority to read this system value, so the value is not graded." \
            "grant the scan profile read access to QRMTSRVATR and re-take cap-system-values. Do not run this check as QSECOFR to paper over the gap." \
            "cis-l1"
      elif [ -z "$QRSA_VAL" ]; then
        add security sv_qrmtsrvatr "Remote service attribute" NOT_ASSESSED low \
            "not assessed — QRMTSRVATR value unreadable" \
            "The QRMTSRVATR row was present, but the catalog value was empty, so it is not graded." \
            "inspect the QRMTSRVATR row in QSYS2.SYSTEM_VALUE_INFO and DSPSYSVAL SYSVAL(QRMTSRVATR)." \
            "cis-l1"
      elif [ "$QRSA_VAL" = "0" ]; then
        add security sv_qrmtsrvatr "Remote service attribute" PASS low \
            "QRMTSRVATR=0" \
            "QRMTSRVATR is 0, so remote problem analysis of the system is not allowed." \
            "n/a" \
            "cis-l1"
      elif [ "$QRSA_VAL" = "1" ]; then
        add security sv_qrmtsrvatr "Remote service attribute" FAIL high \
            "QRMTSRVATR=1" \
            "QRMTSRVATR is 1, so the system can be analyzed remotely through remote service support." \
            "set QRMTSRVATR to 0 using CHGSYSVAL SYSVAL(QRMTSRVATR) VALUE('0'). This scanner never changes system values." \
            "cis-l1"
      else
        add security sv_qrmtsrvatr "Remote service attribute" NOT_ASSESSED low \
            "not assessed — QRMTSRVATR value unreadable" \
            "The QRMTSRVATR row was present, but the catalog value was not 0, 1, or *NOTAVL, so it is not graded." \
            "inspect the QRMTSRVATR row in QSYS2.SYSTEM_VALUE_INFO and DSPSYSVAL SYSVAL(QRMTSRVATR)." \
            "cis-l1"
      fi
    fi
  fi

  # sv_qscanfs — IBM i QSCANFS (scan file systems).
  # Authority: CIS IBM i V7R5M0/V7R4M0 5.1.1.31 (L1=*ROOTOPNUD). No L2 rec.
  # One finding. Parses the shared cap-system-values dump. Does not call
  # ibmi_sql. Does not CHGSYSVAL. *NOTAVL is a refusal, never PASS.
  # Exact *ROOTOPNUD is PASS. Exact *NONE (scanning off) is FAIL.
  # live Phase 0 dump is QSCANFS||*ROOTOPNUD.
  if [ "${SYSVAL_OK:-0}" -ne 1 ]; then
    add security sv_qscanfs "Scan file systems" NOT_ASSESSED low \
        "not assessed — ${SYSVAL_WHY:-capture unavailable}" \
        "The SYSTEM_VALUE_INFO capture did not yield a readable dump, so QSCANFS cannot be graded." \
        "re-run the scan as the scan profile and confirm QSYS2.SYSTEM_VALUE_INFO returns rows. This scanner never changes system values." \
        "cis-l1"
  else
    QSF_LINE=$(printf '%s\n' "$SYSVAL_RAW" | awk -F'|' '$1=="QSCANFS"{n++; line=$0} END{if(n==1) print line}')
    QSF_RC=$?
    if [ -z "$QSF_LINE" ]; then
      add security sv_qscanfs "Scan file systems" NOT_ASSESSED low \
          "not assessed — QSCANFS row missing or not unique in SYSTEM_VALUE_INFO" \
          "The system-value dump was readable, but it did not contain exactly one QSCANFS row, so the value cannot be graded." \
          "inspect QSYS2.SYSTEM_VALUE_INFO for SYSTEM_VALUE_NAME = QSCANFS." \
          "cis-l1"
    else
      QSF_VAL=$(printf '%s\n' "$QSF_LINE" | awk -F'|' '{ v=$3; if (v=="") v=$2; sub(/[ \t]+$/, "", v); print v }')
      if [ "$QSF_VAL" = "*NOTAVL" ]; then
        add security sv_qscanfs "Scan file systems" NOT_ASSESSED low \
            "not assessed — QSCANFS=*NOTAVL (scan profile cannot read this system value)" \
            "The catalog returned *NOTAVL for QSCANFS — the scan profile lacks authority to read this system value, so the value is not graded." \
            "grant the scan profile read access to QSCANFS and re-take cap-system-values. Do not run this check as QSECOFR to paper over the gap." \
            "cis-l1"
      elif [ -z "$QSF_VAL" ]; then
        add security sv_qscanfs "Scan file systems" NOT_ASSESSED low \
            "not assessed — QSCANFS value unreadable" \
            "The QSCANFS row was present, but the catalog value was empty, so it is not graded." \
            "inspect the QSCANFS row in QSYS2.SYSTEM_VALUE_INFO and DSPSYSVAL SYSVAL(QSCANFS)." \
            "cis-l1"
      elif [ "$QSF_VAL" = "*ROOTOPNUD" ]; then
        add security sv_qscanfs "Scan file systems" PASS low \
            "QSCANFS=*ROOTOPNUD" \
            "QSCANFS is *ROOTOPNUD, so stream files in the root, QOpenSys, and user-defined file systems are scanned when scan-related exit programs are registered." \
            "n/a" \
            "cis-l1"
      elif [ "$QSF_VAL" = "*NONE" ]; then
        add security sv_qscanfs "Scan file systems" FAIL high \
            "QSCANFS=*NONE" \
            "QSCANFS is *NONE, so no integrated file system objects are scanned even when scan-related exit programs are registered." \
            "set QSCANFS to *ROOTOPNUD using CHGSYSVAL SYSVAL(QSCANFS) VALUE('*ROOTOPNUD'). This scanner never changes system values." \
            "cis-l1"
      else
        add security sv_qscanfs "Scan file systems" NOT_ASSESSED low \
            "not assessed — QSCANFS value unreadable" \
            "The QSCANFS row was present, but the catalog value was not *ROOTOPNUD, *NONE, or *NOTAVL, so it is not graded." \
            "inspect the QSCANFS row in QSYS2.SYSTEM_VALUE_INFO and DSPSYSVAL SYSVAL(QSCANFS)." \
            "cis-l1"
      fi
    fi
  fi

  # sv_qscanfsctl — IBM i QSCANFSCTL (scan file systems control).
  # Authority: CIS IBM i V7R5M0/V7R4M0 5.1.1.32 (L1=*ERRFAIL *NOWRTUPG).
  # No L2 rec. One finding. Parses the shared cap-system-values dump.
  # Does not call ibmi_sql. Does not CHGSYSVAL. *NOTAVL is a refusal,
  # never PASS. Exact token set *ERRFAIL plus *NOWRTUPG (any order,
  # any whitespace) is PASS. *NONE (IBM ship default) or any other
  # documented token set is FAIL. An undocumented token set is
  # NOT_ASSESSED. live Phase 0 dump is
  # QSCANFSCTL||*ERRFAIL  *NOWRTUPG (two spaces).
  if [ "${SYSVAL_OK:-0}" -ne 1 ]; then
    add security sv_qscanfsctl "Scan file system control" NOT_ASSESSED low \
        "not assessed — ${SYSVAL_WHY:-capture unavailable}" \
        "The SYSTEM_VALUE_INFO capture did not yield a readable dump, so QSCANFSCTL cannot be graded." \
        "re-run the scan as the scan profile and confirm QSYS2.SYSTEM_VALUE_INFO returns rows. This scanner never changes system values." \
        "cis-l1"
  else
    QSFC_LINE=$(printf '%s\n' "$SYSVAL_RAW" | awk -F'|' '$1=="QSCANFSCTL"{n++; line=$0} END{if(n==1) print line}')
    QSFC_RC=$?
    if [ -z "$QSFC_LINE" ]; then
      add security sv_qscanfsctl "Scan file system control" NOT_ASSESSED low \
          "not assessed — QSCANFSCTL row missing or not unique in SYSTEM_VALUE_INFO" \
          "The system-value dump was readable, but it did not contain exactly one QSCANFSCTL row, so the value cannot be graded." \
          "inspect QSYS2.SYSTEM_VALUE_INFO for SYSTEM_VALUE_NAME = QSCANFSCTL." \
          "cis-l1"
    else
      QSFC_VAL=$(printf '%s\n' "$QSFC_LINE" | awk -F'|' '{ v=$3; if (v=="") v=$2; sub(/[ \t]+$/, "", v); print v }')
      QSFC_TOK=$(printf '%s\n' "$QSFC_VAL" | awk '
        {
          n=split($0, a, /[ \t]+/)
          for (i=1; i<=n; i++) {
            if (a[i]=="") continue
            nt++
            if (a[i]=="*NOTAVL") nv=1
            if (a[i]=="*ERRFAIL") ef=1
            if (a[i]=="*NOWRTUPG") nw=1
            if (a[i]=="*NONE" || a[i]=="*ERRFAIL" || a[i]=="*FSVRONLY" || a[i]=="*NOFAILCLO" || a[i]=="*NOPOSTRST" || a[i]=="*NOWRTUPG" || a[i]=="*USEOCOATR") d++
            else j++
          }
        }
        END {
          if (nv) print "NOTAVL"
          else if (j || nt<1) print "BAD"
          else if (nt==2 && ef && nw) print "PASS"
          else print "FAIL"
        }')
      if [ "$QSFC_TOK" = NOTAVL ]; then
        add security sv_qscanfsctl "Scan file system control" NOT_ASSESSED low \
            "not assessed — QSCANFSCTL=*NOTAVL (scan profile cannot read this system value)" \
            "The catalog returned *NOTAVL for QSCANFSCTL — the scan profile lacks authority to read this system value, so the value is not graded." \
            "grant the scan profile read access to QSCANFSCTL and re-take cap-system-values. Do not run this check as QSECOFR to paper over the gap." \
            "cis-l1"
      elif [ "$QSFC_TOK" = PASS ]; then
        add security sv_qscanfsctl "Scan file system control" PASS low \
            "QSCANFSCTL=$QSFC_VAL" \
            "QSCANFSCTL is *ERRFAIL and *NOWRTUPG, so a scan-exit failure fails the request and the scan descriptor is not upgraded to write access." \
            "n/a" \
            "cis-l1"
      elif [ "$QSFC_TOK" = FAIL ]; then
        add security sv_qscanfsctl "Scan file system control" FAIL high \
            "QSCANFSCTL=$QSFC_VAL" \
            "QSCANFSCTL is not exactly the required *ERRFAIL plus *NOWRTUPG token set, so the required scan-exit failure and no-write-upgrade behavior cannot be confirmed." \
            "set QSCANFSCTL to *ERRFAIL *NOWRTUPG using CHGSYSVAL SYSVAL(QSCANFSCTL) VALUE('*ERRFAIL *NOWRTUPG'). This scanner never changes system values." \
            "cis-l1"
      else
        add security sv_qscanfsctl "Scan file system control" NOT_ASSESSED low \
            "not assessed — QSCANFSCTL value unreadable" \
            "The QSCANFSCTL row was present, but the catalog value was not a documented scan-control token set, *ERRFAIL plus *NOWRTUPG, or *NOTAVL, so it is not graded." \
            "inspect the QSCANFSCTL row in QSYS2.SYSTEM_VALUE_INFO and DSPSYSVAL SYSVAL(QSCANFSCTL)." \
            "cis-l1"
      fi
    fi
  fi

  # sv_qsecurity — IBM i QSECURITY. L1 min 40 (CIS IBM i 5.1.1.33);
  # L2 (5.1.2.23, min 50) is a tag, not a second finding.
  # Parses cap-system-values (D-i3). Never CHGSYSVAL. Never DSPSYSVAL.
  # Never ibmi_sql from this fragment.
  if [ "${SYSVAL_OK:-0}" -ne 1 ]; then
    add security sv_qsecurity "System security level" NOT_ASSESSED low \
        "not assessed — ${SYSVAL_WHY:-SYSTEM_VALUE_INFO capture missing}" \
        "The SYSTEM_VALUE_INFO capture did not yield a readable QSECURITY value." \
        "re-run the scan after SYSTEM_VALUE_INFO is readable, or inspect DSPSYSVAL SYSVAL(QSECURITY) manually." \
        "cis:5.1.1.33 cis:5.1.2.23"
  else
    QSEC_ROW=$(printf '%s\n' "$SYSVAL_RAW" | awk -F'|' '$1=="QSECURITY" { print; exit }')
    if [ -z "$QSEC_ROW" ]; then
      add security sv_qsecurity "System security level" NOT_ASSESSED low \
          "not assessed — QSECURITY row absent from SYSTEM_VALUE_INFO" \
          "The SYSTEM_VALUE_INFO capture did not yield a readable QSECURITY value." \
          "re-run the scan after SYSTEM_VALUE_INFO is readable, or inspect DSPSYSVAL SYSVAL(QSECURITY) manually." \
          "cis:5.1.1.33 cis:5.1.2.23"
    else
      QSEC_VAL=$(printf '%s\n' "$QSEC_ROW" | awk -F'|' '{ v=$3; if (v=="") v=$2; print v }')
      if [ "$QSEC_VAL" = "*NOTAVL" ]; then
        add security sv_qsecurity "System security level" NOT_ASSESSED low \
            "not assessed — QSECURITY=*NOTAVL (scan profile cannot read this system value)" \
            "QSECURITY is not available to this scan profile. A missing authority is not a clean result." \
            "grant the scan profile authority to read QSECURITY, recapture SYSTEM_VALUE_INFO, or inspect DSPSYSVAL SYSVAL(QSECURITY) as a profile that can see it." \
            "cis:5.1.1.33 cis:5.1.2.23"
      else
        QSEC_GRADE=$(printf '%s\n' "$QSEC_VAL" | awk '
          $0 ~ /^[0-9]+$/ { if ($0+0>=40) print "pass"; else print "fail"; next }
          { print "bad" }')
        if [ "$QSEC_GRADE" = pass ]; then
          QSEC_L2=""
          if [ "$QSEC_VAL" -ge 50 ]; then
            QSEC_L2=" cis:5.1.2.23"
          fi
          add security sv_qsecurity "System security level" PASS low \
              "QSECURITY=$QSEC_VAL" \
              "System security level QSECURITY is 40 or higher, so resource-level integrity protection is on." \
              "n/a" \
              "cis:5.1.1.33${QSEC_L2}"
        elif [ "$QSEC_GRADE" = fail ]; then
          add security sv_qsecurity "System security level" FAIL high \
              "QSECURITY=$QSEC_VAL" \
              "System security level QSECURITY is below 40. Levels 10, 20, and 30 do not provide resource-level integrity protection." \
              "set QSECURITY to 40 (or 50) with CHGSYSVAL SYSVAL(QSECURITY) VALUE(40) after confirming applications tolerate that level. This scanner never changes system values." \
              "cis:5.1.1.33 cis:5.1.2.23"
        else
          add security sv_qsecurity "System security level" NOT_ASSESSED low \
              "not assessed — QSECURITY=$QSEC_VAL is not a decimal security level" \
              "The QSECURITY row was present but the value was not a decimal security level, so it cannot be graded." \
              "inspect DSPSYSVAL SYSVAL(QSECURITY) manually and recapture SYSTEM_VALUE_INFO." \
              "cis:5.1.1.33 cis:5.1.2.23"
        fi
      fi
    fi
  fi

  # sv_qshrmemctl — IBM i QSHRMEMCTL (shared memory control).
  # Authority: CIS IBM i V7R5M0/V7R4M0 5.1.1.34 (L1=1) and
  # 5.1.2.24/5.1.2.25 (L2=0). Grade L1. One finding. Parses the shared
  # cap-system-values dump. Does not call ibmi_sql. Does not CHGSYSVAL.
  # *NOTAVL is a refusal, never PASS. Exact 1 is PASS. Exact 0 (L2
  # token; blocks shmat/mmap write) is FAIL. live Phase 0 dump is
  # QSHRMEMCTL||1.
  if [ "${SYSVAL_OK:-0}" -ne 1 ]; then
    add security sv_qshrmemctl "Shared memory control" NOT_ASSESSED low \
        "not assessed — ${SYSVAL_WHY:-capture unavailable}" \
        "The SYSTEM_VALUE_INFO capture did not yield a readable dump, so QSHRMEMCTL cannot be graded." \
        "re-run the scan as the scan profile and confirm QSYS2.SYSTEM_VALUE_INFO returns rows. This scanner never changes system values." \
        "cis-l1"
  else
    QSHM_LINE=$(printf '%s\n' "$SYSVAL_RAW" | awk -F'|' '$1=="QSHRMEMCTL"{n++; line=$0} END{if(n==1) print line}')
    QSHM_RC=$?
    if [ -z "$QSHM_LINE" ]; then
      add security sv_qshrmemctl "Shared memory control" NOT_ASSESSED low \
          "not assessed — QSHRMEMCTL row missing or not unique in SYSTEM_VALUE_INFO" \
          "The system-value dump was readable, but it did not contain exactly one QSHRMEMCTL row, so the value cannot be graded." \
          "inspect QSYS2.SYSTEM_VALUE_INFO for SYSTEM_VALUE_NAME = QSHRMEMCTL." \
          "cis-l1"
    else
      QSHM_VAL=$(printf '%s\n' "$QSHM_LINE" | awk -F'|' '{ v=$3; if (v=="") v=$2; sub(/[ \t]+$/, "", v); print v }')
      if [ "$QSHM_VAL" = "*NOTAVL" ]; then
        add security sv_qshrmemctl "Shared memory control" NOT_ASSESSED low \
            "not assessed — QSHRMEMCTL=*NOTAVL (scan profile cannot read this system value)" \
            "The catalog returned *NOTAVL for QSHRMEMCTL — the scan profile lacks authority to read this system value, so the value is not graded." \
            "grant the scan profile read access to QSHRMEMCTL and re-take cap-system-values. Do not run this check as QSECOFR to paper over the gap." \
            "cis-l1"
      elif [ -z "$QSHM_VAL" ]; then
        add security sv_qshrmemctl "Shared memory control" NOT_ASSESSED low \
            "not assessed — QSHRMEMCTL value unreadable" \
            "The QSHRMEMCTL row was present, but the catalog value was empty, so it is not graded." \
            "inspect the QSHRMEMCTL row in QSYS2.SYSTEM_VALUE_INFO and DSPSYSVAL SYSVAL(QSHRMEMCTL)." \
            "cis-l1"
      elif [ "$QSHM_VAL" = "1" ]; then
        add security sv_qshrmemctl "Shared memory control" PASS low \
            "QSHRMEMCTL=1" \
            "QSHRMEMCTL is 1, so users can use shared-memory APIs and mapped memory with write capability." \
            "n/a" \
            "cis-l1"
      elif [ "$QSHM_VAL" = "0" ]; then
        add security sv_qshrmemctl "Shared memory control" FAIL high \
            "QSHRMEMCTL=0" \
            "QSHRMEMCTL is 0, so users cannot use shared-memory APIs (shmat) or mapped memory with write capability (mmap)." \
            "set QSHRMEMCTL to 1 using CHGSYSVAL SYSVAL(QSHRMEMCTL) VALUE('1'). 0 is the CIS L2 hardened value; this check grades strictly to L1. This scanner never changes system values." \
            "cis-l1"
      else
        add security sv_qshrmemctl "Shared memory control" NOT_ASSESSED low \
            "not assessed — QSHRMEMCTL value unreadable" \
            "The QSHRMEMCTL row was present, but the catalog value was not 0, 1, or *NOTAVL, so it is not graded." \
            "inspect the QSHRMEMCTL row in QSYS2.SYSTEM_VALUE_INFO and DSPSYSVAL SYSVAL(QSHRMEMCTL)." \
            "cis-l1"
      fi
    fi
  fi

  # sv_qsslcsl — IBM i QSSLCSL (System TLS cipher specification list).
  # Authority: CIS IBM i V7R5M0/V7R4M0 5.1.1.35 (L1).
  # No L2 rec. One finding. Parses the shared cap-system-values dump.
  # Does not call ibmi_sql. Does not CHGSYSVAL. *NOTAVL is a refusal,
  # never PASS. Non-empty subset of the nine AES-GCM/ChaCha20 suites
  # is PASS (live *OPSYS dump is two TLS 1.3 AES-GCM tokens, padded).
  # Any documented older suite is FAIL. live Phase 0 dump is
  # QSSLCSL||*AES_128_GCM_SHA256                     *AES_256_GCM_SHA384.
  if [ "${SYSVAL_OK:-0}" -ne 1 ]; then
    add security sv_qsslcsl "SSL cipher specification list" NOT_ASSESSED low \
        "not assessed — ${SYSVAL_WHY:-capture unavailable}" \
        "The SYSTEM_VALUE_INFO capture did not yield a readable dump, so QSSLCSL cannot be graded." \
        "re-run the scan as the scan profile and confirm QSYS2.SYSTEM_VALUE_INFO returns rows. This scanner never changes system values." \
        "cis-l1"
  else
    QCSL_LINE=$(printf '%s\n' "$SYSVAL_RAW" | awk -F'|' '$1=="QSSLCSL"{n++; line=$0} END{if(n==1) print line}')
    QCSL_RC=$?
    if [ -z "$QCSL_LINE" ]; then
      add security sv_qsslcsl "SSL cipher specification list" NOT_ASSESSED low \
          "not assessed — QSSLCSL row missing or not unique in SYSTEM_VALUE_INFO" \
          "The system-value dump was readable, but it did not contain exactly one QSSLCSL row, so the value cannot be graded." \
          "inspect QSYS2.SYSTEM_VALUE_INFO for SYSTEM_VALUE_NAME = QSSLCSL." \
          "cis-l1"
    else
      QCSL_VAL=$(printf '%s\n' "$QCSL_LINE" | awk -F'|' '{ v=$3; if (v=="") v=$2; sub(/[ \t]+$/, "", v); print v }')
      QCSL_TOK=$(printf '%s\n' "$QCSL_VAL" | awk '
        {
          n=split($0, a, /[ \t]+/)
          for (i=1; i<=n; i++) {
            t=a[i]
            if (t=="") continue
            nt++
            if (t=="*NOTAVL") nv=1
            if (t=="*AES_128_GCM_SHA256" || t=="*AES_256_GCM_SHA384" || t=="*CHACHA20_POLY1305_SHA256") { s++; d++; continue }
            if (t=="*ECDHE_ECDSA_AES_128_GCM_SHA256" || t=="*ECDHE_ECDSA_AES_256_GCM_SHA384") { s++; d++; continue }
            if (t=="*ECDHE_RSA_AES_128_GCM_SHA256" || t=="*ECDHE_RSA_AES_256_GCM_SHA384") { s++; d++; continue }
            if (t=="*ECDHE_ECDSA_CHACHA20_POLY1305_SHA256" || t=="*ECDHE_RSA_CHACHA20_POLY1305_SHA256") { s++; d++; continue }
            if (t=="*RSA_AES_128_GCM_SHA256" || t=="*RSA_AES_256_GCM_SHA384") { d++; continue }
            if (t=="*ECDHE_ECDSA_NULL_SHA" || t=="*ECDHE_ECDSA_RC4_128_SHA" || t=="*ECDHE_ECDSA_3DES_EDE_CBC_SHA") { d++; continue }
            if (t=="*ECDHE_RSA_NULL_SHA" || t=="*ECDHE_RSA_RC4_128_SHA" || t=="*ECDHE_RSA_3DES_EDE_CBC_SHA") { d++; continue }
            if (t=="*ECDHE_ECDSA_AES_128_CBC_SHA256" || t=="*ECDHE_ECDSA_AES_256_CBC_SHA384") { d++; continue }
            if (t=="*ECDHE_RSA_AES_128_CBC_SHA256" || t=="*ECDHE_RSA_AES_256_CBC_SHA384") { d++; continue }
            if (t=="*RSA_AES_128_CBC_SHA256" || t=="*RSA_AES_128_CBC_SHA" || t=="*RSA_AES_256_CBC_SHA256" || t=="*RSA_AES_256_CBC_SHA") { d++; continue }
            if (t=="*RSA_3DES_EDE_CBC_SHA" || t=="*RSA_RC4_128_SHA" || t=="*RSA_RC4_128_MD5" || t=="*RSA_DES_CBC_SHA") { d++; continue }
            if (t=="*RSA_EXPORT_RC2_CBC_40_MD5" || t=="*RSA_EXPORT_RC4_40_MD5" || t=="*RSA_NULL_SHA256" || t=="*RSA_NULL_SHA" || t=="*RSA_NULL_MD5") { d++; continue }
            if (t=="*RSA_RC2_CBC_128_MD5" || t=="*RSA_3DES_EDE_CBC_MD5" || t=="*RSA_DES_CBC_MD5") { d++; continue }
            j++
          }
        }
        END {
          if (nv) print "NOTAVL"
          else if (j || nt<1) print "BAD"
          else if (s==nt) print "PASS"
          else print "FAIL"
        }')
      if [ "$QCSL_TOK" = NOTAVL ]; then
        add security sv_qsslcsl "SSL cipher specification list" NOT_ASSESSED low \
            "not assessed — QSSLCSL=*NOTAVL (scan profile cannot read this system value)" \
            "The catalog returned *NOTAVL for QSSLCSL — the scan profile lacks authority to read this system value, so the value is not graded." \
            "grant the scan profile read access to QSSLCSL and re-take cap-system-values. Do not run this check as QSECOFR to paper over the gap." \
            "cis-l1"
      elif [ "$QCSL_TOK" = PASS ]; then
        add security sv_qsslcsl "SSL cipher specification list" PASS low \
            "QSSLCSL=$QCSL_VAL" \
            "QSSLCSL lists only AES-GCM and ChaCha20 System TLS cipher suites, so applications that use the default list cannot negotiate older suites." \
            "n/a" \
            "cis-l1"
      elif [ "$QCSL_TOK" = FAIL ]; then
        add security sv_qsslcsl "SSL cipher specification list" FAIL high \
            "QSSLCSL=$QCSL_VAL" \
            "QSSLCSL includes an older System TLS cipher suite (NULL, EXPORT, RC4, DES, 3DES, CBC, MD5, or RSA-only GCM), so applications that use the default list can negotiate a weak suite." \
            "set QSSLCSLCTL to *OPSYS so the system maintains QSSLCSL without older suites, using CHGSYSVAL SYSVAL(QSSLCSLCTL) VALUE('*OPSYS'). This scanner never changes system values." \
            "cis-l1"
      else
        add security sv_qsslcsl "SSL cipher specification list" NOT_ASSESSED low \
            "not assessed — QSSLCSL value unreadable" \
            "The QSSLCSL row was present, but the catalog value was not a documented cipher-suite token set or *NOTAVL, so it is not graded." \
            "inspect the QSSLCSL row in QSYS2.SYSTEM_VALUE_INFO and DSPSYSVAL SYSVAL(QSSLCSL)." \
            "cis-l1"
      fi
    fi
  fi

  # sv_qsslcslctl — IBM i QSSLCSLCTL (System TLS cipher control).
  # Authority: CIS IBM i V7R5M0/V7R4M0 5.1.1.36 (L1=*OPSYS).
  # No L2 rec. One finding. Parses the shared cap-system-values dump.
  # Does not call ibmi_sql. Does not CHGSYSVAL. *NOTAVL is a refusal,
  # never PASS. Exact *OPSYS is PASS. Exact *USRDFN (user-edited
  # QSSLCSL; new suites not added on upgrade) is FAIL.
  # live Phase 0 dump is QSSLCSLCTL||*OPSYS.
  if [ "${SYSVAL_OK:-0}" -ne 1 ]; then
    add security sv_qsslcslctl "SSL cipher control" NOT_ASSESSED low \
        "not assessed — ${SYSVAL_WHY:-capture unavailable}" \
        "The SYSTEM_VALUE_INFO capture did not yield a readable dump, so QSSLCSLCTL cannot be graded." \
        "re-run the scan as the scan profile and confirm QSYS2.SYSTEM_VALUE_INFO returns rows. This scanner never changes system values." \
        "cis-l1"
  else
    QCLC_LINE=$(printf '%s\n' "$SYSVAL_RAW" | awk -F'|' '$1=="QSSLCSLCTL"{n++; line=$0} END{if(n==1) print line}')
    QCLC_RC=$?
    if [ -z "$QCLC_LINE" ]; then
      add security sv_qsslcslctl "SSL cipher control" NOT_ASSESSED low \
          "not assessed — QSSLCSLCTL row missing or not unique in SYSTEM_VALUE_INFO" \
          "The system-value dump was readable, but it did not contain exactly one QSSLCSLCTL row, so the value cannot be graded." \
          "inspect QSYS2.SYSTEM_VALUE_INFO for SYSTEM_VALUE_NAME = QSSLCSLCTL." \
          "cis-l1"
    else
      QCLC_VAL=$(printf '%s\n' "$QCLC_LINE" | awk -F'|' '{ v=$3; if (v=="") v=$2; sub(/[ \t]+$/, "", v); print v }')
      if [ "$QCLC_VAL" = "*NOTAVL" ]; then
        add security sv_qsslcslctl "SSL cipher control" NOT_ASSESSED low \
            "not assessed — QSSLCSLCTL=*NOTAVL (scan profile cannot read this system value)" \
            "The catalog returned *NOTAVL for QSSLCSLCTL — the scan profile lacks authority to read this system value, so the value is not graded." \
            "grant the scan profile read access to QSSLCSLCTL and re-take cap-system-values. Do not run this check as QSECOFR to paper over the gap." \
            "cis-l1"
      elif [ -z "$QCLC_VAL" ]; then
        add security sv_qsslcslctl "SSL cipher control" NOT_ASSESSED low \
            "not assessed — QSSLCSLCTL value unreadable" \
            "The QSSLCSLCTL row was present, but the catalog value was empty, so it is not graded." \
            "inspect the QSSLCSLCTL row in QSYS2.SYSTEM_VALUE_INFO and DSPSYSVAL SYSVAL(QSSLCSLCTL)." \
            "cis-l1"
      elif [ "$QCLC_VAL" = "*OPSYS" ]; then
        add security sv_qsslcslctl "SSL cipher control" PASS low \
            "QSSLCSLCTL=*OPSYS" \
            "QSSLCSLCTL is *OPSYS, so the operating system maintains QSSLCSL and adds new System TLS cipher suites on a release upgrade." \
            "n/a" \
            "cis-l1"
      elif [ "$QCLC_VAL" = "*USRDFN" ]; then
        add security sv_qsslcslctl "SSL cipher control" FAIL high \
            "QSSLCSLCTL=*USRDFN" \
            "QSSLCSLCTL is *USRDFN, so QSSLCSL is user-edited and new System TLS cipher suites are not added automatically on a release upgrade." \
            "set QSSLCSLCTL to *OPSYS using CHGSYSVAL SYSVAL(QSSLCSLCTL) VALUE('*OPSYS'). This scanner never changes system values." \
            "cis-l1"
      else
        add security sv_qsslcslctl "SSL cipher control" NOT_ASSESSED low \
            "not assessed — QSSLCSLCTL value unreadable" \
            "The QSSLCSLCTL row was present, but the catalog value was not *OPSYS, *USRDFN, or *NOTAVL, so it is not graded." \
            "inspect the QSSLCSLCTL row in QSYS2.SYSTEM_VALUE_INFO and DSPSYSVAL SYSVAL(QSSLCSLCTL)." \
            "cis-l1"
      fi
    fi
  fi

  # sv_qsslpcl — IBM i QSSLPCL (System TLS protocol list).
  # Authority: CIS IBM i V7R5M0/V7R4M0 5.1.1.37 (L1=*OPSYS).
  # No L2 rec. One finding. Parses the shared cap-system-values dump.
  # Does not call ibmi_sql. Does not CHGSYSVAL. *NOTAVL is a refusal,
  # never PASS. Exact *OPSYS is PASS (live dump; IBM default; 7.4/7.5
  # expansion is TLS 1.3 + TLS 1.2). Non-empty subset of *TLSV1.3 /
  # *TLSV1.2 is PASS. Any documented older protocol (TLS 1.1, TLS 1.0,
  # SSL 3.0) is FAIL. live Phase 0 dump is QSSLPCL||*OPSYS.
  if [ "${SYSVAL_OK:-0}" -ne 1 ]; then
    add security sv_qsslpcl "SSL security protocols" NOT_ASSESSED low \
        "not assessed — ${SYSVAL_WHY:-capture unavailable}" \
        "The SYSTEM_VALUE_INFO capture did not yield a readable dump, so QSSLPCL cannot be graded." \
        "re-run the scan as the scan profile and confirm QSYS2.SYSTEM_VALUE_INFO returns rows. This scanner never changes system values." \
        "cis-l1"
  else
    QPCL_LINE=$(printf '%s\n' "$SYSVAL_RAW" | awk -F'|' '$1=="QSSLPCL"{n++; line=$0} END{if(n==1) print line}')
    QPCL_RC=$?
    if [ -z "$QPCL_LINE" ]; then
      add security sv_qsslpcl "SSL security protocols" NOT_ASSESSED low \
          "not assessed — QSSLPCL row missing or not unique in SYSTEM_VALUE_INFO" \
          "The system-value dump was readable, but it did not contain exactly one QSSLPCL row, so the value cannot be graded." \
          "inspect QSYS2.SYSTEM_VALUE_INFO for SYSTEM_VALUE_NAME = QSSLPCL." \
          "cis-l1"
    else
      QPCL_VAL=$(printf '%s\n' "$QPCL_LINE" | awk -F'|' '{ v=$3; if (v=="") v=$2; sub(/[ \t]+$/, "", v); print v }')
      QPCL_TOK=$(printf '%s\n' "$QPCL_VAL" | awk '
        {
          n=split($0, a, /[ \t]+/)
          for (i=1; i<=n; i++) {
            t=a[i]
            if (t=="") continue
            nt++
            if (t=="*NOTAVL") nv=1
            if (t=="*OPSYS") { op=1; continue }
            if (t=="*TLSV1.3" || t=="*TLSV1.2") { s++; d++; continue }
            if (t=="*TLSV1.1" || t=="*TLSV1" || t=="*SSLV3") { d++; continue }
            j++
          }
        }
        END {
          if (nv) print "NOTAVL"
          else if (j || nt<1) print "BAD"
          else if (op && nt==1) print "PASS"
          else if (op) print "BAD"
          else if (s==nt) print "PASS"
          else print "FAIL"
        }')
      if [ "$QPCL_TOK" = NOTAVL ]; then
        add security sv_qsslpcl "SSL security protocols" NOT_ASSESSED low \
            "not assessed — QSSLPCL=*NOTAVL (scan profile cannot read this system value)" \
            "The catalog returned *NOTAVL for QSSLPCL — the scan profile lacks authority to read this system value, so the value is not graded." \
            "grant the scan profile read access to QSSLPCL and re-take cap-system-values. Do not run this check as QSECOFR to paper over the gap." \
            "cis-l1"
      elif [ "$QPCL_TOK" = PASS ]; then
        add security sv_qsslpcl "SSL security protocols" PASS low \
            "QSSLPCL=$QPCL_VAL" \
            "QSSLPCL is *OPSYS, or lists only TLS 1.2 and TLS 1.3, so System TLS cannot negotiate TLS 1.1, TLS 1.0, or SSL 3.0." \
            "n/a" \
            "cis-l1"
      elif [ "$QPCL_TOK" = FAIL ]; then
        add security sv_qsslpcl "SSL security protocols" FAIL high \
            "QSSLPCL=$QPCL_VAL" \
            "QSSLPCL includes an older System TLS protocol (TLS 1.1, TLS 1.0, or SSL 3.0), so applications that use the default list can negotiate a weak protocol." \
            "set QSSLPCL to *OPSYS using CHGSYSVAL SYSVAL(QSSLPCL) VALUE('*OPSYS'). This scanner never changes system values." \
            "cis-l1"
      else
        add security sv_qsslpcl "SSL security protocols" NOT_ASSESSED low \
            "not assessed — QSSLPCL value unreadable" \
            "The QSSLPCL row was present, but the catalog value was not *OPSYS, a documented protocol-token set, or *NOTAVL, so it is not graded." \
            "inspect the QSSLPCL row in QSYS2.SYSTEM_VALUE_INFO and DSPSYSVAL SYSVAL(QSSLPCL)." \
            "cis-l1"
      fi
    fi
  fi

  # sv_qsyslibl — IBM i QSYSLIBL (system portion of the library list).
  # Authority: CIS IBM i V7R5M0/V7R4M0 5.1.1.38 (L1).
  # No L2 rec. One finding. Parses the shared cap-system-values dump.
  # Does not call ibmi_sql. Does not CHGSYSVAL. *NOTAVL is a refusal,
  # never PASS. Catalog encoding is concatenated CHAR(10) names.
  # QSYS plus only QSYS2 / QHLPSYS / QUSRSYS is PASS (live dump is
  # the IBM default four). Any extra valid library name is FAIL.
  # live Phase 0 dump is QSYSLIBL||QSYS      QSYS2     QHLPSYS   QUSRSYS
  if [ "${SYSVAL_OK:-0}" -ne 1 ]; then
    add security sv_qsyslibl "System library list" NOT_ASSESSED low \
        "not assessed — ${SYSVAL_WHY:-capture unavailable}" \
        "The SYSTEM_VALUE_INFO capture did not yield a readable dump, so QSYSLIBL cannot be graded." \
        "re-run the scan as the scan profile and confirm QSYS2.SYSTEM_VALUE_INFO returns rows. This scanner never changes system values." \
        "cis-l1"
  else
    QSL_LINE=$(printf '%s\n' "$SYSVAL_RAW" | awk -F'|' '$1=="QSYSLIBL"{n++; line=$0} END{if(n==1) print line}')
    QSL_RC=$?
    if [ -z "$QSL_LINE" ]; then
      add security sv_qsyslibl "System library list" NOT_ASSESSED low \
          "not assessed — QSYSLIBL row missing or not unique in SYSTEM_VALUE_INFO" \
          "The system-value dump was readable, but it did not contain exactly one QSYSLIBL row, so the value cannot be graded." \
          "inspect QSYS2.SYSTEM_VALUE_INFO for SYSTEM_VALUE_NAME = QSYSLIBL." \
          "cis-l1"
    else
      QSL_VAL=$(printf '%s\n' "$QSL_LINE" | awk -F'|' '{ v=$3; if (v=="") v=$2; sub(/[ \t]+$/, "", v); print v }')
      QSL_TOK=$(printf '%s\n' "$QSL_VAL" | awk '
        {
          sub(/[ \t]+$/, "", $0)
          while (length($0)>0 && length($0)%10!=0) $0=$0 " "
          n=length($0)/10
          for (i=0; i<n; i++) {
            t=substr($0, i*10+1, 10)
            sub(/[ \t]+$/, "", t)
            sub(/^[ \t]+/, "", t)
            if (t=="") continue
            nt++
            if (t=="*NOTAVL") nv=1
            if (t=="QSYS") qs=1
            if (t=="QSYS" || t=="QSYS2" || t=="QHLPSYS" || t=="QUSRSYS") continue
            if (t ~ /^[A-Z#@$][A-Z0-9#@$]*$/) x++
            else j++
          }
        }
        END {
          if (nv) print "NOTAVL"
          else if (j || nt<1) print "BAD"
          else if (x) print "FAIL"
          else if (qs) print "PASS"
          else print "BAD"
        }')
      if [ "$QSL_TOK" = NOTAVL ]; then
        add security sv_qsyslibl "System library list" NOT_ASSESSED low \
            "not assessed — QSYSLIBL=*NOTAVL (scan profile cannot read this system value)" \
            "The catalog returned *NOTAVL for QSYSLIBL — the scan profile lacks authority to read this system value, so the value is not graded." \
            "grant the scan profile read access to QSYSLIBL and re-take cap-system-values. Do not run this check as QSECOFR to paper over the gap." \
            "cis-l1"
      elif [ "$QSL_TOK" = PASS ]; then
        add security sv_qsyslibl "System library list" PASS low \
            "QSYSLIBL=$QSL_VAL" \
            "QSYSLIBL lists only IBM-supplied system libraries and includes QSYS, so the system portion of the library list does not search a user library before IBM libraries." \
            "n/a" \
            "cis-l1"
      elif [ "$QSL_TOK" = FAIL ]; then
        add security sv_qsyslibl "System library list" FAIL high \
            "QSYSLIBL=$QSL_VAL" \
            "QSYSLIBL includes a library other than QSYS, QSYS2, QHLPSYS, or QUSRSYS, so a non-system library is searched in the system portion of the library list and can hide IBM objects." \
            "set QSYSLIBL to QSYS QSYS2 QHLPSYS QUSRSYS using CHGSYSVAL SYSVAL(QSYSLIBL) VALUE('QSYS QSYS2 QHLPSYS QUSRSYS'). This scanner never changes system values." \
            "cis-l1"
      else
        add security sv_qsyslibl "System library list" NOT_ASSESSED low \
            "not assessed — QSYSLIBL value unreadable" \
            "The QSYSLIBL row was present, but the catalog value was not QSYS plus only QSYS2, QHLPSYS, and/or QUSRSYS, an extra library, or *NOTAVL, so it is not graded." \
            "inspect the QSYSLIBL row in QSYS2.SYSTEM_VALUE_INFO and DSPSYSVAL SYSVAL(QSYSLIBL)." \
            "cis-l1"
      fi
    fi
  fi

  # sv_quseadpaut — IBM i QUSEADPAUT (use adopted authority).
  # Authority: CIS IBM i V7R5M0/V7R4M0 5.1.1.39 (L1=authorization-list
  # name, not *NONE). No L2 rec.
  # One finding. Parses the shared cap-system-values dump. Does not call
  # ibmi_sql. Does not CHGSYSVAL. Does not CRTAUTL. *NOTAVL is a
  # refusal, never PASS. A simple IBM i list name is PASS (live dump
  # QUSEADPAUT, or any other legal name). Exact *NONE is FAIL.
  # live Phase 0 dump is QUSEADPAUT||QUSEADPAUT.
  if [ "${SYSVAL_OK:-0}" -ne 1 ]; then
    add security sv_quseadpaut "Use adopted authority" NOT_ASSESSED low \
        "not assessed — ${SYSVAL_WHY:-capture unavailable}" \
        "The SYSTEM_VALUE_INFO capture did not yield a readable dump, so QUSEADPAUT cannot be graded." \
        "re-run the scan as the scan profile and confirm QSYS2.SYSTEM_VALUE_INFO returns rows. This scanner never changes system values." \
        "cis-l1"
  else
    QADP_LINE=$(printf '%s\n' "$SYSVAL_RAW" | awk -F'|' '$1=="QUSEADPAUT"{n++; line=$0} END{if(n==1) print line}')
    QADP_RC=$?
    if [ -z "$QADP_LINE" ]; then
      add security sv_quseadpaut "Use adopted authority" NOT_ASSESSED low \
          "not assessed — QUSEADPAUT row missing or not unique in SYSTEM_VALUE_INFO" \
          "The system-value dump was readable, but it did not contain exactly one QUSEADPAUT row, so the value cannot be graded." \
          "inspect QSYS2.SYSTEM_VALUE_INFO for SYSTEM_VALUE_NAME = QUSEADPAUT." \
          "cis-l1"
    else
      QADP_VAL=$(printf '%s\n' "$QADP_LINE" | awk -F'|' '{ v=$3; if (v=="") v=$2; sub(/[ \t]+$/, "", v); print v }')
      QADP_TOK=$(printf '%s\n' "$QADP_VAL" | awk '
        $0=="*NOTAVL" { print "NOTAVL"; exit }
        $0=="" { print "BAD"; exit }
        $0=="*NONE" { print "FAIL"; exit }
        length($0)>=1 && length($0)<=10 && $0 ~ /^[A-Z$#@][A-Z0-9$#@_]*$/ { print "PASS"; exit }
        { print "BAD" }')
      if [ "$QADP_TOK" = NOTAVL ]; then
        add security sv_quseadpaut "Use adopted authority" NOT_ASSESSED low \
            "not assessed — QUSEADPAUT=*NOTAVL (scan profile cannot read this system value)" \
            "The catalog returned *NOTAVL for QUSEADPAUT — the scan profile lacks authority to read this system value, so the value is not graded." \
            "grant the scan profile read access to QUSEADPAUT and re-take cap-system-values. Do not run this check as QSECOFR to paper over the gap." \
            "cis-l1"
      elif [ "$QADP_TOK" = PASS ]; then
        add security sv_quseadpaut "Use adopted authority" PASS low \
            "QUSEADPAUT=$QADP_VAL" \
            "QUSEADPAUT names an authorization list, so only users with *USE to that list can create or change programs that use adopted authority from a calling program." \
            "n/a" \
            "cis-l1"
      elif [ "$QADP_TOK" = FAIL ]; then
        add security sv_quseadpaut "Use adopted authority" FAIL high \
            "QUSEADPAUT=*NONE" \
            "QUSEADPAUT is *NONE, so any user with authority to a program can create or change that program to use adopted authority from a calling program." \
            "set QUSEADPAUT to an authorization list name using CHGSYSVAL SYSVAL(QUSEADPAUT) VALUE('QUSEADPAUT'). Create the list first if it does not exist. This scanner never changes system values." \
            "cis-l1"
      else
        add security sv_quseadpaut "Use adopted authority" NOT_ASSESSED low \
            "not assessed — QUSEADPAUT value unreadable" \
            "The QUSEADPAUT row was present, but the catalog value was not *NONE, an authorization-list name, or *NOTAVL, so it is not graded." \
            "inspect the QUSEADPAUT row in QSYS2.SYSTEM_VALUE_INFO and DSPSYSVAL SYSVAL(QUSEADPAUT)." \
            "cis-l1"
      fi
    fi
  fi

  # sv_qvfyobjrst — IBM i QVFYOBJRST (verify object on restore).
  # Authority: CIS IBM i V7R5M0 5.1.1.40 (L1=3) and 5.1.2.25 (L2=5);
  # V7R4M0 L2 rec is 5.1.2.26. Grade L1. One finding. Parses the shared
  # cap-system-values dump. Does not call ibmi_sql. Does not CHGSYSVAL.
  # *NOTAVL is a refusal, never PASS.
  # Exact integer 3 or exact integer 5 is PASS (5 is stricter than L1).
  # Integer 1 (no verify), 2, or 4 is FAIL. 0 and 6+ are unreadable.
  # live Phase 0 dump is QVFYOBJRST||3 -> 3 (PASS). Do not treat >=3 as PASS.
  if [ "${SYSVAL_OK:-0}" -ne 1 ]; then
    add security sv_qvfyobjrst "Verify object on restore" NOT_ASSESSED low \
        "not assessed — ${SYSVAL_WHY:-capture unavailable}" \
        "The SYSTEM_VALUE_INFO capture did not yield a readable dump, so QVFYOBJRST cannot be graded." \
        "re-run the scan as the scan profile and confirm QSYS2.SYSTEM_VALUE_INFO returns rows. This scanner never changes system values." \
        "cis-l1 cis-l2"
  else
    QVFY_LINE=$(printf '%s\n' "$SYSVAL_RAW" | awk -F'|' '$1=="QVFYOBJRST"{n++; line=$0} END{if(n==1) print line}')
    QVFY_RC=$?
    if [ -z "$QVFY_LINE" ]; then
      add security sv_qvfyobjrst "Verify object on restore" NOT_ASSESSED low \
          "not assessed — QVFYOBJRST row missing or not unique in SYSTEM_VALUE_INFO" \
          "The system-value dump was readable, but it did not contain exactly one QVFYOBJRST row, so the value cannot be graded." \
          "inspect QSYS2.SYSTEM_VALUE_INFO for SYSTEM_VALUE_NAME = QVFYOBJRST." \
          "cis-l1 cis-l2"
    else
      QVFY_NUM=$(printf '%s\n' "$QVFY_LINE" | awk -F'|' '{print $2}')
      QVFY_CHR=$(printf '%s\n' "$QVFY_LINE" | awk -F'|' '{print $3}')
      if [ -n "$QVFY_NUM" ]; then
        QVFY_RAW=$QVFY_NUM
      else
        QVFY_RAW=$QVFY_CHR
      fi
      if [ "$QVFY_RAW" = "*NOTAVL" ]; then
        add security sv_qvfyobjrst "Verify object on restore" NOT_ASSESSED low \
            "not assessed — QVFYOBJRST=*NOTAVL (scan profile cannot read this system value)" \
            "The catalog returned *NOTAVL for QVFYOBJRST — the scan profile lacks authority to read this system value, so the value is not graded." \
            "grant the scan profile read access to QVFYOBJRST and re-take cap-system-values. Do not run this check as QSECOFR to paper over the gap." \
            "cis-l1 cis-l2"
      else
        QVFN=$(printf '%s\n' "$QVFY_RAW" | awk '/^[0-9]+$/{ if ($0 ~ /^0+$/) print 0; else { sub(/^0+/,""); print } }')
        if [ -z "$QVFN" ] || [ "$QVFN" -lt 1 ] || [ "$QVFN" -gt 5 ]; then
          add security sv_qvfyobjrst "Verify object on restore" NOT_ASSESSED low \
              "not assessed — QVFYOBJRST value unreadable" \
              "The QVFYOBJRST row was present, but the catalog value was not an integer 1-5 or *NOTAVL, so it is not graded." \
              "inspect the QVFYOBJRST row in QSYS2.SYSTEM_VALUE_INFO and DSPSYSVAL SYSVAL(QVFYOBJRST)." \
              "cis-l1 cis-l2"
        elif [ "$QVFN" -eq 3 ] || [ "$QVFN" -eq 5 ]; then
          add security sv_qvfyobjrst "Verify object on restore" PASS low \
              "QVFYOBJRST=$QVFN" \
              "QVFYOBJRST is 3 or 5, so signed objects restore only with valid signatures, and at 5 unsigned user-state objects are also blocked." \
              "n/a" \
              "cis-l1 cis-l2"
        else
          add security sv_qvfyobjrst "Verify object on restore" FAIL high \
              "QVFYOBJRST=$QVFN" \
              "QVFYOBJRST is not 3 or 5, so restore may skip signature verification or may restore objects whose signatures are not valid." \
              "set QVFYOBJRST to 3, or to 5, using CHGSYSVAL SYSVAL(QVFYOBJRST) VALUE('3'). This scanner never changes system values." \
              "cis-l1 cis-l2"
        fi
      fi
    fi
  fi

  # usr_action_auditing — IBM i *CMD action auditing on
  # administrative special-authority profiles.
  # Authority: CIS IBM i V7R5M0/V7R4M0 4.5 (L1=*CMD on every
  # in-scope profile; IBM-supplied Q* skipped except QSECOFR).
  # No L2 rec. One finding. Calls ibmi_sql for USER_INFO COUNT
  # plus SPECIAL_AUTHORITIES / USER_ACTION_AUDIT_LEVEL rows.
  # Does not call ibmi_cl / DSPUSRPRF / PRTUSRPRF / CHGUSRAUD.
  # Does not filter SPCAUT IS NOT NULL (that 0-row SELECT is
  # SQLCODE 100 and drops group-inherited administrators).
  # Cumulative SPCAUT from user + group + supplemental.
  # *CMD present (extras allowed) on every in-scope name is PASS.
  # Any in-scope name without *CMD is FAIL.
  # Probe note: VARCHAR(COUNT(*),10) is SQLSTATE 42815 on IBM i 7.5
  # (two-arg VARCHAR needs a string first arg); VARCHAR(COUNT(*)) is used.
  AA_RAW=$(ibmi_sql usrprf_action_audit "SELECT 'CNT' CONCAT '|' CONCAT VARCHAR(COUNT(*)) CONCAT '|' CONCAT '-' CONCAT '|' CONCAT '-' CONCAT '|' CONCAT '-' CONCAT '|' CONCAT '-' CONCAT '|' CONCAT '-' FROM QSYS2.USER_INFO UNION ALL SELECT 'USR' CONCAT '|' CONCAT VARCHAR(TRIM(AUTHORIZATION_NAME),10) CONCAT '|' CONCAT VARCHAR(COALESCE(SPECIAL_AUTHORITIES,'*NONE'),88) CONCAT '|' CONCAT VARCHAR(COALESCE(USER_ACTION_AUDIT_LEVEL,'*NONE'),363) CONCAT '|' CONCAT VARCHAR(COALESCE(OBJECT_AUDITING_VALUE,'*NONE'),10) CONCAT '|' CONCAT VARCHAR(TRIM(COALESCE(GROUP_PROFILE_NAME,'*NONE')),10) CONCAT '|' CONCAT VARCHAR(COALESCE(SUPPLEMENTAL_GROUP_LIST,'-'),150) FROM QSYS2.USER_INFO")
  AA_RC=$?
  if [ "$AA_RC" -ne 0 ]; then
    add security usr_action_auditing "User profile action auditing" NOT_ASSESSED low \
        "not assessed — capture failed (rc=$AA_RC)" \
        "The user-profile action-auditing probe did not yield a readable USER_INFO dump, so command auditing on administrative profiles cannot be graded." \
        "re-run the scan as the scan profile and confirm QSYS2.USER_INFO returns SPECIAL_AUTHORITIES and USER_ACTION_AUDIT_LEVEL. This scanner never changes user auditing." \
        "cis-l1"
  elif [ -z "$AA_RAW" ]; then
    add security usr_action_auditing "User profile action auditing" NOT_ASSESSED low \
        "not assessed — capture empty (rc=0)" \
        "The user-profile action-auditing probe returned no pipe row, so command auditing on administrative profiles cannot be graded." \
        "re-run the scan as the scan profile and confirm QSYS2.USER_INFO returns SPECIAL_AUTHORITIES and USER_ACTION_AUDIT_LEVEL. This scanner never changes user auditing." \
        "cis-l1"
  else
    AA_PARSE=$(printf '%s\n' "$AA_RAW" | awk -F'|' '
      function has_tok(s, tok,    t) {
        t = " " s " "
        gsub(/[ \t]+/, " ", t)
        return (index(t, " " tok " ") > 0)
      }
      function has_eight(s) {
        return has_tok(s, "*ALLOBJ") || has_tok(s, "*SAVSYS") || has_tok(s, "*JOBCTL") || has_tok(s, "*SECADM") || has_tok(s, "*SPLCTL") || has_tok(s, "*SERVICE") || has_tok(s, "*AUDIT") || has_tok(s, "*IOSYSCFG")
      }
      function skip_ibm(n) {
        return (substr(n, 1, 1) == "Q" && n != "QSECOFR")
      }
      $1=="CNT" {
        c=$2; sub(/[ \t]+$/, "", c)
        if (c !~ /^[0-9]+$/ || cntn) { junk=1; next }
        cntn=1
        cnt=c+0
        next
      }
      $1=="USR" {
        name=$2; sub(/[ \t]+$/, "", name)
        spc=$3
        aud=$4
        obj=$5; sub(/[ \t]+$/, "", obj)
        grp=$6; sub(/[ \t]+$/, "", grp)
        sup=$7
        if (name !~ /^[A-Z][A-Z0-9#$_]{0,9}$/) { junk=1; next }
        if (obj != "*ALL" && obj != "*CHANGE" && obj != "*NONE" && obj != "*NOTAVL") {
          junk=1
          next
        }
        if (name in seen) { junk=1; next }
        seen[name]=1
        spcaut[name]=spc
        audlvl[name]=aud
        objaud[name]=obj
        grpprf[name]=grp
        suplst[name]=sup
        n++
      }
      END {
        if (junk) { print "JUNK"; exit }
        if (!cntn) { print "NOCNT"; exit }
        if (!("QSECOFR" in seen)) { print "NOQSECOFR"; exit }
        if (!has_eight(spcaut["QSECOFR"])) { print "JUNK"; exit }
        for (u in seen) {
          if (skip_ibm(u)) continue
          cum = spcaut[u]
          g = grpprf[u]
          if (g != "" && g != "*NONE" && g != "-") {
            if (!(g in seen)) { print "NOGRP"; exit }
            cum = cum " " spcaut[g]
          }
          s = suplst[u]
          if (s != "" && s != "-") {
            slen = length (s)
            for (i = 1; i <= slen; i += 10) {
              chunk = substr(s, i, 10)
              sub(/[ \t]+$/, "", chunk)
              sub(/^[ \t]+/, "", chunk)
              if (chunk == "" || chunk == "-") continue
              if (!(chunk in seen)) { print "NOGRP"; exit }
              cum = cum " " spcaut[chunk]
            }
          }
          if (!has_eight(cum)) continue
          if (objaud[u] == "*NOTAVL") { print "NOTAVL"; exit }
          adm++
          if (has_tok(audlvl[u], "*CMD")) cmd++
          else miss++
        }
        printf "OK %d %d %d %d %d\n", cnt, n+0, adm+0, cmd+0, miss+0
      }')
    if [ "$AA_PARSE" = "JUNK" ]; then
      add security usr_action_auditing "User profile action auditing" NOT_ASSESSED low \
          "not assessed — USER_INFO value unreadable" \
          "The user-profile action-auditing dump was readable, but a row carried a profile name or OBJECT_AUDITING_VALUE token that could not be graded." \
          "inspect QSYS2.USER_INFO AUTHORIZATION_NAME, SPECIAL_AUTHORITIES, USER_ACTION_AUDIT_LEVEL, and OBJECT_AUDITING_VALUE." \
          "cis-l1"
    elif [ "$AA_PARSE" = "NOCNT" ]; then
      add security usr_action_auditing "User profile action auditing" NOT_ASSESSED low \
          "not assessed — USER_INFO count missing or not unique" \
          "The user-profile action-auditing dump was readable, but it did not contain exactly one profile-count row, so completeness cannot be graded." \
          "inspect QSYS2.USER_INFO COUNT of user profiles." \
          "cis-l1"
    elif [ "$AA_PARSE" = "NOQSECOFR" ]; then
      add security usr_action_auditing "User profile action auditing" NOT_ASSESSED low \
          "not assessed — QSECOFR missing from USER_INFO listing" \
          "The profile listing does not include QSECOFR, so command auditing on administrative profiles cannot be graded." \
          "grant the scan profile catalog listing of user profiles including QSECOFR and re-run. Do not run this check as QSECOFR to paper over the gap." \
          "cis-l1"
    elif [ "$AA_PARSE" = "NOGRP" ]; then
      add security usr_action_auditing "User profile action auditing" NOT_ASSESSED low \
          "not assessed — group profile missing from USER_INFO listing" \
          "A user profile names a group or supplemental group that is not in the dump, so cumulative special authorities cannot be graded." \
          "grant the scan profile catalog listing of group profiles and re-run. Do not run this check as QSECOFR to paper over the gap." \
          "cis-l1"
    elif [ "$AA_PARSE" = "NOTAVL" ]; then
      add security usr_action_auditing "User profile action auditing" NOT_ASSESSED low \
          "not assessed — USER_ACTION_AUDIT_LEVEL=*NOTAVL (scan profile lacks *AUDIT)" \
          "The scan profile cannot read USER_ACTION_AUDIT_LEVEL for an administrative profile. IBM returns OBJECT_AUDITING_VALUE=*NOTAVL when the job is not allowed to retrieve the audit values. That is not a configured value and is not a clean result." \
          "grant the scan profile *AUDIT (or the catalog authority to read USER_ACTION_AUDIT_LEVEL) and re-run. This scanner never grants authority and never changes user auditing." \
          "cis-l1"
    else
      AA_CNT=$(printf '%s\n' "$AA_PARSE" | awk '{ print $2 }')
      AA_ROWS=$(printf '%s\n' "$AA_PARSE" | awk '{ print $3 }')
      AA_N=$(printf '%s\n' "$AA_PARSE" | awk '{ print $4 }')
      AA_CMD=$(printf '%s\n' "$AA_PARSE" | awk '{ print $5 }')
      AA_MISS=$(printf '%s\n' "$AA_PARSE" | awk '{ print $6 }')
      if [ -z "$AA_CNT" ] || [ "$AA_CNT" -lt 4 ]; then
        add security usr_action_auditing "User profile action auditing" NOT_ASSESSED low \
            "not assessed — USER_INFO count too small to be a complete estate" \
            "The profile count is smaller than a supported IBM i ships, so command auditing on administrative profiles cannot be graded." \
            "grant the scan profile catalog listing of user profiles and re-run. Do not run this check as QSECOFR to paper over the gap." \
            "cis-l1"
      elif [ "$AA_ROWS" -ne "$AA_CNT" ]; then
        add security usr_action_auditing "User profile action auditing" NOT_ASSESSED low \
            "not assessed — USER_INFO listing incomplete" \
            "The profile count and the USER_INFO listing do not match, so command auditing on administrative profiles cannot be graded." \
            "grant the scan profile catalog listing of user profiles and re-run. Do not run this check as QSECOFR to paper over the gap." \
            "cis-l1"
      elif [ "$AA_MISS" -eq 0 ]; then
        add security usr_action_auditing "User profile action auditing" PASS low \
            "admins=$AA_N cmd=$AA_CMD missing=$AA_MISS" \
            "Every user profile with administrative special authority, other than IBM-supplied profiles except QSECOFR, has *CMD action auditing, so commands those administrators run are written to the security audit journal." \
            "n/a" \
            "cis-l1"
      else
        add security usr_action_auditing "User profile action auditing" FAIL high \
            "admins=$AA_N cmd=$AA_CMD missing=$AA_MISS" \
            "One or more user profiles with administrative special authority, other than IBM-supplied profiles except QSECOFR, do not have *CMD action auditing, so commands those administrators run are not written to the security audit journal." \
            "set action auditing to include *CMD on every user profile that has administrative special authority using CHGUSRAUD AUDLVL(*CMD). This scanner never changes user auditing." \
            "cis-l1"
      fi
    fi
  fi

  # usr_command_line_access — IBM i LIMIT_CAPABILITIES (LMTCPB).
  # Authority: CIS IBM i V7R5M0/V7R4M0 4.9 (L1=*YES on every
  # in-scope application user; IBM-supplied Q* skipped including
  # QSECOFR; administrators with special authorities skipped).
  # No L2 rec. One finding. Calls ibmi_sql for USER_INFO COUNT
  # plus STATUS / LIMIT_CAPABILITIES / compact-admin-flag rows.
  # Does not call ibmi_cl / DSPUSRPRF / PRTUSRPRF / CHGUSRPRF.
  # Does not filter LMTCPB <> *YES (that 0-row SELECT is SQLCODE
  # 100 on a compliant box). Does not skip *DISABLED (CIS 4.9
  # does not). *PARTIAL is not *YES. Compact admin flag (0/1/X)
  # so db2 wrap cannot drop SPECIAL_AUTHORITIES.
  # VARCHAR(COUNT(*)) not VARCHAR(COUNT(*),10): IBM i 7.5 is
  # SQLSTATE 42815 on the two-arg form with a numeric first arg.
  # Exact *YES on every in-scope name is PASS. Any in-scope
  # *NO or *PARTIAL is FAIL.
  CL_RAW=$(ibmi_sql usrprf_lmtcpb "SELECT 'CNT' CONCAT '|' CONCAT VARCHAR(COUNT(*)) CONCAT '|' CONCAT '-' CONCAT '|' CONCAT '-' CONCAT '|' CONCAT '-' FROM QSYS2.USER_INFO UNION ALL SELECT 'USR' CONCAT '|' CONCAT VARCHAR(TRIM(AUTHORIZATION_NAME),10) CONCAT '|' CONCAT VARCHAR(TRIM(COALESCE(STATUS,'*NONE')),10) CONCAT '|' CONCAT VARCHAR(TRIM(COALESCE(LIMIT_CAPABILITIES,'-')),10) CONCAT '|' CONCAT VARCHAR(CASE WHEN SPECIAL_AUTHORITIES IS NULL OR TRIM(SPECIAL_AUTHORITIES) = '' OR TRIM(SPECIAL_AUTHORITIES) = '*NONE' THEN '0' WHEN POSSTR(SPECIAL_AUTHORITIES, '*ALLOBJ') = 0 AND POSSTR(SPECIAL_AUTHORITIES, '*AUDIT') = 0 AND POSSTR(SPECIAL_AUTHORITIES, '*IOSYSCFG') = 0 AND POSSTR(SPECIAL_AUTHORITIES, '*JOBCTL') = 0 AND POSSTR(SPECIAL_AUTHORITIES, '*SAVSYS') = 0 AND POSSTR(SPECIAL_AUTHORITIES, '*SECADM') = 0 AND POSSTR(SPECIAL_AUTHORITIES, '*SERVICE') = 0 AND POSSTR(SPECIAL_AUTHORITIES, '*SPLCTL') = 0 THEN 'X' ELSE '1' END, 1) FROM QSYS2.USER_INFO")
  CL_RC=$?
  if [ "$CL_RC" -ne 0 ]; then
    add security usr_command_line_access "User profile command line access" NOT_ASSESSED low \
        "not assessed — capture failed (rc=$CL_RC)" \
        "The user-profile command-line-access probe did not yield a readable USER_INFO dump, so limit capabilities cannot be graded." \
        "re-run the scan as the scan profile and confirm QSYS2.USER_INFO returns LIMIT_CAPABILITIES. This scanner never changes user profiles." \
        "cis-l1"
  elif [ -z "$CL_RAW" ]; then
    add security usr_command_line_access "User profile command line access" NOT_ASSESSED low \
        "not assessed — capture empty (rc=0)" \
        "The user-profile command-line-access probe returned no pipe row, so limit capabilities cannot be graded." \
        "re-run the scan as the scan profile and confirm QSYS2.USER_INFO returns LIMIT_CAPABILITIES. This scanner never changes user profiles." \
        "cis-l1"
  else
    CL_PARSE=$(printf '%s\n' "$CL_RAW" | awk -F'|' '
      $1=="CNT" {
        c=$2; sub(/[ \t]+$/, "", c)
        if (c !~ /^[0-9]+$/ || cntn) { junk=1; next }
        cntn=1
        cnt=c+0
        next
      }
      $1=="USR" {
        name=$2; sub(/[ \t]+$/, "", name)
        st=$3; sub(/[ \t]+$/, "", st)
        lmt=$4; sub(/[ \t]+$/, "", lmt)
        adm=$5; sub(/[ \t]+$/, "", adm)
        if (name !~ /^[A-Z][A-Z0-9#$_]{0,9}$/) { junk=1; next }
        if (st != "*ENABLED" && st != "*DISABLED") { junk=1; next }
        if (lmt != "*YES" && lmt != "*NO" && lmt != "*PARTIAL" && lmt != "-") { junk=1; next }
        if (adm != "0" && adm != "1" && adm != "X") { junk=1; next }
        if (lmt == "-" || adm == "X") { junk=1; next }
        if (name in seen) {
          if (status[name] != st || lmtcpb[name] != lmt || admin[name] != adm) junk=1
          next
        }
        seen[name]=1
        status[name]=st
        lmtcpb[name]=lmt
        admin[name]=adm
        n++
      }
      END {
        if (junk) { print "JUNK"; exit }
        if (!cntn) { print "NOCNT"; exit }
        if (!("QSECOFR" in seen)) { print "NOQSECOFR"; exit }
        if (admin["QSECOFR"] != "1") { print "JUNK"; exit }
        for (u in seen) {
          if (substr(u, 1, 1) == "Q") continue
          if (admin[u] == "1") continue
          apps++
          f = lmtcpb[u]
          if (f == "*YES") yes++
          else open++
        }
        printf "OK %d %d %d %d %d\n", cnt, n+0, apps+0, yes+0, open+0
      }')
    if [ "$CL_PARSE" = "JUNK" ]; then
      add security usr_command_line_access "User profile command line access" NOT_ASSESSED low \
          "not assessed — USER_INFO value unreadable" \
          "The user-profile command-line-access dump was readable, but a row carried a profile name, STATUS, LIMIT_CAPABILITIES, or special-authority flag that could not be graded." \
          "inspect QSYS2.USER_INFO AUTHORIZATION_NAME, STATUS, LIMIT_CAPABILITIES, and SPECIAL_AUTHORITIES." \
          "cis-l1"
    elif [ "$CL_PARSE" = "NOCNT" ]; then
      add security usr_command_line_access "User profile command line access" NOT_ASSESSED low \
          "not assessed — USER_INFO count missing or not unique" \
          "The user-profile command-line-access dump was readable, but it did not contain exactly one profile-count row, so completeness cannot be graded." \
          "inspect QSYS2.USER_INFO COUNT of user profiles." \
          "cis-l1"
    elif [ "$CL_PARSE" = "NOQSECOFR" ]; then
      add security usr_command_line_access "User profile command line access" NOT_ASSESSED low \
          "not assessed — QSECOFR missing from USER_INFO listing" \
          "The profile listing does not include QSECOFR, so limit capabilities cannot be graded." \
          "grant the scan profile *ALLOBJ (CHGUSRPRF SPCAUT(*ALLOBJ)) so QSYS2.USER_INFO lists every user profile including QSECOFR, then re-run. Do not run this check as QSECOFR to paper over the gap." \
          "cis-l1"
    else
      CL_CNT=$(printf '%s\n' "$CL_PARSE" | awk '{ print $2 }')
      CL_ROWS=$(printf '%s\n' "$CL_PARSE" | awk '{ print $3 }')
      CL_N=$(printf '%s\n' "$CL_PARSE" | awk '{ print $4 }')
      CL_YES=$(printf '%s\n' "$CL_PARSE" | awk '{ print $5 }')
      CL_OPEN=$(printf '%s\n' "$CL_PARSE" | awk '{ print $6 }')
      if [ -z "$CL_CNT" ] || [ "$CL_CNT" -lt 4 ]; then
        add security usr_command_line_access "User profile command line access" NOT_ASSESSED low \
            "not assessed — USER_INFO count too small to be a complete estate" \
            "The profile count is smaller than a supported IBM i ships, so limit capabilities cannot be graded." \
            "grant the scan profile *ALLOBJ (CHGUSRPRF SPCAUT(*ALLOBJ)) so QSYS2.USER_INFO lists every user profile, then re-run. Do not run this check as QSECOFR to paper over the gap." \
            "cis-l1"
      elif [ "$CL_ROWS" -ne "$CL_CNT" ]; then
        add security usr_command_line_access "User profile command line access" NOT_ASSESSED low \
            "not assessed — USER_INFO listing incomplete" \
            "The profile count and the USER_INFO listing do not match, so limit capabilities cannot be graded." \
            "grant the scan profile *ALLOBJ (CHGUSRPRF SPCAUT(*ALLOBJ)) so QSYS2.USER_INFO lists every user profile, then re-run. Do not run this check as QSECOFR to paper over the gap." \
            "cis-l1"
      elif [ "$CL_OPEN" -eq 0 ]; then
        add security usr_command_line_access "User profile command line access" PASS low \
            "apps=$CL_N yes=$CL_YES open=$CL_OPEN" \
            "Every remaining application user profile, other than IBM-supplied profiles and administrators with special authorities, has limit capabilities *YES, so those users cannot run commands from a command line." \
            "n/a" \
            "cis-l1"
      else
        add security usr_command_line_access "User profile command line access" FAIL high \
            "apps=$CL_N yes=$CL_YES open=$CL_OPEN" \
            "One or more remaining application user profiles, other than IBM-supplied profiles and administrators with special authorities, have limit capabilities other than *YES, so those users can run commands from a command line." \
            "set limit capabilities to *YES on every remaining application user profile using CHGUSRPRF LMTCPB(*YES). This scanner never changes user profiles." \
            "cis-l1"
      fi
    fi
  fi

  # usr_default_passwords — IBM i USER_DEFAULT_PASSWORD (DFTPWD).
  # Authority: CIS IBM i V7R5M0/V7R4M0 4.6 (L1=every profile
  # DFTPWD=NO). No L2 rec. One finding. Calls ibmi_sql for
  # USER_INFO COUNT plus name / STATUS / DFTPWD rows.
  # Does not call ibmi_cl / ANZDFTPWD / DSPUSRPRF / CHGUSRPRF.
  # Does not filter DFTPWD = YES (that 0-row SELECT is SQLCODE
  # 100 on a compliant box). Does not skip Q* or *DISABLED
  # (CIS 4.6 does not). Does not read USER_INFO_BASIC (always
  # null DFTPWD). Does not grade PWDEXP or QPWDRULES.
  # Null DFTPWD (encoded -) is NOT_ASSESSED, never PASS.
  # Exact NO on every remaining name is PASS. Any YES is FAIL.
  DP_RAW=$(ibmi_sql usrprf_dftpwd "SELECT 'CNT' CONCAT '|' CONCAT VARCHAR(COUNT(*)) CONCAT '|' CONCAT '-' CONCAT '|' CONCAT '-' FROM QSYS2.USER_INFO UNION ALL SELECT 'USR' CONCAT '|' CONCAT VARCHAR(TRIM(AUTHORIZATION_NAME),10) CONCAT '|' CONCAT VARCHAR(TRIM(COALESCE(STATUS,'*NONE')),10) CONCAT '|' CONCAT VARCHAR(COALESCE(USER_DEFAULT_PASSWORD,'-'),3) FROM QSYS2.USER_INFO")
  DP_RC=$?
  if [ "$DP_RC" -ne 0 ]; then
    add security usr_default_passwords "User profile default passwords" NOT_ASSESSED low \
        "not assessed — capture failed (rc=$DP_RC)" \
        "The user-profile default-password probe did not yield a readable USER_INFO dump, so default passwords cannot be graded." \
        "re-run the scan as the scan profile and confirm QSYS2.USER_INFO returns USER_DEFAULT_PASSWORD. This scanner never changes passwords." \
        "cis-l1"
  elif [ -z "$DP_RAW" ]; then
    add security usr_default_passwords "User profile default passwords" NOT_ASSESSED low \
        "not assessed — capture empty (rc=0)" \
        "The user-profile default-password probe returned no pipe row, so default passwords cannot be graded." \
        "re-run the scan as the scan profile and confirm QSYS2.USER_INFO returns USER_DEFAULT_PASSWORD. This scanner never changes passwords." \
        "cis-l1"
  else
    DP_PARSE=$(printf '%s\n' "$DP_RAW" | awk -F'|' '
      $1=="CNT" {
        c=$2; sub(/[ \t]+$/, "", c)
        if (c !~ /^[0-9]+$/ || cntn) { junk=1; next }
        cntn=1
        cnt=c+0
        next
      }
      $1=="USR" {
        name=$2; sub(/[ \t]+$/, "", name)
        st=$3; sub(/[ \t]+$/, "", st)
        flag=$4; sub(/[ \t]+$/, "", flag)
        if (name !~ /^[A-Z][A-Z0-9#$_]{0,9}$/) { junk=1; next }
        if (st != "*ENABLED" && st != "*DISABLED") { junk=1; next }
        if (flag != "YES" && flag != "NO" && flag != "-") { junk=1; next }
        if (name in seen) {
          if (status[name] != st || dftpwd[name] != flag) junk=1
          next
        }
        seen[name]=1
        status[name]=st
        dftpwd[name]=flag
        n++
      }
      END {
        if (junk) { print "JUNK"; exit }
        if (!cntn) { print "NOCNT"; exit }
        if (!("QSECOFR" in seen)) { print "NOQSECOFR"; exit }
        for (u in seen) {
          f = dftpwd[u]
          if (f == "-") { print "NOTAVL"; exit }
          if (f == "YES") yes++
          else no++
        }
        printf "OK %d %d %d %d\n", cnt, n+0, yes+0, no+0
      }')
    if [ "$DP_PARSE" = "JUNK" ]; then
      add security usr_default_passwords "User profile default passwords" NOT_ASSESSED low \
          "not assessed — USER_INFO value unreadable" \
          "The user-profile default-password dump was readable, but a row carried a profile name, STATUS, or USER_DEFAULT_PASSWORD token that could not be graded." \
          "inspect QSYS2.USER_INFO AUTHORIZATION_NAME, STATUS, and USER_DEFAULT_PASSWORD." \
          "cis-l1"
    elif [ "$DP_PARSE" = "NOCNT" ]; then
      add security usr_default_passwords "User profile default passwords" NOT_ASSESSED low \
          "not assessed — USER_INFO count missing or not unique" \
          "The user-profile default-password dump was readable, but it did not contain exactly one profile-count row, so completeness cannot be graded." \
          "inspect QSYS2.USER_INFO COUNT of user profiles." \
          "cis-l1"
    elif [ "$DP_PARSE" = "NOQSECOFR" ]; then
      add security usr_default_passwords "User profile default passwords" NOT_ASSESSED low \
          "not assessed — QSECOFR missing from USER_INFO listing" \
          "The profile listing does not include QSECOFR, so default passwords cannot be graded." \
          "grant the scan profile catalog listing of user profiles including QSECOFR and re-run. Do not run this check as QSECOFR to paper over the gap." \
          "cis-l1"
    elif [ "$DP_PARSE" = "NOTAVL" ]; then
      add security usr_default_passwords "User profile default passwords" NOT_ASSESSED low \
          "not assessed — USER_DEFAULT_PASSWORD is null (scan profile lacks *ALLOBJ *SECADM)" \
          "The scan profile cannot read USER_DEFAULT_PASSWORD. IBM returns null for that column unless the job has *ALLOBJ and *SECADM. That is not a configured value and is not a clean result." \
          "grant the scan profile catalog authority to read USER_DEFAULT_PASSWORD and re-run. This scanner never grants *ALLOBJ and never changes passwords. Do not run this check as QSECOFR to paper over the gap." \
          "cis-l1"
    else
      DP_CNT=$(printf '%s\n' "$DP_PARSE" | awk '{ print $2 }')
      DP_N=$(printf '%s\n' "$DP_PARSE" | awk '{ print $3 }')
      DP_YES=$(printf '%s\n' "$DP_PARSE" | awk '{ print $4 }')
      DP_NO=$(printf '%s\n' "$DP_PARSE" | awk '{ print $5 }')
      if [ -z "$DP_CNT" ] || [ "$DP_CNT" -lt 4 ]; then
        add security usr_default_passwords "User profile default passwords" NOT_ASSESSED low \
            "not assessed — USER_INFO count too small to be a complete estate" \
            "The profile count is smaller than a supported IBM i ships, so default passwords cannot be graded." \
            "grant the scan profile catalog listing of user profiles and re-run. Do not run this check as QSECOFR to paper over the gap." \
            "cis-l1"
      elif [ "$DP_N" -ne "$DP_CNT" ]; then
        add security usr_default_passwords "User profile default passwords" NOT_ASSESSED low \
            "not assessed — USER_INFO listing incomplete" \
            "The profile count and the USER_INFO listing do not match, so default passwords cannot be graded." \
            "grant the scan profile catalog listing of user profiles and re-run. Do not run this check as QSECOFR to paper over the gap." \
            "cis-l1"
      elif [ "$DP_YES" -eq 0 ]; then
        add security usr_default_passwords "User profile default passwords" PASS low \
            "profiles=$DP_N yes=$DP_YES no=$DP_NO" \
            "Every user profile has a password that does not match the profile name, so a guessed profile name is not a working password." \
            "n/a" \
            "cis-l1"
      else
        add security usr_default_passwords "User profile default passwords" FAIL high \
            "profiles=$DP_N yes=$DP_YES no=$DP_NO" \
            "One or more user profiles have a password that matches the profile name, so that name is a working password." \
            "set a unique password that does not match the user profile name on every profile whose default-password flag is YES, using CHGUSRPRF PASSWORD(...) PWDEXP(*YES). This scanner never changes passwords." \
            "cis-l1"
      fi
    fi
  fi

  # usr_group_passwords — IBM i group profiles with a password.
  # Authority: CIS IBM i V7R5M0/V7R4M0 4.11 (L1=every group
  # that has members has NOPWD=YES / PASSWORD(*NONE)).
  # No L2 rec. One finding. Calls ibmi_sql for USER_INFO
  # COUNT plus name / NOPWD / GROUP_MEMBER_INDICATOR rows.
  # Does not call ibmi_cl / DSPUSRPRF / PRTUSRPRF / CHGUSRPRF.
  # Does not query GROUP_PROFILE_ENTRIES (GRPMBR=YES is the
  # GROUPLIST membership set). Does not filter NOPWD = NO
  # (that 0-row JOIN is SQLCODE 100 on a compliant box).
  # Does not skip Q* (CIS 4.11 does not). Does not use GID
  # (a GID with no members is not GROUPLIST). CAST COUNT —
  # VARCHAR(COUNT(*),10) is SQLSTATE 42815. Exact YES on
  # every in-scope name (including groups=0) is PASS. Any
  # in-scope NO is FAIL.
  GP_RAW=$(ibmi_sql usrprf_grppwd "SELECT 'CNT' CONCAT '|' CONCAT CAST(COUNT(*) AS VARCHAR(10)) CONCAT '|' CONCAT '-' CONCAT '|' CONCAT '-' FROM QSYS2.USER_INFO UNION ALL SELECT 'USR' CONCAT '|' CONCAT VARCHAR(TRIM(AUTHORIZATION_NAME),10) CONCAT '|' CONCAT VARCHAR(TRIM(COALESCE(NO_PASSWORD_INDICATOR,'-')),3) CONCAT '|' CONCAT VARCHAR(TRIM(COALESCE(GROUP_MEMBER_INDICATOR,'-')),3) FROM QSYS2.USER_INFO")
  GP_RC=$?
  if [ "$GP_RC" -ne 0 ]; then
    add security usr_group_passwords "Group profiles with passwords" NOT_ASSESSED low \
        "not assessed — capture failed (rc=$GP_RC)" \
        "The group-profile password probe did not yield a readable USER_INFO dump, so group profiles with a password cannot be graded." \
        "re-run the scan as the scan profile and confirm QSYS2.USER_INFO returns NO_PASSWORD_INDICATOR and GROUP_MEMBER_INDICATOR. This scanner never changes user profiles." \
        "cis-l1"
  elif [ -z "$GP_RAW" ]; then
    add security usr_group_passwords "Group profiles with passwords" NOT_ASSESSED low \
        "not assessed — capture empty (rc=0)" \
        "The group-profile password probe returned no pipe row, so group profiles with a password cannot be graded." \
        "re-run the scan as the scan profile and confirm QSYS2.USER_INFO returns NO_PASSWORD_INDICATOR and GROUP_MEMBER_INDICATOR. This scanner never changes user profiles." \
        "cis-l1"
  else
    GP_PARSE=$(printf '%s\n' "$GP_RAW" | awk -F'|' '
      $1=="CNT" {
        c=$2; sub(/[ \t]+$/, "", c)
        if (c !~ /^[0-9]+$/ || cntn) { junk=1; next }
        cntn=1
        cnt=c+0
        next
      }
      $1=="USR" {
        name=$2; sub(/[ \t]+$/, "", name)
        np=$3; sub(/[ \t]+$/, "", np)
        gm=$4; sub(/[ \t]+$/, "", gm)
        if (name !~ /^[A-Z][A-Z0-9#$_]{0,9}$/) { junk=1; next }
        if (np != "YES" && np != "NO") { junk=1; next }
        if (gm != "YES" && gm != "NO") { junk=1; next }
        if (name in seen) { junk=1; next }
        seen[name]=1
        nopwd[name]=np
        grpmbr[name]=gm
        n++
      }
      END {
        if (junk) { print "JUNK"; exit }
        if (!cntn) { print "NOCNT"; exit }
        if (!("QSECOFR" in seen)) { print "NOQSECOFR"; exit }
        for (u in seen) {
          if (grpmbr[u] != "YES") continue
          gn++
          if (nopwd[u] == "NO") bad++
          else ok++
        }
        printf "OK %d %d %d %d %d\n", cnt, n+0, gn+0, bad+0, ok+0
      }')
    if [ "$GP_PARSE" = "JUNK" ]; then
      add security usr_group_passwords "Group profiles with passwords" NOT_ASSESSED low \
          "not assessed — USER_INFO value unreadable" \
          "The group-profile password dump was readable, but a row carried a profile name, NO_PASSWORD_INDICATOR, or GROUP_MEMBER_INDICATOR token that could not be graded." \
          "inspect QSYS2.USER_INFO AUTHORIZATION_NAME, NO_PASSWORD_INDICATOR, and GROUP_MEMBER_INDICATOR." \
          "cis-l1"
    elif [ "$GP_PARSE" = "NOCNT" ]; then
      add security usr_group_passwords "Group profiles with passwords" NOT_ASSESSED low \
          "not assessed — USER_INFO count missing or not unique" \
          "The group-profile password dump was readable, but it did not contain exactly one profile-count row, so completeness cannot be graded." \
          "inspect QSYS2.USER_INFO COUNT of user profiles." \
          "cis-l1"
    elif [ "$GP_PARSE" = "NOQSECOFR" ]; then
      add security usr_group_passwords "Group profiles with passwords" NOT_ASSESSED low \
          "not assessed — QSECOFR missing from USER_INFO listing" \
          "The profile listing does not include QSECOFR, so group profiles with a password cannot be graded." \
          "grant the scan profile *OBJOPR and *READ on *USRPRF objects so QSYS2.USER_INFO lists every user profile including QSECOFR, then re-run. This scanner never changes user profiles." \
          "cis-l1"
    else
      GP_CNT=$(printf '%s\n' "$GP_PARSE" | awk '{ print $2 }')
      GP_ROWS=$(printf '%s\n' "$GP_PARSE" | awk '{ print $3 }')
      GP_N=$(printf '%s\n' "$GP_PARSE" | awk '{ print $4 }')
      GP_BAD=$(printf '%s\n' "$GP_PARSE" | awk '{ print $5 }')
      GP_OK=$(printf '%s\n' "$GP_PARSE" | awk '{ print $6 }')
      if [ -z "$GP_CNT" ] || [ "$GP_CNT" -lt 4 ]; then
        add security usr_group_passwords "Group profiles with passwords" NOT_ASSESSED low \
            "not assessed — USER_INFO count too small to be a complete estate" \
            "The profile count is smaller than a supported IBM i ships, so group profiles with a password cannot be graded." \
            "grant the scan profile *OBJOPR and *READ on *USRPRF objects so QSYS2.USER_INFO lists every user profile, then re-run. This scanner never changes user profiles." \
            "cis-l1"
      elif [ "$GP_ROWS" -ne "$GP_CNT" ]; then
        add security usr_group_passwords "Group profiles with passwords" NOT_ASSESSED low \
            "not assessed — USER_INFO listing incomplete" \
            "The profile count and the USER_INFO listing do not match, so group profiles with a password cannot be graded." \
            "grant the scan profile *OBJOPR and *READ on *USRPRF objects so QSYS2.USER_INFO lists every user profile, then re-run. This scanner never changes user profiles." \
            "cis-l1"
      elif [ "$GP_BAD" -eq 0 ]; then
        add security usr_group_passwords "Group profiles with passwords" PASS low \
            "groups=$GP_N pwd=$GP_BAD none=$GP_OK" \
            "Every remaining group profile that has members uses password *NONE, so a shared group profile cannot be used to sign on." \
            "n/a" \
            "cis-l1"
      else
        add security usr_group_passwords "Group profiles with passwords" FAIL high \
            "groups=$GP_N pwd=$GP_BAD none=$GP_OK" \
            "One or more remaining group profiles that have members have a password, so that shared group profile can be used to sign on." \
            "set PASSWORD(*NONE) on every group profile that has a password using CHGUSRPRF. This scanner never changes user profiles." \
            "cis-l1"
      fi
    fi
  fi

  # usr_ibm_supplied_profiles — IBM i Q* profiles vs IBM
  # shipped six (NOPWD / STATUS / USRCLS / INLPGM /
  # LMTCPB / SPCAUT) plus Q* used as groups.
  # Authority: CIS IBM i V7R5M0/V7R4M0 4.10 (L1=match
  # IBM shipped six; QBRMS QMQMADM QONDADM QRDARS400
  # QRDARSADM QWQADMIN may be groups). No L2 rec.
  # One finding. Calls ibmi_sql for USER_INFO COUNT
  # plus six-parameter rows plus GROUP_PROFILE_ENTRIES.
  # Does not call ibmi_cl / DSPUSRPRF / CHGUSRPRF /
  # QSYRESPA. Does not filter LIKE Q% (that 0-row
  # SELECT is SQLCODE 100 on a generic-only box).
  # QSECOFR STATUS is wildcard (sibling 6.1).
  # CAST(COUNT(*) AS VARCHAR(10)) not VARCHAR(COUNT(*),10).
  # Compact 8-bit SPCAUT so db2 wrap cannot drop it.
  # Zero drift and zero remaining groups is PASS.
  # Any drift or remaining Q* group is FAIL.
  IB_RAW=$(ibmi_sql usrprf_ibm "SELECT 'CNT' CONCAT '|' CONCAT CAST(COUNT(*) AS VARCHAR(10)) CONCAT '|' CONCAT '-' CONCAT '|' CONCAT '-' CONCAT '|' CONCAT '-' CONCAT '|' CONCAT '-' CONCAT '|' CONCAT '-' CONCAT '|' CONCAT '-' FROM QSYS2.USER_INFO UNION ALL SELECT 'USR' CONCAT '|' CONCAT VARCHAR(TRIM(AUTHORIZATION_NAME),10) CONCAT '|' CONCAT VARCHAR(TRIM(COALESCE(NO_PASSWORD_INDICATOR,'-')),3) CONCAT '|' CONCAT VARCHAR(TRIM(COALESCE(STATUS,'-')),10) CONCAT '|' CONCAT VARCHAR(TRIM(COALESCE(USER_CLASS_NAME,'-')),10) CONCAT '|' CONCAT VARCHAR(TRIM(COALESCE(INITIAL_PROGRAM_NAME,'*NONE')),10) CONCAT '|' CONCAT VARCHAR(TRIM(COALESCE(LIMIT_CAPABILITIES,'-')),10) CONCAT '|' CONCAT VARCHAR(CASE WHEN SPECIAL_AUTHORITIES IS NULL OR TRIM(SPECIAL_AUTHORITIES) = '' OR TRIM(SPECIAL_AUTHORITIES) = '*NONE' THEN '00000000' ELSE CASE WHEN POSSTR(SPECIAL_AUTHORITIES, '*ALLOBJ') = 0 THEN '0' ELSE '1' END CONCAT CASE WHEN POSSTR(SPECIAL_AUTHORITIES, '*AUDIT') = 0 THEN '0' ELSE '1' END CONCAT CASE WHEN POSSTR(SPECIAL_AUTHORITIES, '*IOSYSCFG') = 0 THEN '0' ELSE '1' END CONCAT CASE WHEN POSSTR(SPECIAL_AUTHORITIES, '*JOBCTL') = 0 THEN '0' ELSE '1' END CONCAT CASE WHEN POSSTR(SPECIAL_AUTHORITIES, '*SAVSYS') = 0 THEN '0' ELSE '1' END CONCAT CASE WHEN POSSTR(SPECIAL_AUTHORITIES, '*SECADM') = 0 THEN '0' ELSE '1' END CONCAT CASE WHEN POSSTR(SPECIAL_AUTHORITIES, '*SERVICE') = 0 THEN '0' ELSE '1' END CONCAT CASE WHEN POSSTR(SPECIAL_AUTHORITIES, '*SPLCTL') = 0 THEN '0' ELSE '1' END END, 8) FROM QSYS2.USER_INFO UNION ALL SELECT 'GRP' CONCAT '|' CONCAT VARCHAR(TRIM(GROUP_PROFILE_NAME),10) CONCAT '|' CONCAT VARCHAR(TRIM(USER_PROFILE_NAME),10) CONCAT '|' CONCAT '-' CONCAT '|' CONCAT '-' CONCAT '|' CONCAT '-' CONCAT '|' CONCAT '-' CONCAT '|' CONCAT '-' FROM QSYS2.GROUP_PROFILE_ENTRIES")
  IB_RC=$?
  if [ "$IB_RC" -ne 0 ]; then
    add security usr_ibm_supplied_profiles "IBM supplied user profiles" NOT_ASSESSED low \
        "not assessed — capture failed (rc=$IB_RC)" \
        "The IBM-supplied user-profile probe did not yield a readable USER_INFO dump, so IBM-supplied profile attributes cannot be graded." \
        "re-run the scan as the scan profile and confirm QSYS2.USER_INFO returns NO_PASSWORD_INDICATOR, STATUS, USER_CLASS_NAME, INITIAL_PROGRAM_NAME, LIMIT_CAPABILITIES, and SPECIAL_AUTHORITIES, and QSYS2.GROUP_PROFILE_ENTRIES returns group pairs. This scanner never changes user profiles." \
        "cis-l1"
  elif [ -z "$IB_RAW" ]; then
    add security usr_ibm_supplied_profiles "IBM supplied user profiles" NOT_ASSESSED low \
        "not assessed — capture empty (rc=0)" \
        "The IBM-supplied user-profile probe returned no pipe row, so IBM-supplied profile attributes cannot be graded." \
        "re-run the scan as the scan profile and confirm QSYS2.USER_INFO returns NO_PASSWORD_INDICATOR, STATUS, USER_CLASS_NAME, INITIAL_PROGRAM_NAME, LIMIT_CAPABILITIES, and SPECIAL_AUTHORITIES, and QSYS2.GROUP_PROFILE_ENTRIES returns group pairs. This scanner never changes user profiles." \
        "cis-l1"
  else
    IB_PARSE=$(printf '%s\n' "$IB_RAW" | awk -F'|' '
      function exp_of(n, e) {
        if (n == "QSECOFR") e = "NO|*|*SECOFR|*NONE|*NO|11111111"
        else if (n == "QSYS") e = "YES|*ENABLED|*SECOFR|*NONE|*NO|11111111"
        else if (n == "QADSM") e = "YES|*ENABLED|*SYSOPR|*NONE|*NO|00011000"
        else if (n == "QAFOWN") e = "YES|*ENABLED|*PGMR|*NONE|*NO|00010000"
        else if (n == "QAFDFTUSR") e = "YES|*ENABLED|*USER|QAFINLPG|*YES|00000000"
        else if (n == "QCLUMGT") e = "YES|*DISABLED|*USER|*NONE|*NO|00000000"
        else if (n == "QCLUSTER") e = "YES|*ENABLED|*USER|*NONE|*NO|00100000"
        else if (n == "QDIRSRV") e = "YES|*ENABLED|*USER|*NONE|*YES|00000000"
        else if (n == "QLPAUTO") e = "YES|*ENABLED|*SYSOPR|QLPINATO|*NO|10111100"
        else if (n == "QLPINSTALL") e = "YES|*ENABLED|*SYSOPR|*NONE|*NO|10111100"
        else if (n == "QMQM") e = "YES|*ENABLED|*SECADM|*NONE|*NO|00000000"
        else if (n == "QPGMR") e = "YES|*ENABLED|*PGMR|*NONE|*NO|x0011000"
        else if (n == "QPM400") e = "YES|*ENABLED|*USER|*NONE|*NO|00110000"
        else if (n == "QRDARS400") e = "YES|*ENABLED|*PGMR|*NONE|*NO|00111001"
        else if (n == "QRJE") e = "YES|*ENABLED|*PGMR|*NONE|*NO|x0011000"
        else if (n == "QSOC") e = "YES|*ENABLED|*SYSOPR|*NONE|*NO|00010000"
        else if (n == "QSRV") e = "YES|*ENABLED|*PGMR|*NONE|*NO|x0011010"
        else if (n == "QSRVAGT") e = "YES|*ENABLED|*SYSOPR|*NONE|*NO|x0111010"
        else if (n == "QSRVBAS") e = "YES|*ENABLED|*PGMR|*NONE|*NO|x0011000"
        else if (n == "QSVCCS") e = "YES|*ENABLED|*SYSOPR|*NONE|*NO|00010000"
        else if (n == "QSVSM") e = "YES|*DISABLED|*SYSOPR|*NONE|*NO|00010000"
        else if (n == "QSVSMSS") e = "YES|*DISABLED|*SYSOPR|*NONE|*NO|00010000"
        else if (n == "QSYSOPR") e = "YES|*ENABLED|*SYSOPR|*NONE|*NO|x0011000"
        else if (n == "QTCM") e = "YES|*DISABLED|*USER|*NONE|*NO|00000000"
        else if (n == "QTCP") e = "YES|*ENABLED|*SYSOPR|*NONE|*NO|00010000"
        return e
      }
      function spc_ok(got, ex, i, gc, ec) {
        if (got !~ /^[01]{8}$/ || ex !~ /^[0-9x]{8}$/) return 0
        for (i = 1; i <= 8; i++) {
          gc = substr(got, i, 1)
          ec = substr(ex, i, 1)
          if (ec == "x") {
            if (gc != "0" && gc != "1") return 0
          } else if (gc != ec) return 0
        }
        return 1
      }
      function tuple_ok(got, ex, gg, ge) {
        split(got, gg, "|")
        split(ex, ge, "|")
        if (gg[1] != ge[1]) return 0
        if (ge[2] != "*" && gg[2] != ge[2]) return 0
        if (gg[3] != ge[3]) return 0
        if (gg[4] != ge[4]) return 0
        if (gg[5] != ge[5]) return 0
        return spc_ok(gg[6], ge[6])
      }
      function skip_grp(n) {
        return (n == "QBRMS" || n == "QMQMADM" || n == "QONDADM" || n == "QRDARS400" || n == "QRDARSADM" || n == "QWQADMIN")
      }
      $1=="CNT" {
        c=$2; sub(/[ \t]+$/, "", c)
        if (c !~ /^[0-9]+$/ || cntn) { junk=1; next }
        cntn=1
        cnt=c+0
        next
      }
      $1=="USR" {
        name=$2; sub(/[ \t]+$/, "", name)
        np=$3; sub(/[ \t]+$/, "", np)
        st=$4; sub(/[ \t]+$/, "", st)
        uc=$5; sub(/[ \t]+$/, "", uc)
        ip=$6; sub(/[ \t]+$/, "", ip)
        lm=$7; sub(/[ \t]+$/, "", lm)
        sp=$8; sub(/[ \t]+$/, "", sp)
        if (name !~ /^[A-Z][A-Z0-9#$_]{0,9}$/) { junk=1; next }
        if (np != "YES" && np != "NO") { junk=1; next }
        if (st != "*ENABLED" && st != "*DISABLED") { junk=1; next }
        if (uc != "*USER" && uc != "*SYSOPR" && uc != "*PGMR" && uc != "*SECADM" && uc != "*SECOFR") { junk=1; next }
        if (ip == "" || ip == "-") { junk=1; next }
        if (lm != "*NO" && lm != "*YES" && lm != "*PARTIAL") { junk=1; next }
        if (sp !~ /^[01]{8}$/) { junk=1; next }
        got = np "|" st "|" uc "|" ip "|" lm "|" sp
        if (name in seen) {
          if (attr[name] != got) junk=1
          next
        }
        seen[name]=1
        attr[name]=got
        n++
        next
      }
      $1=="GRP" {
        g=$2; sub(/[ \t]+$/, "", g)
        u=$3; sub(/[ \t]+$/, "", u)
        if (g !~ /^[A-Z][A-Z0-9#$_]{0,9}$/) { junk=1; next }
        if (u !~ /^[A-Z][A-Z0-9#$_]{0,9}$/) { junk=1; next }
        pair = g " " u
        if (pair in gp) next
        gp[pair]=1
        if (substr(g, 1, 1) != "Q") next
        if (skip_grp(g)) next
        if (!(g in gseen)) {
          gseen[g]=1
          gcount++
        }
        next
      }
      END {
        if (junk) { print "JUNK"; exit }
        if (!cntn) { print "NOCNT"; exit }
        if (!("QSECOFR" in seen)) { print "NOQSECOFR"; exit }
        for (u in seen) {
          if (substr(u, 1, 1) != "Q") continue
          ex = exp_of(u)
          if (ex == "") continue
          ibm++
          if (!tuple_ok(attr[u], ex)) bad++
        }
        printf "OK %d %d %d %d %d\n", cnt, n+0, ibm+0, bad+0, gcount+0
      }')
    if [ "$IB_PARSE" = "JUNK" ]; then
      add security usr_ibm_supplied_profiles "IBM supplied user profiles" NOT_ASSESSED low \
          "not assessed — USER_INFO value unreadable" \
          "The IBM-supplied user-profile dump was readable, but a row carried a profile name, attribute token, special-authority flag, or group pair that could not be graded." \
          "inspect QSYS2.USER_INFO AUTHORIZATION_NAME, NO_PASSWORD_INDICATOR, STATUS, USER_CLASS_NAME, INITIAL_PROGRAM_NAME, LIMIT_CAPABILITIES, and SPECIAL_AUTHORITIES, and QSYS2.GROUP_PROFILE_ENTRIES." \
          "cis-l1"
    elif [ "$IB_PARSE" = "NOCNT" ]; then
      add security usr_ibm_supplied_profiles "IBM supplied user profiles" NOT_ASSESSED low \
          "not assessed — USER_INFO count missing or not unique" \
          "The IBM-supplied user-profile dump was readable, but it did not contain exactly one profile-count row, so completeness cannot be graded." \
          "inspect QSYS2.USER_INFO COUNT of user profiles." \
          "cis-l1"
    elif [ "$IB_PARSE" = "NOQSECOFR" ]; then
      add security usr_ibm_supplied_profiles "IBM supplied user profiles" NOT_ASSESSED low \
          "not assessed — QSECOFR missing from USER_INFO listing" \
          "The profile listing does not include QSECOFR, so IBM-supplied profile attributes cannot be graded." \
          "grant the scan profile *ALLOBJ (CHGUSRPRF SPCAUT(*ALLOBJ)) so QSYS2.USER_INFO lists every user profile including QSECOFR, then re-run. Do not run this check as QSECOFR to paper over the gap." \
          "cis-l1"
    else
      IB_CNT=$(printf '%s\n' "$IB_PARSE" | awk '{ print $2 }')
      IB_ROWS=$(printf '%s\n' "$IB_PARSE" | awk '{ print $3 }')
      IB_N=$(printf '%s\n' "$IB_PARSE" | awk '{ print $4 }')
      IB_BAD=$(printf '%s\n' "$IB_PARSE" | awk '{ print $5 }')
      IB_G=$(printf '%s\n' "$IB_PARSE" | awk '{ print $6 }')
      if [ -z "$IB_CNT" ] || [ "$IB_CNT" -lt 4 ]; then
        add security usr_ibm_supplied_profiles "IBM supplied user profiles" NOT_ASSESSED low \
            "not assessed — USER_INFO count too small to be a complete estate" \
            "The profile count is smaller than a supported IBM i ships, so IBM-supplied profile attributes cannot be graded." \
            "grant the scan profile *ALLOBJ (CHGUSRPRF SPCAUT(*ALLOBJ)) so QSYS2.USER_INFO lists every user profile, then re-run. Do not run this check as QSECOFR to paper over the gap." \
            "cis-l1"
      elif [ "$IB_ROWS" -ne "$IB_CNT" ]; then
        add security usr_ibm_supplied_profiles "IBM supplied user profiles" NOT_ASSESSED low \
            "not assessed — USER_INFO listing incomplete" \
            "The profile count and the USER_INFO listing do not match, so IBM-supplied profile attributes cannot be graded." \
            "grant the scan profile *ALLOBJ (CHGUSRPRF SPCAUT(*ALLOBJ)) so QSYS2.USER_INFO lists every user profile, then re-run. Do not run this check as QSECOFR to paper over the gap." \
            "cis-l1"
      elif [ "$IB_BAD" -eq 0 ] && [ "$IB_G" -eq 0 ]; then
        add security usr_ibm_supplied_profiles "IBM supplied user profiles" PASS low \
            "ibm=$IB_N drift=$IB_BAD groups=$IB_G" \
            "Every IBM-supplied user profile matches the IBM shipped values for password presence, status, user class, initial program, limit capabilities, and special authorities, and no IBM-supplied profile other than the documented group exceptions is used as a group profile, so those vendor accounts have not been rewritten as shop accounts." \
            "n/a" \
            "cis-l1"
      else
        add security usr_ibm_supplied_profiles "IBM supplied user profiles" FAIL high \
            "ibm=$IB_N drift=$IB_BAD groups=$IB_G" \
            "One or more IBM-supplied user profiles differ from the IBM shipped values for password presence, status, user class, initial program, limit capabilities, or special authorities, or an IBM-supplied profile other than the documented group exceptions is used as a group profile, so a vendor account can be used as a shop account." \
            "restore every IBM-supplied user profile to the IBM shipped values using CHGUSRPRF or the Reset Profile Attributes (QSYRESPA) API, and remove IBM-supplied group memberships other than the documented group exceptions using CHGUSRPRF GRPPRF and SUPGRPPRF. This scanner never changes user profiles." \
            "cis-l1"
      fi
    fi
  fi

  # usr_inactive_profiles — IBM i *ENABLED shop profiles
  # unused 90+ days (LAST_USED_TIMESTAMP / never-used
  # plus CREATION_TIMESTAMP).
  # Authority: CIS IBM i V7R5M0/V7R4M0 4.7 (L1=disable
  # inactive within 90 days; IBM-supplied Q* skipped).
  # No L2 rec. One finding. Calls ibmi_sql for USER_INFO
  # COUNT plus STATUS / last-used days / creation days.
  # Does not call ibmi_cl / DSPUSRPRF / ANZPRFACT /
  # CHGUSRPRF. Does not filter STATUS or LASTUSED in
  # the WHERE (that 0-row SELECT is SQLCODE 100 on a
  # compliant box). Does not read PREVIOUS_SIGNON
  # (CIS LASTUSED). 90-day lock, not CIS Controls 5.3
  # 45. Recently created unused is not inactive.
  # Zero remaining inactive enabled shop profiles is PASS.
  # Any remaining inactive enabled shop profile is FAIL.
  IN_RAW=$(ibmi_sql usrprf_inactive "SELECT 'CNT' CONCAT '|' CONCAT VARCHAR(COUNT(*)) CONCAT '|' CONCAT '-' CONCAT '|' CONCAT '-' CONCAT '|' CONCAT '-' FROM QSYS2.USER_INFO UNION ALL SELECT 'USR' CONCAT '|' CONCAT VARCHAR(TRIM(AUTHORIZATION_NAME),10) CONCAT '|' CONCAT VARCHAR(TRIM(COALESCE(STATUS,'-')),10) CONCAT '|' CONCAT VARCHAR(COALESCE(CHAR(DAYS(CURRENT_DATE) - DAYS(DATE(LAST_USED_TIMESTAMP))), '-'),11) CONCAT '|' CONCAT VARCHAR(COALESCE(CHAR(DAYS(CURRENT_DATE) - DAYS(DATE(CREATION_TIMESTAMP))), '-'),11) FROM QSYS2.USER_INFO")
  IN_RC=$?
  if [ "$IN_RC" -ne 0 ]; then
    add security usr_inactive_profiles "Inactive user profiles" NOT_ASSESSED low \
        "not assessed — capture failed (rc=$IN_RC)" \
        "The user-profile inactivity probe did not yield a readable USER_INFO dump, so dormant enabled profiles cannot be graded." \
        "re-run the scan as the scan profile and confirm QSYS2.USER_INFO returns STATUS, LAST_USED_TIMESTAMP, and CREATION_TIMESTAMP. This scanner never changes user profiles." \
        "cis-l1"
  elif [ -z "$IN_RAW" ]; then
    add security usr_inactive_profiles "Inactive user profiles" NOT_ASSESSED low \
        "not assessed — capture empty (rc=0)" \
        "The user-profile inactivity probe returned no pipe row, so dormant enabled profiles cannot be graded." \
        "re-run the scan as the scan profile and confirm QSYS2.USER_INFO returns STATUS, LAST_USED_TIMESTAMP, and CREATION_TIMESTAMP. This scanner never changes user profiles." \
        "cis-l1"
  else
    IN_PARSE=$(printf '%s\n' "$IN_RAW" | awk -F'|' '
      function skip_ibm(n) {
        return (substr(n, 1, 1) == "Q")
      }
      $1=="CNT" {
        c=$2; sub(/[ \t]+$/, "", c)
        if (c !~ /^[0-9]+$/ || cntn) { junk=1; next }
        cntn=1
        cnt=c+0
        next
      }
      $1=="USR" {
        name=$2; sub(/[ \t]+$/, "", name)
        st=$3; sub(/[ \t]+$/, "", st)
        lu=$4; sub(/[ \t]+$/, "", lu); sub(/^[ \t]+/, "", lu)
        cr=$5; sub(/[ \t]+$/, "", cr); sub(/^[ \t]+/, "", cr)
        if (name !~ /^[A-Z][A-Z0-9#$_]{0,9}$/) { junk=1; next }
        if (st != "*ENABLED" && st != "*DISABLED") { junk=1; next }
        if (lu != "-" && lu !~ /^-?[0-9]+$/) { junk=1; next }
        if (cr !~ /^[0-9]+$/) { junk=1; next }
        if (name in seen) { junk=1; next }
        seen[name]=1
        status[name]=st
        lastused[name]=lu
        created[name]=cr
        n++
      }
      END {
        if (junk) { print "JUNK"; exit }
        if (!cntn) { print "NOCNT"; exit }
        for (u in seen) {
          if (skip_ibm(u)) continue
          if (status[u] != "*ENABLED") continue
          en++
          crd = created[u]+0
          if (crd < 90) { ok++; continue }
          lu = lastused[u]
          if (lu == "-") { bad++; continue }
          lud = lu+0
          if (lud < 0) lud=0
          if (lud >= 90) bad++
          else ok++
        }
        printf "OK %d %d %d %d %d\n", cnt, n+0, en+0, ok+0, bad+0
      }')
    if [ "$IN_PARSE" = "JUNK" ]; then
      add security usr_inactive_profiles "Inactive user profiles" NOT_ASSESSED low \
          "not assessed — USER_INFO value unreadable" \
          "The user-profile inactivity dump was readable, but a row carried a profile name, STATUS, or date token that could not be graded." \
          "inspect QSYS2.USER_INFO AUTHORIZATION_NAME, STATUS, LAST_USED_TIMESTAMP, and CREATION_TIMESTAMP." \
          "cis-l1"
    elif [ "$IN_PARSE" = "NOCNT" ]; then
      add security usr_inactive_profiles "Inactive user profiles" NOT_ASSESSED low \
          "not assessed — USER_INFO count missing or not unique" \
          "The user-profile inactivity dump was readable, but it did not contain exactly one profile-count row, so completeness cannot be graded." \
          "inspect QSYS2.USER_INFO COUNT of user profiles." \
          "cis-l1"
    else
      IN_CNT=$(printf '%s\n' "$IN_PARSE" | awk '{ print $2 }')
      IN_ROWS=$(printf '%s\n' "$IN_PARSE" | awk '{ print $3 }')
      IN_N=$(printf '%s\n' "$IN_PARSE" | awk '{ print $4 }')
      IN_OK=$(printf '%s\n' "$IN_PARSE" | awk '{ print $5 }')
      IN_BAD=$(printf '%s\n' "$IN_PARSE" | awk '{ print $6 }')
      if [ -z "$IN_CNT" ] || [ "$IN_CNT" -lt 4 ]; then
        add security usr_inactive_profiles "Inactive user profiles" NOT_ASSESSED low \
            "not assessed — USER_INFO count too small to be a complete estate" \
            "The profile count is smaller than a supported IBM i ships, so dormant enabled profiles cannot be graded." \
            "grant the scan profile catalog listing of user profiles and re-run. Do not run this check as QSECOFR to paper over the gap." \
            "cis-l1"
      elif [ "$IN_ROWS" -ne "$IN_CNT" ]; then
        add security usr_inactive_profiles "Inactive user profiles" NOT_ASSESSED low \
            "not assessed — USER_INFO listing incomplete" \
            "The profile count and the USER_INFO listing do not match, so dormant enabled profiles cannot be graded." \
            "grant the scan profile catalog listing of user profiles and re-run. Do not run this check as QSECOFR to paper over the gap." \
            "cis-l1"
      elif [ "$IN_BAD" -eq 0 ]; then
        add security usr_inactive_profiles "Inactive user profiles" PASS low \
            "enabled=$IN_N recent=$IN_OK inactive=$IN_BAD" \
            "Every remaining enabled user profile, other than IBM-supplied profiles, has been used within 90 days or was created within 90 days, so no dormant enabled shop profile is left to sign on." \
            "n/a" \
            "cis-l1"
      else
        add security usr_inactive_profiles "Inactive user profiles" FAIL high \
            "enabled=$IN_N recent=$IN_OK inactive=$IN_BAD" \
            "One or more remaining enabled user profiles, other than IBM-supplied profiles, have not been used for 90 days or more and were created at least 90 days ago, so a dormant enabled shop profile can still sign on." \
            "set STATUS to *DISABLED on every remaining enabled user profile that has not been used for 90 days using CHGUSRPRF STATUS(*DISABLED). This scanner never changes user profiles." \
            "cis-l1"
      fi
    fi
  fi

  # usr_nonexpiring_passwords — IBM i per-profile PWDEXPITV
  # *NOMAX on profiles that have a password.
  # Authority: CIS IBM i V7R5M0/V7R4M0 4.8 (L1=*NOMAX only on
  # passworded profiles is FAIL; NOPWD=YES skipped; Q* not
  # skipped). No L2 rec. One finding. Calls ibmi_sql for
  # USER_INFO COUNT plus PASSWORD_EXPIRATION_INTERVAL /
  # NO_PASSWORD_INDICATOR rows. Does not call ibmi_cl /
  # DSPUSRPRF / PRTUSRPRF / CHGUSRPRF. Does not filter
  # PWDEXPITV = -1 (that 0-row SELECT is SQLCODE 100 on a
  # compliant box). CAST numerics — VARCHAR(COUNT(*),10) is
  # SQLSTATE 42815. Interval -1 on a passworded name is FAIL.
  # 0 or 1-366 on every passworded name is PASS.
  NX_RAW=$(ibmi_sql usrprf_pwdexpitv "SELECT 'CNT' CONCAT '|' CONCAT CAST(COUNT(*) AS VARCHAR(10)) CONCAT '|' CONCAT '-' CONCAT '|' CONCAT '-' FROM QSYS2.USER_INFO UNION ALL SELECT 'USR' CONCAT '|' CONCAT VARCHAR(TRIM(AUTHORIZATION_NAME),10) CONCAT '|' CONCAT CAST(COALESCE(PASSWORD_EXPIRATION_INTERVAL, 9999) AS VARCHAR(11)) CONCAT '|' CONCAT VARCHAR(TRIM(COALESCE(NO_PASSWORD_INDICATOR, '-')),3) FROM QSYS2.USER_INFO")
  NX_RC=$?
  if [ "$NX_RC" -ne 0 ]; then
    add security usr_nonexpiring_passwords "User profile non-expiring passwords" NOT_ASSESSED low \
        "not assessed — capture failed (rc=$NX_RC)" \
        "The user-profile non-expiring-password probe did not yield a readable USER_INFO dump, so password expiration intervals cannot be graded." \
        "re-run the scan as the scan profile and confirm QSYS2.USER_INFO returns PASSWORD_EXPIRATION_INTERVAL and NO_PASSWORD_INDICATOR. This scanner never changes user profiles." \
        "cis-l1"
  elif [ -z "$NX_RAW" ]; then
    add security usr_nonexpiring_passwords "User profile non-expiring passwords" NOT_ASSESSED low \
        "not assessed — capture empty (rc=0)" \
        "The user-profile non-expiring-password probe returned no pipe row, so password expiration intervals cannot be graded." \
        "re-run the scan as the scan profile and confirm QSYS2.USER_INFO returns PASSWORD_EXPIRATION_INTERVAL and NO_PASSWORD_INDICATOR. This scanner never changes user profiles." \
        "cis-l1"
  else
    NX_PARSE=$(printf '%s\n' "$NX_RAW" | awk -F'|' '
      $1=="CNT" {
        c=$2; sub(/[ \t]+$/, "", c)
        if (c !~ /^[0-9]+$/ || cntn) { junk=1; next }
        cntn=1
        cnt=c+0
        next
      }
      $1=="USR" {
        name=$2; sub(/[ \t]+$/, "", name)
        iv=$3; sub(/[ \t]+$/, "", iv)
        np=$4; sub(/[ \t]+$/, "", np)
        if (name !~ /^[A-Z][A-Z0-9#$_]{0,9}$/) { junk=1; next }
        if (iv !~ /^-?[0-9]+$/) { junk=1; next }
        nexp=iv+0
        if (nexp != -1 && nexp != 0 && (nexp < 1 || nexp > 366)) { junk=1; next }
        if (np != "YES" && np != "NO") { junk=1; next }
        if (name in seen) { junk=1; next }
        seen[name]=1
        interval[name]=nexp
        nopwd[name]=np
        n++
      }
      END {
        if (junk) { print "JUNK"; exit }
        if (!cntn) { print "NOCNT"; exit }
        if (!("QSECOFR" in seen)) { print "NOQSECOFR"; exit }
        if (nopwd["QSECOFR"] != "NO") { print "JUNK"; exit }
        for (u in seen) {
          if (nopwd[u] != "NO") continue
          pwdn++
          if (interval[u] == -1) nom++
          else ok++
        }
        printf "OK %d %d %d %d %d\n", cnt, n+0, pwdn+0, nom+0, ok+0
      }')
    if [ "$NX_PARSE" = "JUNK" ]; then
      add security usr_nonexpiring_passwords "User profile non-expiring passwords" NOT_ASSESSED low \
          "not assessed — USER_INFO value unreadable" \
          "The user-profile non-expiring-password dump was readable, but a row carried a profile name, PASSWORD_EXPIRATION_INTERVAL, or NO_PASSWORD_INDICATOR token that could not be graded." \
          "inspect QSYS2.USER_INFO AUTHORIZATION_NAME, PASSWORD_EXPIRATION_INTERVAL, and NO_PASSWORD_INDICATOR." \
          "cis-l1"
    elif [ "$NX_PARSE" = "NOCNT" ]; then
      add security usr_nonexpiring_passwords "User profile non-expiring passwords" NOT_ASSESSED low \
          "not assessed — USER_INFO count missing or not unique" \
          "The user-profile non-expiring-password dump was readable, but it did not contain exactly one profile-count row, so completeness cannot be graded." \
          "inspect QSYS2.USER_INFO COUNT of user profiles." \
          "cis-l1"
    elif [ "$NX_PARSE" = "NOQSECOFR" ]; then
      add security usr_nonexpiring_passwords "User profile non-expiring passwords" NOT_ASSESSED low \
          "not assessed — QSECOFR missing from USER_INFO listing" \
          "The profile listing does not include QSECOFR, so password expiration intervals cannot be graded." \
          "grant the scan profile catalog listing of user profiles including QSECOFR and re-run. Do not run this check as QSECOFR to paper over the gap." \
          "cis-l1"
    else
      NX_CNT=$(printf '%s\n' "$NX_PARSE" | awk '{ print $2 }')
      NX_ROWS=$(printf '%s\n' "$NX_PARSE" | awk '{ print $3 }')
      NX_N=$(printf '%s\n' "$NX_PARSE" | awk '{ print $4 }')
      NX_NOM=$(printf '%s\n' "$NX_PARSE" | awk '{ print $5 }')
      NX_OK=$(printf '%s\n' "$NX_PARSE" | awk '{ print $6 }')
      if [ -z "$NX_CNT" ] || [ "$NX_CNT" -lt 4 ]; then
        add security usr_nonexpiring_passwords "User profile non-expiring passwords" NOT_ASSESSED low \
            "not assessed — USER_INFO count too small to be a complete estate" \
            "The profile count is smaller than a supported IBM i ships, so password expiration intervals cannot be graded." \
            "grant the scan profile catalog listing of user profiles and re-run. Do not run this check as QSECOFR to paper over the gap." \
            "cis-l1"
      elif [ "$NX_ROWS" -ne "$NX_CNT" ]; then
        add security usr_nonexpiring_passwords "User profile non-expiring passwords" NOT_ASSESSED low \
            "not assessed — USER_INFO listing incomplete" \
            "The profile count and the USER_INFO listing do not match, so password expiration intervals cannot be graded." \
            "grant the scan profile catalog listing of user profiles and re-run. Do not run this check as QSECOFR to paper over the gap." \
            "cis-l1"
      elif [ "$NX_NOM" -eq 0 ]; then
        add security usr_nonexpiring_passwords "User profile non-expiring passwords" PASS low \
            "passworded=$NX_N nomax=$NX_NOM sysval_or_days=$NX_OK" \
            "Every user profile that has a password uses *SYSVAL or a day count for its password expiration interval, so those passwords cannot remain valid indefinitely." \
            "n/a" \
            "cis-l1"
      else
        add security usr_nonexpiring_passwords "User profile non-expiring passwords" FAIL high \
            "passworded=$NX_N nomax=$NX_NOM sysval_or_days=$NX_OK" \
            "One or more user profiles that have a password use *NOMAX for the password expiration interval, so those passwords never expire." \
            "set PWDEXPITV(*SYSVAL) on every user profile that has a password using CHGUSRPRF. This scanner never changes user profiles." \
            "cis-l1"
      fi
    fi
  fi

  # usr_ownership — IBM i object owner of *USRPRF objects.
  # Authority: CIS IBM i V7R5M0/V7R4M0 4.3 (L1=owner QSECOFR or
  # QSYS, plus QFAXMSF/QAUTPROF, QRDARS400*/QRDARS400,
  # QTIVOLI QTIVROOT QTIVUSER/QTIVOLI). No L2 rec.
  # One finding. Calls ibmi_sql for USER_INFO COUNT plus
  # OBJECT_PRIVILEGES *PUBLIC owner rows. Does not call ibmi_cl /
  # DSPOBJAUT / CHGOBJOWN. Does not filter OWNER NOT IN
  # (QSECOFR, QSYS) (that 0-row SELECT is SQLCODE 100 on a
  # compliant box). Does not read USER_INFO.OWNER (*USRPRF /
  # *GRPPRF creation default). Exact QSECOFR/QSYS or a frozen
  # extra-owner pair on every remaining name is PASS. Any
  # remaining other owner is FAIL.
  OW_RAW=$(ibmi_sql usrprf_owner "SELECT 'CNT' CONCAT '|' CONCAT VARCHAR(CHAR(COUNT(*)),10) CONCAT '|' CONCAT '-' FROM QSYS2.USER_INFO UNION ALL SELECT 'OWN' CONCAT '|' CONCAT VARCHAR(TRIM(SYSTEM_OBJECT_NAME),10) CONCAT '|' CONCAT VARCHAR(TRIM(OWNER),10) FROM QSYS2.OBJECT_PRIVILEGES WHERE SYSTEM_OBJECT_SCHEMA = 'QSYS' AND OBJECT_TYPE = '*USRPRF' AND AUTHORIZATION_NAME = '*PUBLIC'")
  OW_RC=$?
  if [ "$OW_RC" -ne 0 ]; then
    add security usr_ownership "User profile object ownership" NOT_ASSESSED low \
        "not assessed — capture failed (rc=$OW_RC)" \
        "The user-profile ownership probe did not yield a readable OBJECT_PRIVILEGES dump, so object ownership of user profiles cannot be graded." \
        "re-run the scan as the scan profile and confirm QSYS2.OBJECT_PRIVILEGES returns *PUBLIC owner rows for *USRPRF objects. This scanner never changes object ownership." \
        "cis-l1"
  elif [ -z "$OW_RAW" ]; then
    add security usr_ownership "User profile object ownership" NOT_ASSESSED low \
        "not assessed — capture empty (rc=0)" \
        "The user-profile ownership probe returned no pipe row, so object ownership of user profiles cannot be graded." \
        "re-run the scan as the scan profile and confirm QSYS2.OBJECT_PRIVILEGES returns *PUBLIC owner rows for *USRPRF objects. This scanner never changes object ownership." \
        "cis-l1"
  else
    OW_PARSE=$(printf '%s\n' "$OW_RAW" | awk -F'|' '
      $1=="CNT" {
        c=$2; sub(/[ \t]+$/, "", c)
        if (c !~ /^[0-9]+$/ || cntn) { junk=1; next }
        cntn=1
        cnt=c+0
        next
      }
      $1=="OWN" {
        name=$2; sub(/[ \t]+$/, "", name)
        own=$3; sub(/[ \t]+$/, "", own)
        if (name !~ /^[A-Z][A-Z0-9#$_]{0,9}$/) { junk=1; next }
        if (own !~ /^[A-Z][A-Z0-9#$_]{0,9}$/) { junk=1; next }
        if (seen[name] && owner[name] != own) { junk=1; next }
        if (seen[name]) next
        seen[name]=1
        owner[name]=own
        n++
        if (own == "QSECOFR" || own == "QSYS") ok++
        else if (name == "QFAXMSF" && own == "QAUTPROF") ex++
        else if (name ~ /^QRDARS400[A-Z0-9#$_]?$/ && own == "QRDARS400") ex++
        else if ((name == "QTIVOLI" || name == "QTIVROOT" || name == "QTIVUSER") && own == "QTIVOLI") ex++
        else bad++
      }
      END {
        if (junk) { print "JUNK"; exit }
        if (!cntn) { print "NOCNT"; exit }
        printf "OK %d %d %d %d %d\n", cnt, n+0, ok+0, ex+0, bad+0
      }')
    if [ "$OW_PARSE" = "JUNK" ]; then
      add security usr_ownership "User profile object ownership" NOT_ASSESSED low \
          "not assessed — OBJECT_PRIVILEGES value unreadable" \
          "The user-profile ownership dump was readable, but a row carried a profile name or OWNER token that could not be graded." \
          "inspect QSYS2.OBJECT_PRIVILEGES SYSTEM_OBJECT_NAME and OWNER for *USRPRF *PUBLIC rows." \
          "cis-l1"
    elif [ "$OW_PARSE" = "NOCNT" ]; then
      add security usr_ownership "User profile object ownership" NOT_ASSESSED low \
          "not assessed — USER_INFO count missing or not unique" \
          "The user-profile ownership dump was readable, but it did not contain exactly one profile-count row, so completeness cannot be graded." \
          "inspect QSYS2.USER_INFO COUNT of user profiles." \
          "cis-l1"
    else
      OW_CNT=$(printf '%s\n' "$OW_PARSE" | awk '{ print $2 }')
      OW_N=$(printf '%s\n' "$OW_PARSE" | awk '{ print $3 }')
      OW_OK=$(printf '%s\n' "$OW_PARSE" | awk '{ print $4 }')
      OW_EX=$(printf '%s\n' "$OW_PARSE" | awk '{ print $5 }')
      OW_BAD=$(printf '%s\n' "$OW_PARSE" | awk '{ print $6 }')
      if [ -z "$OW_CNT" ] || [ "$OW_CNT" -lt 4 ]; then
        add security usr_ownership "User profile object ownership" NOT_ASSESSED low \
            "not assessed — USER_INFO count too small to be a complete estate" \
            "The profile count is smaller than a supported IBM i ships, so object ownership of user profiles cannot be graded." \
            "grant the scan profile catalog listing of user profiles (OBJECT_PRIVILEGES *OBJMGT or QIBM_DB_SECADM and QIBM_LIST_ALL_OBJS_SQL) and re-run. Do not run this check as QSECOFR to paper over the gap." \
            "cis-l1"
      elif [ "$OW_N" -ne "$OW_CNT" ]; then
        add security usr_ownership "User profile object ownership" NOT_ASSESSED low \
            "not assessed — OBJECT_PRIVILEGES *PUBLIC listing incomplete" \
            "The profile count and the *PUBLIC *USRPRF listing do not match, so object ownership of user profiles cannot be graded." \
            "grant the scan profile catalog listing of *PUBLIC owner rows on *USRPRF objects and re-run. Do not run this check as QSECOFR to paper over the gap." \
            "cis-l1"
      elif [ "$OW_BAD" -eq 0 ]; then
        add security usr_ownership "User profile object ownership" PASS low \
            "profiles=$OW_N ok=$OW_OK exception=$OW_EX other=$OW_BAD" \
            "Every user profile is owned by QSECOFR or QSYS, or matches the IBM-shipped QFAXMSF, QRDARS400, or QTIVOLI ownership pairs, so a non-owner cannot swap into those profiles by owning them." \
            "n/a" \
            "cis-l1"
      else
        add security usr_ownership "User profile object ownership" FAIL high \
            "profiles=$OW_N ok=$OW_OK exception=$OW_EX other=$OW_BAD" \
            "One or more user profiles are owned by a profile other than QSECOFR, QSYS, or the IBM-shipped QFAXMSF, QRDARS400, or QTIVOLI pairs, so that owner can swap into those profiles without a password." \
            "set the owner of every user profile that is not an IBM-shipped extra-owner pair to QSECOFR using CHGOBJOWN OBJTYPE(*USRPRF) NEWOWN(QSECOFR) CUROWNAUT(*REVOKE). This scanner never changes object ownership." \
            "cis-l1"
      fi
    fi
  fi

  # usr_private_authority — IBM i private authority on *USRPRF objects.
  # Authority: CIS IBM i V7R5M0/V7R4M0 4.2 (L1=no private
  # authority other than owner, self, IBM pairs, and
  # group-member USER DEFINED without extra object rights).
  # No L2 rec. One finding. Calls ibmi_sql for USER_INFO COUNT,
  # OBJECT_PRIVILEGES *PUBLIC names plus private rows, and
  # GROUP_PROFILE_ENTRIES pairs. Does not call ibmi_cl /
  # DSPOBJAUT / RVKOBJAUT. Does not filter USERNAME IS NULL
  # or OBJEXIST CONCAT extra bits (those 0-row SELECTs are
  # SQLCODE 100 on a compliant box). Exact skip of remaining
  # private rows is PASS. Any remaining non-member private or
  # member extra / *USE / *CHANGE / *ALL / *AUTL is FAIL.
  PV_RAW=$(ibmi_sql usrprf_private "SELECT 'CNT' CONCAT '|' CONCAT VARCHAR(CHAR(COUNT(*)),10) CONCAT '|' CONCAT '-' CONCAT '|' CONCAT '-' CONCAT '|' CONCAT '-' CONCAT '|' CONCAT '-' FROM QSYS2.USER_INFO UNION ALL SELECT 'PUB' CONCAT '|' CONCAT VARCHAR(TRIM(SYSTEM_OBJECT_NAME),10) CONCAT '|' CONCAT '-' CONCAT '|' CONCAT '-' CONCAT '|' CONCAT '-' CONCAT '|' CONCAT '-' FROM QSYS2.OBJECT_PRIVILEGES WHERE SYSTEM_OBJECT_SCHEMA = 'QSYS' AND OBJECT_TYPE = '*USRPRF' AND AUTHORIZATION_NAME = '*PUBLIC' UNION ALL SELECT 'GRP' CONCAT '|' CONCAT VARCHAR(TRIM(GROUP_PROFILE_NAME),10) CONCAT '|' CONCAT VARCHAR(TRIM(USER_PROFILE_NAME),10) CONCAT '|' CONCAT '-' CONCAT '|' CONCAT '-' CONCAT '|' CONCAT '-' FROM QSYS2.GROUP_PROFILE_ENTRIES UNION ALL SELECT 'PRIV' CONCAT '|' CONCAT VARCHAR(TRIM(SYSTEM_OBJECT_NAME),10) CONCAT '|' CONCAT VARCHAR(TRIM(AUTHORIZATION_NAME),10) CONCAT '|' CONCAT VARCHAR(TRIM(OBJECT_AUTHORITY),12) CONCAT '|' CONCAT VARCHAR(TRIM(OBJECT_EXISTENCE),3) CONCAT '|' CONCAT VARCHAR(TRIM(OBJECT_ALTER),3) CONCAT '|' CONCAT VARCHAR(TRIM(OBJECT_REFERENCE),3) FROM QSYS2.OBJECT_PRIVILEGES WHERE SYSTEM_OBJECT_SCHEMA = 'QSYS' AND OBJECT_TYPE = '*USRPRF' AND AUTHORIZATION_NAME <> '*PUBLIC' AND TRIM(SYSTEM_OBJECT_NAME) <> TRIM(AUTHORIZATION_NAME) AND TRIM(AUTHORIZATION_NAME) <> TRIM(OWNER)")
  PV_RC=$?
  if [ "$PV_RC" -ne 0 ]; then
    add security usr_private_authority "User profile private authority" NOT_ASSESSED low \
        "not assessed — capture failed (rc=$PV_RC)" \
        "The user-profile private-authority probe did not yield a readable OBJECT_PRIVILEGES dump, so private authority on user profiles cannot be graded." \
        "re-run the scan as the scan profile and confirm QSYS2.OBJECT_PRIVILEGES and QSYS2.GROUP_PROFILE_ENTRIES return rows. This scanner never changes object authority." \
        "cis-l1"
  elif [ -z "$PV_RAW" ]; then
    add security usr_private_authority "User profile private authority" NOT_ASSESSED low \
        "not assessed — capture empty (rc=0)" \
        "The user-profile private-authority probe returned no pipe row, so private authority on user profiles cannot be graded." \
        "re-run the scan as the scan profile and confirm QSYS2.OBJECT_PRIVILEGES and QSYS2.GROUP_PROFILE_ENTRIES return rows. This scanner never changes object authority." \
        "cis-l1"
  else
    PV_PARSE=$(printf '%s\n' "$PV_RAW" | awk -F'|' '
      $1=="CNT" {
        c=$2; sub(/[ \t]+$/, "", c)
        if (c !~ /^[0-9]+$/ || cntn) { junk=1; next }
        cntn=1
        cnt=c+0
        next
      }
      $1=="PUB" {
        name=$2; sub(/[ \t]+$/, "", name)
        if (name !~ /^[A-Z][A-Z0-9#$_]{0,9}$/) { junk=1; next }
        if (!pub[name]) { pub[name]=1; n++ }
        next
      }
      $1=="GRP" {
        g=$2; sub(/[ \t]+$/, "", g)
        u=$3; sub(/[ \t]+$/, "", u)
        if (g !~ /^[A-Z][A-Z0-9#$_]{0,9}$/) { junk=1; next }
        if (u !~ /^[A-Z][A-Z0-9#$_]{0,9}$/) { junk=1; next }
        if (grp[g,u]) next
        grp[g,u]=1
        gr++
        next
      }
      $1=="PRIV" {
        obj=$2; sub(/[ \t]+$/, "", obj)
        usr=$3; sub(/[ \t]+$/, "", usr)
        auth=$4; sub(/[ \t]+$/, "", auth)
        exi=$5; sub(/[ \t]+$/, "", exi)
        alt=$6; sub(/[ \t]+$/, "", alt)
        ref=$7; sub(/[ \t]+$/, "", ref)
        if (obj !~ /^[A-Z][A-Z0-9#$_]{0,9}$/) { junk=1; next }
        if (usr !~ /^[A-Z][A-Z0-9#$_]{0,9}$/) { junk=1; next }
        if (auth != "*ALL" && auth != "*AUTL" && auth != "*CHANGE" && auth != "*EXCLUDE" && auth != "*USE" && auth != "USER DEFINED") {
          junk=1
          next
        }
        if (exi != "YES" && exi != "NO") { junk=1; next }
        if (alt != "YES" && alt != "NO") { junk=1; next }
        if (ref != "YES" && ref != "NO") { junk=1; next }
        key=obj SUBSEP usr
        bits=auth SUBSEP exi SUBSEP alt SUBSEP ref
        if (seen[key] && usage[key] != bits) { junk=1; next }
        if (seen[key]) next
        seen[key]=1
        usage[key]=bits
        if ((obj=="QGATE" && usr=="QSNADS") || (obj=="QMQM" && usr=="QMQMADM") || (obj=="QMSF" && usr=="QTCP") || (obj=="QSPLJOB" && usr=="QSPL") || (obj=="QTCP" && usr=="QMSF") || (obj=="QTMHHTTP" && usr=="QCLUSTER")) next
        if (grp[obj,usr]) {
          if (exi=="YES" || alt=="YES" || ref=="YES") { x++; next }
          if (auth=="USER DEFINED" || auth=="*EXCLUDE") next
          x++
          next
        }
        p++
      }
      END {
        if (junk) { print "JUNK"; exit }
        if (!cntn) { print "NOCNT"; exit }
        printf "OK %d %d %d %d %d\n", cnt, n+0, p+0, x+0, gr+0
      }')
    if [ "$PV_PARSE" = "JUNK" ]; then
      add security usr_private_authority "User profile private authority" NOT_ASSESSED low \
          "not assessed — OBJECT_PRIVILEGES value unreadable" \
          "The user-profile private-authority dump was readable, but a row carried a profile name, group pair, OBJECT_AUTHORITY token, or object-authority bit that could not be graded." \
          "inspect QSYS2.OBJECT_PRIVILEGES SYSTEM_OBJECT_NAME, AUTHORIZATION_NAME, OBJECT_AUTHORITY, OBJECT_EXISTENCE, OBJECT_ALTER, and OBJECT_REFERENCE for *USRPRF private rows." \
          "cis-l1"
    elif [ "$PV_PARSE" = "NOCNT" ]; then
      add security usr_private_authority "User profile private authority" NOT_ASSESSED low \
          "not assessed — USER_INFO count missing or not unique" \
          "The user-profile private-authority dump was readable, but it did not contain exactly one profile-count row, so completeness cannot be graded." \
          "inspect QSYS2.USER_INFO COUNT of user profiles." \
          "cis-l1"
    else
      PV_CNT=$(printf '%s\n' "$PV_PARSE" | awk '{ print $2 }')
      PV_N=$(printf '%s\n' "$PV_PARSE" | awk '{ print $3 }')
      PV_P=$(printf '%s\n' "$PV_PARSE" | awk '{ print $4 }')
      PV_X=$(printf '%s\n' "$PV_PARSE" | awk '{ print $5 }')
      PV_GR=$(printf '%s\n' "$PV_PARSE" | awk '{ print $6 }')
      if [ -z "$PV_CNT" ] || [ "$PV_CNT" -lt 4 ]; then
        add security usr_private_authority "User profile private authority" NOT_ASSESSED low \
            "not assessed — USER_INFO count too small to be a complete estate" \
            "The profile count is smaller than a supported IBM i ships, so private authority on user profiles cannot be graded." \
            "grant the scan profile catalog listing of user profiles (OBJECT_PRIVILEGES *OBJMGT or QIBM_DB_SECADM and QIBM_LIST_ALL_OBJS_SQL) and re-run. Do not run this check as QSECOFR to paper over the gap." \
            "cis-l1"
      elif [ "$PV_N" -ne "$PV_CNT" ]; then
        add security usr_private_authority "User profile private authority" NOT_ASSESSED low \
            "not assessed — OBJECT_PRIVILEGES *PUBLIC listing incomplete" \
            "The profile count and the *PUBLIC *USRPRF listing do not match, so private authority on user profiles cannot be graded." \
            "grant the scan profile catalog listing of *PUBLIC authority on *USRPRF objects and re-run. Do not run this check as QSECOFR to paper over the gap." \
            "cis-l1"
      elif [ "$PV_P" -eq 0 ] && [ "$PV_X" -eq 0 ]; then
        add security usr_private_authority "User profile private authority" PASS low \
            "profiles=$PV_N private=$PV_P extra=$PV_X groups=$PV_GR" \
            "No user profile grants a private authority other than the owner, the profile itself, the IBM-shipped pairs, or group-member USER DEFINED authority without extra object rights, so an authenticated user cannot swap to those profiles without a password." \
            "n/a" \
            "cis-l1"
      else
        add security usr_private_authority "User profile private authority" FAIL high \
            "profiles=$PV_N private=$PV_P extra=$PV_X groups=$PV_GR" \
            "One or more user profiles grant a private authority other than the owner, the profile itself, the IBM-shipped pairs, or group-member USER DEFINED authority without extra object rights, so an authenticated user can swap to those profiles without a password." \
            "remove private authority on every user profile other than the owner, the profile itself, the IBM-shipped pairs, and group-member USER DEFINED using RVKOBJAUT OBJTYPE(*USRPRF) AUT(*ALL). This scanner never changes object authority." \
            "cis-l1"
      fi
    fi
  fi

  # usr_public_authority — IBM i *PUBLIC authority on *USRPRF objects.
  # Authority: CIS IBM i V7R5M0/V7R4M0 4.1 (L1=*PUBLIC *EXCLUDE
  # on every *USRPRF other than QDBSHR, QDBSHRDO, QTMPLPD). No L2 rec.
  # One finding. Calls ibmi_sql for USER_INFO COUNT plus
  # OBJECT_PRIVILEGES *PUBLIC rows. Does not call ibmi_cl /
  # DSPOBJAUT / GRTOBJAUT. Does not filter OBJ_AUTH <> *EXCLUDE
  # (that 0-row SELECT is SQLCODE 100 on a compliant box).
  # Exact *EXCLUDE on every remaining name is PASS.
  # Any remaining *USE / *CHANGE / *ALL / *AUTL / USER DEFINED is FAIL.
  # VARCHAR(COUNT(*),10) is SQLSTATE 42815 on live IBM i (two-arg VARCHAR
  # character form needs a character string); CHAR(COUNT(*)) keeps the same
  # COUNT(*) value and the locked pipe shape. Probed on the 7.5 lab.
  PA_RAW=$(ibmi_sql usrprf_public "SELECT 'CNT' CONCAT '|' CONCAT VARCHAR(CHAR(COUNT(*)),10) CONCAT '|' CONCAT '-' FROM QSYS2.USER_INFO WHERE AUTHORIZATION_NAME NOT IN ('QDBSHR','QDBSHRDO','QTMPLPD') UNION ALL SELECT 'PUB' CONCAT '|' CONCAT VARCHAR(TRIM(SYSTEM_OBJECT_NAME),10) CONCAT '|' CONCAT VARCHAR(TRIM(OBJECT_AUTHORITY),12) FROM QSYS2.OBJECT_PRIVILEGES WHERE SYSTEM_OBJECT_SCHEMA = 'QSYS' AND OBJECT_TYPE = '*USRPRF' AND AUTHORIZATION_NAME = '*PUBLIC' AND SYSTEM_OBJECT_NAME NOT IN ('QDBSHR','QDBSHRDO','QTMPLPD')")
  PA_RC=$?
  if [ "$PA_RC" -ne 0 ]; then
    add security usr_public_authority "User profile public authority" NOT_ASSESSED low \
        "not assessed — capture failed (rc=$PA_RC)" \
        "The user-profile public-authority probe did not yield a readable OBJECT_PRIVILEGES dump, so *PUBLIC authority on user profiles cannot be graded." \
        "re-run the scan as the scan profile and confirm QSYS2.OBJECT_PRIVILEGES returns *PUBLIC rows for *USRPRF objects. This scanner never changes object authority." \
        "cis-l1"
  elif [ -z "$PA_RAW" ]; then
    add security usr_public_authority "User profile public authority" NOT_ASSESSED low \
        "not assessed — capture empty (rc=0)" \
        "The user-profile public-authority probe returned no pipe row, so *PUBLIC authority on user profiles cannot be graded." \
        "re-run the scan as the scan profile and confirm QSYS2.OBJECT_PRIVILEGES returns *PUBLIC rows for *USRPRF objects. This scanner never changes object authority." \
        "cis-l1"
  else
    PA_PARSE=$(printf '%s\n' "$PA_RAW" | awk -F'|' '
      $1=="CNT" {
        c=$2; sub(/[ \t]+$/, "", c)
        if (c !~ /^[0-9]+$/ || cntn) { junk=1; next }
        cntn=1
        cnt=c+0
        next
      }
      $1=="PUB" {
        name=$2; sub(/[ \t]+$/, "", name)
        auth=$3; sub(/[ \t]+$/, "", auth)
        if (name=="QDBSHR" || name=="QDBSHRDO" || name=="QTMPLPD") next
        if (name !~ /^[A-Z][A-Z0-9#$_]{0,9}$/) { junk=1; next }
        if (auth != "*ALL" && auth != "*AUTL" && auth != "*CHANGE" && auth != "*EXCLUDE" && auth != "*USE" && auth != "USER DEFINED") {
          junk=1
          next
        }
        if (seen[name] && usage[name] != auth) { junk=1; next }
        if (seen[name]) next
        seen[name]=1
        usage[name]=auth
        n++
        if (auth == "*EXCLUDE") ex++
        else oth++
      }
      END {
        if (junk) { print "JUNK"; exit }
        if (!cntn) { print "NOCNT"; exit }
        printf "OK %d %d %d %d\n", cnt, n+0, ex+0, oth+0
      }')
    if [ "$PA_PARSE" = "JUNK" ]; then
      add security usr_public_authority "User profile public authority" NOT_ASSESSED low \
          "not assessed — OBJECT_PRIVILEGES value unreadable" \
          "The user-profile public-authority dump was readable, but a row carried a profile name or OBJECT_AUTHORITY token that could not be graded." \
          "inspect QSYS2.OBJECT_PRIVILEGES SYSTEM_OBJECT_NAME and OBJECT_AUTHORITY for *USRPRF *PUBLIC rows." \
          "cis-l1"
    elif [ "$PA_PARSE" = "NOCNT" ]; then
      add security usr_public_authority "User profile public authority" NOT_ASSESSED low \
          "not assessed — USER_INFO count missing or not unique" \
          "The user-profile public-authority dump was readable, but it did not contain exactly one profile-count row, so completeness cannot be graded." \
          "inspect QSYS2.USER_INFO COUNT of user profiles." \
          "cis-l1"
    else
      PA_CNT=$(printf '%s\n' "$PA_PARSE" | awk '{ print $2 }')
      PA_N=$(printf '%s\n' "$PA_PARSE" | awk '{ print $3 }')
      PA_EX=$(printf '%s\n' "$PA_PARSE" | awk '{ print $4 }')
      PA_OTH=$(printf '%s\n' "$PA_PARSE" | awk '{ print $5 }')
      if [ -z "$PA_CNT" ] || [ "$PA_CNT" -lt 4 ]; then
        add security usr_public_authority "User profile public authority" NOT_ASSESSED low \
            "not assessed — USER_INFO count too small to be a complete estate" \
            "The profile count is smaller than a supported IBM i ships, so *PUBLIC authority on user profiles cannot be graded." \
            "grant the scan profile catalog listing of user profiles (OBJECT_PRIVILEGES *OBJMGT or QIBM_DB_SECADM and QIBM_LIST_ALL_OBJS_SQL) and re-run. Do not run this check as QSECOFR to paper over the gap." \
            "cis-l1"
      elif [ "$PA_N" -ne "$PA_CNT" ]; then
        add security usr_public_authority "User profile public authority" NOT_ASSESSED low \
            "not assessed — OBJECT_PRIVILEGES *PUBLIC listing incomplete" \
            "The profile count and the *PUBLIC *USRPRF listing do not match, so *PUBLIC authority on user profiles cannot be graded." \
            "grant the scan profile catalog listing of *PUBLIC authority on *USRPRF objects and re-run. Do not run this check as QSECOFR to paper over the gap." \
            "cis-l1"
      elif [ "$PA_OTH" -eq 0 ]; then
        add security usr_public_authority "User profile public authority" PASS low \
            "profiles=$PA_N exclude=$PA_EX other=$PA_OTH" \
            "Every user profile other than QDBSHR, QDBSHRDO, and QTMPLPD has *PUBLIC authority *EXCLUDE, so an authenticated user cannot swap to those profiles without a password." \
            "n/a" \
            "cis-l1"
      else
        add security usr_public_authority "User profile public authority" FAIL high \
            "profiles=$PA_N exclude=$PA_EX other=$PA_OTH" \
            "One or more user profiles other than QDBSHR, QDBSHRDO, and QTMPLPD grant *PUBLIC authority other than *EXCLUDE, so an authenticated user can swap to those profiles without a password." \
            "set *PUBLIC authority to *EXCLUDE on every user profile other than QDBSHR, QDBSHRDO, and QTMPLPD using GRTOBJAUT OBJTYPE(*USRPRF) USER(*PUBLIC) AUT(*EXCLUDE). This scanner never changes object authority." \
            "cis-l1"
      fi
    fi
  fi

  # usr_qsecofr_disabled — IBM i QSECOFR STATUS.
  # Authority: CIS IBM i V7R5M0/V7R4M0 6.1 (L1=QSECOFR
  # STATUS=*DISABLED). No L2 rec. One finding. Calls
  # ibmi_sql for USER_INFO COUNT of QSECOFR plus the
  # name / STATUS row. Does not call ibmi_cl /
  # DSPUSRPRF / CHGUSRPRF. Does not filter
  # STATUS=*DISABLED (that 0-row SELECT is SQLCODE
  # 100 on an enabled QSECOFR). Name filter
  # AUTHORIZATION_NAME=QSECOFR is the DSPUSRPRF
  # equivalent, not the grade predicate. Does not
  # list the estate (Phase 3 COUNT=1 PARK). Does
  # not grade GROUP_MEMBER_INDICATOR (sibling 6.2).
  # CAST COUNT — VARCHAR(COUNT(*),10) is SQLSTATE
  # 42815. Exact *DISABLED is PASS. Exact *ENABLED
  # is FAIL. Missing QSECOFR is NOT_ASSESSED.
  QD_RAW=$(ibmi_sql usrprf_qsecofr "SELECT 'CNT' CONCAT '|' CONCAT CAST(COUNT(*) AS VARCHAR(10)) CONCAT '|' CONCAT '-' FROM QSYS2.USER_INFO WHERE AUTHORIZATION_NAME = 'QSECOFR' UNION ALL SELECT 'USR' CONCAT '|' CONCAT VARCHAR(TRIM(AUTHORIZATION_NAME),10) CONCAT '|' CONCAT VARCHAR(TRIM(COALESCE(STATUS,'-')),10) FROM QSYS2.USER_INFO WHERE AUTHORIZATION_NAME = 'QSECOFR'")
  QD_RC=$?
  if [ "$QD_RC" -ne 0 ]; then
    add security usr_qsecofr_disabled "QSECOFR profile status" NOT_ASSESSED low \
        "not assessed — capture failed (rc=$QD_RC)" \
        "The QSECOFR status probe did not yield a readable USER_INFO dump, so the shipped security-officer profile cannot be graded." \
        "re-run the scan as QSECOFR and confirm QSYS2.USER_INFO returns STATUS for AUTHORIZATION_NAME QSECOFR. This scanner never changes user profiles." \
        "cis-l1"
  elif [ -z "$QD_RAW" ]; then
    add security usr_qsecofr_disabled "QSECOFR profile status" NOT_ASSESSED low \
        "not assessed — capture empty (rc=0)" \
        "The QSECOFR status probe returned no pipe row, so the shipped security-officer profile cannot be graded." \
        "re-run the scan as QSECOFR and confirm QSYS2.USER_INFO returns STATUS for AUTHORIZATION_NAME QSECOFR. This scanner never changes user profiles." \
        "cis-l1"
  else
    QD_PARSE=$(printf '%s\n' "$QD_RAW" | awk -F'|' '
      $1=="CNT" {
        c=$2; sub(/[ \t]+$/, "", c)
        if (c !~ /^[0-9]+$/ || cntn) { junk=1; next }
        cntn=1
        cnt=c+0
        next
      }
      $1=="USR" {
        name=$2; sub(/[ \t]+$/, "", name)
        st=$3; sub(/[ \t]+$/, "", st)
        if (name !~ /^[A-Z][A-Z0-9#$_]{0,9}$/) { junk=1; next }
        if (name != "QSECOFR") { junk=1; next }
        if (st != "*ENABLED" && st != "*DISABLED" && st != "-") { junk=1; next }
        if (seen) { junk=1; next }
        seen=1
        status=st
        n++
      }
      END {
        if (junk) { print "JUNK"; exit }
        if (!cntn) { print "NOCNT"; exit }
        if (cnt == 0 || !seen) { print "NOQSECOFR"; exit }
        if (status == "-") { print "JUNK"; exit }
        printf "OK %d %s\n", cnt, status
      }')
    if [ "$QD_PARSE" = "JUNK" ]; then
      add security usr_qsecofr_disabled "QSECOFR profile status" NOT_ASSESSED low \
          "not assessed — USER_INFO value unreadable" \
          "The QSECOFR status dump was readable, but a row carried a profile name or STATUS token that could not be graded." \
          "inspect QSYS2.USER_INFO AUTHORIZATION_NAME and STATUS for QSECOFR." \
          "cis-l1"
    elif [ "$QD_PARSE" = "NOCNT" ]; then
      add security usr_qsecofr_disabled "QSECOFR profile status" NOT_ASSESSED low \
          "not assessed — USER_INFO count missing or not unique" \
          "The QSECOFR status dump was readable, but it did not contain exactly one QSECOFR-count row, so completeness cannot be graded." \
          "inspect QSYS2.USER_INFO COUNT of AUTHORIZATION_NAME QSECOFR." \
          "cis-l1"
    elif [ "$QD_PARSE" = "NOQSECOFR" ]; then
      add security usr_qsecofr_disabled "QSECOFR profile status" NOT_ASSESSED low \
          "not assessed — QSECOFR missing from USER_INFO listing" \
          "The profile listing does not include QSECOFR, so the shipped security-officer profile cannot be graded. The profile running xray needs *OBJOPR and *READ on user profile QSECOFR." \
          "grant the scan profile *OBJOPR and *READ on QSECOFR (GRTOBJAUT OBJ(QSECOFR) OBJTYPE(*USRPRF) AUT(*OBJOPR *READ)), or re-run as QSECOFR. This scanner never changes user profiles." \
          "cis-l1"
    else
      QD_CNT=$(printf '%s\n' "$QD_PARSE" | awk '{ print $2 }')
      QD_ST=$(printf '%s\n' "$QD_PARSE" | awk '{ print $3 }')
      if [ -z "$QD_CNT" ] || [ "$QD_CNT" -ne 1 ]; then
        add security usr_qsecofr_disabled "QSECOFR profile status" NOT_ASSESSED low \
            "not assessed — USER_INFO listing incomplete" \
            "The QSECOFR count and the QSECOFR USER_INFO row do not match, so the shipped security-officer profile cannot be graded." \
            "grant the scan profile catalog listing of QSECOFR and re-run. This scanner never changes user profiles." \
            "cis-l1"
      elif [ "$QD_ST" = "*DISABLED" ]; then
        add security usr_qsecofr_disabled "QSECOFR profile status" PASS low \
            "status=*DISABLED" \
            "The shipped security-officer profile is disabled, so it cannot be used for interactive sign-on from a workstation. Console sign-on remains possible." \
            "n/a" \
            "cis-l1"
      else
        add security usr_qsecofr_disabled "QSECOFR profile status" FAIL high \
            "status=*ENABLED" \
            "The shipped security-officer profile is enabled, so it can be used for interactive sign-on from a workstation." \
            "set STATUS to *DISABLED on QSECOFR using CHGUSRPRF USRPRF(QSECOFR) STATUS(*DISABLED). This scanner never changes user profiles." \
            "cis-l1"
      fi
    fi
  fi

  # usr_qsecofr_not_group — IBM i QSECOFR must not be a
  # group profile (GID 0 and GROUP_MEMBER_INDICATOR=NO).
  # Authority: CIS IBM i V7R5M0/V7R4M0 6.2 (L1).
  # No L2 rec. One finding. Calls ibmi_sql for USER_INFO
  # COUNT of QSECOFR plus GID / GRPMBR. Does not call
  # ibmi_cl / DSPUSRPRF / CHGUSRPRF. Does not query
  # GROUP_PROFILE_ENTRIES (member names are D82).
  # Does not filter GID <> 0 (the COUNT UNION keeps a
  # row when QSECOFR is invisible). CAST COUNT and CAST
  # GID — VARCHAR(numeric, n) is SQLSTATE 42815.
  # gid=0 and grpmbr=NO is PASS. Any gid or YES is FAIL.
  QG_RAW=$(ibmi_sql usrprf_qsecgrp "SELECT 'CNT' CONCAT '|' CONCAT CAST(COUNT(*) AS VARCHAR(10)) CONCAT '|' CONCAT '-' CONCAT '|' CONCAT '-' FROM QSYS2.USER_INFO WHERE AUTHORIZATION_NAME = 'QSECOFR' UNION ALL SELECT 'USR' CONCAT '|' CONCAT VARCHAR(TRIM(AUTHORIZATION_NAME),10) CONCAT '|' CONCAT COALESCE(CAST(GROUP_ID_NUMBER AS VARCHAR(20)), '-') CONCAT '|' CONCAT VARCHAR(TRIM(COALESCE(GROUP_MEMBER_INDICATOR, '-')),3) FROM QSYS2.USER_INFO WHERE AUTHORIZATION_NAME = 'QSECOFR'")
  QG_RC=$?
  if [ "$QG_RC" -ne 0 ]; then
    add security usr_qsecofr_not_group "QSECOFR not a group profile" NOT_ASSESSED low \
        "not assessed — capture failed (rc=$QG_RC)" \
        "The QSECOFR group-profile probe did not yield a readable USER_INFO dump, so QSECOFR group status cannot be graded." \
        "re-run the scan as the scan profile and confirm QSYS2.USER_INFO returns GROUP_ID_NUMBER and GROUP_MEMBER_INDICATOR for QSECOFR. This scanner never changes user profiles." \
        "cis-l1"
  elif [ -z "$QG_RAW" ]; then
    add security usr_qsecofr_not_group "QSECOFR not a group profile" NOT_ASSESSED low \
        "not assessed — capture empty (rc=0)" \
        "The QSECOFR group-profile probe returned no pipe row, so QSECOFR group status cannot be graded." \
        "re-run the scan as the scan profile and confirm QSYS2.USER_INFO returns GROUP_ID_NUMBER and GROUP_MEMBER_INDICATOR for QSECOFR. This scanner never changes user profiles." \
        "cis-l1"
  else
    QG_PARSE=$(printf '%s\n' "$QG_RAW" | awk -F'|' '
      $1=="CNT" {
        c=$2; sub(/[ \t]+$/, "", c)
        if (c !~ /^[0-9]+$/ || cntn) { junk=1; next }
        cntn=1
        cnt=c+0
        next
      }
      $1=="USR" {
        name=$2; sub(/[ \t]+$/, "", name); sub(/^[ \t]+/, "", name)
        gid=$3; sub(/[ \t]+$/, "", gid); sub(/^[ \t]+/, "", gid)
        mbr=$4; sub(/[ \t]+$/, "", mbr); sub(/^[ \t]+/, "", mbr)
        if (name !~ /^[A-Z][A-Z0-9#$_]{0,9}$/) { junk=1; next }
        if (gid !~ /^[0-9]+$/) { junk=1; next }
        if (mbr != "YES" && mbr != "NO") { junk=1; next }
        if (seen && (uname != name || ugid != gid || umbr != mbr)) { junk=1; next }
        if (seen) next
        seen=1
        uname=name
        ugid=gid
        umbr=mbr
        n++
      }
      END {
        if (junk) { print "JUNK"; exit }
        if (!cntn) { print "NOCNT"; exit }
        if (cnt != 1 || n != 1 || uname != "QSECOFR") { print "NOQSECOFR"; exit }
        gtok = (ugid+0 == 0) ? "0" : "set"
        printf "OK %s %s\n", gtok, umbr
      }')
    if [ "$QG_PARSE" = "JUNK" ]; then
      add security usr_qsecofr_not_group "QSECOFR not a group profile" NOT_ASSESSED low \
          "not assessed — USER_INFO value unreadable" \
          "The QSECOFR group-profile dump was readable, but a row carried a profile name, GROUP_ID_NUMBER, or GROUP_MEMBER_INDICATOR token that could not be graded." \
          "inspect QSYS2.USER_INFO AUTHORIZATION_NAME, GROUP_ID_NUMBER, and GROUP_MEMBER_INDICATOR for QSECOFR." \
          "cis-l1"
    elif [ "$QG_PARSE" = "NOCNT" ]; then
      add security usr_qsecofr_not_group "QSECOFR not a group profile" NOT_ASSESSED low \
          "not assessed — USER_INFO count missing or not unique" \
          "The QSECOFR group-profile dump was readable, but it did not contain exactly one profile-count row, so completeness cannot be graded." \
          "inspect QSYS2.USER_INFO COUNT of QSECOFR." \
          "cis-l1"
    elif [ "$QG_PARSE" = "NOQSECOFR" ]; then
      add security usr_qsecofr_not_group "QSECOFR not a group profile" NOT_ASSESSED low \
          "not assessed — QSECOFR missing from USER_INFO listing" \
          "The profile listing does not include exactly one QSECOFR row, so QSECOFR group status cannot be graded." \
          "grant the scan profile catalog listing of QSECOFR and re-run." \
          "cis-l1"
    else
      QG_GID=$(printf '%s\n' "$QG_PARSE" | awk '{ print $2 }')
      QG_MBR=$(printf '%s\n' "$QG_PARSE" | awk '{ print $3 }')
      QG_CNT=1
      if [ "$QG_GID" = "0" ] && [ "$QG_MBR" = "NO" ]; then
        add security usr_qsecofr_not_group "QSECOFR not a group profile" PASS low \
            "gid=0 grpmbr=NO" \
            "QSECOFR is not a group profile, so no profile inherits QSECOFR special authorities through group membership." \
            "n/a" \
            "cis-l1"
      else
        add security usr_qsecofr_not_group "QSECOFR not a group profile" FAIL high \
            "gid=$QG_GID grpmbr=$QG_MBR" \
            "QSECOFR is a group profile, so group members inherit QSECOFR special authorities." \
            "move every profile that names QSECOFR as its group or supplemental group onto a shop-created group using CHGUSRPRF GRPPRF, then set QSECOFR group ID to *NONE using CHGUSRPRF GID(*NONE). This scanner never changes user profiles." \
            "cis-l1"
      fi
    fi
  fi

  # usr_special_authorities — IBM i special authorities on *USRPRF.
  # Authority: CIS IBM i V7R5M0/V7R4M0 4.4 (L1=*USER class remaining
  # profiles have no effective special authority, own or inherited).
  # No L2 rec. One finding. Calls ibmi_sql for USER_INFO COUNT plus
  # class / compact-flag / group rows. Does not call ibmi_cl /
  # PRTUSRPRF / CHGUSRPRF. Does not filter SPCAUT <> *NONE
  # (that 0-row SELECT is SQLCODE 100 on a compliant box).
  # Q-prefixed names are grading-skipped (IBM-supplied).
  # Remaining *USER with any of AUIJSEVP is FAIL.
  # Remaining *PGMR/*SYSOPR/*SECADM/*SECOFR are counted, not FAIL.
  SA_RAW=$(ibmi_sql usrprf_spcaut "SELECT 'CNT' CONCAT '|' CONCAT VARCHAR(CHAR(COUNT(*)),10) CONCAT '|' CONCAT '-' CONCAT '|' CONCAT '-' CONCAT '|' CONCAT '-' CONCAT '|' CONCAT '0' CONCAT '|' CONCAT '-' FROM QSYS2.USER_INFO UNION ALL SELECT 'USR' CONCAT '|' CONCAT VARCHAR(TRIM(AUTHORIZATION_NAME),10) CONCAT '|' CONCAT VARCHAR(TRIM(USER_CLASS_NAME),10) CONCAT '|' CONCAT VARCHAR(CASE WHEN SPECIAL_AUTHORITIES IS NULL OR TRIM(SPECIAL_AUTHORITIES) = '' OR TRIM(SPECIAL_AUTHORITIES) = '*NONE' THEN '--------' WHEN POSSTR(SPECIAL_AUTHORITIES, '*ALLOBJ') = 0 AND POSSTR(SPECIAL_AUTHORITIES, '*AUDIT') = 0 AND POSSTR(SPECIAL_AUTHORITIES, '*IOSYSCFG') = 0 AND POSSTR(SPECIAL_AUTHORITIES, '*JOBCTL') = 0 AND POSSTR(SPECIAL_AUTHORITIES, '*SAVSYS') = 0 AND POSSTR(SPECIAL_AUTHORITIES, '*SECADM') = 0 AND POSSTR(SPECIAL_AUTHORITIES, '*SERVICE') = 0 AND POSSTR(SPECIAL_AUTHORITIES, '*SPLCTL') = 0 THEN 'XXXXXXXX' ELSE CONCAT(CASE WHEN POSSTR(SPECIAL_AUTHORITIES, '*ALLOBJ') > 0 THEN 'A' ELSE '-' END, CONCAT(CASE WHEN POSSTR(SPECIAL_AUTHORITIES, '*AUDIT') > 0 THEN 'U' ELSE '-' END, CONCAT(CASE WHEN POSSTR(SPECIAL_AUTHORITIES, '*IOSYSCFG') > 0 THEN 'I' ELSE '-' END, CONCAT(CASE WHEN POSSTR(SPECIAL_AUTHORITIES, '*JOBCTL') > 0 THEN 'J' ELSE '-' END, CONCAT(CASE WHEN POSSTR(SPECIAL_AUTHORITIES, '*SAVSYS') > 0 THEN 'S' ELSE '-' END, CONCAT(CASE WHEN POSSTR(SPECIAL_AUTHORITIES, '*SECADM') > 0 THEN 'E' ELSE '-' END, CONCAT(CASE WHEN POSSTR(SPECIAL_AUTHORITIES, '*SERVICE') > 0 THEN 'V' ELSE '-' END, CASE WHEN POSSTR(SPECIAL_AUTHORITIES, '*SPLCTL') > 0 THEN 'P' ELSE '-' END))))))) END, 8) CONCAT '|' CONCAT VARCHAR(TRIM(COALESCE(GROUP_PROFILE_NAME, '*NONE')),10) CONCAT '|' CONCAT VARCHAR(CHAR(SUPPLEMENTAL_GROUP_COUNT),3) CONCAT '|' CONCAT VARCHAR(COALESCE(SUPPLEMENTAL_GROUP_LIST, ''),150) FROM QSYS2.USER_INFO")
  SA_RC=$?
  if [ "$SA_RC" -ne 0 ]; then
    add security usr_special_authorities "User profile special authorities" NOT_ASSESSED low \
        "not assessed — capture failed (rc=$SA_RC)" \
        "The user-profile special-authority probe did not yield a readable USER_INFO dump, so special authorities cannot be graded." \
        "re-run the scan as the scan profile and confirm QSYS2.USER_INFO returns USER_CLASS_NAME and SPECIAL_AUTHORITIES rows. This scanner never changes user profiles." \
        "cis-l1"
  elif [ -z "$SA_RAW" ]; then
    add security usr_special_authorities "User profile special authorities" NOT_ASSESSED low \
        "not assessed — capture empty (rc=0)" \
        "The user-profile special-authority probe returned no pipe row, so special authorities cannot be graded." \
        "re-run the scan as the scan profile and confirm QSYS2.USER_INFO returns USER_CLASS_NAME and SPECIAL_AUTHORITIES rows. This scanner never changes user profiles." \
        "cis-l1"
  else
    SA_PARSE=$(printf '%s\n' "$SA_RAW" | awk -F'|' '
      function orflags(a, b,    i, r, ca, cb) {
        r = ""
        for (i = 1; i <= 8; i++) {
          ca = substr(a, i, 1)
          cb = substr(b, i, 1)
          if (ca != "-" && ca != "") r = r ca
          else if (cb != "-" && cb != "") r = r cb
          else r = r "-"
        }
        return r
      }
      $1=="CNT" {
        c=$2; sub(/[ \t]+$/, "", c)
        if (c !~ /^[0-9]+$/ || cntn) { junk=1; next }
        cntn=1
        cnt=c+0
        next
      }
      $1=="USR" {
        name=$2; sub(/[ \t]+$/, "", name)
        cls=$3; sub(/[ \t]+$/, "", cls)
        fl=$4; sub(/[ \t]+$/, "", fl)
        grp=$5; sub(/[ \t]+$/, "", grp)
        sc=$6; sub(/[ \t]+$/, "", sc)
        sl=$7; sub(/[ \t]+$/, "", sl)
        if (name !~ /^[A-Z][A-Z0-9#$_]{0,9}$/) { junk=1; next }
        if (cls != "*USER" && cls != "*PGMR" && cls != "*SYSOPR" && cls != "*SECADM" && cls != "*SECOFR") {
          junk=1
          next
        }
        if (fl !~ /^[AUIJSEVP-]{8}$/) { junk=1; next }
        if (grp != "*NONE" && grp !~ /^[A-Z][A-Z0-9#$_]{0,9}$/) { junk=1; next }
        if (sc !~ /^[0-9]+$/) { junk=1; next }
        if (seen[name] && (own[name] != fl || classof[name] != cls || gprof[name] != grp)) { junk=1; next }
        if (seen[name]) next
        seen[name]=1
        own[name]=fl
        classof[name]=cls
        gprof[name]=grp
        scnt[name]=sc+0
        slist[name]=sl
        n++
      }
      END {
        if (junk) { print "JUNK"; exit }
        if (!cntn) { print "NOCNT"; exit }
        for (name in own) {
          if (name ~ /^Q[A-Z0-9#$_]{0,9}$/) continue
          eff = own[name]
          g = gprof[name]
          if (g != "*NONE") {
            if (!(g in own)) { print "JUNK"; exit }
            eff = orflags(eff, own[g])
          }
          ng = split(slist[name], ga, /[ \t]+/)
          ns = 0
          for (i = 1; i <= ng; i++) {
            if (ga[i] == "") continue
            ns++
            if (ga[i] !~ /^[A-Z][A-Z0-9#$_]{0,9}$/) { print "JUNK"; exit }
            if (!(ga[i] in own)) { print "JUNK"; exit }
            eff = orflags(eff, own[ga[i]])
          }
          if (ns != scnt[name]) { print "JUNK"; exit }
          if (classof[name] == "*USER") {
            usr++
            if (eff ~ /[AUIJSEVP]/) ua++
          } else adm++
        }
        printf "OK %d %d %d %d %d\n", cnt, n+0, usr+0, ua+0, adm+0
      }')
    if [ "$SA_PARSE" = "JUNK" ]; then
      add security usr_special_authorities "User profile special authorities" NOT_ASSESSED low \
          "not assessed — USER_INFO value unreadable" \
          "The user-profile special-authority dump was readable, but a row carried a profile name, user class, special-authority flag, or group name that could not be graded." \
          "inspect QSYS2.USER_INFO AUTHORIZATION_NAME, USER_CLASS_NAME, SPECIAL_AUTHORITIES, GROUP_PROFILE_NAME, and SUPPLEMENTAL_GROUP_LIST." \
          "cis-l1"
    elif [ "$SA_PARSE" = "NOCNT" ]; then
      add security usr_special_authorities "User profile special authorities" NOT_ASSESSED low \
          "not assessed — USER_INFO count missing or not unique" \
          "The user-profile special-authority dump was readable, but it did not contain exactly one profile-count row, so completeness cannot be graded." \
          "inspect QSYS2.USER_INFO COUNT of user profiles." \
          "cis-l1"
    else
      SA_CNT=$(printf '%s\n' "$SA_PARSE" | awk '{ print $2 }')
      SA_N=$(printf '%s\n' "$SA_PARSE" | awk '{ print $3 }')
      SA_USR=$(printf '%s\n' "$SA_PARSE" | awk '{ print $4 }')
      SA_UA=$(printf '%s\n' "$SA_PARSE" | awk '{ print $5 }')
      SA_ADM=$(printf '%s\n' "$SA_PARSE" | awk '{ print $6 }')
      if [ -z "$SA_CNT" ] || [ "$SA_CNT" -lt 4 ]; then
        add security usr_special_authorities "User profile special authorities" NOT_ASSESSED low \
            "not assessed — USER_INFO count too small to be a complete estate" \
            "The profile count is smaller than a supported IBM i ships, so special authorities cannot be graded." \
            "grant the scan profile *OBJOPR and *READ on user profiles and re-run. Do not run this check as QSECOFR to paper over the gap." \
            "cis-l1"
      elif [ "$SA_N" -ne "$SA_CNT" ]; then
        add security usr_special_authorities "User profile special authorities" NOT_ASSESSED low \
            "not assessed — USER_INFO listing incomplete" \
            "The profile count and the USER_INFO listing do not match, so special authorities cannot be graded." \
            "grant the scan profile catalog listing of user profiles and re-run. Do not run this check as QSECOFR to paper over the gap." \
            "cis-l1"
      elif [ "$SA_UA" -eq 0 ]; then
        add security usr_special_authorities "User profile special authorities" PASS low \
            "profiles=$SA_N user=$SA_USR userauth=$SA_UA admins=$SA_ADM" \
            "Every remaining user profile of class *USER has no administrative special authority, including authority inherited from a group profile." \
            "n/a" \
            "cis-l1"
      else
        add security usr_special_authorities "User profile special authorities" FAIL high \
            "profiles=$SA_N user=$SA_USR userauth=$SA_UA admins=$SA_ADM" \
            "One or more remaining user profiles of class *USER have an administrative special authority, including authority inherited from a group profile." \
            "set SPCAUT(*NONE) on every non-administrative *USER class user and group using CHGUSRPRF. This scanner never changes user profiles." \
            "cis-l1"
      fi
    fi
  fi

MANUAL_CONTROLS=$(cat <<'PTXRAY_MANUAL_EOF'
7.4,7.5|4.12|L1|Implement Multi-factor authentication (MFA)
7.4,7.5|5.2.9|L1|Intrusion Detection
7.4,7.5|5.2.12|L1|SMTP Mail Relay
7.4,7.5|5.2.13|L1|SNMP Access
7.4,7.5|5.3.7|L1|Malware Defenses
7.4|5.6.1|L1|System Service Tools Password Expiration Interval
7.4|5.6.2|L1|System Service Tools Changing the maximum failed sign-on attempts
7.4|5.6.3|L1|System Service Tools Changing the duplicate password control
PTXRAY_MANUAL_EOF
)
CONTROL_ROWS=$(cat <<'PTXRAY_CONTROL_EOF'
7.4|4.1|L1|automated|implemented|usr_public_authority
7.4|4.2|L1|automated|implemented|usr_private_authority
7.4|4.3|L1|automated|implemented|usr_ownership
7.4|4.4|L1|automated|implemented|usr_special_authorities
7.4|4.5|L1|automated|implemented|usr_action_auditing
7.4|4.6|L1|automated|implemented|usr_default_passwords
7.4|4.7|L1|automated|implemented|usr_inactive_profiles
7.4|4.8|L1|automated|implemented|usr_nonexpiring_passwords
7.4|4.9|L1|automated|implemented|usr_command_line_access
7.4|4.10|L1|automated|implemented|usr_ibm_supplied_profiles
7.4|4.11|L1|automated|implemented|usr_group_passwords
7.4|4.12|L1|manual|manual|
7.4|5.1.1.1|L1|automated|implemented|sv_qalwobjrst
7.4|5.1.1.2|L1|automated|implemented|sv_qatnpgm
7.4|5.1.1.3|L1|automated|implemented|sv_qaudctl
7.4|5.1.1.4|L1|automated|implemented|sv_qaudendacn
7.4|5.1.1.5|L1|automated|implemented|sv_qaudfrclvl
7.4|5.1.1.6|L1|automated|implemented|sv_qaudlvl
7.4|5.1.1.7|L1|automated|implemented|sv_qaudlvl2
7.4|5.1.1.8|L1|automated|implemented|sv_qautocfg
7.4|5.1.1.9|L1|automated|implemented|sv_qautormt
7.4|5.1.1.10|L1|automated|implemented|sv_qautovrt
7.4|5.1.1.11|L1|automated|implemented|sv_qcrtaut
7.4|5.1.1.12|L1|automated|implemented|sv_qdscjobitv
7.4|5.1.1.13|L1|automated|implemented|sv_qdspsgninf
7.4|5.1.1.14|L1|automated|implemented|sv_qfrccvnrst
7.4|5.1.1.15|L1|automated|implemented|sv_qinactitv
7.4|5.1.1.16|L1|automated|implemented|sv_qinactmsgq
7.4|5.1.1.17|L1|automated|implemented|sv_qlmtdevssn
7.4|5.1.1.18|L1|automated|implemented|sv_qlmtsecofr
7.4|5.1.1.19|L1|automated|implemented|sv_qmaxsgnacn
7.4|5.1.1.20|L1|automated|implemented|sv_qmaxsign
7.4|5.1.1.21|L1|automated|unimplemented|
7.4|5.1.1.22|L1|automated|implemented|sv_qpwdexpitv
7.4|5.1.1.23|L1|automated|implemented|sv_qpwdexpwrn
7.4|5.1.1.24|L1|automated|implemented|sv_qpwdlvl
7.4|5.1.1.25|L1|automated|implemented|sv_qpwdrqddif
7.4|5.1.1.26|L1|automated|implemented|sv_qpwdrules
7.4|5.1.1.27|L1|automated|implemented|sv_qretsvrsec
7.4|5.1.1.28|L1|automated|implemented|sv_qrmtipl
7.4|5.1.1.29|L1|automated|implemented|sv_qrmtsign
7.4|5.1.1.30|L1|automated|implemented|sv_qrmtsrvatr
7.4|5.1.1.31|L1|automated|implemented|sv_qscanfs
7.4|5.1.1.32|L1|automated|implemented|sv_qscanfsctl
7.4|5.1.1.33|L1|automated|implemented|sv_qsecurity
7.4|5.1.1.34|L1|automated|implemented|sv_qshrmemctl
7.4|5.1.1.35|L1|automated|implemented|sv_qsslcsl
7.4|5.1.1.36|L1|automated|implemented|sv_qsslcslctl
7.4|5.1.1.37|L1|automated|implemented|sv_qsslpcl
7.4|5.1.1.38|L1|automated|implemented|sv_qsyslibl
7.4|5.1.1.39|L1|automated|implemented|sv_quseadpaut
7.4|5.1.1.40|L1|automated|implemented|sv_qvfyobjrst
7.4|5.1.2.1|L2|automated|unimplemented|
7.4|5.1.2.2|L2|automated|implemented|sv_qalwusrdmn
7.4|5.1.2.3|L2|automated|implemented|sv_qaudctl
7.4|5.1.2.4|L2|automated|unimplemented|
7.4|5.1.2.5|L2|automated|implemented|sv_qaudfrclvl
7.4|5.1.2.6|L2|automated|unimplemented|
7.4|5.1.2.7|L2|automated|unimplemented|
7.4|5.1.2.8|L2|automated|implemented|sv_qcrtobjaud
7.4|5.1.2.9|L2|automated|unimplemented|
7.4|5.1.2.10|L2|automated|unimplemented|
7.4|5.1.2.11|L2|automated|unimplemented|
7.4|5.1.2.12|L2|automated|unimplemented|
7.4|5.1.2.13|L2|automated|unimplemented|
7.4|5.1.2.14|L2|automated|implemented|sv_qlmtsecofr
7.4|5.1.2.15|L2|automated|unimplemented|
7.4|5.1.2.16|L2|automated|unimplemented|
7.4|5.1.2.17|L2|automated|unimplemented|
7.4|5.1.2.18|L2|automated|unimplemented|
7.4|5.1.2.19|L2|automated|unimplemented|
7.4|5.1.2.20|L2|automated|unimplemented|
7.4|5.1.2.21|L2|automated|implemented|sv_qpwdvldpgm
7.4|5.1.2.22|L2|automated|unimplemented|
7.4|5.1.2.23|L2|automated|unimplemented|
7.4|5.1.2.24|L2|automated|unimplemented|
7.4|5.1.2.25|L2|automated|unimplemented|
7.4|5.1.2.26|L2|automated|unimplemented|
7.4|5.2.1|L1|automated|implemented|net_jobacn
7.4|5.2.2|L1|automated|implemented|net_ddm_sna
7.4|5.2.3|L1|automated|implemented|net_ddm_tcp
7.4|5.2.4|L2|automated|unimplemented|
7.4|5.2.5|L1|automated|implemented|net_nfs_shares
7.4|5.2.6|L2|automated|unimplemented|
7.4|5.2.7|L1|automated|implemented|net_exit_points
7.4|5.2.8|L1|automated|implemented|net_function_usage
7.4|5.2.9|L1|manual|manual|
7.4|5.2.10|L1|automated|implemented|net_telnet
7.4|5.2.11|L1|automated|unimplemented|
7.4|5.2.12|L1|manual|manual|
7.4|5.2.13|L1|manual|manual|
7.4|5.3.1|L1|automated|unimplemented|
7.4|5.3.2|L1|automated|unimplemented|
7.4|5.3.3|L1|automated|unimplemented|
7.4|5.3.4|L1|automated|unimplemented|
7.4|5.3.5|L1|automated|implemented|net_netserver_shares
7.4|5.3.6|L2|automated|unimplemented|
7.4|5.3.7|L1|manual|manual|
7.4|5.4.1|L1|automated|implemented|ssh_protocol
7.4|5.4.2|L1|automated|implemented|ibmi_ssh_banner
7.4|5.4.3|L1|automated|implemented|ssh_hostbased_auth
7.4|5.4.4|L1|automated|implemented|ssh_privsep
7.4|5.4.5|L1|automated|implemented|ibmi_ssh_maxauthtries
7.4|5.4.6|L1|automated|implemented|ssh_idle_timeout
7.4|5.4.7|L1|automated|implemented|ibmi_ssh_ciphers
7.4|5.4.8|L1|automated|implemented|ssh_limit_access
7.4|5.5.1|L1|automated|implemented|cur_ptf_groups
7.4|5.6.1|L1|manual|manual|
7.4|5.6.2|L1|manual|manual|
7.4|5.6.3|L1|manual|manual|
7.4|5.6.4|L1|automated|implemented|sst_pwdlvl
7.4|5.6.5|L1|automated|implemented|sst_new_certs
7.4|5.6.6|L1|automated|unimplemented|
7.4|5.6.7|L1|automated|implemented|sst_lock_sysval
7.4|5.6.8|L1|automated|implemented|sst_pwdrules
7.4|6.1|L1|automated|implemented|usr_qsecofr_disabled
7.4|6.2|L1|automated|implemented|usr_qsecofr_not_group
7.5|4.1|L1|automated|implemented|usr_public_authority
7.5|4.2|L1|automated|implemented|usr_private_authority
7.5|4.3|L1|automated|implemented|usr_ownership
7.5|4.4|L1|automated|implemented|usr_special_authorities
7.5|4.5|L1|automated|implemented|usr_action_auditing
7.5|4.6|L1|automated|implemented|usr_default_passwords
7.5|4.7|L1|automated|implemented|usr_inactive_profiles
7.5|4.8|L1|automated|implemented|usr_nonexpiring_passwords
7.5|4.9|L1|automated|implemented|usr_command_line_access
7.5|4.10|L1|automated|implemented|usr_ibm_supplied_profiles
7.5|4.11|L1|automated|implemented|usr_group_passwords
7.5|4.12|L1|manual|manual|
7.5|5.1.1.1|L1|automated|implemented|sv_qalwobjrst
7.5|5.1.1.2|L1|automated|implemented|sv_qatnpgm
7.5|5.1.1.3|L1|automated|implemented|sv_qaudctl
7.5|5.1.1.4|L1|automated|implemented|sv_qaudendacn
7.5|5.1.1.5|L1|automated|implemented|sv_qaudfrclvl
7.5|5.1.1.6|L1|automated|implemented|sv_qaudlvl
7.5|5.1.1.7|L1|automated|implemented|sv_qaudlvl2
7.5|5.1.1.8|L1|automated|implemented|sv_qautocfg
7.5|5.1.1.9|L1|automated|implemented|sv_qautormt
7.5|5.1.1.10|L1|automated|implemented|sv_qautovrt
7.5|5.1.1.11|L1|automated|implemented|sv_qcrtaut
7.5|5.1.1.12|L1|automated|implemented|sv_qdscjobitv
7.5|5.1.1.13|L1|automated|implemented|sv_qdspsgninf
7.5|5.1.1.14|L1|automated|implemented|sv_qfrccvnrst
7.5|5.1.1.15|L1|automated|implemented|sv_qinactitv
7.5|5.1.1.16|L1|automated|implemented|sv_qinactmsgq
7.5|5.1.1.17|L1|automated|implemented|sv_qlmtdevssn
7.5|5.1.1.18|L1|automated|implemented|sv_qlmtsecofr
7.5|5.1.1.19|L1|automated|implemented|sv_qmaxsgnacn
7.5|5.1.1.20|L1|automated|implemented|sv_qmaxsign
7.5|5.1.1.21|L1|automated|unimplemented|
7.5|5.1.1.22|L1|automated|implemented|sv_qpwdexpitv
7.5|5.1.1.23|L1|automated|implemented|sv_qpwdexpwrn
7.5|5.1.1.24|L1|automated|implemented|sv_qpwdlvl
7.5|5.1.1.25|L1|automated|implemented|sv_qpwdrqddif
7.5|5.1.1.26|L1|automated|implemented|sv_qpwdrules
7.5|5.1.1.27|L1|automated|implemented|sv_qretsvrsec
7.5|5.1.1.28|L1|automated|implemented|sv_qrmtipl
7.5|5.1.1.29|L1|automated|implemented|sv_qrmtsign
7.5|5.1.1.30|L1|automated|implemented|sv_qrmtsrvatr
7.5|5.1.1.31|L1|automated|implemented|sv_qscanfs
7.5|5.1.1.32|L1|automated|implemented|sv_qscanfsctl
7.5|5.1.1.33|L1|automated|implemented|sv_qsecurity
7.5|5.1.1.34|L1|automated|implemented|sv_qshrmemctl
7.5|5.1.1.35|L1|automated|implemented|sv_qsslcsl
7.5|5.1.1.36|L1|automated|implemented|sv_qsslcslctl
7.5|5.1.1.37|L1|automated|implemented|sv_qsslpcl
7.5|5.1.1.38|L1|automated|implemented|sv_qsyslibl
7.5|5.1.1.39|L1|automated|implemented|sv_quseadpaut
7.5|5.1.1.40|L1|automated|implemented|sv_qvfyobjrst
7.5|5.1.2.1|L2|automated|unimplemented|
7.5|5.1.2.2|L2|automated|implemented|sv_qalwusrdmn
7.5|5.1.2.3|L2|automated|implemented|sv_qaudctl
7.5|5.1.2.4|L2|automated|unimplemented|
7.5|5.1.2.5|L2|automated|implemented|sv_qaudfrclvl
7.5|5.1.2.6|L2|automated|unimplemented|
7.5|5.1.2.7|L2|automated|unimplemented|
7.5|5.1.2.8|L2|automated|implemented|sv_qcrtobjaud
7.5|5.1.2.9|L2|automated|unimplemented|
7.5|5.1.2.10|L2|automated|unimplemented|
7.5|5.1.2.11|L2|automated|unimplemented|
7.5|5.1.2.12|L2|automated|unimplemented|
7.5|5.1.2.13|L2|automated|unimplemented|
7.5|5.1.2.14|L2|automated|implemented|sv_qlmtsecofr
7.5|5.1.2.15|L2|automated|unimplemented|
7.5|5.1.2.16|L2|automated|unimplemented|
7.5|5.1.2.17|L2|automated|unimplemented|
7.5|5.1.2.18|L2|automated|unimplemented|
7.5|5.1.2.19|L2|automated|unimplemented|
7.5|5.1.2.20|L2|automated|unimplemented|
7.5|5.1.2.21|L2|automated|implemented|sv_qpwdvldpgm
7.5|5.1.2.22|L2|automated|unimplemented|
7.5|5.1.2.23|L2|automated|unimplemented|
7.5|5.1.2.24|L2|automated|unimplemented|
7.5|5.1.2.25|L2|automated|unimplemented|
7.5|5.2.1|L1|automated|implemented|net_jobacn
7.5|5.2.2|L1|automated|implemented|net_ddm_sna
7.5|5.2.3|L1|automated|implemented|net_ddm_tcp
7.5|5.2.4|L2|automated|unimplemented|
7.5|5.2.5|L1|automated|implemented|net_nfs_shares
7.5|5.2.6|L2|automated|unimplemented|
7.5|5.2.7|L1|automated|implemented|net_exit_points
7.5|5.2.8|L1|automated|implemented|net_function_usage
7.5|5.2.9|L1|manual|manual|
7.5|5.2.10|L1|automated|implemented|net_telnet
7.5|5.2.11|L1|automated|unimplemented|
7.5|5.2.12|L1|manual|manual|
7.5|5.2.13|L1|manual|manual|
7.5|5.3.1|L1|automated|unimplemented|
7.5|5.3.2|L1|automated|unimplemented|
7.5|5.3.3|L1|automated|unimplemented|
7.5|5.3.4|L1|automated|unimplemented|
7.5|5.3.5|L1|automated|implemented|net_netserver_shares
7.5|5.3.6|L2|automated|unimplemented|
7.5|5.3.7|L1|manual|manual|
7.5|5.4.1|L1|automated|implemented|ssh_protocol
7.5|5.4.2|L1|automated|implemented|ibmi_ssh_banner
7.5|5.4.3|L1|automated|implemented|ssh_hostbased_auth
7.5|5.4.4|L1|automated|implemented|ssh_privsep
7.5|5.4.5|L1|automated|implemented|ibmi_ssh_maxauthtries
7.5|5.4.6|L1|automated|implemented|ssh_idle_timeout
7.5|5.4.7|L1|automated|implemented|ibmi_ssh_ciphers
7.5|5.4.8|L1|automated|implemented|ssh_limit_access
7.5|5.5.1|L1|automated|implemented|cur_ptf_groups
7.5|5.6.1|L1|automated|implemented|sst_pwdexpitv
7.5|5.6.2|L1|automated|implemented|sst_maxsign
7.5|5.6.3|L1|automated|implemented|sst_dup_password
7.5|5.6.4|L1|automated|implemented|sst_pwdlvl
7.5|5.6.5|L1|automated|implemented|sst_new_certs
7.5|5.6.6|L1|automated|unimplemented|
7.5|5.6.7|L1|automated|implemented|sst_lock_sysval
7.5|5.6.8|L1|automated|implemented|sst_pwdrules
7.5|5.6.9|L1|automated|unimplemented|
7.5|6.1|L1|automated|implemented|usr_qsecofr_disabled
7.5|6.2|L1|automated|implemented|usr_qsecofr_not_group
PTXRAY_CONTROL_EOF
)

PASS_N=0; WARN_N=0; FAIL_N=0; NA_N=0; NAPP_N=0
CUR_TOTAL=0; CUR_ASSESSED=0; CUR_PASS=0
i=0
while [ "$i" -lt "$NFIND" ]; do
  case "${F_ST[$i]}" in
    PASS) PASS_N=$((PASS_N+1)); assessed=1 ;;
    WARN) WARN_N=$((WARN_N+1)); assessed=1 ;;
    FAIL) FAIL_N=$((FAIL_N+1)); assessed=1 ;;
    NOT_ASSESSED) NA_N=$((NA_N+1)); assessed=0 ;;
    NOT_APPLICABLE) NAPP_N=$((NAPP_N+1)); assessed=0 ;;
  esac
  case "${F_CAT[$i]}" in
    lifecycle|patch)
      CUR_TOTAL=$((CUR_TOTAL+1)); CUR_ASSESSED=$((CUR_ASSESSED+assessed))
      [ "${F_ST[$i]}" = PASS ] && CUR_PASS=$((CUR_PASS+1))
      ;;
    *) ;;
  esac
  i=$((i+1))
done
ASSESSED=$((PASS_N+WARN_N+FAIL_N))
RELEASE=${REL:-unknown}
case "$RELEASE" in
  7.4|7.5)
    MODEL_RELEASE=$RELEASE
    CROSSWALK_STATUS=exact
    CROSSWALK_NOTE="Exact CIS IBM i $RELEASE Benchmark v2.1.0 crosswalk."
    ;;
  *)
    MODEL_RELEASE=""
    CROSSWALK_STATUS=unavailable
    CROSSWALK_NOTE="Exact release-specific CIS crosswalk unavailable; semantic predicates are reported without control numbers."
    ;;
esac

SEC_TOTAL=0; SEC_ASSESSED=0; SEC_PASS=0
if [ "$CROSSWALK_STATUS" = exact ]; then
  while IFS='|' read control_release control_ref control_level control_automation control_disposition control_finding; do
    [ "$control_release" = "$MODEL_RELEASE" ] || continue
    [ "$control_automation" = automated ] || continue
    if [ "$COMPLIANCE" = cis-l1 ] && [ "$control_level" != L1 ]; then continue; fi
    SEC_TOTAL=$((SEC_TOTAL+1))
    [ "$control_disposition" = implemented ] || continue
    control_status=""
    i=0
    while [ "$i" -lt "$NFIND" ]; do
      if [ "${F_ID[$i]}" = "$control_finding" ]; then control_status=${F_ST[$i]}; break; fi
      i=$((i+1))
    done
    case "$control_status" in
      PASS) SEC_ASSESSED=$((SEC_ASSESSED+1)); SEC_PASS=$((SEC_PASS+1));;
      WARN|FAIL) SEC_ASSESSED=$((SEC_ASSESSED+1));;
    esac
  done <<PTXRAY_CONTROL_INPUT
$CONTROL_ROWS
PTXRAY_CONTROL_INPUT
else
  # Outside the two verified benchmark releases, score the release-independent
  # semantic predicates once per finding. Do not borrow a release-specific
  # recommendation number or completeness denominator.
  semantic_seen='|'
  while IFS='|' read control_release control_ref control_level control_automation control_disposition control_finding; do
    [ "$control_automation" = automated ] || continue
    [ "$control_disposition" = implemented ] || continue
    if [ "$COMPLIANCE" = cis-l1 ] && [ "$control_level" != L1 ]; then continue; fi
    [ -n "$control_finding" ] || continue
    case "$semantic_seen" in *"|$control_finding|"*) continue;; esac
    semantic_seen="$semantic_seen$control_finding|"
    SEC_TOTAL=$((SEC_TOTAL+1))
    control_status=""
    i=0
    while [ "$i" -lt "$NFIND" ]; do
      if [ "${F_ID[$i]}" = "$control_finding" ]; then control_status=${F_ST[$i]}; break; fi
      i=$((i+1))
    done
    case "$control_status" in
      PASS) SEC_ASSESSED=$((SEC_ASSESSED+1)); SEC_PASS=$((SEC_PASS+1));;
      WARN|FAIL) SEC_ASSESSED=$((SEC_ASSESSED+1));;
    esac
  done <<PTXRAY_SEMANTIC_INPUT
$CONTROL_ROWS
PTXRAY_SEMANTIC_INPUT
fi

MANUAL_DISPLAY=""
if [ "$CROSSWALK_STATUS" = exact ]; then
  while IFS='|' read manual_releases manual_ref manual_level manual_title; do
    case ",$manual_releases," in
      *",$MODEL_RELEASE,"*)
        MANUAL_DISPLAY="${MANUAL_DISPLAY}${manual_ref}|${manual_level}|${manual_title}
"
        ;;
    esac
  done <<PTXRAY_MANUAL_INPUT
$MANUAL_CONTROLS
PTXRAY_MANUAL_INPUT
else
  MANUAL_DISPLAY="$CROSSWALK_NOTE"
fi

MEASURED_TOTAL=$((SEC_TOTAL+CUR_TOTAL))
MEASURED_ASSESSED=$((SEC_ASSESSED+CUR_ASSESSED))
MEASURED_PASS=$((SEC_PASS+CUR_PASS))
SCORE=""; SCOREABLE=0
if [ "$MEASURED_TOTAL" -gt 0 ] && [ $((MEASURED_ASSESSED*100)) -ge $((MEASURED_TOTAL*80)) ] \
   && [ "$SEC_TOTAL" -gt 0 ] && [ $((SEC_ASSESSED*100)) -ge $((SEC_TOTAL*80)) ] \
   && [ "$CUR_TOTAL" -gt 0 ] && [ $((CUR_ASSESSED*100)) -ge $((CUR_TOTAL*80)) ]; then
  SCORE=$((MEASURED_PASS*100/MEASURED_ASSESSED)); SCOREABLE=1
fi
case "$RELEASE" in 7.*) SCAN_LABEL="IBM i assessment" ;; *) SCAN_LABEL="IBM i COMPATIBILITY SCAN" ;; esac

if [ "$FORMAT" = json ]; then
  if [ "$SCOREABLE" -eq 1 ]; then score_json=$SCORE; else score_json=null; fi
  if [ "$CROSSWALK_STATUS" = exact ]; then crosswalk_release_json="\"$MODEL_RELEASE\""; else crosswalk_release_json=null; fi
  printf '{\n  "product": "PTxray", "edition": "IBM i", "version": "%s",\n' "$PTXRAY_VERSION"
  printf '  "scan_label": "%s", "release": "%s", "compliance": "%s",\n' "$(printf '%s' "$SCAN_LABEL"|jesc)" "$(printf '%s' "$RELEASE"|jesc)" "$COMPLIANCE"
  printf '  "cis_crosswalk": {"status":"%s","release":%s},\n' "$CROSSWALK_STATUS" "$crosswalk_release_json"
  printf '  "summary": {"pass": %d, "warn": %d, "fail": %d, "not_assessed": %d, "not_applicable": %d, "assessed": %d, "total": %d, "score_pct": %s},\n' "$PASS_N" "$WARN_N" "$FAIL_N" "$NA_N" "$NAPP_N" "$MEASURED_ASSESSED" "$MEASURED_TOTAL" "$score_json"
  printf '  "pillars": {"security":{"pass":%d,"assessed":%d,"total":%d},"currency":{"pass":%d,"assessed":%d,"total":%d}},\n' "$SEC_PASS" "$SEC_ASSESSED" "$SEC_TOTAL" "$CUR_PASS" "$CUR_ASSESSED" "$CUR_TOTAL"
  printf '  "findings": [\n'
  i=0
  while [ "$i" -lt "$NFIND" ]; do
    [ "$i" -gt 0 ] && printf ',\n'
    control_tags=""
    if [ "$CROSSWALK_STATUS" = exact ]; then
      while IFS='|' read control_release control_ref control_level control_automation control_disposition control_finding; do
        [ "$control_release" = "$MODEL_RELEASE" ] || continue
        [ "$control_automation" = automated ] || continue
        [ "$control_disposition" = implemented ] || continue
        [ "$control_finding" = "${F_ID[$i]}" ] || continue
        if [ "$COMPLIANCE" = cis-l1 ] && [ "$control_level" != L1 ]; then continue; fi
        [ -z "$control_tags" ] || control_tags="$control_tags "
        control_tags="${control_tags}cis:$control_ref"
      done <<PTXRAY_FINDING_CONTROL_INPUT
$CONTROL_ROWS
PTXRAY_FINDING_CONTROL_INPUT
    fi
    printf '    {"category":"%s","id":"%s","label":"%s","status":"%s","severity":"%s","observed":"%s","meaning":"%s","fix":"%s","controls":"%s"}' \
      "$(printf '%s' "${F_CAT[$i]}"|jesc)" "$(printf '%s' "${F_ID[$i]}"|jesc)" "$(printf '%s' "${F_LABEL[$i]}"|jesc)" "${F_ST[$i]}" "${F_SEV[$i]}" \
      "$(printf '%s' "${F_OBS[$i]}"|jesc)" "$(printf '%s' "${F_MEAN[$i]}"|jesc)" "$(printf '%s' "${F_FIX[$i]}"|jesc)" "$(printf '%s' "$control_tags"|jesc)"
    i=$((i+1))
  done
  printf '\n  ]\n}\n'
elif [ "$FORMAT" = html ]; then
  if [ "$SCOREABLE" -eq 1 ]; then score_html="${SCORE}%"; else score_html="NOT SCORED"; fi
  printf '%s\n' '<!doctype html><html><head><meta charset="utf-8">'
  printf '<title>PTxray %s — IBM i assessment</title><style>body{font:15px system-ui;margin:2rem;color:#17202a}table{border-collapse:collapse;width:100%%}th,td{border-bottom:1px solid #ccd1d1;padding:.45rem;text-align:left}.score{font-size:2rem;font-weight:700}.na{color:#566573}</style></head><body>\n' "$PTXRAY_VERSION"
  printf '<h1>PTxray %s — %s</h1><p>%s</p><p class="score">%s</p><p>Coverage: %d of %d assessed.</p><table><thead><tr><th>Status</th><th>Check</th><th>Observed</th></tr></thead><tbody>\n' "$PTXRAY_VERSION" "$(printf '%s' "$SCAN_LABEL"|hesc)" "$(printf '%s' "$CROSSWALK_NOTE"|hesc)" "$score_html" "$MEASURED_ASSESSED" "$MEASURED_TOTAL"
  i=0; while [ "$i" -lt "$NFIND" ]; do printf '<tr><td>%s</td><td>%s</td><td>%s</td></tr>\n' "${F_ST[$i]}" "$(printf '%s' "${F_LABEL[$i]}"|hesc)" "$(printf '%s' "${F_OBS[$i]}"|hesc)"; i=$((i+1)); done
  printf '</tbody></table><h2>Requires human attestation</h2><pre>%s</pre></body></html>\n' "$(printf '%s' "$MANUAL_DISPLAY"|hesc)"
else
  printf 'PTxray %s — IBM i assessment\n' "$PTXRAY_VERSION"
  printf '%s\n' "$SCAN_LABEL"
  printf '%s\n' "$CROSSWALK_NOTE"
  printf 'Coverage: %d of %d assessed' "$MEASURED_ASSESSED" "$MEASURED_TOTAL"
  if [ "$SCOREABLE" -eq 1 ]; then printf ' — score %d%%\n' "$SCORE"; else printf ' — NOT SCORED\n'; fi
  i=0; while [ "$i" -lt "$NFIND" ]; do printf '%-15s %-30s %s\n' "${F_ST[$i]}" "${F_ID[$i]}" "${F_OBS[$i]}"; i=$((i+1)); done
  printf '\nRequires human attestation\n%s\n' "$MANUAL_DISPLAY"
fi
