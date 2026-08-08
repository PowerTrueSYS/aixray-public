#!/bin/sh
# egress-lint.sh -- docs/aixray-spec-v2.md §3.3(c): the static grep-class lint.
# Explicitly demoted to "a cheap, fast, PR-time tripwire" -- NOT the enforcement
# mechanism. The syscall-trace CI in egress-trace.sh (and a real AIX truss lab
# run) is the real enforcement mechanism (b).
# A grep is "readily bypassed by shell variables, other clients, Python/Perl
# sockets, or direct socket code" (§3.3's own words) -- this catches the common
# case immediately, nothing more.
#
# Usage:
#   egress-lint.sh <file> [<file> ...]
#
# General command-name tokens are matched as whole WORDS (\b...\b), while the
# shell device paths are matched as literal path prefixes. An earlier draft
# matched bare substrings and false-positived on tftp_value (contains "ftp"),
# "curlabel" (a real awk variable name in this repo containing "curl"), and
# "sync " (contains "nc "); caught live against this repo's own aixray-aix.sh
# during this milestone's self-review, not deferred -- see CHANGELOG.
#
# DNS lookup clients need a narrower grammar because `host` is also ordinary
# prose and `$HOST` is a scanner variable. A second pass tokenizes each shell
# source line (comments and quoted prose stay non-command arguments) and rejects
# host/nslookup/dig only when used as a command, including the scanner's
# `aix <fixture-key> <command> ...` capture wrapper. This is still deliberately
# a grep-class tripwire, not a substitute for the real AIX syscall trace.
#
# A violation is allow-listed two ways (never a blanket file-level exemption):
#   1. Same-line marker: the matching line itself carries
#      `# network-lint: allow -- <reason>`.
#   2. Block marker: a line `# network-lint: allow-next=<N> -- <reason>` (on
#      its own) allow-lists the NEXT <N> physical lines -- for data tables
#      (e.g. a here-string of STIG service names) where appending a trailing
#      comment to each data line would corrupt the data itself.
set -u

BANNED_RE='(\b(curl|wget|ftp|telnet|nc|ssh|scp|tftp|sftp|rcp|rsh|rexec|socat|ping|traceroute|sendmail)\b|/dev/(tcp|udp)\b)'
ALLOW_MARKER='network-lint: allow'
ALLOW_NEXT_RE='network-lint: allow-next=([0-9]+)'

if [ "$#" -eq 0 ]; then
  echo "usage: egress-lint.sh <file> [<file> ...]" >&2
  exit 2
fi

TMP=$(mktemp -d) || { echo "egress-lint: FAIL -- mktemp -d failed" >&2; exit 1; }
trap 'rm -rf "$TMP"' EXIT INT TERM HUP
: > "$TMP/violations"

for f in "$@"; do
  if [ ! -f "$f" ]; then
    echo "egress-lint: FAIL -- $f: no such file" >&2
    echo "x" >> "$TMP/violations"
    continue
  fi

  # Pass 1: compute the set of line numbers covered by any preceding
  # "allow-next=N" directive, written to a file (never a shell array, for
  # portability).
  python3 - "$f" "$TMP/allowed_lines" <<'PYEOF'
import re, sys
path, out_path = sys.argv[1], sys.argv[2]
allow_next_re = re.compile(r'network-lint: allow-next=(\d+)')
allowed = set()
with open(path, errors="replace") as fh:
    lines = fh.readlines()
for i, line in enumerate(lines, start=1):
    m = allow_next_re.search(line)
    if m:
        n = int(m.group(1))
        for j in range(i + 1, i + 1 + n):
            allowed.add(j)
with open(out_path, "w") as out:
    for ln in sorted(allowed):
        out.write(f"{ln}\n")
PYEOF

  grep -nE "$BANNED_RE" "$f" > "$TMP/hits" 2>/dev/null || true

  # Pass 2: reject DNS lookup clients in executable command positions without
  # false-positive matches on comments, quoted prose, host_label, or $HOST.
  # Python is already a declared dependency of this lint (Pass 1 above).
  python3 - "$f" >> "$TMP/hits" <<'PYEOF'
import os
import re
import shlex
import sys

path = sys.argv[1]
dns_clients = {"host", "nslookup", "dig"}
command_separators = {";", "&&", "||", "|", "&", "(", ")", "{"}
leading_keywords = {"if", "then", "elif", "else", "while", "until", "do", "!"}
assignment_re = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
function_def_re = re.compile(
    r"^\s*(?:function\s+)?(?:host|nslookup|dig)\s*(?:\(\s*\))?\s*\{"
)


def command_name(token):
    return os.path.basename(token)


def simple_commands(tokens):
    command = []
    for token in tokens:
        if token in command_separators:
            if command:
                yield command
                command = []
        else:
            command.append(token)
    if command:
        yield command


def invoked_dns(command):
    while command and command[0] in leading_keywords:
        command = command[1:]
    while command and assignment_re.match(command[0]):
        command = command[1:]
    if not command:
        return False

    executable = command_name(command[0])
    if executable in dns_clients:
        return True

    # `aix` is the scanner's fixture/live-read boundary: aix KEY COMMAND ARGS.
    # COMMAND is genuinely executed by aix() in live mode, so it is a command
    # position even though it is the wrapper's third shell word.
    if executable == "aix" and len(command) >= 3:
        return command_name(command[2]) in dns_clients

    # Common transparent command prefixes. `command -v/-V` only inspects a
    # name and must not be confused with invoking it.
    if executable in {"command", "env", "exec", "nohup"}:
        rest = command[1:]
        if executable == "command" and rest and rest[0] in {"-v", "-V"}:
            return False
        while rest and (rest[0] == "--" or rest[0].startswith("-") or assignment_re.match(rest[0])):
            rest = rest[1:]
        return bool(rest) and command_name(rest[0]) in dns_clients

    return False


with open(path, errors="replace") as source:
    lines = source.readlines()

# The workflow also scans Python analyzer scripts. Applying shell command
# grammar to `host = parsed.hostname` is a category error, not a violation.
# Files without a shebang retain the conservative shell-default behavior.
if lines and lines[0].startswith("#!"):
    try:
        shebang = shlex.split(lines[0][2:].strip())
    except ValueError:
        shebang = []
    interpreter = command_name(shebang[0]) if shebang else ""
    if interpreter == "env":
        interpreter = ""
        for word in shebang[1:]:
            if word == "-S" or word.startswith("-"):
                continue
            interpreter = command_name(word)
            break
    shell_interpreters = {"sh", "ash", "bash", "dash", "ksh", "ksh88", "ksh93", "zsh"}
    if interpreter and interpreter not in shell_interpreters:
        sys.exit(0)

for line_number, line in enumerate(lines, start=1):
    if function_def_re.match(line):
        continue
    try:
        lexer = shlex.shlex(line, posix=True, punctuation_chars=";&|(){}")
        lexer.whitespace_split = True
        lexer.commenters = "#"
        tokens = list(lexer)
    except ValueError:
        # An incomplete quote/heredoc on one physical line is outside this
        # cheap lint's grammar. The syscall trace remains the real gate.
        continue
    if any(invoked_dns(command) for command in simple_commands(tokens)):
        print(f"{line_number}:{line.rstrip()}")
PYEOF

  if [ -s "$TMP/hits" ]; then
    sort -t: -k1,1n -u "$TMP/hits" > "$TMP/hits.sorted"
    mv "$TMP/hits.sorted" "$TMP/hits"
  fi
  if [ ! -s "$TMP/hits" ]; then
    echo "egress-lint: PASS -- $f: no banned network command references"
    continue
  fi
  ANY_VIOLATION=0
  while IFS=: read -r matchline content; do
    if [ -s "$TMP/allowed_lines" ] && grep -qx "$matchline" "$TMP/allowed_lines"; then
      echo "egress-lint: ALLOWED (line $matchline, block marker): ${content# }"
      continue
    fi
    # build/assemble.sh stamps each standalone tool with its own identity as a
    # bare constant, `AIXRAY_TOOL=ck-<name>`. Twenty-one ck-ssh-* tools and
    # ck-system-accounts-ftp carry a banned token inside their NAME, so the
    # word-boundary grep flags a hyphenated identifier that is not in a command
    # position. This exemption is anchored to the whole line and admits only
    # [a-z0-9-] after the prefix, so it cannot cover an expansion, a command
    # substitution, an argument, or a second command after a separator -- the
    # first pattern below rejects anything containing such a character. It is
    # not a file-level exemption and it does not widen BANNED_RE.
    TOOL_IDENTITY_LINE=0
    case "$content" in
      AIXRAY_TOOL=ck-*[!a-z0-9-]*) ;;
      AIXRAY_TOOL=ck-?*) TOOL_IDENTITY_LINE=1 ;;
    esac
    if [ "$TOOL_IDENTITY_LINE" -eq 1 ]; then
      echo "egress-lint: ALLOWED (line $matchline, generated tool identity): ${content# }"
      continue
    fi
    case "$content" in
      *"$ALLOW_MARKER"*)
        echo "egress-lint: ALLOWED (line $matchline): ${content# }"
        ;;
      *)
        echo "egress-lint: FAIL -- $f:$matchline: banned network command reference, not allow-listed: ${content# }" >&2
        ANY_VIOLATION=1
        ;;
    esac
  done < "$TMP/hits"
  if [ "$ANY_VIOLATION" -eq 1 ]; then
    echo "x" >> "$TMP/violations"
  fi
done

if [ -s "$TMP/violations" ]; then
  exit 1
fi
exit 0
