#!/usr/bin/env python3
"""Fail closed if the Git index contains IBM FLRTVC delivery data.

The scanner repository is public. IBM's flrtvc.ksh and apar.csv are permitted
for PowerTrue delivery use but must never be committed or redistributed here.
This guard examines the complete staged/index snapshot so it protects both a
pre-commit run and CI after a bad commit. It reports only paths and reasons,
never the prohibited bytes themselves.
"""

import os
import re
import subprocess
import sys


RAW_FILENAMES = {"flrtvc.ksh", "apar.csv"}
BUNDLED_ARTIFACT = "aixray-aix.bundled.sh"
SLOT_ASSIGNMENT_RE = re.compile(
    rb"(?<![A-Za-z0-9_])"
    rb"(flrtvc_ksh_b64|flrtvc_ksh_sha256|flrtvc_ksh_version|"
    rb"apar_csv_b64|apar_csv_sha256|apar_csv_vintage)[ \t]*="
)
FLRTVC_VERSION_RE = re.compile(rb'(?m)^VERSION="[0-9][^"\r\n]*"\s*$')
APAR_HEADER = (
    b"type,product,versions,abstract,apars,fixedIn,ifixes,bulletinUrl,"
    b"filesets,issued,updated,siblings,download,cvss,reboot"
)
APAR_VINTAGE_RE = re.compile(rb"^[^,\r\n]+,[0-9]{4}\.[0-9]{2}\.[0-9]{2}\s*$")


def git_bytes(*args):
    try:
        proc = subprocess.run(
            ["git", *args],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise RuntimeError("could not inspect the Git index") from exc
    return proc.stdout


def staged_paths():
    raw = git_bytes("ls-files", "-z")
    return [p for p in raw.split(b"\0") if p]


def staged_blob(path):
    label = path.decode("utf-8", "surrogateescape")
    return git_bytes("show", ":%s" % label)


def blob_reasons(path, blob):
    label = path.decode("utf-8", "surrogateescape")
    base = os.path.basename(label).lower()
    reasons = []
    if base in RAW_FILENAMES:
        reasons.append("prohibited IBM delivery-data filename")
    if base == BUNDLED_ARTIFACT:
        reasons.append("local bundled delivery artifact is tracked")

    # Shell permits assignments after compound-command separators and declarations,
    # and permits a backslash-newline before '='. Treat the blob as logical lines and
    # conservatively reject ANY protected-name assignment unless that complete line is
    # exactly the public empty form. This is intentionally broader than a shell parser:
    # a renamed bundled scanner must not evade the legal gate through harmless-looking
    # syntax variation, quoting, declarations, or command composition.
    logical_blob = re.sub(rb"\\\r?\n[ \t]*", b"", blob)
    for match in SLOT_ASSIGNMENT_RE.finditer(logical_blob):
        line_start = logical_blob.rfind(b"\n", 0, match.start()) + 1
        line_end = logical_blob.find(b"\n", match.end())
        if line_end < 0:
            line_end = len(logical_blob)
        line = logical_blob[line_start:line_end]
        approved_empty = match.group(1) + b"=''"
        if line != approved_empty:
            reasons.append("scanner contains a filled delivery embed slot")
            break

    first_line = blob.splitlines()[:1]
    if (
        first_line
        and b"ksh93" in first_line[0]
        and FLRTVC_VERSION_RE.search(blob)
        and b"parseLSLPP" in blob
        and b"parseEFIX" in blob
    ):
        reasons.append("blob has IBM flrtvc.ksh's structural signature")

    lines = blob.splitlines()
    if (
        len(lines) >= 100
        and lines[0].strip() == APAR_HEADER
        and len(lines) >= 2
        and APAR_VINTAGE_RE.match(lines[1])
    ):
        reasons.append("blob has a full IBM apar.csv feed signature")
    return reasons


def main():
    try:
        paths = staged_paths()
        violations = []
        for path in paths:
            try:
                blob = staged_blob(path)
            except RuntimeError:
                # Gitlinks and other non-blob entries are not delivery payloads.
                continue
            for reason in blob_reasons(path, blob):
                violations.append(
                    (path.decode("utf-8", "backslashreplace"), reason)
                )
    except RuntimeError as exc:
        print("no-IBM-redistribution: FAIL — %s" % exc, file=sys.stderr)
        return 2

    if violations:
        print(
            "no-IBM-redistribution: FAIL — prohibited delivery data is staged/tracked:",
            file=sys.stderr,
        )
        for path, reason in violations:
            print("  %s: %s" % (path, reason), file=sys.stderr)
        print(
            "Remove IBM flrtvc.ksh/apar.csv bytes and filled bundled scanners from "
            "the index; only empty public embed slots may be committed.",
            file=sys.stderr,
        )
        return 1

    print(
        "no-IBM-redistribution OK: tracked index contains no raw IBM FLRTVC data "
        "or filled scanner slots"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
