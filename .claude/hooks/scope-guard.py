#!/usr/bin/env python3
"""
PreToolUse hook: refuse a write outside the task's declared `touches`, and
refuse the git verbs that publish or rewrite history.

Catches a scope violation at the moment of the write rather than in a post-hoc
diff, so the builder is told inside the same turn and can correct.

Exit 2 blocks the tool call and returns stderr to the model.
Exit 0 allows it. Any other exit is a hook error and does not block.

Enabled only when TASK_TOUCHES is set, so interactive sessions are unaffected.

Protected paths are DATA, not code: each repo declares its own shared surfaces in
.claude/protected.txt, one pattern per line, '#' comments allowed. A pattern
matches if it equals the path, is a directory prefix of it, or fnmatches it --
and a bare filename pattern matches that filename ANYWHERE in the tree, because
the surfaces worth protecting are rarely at the repo root.

This hook FAILS CLOSED. A dispatched build in a repo with no protected.txt is
refused rather than allowed. A guard that silently no-ops is worse than none:
it reports safe while guarding nothing.
"""

import fnmatch
import json
import os
import re
import sys
from pathlib import Path

PROTECTED_FILE = ".claude/protected.txt"

# History-rewriting and publishing git verbs. A builder proposes a change; it
# never lands one. These live here rather than in settings.json's `deny` because
# `deny` is unconditional -- it would refuse the human's own commits too, and a
# deny is a hard refusal with no prompt. Gated on TASK_TOUCHES like everything
# else in this hook, so interactive sessions keep working.
# The flag prefix must swallow flags that take a separate argument -- `git -C
# /elsewhere push` is a push, and an earlier form of this pattern let it through.
_GIT_FLAGS = r"(?:-{1,2}\S+(?:[=\s]+\S+)?\s+)*"
FORBIDDEN_GIT = re.compile(
    rf"\bgit\s+{_GIT_FLAGS}(commit|merge|push|rebase|cherry-pick|clean)\b"
    rf"|\bgit\s+{_GIT_FLAGS}reset\s+.*--hard"
    rf"|\bgit\s+{_GIT_FLAGS}checkout\s+--\s"
)


def _load_protected(root):
    """Read the repo's protected patterns. Returns None if undeclared."""
    path = root / PROTECTED_FILE
    if not path.is_file():
        return None
    pats = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            pats.append(line)
    return pats


def _protected(rel, patterns):
    """True if a repo-relative POSIX path is protected."""
    name = rel.rsplit("/", 1)[-1]
    for pat in patterns:
        pat = pat.rstrip("/")
        # directory prefix: "tests" protects "tests/expected/x.status"
        if rel == pat or rel.startswith(pat + "/"):
            return True
        # glob against the full relative path, and against the dir-contents form
        if fnmatch.fnmatch(rel, pat) or fnmatch.fnmatch(rel, pat + "/*"):
            return True
        # a bare filename pattern protects that file anywhere in the tree --
        # finding_library.json really lives at pipeline/contract_v2/, not root
        if "/" not in pat and fnmatch.fnmatch(name, pat):
            return True
    return False


def _refuse(msg):
    print(msg, file=sys.stderr)
    sys.exit(2)


def main():
    declared = os.environ.get("TASK_TOUCHES")
    if not declared:
        sys.exit(0)                      # not a dispatched build; stay out of the way

    try:
        payload = json.load(sys.stdin)
    except Exception:
        sys.exit(0)                      # never block on a malformed payload

    tool_input = payload.get("tool_input") or {}

    if payload.get("tool_name") == "Bash":
        verb = FORBIDDEN_GIT.search(tool_input.get("command", "") or "")
        if verb:
            _refuse(
                f"Refused: `{verb.group(0).strip()}` is not a builder's to run. "
                f"Leave the work in the tree and report what you changed; the "
                f"dispatcher commits, merges and pushes after review. Rewriting or "
                f"publishing history from inside a task destroys the reviewable diff."
            )
        sys.exit(0)

    target = tool_input.get("file_path")
    if not target:
        sys.exit(0)

    root = Path(os.environ.get("CLAUDE_PROJECT_DIR", ".")).resolve()

    patterns = _load_protected(root)
    if patterns is None:
        _refuse(
            f"Refused: this repo declares no {PROTECTED_FILE}, so the scope guard "
            f"cannot tell which files are shared surfaces. Add it before dispatching "
            f"builds here. Refusing rather than allowing an unguarded write."
        )

    try:
        rel = Path(target).resolve().relative_to(root).as_posix()
    except ValueError:
        _refuse(f"Refused: {target} is outside the project root.")

    if _protected(rel, patterns):
        _refuse(
            f"Refused: {rel} is protected. Tests, fixtures, generated output, and "
            f"project rules are written by the spec author and are not yours to "
            f"change. If the test is wrong, that is an escalation, not an edit."
        )

    allowed = [t.strip() for t in declared.split(",") if t.strip()]
    if not any(rel == a or fnmatch.fnmatch(rel, a) for a in allowed):
        _refuse(
            f"Refused: {rel} is not in this task's declared scope.\n"
            f"You may write only: {', '.join(allowed)}\n"
            f"Other builders own the rest of the tree right now. If the task cannot "
            f"be completed within these files, stop and say so."
        )

    sys.exit(0)


if __name__ == "__main__":
    main()
