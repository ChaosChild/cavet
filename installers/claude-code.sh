#!/usr/bin/env bash
# cavet installer - Claude Code (reference implementation)
# Copies the six cavet-* skills, writes the cavet-security subagent, and
# appends the instruction snippet to the user instruction file. Idempotent.
# Uninstall: delete cavet-* from the skills dir, the subagent file, and the
# snippet from the instruction file.
#
# Paths (verified 2026-08, sources in installers/README.md):
#   skills        ~/.claude/skills/                     (user level, flat)
#   subagent      ~/.claude/agents/cavet-security.md    (YAML frontmatter)
#   instructions  ~/.claude/CLAUDE.md                   (user memory)
# Claude Code's `tools:` field cannot scope Bash to one binary, so the
# cavet-only shell restriction is restated in the subagent body.
#
# --target <dir> (or env CAVET_INSTALL_TARGET) redirects ALL writes under
# <dir> instead of the real harness home, for testing.

set -euo pipefail

REPO=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
SKILL_NAMES="cavet-deployment cavet-design cavet-design-review cavet-secure-coding cavet-supply-chain cavet-triage"
MARKER='Security runs through cavet'
SNIPPET=$(cat <<'CAVET_SNIPPET'
Security runs through cavet. Six skills cover the whole path: cavet-design,
cavet-design-review, cavet-supply-chain, cavet-secure-coding, cavet-deployment,
cavet-triage. Each skill's description states exactly when it fires; when the
current task matches one, load that skill and follow it. Do not improvise your
own security review, and do not skip a matching skill because the task looks
safe: recognising what is security-relevant is what the skills are for. The
skills advise, never block; the operator decides. Before scanning, check
`cavet log --since`: a recorded scan may already cover the current state.
Never write to .cavet/ directly: the cavet CLI is the only author of its log.
CAVET_SNIPPET
)
OLD_SNIPPET='Security is part of design, not a phase after it. When we discuss architecture,
features, integrations, data flows, auth, or third-party services, surface security
implications alongside functional ones — one line, at the decision point, via the
cavet-design skill. When code is written, apply cavet-secure-coding. Before commit
or on request, run cavet-triage. Never write to .cavet/ directly; the cavet CLI is
the only author of its log.'

TARGET="${CAVET_INSTALL_TARGET:-}"
while [ $# -gt 0 ]; do
  case "$1" in
    --target) TARGET="${2:?--target needs a value}"; shift 2 ;;
    --target=*) TARGET="${1#--target=}"; shift ;;
    *) echo "unknown argument: $1 (usage: $0 [--target <dir>])" >&2; exit 2 ;;
  esac
done

# 1. resolve roots: real harness home, or the test target
if [ -n "$TARGET" ]; then HARNESS_HOME=$TARGET; else HARNESS_HOME=$HOME/.claude; fi
SKILLS_DIR=$HARNESS_HOME/skills
AGENTS_DIR=$HARNESS_HOME/agents
INSTR_FILE=$HARNESS_HOME/CLAUDE.md

# 2. copy the six skills (overwrite = remove then copy; uninstall = delete cavet-*)
mkdir -p "$SKILLS_DIR"
for name in $SKILL_NAMES; do
  src="$REPO/skills/$name"
  [ -d "$src" ] || { echo "missing skill source: $src" >&2; exit 1; }
  rm -rf "${SKILLS_DIR:?}/$name"
  cp -R "$src" "$SKILLS_DIR/$name"
done

# 3. write the subagent in harness format
mkdir -p "$AGENTS_DIR"
cat > "$AGENTS_DIR/cavet-security.md" <<'EOF'
---
name: cavet-security
description: Runs a cavet security scan for the given scope and phase, triages every finding, and returns the CLI's structured output verbatim. Use for review-time scans and pre-commit triage.
tools: Read, Bash
---

You are the cavet security subagent. You have read access to the repository and
the `cavet` command, and nothing else — by design. Your job is triage and
deduplication, not narration and not remediation. Run the scan for the scope and
phase you were given. For each finding, read the code, decide confirmed or
dismissed, and record it with `cavet triage` with a specific reason and a
confidence. For dependency findings, `cavet lookup` the identifiers first and cite
them in your reason. If a finding turns on a question you cannot answer from code
or advisories, mark it confirmed with low confidence, raise a verification item
with `cavet raise`, and include the question in a `verify` block. Reply with the
CLI's aggregate line, table, next-step hints, and verify block, verbatim. Nothing
else. Follow the `cavet-triage` skill's subagent section.

Shell restriction: only commands that invoke the `cavet` binary. No file writes,
no web, nothing else.

Input (from parent):

    scope: staged | diff <ref> | full | path <p>
    phase: build | test | deploy
    context: <optional, a few lines: files not to touch, prior decisions, intent>

Output (to parent) — exactly this, nothing else:

    <CLI aggregate line>
    <CLI findings table — confirmed only>
    <CLI next: hints>
    verify[n]{id,question}:        # only if any raised
      <id>,<question>
EOF

# 4. instruction snippet: skip if current, replace the old text, else append
INSTR_CONTENT=''
if [ -f "$INSTR_FILE" ]; then
  INSTR_CONTENT=$(cat "$INSTR_FILE" && printf x)
  INSTR_CONTENT=${INSTR_CONTENT%x}
fi
case "$INSTR_CONTENT" in
  *"$MARKER"*) INSTR_ACTION='already present' ;;
  *"$OLD_SNIPPET"*)
    printf '%s' "${INSTR_CONTENT//"$OLD_SNIPPET"/"$SNIPPET"}" > "$INSTR_FILE"
    INSTR_ACTION='upgraded' ;;
  *)
    printf '\n%s\n' "$SNIPPET" >> "$INSTR_FILE"
    INSTR_ACTION='appended' ;;
esac

# 5. summary
echo 'cavet -> Claude Code'
echo "  skills       : $SKILLS_DIR (6 cavet-* dirs)"
echo "  subagent     : $AGENTS_DIR/cavet-security.md"
echo "  instructions : $INSTR_FILE ($INSTR_ACTION)"
