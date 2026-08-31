#!/usr/bin/env bash
# cavet installer - DeepSeek Harness (dsh)
# Copies the six cavet-* skills, writes the translated cavet-security
# definition, and appends the instruction snippet to the user-global
# instruction file. Idempotent. Uninstall: delete cavet-* from the skills dir,
# the definition file, and the snippet from the instruction file.
#
# Paths (verified 2026-08, sources in installers/README.md):
#   skills        $DSH_HOME/skills/                   (user root, flat; default ~/.dsh)
#   subagent      $DSH_HOME/cavet-security.md         (documented file, see note)
#   instructions  $DSH_HOME/AGENTS.md                 (user-global instruction file)
# limitation: dsh subagents are created at call time (delegation via the
# subagent tool), not by files; tool restriction is a per-request `toolFilter`
# on the delegation. The translated definition is a documented file; paste its
# body into the delegation and restrict the child's tools there to Read +
# shell scoped to `cavet`.
# note: dsh also scans ~/.agents/skills (after $DSH_HOME/skills), so cavet
# skills installed for codex/pi are discoverable too; this installer writes the
# dsh-native root, which dsh scans first.
#
# --target <dir> (or env CAVET_INSTALL_TARGET) redirects ALL writes under
# <dir> instead of the real harness home, for testing.

set -euo pipefail

REPO=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
SKILL_NAMES="cavet-deployment cavet-design cavet-design-review cavet-secure-coding cavet-supply-chain cavet-triage"
MARKER='Never write to .cavet/ directly'
SNIPPET='Security is part of design, not a phase after it. When we discuss architecture,
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
DSH_HOME="${DSH_HOME:-$HOME/.dsh}"
if [ -n "$TARGET" ]; then HARNESS_HOME=$TARGET; else HARNESS_HOME=$DSH_HOME; fi
SKILLS_DIR=$HARNESS_HOME/skills
INSTR_FILE=$HARNESS_HOME/AGENTS.md

# 2. copy the six skills (overwrite = remove then copy; uninstall = delete cavet-*)
mkdir -p "$SKILLS_DIR"
for name in $SKILL_NAMES; do
  src="$REPO/skills/$name"
  [ -d "$src" ] || { echo "missing skill source: $src" >&2; exit 1; }
  rm -rf "${SKILLS_DIR:?}/$name"
  cp -R "$src" "$SKILLS_DIR/$name"
done

# 3. write the subagent definition as a documented file
mkdir -p "$HARNESS_HOME"
cat > "$HARNESS_HOME/cavet-security.md" <<'EOF'
# cavet-security subagent definition
# (translated from the "Subagent role" section of skills/cavet-triage/SKILL.md)

dsh subagents are created at call time via delegation; there is no definition
file format (verified 2026-08). Tool restriction is a per-request `toolFilter`
on the delegation. This file is the documented source for the subagent prompt.
To use it, paste the body below into the delegation request and set the child's
toolFilter to Read (repository files) + shell scoped to the `cavet` binary.
Nothing else.

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

# 4. append the instruction snippet, idempotently
if [ -f "$INSTR_FILE" ] && grep -qF "$MARKER" "$INSTR_FILE"; then
  INSTR_ACTION='already present'
else
  printf '\n%s\n' "$SNIPPET" >> "$INSTR_FILE"
  INSTR_ACTION='appended'
fi

# 5. summary
echo 'cavet -> DeepSeek Harness (dsh)'
echo "  skills       : $SKILLS_DIR (6 cavet-* dirs)"
echo "  subagent     : $HARNESS_HOME/cavet-security.md (documented file; dsh subagents are call-time)"
echo "  instructions : $INSTR_FILE ($INSTR_ACTION)"
