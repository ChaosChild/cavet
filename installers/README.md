# cavet installers

One installer per harness, in two shells (`.ps1` for pwsh, `.sh` for bash).
Each does the same five things, in the same order:

1. resolve roots (real harness home, or a test target — see below),
2. copy the six `cavet-*` skill directories from `skills/` as loose
   directories under the harness's skills path (flat namespace, overwrite on
   re-run; uninstall = delete `cavet-*`),
3. translate the subagent contract from the "Subagent role" section of
   `skills/cavet-triage/SKILL.md` into the harness's subagent/agent
   format, tool allowlist = Read + shell scoped to `cavet`,
4. append the instruction snippet from `docs/install-notes.md` to the
   harness's instruction file, idempotently (skip if
   `Never write to .cavet/ directly` is already present),
5. print a summary of the paths written.

## Path table (verified 2026-08)

| Harness | Skills | Subagent | Instruction file |
|---|---|---|---|
| Claude Code | `~/.claude/skills/` | `~/.claude/agents/cavet-security.md` — YAML frontmatter | `~/.claude/CLAUDE.md` |
| ZCode | `~/.zcode/skills/` | `~/.zcode/agents/cavet-security.md` — YAML frontmatter | `~/.zcode/AGENTS.md` |
| Codex | `~/.agents/skills/` | `$CODEX_HOME/agents/cavet-security.toml` — TOML (`name`, `description`, `sandbox_mode`, `developer_instructions`); `$CODEX_HOME` defaults to `~/.codex` | `$CODEX_HOME/AGENTS.md` |
| OpenCode | `$XDG_CONFIG_HOME/opencode/skills/` (default `~/.config/opencode/skills/`) | `<config>/agents/cavet-security.md` — YAML frontmatter with `permission` | `<config>/AGENTS.md` |
| pi (+ omp family) | `~/.agents/skills/` | `~/.pi/agent/cavet-security.md` — documented file (see limitations) | `~/.pi/agent/AGENTS.md` |
| Hermes | `$HERMES_HOME/skills/` (default `~/.hermes/skills/`) | `$HERMES_HOME/cavet-security.md` — documented file (see limitations) | `./AGENTS.md` (project context file) |
| DeepSeek Harness | `$DSH_HOME/skills/` (default `~/.dsh/skills/`) | `$DSH_HOME/cavet-security.md` — documented file (see limitations) | `$DSH_HOME/AGENTS.md` |

## Tool-allowlist expression per harness

- **Claude Code**: `tools: Read, Bash` in the subagent frontmatter. The
  `tools` field cannot scope Bash to one binary, so the cavet-only shell rule
  is restated in the subagent body.
- **OpenCode**: native and exact — `permission: {edit: deny, webfetch: deny,
  bash: {"*": deny, "cavet*": allow}}` (OpenCode bash rules: last matching
  pattern wins).
- **Codex**: no per-agent tool allowlist exists; the closest native
  restriction is `sandbox_mode = "read-only"`, plus the cavet-only shell rule
  stated in `developer_instructions`. Marked `# assumption:` in the installer.
- **pi / Hermes / DeepSeek Harness**: no subagent definition-file surface to
  hang an allowlist on (below); the restriction travels as text in the
  documented definition file.
- **ZCode**: agent frontmatter has no documented per-agent tool allowlist;
  the cavet-only shell rule is restated in the subagent body (same approach as
  Claude Code's unscopeable `tools:` field).

## Limitations and assumptions

- **pi has no first-class subagent surface** (extensions are TypeScript
  modules; no agent-definition file format). The translated definition is a
  documented file under `~/.pi/agent/`, not auto-loaded: dispatch its body as
  a task prompt and restate the tool restriction in the dispatch.
- **pi skills path is `~/.agents/skills/`, not `~/.pi/agent/skills/`**: pi
  documents both as global skill locations; we write `~/.agents/skills/`
  because the omp family ([oh-my-pi](https://github.com/can1357/oh-my-pi))
  treats `.agents/skills` as its canonical skills location — one write covers
  pi and omp.
- **Hermes subagents are call-time** (`delegate_task` with goal + context; no
  definition file format, children inherit the parent's toolsets, no
  per-subagent allowlist). The translated definition is a documented file
  under `$HERMES_HOME`; paste its body into the delegation goal.
- **Hermes instruction file is project-level**: Hermes has no documented
  global instruction file; context files (`AGENTS.md`, `HERMES.md`) are
  per-project. The installer appends to `AGENTS.md` in the current directory.
  Marked `# assumption:` in the installer.
- **DeepSeek Harness subagents are call-time** (delegation via the subagent
  tool; no definition-file format). A per-request `toolFilter` restriction
  exists but no saved per-agent allowlist. The translated definition is a
  documented file under `$DSH_HOME`; paste its body into the delegation and
  restrict the child's tools there. Verified 2026-08 against the official
  `docs/subsystems/subagent.md`.
- **dsh also scans `~/.agents/skills`** (rank after `$DSH_HOME/skills`), so
  cavet skills installed for codex/pi are already discoverable by dsh; the
  installer writes the dsh-native root, which dsh scans first.
- **ZCode paths verified from the client's own docs and the dev machine**
  (2026-08): skills roots, user instruction file `~/.zcode/AGENTS.md`, and the
  `~/.zcode/agents/*.md` YAML-frontmatter subagent format (observed working
  user definitions). No per-agent tool allowlist is documented for it.

## Sources

- Claude Code: [skills](https://code.claude.com/docs/en/skills),
  [subagents](https://code.claude.com/docs/en/subagents),
  [.claude directory](https://code.claude.com/docs/en/claude-directory)
- Codex: [build skills](https://learn.chatgpt.com/docs/build-skills),
  [subagents](https://learn.chatgpt.com/docs/agent-configuration/subagents),
  [AGENTS.md](https://learn.chatgpt.com/docs/agent-configuration/agents-md)
- OpenCode: [skills](https://opencode.ai/docs/skills/),
  [agents](https://opencode.ai/docs/agents/),
  [rules](https://opencode.ai/docs/rules/)
- pi: [skills](https://pi.dev/docs/latest/skills),
  [usage (AGENTS.md)](https://pi.dev/docs/latest/usage);
  omp: [docs/skills.md](https://github.com/can1357/oh-my-pi/blob/main/docs/skills.md)
- Hermes: [skills](https://hermes-agent.nousresearch.com/docs/user-guide/features/skills),
  [delegation](https://hermes-agent.nousresearch.com/docs/user-guide/features/delegation),
  [which file does what](https://hermes-agent.nousresearch.com/docs/user-guide/which-file-does-what)
- ZCode: the client's bundled official `zcode-guide` plugin
  (`zcode-configuration-guide` skill — configuration scopes, skills discovery
  order, user instruction file); subagent format from working user
  definitions in `~/.zcode/agents/` on the dev machine (verified 2026-08)
- DeepSeek Harness: [skill-filesystem README](https://github.com/deepseek-ai/deepseek-harness/blob/master/packages/skill/skill-filesystem/README.md)
  (skill roots, `$DSH_HOME`), [agent-instructions README](https://github.com/deepseek-ai/deepseek-harness/blob/master/packages/context/agent-instructions/README.md)
  (`$DSH_HOME/AGENTS.md` user-global instruction file), [subagents doc](https://github.com/deepseek-ai/deepseek-harness/blob/master/docs/subsystems/subagent.md)
  (call-time delegation, per-request `toolFilter`)

## Testing without polluting real config

`.ps1`: `pwsh -NoProfile -File installers/<harness>.ps1 -Target <dir>` (or env
`CAVET_INSTALL_TARGET`). `.sh`: `bash installers/<harness>.sh --target <dir>`
(or env `CAVET_INSTALL_TARGET`). The target directory replaces every real
write location; the run is otherwise identical. Re-running against the same
target verifies idempotency: skills are replaced, the subagent file is
rewritten, the snippet is appended only once.

## Uninstall

Delete `cavet-*` from the skills directory, delete the subagent/definition
file from the table above, and remove the instruction snippet (the block
ending `... the only author of its log.`) from the instruction file.
