---
name: cavet-design-review
description: Full security sweep of a design at the moment it is being finalised, agreed, written up, or handed to build — "let's go with this", "write the design doc", "ready to implement", an ADR or spec being completed, a plan being approved. Use even if security was discussed during the design conversation; the review exists because conversational flags are probabilistic and things get deprioritised mid-flow. Produces the threat model and decision records.
---

# cavet-design-review

The checkpoint. Conversational flagging (`cavet-design`) is probabilistic; this is
the deterministic pass at the door between design and build. It exists to catch two
things: what was raised and then forgotten, and what was never raised at all.

## Procedure

1. **Read the open items first.** Run `cavet items`. This is not optional and it is
   not a formality: the review must not re-derive from the design document alone,
   because the class of thing that was raised, correctly deprioritised, and then
   forgotten is invisible in the document.
2. **Tier 1 — raised and unresolved.** For each open design item: restate the
   concern, the operator's stated reason for deferring (from the item), and whether
   the finalised design changes that calculus. Ranked above everything else.
3. **Tier 2 — never raised.** Sweep the finalised design against
   `references/checklist.md`. Report only gaps that are not already open items.
4. **Present both tiers**, tier 1 first, as tables (format below).
5. **Record decisions.** For each item the operator decides: run `cavet resolve`
   with the decision (accept risk / mitigate how / out of scope why). Items the
   operator defers again stay open with the new reason via the CLI. Do not close an
   item on your own judgement.
6. **Write the artefacts.** Update `.cavet/design/threat-model.md` and add one file
   per non-trivial decision under `.cavet/design/decisions/`. Templates in
   `references/templates.md`. These are what make build-phase findings interpretable
   later ("we accepted this because…"), so they carry reasoning, not just outcomes.

## Output format

```
design review · <design name> · <n> open items · <m> new gaps

## Raised and unresolved
| item | concern | your reason at the time | still holds? |
|------|---------|--------------------------|--------------|

## Not previously raised
| # | area | gap | consequence |
|---|------|-----|-------------|
```

Then: for each row, one line of recommended disposition. No essay. Full rationale
on request only (`cavet-design/references/rationale.md` has the common ones).

## Calibration

- A gap is something the design *does not address*, not something it addresses
  differently from how you would.
- Do not pad tier 2 to look thorough. An empty tier 2 is a good result and should
  be said plainly: "no additional gaps".
- If the design is too thin to review ("we'll figure out auth later"), say that as
  one tier-2 row rather than inventing detail.
