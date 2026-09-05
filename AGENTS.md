# v6 work continuity

Before changes, exact-check remote branch/HEAD and reread the affected current
source. Read `progress.md`, `V6_BACKLOG.md`, `V6_HELP_BACKLOG.md`,
`V6_SENSOR_ENRICHMENT_BACKLOG.md`, `V6_PROTOCOL_INTEGRATION_MATRIX.md` and
`V6_CORE_CONTRACTS.md` and `V6_STATE_BUDGETS.md`. Preserve parallel changes.
Announce any new branch first.

Follow the update/completion rules in `progress.md`. Update it when a task is
finished and before every handoff, including blockers, test evidence and next step.
Never check a task complete merely because code exists or a standalone test passes.
Keep staging parsers runtime-isolated until the core-contract readiness review.

Keep completed history high-level. When checking a task, collapse obsolete working
notes to one outcome and evidence reference; carry every unresolved acceptance
criterion into an open task. Reconcile new backlog requirements into the coverage
map, then proceed to the next dependency-safe step. Never delete unmet work to
make progress look shorter.
