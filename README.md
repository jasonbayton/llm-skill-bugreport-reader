# Android Enterprise bug-report analysis skill

> **Under active testing — not production-ready.** This skill is still being tested and refined. Diagnostic accuracy and reliability have not yet been established for production use. Review findings against the original evidence; passing automated tests does not guarantee a correct diagnosis.

A reusable, evidence-first **end-to-end diagnostic** skill for Android bugreport ZIP/TXT archives. It reconstructs enterprise management and device state, follows an incident across processes and framework services, tests competing causal hypotheses and determines the earliest supported root cause. When the evidence is incomplete, it reports the first demonstrated failing boundary and the smallest decisive next test. It does not invent causes from noisy log messages. Triage signatures and playbooks are search aids: an unindexed symptom is investigated through its app, framework and vendor components using service dumps, process logs and properties.

## Structure

- `SKILL.md` - skill metadata and mandatory workflow.
- `references/` - mandatory root-cause reasoning engine, reconnaissance, timeline method, focused playbooks, signal catalogue and response format.
- `scripts/triage.py` - standard-library-only, read-only report triage (ZIP, TXT, directory), redacted by default.
- `scripts/context.py` - targeted regex, literal or exact-line lookup with surrounding lines and a bounded match count.
- `scripts/compare.py` - changes in observed properties, owner/lock-task snapshots and diagnostic signature counts across two reports.
- `scripts/package_state.py` - exact package blocks, their own user rows, and active versus factory-copy subsection labels.
- `scripts/incident_time.py` - per-member clock inventory and conservative UTC incident alignment.
- `scripts/evidence_context.py` - section, buffer, chronology and package-scope annotations shared by the readers.
- `scripts/report_io.py` - bounded text/archive reading, coverage accounting and best-effort redaction.
- `scripts/overview.py` - symptom-free management, policy, per-user app and health inventory, with optional JSON/HTML output.
- `scripts/overview_html.py` - offline, script-free HTML presentation with source evidence and coverage details.
- `scripts/overview_charts.py` - source-backed battery, memory, storage and per-user app charts.
- `references/overview.md` - supported overview fields, evidence semantics and health limitations.
- `references/capture-recipes.md` - concrete follow-up captures and expected confirming evidence.
- `tests/` - synthetic tests and example report fragments.
- `evals/` - synthetic diagnosis scenarios and a separate semantic scoring rubric.

## Quick start

Resolve the actual skill directory first. In the examples below, set `SKILL_BASE` to the absolute directory containing this README (for example, `$HOME/.codex/skills/android-enterprise-bugreport` for Codex or `$HOME/.claude/skills/android-enterprise-bugreport` for Claude Code). REPORT/BEFORE/AFTER and output paths should refer to the case workspace; do not change the working directory just to find the scripts.

```sh
python3 "$SKILL_BASE/scripts/triage.py" /path/to/bugreport.zip --focus provisioning
python3 "$SKILL_BASE/scripts/triage.py" /path/to/bugreport.zip --focus kiosk --package com.example.app --incident '2026-01-01T14:30:00' --minutes 10
python3 "$SKILL_BASE/scripts/triage.py" /path/to/bugreport.zip --json /tmp/triage.json
python3 "$SKILL_BASE/scripts/compare.py" /path/to/before.zip /path/to/after.zip
python3 "$SKILL_BASE/scripts/context.py" /path/to/bugreport.zip --pattern 'STATUS_.*NOT_SUPPORTED' --context 8
python3 "$SKILL_BASE/scripts/context.py" /path/to/bugreport.zip --member 'inner.zip!bugreport.txt' --line 1234 --context 10
python3 -m unittest discover -s "$SKILL_BASE/tests" -v
```

The skill instructs the assistant to **perform root-cause analysis automatically** after evidence collection. The scripts are optional accelerators, not the final answer: they cannot reliably infer causation from arbitrary log text. The assistant must resolve the timeline, test hypotheses, trace dependencies, assess contradictions and deliver a diagnosis in the same request. The default CLI masks common sensitive values in excerpts; source files are never modified. Avoid publishing unredacted output.

The helpers also support isolated Python, for example `python3 -I "$SKILL_BASE/scripts/triage.py" /path/to/bugreport.zip`. They explicitly load sibling modules only from the installed script directory, not the report or working directory. Use a trusted skill copy: [`-I`](https://docs.python.org/3/using/cmdline.html#cmdoption-I) excludes user-site packages and environment/search-path influence, but is not an operating-system sandbox and does not make arbitrary downloaded Python code safe. `incident_time.py` is a library used by triage, not a standalone analysis CLI.

## Coverage and limits

Nested ZIPs are read without extracting their members. Defaults are 600 candidates, 256 MiB per member, 768 MiB aggregate reads, three nested ZIP levels and 1 MiB per physical line. Narrow with `--member`, or deliberately increase `--max-members`, `--max-member-mib` and `--max-total-mib`. Skipped members, clipped lines, decoding replacements and null-byte lines are recorded. Null bytes in text candidates render as `[NUL]` without discarding the rest of a valid report. Known binary formats are excluded; mixed binary sections in text candidates still need interpretation.

The JSON `coverage` object is part of the evidence. A complete scan means selected text candidates were read; it does not prove all relevant events were captured. First/last examples and hit-limited context are samples. Separate nested captures before drawing causal conclusions, and identify renamed duplicates by hash. Counts can include repeated copies of the same log event.

## Device overview and HTML

Ask the assistant to **analyse this device** for a management/health overview without inventing a symptom. Add **generate an HTML report** for a shareable local overview, or ask for it alongside a diagnosis. Direct usage:

```sh
python3 -I "$SKILL_BASE/scripts/overview.py" /path/to/report.zip --html /absolute/case/device.html --json /absolute/case/device.json
```

Omit both output flags for a text overview. The HTML includes owner/admin records and organization-owned flags, user/profile topology, recorded camera/password/kiosk/logging fields, effective user-restriction-cache observations, app states by user, build/security properties, and supported battery, memory, storage, uptime and thermal observations. Every row has a source pointer. Text sources and factory app copies remain separate. Missing or conflicting data stays visible; no overall health score or production-readiness claim is generated.

The HTML leads with a visual summary: battery charge, RAM, free storage and app counts by user. Detailed readings and source lines expand underneath. Charts show captured values with units and denominators; missing or conflicting values aren't guessed. It is standalone, responsive, printable and contains no JavaScript or external assets. Generated reports omit development-status banners. User display names and serial properties are omitted; remaining content may still be sensitive. Read [overview coverage and limits](references/overview.md) before interpreting unsupported/OEM fields, policy enforcement or battery wear. This is not a replacement for Battery Historian or a time-series power profiler.

## Diagnostic helper behaviour

Identical nested ZIPs are counted once by SHA-256 (aliases listed in `duplicate_archives`); a member-filtered scan can select any alias. Mac resource-fork entries are ignored as metadata. Distinct property/snapshot sources populate `captures`, and `multiple_capture_sources` suppresses a misleading combined device profile/current snapshot. The comparison helper requires one such source per input. Repeated log buffers inside a capture are not automatically deduplicated.

Explicit lock-task denial, native tombstone and managed-account sync signals have their own groups. Quoted JSON installation-failure fields are recognized. Necessary-literal prefilters accelerate regex matching, with the original regex retained as the decision and a fallback for non-ASCII lines. These changes improve discovery; none turns a signal count into a diagnosis.

Dated DropBox crash/ANR entries, Flutter DNS failures, policy-response timeouts and native allocation failures are also indexed. The reader discloses recognized dry-run ZIP placeholders and explicit source truncation markers. Neither a dry run nor an already-truncated capture supports a clean negative finding.

`--focus auto` searches every signature with its base weight. A named focus adds a ranking boost to that category; it does not filter out other categories or choose a root cause. Incident and package matches also affect ranking.

`--incident` defaults to device-local time without an offset. With `--utc`, a naive incident is UTC and an offset-aware incident is normalized to UTC. Explicit event offsets take precedence. Local log times use each member's `persist.sys.timezone` (IANA rules at the event date); a numeric dumpstate-header offset is only a fixed-offset inference. Conflicting zones/header offsets, unknown zones, ambiguous daylight-saving folds and nonexistent local times remain unresolved (`incident_window: null`). Capture timezone may not reflect the historical timezone. Use `--timezone Europe/London --utc` only when independently known. Yearless events still infer the nearest year. The clock inventory requires a separate bounded pass and exposes its own coverage. An incomplete prepass may omit clock evidence, so review both passes before any negative claim.

Examples:
```sh
python3 "$SKILL_BASE/scripts/triage.py" /absolute/case/report.zip --incident '2026-07-01T11:00:00Z' --utc
python3 "$SKILL_BASE/scripts/package_state.py" /absolute/case/report.zip com.example.app --uid 1012345
```

Every retained triage/context hit includes section, kind, buffer, timeline segment and boot confidence. Signal counts also expose occurrences_by_kind so snapshot and historical matches are not silently one undifferentiated total. Unknown sections stay unknown. Timestamped log records inside a service dump remain logs. Source/section/buffer switches separate chronology and reset carried boot context. Explicit boot IDs can identify a boot; boot-completed markers and uptime decreases are only candidates. Backward wall clocks split segments without proving reboot. Retained crash/ANR records start their own segments. Boundary samples are capped at 1000 with a total count; evidence annotations continue beyond that cap. These are conservative textual heuristics, not a complete Android boot-history parser.

`package_state.py REPORT PACKAGE` returns each exact Package block separately, its version/installer metadata and its own User rows. `package_subsection` distinguishes `Packages` from `Hidden system packages`; `package_state_kind` labels the latter as `factory_system_image_copy`, not current installed state. Missing subsection headers stay unknown. Triage and context share these package-scope annotations, including in Markdown, so user rows cannot silently borrow another package's identity. It stops at another package, source, section or block boundary. Missing fields remain absent; raw `enabled=0` is not interpreted as disabled. Package-level `userId` can be an app ID, so only `--uid` explicitly applies full UID arithmetic. A shared/isolated UID does not identify a unique app. No missing block proves uninstallation. [AOSP UserHandle](https://android.googlesource.com/platform/frameworks/base/+/refs/heads/main/core/java/android/os/UserHandle.java) defines the 100000 per-user range.

JSON/Markdown output paths must be new files outside an input directory. Existing files and report inputs are protected from overwrite. Redaction masks common credentials and identifiers, but is best-effort; paths and unrecognised formats may remain private. The comparison helper covers selected properties, owner/user/lock-task clues and signature counts, not a full policy or package diff.

## Installation

Clone this repository into a new `android-enterprise-bugreport` directory in your assistant's skills directory. Choose the command for your assistant:

```sh
# Claude Code
git clone https://github.com/jasonbayton/llm-skill-bugreport-reader.git "$HOME/.claude/skills/android-enterprise-bugreport"

# Codex
git clone https://github.com/jasonbayton/llm-skill-bugreport-reader.git "$HOME/.codex/skills/android-enterprise-bugreport"
```

If that directory already exists, preserve any local changes before updating it. For other skill-enabled assistants, install the directory containing `SKILL.md` using the platform's supported mechanism. The analysis scripts need Python 3.10 or newer and system IANA timezone data for named-zone UTC alignment; they use no third-party Python libraries.

For direct command-line use, clone into any directory and set `SKILL_BASE` to its absolute path. The repository's name can differ from the skill's name.

## Development and privacy

Run `python3 -m unittest discover -s tests -v` from the repository root. The suite has 117 automated parser and behavior tests. The four diagnosis scenarios have been run blind against the current fixtures and rubric once per case, with all four passing; a separate draft set of four larger synthetic cases passed three of four. Both runs were scored by their operator on one model, before the device overview was added; they are not independently audited or evidence of production accuracy, and the overview has not been model-evaluated. See [evaluation limits](evals/README.md).

Keep real bugreports, customer data, generated analysis and credentials outside this repository. Test fixtures must be synthetic, using invented identifiers and example domains. When reporting a problem, provide a minimal synthetic reproduction; do not attach a real diagnostic archive. The ignore rules are only a convenience and do not replace reviewing what is committed.

## Scope

The skill is generic. It contains no references to previous cases, conversations, individuals, organisations, device models or customer environments. Future submitted reports may of course include identifiers needed to diagnose that specific submission; handle them as sensitive case data.

For command capture recipes see [capture-recipes.md](references/capture-recipes.md). For diagnosis evaluations, see [evals/README.md](evals/README.md); unit-test passes are not a diagnosis benchmark.
