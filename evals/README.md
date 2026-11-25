# Diagnosis evaluations

These four synthetic cases test conclusions and evidence discipline, not just parsing. Cases cover unsupported provisioning, a suspended work-user browser with a later contradictory snapshot, a pending update with an older installed version, and an active call with rejected UI. No real customer data is included.

## Results and limits

One run of the earlier fixtures was reported on 25 November 2026: four fresh model sessions, four criteria passed per case, and no old-rubric forbidden claims. The operator reported freezing answer hashes before scoring and checking every cited line. The same operator judged the answers, with one run per case on one model; the answer artifacts, hashes and exact model version are not included here, so these results have not been independently audited. Helpers were not used. One answer reportedly prescribed AMAPI `installType: KIOSK` for a secondary dialer, an incorrect policy recommendation that the old rubric did not catch. An old-rubric pass was therefore not a fully correct answer.

Current fixtures remove explicit distractor labels and fabricated IDs shared across unrelated components. Component-owned identifiers, such as a Telecom call ID or AMAPI command ID, remain where useful. The call/UI rubric now checks concrete policy advice and rejects treating `KIOSK` designation as a secondary-app allowlist.

The revised fixtures and rubric were run once on 25 November 2026 against the skill at commit 86a3732: four fresh model sessions given only the prepared request, report and rubric-free skill copy, with answer hashes frozen before scoring and every cited line checked. All four cases passed every criterion with no forbidden claims; the call/UI answer explicitly warned against `installType: KIOSK` for the dialer. Helpers were used in one case. One answer overstated a negative (calling the personal user "never suspended" from a capture-time snapshot and a missing log line), which the rubric does not check.

A separate draft set of four larger synthetic cases (1,300–8,000 lines, one nested ZIP, non-UTC devices, a correct "not established" result) was run the same way and is not included in this repository. Three of four passed under a strict reading; the failing answer labelled an inferred design flaw as part of a confirmed cause. Helpers ran in all four. The same pattern of stating an inference or absence as fact appeared in two other answers outside rubric criteria.

Both runs used one model with one run per case, and were scored by the operator who wrote the fixtures, so they are not independent. They predate the device overview, which has not been model-evaluated.

The reports remain only 11–16 lines long. They are reasoning smoke tests, not a tooling or realistic-correlation benchmark. A stronger future suite needs longer interleaved captures, multiple users/attempts, missing links, ordinary unlabeled noise and evidence across sections/members. Record whether helpers actually ran, how their output affected the answer and whether the proposed fix uses documented policy semantics. Include cases whose correct result is insufficient evidence. Repeated runs and an independent judge are still needed before making accuracy or production-readiness claims.

## Run preparation

Prepare an isolated run from any working directory:

```sh
python3 "$SKILL_BASE/evals/prepare.py" --skill "$SKILL_BASE" --out /absolute/new-eval-run
```

The preparer copies the skill's instructions, README, helpers, references and optional agents/assets into the run's `skill/` directory. It excludes `evals/`, `tests/`, Git metadata and Python caches, and removes development/evaluation pointers from the copied instructions and README. Every request points at this copy, never the original skill directory. Case directories use neutral numbers so their names do not reveal expected diagnoses. The coordinator's `requests.json` retains case IDs for scoring; do not give that index to evaluators. Symlinked resources are rejected. Keep the run outside the source skill.

For each case, give a fresh evaluator only its request.txt, raw report and the copied `skill/` directory. Do not mount or otherwise expose the original repository, rubric.json, other answers or prior diagnoses. Copying files is not an operating-system access restriction: a process with access to the original repository can still read it. Ask for the finished answer, not merely helper output. Use an independent agent only when delegation is authorized. This preparer does not start agents or make network requests.

Freeze answers before opening rubric.json. A human or independently authorized judge should score each criterion and verify the cited lines against the raw fixture. Record answer path, model/version, skill file hashes, pass/fail per criterion, forbidden claims, elapsed time and tool usage. A case passes only when all criteria pass and no forbidden claim is present. Do not score on exact wording.

To compare wording changes, use the same requests, artifacts and model/settings in separate baseline and candidate runs, ideally repeated; label judge uncertainty. Keep expected answers out of both runs. Four cases are a small regression set, not broad accuracy measurement. Parser tests, helper runs, a rubric written by the author, and a self-reviewed diagnosis are not a blind independent benchmark. Store run artifacts in the case workspace, outside the installed skill.
