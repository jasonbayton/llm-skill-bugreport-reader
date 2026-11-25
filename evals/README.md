# Diagnosis evaluations

These four synthetic cases test conclusions and evidence discipline, not just parsing. Cases cover unsupported provisioning, a suspended work-user browser with a later contradictory snapshot, a pending update with an older installed version, and an active call with rejected UI. No real customer data is included.

Prepare an isolated run from any working directory:

```sh
python3 "$SKILL_BASE/evals/prepare.py" --skill "$SKILL_BASE" --out /absolute/new-eval-run
```

The preparer copies the skill's instructions, README, helpers, references and optional agents/assets into the run's `skill/` directory. It excludes `evals/`, `tests/`, Git metadata and Python caches, and removes development/evaluation pointers from the copied instructions and README. Every request points at this copy, never the original skill directory. Case directories use neutral numbers so their names do not reveal expected diagnoses. The coordinator's `requests.json` retains case IDs for scoring; do not give that index to evaluators. Symlinked resources are rejected. Keep the run outside the source skill.

For each case, give a fresh evaluator only its request.txt, raw report and the copied `skill/` directory. Do not mount or otherwise expose the original repository, rubric.json, other answers or prior diagnoses. Copying files is not an operating-system access restriction: a process with access to the original repository can still read it. Ask for the finished answer, not merely helper output. Use an independent agent only when delegation is authorized. This preparer does not start agents or make network requests.

Freeze answers before opening rubric.json. A human or independently authorized judge should score each criterion and verify the cited lines against the raw fixture. Record answer path, model/version, skill file hashes, pass/fail per criterion, forbidden claims, elapsed time and tool usage. A case passes only when all criteria pass and no forbidden claim is present. Do not score on exact wording.

To compare wording changes, use the same requests, artifacts and model/settings in separate baseline and candidate runs, ideally repeated; label judge uncertainty. Keep expected answers out of both runs. Four cases are a small regression set, not broad accuracy measurement. Parser tests, helper runs, a rubric written by the author, and a self-reviewed diagnosis are not a blind independent benchmark. Store run artifacts in the case workspace, outside the installed skill.
