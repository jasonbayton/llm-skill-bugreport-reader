# Diagnostic output format

Write the top line immediately after finding decisive evidence. Keep the first response concise; attach expanded findings only if useful.

## Confidence definitions

- Confirmed: a coherent operation-specific causal sequence or authoritative decision, with material contradictions resolved.
- Probable: strong support, but a necessary causal link is unavailable.
- Possible: compatible with the evidence; meaningful alternatives remain.
- Not established: the evidence does not identify a credible cause. Still report any observed failing boundary.
- Contradicted: affirmative evidence conflicts with the proposed mechanism; silence alone is not contradiction.

## Diagnosis

**[Confirmed / Probable / Possible / Not established / Contradicted]** One or two sentences describing the actual failure boundary and (when supported) root cause. Avoid attributing causation to a generic exception without a linked operation.

## Decisive evidence

| Source/time | Observation | Why it matters |
|---|---|---|
| `report.txt:1234`, `MM-DD HH:MM:SS` | Short redacted excerpt | Causal implication |

List the strongest 1–3 first. Add a short chronological chain if it clarifies a multi-service failure.

## Device / management context

- Android/API and features relevant to the issue; ownership/profile/user; relevant DPC role, effective restrictions, lock-task at **incident** vs **capture**, package and dependent role states.
- Clearly mark **not established** values. Do not print unrelated identifiers, account details, location or unique device IDs.

## Important alternatives or negative findings

- What the search does and does not rule out; competing hypotheses; missing buffers/windows; whether a supposed failure was in fact successful.

## Next action

- **Change or test:** one feasible controlled step for the observed management mode and OS.
- **Verify:** exact expected log/service state or user-visible transition.
- **If unresolved:** smallest additional bugreport/log capture needed and an approximate reproduction timestamp.

If the cause is unknown, say so in the headline, but still provide the strongest observed issue boundary and targeted next test. Do not label a plausible cause as confirmed just to sound decisive.

Use [capture-recipes.md](capture-recipes.md) for concrete follow-ups. Preserve section/kind, user and chronology provenance when it changes the conclusion; do not turn a candidate boot epoch into a factual reboot.

## Device overview without a reported symptom

Use an overview rather than the incident/root-cause structure above. Lead with what the capture establishes about the device, then summarise ownership and organization-owned flags, user/profile boundaries, recorded policy versus effective restrictions, per-user app state, build/security properties and available health observations. Include source/line evidence and material gaps. Do not classify the device as unmanaged, unrestricted or healthy merely because a field is absent. Do not invent a failure or root cause. Suggest a targeted follow-up only for a material unanswered question.

When requested, deliver a link to the offline HTML from `overview.py`, with a short summary of the main observations and limitations. It may supplement a symptom-led diagnosis. Verify that the HTML is from the intended source/member and that any truncation/conflicts are disclosed. A generated inventory is a starting point for interpretation, not a compliance certificate.
