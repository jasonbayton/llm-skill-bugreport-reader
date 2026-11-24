# Mandatory root-cause analysis engine

The skill must **perform this reasoning automatically** after reading the submitted bug report. Do not stop at an error list, signal ranking, timeline dump, or a request for the user to interpret the evidence. Scripts only reduce searching; the assistant owns the investigation and conclusion.

## Definition of a root cause

A root cause is the earliest supported, actionable failure condition that explains the reported outcome along the same operation path. The most prominent exception is often a downstream symptom. A causal explanation must account for **what was attempted, what should have happened, which boundary first failed, what caused that failure, and what happened instead**.

A root cause may be a violated prerequisite (unsupported system feature, absent ownership, user restriction, suspended dependency), a platform decision (security or policy denial), application error (crash, bad state or corrupted data), unavailable dependency, or a genuine OS/OEM defect. It need not be a single log line.

## Investigation algorithm

Run steps 1–8 for every issue. Keep the working hypothesis table internal; publish the decisive evidence, contradictions and conclusion. Time-box *unproductive exploration* rather than stopping before testing the causal explanation.

1. **Translate the symptom into a failed transition.** Define `actor + user/profile + attempted operation + expected result + observed result + approximate window`. If no symptom is supplied, first identify meaningful anomalies and state that there is no confirmed user-visible incident to attribute.
2. **Map the execution path.** Trace at least: `originating application/component -> intent/API/IPC -> resolver/framework -> policy/capability/permission gate -> dependent service -> resulting state`. Branch as needed for install, network, boot, storage, telephony, lifecycle, or OEM paths.
3. **Locate the first divergence.** Use explicit status codes and state transitions to find the *earliest observed operation that did not complete as expected*. Distinguish a component that did not run from a component that ran and failed. A timeout is an outcome, not a root cause.
4. **Generate competing explanations.** Form up to three **mechanistic** hypotheses for that divergence. Each hypothesis must predict a discoverable status, state or transition. Prefer those supported by specific evidence over generic error frequencies. Avoid inventing a precise mechanism when the report lacks the necessary detail.
5. **Test each hypothesis against the report.** Search context around the first divergence and upstream prerequisites, using the exact user/UID, package, process, session/call/task identifier, boot and time window. Seek both supporting and **falsifying** evidence. Compare requested policy, applied policy and actual enforcement separately. Treat a snapshot as a snapshot.
6. **Trace backwards to the earliest supported blocker.** Ask: *If this condition were corrected, would the failed operation be expected to proceed?* Check that this condition existed **at the incident time** and on the same execution path. If earlier necessary conditions cannot be inspected, stop at the **first proven failure boundary** rather than claiming deeper causation.
7. **Reconcile contradictions.** Check whether the alleged failure actually succeeded (activity displayed, call reached active, installer committed, network validated, profile created). If so, revise the theory to a later stage, different user/profile, different attempt, or an application-level failure. Do not declare an Android Enterprise policy violation without a correlated enforcement decision.
8. **Decide and report.** Use the confidence definitions and response contract in [report-format.md](report-format.md). If no cause is established, give the first verified failing boundary, the strongest competing hypotheses and **one smallest targeted discriminating test**, including the exact expected evidence for each outcome.

## Hypothesis comparison (internal working structure)

For each candidate maintain:

| Field | Required value |
|---|---|
| Proposed mechanism | Condition -> platform/app decision -> symptom |
| Predicted evidence | Which specific result or transition should exist if true |
| Supporting observations | Timestamped `source:line`, relevant UID/user, package/session |
| Contrary observations | Successful transitions, inconsistent identifiers, conflicting policy state |
| Coverage | Buffers/windows actually searched; known gaps |
| Confidence | Confirmed / Probable / Possible / Not established / Contradicted |
| Next discriminator | Smallest controlled state change or trace that would prove/disprove it |

Never present a numerical probability inferred from log frequency or from the scripts' heuristic score.

## Root-cause decision gates

Only say **Confirmed** if all of these hold:

- The failure is demonstrably on the **reported** operation path and incident attempt.
- There is an authoritative outcome or directly observed, coherent causal sequence.
- The proposed cause precedes the failure (or is a persistent prerequisite valid at that time).
- Identity/time/user/profile/boot/session linkage is established where applicable.
- Material contradictions have been investigated and resolved.

Apply the confidence definitions in [report-format.md](report-format.md). Never make a diagnostic claim from search hits, static settings, installer policy requests or missing matches alone.

## Efficient search policy

1. Begin with exact user symptom/time/package and high-signal failures. Do not print the top 100 generic warning lines.
2. Follow the failed boundary 1–3 hops upstream and downstream, extracting context around each decision rather than scanning unrelated services.
3. Expand into one additional playbook only when the first path identifies a dependency. Re-examine the report as required to resolve a contradiction; do not force an artificial search limit.
4. Prefer authoritative framework outcomes to unstructured app logs, but check that the reported user-visible symptom occurred **after** the framework outcome.
5. Stop once a confirmed explanatory chain and a verification action exist; do not chase unrelated concurrent warnings.
6. For multiple reports, analyse each separately before treating differences as explanatory. Compare event windows and effective state, not merely counts of lines.

## Generic interpretation examples

- If a provisioning request is refused because a required system capability is unavailable, the missing capability is the supported blocker. Repeated installer warnings after the refusal are not the initiating cause.
- If a dependent application is suspended for the relevant user and the expected activity resolves to it, establish suspension at the incident time before attributing a failure to policy. A later snapshot alone supports a hypothesis, not a confirmed historical violation.
- If a process resumes and draws successfully yet shows no useful content, do not report an activity launch failure. Investigate app startup/readiness and the dependencies invoked after first draw.
- If a communication service reaches an active state, do not attribute a "failed initiation" to a prior warning without proving that warning belongs to the same attempt. The symptom may instead involve audio, UI, service state, or a different attempt.
- If a managed app is desired by policy but no installer session is observed in a retained log interval, report the missing observed handoff; do not assert that the session never existed outside the captured data.

## Response

Use [report-format.md](report-format.md) for confidence labels and the final answer. The reasoning gates above determine whether the evidence supports that answer.
