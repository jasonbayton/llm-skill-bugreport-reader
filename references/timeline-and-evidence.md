# Event timeline and causal evidence

## First construct the smallest relevant interval

Identify the reported action, package, user/profile, approximate incident time and expected outcome. Begin with ±5–15 minutes when a time is known. Expand backwards for prerequisites and forwards for outcomes. Where no time is known, seek distinctive actions, explicit failure statuses and component state transitions. Do not treat the latest warnings near capture time as the incident by default.

For each event retain: local wall clock or elapsed time and its basis; `source:line`; PID/TID/UID/user if visible; service/component; action; result; and confidence that it belongs to this flow.

## Example event chain (generic, not a case)

```
User/app action -> intent/API request -> resolver / framework service
  -> policy/capability/permission/role gate -> dependent service
  -> state transition or explicit failure -> user-visible symptom
```

For installation: policy desired -> DPC accepts -> managed store requests -> PackageInstaller session -> verifier -> install result -> package available/enabled for target user. A gap between stages is significant; do not assume the next stage ran.

For kiosk app launch: origin -> resolved target activity -> user context -> allowed package / task policy -> ActivityTaskManager launch result -> resumed/displayed or rejection. Successful `Displayed` is evidence that the window drew, not that the UI completed its own startup logic.

For calling: intent/Telecom API -> resolved dialler/ConnectionService -> account/service selection -> `NEW`/`CONNECTING`/`DIALING`/`ACTIVE`/`DISCONNECTED` -> reason. An app error may coexist with a successfully placed call.

## Time handling

- Logcat often uses `MM-DD HH:MM:SS.mmm` with no year or time zone. A report filename or collection header can suggest a year, but label inferred years.
- Android logs can include UTC, local time, elapsedRealtime, uptime and kernel monotonic seconds. Convert only with verified anchors (e.g. boot epoch or paired clocks).
- Watch for reboot, clock correction, time-zone changes, rotated buffers, reordered merged logs and log-drop notices.
- A single report may include older bugreport metadata; prefer the actual source timestamp and state-specific capture times.
- Cross-report comparisons need boot/capture alignment and cannot assume user, policy or installed package identity is stable.
- Telecom saved event histories may use time-only entries such as `HH:MM:SS.mmm - SET_DIALING`, `SET_ACTIVE` and `SET_DISCONNECTED`, without repeating a service tag. Search those directly, recover the enclosing call identity and anchor their date/boot from surrounding metadata. Do not treat an unrelated AppOps `active=true` line as an active call.
- With `--utc`, the helper uses each member's report timezone and capture header to align supported timestamps, preserving the basis and uncertainty. Explicit UTC/GMT/numeric offsets are supported; ambiguous DST times, conflicting anchors and unsupported abbreviations remain unaligned. Check `time_alignment` before joining events; a timezone at capture is not proof of the timezone at an earlier incident.

## Distinguish evidence types

| Evidence | What it establishes | What it does not establish |
|---|---|---|
| Explicit provisioning/installer result | A framework outcome for that operation | Which upstream condition produced it without corroboration |
| DPM restriction/suspension at capture | Effective snapshot when recorded | Whether it was present earlier or caused a prior incident |
| Configuration payload/request | Desired state or command | Successful application or enforcement |
| Permission grant | Package permission state for a user | Role entitlement, app-op allowance or actual call/service success |
| Activity `START`/`RESUMED`/`Displayed` | Task/lifecycle or draw progress | Application's own readiness or content success |
| ANR or fatal exception | Actual process responsiveness/crash event | That it coincided with reported symptom unless correlated |
| Active Telecom state | Call active according to Telecom | User perception, media/audio correctness, or durable call quality |
| Error/warning log | A component recorded a problem | That this component caused the complaint |
| No matching log found | None in examined sources/window/patterns | That the event never happened |

## Causal reasoning procedure

1. State the expected transition that failed and the first **observable divergence**.
2. Seek an authoritative status/result at that divergence.
3. Work backwards to the earliest necessary precondition that was false. Treat upstream prerequisites as stronger than downstream noise.
4. Confirm the same user/profile, package instance, boot/session and interval.
5. Test alternatives against contradictions: did the operation actually succeed, did the activity draw, did the network validate, did the policy block at all?
6. Rank conclusions **confirmed / probable / possible / not established / contradicted**. Never promote a hypothesis just because a matching error appears frequently.
7. Recommend the smallest controlled test that would discriminate remaining hypotheses (e.g. change one policy gate and repeat while capturing framework transitions).

## Search discipline

- Exact logcat case searches: full exception, status token, service/tag, package and component, UID/user, install session ID, call ID or activity record; include ±10–30 context lines.
- Consult `dumpsys` to verify current state but do not treat it as a timeline unless it contains historical events.
- Correlate package-dependent infrastructure: a browser, WebView, dialler, account/installer, verifier, VPN, network service or platform feature may be the true blocker.
- Keep evidence source pointers precise: archive member, line number, timestamp, minimal excerpt. If you cannot locate a source line, do not give a fake one.
- Mark search coverage: which members, buffers, windows and patterns were actually inspected.
