# Device and management reconnaissance

Complete this once per report. Record each field as **observed**, **inferred**, **not shown** or **conflicting**, with the source and timestamp where possible. Avoid dumping the entire inventory into the user-facing answer; surface context relevant to the incident.

## Provenance and time

- Archive/file identity, collection timestamp (report wall clock and time zone when available), log-buffer coverage, boot count/uptime, buffer rollover, truncation and sensitive-data redaction.
- Confirm whether `getprop`, `dumpsys`, logcat `main/system/events/crash`, kernel messages, package dumps and management dumps are present.
- Determine whether the same report spans a reboot and whether timestamps and clocks changed. Check log timestamps separately from capture date.

## OS, hardware and platform capabilities

| Need | Look for | Pitfall |
|---|---|---|
| Platform/build | `ro.build.version.release`, `ro.build.version.sdk`, `ro.build.fingerprint`, `ro.build.id`, `ro.build.type`, security patch props | Build fingerprint may expose private information; do not print unless necessary |
| Device | `ro.product.manufacturer`, `ro.product.model`, `ro.product.device`, `ro.hardware`, CPU ABI, kernel | Identity helps diagnose platform differences, but is not itself a cause |
| Security | SELinux mode, Verified Boot, encryption, user unlock state, system update/patch | Security state can differ across boots |
| Features | PackageManager declared `android.software.device_admin`, `android.software.managed_users`, telephony, NFC, camera, location, touchscreen | `supported=false` needs affirmative evidence; absence from an incomplete list is not proof |
| GMS components | Package names/versions, service availability and managed-store/installer evidence | Presence does not prove certification or account readiness |

Exclude serial numbers, IMEI/MEID, MAC, subscriber IDs, account names and other unique identifiers from the report unless required and authorised.

## Enterprise ownership and user/profile topology

Inspect `DUMP OF SERVICE device_policy`, DevicePolicyManager messages, `dumpsys user`, `dumpsys activity`, package state by user, and profile state. Map:

- Device Owner and Profile Owner components; user handles they govern; whether ownership is established, absent or unclear.
- User and profile IDs, parent-child relationships, system/headless system user state, running/quiet/unlocked profiles, current foreground user.
- Enrolment/provisioning stage, DevicePolicyManager and provisioning app activity, account/managed store readiness.
- Delegated scopes, role holders, available DPC privileges and potential conflicts between controllers.
- Current **effective** restrictions (e.g. outgoing calls, install apps, USB, debugging, app control, unknown sources), separately from policy payloads or desired settings.
- Lock-task configured packages/features, observed current mode, task/window history, activity launch restrictions and events.

A work-profile restriction may apply to the managed user but not the parent. `mLockTaskModeState=NONE` is capture-time state, not an incident-time verdict.

## Application and role state

For each relevant package and dependency, determine *per user*:

- Installed/not installed, enabled/disabled, hidden/unhidden, suspended/unsuspended, stopped, instant/system/updated system, installed version, last update if available.
- Installed-for-user versus package globally present; package installer session/verification/completion.
- Permissions: declared, granted, `POLICY_FIXED`/`USER_FIXED`, restrictions, app-ops and background execution allowance. An Android permission grant does not override app-op or user restriction.
- Default HOME, browser, SMS, dialler/calling roles and intent handlers. Check which specific activity/service resolves, which user executes it, and whether a dependent package is blocked.
- Process/startup, crash/ANR, service binding, storage context, app standby, doze/battery and foreground service.

When reading a PackageManager dump, anchor on the exact `Package [name]` header and stop at the next package header. Read that block's user line; the nearby user line before the header belongs to the preceding package. Keep `Packages:` separate from `Hidden system packages:`: the latter describes factory/system-image copies, not current installed state. A missing subsection header leaves that distinction unknown. Likewise, bind a JSON noncompliance reason to its enclosing package record, not the closest package mention elsewhere in the report.

## Connectivity and hardware context

- Transport availability (Wi-Fi/cellular/Ethernet), validation, proxy, VPN, DNS/private DNS, TLS trust/time, captive portal, firewall, background data rules. Distinguish service transport from successful app connection.
- Cellular subscription/SIM/service and default dialler if calls fail; do not print phone numbers.
- Storage free space, mount state, `/data` and CE/DE availability, keystore readiness, FBE state, user unlock.
- Memory pressure/OOM/LMKD, process kill reason, CPU/thermal, watchdog, battery and reboot records.
- Relevant OEM services/privilege mechanisms, but do not assume vendor semantics from a generic tag name.

## Device state synthesis

Construct a brief internal record:

```
report_captured_at: observed / unknown
incident_window: observed / approximate / unknown
android_api_level: observed / unknown
build: observed / unknown
management_mode: DO / PO / organisation-owned managed profile / unmanaged / unknown
owner_user: observed / unknown
current_user_and_profiles: observed / unknown
system_features_relevant_to_incident: observed / unknown
lock_task_at_capture: observed / unknown
lock_task_during_incident: observed / unknown
relevant_package_states: package + user + state + source
relevant_roles_and_intents: role + component + user + source
restrictions: enforced / configured / claimed / not established
report_completeness: available buffers, gaps and missing sections
```

## Mechanical package/user lookup

Run `python3 "$SKILL_BASE/scripts/package_state.py" /absolute/case/report.zip com.example.app` (set SKILL_BASE as in SKILL.md). Use the record's exact source, package header and own User line, not a nearby package's state. Multiple records remain separate captures/blocks. `--uid 1012345` optionally decodes a full UID into user 10 and app ID 12345; it does not identify a package or interpret a package-level appId as a full UID. Cross-check managed/personal profile IDs with the owner/user sections; COPE wording alone is insufficient.
