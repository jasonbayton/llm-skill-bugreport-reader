# Capture the missing causal link

Choose the recipe that distinguishes the remaining hypotheses. Record the symptom, package, user/profile, operation/command ID, expected outcome and exact reproduction time. Use one device serial consistently. Choose new local output filenames; do not overwrite an earlier capture. Diagnostic collection is itself load and can perturb performance.

## Baseline capture around a reproduction

With an authorized, connected device, record clock and boot context before reproducing:

```sh
adb devices -l
adb -s SERIAL shell date '+%Y-%m-%dT%H:%M:%S%z'
adb -s SERIAL shell getprop persist.sys.timezone
adb -s SERIAL shell cat /proc/uptime
adb -s SERIAL shell cat /proc/sys/kernel/random/boot_id
adb -s SERIAL shell am get-current-user
```

Access varies by device. Preserve permission errors as coverage limits. Note the EMM/AMAPI console UTC timestamp alongside device time, rather than assuming the Mac's timezone.

In one terminal start continuous logging, reproduce once, record its start/end times, then stop the logger with Ctrl-C:

```sh
adb -s SERIAL logcat -b all -v threadtime > /absolute/case/repro-logcat.txt
```

Immediately collect a bugreport to a new destination:

```sh
adb -s SERIAL bugreport /absolute/case/repro-bugreport.zip
```

The bugreport contains service state and retained log evidence; the separate live log helps retain the attempt across collection delays. Do not clear log buffers before preserving existing evidence. [Android bugreport capture](https://developer.android.com/studio/debug/bug-report).

## Buffer loss or short retention

Inspect supported flags and existing buffer sizes first:

```sh
adb -s SERIAL logcat --help
adb -s SERIAL logcat -b all -g
```

If authorized to change temporary logging configuration and the device supports it, an example larger ring is `adb -s SERIAL logcat -b all -G 16M`. Record previous per-buffer sizes and restore each supported buffer to its own original size afterwards; do not assume they were equal. Permissions, supported buffers and size limits vary. Continuous host logging may avoid a size change. Increasing a buffer cannot recover already overwritten events. Never use `logcat -c` as a routine preparation step. [Logcat options and buffers](https://developer.android.com/tools/logcat).

## DPC / management-client logging

Prefer the EMM/DPC's documented diagnostic export or supported verbose setting. For a tag the app actually uses, inspect its existing property with `adb -s SERIAL shell getprop log.tag.ExampleDpc`. With authorization, `adb -s SERIAL shell setprop log.tag.ExampleDpc VERBOSE` can affect property-controlled logging; save and restore the original value, including an empty value. This cannot restore compiled-out logs, bypass app filtering or guarantee verbose Android Device Policy output. Do not invent a universal CloudDPC debug switch or change global persistent logging properties. Keep enrollment tokens out of notes and shared exports. [Android logging filters](https://developer.android.com/tools/logcat).

## Pick the smallest useful addition

| Unresolved link | Capture | Discriminating result |
|---|---|---|
| Install accepted but no completion | Full live log around one command plus EMM command result; bugreport after the attempt | Same command/package/user reaches final installer result, or an identified handoff stops |
| Kiosk/browser blocked or app internally blank | Live activity/policy logs and post-attempt package/user snapshot | Framework denial for the resolved target versus accepted launch followed by app readiness failure |
| Work/personal profile mismatch | User/owner state plus exact event UID and command target user | Action and effective restriction belong to the same user, or demonstrably different profiles |
| Boot-related failure | Boot ID/uptime before and after; retained recovery/pstore evidence if accessible | Confirmed boot transition and preceding failure, rather than a mere log-buffer switch |
| UI hang or jank | Reproduction timestamp, ANR/thread dump and a suitable Perfetto trace with fixed workload | Blocking thread/resource owner and timing; a vendor frame alone does not identify the defective component |

Describe configuration changes and their reversal before doing them. Collect only within the user's authorization. If reproduction or state changes are not authorized, give the concrete recipe and expected distinguishing evidence without executing it.
