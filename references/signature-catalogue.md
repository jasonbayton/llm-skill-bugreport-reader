# Signal catalogue: pattern, meaning, confirmation and false positives

Use as a **search guide**, never as a replacement for timeline-based causal reasoning. Signatures match varying Android versions/builds differently. `scripts/triage.py` contains a practical, deliberately limited high-signal subset.

| Search string / family | Likely domain | Confirm with | Common false positive |
|---|---|---|---|
| `STATUS_DEVICE_ADMIN_NOT_SUPPORTED`, provisioning `STATUS_*` | Provisioning eligibility/failure | Requested action, system feature declaration, provisioning result | Status from unrelated attempt |
| `android.software.device_admin`, `android.software.managed_users` | Provisioning prerequisites | Explicit feature list/PackageManager, OS version | Omitted feature in incomplete dump |
| `INSTALL_FAILED_*`, `STATUS_FAILURE_*` | Package installation result | Session ID, package, target user and requested policy | Different concurrent install |
| `installationFailureReason` | Managed app install | Managed-store handoff, installer session, value semantics | Policy reports old attempt |
| `setPackagesSuspended`, `isPackageSuspended` | Application policy | Effective per-user suspended state and affected resolver/dependency | Suspended unrelated package |
| `DISALLOW_*` / user restrictions | Enterprise restriction | Target user/profile, effective policy and denied operation | Restriction exists but not relevant |
| `LockTaskController`, `mLockTaskModeState`, `startLockTask` | Kiosk and task policy | Incident-time transition and target package | `NONE` snapshot taken after incident |
| `ActivityTaskManager START`, `Displayed`, `am_resume_activity` | UI launch path | Full target component and activity lifecycle | Drawn window but blank app content |
| `FATAL EXCEPTION`, `am_crash`, `ANR in` | Crash/hang | Same package/PID/time and exception stack | Background process unrelated to symptom |
| `InvalidProtocolBufferException`, `SQLiteException` | Data corruption/access | Earlier file creation/access errors, unlock state | Secondary exception from prior storage error |
| `isUserUnlocked`, `ACTION_LOCKED_BOOT_COMPLETED` | Direct Boot | CE/DE path, boot stage, failing process | Boot broadcasts without actual locked access |
| `SecurityException`, `AppOps` | Permission or policy enforcement | Caller UID/user, API, grant, role, app-op | Expected probes by system components |
| `ROLE_DIALER`, `ConnectionService`, `Telecom` | Calling | Call state sequence and actual disconnect cause | Generic dialler logs from unrelated call |
| `NET_CAPABILITY_VALIDATED`, `NetworkMonitor` | Network state | Route, VPN, DNS, app connection result | Validated default network but app-specific block |
| `SSLHandshakeException`, `PKIX` | TLS trust/time/interception | Certificate chain, endpoint and clock, trust store | Expired or unrelated connection |
| `KeyStore`, `KeyMint`, `keymaster` | Keypair and certificate handling | Return code and operation/alias/user | Routine key probes and expected errors |
| `lmkd`, `am_kill`, `watchdog` | Process/resource death | PID, oom_adj, incident timestamp, subsequent crash | Background process killed normally |
| `fs_mgr`, `avb`, `dm-verity`, `vold` | Boot/integrity/storage | Boot stage and reboot cause | Routine verified-boot logs |
| `GnssLocationProvider`, `LocationManagerService` | Location provider | Request and provider callbacks, permission/app-op | Provider idle because app never requested |
| `SurfaceFlinger`, `HWComposer`, `VINTF` | Display/HAL | Frame/composition errors correlated with symptom | Normal composition fallback |
| `UsbDeviceManager`, `ACTION_USB_DEVICE_DETACHED` | USB role/power/link | Port state and device event sequence | Logical role change without cable removal |

## Search order for a typical complaint

1. User-supplied app package and symptom-specific action keyword.
2. Explicit failure status, policy denial, exception or state transition for that action.
3. First preceding failing prerequisite or dependency.
4. Effective device/user/package state at collection time, clearly separated from the incident.
5. Adjacent buffers/sections for corroboration and contradictions.
6. Only then search general `Error`, `Exception`, `WTF`, `denied`, `failed` if needed.

Capture the source buffer and line on every hit. Avoid giant flat grep outputs without context and timestamps.

## Android Enterprise search leads

- `CloudDPC`, `AndroidDevicePolicy`, `com.google.android.apps.work.clouddpc`, `AMAPI`: management client and policy handoff; an installed package is not ownership.
- `nonComplianceDetails`, `nonComplianceReason`, `appliedPolicyName`, `appliedPolicyVersion`, `policyCompliant`: compare intended and reported policy. Keep the enclosing package/user and schema version; do not decode undocumented numeric variants. [Device schema](https://developers.google.com/android/management/reference/rest/v1/enterprises.devices).
- `InstallApplicationCommand`, `CommandState`, `CommandStatus`, `CustomAppInstallationWorker`, `PENDING`, `SUCCEEDED`, `FAILED`, `COMPLETED`: trace one command ID through its actual result. SDK and EMM lifecycle schemas differ; a word match does not establish success.
- `Finsky` plus install/download/queue/delivery/session, `app_auto_install`, `AppAutoInstall`: policy-to-Play-to-installer handoff. Request acknowledgement is not installed state.
- `PROVISIONING_*`, `zero-touch`, `QrCodeProvisioning`, QR provisioning: check the consumed mode/extras, not just advertised enrollment capability. [Provisioning methods](https://developers.google.com/android/management/provision-device).
- `MANAGED_PROFILE`, `profileGroupId`, `organizationOwned`, `SCOPE_PERSONAL_PROFILE`, `COPE`: resolve concrete users and ownership before joining events across profiles.
- `setDelegatedScopes`, `getDelegatedScopes`, `delegation-*`, `mDelegationMap`: package, user and effective scope must match the failed call.

These signatures deliberately find context as well as errors. They rank search leads and never automatically establish management mode, policy enforcement or a cause.
