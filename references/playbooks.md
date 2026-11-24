# Focused diagnostic playbooks

Select the paths that match the complaint. Start with a direct outcome or policy decision and then trace the missing predecessor or failing dependency. The search terms below are hints, not proof. Check Android-version and management-mode applicability before drawing conclusions.

## 1. Provisioning / enrolment / managed profile

**Start:** `ManagedProvisioning`, `PROVISION_MANAGED_DEVICE`, `PROVISION_MANAGED_PROFILE`, `ACTION_PROVISION_*`, `DevicePolicyManager`, `STATUS_*`, `RESULT_*`, `REQUIRED_FOR_SETUP`, install sessions, DPC setup result.

**Sequence:** requested provisioning mode -> device feature/ownership eligibility -> preconditions (existing accounts/users, encryption, reset state, network) -> provisioning component start -> DPC installation/activation -> user/profile setup -> role/policy setup -> managed store/dependent app install -> completed/failed.

**Check:** `android.software.device_admin`, `android.software.managed_users` capabilities where applicable; user/profile creation; `getDeviceOwner`/`getProfileOwner` state; account conflicts; setup wizard; deferred operations; explicit error status. One missing feature can invalidate the entire operation, even if app/network logs are noisy.

**Avoid:** declaring a Play verification notification the cause unless the verification operation demonstrably blocked provisioning; treating timeout as a root cause.

**Next test:** inspect provisioning return code and feature flags on the same build; reproduce from the required precondition state and capture the failure timestamp.

## 2. Kiosk, lock-task, HOME and cross-app launch

**Start:** `LockTaskController`, `isLockTaskPermitted`, `mLockTaskModeState`, `mLockTaskPackages`, `ActivityTaskManager`, `START`, `Displayed`, `SecurityException`, `START_CANCELED`, `DISALLOW_*`, `setPackagesSuspended`, app roles and intent resolution.

**Sequence:** source package/user -> action and resolved target -> package and target user state -> lock-task permission/allowlist -> task/window decision -> activity resume/draw -> downstream service operation.

**Check:** current mode **and historical events**; app suspension, hidden/disabled state and policy-protected packages; default HOME; whether external target is in allowlist; activity versus service/BroadcastReceiver restriction; user/profile boundary; screen-off task removal. Keep allowlist configuration separate from observed enforcement.

**Avoid:** inferring an actual lock-task violation from kiosk context alone, or using capture-time `NONE` to rule out a past violation. A successfully drawn activity can still be internally blank or unready.

**Next test:** capture the exact launch attempt and resolved component, inspect corresponding activity manager/task and policy decision logs.

## 3. Managed apps, Play, PackageInstaller and package availability

**Start:** `PackageInstaller`, `PackageManager`, `INSTALL_FAILED_*`, `STATUS_FAILURE_*`, `installationFailureReason`, `verifier`, `PackageVerification`, `PACKAGE_ADDED`, `PACKAGE_REMOVED`, `setPackagesSuspended`, managed-store client and DPC orchestration logs.

**Sequence:** policy requests app -> management service accepts -> store/account/installer obtains request -> installer session begins -> verification/constraints -> session committed -> package installed for target user -> enabled/unsuspended -> launchable.

**Check:** no installer session versus explicit install failure; no compatible APK; installer ownership, signature, policy, network, account, storage, package visibility, profile/user restrictions, Play Protect and automatic-update windows. A package being present in the system image does not mean installed/enabled for the managed user.

**Avoid:** assigning `INSTALL_FAILED_*` to an application until session/package ID matches; treating absent store activity in a truncated buffer as definitive proof it never occurred.

For custom APKs, validate the delivered bytes (length, ZIP structure, package/version and signing certificate) and distinguish the cached file from the intended download. Follow command/session IDs through final completion: an accepted or PENDING command is not installation success. PACKAGE_REMOVED with replacement semantics can be an update, not an uninstall. Check device-reported policy payloads as well as console intent.

**Next test:** capture package/session ID and the first missing handoff, compare desired policy with actual per-user package state.

## 4. App crash, ANR, blank or blocked launch

**Start:** `FATAL EXCEPTION`, `AndroidRuntime`, `ANR in`, `Input dispatching timed out`, `Process .* died`, `ActivityTaskManager`, `Start proc`, `Displayed`, `WindowManager`, `am_crash`, storage exceptions.

**Sequence:** process launch -> service/provider/application init -> activity lifecycle -> first draw -> dependency/permission/storage/role checks -> exception, ANR, process kill or rendered-but-blank UI.

**Check:** actual crash versus successful draw; repeated process restart; CE/DE storage with user locked; application data directory creation; corruption/keystore; caller and process UID, work-profile user; LMKD/resource kills versus Java crash; WebView or role dependency.

**Avoid:** treating `Displayed` as proof of functional app startup; describing an app as crashing absent a matching fatal/ANR/kill record.

**Next test:** match pid to full exception/kill reason and activity drawn state at incident time.

Standalone DropBox ANRs may use a dated system_app_anr/data_app_anr header without an "ANR in" logcat line. Read the following Process, PID, timestamp and thread sections. If the main thread waits for rendering, inspect RenderThread and the dependent native stack, plus contemporaneous pressure data; a wait stack identifies a boundary, not the owner of the delay. Treat explicit [[TRUNCATED]] markers as source gaps. Do not infer a driver defect from a vendor-library frame alone.

## 5. Direct Boot, locked users, CE/DE storage, startup services

**Start:** `ACTION_LOCKED_BOOT_COMPLETED`, `ACTION_BOOT_COMPLETED`, `UserController`, `isUserUnlocked`, `UserManager`, `vold`, `fscrypt`, `CredentialEncrypted`, `DeviceProtectedStorage`, `Failed to create`, `Keystore`, `SQLite*`, `InvalidProtocolBufferException`.

**Sequence:** boot -> user locked -> receiver/service start -> data store opened -> CE/DE availability -> failure/retry -> user unlock -> recovery or persistent corruption.

**Check:** whether code opened credential-encrypted data before unlock; file system mount/storage pressure; permissions/ownership, first-run migration, corrupt file versus inability to create file; start reason and service policy restrictions. An exception describing corrupt data may be secondary to storage setup failure.

**Avoid:** assuming Direct Boot is the root cause solely from timing. Differentiate actual bytes corruption from access errors.

**Next test:** reproduce before/after unlock and record storage path/creation errors without exposing data contents.

## 6. Telephony, emergency/SOS, outgoing calls and dialler routing

**Start:** `Telecom`, `ConnectionService`, `InCallService`, `Telephony`, `ACTION_CALL`, `ACTION_DIAL`, `placeCall`, `CALL_PHONE`, `ROLE_DIALER`, `DISALLOW_OUTGOING_CALLS`, `CallState`, `DISCONNECTED`/disconnect cause.

**Sequence:** initiating app -> action/number type -> resolved dialler/connection service -> user and policy gate -> account/subscription selection -> new/connecting/dialling/active/disconnected -> disconnect reason.

**Check:** whether a call actually reached active, role/default dialler, user restriction, permission plus app-op, SIM/service/radio state, lock task blocks on external UI, carrier restriction, emergency-call special routing. Distinguish call setup from UI visibility and audio/media quality.

**Avoid:** concluding that a failed third-party activity implies a failed Telecom operation; never print dialled numbers.

**Next test:** instrument a new call with an exact timestamp and compare Telecom IDs and framework states.

## 7. Networking, certificates, managed browser and web apps

**Start:** `ConnectivityService`, `NetworkMonitor`, `NET_CAPABILITY_VALIDATED`, `DNS`, `UnknownHostException`, `SSLHandshakeException`, `CertPathValidatorException`, `PKIX`, `Vpn`, `Proxy`, `WebView`, `ActivityTaskManager`, browser package state.

**Sequence:** app request/intent -> browser or network stack -> selected transport/VPN/proxy/DNS -> TLS trust + certificate chain -> HTTP/service result -> UI response.

**Check:** actual network validation versus app transport; VPN lockdown, captive portal, proxy auth, user CA vs system trust, device time, browser suspension/disablement and web intent resolution; differing behaviour between host app and underlying web runtime.

**Avoid:** attributing all TLS errors to CA certificates or interpreting active Wi-Fi as successful service connectivity. A suspended dependent browser can break otherwise healthy web-app packages.

**Next test:** isolate resolver/transport/TLS/HTTP boundary with exact error codes and per-user package state.

## 8. Certificates, keychain, keymaster, hardware-backed storage

**Start:** `KeyChain`, `KeyStore`, `Keystore`, `keymaster`, `KeyMint`, `installKeyPair`, `installCaCert`, `PKCS12`, `KeyChainActivity`, `CertPathValidatorException`, `SecurityException`.

**Sequence:** certificate source -> decoding/password -> requested CA/keypair operation -> policy/delegation/permission gate -> keystore/keymaster/hardware operation -> install result -> user/app selection/use.

**Check:** certificate type (CA vs keypair), certificate chain, password/format and expiry, alias collisions, per-user install context, delegated scope, user-selectability, hardware availability, lock state and exact keystore transaction errors.

**Avoid:** assuming a cryptographic import error means the password is incorrect; distinguish UI selection from successful private key insertion.

Service-manager skips and transaction errors in dumpstate_log describe report collection. Locate the actual import exception/result in runtime evidence before attributing certificate failure to a keystore service. Keep CA, client keypair, APK-signing certificate and download hash identities separate.

**Next test:** trace the installer API result and keymaster/keystore response under the same UID and user.

## 9. Boot loops, system upgrades, GSI/DSU and firmware integrity

**Start:** `init`, `bootstat`, `pstore`, `last_kmsg`, `tombstone`, `watchdog`, `kernel panic`, `fs_mgr`, `vold`, `avb`, `vbmeta`, `dm-verity`, `gsid`, `update_engine`, rollback, boot slot.

**Sequence:** bootloader/verified boot -> mount/decrypt -> init services -> SystemServer -> user start/unlock -> provisioning/policy application -> reboot/crash/recovery.

**Check:** actual reboot count and reason, whether only recovery or partial boot logs survived, verified-boot state, slot mismatches, dynamic partition state, vendor/system compatibility, FBE, post-update migration, system server watchdog and memory pressure.

For a pending OTA, trace scheduled window -> INSTALL_UPDATE job/intent -> OEM updater decision -> recovery/update-engine handoff -> installed build. A job that exits immediately and an updater's unchanged-policy message do not establish a firmware-install attempt or identify an OEM defect. Compare that chain separately from ordinary app updates.

**Avoid:** naming a firmware/verity cause without low-level evidence. Failed UI startup is not necessarily a boot loop.

**Next test:** obtain bootloader/recovery/pstore evidence, kernel reason, update metadata and preceding boot's last available log.

## 10. GNSS, background location, sensors and hardware switches

**Start:** `LocationManagerService`, `GnssLocationProvider`, `Fused`, `AppOps`, `ACCESS_FINE_LOCATION`, `ACCESS_BACKGROUND_LOCATION`, `SensorService`, input events, hardware intent/broadcast.

**Sequence:** app requests -> permission and app-op -> DPC/user restriction -> provider availability -> hardware/service event -> callback delivery -> background execution constraints.

**Check:** device-wide location enabled, user/profile scope, precise/background grant and foreground service restrictions, GNSS session started or not, provider fix failures, battery optimisation and sensor availability. For physical switches, verify key/scancode or broadcast transition and target listener/background launch policy.

**Avoid:** treating a permission grant as proof the provider ran or that a callback was delivered.

**Next test:** correlate request, provider start, sensor/GNSS state, and callback within the same interval.

## 11. Resource pressure, battery and intermittent behaviour

**Start:** `lmkd`, `lowmemorykiller`, `am_kill`, `OutOfMemoryError`, `watchdog`, `thermal`, `batterystats`, `dumpsys meminfo`, device idle and job scheduling.

**Sequence:** memory/storage/thermal/idle constraint -> scheduler or system decision -> process/service death or deferral -> restart or recovery.

**Check:** oom_adj and kill reason, process RSS, foreground service state, app standby, Doze, exact reboot boundary, on-battery vs uptime. Compare resource snapshots with incident-time kills.

**Avoid:** claiming battery life from raw uptime or assuming every memory warning caused the reported process death.

For native/system-server exhaustion, quantify the resource that reached its limit: heap/RSS, virtual mappings, descriptors or thread creation. Preserve units and distinguish a measured limit from a conventional default. Match leak-producing source paths and cleanup to the shipped revision; a plausible source fix is not remediation validation. For stutter, inspect frame and thread dependencies with an appropriate trace parser rather than generic error counts; record diagnostic overhead and comparison confounders.

**Next test:** reproduce with memory/thermal/stats sampling and correlate the kill/deferral with the app operation.

## 12. USB, display, audio/video and hardware integrations

**Start:** `UsbDeviceManager`, `UsbHostManager`, `ACTION_USB_DEVICE_DETACHED`, `SurfaceFlinger`, `HWComposer`, `DisplayManager`, `AudioFlinger`, input/HAL/VINTF/SELinux denials.

**Sequence:** application action -> framework request -> hardware service/HAL -> driver/connection state -> callback/display/media outcome.

**Check:** actual detach vs role reconfiguration, port power/host mode, hardware event timestamp, display composition fallback, service death/restart, vendor/system interface compatibility, access restrictions, camera/mic capture grants.

**Avoid:** inferring hardware failure purely from UI flicker or one SELinux denial; seek matching HAL/display/driver transitions.

**Next test:** compare hardware event sequence, framework state and app callbacks at a precise timestamp.
