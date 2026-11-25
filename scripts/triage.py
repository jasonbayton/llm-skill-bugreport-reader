#!/usr/bin/env python3
"""Read-only, evidence-oriented first pass for Android bugreports.

Typical use:
    python3 scripts/triage.py report.zip --focus provisioning
    python3 scripts/triage.py report.zip --package com.example.app --incident 2026-01-01T14:30:00

Heuristics only: matches are discovery clues, not automatic root-cause assertions.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict, deque
from dataclasses import dataclass
from datetime import datetime
import json
from pathlib import Path
import re
import sys

from evidence_context import ContextTracker, display_tags
from incident_time import clock_inventory, match_utc
from datetime import timezone

from report_io import (iter_lines, redact, new_coverage, ScanLimits, add_scan_arguments,
                       limits_from_args, validate_output_paths)

FOCUSES = ("auto", "provisioning", "kiosk", "install", "crash", "storage", "telephony", "network", "certificates", "boot", "location", "performance", "hardware")

@dataclass(frozen=True)
class Signature:
    name: str
    pattern: str
    focus: str
    explanation: str
    weight: int = 1

SIGNATURES = [
    Signature("android-management", r"CloudDPC|AndroidDevicePolicy|Android Device Policy|com\.google\.android\.apps\.work\.clouddpc|\bAMAPI\b", "provisioning", "Management-client activity; package presence or a tag does not establish device/profile ownership", 3),
    Signature("amapi-compliance", r"nonComplianceDetails|nonComplianceReason|appliedPolicyVersion|appliedPolicyName|policyCompliant", "provisioning", "Compare requested and applied policy for the same device/user; raw values need documented schema/version context", 5),
    Signature("managed-install-command", r"InstallApplicationCommand|CustomAppInstallationWorker|(?:CommandState|CommandStatus).*?(?:PENDING|SUCCEEDED|FAILED|COMPLETED)|AMAPI.*?(?:PENDING|SUCCEEDED|FAILED|COMPLETED)", "install", "Follow command/session identity through completion; PENDING is not success and retries may be separate attempts", 6),
    Signature("managed-play-handoff", r"Finsky.*?(?:install|download|queue|delivery|session)|app_auto_install|AppAutoInstall", "install", "Trace Play request, download and installer handoff; catalogue and delivery logs alone do not prove installation", 5),
    Signature("provisioning-input", r"PROVISIONING_[A-Z_]+|zero[- ]touch|QrCodeProvisioning|QR.*provisioning", "provisioning", "Enrollment input/method lead; verify consumed extras and mode, and keep enrollment credentials private", 4),
    Signature("profile-boundary", r"MANAGED_PROFILE|managed profile|profileGroupId|organizationOwned|organisationOwned|isOrganizationOwnedDeviceWithManagedProfile|SCOPE_PERSONAL_PROFILE|\bCOPE\b", "provisioning", "Resolve concrete user/profile IDs and ownership; the word COPE or a profile flag alone is not proof of management mode", 4),
    Signature("policy-delegation", r"setDelegatedScopes|getDelegatedScopes|delegation-[a-z-]+|DelegationMap|mDelegationMap", "provisioning", "Check delegated package, scope and target user at operation time; requested delegation is not proof it was effective", 5),
    Signature("provisioning-rejected", r"STATUS_DEVICE_ADMIN_NOT_SUPPORTED|PROVISION_[A-Z_]+.*(?:failed|denied|not supported)|ManagedProvisioning.*(?:failed|error)", "provisioning", "Explicit provisioning outcome; confirm mode, requirements and feature declarations", 9),
    Signature("provisioning-preconditions", r"android\.software\.(?:device_admin|managed_users)|provisioning.*(?:precondition|not allowed|ineligible)", "provisioning", "Platform feature or precondition clue; a mention is not proof of availability", 5),
    Signature("policy-sync-timeout", r"POLICY_UPDATE_TIMEOUT_AFTER_FCM_PING", "provisioning", "Policy response timeout: inspect the active transport and request/response chain; timeout is an outcome, not its cause", 8),
    Signature("install-result", r"INSTALL_FAILED_[A-Z_]+|STATUS_FAILURE_[A-Z_]+|installationFailureReason[\"\x27]?\s*[:=]\s*\d+|PackageInstaller.*(?:failure|failed|aborted)", "install", "Check installer session, package, user, verification and status; a numeric field needs version-specific interpretation, not an assumed cause", 9),
    Signature("package-policy", r"setPackagesSuspended|isPackageSuspended|(?:suspended|hidden)\s+(?:package|app)|DISALLOW_[A-Z_]+|\bno_(?:install_apps|outgoing_calls|uninstall_apps|modify_accounts)\b", "kiosk", "Verify effective package/user restriction and whether it gates the action", 7),
    Signature("install-policy-denial", r"Installs disallowed|install.*(?:blocked by|disallowed by).*policy|ENTERPRISE_AUTO_INSTALL_ERROR_APP_UNAVAILABLE|no_install_apps\s*[=:]\s*true", "install", "Find the target package/session and effective restriction; app unavailability is a boundary, not its underlying cause", 9),
    Signature("invalid-apk", r"(?:EOCD|end of central directory).*(?:not found|missing)|Failed to parse.*(?:APK|apk)|INSTALL_PARSE_FAILED_[A-Z_]+|(?:Invalid|invalid) APK", "install", "Validate file length, ZIP structure, hash and cached payload before attributing the cause", 9),
    Signature("locktask", r"LockTaskController|mLockTaskModeState|mLockTaskPackages|startLockTask|(?:lock task|locktask).*(?:violation|denied|not allowed)", "kiosk", "Distinguish configured/current state from incident-time enforcement", 7),
    Signature("locktask-denial", r"(?:lock task|locktask).*(?:violation|denied)", "kiosk", "Enforcement wording: correlate the attempted component, user and time; configured allowlists and current mode are separate evidence", 9),
    Signature("activity-rejected", r"ActivityTaskManager.*(?:START_CANCELED|START_ABORTED|Permission Denial|not allowed|denied)|Background activity launch blocked", "kiosk", "Check origin, target user, intent resolution, and policy decision", 7),
    Signature("activity-lifecycle", r"ActivityTaskManager.*(?:START\s+u\d+|Displayed)|am_resume_activity|Displayed\s+\S+", "crash", "Activity launch/draw events are state transitions, not proof of app readiness", 4),
    Signature("crash-or-anr", r"FATAL EXCEPTION|ANR in\s+\S+|am_crash|Process .* has died|OutOfMemoryError|^\s*\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\s+(?:system_app|data_app|system_server)_(?:anr|crash)\s+\(", "crash", "Match timestamp, package/PID and full stack/kill reason; dated DropBox crash/ANR entries need the following process and thread sections", 9),
    Signature("native-crash", r"\bsignal\s+\d+\s+\(SIG(?:ABRT|SEGV|BUS|ILL|FPE|TRAP)\)|Abort message:", "crash", "Inspect tombstone header, process, timestamp and backtrace; a retained older tombstone is not incident attribution", 9),
    Signature("account-sync-failure", r"BAD_AUTHENTICATION|SyncPolicyRequestFailureMetric|(?:missing|no|not found).*long.lived.*(?:credential|token)|long.lived.*(?:credential|token).*(?:missing|not found)", "install", "Trace the managed account and sync request; do not decode undocumented failure numbers or assume device-wide connectivity failed", 8),
    Signature("storage-failure", r"InvalidProtocolBufferException|SQLite(?:Exception|DatabaseCorruptException)|Failed to create.*(?:directory|data)|EACCES.*(?:/data/|/storage/)|fscrypt.*(?:fail|error)", "storage", "Check earlier storage, file permissions, CE/DE access and unlock", 8),
    Signature("direct-boot", r"ACTION_LOCKED_BOOT_COMPLETED|isUserUnlocked|credential.encrypted|DeviceProtectedStorage|User.*(?:locked|unlocking|unlocked)", "storage", "Determine user/boot phase, storage context and operation order", 4),
    Signature("telephony-restriction", r"DISALLOW_OUTGOING_CALLS|ROLE_DIALER|CALL_PHONE.*(?:denied|not granted)|Telecom.*(?:failed|disconnect|error)", "telephony", "Trace caller, role, user restriction and actual call states", 7),
    Signature("telephony-lifecycle", r"\b(?:Telecom|ConnectionService|InCallService)\s*:.*(?:\bDIALING\b|\bACTIVE\b|\bDISCONNECTED\b|\bCONNECTING\b|placeCall|CreateConnection)|^\s*\d{2}:\d{2}:\d{2}(?:\.\d+)?\s+-\s+SET_(?:NEW|CONNECTING|DIALING|ACTIVE|DISCONNECTED)\b", "telephony", "Correlate call IDs and success/failure outcome; time-only event histories require a date/boot anchor", 5),
    Signature("network-failure", r"SSLHandshakeException|CertPathValidatorException|PKIX path building failed|UnknownHostException|No route to host|Network is unreachable|Failed host lookup|Unable to resolve host|No address associated with hostname", "network", "Find resolver, route, TLS trust, time and endpoint; a request failure alone does not explain an app's blank UI", 8),
    Signature("network-state", r"NET_CAPABILITY_VALIDATED|NetworkMonitor.*(?:validated|validation failed)|PrivateDns|Vpn.*(?:lockdown|blocked)", "network", "Transport validation is not application-level connectivity", 4),
    Signature("certificate-import", r"KeyChain.*(?:install|failed)|KeyStore.*(?:error|failure)|KeyMint.*(?:error|failure)|keymaster.*(?:error|failure)|installKeyPair.*(?:fail|error)", "certificates", "Inspect operation, delegation, user context and keystore result", 7),
    Signature("boot-fault", r"Kernel panic|watchdog.*(?:reboot|reset|bite)|system_server.*(?:crash|restart)|avb.*(?:error|fail)|dm-verity.*(?:fail|corrupt)|gsid.*(?:fail|error)", "boot", "Requires boot boundary and low-level corroboration", 8),
    Signature("boot-lifecycle", r"ACTION_BOOT_COMPLETED|BOOT_COMPLETED|bootstat|fs_mgr|vold.*(?:mount|unmount)|INSTALL_UPDATE|FOTA.*(?:policy|update)|policy is same", "boot", "Separate scheduler entry, updater execution and recovery/update handoff; lifecycle/no-op records are not a fault or proof of installation", 3),
    Signature("location-block", r"ACCESS_BACKGROUND_LOCATION.*(?:denied|not granted)|LocationManagerService.*(?:denied|blocked)|GnssLocationProvider.*(?:error|fail)", "location", "Check actual provider request, permission and app-op", 7),
    Signature("resource-death", r"lmkd.*(?:Kill|kill)|lowmemorykiller|am_kill|thermal.*(?:shutdown|critical)|watchdog.*(?:kill|timeout)", "performance", "Correlate process and kill reason to incident", 7),
    Signature("native-allocation-failure", r"\bmmap failed:\s*ENOMEM\b|pthread_create failed|Too many open files", "performance", "Identify the process and exhausted resource; ENOMEM alone does not distinguish RAM, address space or mapping limits", 9),
    Signature("hardware-state", r"ACTION_USB_DEVICE_DETACHED|UsbDeviceManager.*(?:disconnect|error)|HWComposer.*(?:error|fail)|SurfaceFlinger.*(?:error|fail)", "hardware", "Check hardware service/HAL state and timing, not just warnings", 6),
    Signature("permissions", r"(?:SecurityException|Permission Denial|AppOps).*?(?:denied|requires|not allowed|not granted)|(?:requires|denied).*android\.permission\.", "crash", "Check caller UID/user, permission, role, app-op and restriction", 7),
]

PROPERTY_NAMES = {
    "ro.build.version.release": "android_version",
    "ro.build.version.sdk": "api_level",
    "ro.build.version.security_patch": "security_patch",
    "ro.build.id": "build_id",
    "ro.build.fingerprint": "build_fingerprint",
    "ro.build.type": "build_type",
    "ro.product.manufacturer": "manufacturer",
    "ro.product.model": "model",
    "ro.product.device": "product_device",
    "ro.boot.verifiedbootstate": "verified_boot",
    "ro.boot.flash.locked": "bootloader_locked",
    "ro.boot.selinux": "selinux_boot_mode",
}

# Necessary literals only: these gates avoid expensive regex scans, never define
# a match. Unknown signatures and non-ASCII lines retain the original regex path.
SIGNATURE_GATES = {
    'android-management': ('clouddpc', 'androiddevicepolicy', 'android device policy', 'amapi'),
    'amapi-compliance': ('noncompliance', 'appliedpolicy', 'policycompliant'),
    'managed-install-command': ('installapplicationcommand', 'customappinstallationworker', 'commandstate', 'commandstatus', 'amapi'),
    'managed-play-handoff': ('finsky', 'app_auto_install', 'appautoinstall'),
    'provisioning-input': ('provisioning_', 'zero', 'qrcodeprovisioning', 'qr'),
    'profile-boundary': ('managed_profile', 'managed profile', 'profilegroupid', 'organizationowned', 'organisationowned', 'scope_personal_profile', 'cope'),
    'policy-delegation': ('delegatedscopes', 'delegation-', 'delegationmap'),
    'provisioning-rejected': ('status_device', 'provision_', 'managedprovisioning'),
    'provisioning-preconditions': ('android.software.', 'provisioning'),
    'policy-sync-timeout': ('policy_update_timeout_after_fcm_ping',),
    'install-result': ('install_failed_', 'status_failure_', 'installationfailurereason', 'packageinstaller'),
    'package-policy': ('suspend', 'hidden', 'disallow_', 'no_'),
    'install-policy-denial': ('install', 'enterprise_auto_install_error_app_unavailable'),
    'invalid-apk': ('eocd', 'end of central directory', 'apk', 'install_parse_failed_'),
    'locktask': ('locktask', 'lock task'),
    'locktask-denial': ('locktask', 'lock task'),
    'activity-rejected': ('activitytaskmanager', 'background activity launch blocked'),
    'activity-lifecycle': ('activitytaskmanager', 'am_resume_activity', 'displayed'),
    'crash-or-anr': ('fatal exception', 'anr in', 'am_crash', 'process ', 'outofmemoryerror', '_anr', '_crash'),
    'native-crash': ('signal', 'abort message:'),
    'account-sync-failure': ('bad_authentication', 'syncpolicyrequestfailuremetric', 'long'),
    'storage-failure': ('invalidprotocolbufferexception', 'sqlite', 'failed to create', 'eacces', 'fscrypt'),
    'direct-boot': ('action_locked_boot_completed', 'isuserunlocked', 'credential', 'deviceprotectedstorage', 'user'),
    'telephony-restriction': ('disallow_outgoing_calls', 'role_dialer', 'call_phone', 'telecom'),
    'telephony-lifecycle': ('telecom', 'connectionservice', 'incallservice', 'set_'),
    'network-failure': ('sslhandshakeexception', 'certpathvalidatorexception', 'pkix path building failed', 'unknownhostexception', 'no route to host', 'network is unreachable', 'failed host lookup', 'unable to resolve host', 'no address associated with hostname'),
    'network-state': ('net_capability_validated', 'networkmonitor', 'privatedns', 'vpn'),
    'certificate-import': ('keychain', 'keystore', 'keymint', 'keymaster', 'installkeypair'),
    'boot-fault': ('kernel panic', 'watchdog', 'system_server', 'avb', 'dm-verity', 'gsid'),
    'boot-lifecycle': ('boot_completed', 'bootstat', 'fs_mgr', 'vold', 'install_update', 'fota', 'policy is same'),
    'location-block': ('access_background_location', 'locationmanagerservice', 'gnsslocationprovider'),
    'resource-death': ('lmkd', 'lowmemorykiller', 'am_kill', 'thermal', 'watchdog'),
    'native-allocation-failure': ('mmap failed:', 'pthread_create failed', 'too many open files'),
    'hardware-state': ('action_usb_device_detached', 'usbdevicemanager', 'hwcomposer', 'surfaceflinger'),
    'permissions': ('securityexception', 'permission denial', 'appops', 'android.permission.'),
}
PROP_RE = re.compile(r"^\s*\[(?P<name>ro\.[\w.\-]+)\]\s*:\s*\[(?P<value>[^\]]*)\]")
OWNER_RE = re.compile(r"^\s*(Device Owner|Profile Owner|mDeviceOwner|mProfileOwner)\s*[:=]\s*(.*?)\s*$", re.I)
LOCKTASK_RE = re.compile(r"^\s*mLockTaskModeState\s*[:=]\s*(\w+)", re.I)
CURRENT_USER_RE = re.compile(r"^\s*(?:mCurrentUser|Current user)\s*[:=]\s*(\d+)", re.I)
FEATURE_RE = re.compile(r"^\s*(?:feature\s*[:=]\s*|hasSystemFeature\s*\(\s*)(android\.software\.(?:device_admin|managed_users))\b", re.I)
RESTRICTION_RE = re.compile(r"\b(?:DISALLOW_[A-Z_]+|no_(?:install_apps|outgoing_calls|uninstall_apps|modify_accounts))\b")
LOGCAT_TIME_RE = re.compile(r"(?<![\d-])(?:(?P<year>\d{4})-)?(?P<month>\d{2})-(?P<day>\d{2})[T\s]+(?P<time>\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?)(?P<zone>Z|[+-]\d{2}:?\d{2}|\s+(?:UTC|GMT|[ECMP][DS]T|BST|CEST|CET)\b)?")
STATE_FILTERS = [
    ("management", re.compile(r"\b(?:Device Owner|Profile Owner|deviceOwner|profileOwner|mDeviceOwner|mProfileOwner)\s*[:=]|\b(?:DevicePolicyManager|device_policy).*owner", re.I)),
    ("users", re.compile(r"\b(?:UserInfo\{|UserController|UserState|isUserUnlocked|managed profile)\b", re.I)),
    ("lock_task", re.compile(r"mLockTaskModeState|mLockTaskPackages|LockTaskController", re.I)),
    ("restrictions", re.compile(r"\bDISALLOW_[A-Z_]+\b|\bno_(?:install_apps|outgoing_calls|uninstall_apps|modify_accounts)\b|userRestrictions|User restrictions", re.I)),
    ("roles", re.compile(r"\bROLE_(?:DIALER|BROWSER|HOME|SMS)\b|default (?:dialer|browser|home)", re.I)),
    ("package_state", re.compile(r"\b(?:suspended|enabled|hidden|stopped|installed)=(?:true|false)\b", re.I)),
]


def timestamp_from_line(line: str, incident: datetime | None, minutes: int = 15) -> tuple[str | None, bool | None]:
    match = LOGCAT_TIME_RE.search(line)
    if not match:
        return None, None
    local = match.group(0)
    if incident is None or match.group('zone'):
        return local, None
    try:
        years = [int(match.group('year'))] if match.group('year') else [incident.year - 1, incident.year, incident.year + 1]
        possible = []
        for year in years:
            try:
                possible.append(datetime.fromisoformat(f"{year}-{match.group('month')}-{match.group('day')}T{match.group('time')[:15]}"))
            except ValueError:
                pass
        parsed = min(possible, key=lambda x: abs((x - incident).total_seconds()))
        return local, abs((parsed - incident).total_seconds()) <= minutes * 60
    except (ValueError, TypeError):
        return local, None


def evidence(member: str, line_no: int, raw: str, incident: datetime | None, minutes: int = 15,
             context=None, clocks=None) -> dict:
    stamp, in_window = timestamp_from_line(raw, None if clocks is not None else incident, minutes)
    out = {"source": member, "line": line_no, "timestamp": stamp, "incident_window": in_window, "excerpt": redact(raw)[:500]}
    if context: out.update(context)
    if clocks is not None:
        out.update(match_utc(raw, incident, minutes, clocks['members'].get(member), clocks['override']))
    return out


def analyse(report: Path, focus: str, packages: list[str], incident: datetime | None, minutes: int,
            *, limits: ScanLimits | None = None, member_substring: str | None = None, utc=False, timezone_name=None) -> dict:
    if utc and incident is None:
        raise ValueError('--utc requires --incident')
    if timezone_name and not utc:
        raise ValueError('--timezone requires --utc')
    if utc:
        incident = (incident.replace(tzinfo=timezone.utc) if incident.tzinfo is None else incident.astimezone(timezone.utc))
    clocks = clock_inventory(report, member=member_substring, limits=limits, override=timezone_name) if utc else None
    tracker = ContextTracker()
    boundaries = []
    boundary_count = 0
    compiled = [(sig, re.compile(sig.pattern, re.I), SIGNATURE_GATES.get(sig.name)) for sig in SIGNATURES]
    profile = {}
    capture_profiles = defaultdict(dict)
    capture_snapshots = defaultdict(dict)
    profile_conflicts = defaultdict(list)
    coverage = new_coverage()
    collection_diagnostics = []
    owner_pending = None
    configuration = {"owners": [], "current_user": None, "lock_task_mode_at_capture": None,
                     "declared_feature_mentions": {}, "restriction_mentions": {}}
    state = defaultdict(list)
    samples = defaultdict(lambda: deque(maxlen=35))
    first_samples = defaultdict(list)
    incident_first = defaultdict(list)
    incident_last = defaultdict(lambda: deque(maxlen=12))
    package_first = defaultdict(list)
    package_last = defaultdict(lambda: deque(maxlen=12))
    counts = Counter()
    counts_by_kind = defaultdict(Counter)
    package_evidence = deque(maxlen=120)
    package_incident_first = []
    package_incident_last = deque(maxlen=12)
    files = set()
    scanned_lines = 0
    relevant_lines = 0
    for member, line_no, raw in iter_lines(report, coverage=coverage, limits=limits, member_substring=member_substring):
        scanned_lines += 1
        context = tracker.feed(member, line_no, raw)
        if context['boundary']:
            boundary_count += 1
            if len(boundaries) < 1000:
                boundaries.append({'source': member, 'line': line_no, **context})
        lower = raw.lower()
        ascii_line = raw.isascii()
        files.add(member)
        if 'dumpstate_log' in Path(member).name.lower():
            if len(collection_diagnostics) < 12 and re.search(r'error|fail|skip|denied', raw, re.I):
                collection_diagnostics.append(evidence(member, line_no, raw, incident, minutes, context, clocks))
            continue
        property_match = PROP_RE.search(raw)
        if property_match:
            field = PROPERTY_NAMES.get(property_match.group("name"))
            if field:
                capture_profiles[member][field] = {'value': redact(property_match.group('value')), 'source': member, 'line': line_no, 'basis': 'observed'}
            if field and field not in profile:
                # Preserve a source pointer for every observed property.
                profile[field] = {"value": redact(property_match.group("value")), "source": member, "line": line_no, "basis": "observed"}
            elif field and redact(property_match.group('value')) != profile[field]['value']:
                value = redact(property_match.group('value'))
                if value not in [x['value'] for x in profile_conflicts[field]] and len(profile_conflicts[field]) < 10:
                    profile_conflicts[field].append({'value': value, 'source': member, 'line': line_no})
        # Explicitly label these as dump/snapshot observations, not incident-time facts.
        owner_match = OWNER_RE.search(raw) if context['kind'] != 'log' else None
        if owner_pending:
            item, source, header_line = owner_pending
            if member != source or line_no > header_line + 6 or owner_match:
                owner_pending = None
            elif context['kind'] != 'log' and re.search(r'\b(?:admin|ComponentInfo|User ID|userId)\b', raw):
                item['value'] = (item['value'] + ' ' + redact(raw).strip()).strip()
                item['context_end_line'] = line_no
        if owner_match and len(configuration["owners"]) < 10:
            owner = {"type": owner_match.group(1), "value": redact(owner_match.group(2)),
                     "source": member, "line": line_no}
            configuration["owners"].append(owner)
            owner_pending = (owner, member, line_no) if not owner['value'] else None
        lock_match = LOCKTASK_RE.search(raw) if context['kind'] != 'log' else None
        if lock_match:
            configuration["lock_task_mode_at_capture"] = {"value": lock_match.group(1),
                                                          "source": member, "line": line_no,
                                                          "caveat": "Snapshot, not incident-time proof"}
            capture_snapshots[member]['lock_task_mode_at_capture'] = configuration['lock_task_mode_at_capture']
        user_match = CURRENT_USER_RE.search(raw) if context['kind'] != 'log' else None
        if user_match:
            configuration["current_user"] = {"value": user_match.group(1),
                                             "source": member, "line": line_no}
            capture_snapshots[member]['current_user'] = configuration['current_user']
        feature_match = FEATURE_RE.search(raw)
        if feature_match and feature_match.group(1) not in configuration["declared_feature_mentions"]:
            configuration["declared_feature_mentions"][feature_match.group(1)] = {
                "status": "listed_or_queried; verify support semantics in source context",
                "source": member, "line": line_no, "excerpt": redact(raw)[:250]}
        for restriction in RESTRICTION_RE.findall(raw):
            if restriction not in configuration["restriction_mentions"] and len(configuration["restriction_mentions"]) < 30:
                configuration["restriction_mentions"][restriction] = {"source": member, "line": line_no,
                                                                         "status": "mentioned; enforcement not established"}
        relevant_package = bool(packages and any(pkg.lower() in lower for pkg in packages))
        entry = None
        if relevant_package:
            entry = evidence(member, line_no, raw, incident, minutes, context, clocks)
            package_evidence.append(entry)
            if entry['incident_window'] is True:
                if len(package_incident_first) < 3:
                    package_incident_first.append(entry)
                package_incident_last.append(entry)
        line_matched = relevant_package
        for group, pattern in STATE_FILTERS:
            if (packages or len(state[group]) < 25) and pattern.search(raw):
                # Keep a bounded sample, retaining target rows even after unrelated blocks.
                state[group].append(entry or evidence(member, line_no, raw, incident, minutes, context, clocks))
                if packages:
                    state[group].sort(key=lambda ev: 0 if ev.get('package') in packages else
                                      (1 if not ev.get('package') else 2))
                    del state[group][25:]
        for sig, pattern, gates in compiled:
            if gates and ascii_line and not any(token in lower for token in gates):
                continue
            if pattern.search(raw):
                counts[sig.name] += 1
                counts_by_kind[sig.name][context['kind']] += 1
                if entry is None:
                    entry = evidence(member, line_no, raw, incident, minutes, context, clocks)
                # Preserve first and last for both early failures and recent outcomes.
                if len(first_samples[sig.name]) < 3:
                    first_samples[sig.name].append(entry)
                samples[sig.name].append(entry)
                if entry['incident_window'] is True:
                    if len(incident_first[sig.name]) < 3:
                        incident_first[sig.name].append(entry)
                    incident_last[sig.name].append(entry)
                if relevant_package:
                    if len(package_first[sig.name]) < 3:
                        package_first[sig.name].append(entry)
                    package_last[sig.name].append(entry)
                line_matched = True
        relevant_lines += int(line_matched)
    findings = []
    for sig in SIGNATURES:
        count = counts[sig.name]
        if not count:
            continue
        matched = (first_samples[sig.name] + list(samples[sig.name]) + incident_first[sig.name]
                   + list(incident_last[sig.name]) + package_first[sig.name] + list(package_last[sig.name]))
        seen = set()
        unique = []
        for item in matched:
            key = (item["source"], item["line"])
            if key not in seen:
                seen.add(key)
                unique.append(item)
        unique.sort(key=lambda e: (e['source'], e['line']))
        within = [e for e in unique if e["incident_window"] is True]
        with_package = [e for e in unique if any(p.lower() in e["excerpt"].lower() for p in packages)]
        weight = sig.weight + (5 if focus == sig.focus else 0) + (3 if within else 0) + (2 if with_package else 0)
        if incident and within:
            representative = within[:2] + within[-2:]
        else:
            chosen = with_package or unique
            representative = chosen[:2] + chosen[-2:]
        representative = list({(e['source'], e['line']): e for e in representative}.values())
        findings.append({"id": sig.name, "focus": sig.focus, "score": weight, "occurrences": count, "occurrences_by_kind": dict(counts_by_kind[sig.name]), "interpretation": sig.explanation, "evidence": representative})
    findings.sort(key=lambda x: (-x["score"], -x["occurrences"], x["id"]))
    capture_sources = sorted(set(capture_profiles) | set(capture_snapshots))
    multiple_captures = len(capture_sources) > 1
    if multiple_captures:
        # No synthetic first-profile / last-snapshot device across captures.
        profile = {}
        configuration['current_user'] = None
        configuration['lock_task_mode_at_capture'] = None
    return {
        "source": str(report),
        "focus": focus,
        "requested_packages": packages,
        "incident_local": incident.isoformat() if incident and not utc else None,
        "incident_utc": incident.isoformat() if utc else None,
        "time_alignment": clocks,
        "timeline_boundaries": boundaries,
        "timeline_boundary_count": boundary_count,
        "timeline_boundaries_sampled": boundary_count > len(boundaries),
        "incident_window_minutes": minutes if incident else None,
        "notice": "Heuristic matches are investigation leads, not proved root causes. Report timestamps and state snapshots may not describe the incident time. Redaction is best-effort.",
        "coverage": {**coverage, "member_count": len(files), "members": sorted(files), "scanned_lines": scanned_lines, "matching_lines": relevant_lines},
        "profile": profile,
        "multiple_capture_sources": multiple_captures,
        "captures": [{'source': source, 'profile': capture_profiles[source], 'snapshots': capture_snapshots[source]} for source in capture_sources],
        "profile_conflicts": dict(profile_conflicts),
        "collection_diagnostics": collection_diagnostics,
        "configuration": configuration,
        "state_snapshots_or_mentions": {k: v for k, v in state.items() if v},
        "findings": findings,
        "package_context": list({(e['source'], e['line']): e for e in
                                 (package_incident_first + list(package_incident_last) if package_incident_first else list(package_evidence)[-15:])}.values()),
    }


def markdown_evidence(ev: dict) -> str:
    tags = display_tags(ev)
    return f"- `{ev['source']}:{ev['line']}` {ev.get('timestamp') or ''} [{tags}]: `{ev['excerpt']}`"


def as_markdown(report: dict, limit: int) -> str:
    incident = report.get('incident_utc') or report.get('incident_local')
    basis = 'UTC' if report.get('incident_utc') else 'device-local'
    incident_text = f"`{incident}` ({basis})" if incident else 'not supplied'
    output = ["# Android bug-report triage", "", f"Source: `{report['source']}`", "", f"Focus: `{report['focus']}`. Incident: {incident_text}.", "", "**Important:** " + report["notice"], "", "## Coverage", "", f"{report['coverage']['scanned_lines']:,} lines across {report['coverage']['member_count']} text members. Unscanned/omitted archive members must not be assumed irrelevant.", ""]
    if not report['coverage']['complete']:
        output += ['**INCOMPLETE scan: do not infer absence from these results.**', '']
    for item in report['coverage']['skipped']:
        output.append(f"- Not scanned: `{item['source']}`: {item['reason']}")
    if report['coverage']['truncated_lines']:
        output.append(f"- Long physical lines were clipped: {report['coverage']['truncated_lines']}")
    if report['coverage'].get('source_truncation_markers'):
        output.append(f"- Source already contains truncation markers: {report['coverage']['source_truncation_markers']}")
    if report['coverage']['decode_replacement_lines']:
        output.append(f"- {report['coverage']['decode_replacement_lines']} lines decoded with replacement bytes; verify exact binary-sensitive claims separately.")
    if report['coverage']['null_byte_lines']:
        output.append(f"- {report['coverage']['null_byte_lines']} text-candidate lines contained null bytes, rendered as [NUL]; mixed binary sections need separate interpretation.")
    if report['coverage']['nested_archives']:
        output.append('- Nested archives were scanned; retain each report member as a separate capture/identity.')
    for duplicate in report['coverage'].get('duplicate_archives', []):
        output.append(f"- Byte-identical nested archive counted once: `{duplicate['source']}` duplicates `{duplicate['same_as']}` (SHA-256 verified).")
    if report.get('multiple_capture_sources'):
        output.append('**Multiple capture sources: no combined device profile or current-state snapshot. Select one source with --member before diagnosing or comparing.**')
        for capture in report['captures']:
            output.append(f"- Capture source: `{capture['source']}`")
    if report['coverage']['member_filter']:
        output.append(f"- Scope restricted to members containing: `{report['coverage']['member_filter']}`")
    output += ['', '## Incident timing and chronology', '']
    if incident:
        output.append(f"- Applied incident: {incident_text}; window: ±{report['incident_window_minutes']} minutes.")
    else:
        output.append('- No incident time supplied; no incident window applied.')
    if report.get('incident_utc'):
        output.append('- UTC alignment uses per-member clock evidence; inspect time_basis and time_alignment in JSON for unresolved clocks/DST.')
    output.append(f"- {report.get('timeline_boundary_count', 0)} section/chronology boundaries; boot candidates are not confirmed reboots. JSON retains bounded boundary evidence.")
    output += ['', '## Device profile (observed properties)', '']
    if report['profile_conflicts']:
        output.append('**Conflicting device properties: analyse each nested report/capture separately.**')
        for field, alternatives in report['profile_conflicts'].items():
            output.append(f'- {field}: additional observed values {alternatives}')
    if report["profile"]:
        for key, data in report["profile"].items():
            output.append(f"- **{key}**: `{data['value']}` (`{data['source']}:{data['line']}`)")
    elif not report.get('multiple_capture_sources'):
        output.append("No recognised device properties found. Inspect getprop/dumpstate directly.")
    output += ["", "## Structured management and policy clues", ""]
    config = report["configuration"]
    for item in config["owners"]:
        output.append(f"- **{item['type']}**: `{item['value']}` (`{item['source']}:{item['line']}`)")
    if config["current_user"]:
        item = config["current_user"]
        output.append(f"- **Current user snapshot:** `{item['value']}` (`{item['source']}:{item['line']}`)")
    if config["lock_task_mode_at_capture"]:
        item = config["lock_task_mode_at_capture"]
        output.append(f"- **Lock-task snapshot:** `{item['value']}` (`{item['source']}:{item['line']}`), not evidence of past mode")
    for name, item in config["declared_feature_mentions"].items():
        output.append(f"- **Feature mention:** `{name}` (`{item['source']}:{item['line']}`), availability not established from mention alone")
    for name, item in config["restriction_mentions"].items():
        output.append(f"- **Restriction mention:** `{name}` (`{item['source']}:{item['line']}`), verify user scope and enforcement")
    if not any([config["owners"], config["current_user"], config["lock_task_mode_at_capture"], config["declared_feature_mentions"], config["restriction_mentions"]]):
        output.append("No structured ownership or policy clues found; inspect full dumpsys sections.")
    output += ["", "## Highest-signal leads (not conclusions)", ""]
    for finding in report["findings"][:limit]:
        output.append(f"### {finding['id']} ({finding['focus']}, {finding['occurrences']} matches)")
        output.append(finding["interpretation"])
        for ev in finding["evidence"]:
            output.append(markdown_evidence(ev))
        output.append("")
    if not report["findings"]:
        output.append("No indexed high-signal signature matched. Check the reported action and targeted context manually.")
    output += ["## Relevant state snapshots / mentions", ""]
    output.append('Kinds distinguish history from snapshots. Package user rows belong only to the labelled enclosing package; unknown scope requires source context or package_state.py. Hidden system packages are factory copies, not current installed state.')
    if report.get('requested_packages'):
        output.append('Requested-package rows are shown first, followed by unscoped mentions and other packages; this remains a bounded sample.')
    for category, entries in report["state_snapshots_or_mentions"].items():
        output.append(f"### {category}")
        for ev in entries[:8]:
            output.append(markdown_evidence(ev))
    if report["package_context"]:
        output += ["", "## Recent lines containing requested packages", ""]
        for ev in report["package_context"]:
            output.append(markdown_evidence(ev))
    if report['collection_diagnostics']:
        output += ['', '## Collection diagnostics (not application failure evidence)', '']
        for ev in report['collection_diagnostics'][:5]:
            output.append(f"- `{ev['source']}:{ev['line']}`: `{ev['excerpt']}`")
    output += ["", "Next: reconstruct the exact incident timeline; confirm the earliest failed transition, dependent component and effective policy state. Do not report a cause solely from pattern matches."]
    return "\n".join(output) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path, help="Bugreport TXT, ZIP or directory")
    parser.add_argument("--focus", choices=FOCUSES, default="auto", help="Prioritise an issue category")
    parser.add_argument("--package", action="append", default=[], help="Relevant package name (repeatable)")
    parser.add_argument("--incident", help="Incident datetime; device-local unless --utc")
    parser.add_argument("--utc", action="store_true", help="Interpret incident as UTC; infer each member clock from report evidence")
    parser.add_argument("--timezone", dest="timezone_name", help="Known incident device IANA timezone override (requires --utc)")
    parser.add_argument("--minutes", type=int, default=15, help="Incident search window either side (default 15)")
    parser.add_argument("--json", type=Path, help="Optional output JSON path")
    parser.add_argument("--markdown", type=Path, help="Optional output Markdown path")
    parser.add_argument("--limit", type=int, default=15, help="Max signal groups shown in Markdown")
    add_scan_arguments(parser)
    args = parser.parse_args()
    if args.limit < 1 or args.limit > 100:
        parser.error('--limit must be between 1 and 100')
    if args.minutes < 0 or args.minutes > 1440:
        parser.error("--minutes must be between 0 and 1440")
    try:
        incident = datetime.fromisoformat(args.incident) if args.incident else None
        if incident is not None and incident.tzinfo is not None and not args.utc:
            parser.error("--incident must be device-local time without a timezone offset")
        validate_output_paths([args.report], [p for p in (args.json, args.markdown) if p])
        result = analyse(args.report, args.focus, args.package, incident, args.minutes,
                         limits=limits_from_args(args), member_substring=args.member, utc=args.utc, timezone_name=args.timezone_name)
        markdown = as_markdown(result, args.limit)
        if args.json:
            with args.json.open('x', encoding='utf-8') as handle:
                handle.write(json.dumps(result, indent=2, ensure_ascii=False) + "\n")
        if args.markdown:
            with args.markdown.open('x', encoding='utf-8') as handle:
                handle.write(markdown)
        if not args.json and not args.markdown:
            sys.stdout.write(markdown)
        else:
            print(f"Processed {result['coverage']['scanned_lines']:,} lines; {len(result['findings'])} signal categories", file=sys.stderr)
        return 0
    except Exception as error:
        # ZIP decompression and decode failures should produce a controlled error, never execute report content.
        print(f"Triage failed: {type(error).__name__}: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
