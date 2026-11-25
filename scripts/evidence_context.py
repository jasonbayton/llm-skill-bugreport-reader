"""Streaming source/section and conservative chronology annotations.

Epochs are local to a text member. A buffer boundary is not a reboot.
"""
import re
from pathlib import PurePosixPath

SECTION = re.compile(r'^\s*-{6,}\s+(.+?)\s+-{6,}\s*$')
DURATION = re.compile(r"^\s*-{6,}\s+\d+(?:\.\d+)?s was the duration of .+?-{6,}\s*$")
PACKAGE = re.compile(r'^(\s*)Package \[([^\]]+)\]\s*\(')
PACKAGE_SUBSECTION = re.compile(r'^(\s*)(Packages|Hidden system packages):\s*$')
SERVICE = re.compile(r'^\s*DUMP OF SERVICE(?:\s+(?:CRITICAL|HIGH|NORMAL))?\s+([^:]+):')
BUFFER = re.compile(r'^--------- (?:beginning of|switch to) (\S+)')
LOG = re.compile(r'^\s*(?:\d{4}-)?\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\s+(?:\S+\s+){0,3}[VDIWEFS]\s+\S+')
TIME = re.compile(r'^\s*((?:\d{4}-)?\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2})(?:\.\d+)?')
BOOT_ID = re.compile(r'^\s*(?:boot_id|/proc/sys/kernel/random/boot_id)\s*[:=]\s*([a-fA-F0-9-]{36})\s*$')
UPTIME = re.compile(r'^\s*(?:SystemUptimeMs|uptime_ms)\s*[:=]\s*(\d+)\s*$')
BOOT_EVENT = re.compile(r'\b(?:boot_completed|boot_progress_start|BOOT_COMPLETED)\b')
HISTORY = re.compile(r'^\s*\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\s+\w+_(?:crash|anr)\s+\(')


def display_tags(context):
    """Show package scope only for package-dump rows, not unrelated logs."""
    tags = (f"kind={context.get('kind', 'unknown')} / section={context.get('section', 'unknown')} / "
            f"buffer={context.get('buffer')} / {context.get('timeline_segment', '?')} / "
            f"boot={context.get('boot_epoch')}")
    package_dump = (context.get('package') or context.get('package_subsection') or
                    re.match(r'^DUMP OF SERVICE package\b', context.get('section', '')))
    if package_dump and context.get('kind') not in ('log', 'retained_history', 'collector'):
        tags += (f" / package={context.get('package') or 'unknown'} / "
                 f"subsection={context.get('package_subsection') or 'unknown'} / "
                 f"package_state={context.get('package_state_kind', 'unknown')}")
    return tags


class ContextTracker:
    def __init__(self):
        self.source = None

    def reset(self, source):
        self.source = source
        self.section = 'UNSECTIONED'
        self.section_line = None
        self.section_kind = 'unknown'
        self.buffer = None
        self.segment = 0
        self.boot_id = None
        self.boot_epoch = None
        self.epoch_confidence = 'unknown'
        self.last_time = None
        self.last_uptime = None
        self.package = self.package_line = self.package_indent = None
        self.package_subsection = self.subsection_indent = None

    def feed(self, source, number, raw):
        if source != self.source:
            self.reset(source)
        event = None
        footer = DURATION.match(raw)
        section = SECTION.match(raw) if not footer else None
        service = SERVICE.match(raw)
        buffer = BUFFER.match(raw)
        if section or service:
            self.section = ('DUMP OF SERVICE ' + service[1]) if service else section[1]
            self.section_line = number
            upper = self.section.upper()
            if service or any(s in upper for s in ('DUMP OF SERVICE', 'DUMPSYS', 'SYSTEM PROPERTIES', 'SYSTEM SETTINGS')):
                self.section_kind = 'snapshot'
            elif any(s in upper for s in ('SYSTEM LOG', 'EVENT LOG', 'RADIO LOG', 'MAIN LOG', 'KERNEL LOG', 'LOGCAT')) and not any(s in upper for s in ('TAGS', 'STATISTICS', 'STATS')):
                self.section_kind = 'log'
            elif any(s in upper for s in ('DROPBOX', 'TOMBSTONE', 'ANR')):
                self.section_kind = 'retained_history'
            else:
                self.section_kind = 'unknown'
            self.buffer = None
            self.segment += 1
            self.last_time = self.last_uptime = None
            self.boot_id = self.boot_epoch = None  # never carry a boot ID into another dump section
            self.epoch_confidence = 'unknown'
            event = 'section_boundary'
        if buffer:
            self.buffer = buffer[1]
            self.section_kind = 'log'
            self.segment += 1
            self.last_time = self.last_uptime = None
            self.boot_id = self.boot_epoch = None
            self.epoch_confidence = 'unknown'
            event = 'buffer_boundary_not_reboot'
        if HISTORY.match(raw):
            self.segment += 1
            self.last_time = self.last_uptime = None
            self.boot_id = self.boot_epoch = None
            self.epoch_confidence = 'unknown'
            self.section_kind = 'retained_history'
            event = 'retained_record_boundary_not_reboot'
        stamp = TIME.match(raw)
        is_log = bool(LOG.match(raw))
        kind = 'collector' if 'dumpstate_log' in PurePosixPath(source).name.lower() else ('log' if is_log else self.section_kind)
        if re.match(r'^\s*\d{2}:\d{2}:\d{2}(?:\.\d+)?\s+-\s+SET_(?:NEW|CONNECTING|DIALING|ACTIVE|DISCONNECTED)\b', raw):
            kind = 'retained_history'
        if kind == 'unknown' and re.match(r'^\s*(?:\[ro\.|mLockTaskModeState\s*[=:]|Package \[|User \d+:)', raw):
            kind = 'snapshot'
        if kind == 'unknown' and 'tombstone' in PurePosixPath(source).name.lower():
            kind = 'retained_history'
        if footer:
            kind = 'collector'
        # Package/User rows are meaningful only inside their own indented block.
        # A factory copy must never inherit the active Packages subsection label.
        if section or service or buffer or footer or kind in ('log', 'retained_history', 'collector'):
            self.package = self.package_line = self.package_indent = None
            self.package_subsection = self.subsection_indent = None
        package = PACKAGE.match(raw) if kind not in ('log', 'retained_history', 'collector') else None
        subsection = PACKAGE_SUBSECTION.match(raw) if kind not in ('log', 'retained_history', 'collector') else None
        indent = len(raw) - len(raw.lstrip())
        if subsection:
            self.package_subsection = subsection[2]
            self.subsection_indent = len(subsection[1])
            self.package = self.package_line = self.package_indent = None
        else:
            if self.subsection_indent is not None and raw.strip() and indent <= self.subsection_indent:
                self.package_subsection = self.subsection_indent = None
            if package:
                self.package, self.package_line, self.package_indent = package[2], number, len(package[1])
            elif self.package and raw.strip() and indent <= self.package_indent:
                self.package = self.package_line = self.package_indent = None
        package_state_kind = {'Packages': 'active_package_settings',
                              'Hidden system packages': 'factory_system_image_copy'}.get(self.package_subsection, 'unknown')
        boot = BOOT_ID.match(raw)
        if boot:
            if self.boot_id and self.boot_id != boot[1]:
                self.segment += 1
                event = 'boot_id_changed'
            self.boot_id = boot[1]
            self.boot_epoch = 'boot-id:' + boot[1]
            self.epoch_confidence = 'explicit_id'
        if is_log and stamp:
            key = stamp[0].strip()
            # Yearless Dec->Jan may be rollover, or wall-clock adjustment. Neither proves reboot.
            if self.last_time and key < self.last_time:
                self.segment += 1
                self.boot_epoch = self.boot_id = None
                self.epoch_confidence = 'unknown'
                event = 'wall_clock_regression_not_proven_reboot'
            self.last_time = key
            if BOOT_EVENT.search(raw):
                self.segment += 1
                if not self.boot_id:
                    self.boot_epoch = f'{source}#boot-candidate:{self.segment}'
                    self.epoch_confidence = 'candidate_only'
                event = 'boot_marker_candidate_may_be_repeated'
        up = UPTIME.match(raw)
        if up:
            value = int(up[1])
            if self.last_uptime is not None and value < self.last_uptime:
                self.segment += 1
                if not self.boot_id:
                    self.boot_epoch = f'{source}#boot-candidate:{self.segment}'
                    self.epoch_confidence = 'candidate_only'
                event = 'uptime_decrease_candidate_check_record_order'
            self.last_uptime = value
        return {'section': self.section, 'section_line': self.section_line, 'kind': kind,
                'buffer': self.buffer, 'timeline_segment': f'{source}#s{self.segment}',
                'boot_epoch': self.boot_epoch, 'boot_confidence': self.epoch_confidence,
                'package': self.package, 'package_line': self.package_line,
                'package_subsection': self.package_subsection, 'package_state_kind': package_state_kind,
                'boundary': event}
