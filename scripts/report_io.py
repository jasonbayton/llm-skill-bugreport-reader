#!/usr/bin/env python3
"""Local, bounded report reading; nested ZIPs use temporary spools, never extraction."""
from __future__ import annotations

import argparse
import hashlib
from dataclasses import dataclass
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tempfile
from typing import Iterator
import zipfile

MAX_MEMBERS = 600
MAX_MEMBER_BYTES = 256 * 1024 * 1024
MAX_TOTAL_BYTES = 768 * 1024 * 1024
MAX_LINE_BYTES = 1024 * 1024
TEXT_EXTENSIONS = {'.txt', '.log', '.logcat', '.prop', '.conf', '.xml', '.anr', '.dump'}
TEXT_NAME_HINTS = ('bugreport', 'dumpstate', 'logcat', 'dumpsys', 'tombstone', 'last_kmsg', 'pstore')
BINARY_EXTENSIONS = {'.zip', '.gz', '.tar', '.png', '.jpg', '.jpeg', '.webp', '.pdf', '.apk', '.proto', '.pb', '.perfetto-trace', '.trace', '.bin', '.db', '.sqlite'}

EMAIL_RE = re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b')
IPV4_RE = re.compile(r'(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])')
MAC_RE = re.compile(r'(?i)\b(?:[a-f\d]{2}:){5}[a-f\d]{2}\b')
PHONE_RE = re.compile(r'(?i)\b(?:tel:|number=|phone_number=|msisdn=|destination=)\s*\+?[\d\s\-()]{7,}')
VALUE = r'"(?:\\.|[^"\\])*"|\x27(?:\\.|[^\x27\\])*\x27|(?:Bearer|Basic)\s+[^\s,;"}]+|[^\s,;"}]+'
SECRET_RE = re.compile(r'(?i)\b(PROVISIONING_WIFI_PASSWORD|EXTRA_ENROLLMENT_TOKEN|authorization|(?:access|refresh|registration|fcm|id|auth)[_-]?token|(?:recovery|registration|enrollment|enrolment|activation)[_-]?(?:key|token|code)|client[_-]?secret|token|api[_-]?key|password|passwd|secret|credentials?)["\x27]?\s*[:=]\s*(' + VALUE + r')')
UNIQUE_FIELD_RE = re.compile(r'(?i)\b(serial(?:no|number)?|imei|meid|imsi|iccid|android[_-]?id|subscriber[_-]?id|device[_-]?id)["\x27]?\s*[:=]\s*(' + VALUE + r')')
SERIAL_PROP_RE = re.compile(r'(\[(?:ro\.(?:boot\.)?serialno|ril\.(?:serialnumber|imei))\]\s*:\s*)\[[^\]]*\]', re.I)
LONG_HEX_RE = re.compile(r'(?i)(?<![\da-f])[\da-f]{40,}(?![\da-f])')
URL_RE = re.compile(r'https?://[^\s<>"\x27]+', re.I)


def redact(value: str) -> str:
    """Best effort, not a publication guarantee; private paths may remain."""
    value = SECRET_RE.sub(lambda m: f'{m.group(1)}=[REDACTED]', value)
    value = UNIQUE_FIELD_RE.sub(lambda m: f'{m.group(1)}=[REDACTED]', value)
    value = SERIAL_PROP_RE.sub(r'\1[REDACTED]', value)
    def clean_url(match):
        url = match.group(0)
        base = re.split(r'[?#]', url, maxsplit=1)[0]
        base = re.sub(r'^(https?://)[^/]*@', r'\1[REDACTED]@', base)
        return base + ('?[REDACTED]' if '?' in url or '#' in url else '')
    value = URL_RE.sub(clean_url, value)
    value = EMAIL_RE.sub('[EMAIL]', value)
    value = MAC_RE.sub('[MAC]', value)
    value = IPV4_RE.sub('[IP]', value)
    value = PHONE_RE.sub('[PHONE]', value)
    value = LONG_HEX_RE.sub('[HEX]', value)
    return value.rstrip('\r\n')


@dataclass(frozen=True)
class ScanLimits:
    max_members: int = MAX_MEMBERS
    member_bytes: int = MAX_MEMBER_BYTES
    total_bytes: int = MAX_TOTAL_BYTES
    line_bytes: int = MAX_LINE_BYTES
    nested_depth: int = 3


def new_coverage() -> dict:
    return {'complete': True, 'bytes_read': 0, 'candidate_members': 0,
            'nested_archives': [], 'duplicate_archives': [], 'skipped': [], 'ignored_binary_members': 0, 'ignored_metadata_members': 0,
            'truncated_lines': [], 'source_truncation_markers': [], 'decode_replacement_lines': 0, 'null_byte_lines': 0,
            'member_filter': None, 'stopped_early': False}


def is_text_candidate(name: str) -> bool:
    base = PurePosixPath(name.lower()).name
    suffix = PurePosixPath(base).suffix
    if base.startswith('.') or base in {'thumbs.db', 'metadata.json'} or suffix in BINARY_EXTENSIONS:
        return False
    return suffix in TEXT_EXTENSIONS or any(h in base for h in TEXT_NAME_HINTS)


def safe_archive_name(name: str) -> bool:
    normalized = name.replace('\\', '/')
    path = PurePosixPath(normalized)
    return bool(normalized) and not path.is_absolute() and not re.match(r'^[A-Za-z]:', normalized) and '..' not in path.parts


def iter_lines(report: str | Path, *, coverage: dict | None = None,
               limits: ScanLimits | None = None, member_substring: str | None = None) -> Iterator[tuple[str, int, str]]:
    """Yield source, one-based physical line, text; nested sources use outer.zip!member.

    Exclusions are recorded in coverage. Resource/decompression failures raise.
    'complete' refers to selected text candidates, not every binary report artifact.
    """
    report = Path(report).expanduser()
    if not report.exists():
        raise FileNotFoundError(f'Report not found: {report}')
    limits = limits or ScanLimits()
    if min(limits.max_members, limits.member_bytes, limits.total_bytes, limits.line_bytes) < 1 or limits.nested_depth < 0:
        raise ValueError('Scan limits must be positive (nested depth may be zero)')
    cov = coverage if coverage is not None else new_coverage()
    cov.update({k: v for k, v in new_coverage().items() if k not in cov})
    cov['member_filter'] = member_substring
    archive_hashes = {}

    def skip(name, reason):
        cov['complete'] = False
        cov['skipped'].append({'source': name, 'reason': reason})

    def consume(amount):
        cov['bytes_read'] += amount
        if cov['bytes_read'] > limits.total_bytes:
            raise ValueError('Total scan byte limit reached; narrow --member or increase --max-total-mib')

    def candidate(name, size):
        cov['candidate_members'] += 1
        if cov['candidate_members'] > limits.max_members:
            raise ValueError('Candidate member limit reached; narrow input or increase --max-members')
        if size > limits.member_bytes:
            skip(name, f'{size} bytes exceeds member limit {limits.member_bytes}; use --max-member-mib or a focused input')
            return False
        return True

    def text_stream(name, stream):
        line_no = 0
        used = 0
        while True:
            raw = stream.readline(limits.line_bytes + 1)
            if not raw:
                break
            line_no += 1
            consume(len(raw)); used += len(raw)
            if used > limits.member_bytes:
                raise ValueError(f'Member expanded past its size limit: {name}')
            if len(raw) > limits.line_bytes:
                clipped = raw[:limits.line_bytes]
                while raw and not raw.endswith(b'\n'):
                    raw = stream.readline(limits.line_bytes + 1)
                    consume(len(raw)); used += len(raw)
                    if used > limits.member_bytes:
                        raise ValueError(f'Member expanded past its size limit: {name}')
                if len(cov['truncated_lines']) < 100:
                    cov['truncated_lines'].append({'source': name, 'line': line_no})
                cov['complete'] = False
                raw = clipped + b' [TRUNCATED LINE]\n'
            if b'\x00' in raw:
                cov['null_byte_lines'] += 1
                raw = raw.replace(b'\x00', b'[NUL]')
            decoded = raw.decode('utf-8', errors='replace')
            if decoded.strip() == '[[TRUNCATED]]':
                cov['complete'] = False
                if len(cov['source_truncation_markers']) < 100:
                    cov['source_truncation_markers'].append({'source': name, 'line': line_no})
            if '\ufffd' in decoded:
                cov['decode_replacement_lines'] += 1
            yield name, line_no, decoded

    def zip_stream(archive, prefix='', depth=0):
        members = archive.infolist()
        if len(members) > limits.max_members * 20:
            raise ValueError('Archive directory is too large; select a smaller input')
        for info in members:
            if info.is_dir():
                continue
            name = prefix + info.filename
            if '__MACOSX' in PurePosixPath(info.filename).parts or PurePosixPath(info.filename).name.startswith('._'):
                cov['ignored_metadata_members'] += 1
                continue
            if not safe_archive_name(info.filename) or stat.S_ISLNK(info.external_attr >> 16):
                skip(name, 'unsafe path or symbolic-link member')
                continue
            nested = info.filename.lower().endswith('.zip')
            if not nested and not is_text_candidate(info.filename):
                cov['ignored_binary_members'] += 1
                continue
            if not nested and member_substring and member_substring.lower() not in name.lower():
                continue
            if not candidate(name, info.file_size):
                continue
            with archive.open(info) as stream:
                if not nested:
                    yield from text_stream(name, stream)
                    continue
                if depth >= limits.nested_depth:
                    skip(name, 'nested archive depth limit reached')
                    continue
                cov['nested_archives'].append(name)
                with tempfile.SpooledTemporaryFile(max_size=8 * 1024 * 1024) as spool:
                    used = 0
                    digest = hashlib.sha256()
                    while block := stream.read(1024 * 1024):
                        used += len(block); consume(len(block))
                        if used > limits.member_bytes:
                            raise ValueError(f'Nested archive expanded past its size limit: {name}')
                        spool.write(block)
                        digest.update(block)
                    checksum = digest.hexdigest()
                    if not member_substring and checksum in archive_hashes:
                        cov['duplicate_archives'].append({'source': name, 'same_as': archive_hashes[checksum], 'sha256': checksum})
                        continue
                    archive_hashes[checksum] = name
                    spool.seek(0)
                    # dumpstate dry runs can write a command-status placeholder
                    # under this ZIP filename. Keep other corrupt ZIPs fatal.
                    if (PurePosixPath(info.filename).name == 'visible_windows.zip'
                            and used == 57
                            and spool.read(58) == b'cmd window dump-visible-window-views: skipped on dry run\n'):
                        skip(name, 'dumpstate dry-run placeholder; window views were not collected')
                        continue
                    spool.seek(0)
                    with zipfile.ZipFile(spool) as child:
                        yield from zip_stream(child, name + '!', depth + 1)

    def local_file(path, name, explicit=False):
        if path.is_symlink():
            skip(name, 'symbolic link input'); return
        if path.suffix.lower() == '.zip' or zipfile.is_zipfile(path):
            with zipfile.ZipFile(path) as archive:
                yield from zip_stream(archive, '' if explicit else name + '!')
        elif explicit or is_text_candidate(name):
            if member_substring and member_substring.lower() not in name.lower():
                return
            if candidate(name, path.stat().st_size):
                with path.open('rb') as stream:
                    yield from text_stream(name, stream)

    if report.is_dir():
        for root, directories, files in os.walk(report, followlinks=False):
            directories[:] = [x for x in sorted(directories) if not (Path(root) / x).is_symlink()]
            for filename in sorted(files):
                path = Path(root) / filename
                yield from local_file(path, str(path.relative_to(report)))
    elif report.is_file():
        yield from local_file(report, report.name, True)
    else:
        raise ValueError(f'Not a regular file or directory: {report}')


def add_scan_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument('--member', help='Scan matching text member paths (substring; nested ZIPs use ! separators)')
    parser.add_argument('--max-member-mib', type=int, default=256)
    parser.add_argument('--max-total-mib', type=int, default=768)
    parser.add_argument('--max-members', type=int, default=600)


def limits_from_args(args) -> ScanLimits:
    if min(args.max_member_mib, args.max_total_mib, args.max_members) < 1:
        raise ValueError('Scan limits must be positive')
    return ScanLimits(args.max_members, args.max_member_mib * 1024**2, args.max_total_mib * 1024**2)


def validate_output_paths(inputs: list[Path], outputs: list[Path]) -> None:
    """Refuse source clobbering, existing outputs, and writing into a scanned tree."""
    seen = set()
    for output in outputs:
        target = output.expanduser().resolve()
        if target in seen or output.exists() or output.is_symlink():
            raise ValueError(f'Output must be a distinct new file: {output}')
        seen.add(target)
        for source in inputs:
            origin = source.expanduser().resolve()
            if target == origin or (origin.is_dir() and target.is_relative_to(origin)):
                raise ValueError('Output must be outside the source report/directory')
