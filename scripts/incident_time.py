"""UTC window alignment using per-member clock evidence, never host timezone."""
import re
import sys
from pathlib import Path
from datetime import datetime, timezone, timedelta
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

sys.path.insert(0, str(Path(__file__).resolve().parent))

from report_io import iter_lines, new_coverage

STAMP = re.compile(r'(?<![\d-])(?:(\d{4})-)?(\d{2})-(\d{2})[T ]+(\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?)(Z|[+-]\d{2}:?\d{2}|\s+(?:UTC|GMT|[ECMP][DS]T|BST|CEST|CET)\b)?')
ZONE = re.compile(r'^\s*\[persist\.sys\.timezone\]\s*:\s*\[([^\]]+)\]')


def clock_inventory(report, *, member=None, limits=None, override=None):
    if override: ZoneInfo(override)  # validate even for an empty input
    members = {}; coverage = new_coverage()
    for source, n, raw in iter_lines(report, coverage=coverage, limits=limits, member_substring=member):
        if 'persist.sys.timezone' in raw:
            match = ZONE.match(raw)
            if match:
                rec = members.setdefault(source, {'zones': [], 'headers': []})
                point = {'value': match[1], 'line': n}
                if point not in rec['zones']: rec['zones'].append(point)
        if raw.lstrip().lower().startswith(('== dumpstate:', 'dumpstate:')):
            match = STAMP.search(raw)
            if match and match[1]:
                members.setdefault(source, {'zones': [], 'headers': []})['headers'].append({'value': match[0], 'line': n})
    for source, rec in members.items():
        rec.update(zone=None, offset=None, status='unknown', caveat='Capture clock state may differ from incident clock state.')
        zones = {p['value'] for p in rec['zones']}
        if override:
            rec.update(zone=override, status='user_override'); continue
        if len(zones) > 1:
            rec['status'] = 'conflicting_zones'; continue
        if zones:
            name = next(iter(zones))
            try: zone = ZoneInfo(name)
            except (ZoneInfoNotFoundError, ValueError):
                rec['status'] = 'unrecognized_zone'; continue
            rec.update(zone=name, status='iana_zone_inferred_for_incident')
            for h in rec['headers']:
                try: dt = datetime.fromisoformat(h['value'].replace('Z','+00:00').replace(' UTC','+00:00').replace(' GMT','+00:00'))
                except ValueError: continue
                if dt.tzinfo and dt.utcoffset() != dt.astimezone(zone).utcoffset():
                    rec.update(zone=None, status='header_zone_conflict')
        else:
            offsets = set()
            for h in rec['headers']:
                try: dt = datetime.fromisoformat(h['value'].replace('Z','+00:00').replace(' UTC','+00:00').replace(' GMT','+00:00'))
                except ValueError: continue
                if dt.tzinfo: offsets.add(int(dt.utcoffset().total_seconds()))
            if len(offsets) == 1: rec.update(offset=offsets.pop(), status='fixed_capture_offset_inference')
            elif len(offsets) > 1: rec['status'] = 'conflicting_header_offsets'
    return {'members': members, 'override': override, 'coverage': coverage,
            'notice': 'Clock evidence is local to each member. Capture-time timezone is an inference for historical events; DST folds/gaps and conflicts remain unresolved. Supply --timezone only when independently known.'}


def match_utc(raw, incident, minutes, clock=None, override=None):
    m = STAMP.search(raw)
    result = {'timestamp_utc': None, 'incident_window': None, 'time_basis': 'no_timestamp'}
    if not m: return result
    stamp = m[0]; result['time_basis'] = 'timezone_unresolved'
    suffix = m[5]; zone = None; basis = None
    if suffix:
        suffix = suffix.strip()
        if suffix in ('Z','UTC','GMT'): zone=timezone.utc
        elif re.fullmatch(r'[+-]\d{2}:?\d{2}',suffix):
            sign = -1 if suffix[0]=='-' else 1; digits=suffix[1:].replace(':','')
            hours,mins=int(digits[:2]),int(digits[2:])
            if hours>23 or mins>59:return result
            zone=timezone(sign*timedelta(hours=hours,minutes=mins))
        else:
            result['time_basis']='ambiguous_timezone_abbreviation'; return result
        basis='explicit_event_offset'
    elif override:
        zone=ZoneInfo(override); basis='user_override'
    elif clock and clock.get('zone'):
        zone=ZoneInfo(clock['zone']); basis=clock['status']
    elif clock and clock.get('offset') is not None:
        zone=timezone(timedelta(seconds=clock['offset'])); basis=clock['status']
    if zone is None:return result
    years=[int(m[1])] if m[1] else [incident.year-1,incident.year,incident.year+1]
    candidates=[]
    for year in years:
        try: naive=datetime.fromisoformat(f'{year}-{m[2]}-{m[3]}T{m[4]}')
        except ValueError:continue
        instants=set()
        for fold in (0,1):
            dt=naive.replace(tzinfo=zone,fold=fold);utc=dt.astimezone(timezone.utc)
            if utc.astimezone(zone).replace(tzinfo=None)==naive:instants.add(utc)
        candidates.append((min((abs((t-incident).total_seconds()) for t in instants),default=float('inf')),instants))
    if not candidates:return result
    _, instants=min(candidates,key=lambda c:c[0])
    if len(instants)!=1:
        result['time_basis']='dst_fold_ambiguous' if instants else 'nonexistent_local_time';return result
    dt=next(iter(instants))
    return {'timestamp_utc':dt.isoformat(),'incident_window':abs((dt-incident).total_seconds())<=minutes*60,
            'time_basis':basis+(' + nearest_year_inference' if not m[1] else '')}
