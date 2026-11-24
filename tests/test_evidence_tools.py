import sys,json,zipfile,tempfile,unittest,subprocess
from pathlib import Path
from datetime import datetime,timezone
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'scripts'))
from evidence_context import ContextTracker
from triage import analyse,as_markdown
from context import locate
from package_state import extract,uid_identity
from report_io import redact
from incident_time import match_utc,clock_inventory

class EvidenceTools(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.p=Path(self.tmp.name)/'report.txt'
    def file(self,text):self.p.write_text(text);return self.p
    def track(self,lines):
        t=ContextTracker();return [t.feed('one.txt',n,l) for n,l in enumerate(lines,1)]
    def test_history_and_snapshot_are_different_kinds(self):
        d=analyse(ROOT/'tests/fixtures/kiosk.txt','kiosk',[],None,15)
        rows=[x for f in d['findings'] for x in f['evidence']]
        self.assertEqual(next(x for x in rows if 'mLockTaskModeState' in x['excerpt'])['kind'],'snapshot')
        for finding in d['findings']:self.assertEqual(sum(finding['occurrences_by_kind'].values()),finding['occurrences'])
        x=next(x for x in rows if 'setPackagesSuspended' in x['excerpt']);self.assertEqual(x['kind'],'log');self.assertIn('device_policy',x['section'])
    def test_log_tag_inventory_is_not_event_history(self):
        r=self.track(['------ EVENT LOG TAGS ------','30001 am_proc_start'])
        self.assertEqual(r[-1]['kind'],'unknown')
    def test_section_transition_resets_context(self):
        r=self.track(['------ SYSTEM LOG ------','01-01 12:00:00.000 1 2 I Tag: event','DUMP OF SERVICE package:','  Package [x] (1):'])
        self.assertEqual(r[1]['kind'],'log');self.assertEqual(r[3]['kind'],'snapshot');self.assertNotEqual(r[1]['timeline_segment'],r[3]['timeline_segment'])
    def test_buffer_switch_not_reboot_and_no_cross_buffer_clock_regression(self):
        r=self.track(['--------- beginning of system','01-02 12:00:00.000 1 2 I Tag: a','--------- beginning of events','01-01 12:00:00.000 1 2 I Tag: b'])
        self.assertIsNone(r[2]['boot_epoch']);self.assertEqual(r[2]['boundary'],'buffer_boundary_not_reboot');self.assertIsNone(r[3]['boundary'])
    def test_clock_regression_separates_without_claiming_reboot(self):
        r=self.track(['01-02 12:00:00.000 1 2 I Tag: a','01-01 12:00:00.000 1 2 I Tag: b'])
        self.assertNotEqual(r[0]['timeline_segment'],r[1]['timeline_segment']);self.assertIsNone(r[1]['boot_epoch']);self.assertIn('not_proven',r[1]['boundary'])
    def test_boot_marker_candidate_not_id(self):
        r=self.track(['01-01 12:00:00.000 1 2 I Event: boot_completed','01-01 12:00:01.000 1 2 I Tag: next'])
        self.assertEqual(r[1]['boot_confidence'],'candidate_only');self.assertEqual(r[0]['boot_epoch'],r[1]['boot_epoch'])
    def test_explicit_boot_ids_and_source_isolation(self):
        t=ContextTracker();a=t.feed('a',1,'boot_id: aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa');b=t.feed('a',2,'boot_id: bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb');c=t.feed('b',1,'plain')
        self.assertEqual(b['boundary'],'boot_id_changed');self.assertNotEqual(a['boot_epoch'],b['boot_epoch']);self.assertIsNone(c['boot_epoch'])
    def test_uptime_reset_is_candidate_and_retained_records_reset_uptime(self):
        r=self.track(['SystemUptimeMs: 100','SystemUptimeMs: 5','2026-01-01 12:00:00 system_server_crash (text, 10 bytes)','SystemUptimeMs: 1'])
        self.assertEqual(r[1]['boot_confidence'],'candidate_only');self.assertIsNone(r[3]['boundary']);self.assertEqual(r[3]['kind'],'retained_history')
    def test_context_carries_metadata_for_context_and_hits(self):
        p=self.file('------ EVENT LOG ------\n01-01 12:00:00.000 1 2 I Tag: found\n')
        rows=list(locate(p,['found'],1,1,annotate=True));self.assertEqual(len(rows[0]),5);self.assertEqual(rows[1][4]['kind'],'log')
    def test_package_state_cannot_borrow_other_packages_or_sections(self):
        p=self.file('DUMP OF SERVICE package:\n  Package [before] (1):\n    User 0: installed=false\n  Package [example.app] (2):\n    versionCode=4 minSdk=21\n    versionName=2.0\n    installerPackageName=example.store\n    User 0: installed=true hidden=false suspended=false stopped=true enabled=0\n    User 10: installed=false suspended=true\n  Package [after] (3):\n    User 99: installed=true\nDUMP OF SERVICE device_policy:\n    User 88: installed=true\n')
        r=extract(p,'example.app')['records'];self.assertEqual(len(r),1);self.assertEqual([u['user_id'] for u in r[0]['users']],[0,10]);self.assertEqual(r[0]['metadata']['versionCode']['value'],'4');self.assertEqual(r[0]['users'][0]['state']['enabled'],'0')
    def test_version_name_with_spaces_is_retained(self):
        r=extract(self.file('  Package [x] (1):\n    versionName=2.0 release candidate\n    User 0: installed=true\n'),'x')
        self.assertEqual(r['records'][0]['metadata']['versionName']['value'],'2.0 release candidate')
    def test_missing_package_does_not_report_uninstalled(self):
        self.assertEqual(extract(self.file('plain\n'),'missing')['records'],[])
    def test_package_repeated_captures_not_merged(self):
        z=Path(self.tmp.name)/'multi.zip'
        with zipfile.ZipFile(z,'w') as f:
            for name,state in [('a.txt','true'),('b.txt','false')]:f.writestr(name,f'  Package [x] (1):\n    User 0: installed={state}\n')
        r=extract(z,'x')['records'];self.assertEqual(len(r),2);self.assertNotEqual(r[0]['source'],r[1]['source'])
    def test_uid_decoding_and_invalid_identity(self):
        self.assertEqual(uid_identity(1012345)['user_id'],10);self.assertEqual(uid_identity(1012345)['app_id'],12345)
        for value in [-1,'u10_a345']:
            with self.assertRaises(ValueError):uid_identity(value)
    def test_utc_dst_zone_and_explicit_offset(self):
        t=datetime(2026,7,1,11,tzinfo=timezone.utc)
        x=match_utc('07-01 12:00:00.000 1 2 I X: event',t,0,{'zone':'Europe/London','status':'zone'})
        self.assertTrue(x['incident_window'])
        self.assertTrue(match_utc('2026-07-01T11:00:00Z event',t,0)['incident_window'])
    def test_utc_missing_zone_is_unknown_not_false(self):
        x=match_utc('07-01 12:00:00 event',datetime(2026,7,1,12,tzinfo=timezone.utc),15)
        self.assertIsNone(x['incident_window'])
    def test_dst_fold_and_gap_remain_unknown(self):
        for text,dt in [('2026-10-25 01:30:00',datetime(2026,10,25,1,tzinfo=timezone.utc)),('2026-03-29 01:30:00',datetime(2026,3,29,1,tzinfo=timezone.utc))]:
            x=match_utc(text,dt,60,{'zone':'Europe/London','status':'zone'});self.assertIsNone(x['incident_window'])
    def test_conflicting_header_zone_not_silently_selected(self):
        p=self.file('== dumpstate: 2026-07-01 12:00:00+0000\n[persist.sys.timezone]: [Europe/London]\n')
        d=clock_inventory(p)['members'][p.name];self.assertEqual(d['status'],'header_zone_conflict');self.assertIsNone(d['zone'])
    def test_invalid_report_zone_is_unresolved_not_a_failed_scan(self):
        p=self.file('[persist.sys.timezone]: [../invalid]\n')
        self.assertEqual(clock_inventory(p)['members'][p.name]['status'],'unrecognized_zone')
    def test_fixed_header_offset_and_user_override(self):
        p=self.file('== dumpstate: 2026-01-01 12:00:00+0530\n')
        d=clock_inventory(p)['members'][p.name];self.assertEqual(d['offset'],19800)
        self.assertEqual(clock_inventory(p,override='UTC')['members'][p.name]['status'],'user_override')
    def test_utc_inventory_is_member_specific(self):
        p=Path(self.tmp.name)/'multi.zip'
        with zipfile.ZipFile(p,'w') as z:
            z.writestr('a.txt','[persist.sys.timezone]: [UTC]\n01-01 12:00:00.000 1 2 E Tag: FATAL EXCEPTION\n')
            z.writestr('b.txt','[persist.sys.timezone]: [Asia/Kolkata]\n01-01 12:00:00.000 1 2 E Tag: FATAL EXCEPTION\n')
        d=analyse(p,'auto',[],datetime(2026,1,1,12),1,utc=True)
        rows=next(x for x in d['findings'] if x['id']=='crash-or-anr')['evidence'];self.assertEqual({x['source']:x['incident_window'] for x in rows},{'a.txt':True});self.assertEqual(d['time_alignment']['members']['b.txt']['zone'],'Asia/Kolkata');self.assertFalse(match_utc('01-01 12:00:00 event',datetime(2026,1,1,12,tzinfo=timezone.utc),1,d['time_alignment']['members']['b.txt'])['incident_window'])
    def test_utc_cli_from_case_workspace(self):
        p=self.file('[persist.sys.timezone]: [UTC]\n01-01 12:00:00.000 1 2 E X: FATAL EXCEPTION\n')
        out=Path(self.tmp.name)/'result.json';r=subprocess.run([sys.executable,str(ROOT/'scripts/triage.py'),str(p),'--utc','--incident','2026-01-01T12:00:00Z','--json',str(out)],cwd=self.tmp.name,capture_output=True,text=True)
        self.assertEqual(r.returncode,0,r.stderr);self.assertIn('2026-01-01',json.loads(out.read_text())['incident_utc'])
    def test_saved_call_history_inside_service_dump_is_history(self):
        rows=self.track(['DUMP OF SERVICE telecom:', '  14:00:02.000 - SET_ACTIVE'])
        self.assertEqual(rows[-1]['kind'],'retained_history')
        self.assertIsNone(rows[-1]['boot_epoch'])
    def test_provisioning_secret_extras_redacted(self):
        for key in ['android.app.extra.PROVISIONING_WIFI_PASSWORD','com.google.android.apps.work.clouddpc.EXTRA_ENROLLMENT_TOKEN']:
            self.assertNotIn('invented-sensitive-value',redact(key+'=invented-sensitive-value'))
    def test_enterprise_leads_do_not_claim_outcomes(self):
        p=self.file('CloudDPC policy request\nnonComplianceDetails appliedPolicyVersion=4\nAMAPI command=sample PENDING\nFinsky install delivery\nPROVISIONING_DEVICE_ADMIN_COMPONENT_NAME=example/.Admin\nprofileGroupId=0 COPE\nsetDelegatedScopes example\n')
        d=analyse(p,'auto',[],None,15);ids={x['id'] for x in d['findings']};self.assertTrue({'android-management','amapi-compliance','managed-install-command','managed-play-handoff','provisioning-input','profile-boundary','policy-delegation'}<=ids)

if __name__=='__main__':unittest.main()
