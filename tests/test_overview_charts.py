"""Charts must preserve units, unknowns, profile boundaries and source evidence."""
from copy import deepcopy
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from overview import analyse_overview, as_text
from overview_charts import snapshot_metrics, render_charts
from overview_html import render


class ChartTests(unittest.TestCase):
    def setUp(self):
        self.report = analyse_overview(ROOT / 'tests/fixtures/overview.txt')
        self.capture = self.report['captures'][0]

    def test_snapshot_ratios_and_source_pointers(self):
        charts = snapshot_metrics(self.capture)
        self.assertEqual(charts['battery']['percent'], 78)
        self.assertEqual(charts['memory']['total'], 8000000)
        self.assertEqual(charts['memory']['part'], 2500000)
        self.assertEqual(charts['memory']['label'], 'Free (includes cache)')
        storage = charts['storage'][0]
        self.assertEqual(storage['free'] / storage['total'], .1)
        self.assertTrue(all(r['source'] and r['line'] for r in storage['rows']))
        html = render_charts(self.capture, 'capture-1')
        self.assertIn('10.0% free', html)
        self.assertIn('Source values', html)
        self.assertIn(f"{storage['rows'][0]['source']}:{storage['rows'][0]['line']}", html)

    def test_missing_conflicting_or_invalid_values_are_not_plotted(self):
        baseline = deepcopy(self.capture)
        for value in ('nan', 'inf', '-1', '200'):
            self.capture = deepcopy(baseline)
            row = next(r for r in self.capture['health'] if r['label'] == 'Battery · level')
            row['value'] = value
            self.assertIsNone(snapshot_metrics(self.capture)['battery'])
        self.capture = deepcopy(baseline)
        duplicate = deepcopy(next(r for r in self.capture['health'] if r['label'] == 'Memory · Total RAM'))
        duplicate['value'] = '16,000,000K'
        self.capture['health'].append(duplicate)
        self.assertIsNone(snapshot_metrics(self.capture)['memory'])
        self.capture['health'] = []
        charts = snapshot_metrics(self.capture)
        self.assertIsNone(charts['battery'])
        self.assertIsNone(charts['memory'])
        self.assertEqual(charts['storage'], [])
        self.assertNotIn('<svg', render_charts(self.capture, 'capture-1'))

    def test_scale_and_frozen_readings(self):
        row = next(r for r in self.capture['health'] if r['label'] == 'Battery · scale')
        row['value'] = '200'
        self.capture['health'].append(dict(row, label='Battery · updates stopped', value='UPDATES STOPPED'))
        charts = snapshot_metrics(self.capture)
        self.assertEqual(charts['battery']['percent'], 39)
        self.assertTrue(charts['battery']['frozen'])
        self.assertIn('frozen or simulated', render_charts(self.capture, 'capture-1'))

    def test_memavailable_is_distinct_and_requires_comparable_total(self):
        template = self.capture['health'][0]
        self.capture['health'] += [dict(template, label='Memory · MemTotal', value='9000000 kB', section='MEMORY INFO'),
                                   dict(template, label='Memory · MemAvailable', value='3000000 kB', section='MEMORY INFO')]
        memory = snapshot_metrics(self.capture)['memory']
        self.assertEqual(memory['label'], 'Available')
        self.assertEqual(memory['total'], 9000000)
        self.capture['health'][-1]['section'] = 'OTHER MEMORY INFO'
        self.assertEqual(snapshot_metrics(self.capture)['memory']['label'], 'Free (includes cache)')

    def test_packages_are_unique_active_and_scoped_to_user(self):
        self.capture['packages'].append(deepcopy(self.capture['packages'][0]))
        users = snapshot_metrics(self.capture)['apps']
        self.assertEqual([u['user'] for u in users], [0, 10])
        self.assertEqual([u['installed'] for u in users], [1, 2])
        self.assertEqual([u['suspended'] for u in users], [0, 1])
        self.assertEqual([u['records'] for u in users], [2, 2])
        self.capture['packages'][-1]['users'][1]['state']['installed'] = 'false'
        charts = snapshot_metrics(self.capture)
        self.assertEqual(charts['app_conflicts'], 1)
        self.assertEqual(charts['apps'][1]['installed'], 1)

    def test_missing_package_fields_are_unknown_not_false(self):
        self.capture['packages'][0]['users'][1]['state'].pop('installed')
        self.capture['packages'][1]['users'][1]['state'].pop('suspended')
        charts = snapshot_metrics(self.capture)
        self.assertEqual(charts['apps'][1]['unknown_install'], 1)
        self.assertEqual(charts['apps'][1]['unknown_suspension'], 1)
        self.assertIn('Unknown fields', render_charts(self.capture, 'capture-1'))

    def test_reports_keep_limits_but_omit_development_banners(self):
        report = analyse_overview(ROOT / 'tests/fixtures/overview.txt', max_rows=1, max_packages=1)
        before = deepcopy(report)
        html = render(report)
        self.assertEqual(report, before)
        self.assertIn('Charts show only the retained values', html)
        self.assertIn('omitted', html)
        self.assertNotIn('Under testing', html)
        self.assertNotIn('Under testing', as_text(report))
        self.assertNotIn('Under testing', report['notice'])

    def test_clipped_values_do_not_claim_inventory_rows_were_dropped(self):
        self.capture['omitted_rows'] = {'long_values_clipped': 2}
        html = render(self.report)
        self.assertIn('2 long values are shortened', html)
        self.assertNotIn('Some rows were left out', html)


if __name__ == '__main__':
    unittest.main()
