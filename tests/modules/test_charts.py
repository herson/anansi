import unittest

from domain.trend import ScanCounts, SeriesPoint, StatusSeries
from web.charts import LABEL_GAP, Series, line_chart, status_charts

DATES = ['2026-11-01T02:00:00+00:00', '2026-11-08T02:00:00+00:00', '2026-11-15T02:00:00+00:00']


class TestXAxis(unittest.TestCase):

    def test_scans_are_spaced_evenly_from_the_left_edge_to_the_right(self):
        chart = line_chart(DATES, [Series('ports', 'Open ports', [1, 2, 3])])
        xs = [p.x for p in chart.lines[0].points]
        self.assertEqual(xs[0], chart.left)
        self.assertEqual(xs[-1], chart.right)
        self.assertAlmostEqual(xs[1] - xs[0], xs[2] - xs[1])

    def test_the_first_and_last_dates_label_the_axis(self):
        chart = line_chart(DATES, [Series('ports', 'Open ports', [1, 2, 3])])
        self.assertEqual([(label.text, label.anchor) for label in chart.x_labels],
                         [('2026-11-01', 'start'), ('2026-11-15', 'end')])


class TestYAxis(unittest.TestCase):

    def test_zero_sits_on_the_baseline_and_the_top_tick_covers_the_largest_value(self):
        chart = line_chart(DATES, [Series('ports', 'Open ports', [0, 7, 3])])
        points = chart.lines[0].points
        self.assertEqual(points[0].y, chart.bottom)
        top_tick = chart.y_ticks[-1]
        self.assertGreaterEqual(top_tick.value, 7)
        self.assertEqual(top_tick.y, chart.top)
        self.assertGreater(points[1].y, chart.top - 0.001)

    def test_ticks_are_round_numbers_starting_at_zero(self):
        for largest, expected in ((3, [0, 1, 2, 3]), (7, [0, 2, 4, 6, 8]), (37, [0, 10, 20, 30, 40]),
                                  (0, [0, 1])):
            with self.subTest(largest=largest):
                chart = line_chart(DATES, [Series('ports', 'Open ports', [0, largest, 0])])
                self.assertEqual([t.value for t in chart.y_ticks], expected)

    def test_every_line_shares_one_scale(self):
        chart = line_chart(DATES, [Series('ports', 'Open ports', [10, 10, 10]),
                                   Series('hosts', 'Hosts', [5, 5, 5])])
        ports, hosts = chart.lines
        self.assertAlmostEqual(chart.bottom - hosts.points[0].y, (chart.bottom - ports.points[0].y) / 2)


class TestGaps(unittest.TestCase):

    def test_a_missing_value_breaks_the_line_instead_of_dropping_to_zero(self):
        dates = DATES + ['2026-11-22T02:00:00+00:00']
        chart = line_chart(dates, [Series('high', 'High', [1, None, 2, 3])])
        line = chart.lines[0]
        self.assertEqual([p.index for p in line.points], [0, 2, 3])
        self.assertEqual(len(line.segments), 1)  # the lone first point has no segment
        self.assertEqual(line.segments[0].count(' '), 1)  # "x,y x,y": two points

    def test_a_series_with_no_values_has_no_points_or_end_label(self):
        line = line_chart(DATES, [Series('low', 'Low', [None, None, None])]).lines[0]
        self.assertEqual((line.points, line.segments, line.label_y), ([], [], None))


class TestEndLabels(unittest.TestCase):

    def test_each_line_is_labelled_at_its_last_point(self):
        chart = line_chart(DATES, [Series('ports', 'Open ports', [1, 2, 8])])
        line = chart.lines[0]
        self.assertEqual(line.label_y, line.points[-1].y)
        self.assertGreater(chart.width, chart.right)

    def test_labels_that_would_overlap_are_moved_apart(self):
        chart = line_chart(DATES, [Series('a', 'A', [5, 5, 5]), Series('b', 'B', [5, 5, 5]),
                                   Series('c', 'C', [0, 0, 0])])
        ys = sorted(line.label_y for line in chart.lines)
        self.assertTrue(all(b - a >= LABEL_GAP - 1e-9 for a, b in zip(ys, ys[1:])), ys)
        self.assertTrue(all(chart.top - LABEL_GAP <= y <= chart.bottom + LABEL_GAP for y in ys), ys)


def series(cves_per_scan, cve_lookup=True):
    points = [SeriesPoint(i + 1, DATES[i % 3], ScanCounts(open_ports=i + 2, hosts=1, cves=cves))
              for i, cves in enumerate(cves_per_scan)]
    return StatusSeries('10.0.0.0/24', cve_lookup, points)


def severities(critical=0, other=0):
    return {'critical': critical, 'high': 0, 'medium': 0, 'low': 0, 'other': other}


class TestStatusCharts(unittest.TestCase):

    def test_the_ports_chart_has_open_ports_and_hosts(self):
        charts = status_charts(series([None, None], cve_lookup=False))
        self.assertEqual([(line.key, [p.value for p in line.points]) for line in charts.ports.lines],
                         [('ports', [2, 3]), ('hosts', [1, 1])])

    def test_the_cve_chart_has_a_line_per_severity_with_other_dashed(self):
        charts = status_charts(series([severities(critical=1), severities(other=2)]))
        self.assertEqual([line.key for line in charts.cves.lines], ['critical', 'high', 'medium', 'low', 'other'])
        self.assertEqual([line.dashed for line in charts.cves.lines], [False] * 4 + [True])
        self.assertIsNone(charts.cve_note)

    def test_no_cve_chart_when_the_series_did_not_look_up_cves(self):
        charts = status_charts(series([None, None], cve_lookup=False))
        self.assertIsNone(charts.cves)
        self.assertIn("didn't look up CVEs", charts.cve_note)

    def test_no_cve_chart_when_fewer_than_two_scans_have_cve_counts(self):
        charts = status_charts(series([severities(), None, None]))
        self.assertIsNone(charts.cves)
        self.assertIn('lookup', charts.cve_note)


if __name__ == '__main__':
    unittest.main()
