"""Coordinates for the dashboard's status-over-time line charts, drawn as inline SVG (ADR-0014)."""
import math
from dataclasses import dataclass, field
from typing import Iterator, Sequence

from domain.trend import SEVERITIES, StatusSeries

WIDTH, HEIGHT = 640, 220
LEFT, RIGHT_GUTTER, TOP, BOTTOM_GUTTER = 40, 110, 12, 28  # the right gutter holds the end labels
LABEL_GAP = 13  # minimum vertical distance between end labels


@dataclass(frozen=True)
class Series:
    key: str
    label: str
    values: list[int | None]
    dashed: bool = False


@dataclass(frozen=True)
class Point:
    index: int
    x: float
    y: float
    value: int


@dataclass(frozen=True)
class Tick:
    value: int
    y: float


@dataclass(frozen=True)
class AxisLabel:
    text: str
    x: float
    anchor: str


@dataclass
class Line:
    key: str
    label: str
    dashed: bool
    points: list[Point]
    segments: list[str]  # SVG polyline "x,y x,y" strings; a missing value starts a new one
    label_y: float | None = None


@dataclass
class Chart:
    width: int
    height: int
    left: float
    right: float
    top: float
    bottom: float
    y_ticks: list[Tick]
    x_labels: list[AxisLabel]
    lines: list[Line] = field(default_factory=list)


@dataclass
class StatusCharts:
    series: StatusSeries
    ports: Chart
    cves: Chart | None
    cve_note: str | None  # why there is no CVE chart


def status_charts(series: StatusSeries) -> StatusCharts:
    """The open-ports chart, and the CVE chart when at least two scans have CVE counts."""
    dates = [p.completed_at for p in series.points]
    ports = line_chart(dates, [Series('ports', 'Open ports', [p.counts.open_ports for p in series.points]),
                               Series('hosts', 'Hosts', [p.counts.hosts for p in series.points])])
    if not series.cve_lookup:
        return StatusCharts(series, ports, None, "These scans didn't look up CVEs.")
    counted = [p.counts.cves for p in series.points]
    if sum(c is not None for c in counted) < 2:
        return StatusCharts(series, ports, None,
                            "Fewer than two of these scans finished their CVE lookup, so there's no CVE trend yet.")
    cves = line_chart(dates, [Series(sev, sev.capitalize(), [c[sev] if c is not None else None for c in counted],
                                     dashed=sev == 'other') for sev in SEVERITIES])
    return StatusCharts(series, ports, cves, None)


def line_chart(dates: Sequence[str], series: Sequence[Series]) -> Chart:
    """Scans spaced evenly along x in the order given; every series on one y scale from zero."""
    left, right, top, bottom = LEFT, WIDTH - RIGHT_GUTTER, TOP, HEIGHT - BOTTOM_GUTTER
    largest = max((v for s in series for v in s.values if v is not None), default=0)
    ticks = _ticks(largest)
    scale = (bottom - top) / ticks[-1]
    step = (right - left) / max(len(dates) - 1, 1)

    chart = Chart(WIDTH, HEIGHT, left, right, top, bottom,
                  y_ticks=[Tick(t, bottom - t * scale) for t in ticks],
                  x_labels=[AxisLabel(dates[0][:10], left, 'start'), AxisLabel(dates[-1][:10], right, 'end')])
    labelled: list[tuple[Line, float]] = []
    for s in series:
        points = [Point(i, left + i * step, bottom - v * scale, v) for i, v in enumerate(s.values) if v is not None]
        line = Line(s.key, s.label, s.dashed, points, _segments(points))
        if points and points[-1].index == len(dates) - 1:  # label lines that reach the latest scan
            labelled.append((line, points[-1].y))
        chart.lines.append(line)
    for line, y in _spread_labels(labelled, top, bottom):
        line.label_y = y
    return chart


def _ticks(largest: int) -> list[int]:
    """Round steps from zero up to at least largest: about four of them."""
    step = next(s for s in _nice_steps() if s * 4 >= largest)
    return list(range(0, max(math.ceil(largest / step), 1) * step + 1, step))


def _nice_steps() -> Iterator[int]:
    magnitude = 1
    while True:
        for base in (1, 2, 5):
            yield base * magnitude
        magnitude *= 10


def _segments(points: list[Point]) -> list[str]:
    runs: list[list[Point]] = []
    for p in points:
        if runs and runs[-1][-1].index == p.index - 1:
            runs[-1].append(p)
        else:
            runs.append([p])
    return [' '.join(f'{p.x:.1f},{p.y:.1f}' for p in run) for run in runs if len(run) > 1]


def _spread_labels(labelled: list[tuple[Line, float]], top: float, bottom: float) -> list[tuple[Line, float]]:
    """Move end labels apart so none overlap, keeping them between the top of the plot and just below its baseline."""
    labelled = sorted(labelled, key=lambda pair: pair[1])
    ys = [y for _, y in labelled]
    for i in range(1, len(ys)):  # push down past the label above
        ys[i] = max(ys[i], ys[i - 1] + LABEL_GAP)
    if ys:
        ys[-1] = min(ys[-1], bottom + LABEL_GAP)
    for i in range(len(ys) - 2, -1, -1):  # then up, only as far as the label below needs
        ys[i] = max(min(ys[i], ys[i + 1] - LABEL_GAP), top)
    return [(line, y) for (line, _), y in zip(labelled, ys)]
