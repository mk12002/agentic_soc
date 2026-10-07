"""Charts for generated reports.

A report source may return ``"chart": {"title", "categories", "series": [{"name", "values"}]}``. The data is computed
in code like every other figure; the model never sees or shapes it. PowerPoint gets a native (editable) chart, Word a
PNG drawn with Pillow - no plotting library, and the same data always gives the same bytes.
"""

from __future__ import annotations

import io
from typing import Any

from PIL import Image, ImageDraw, ImageFont

SEVERITY_ORDER = ("critical", "high", "medium", "low", "informational")
# colour-blind-safe categorical palette (one colour per series)
PALETTE = ((0x2F, 0x6B, 0xB3), (0xE0, 0x8A, 0x1E), (0x3A, 0x9E, 0x6E), (0xB8, 0x4A, 0x62), (0x6B, 0x5B, 0xA8))


def from_counts(title: str, counts: dict[str, Any], *, name: str = "Count", order: tuple[str, ...] = ()) -> dict | None:
    """One series from a {category: number} mapping; known categories first in ``order``. None when empty."""
    keys = [k for k in order if k in counts] + sorted(k for k in counts if k not in order)
    values = [_num(counts[k]) for k in keys]
    if not keys or not any(values):
        return None
    return {"title": title, "categories": [str(k) for k in keys], "series": [{"name": name, "values": values}]}


def valid(chart: dict | None) -> bool:
    if not chart or not chart.get("categories") or not chart.get("series"):
        return False
    n = len(chart["categories"])
    return all(len(s["values"]) == n for s in chart["series"]) and any(v for s in chart["series"] for v in s["values"])


def _num(v: Any) -> float:
    try:
        return float(v or 0)
    except (TypeError, ValueError):
        return 0.0


def _font(size: int) -> ImageFont.ImageFont | ImageFont.FreeTypeFont:
    try:
        return ImageFont.load_default(size=size)
    except TypeError:                                  # Pillow without FreeType: fixed bitmap font
        return ImageFont.load_default()


def _fmt(v: float) -> str:
    return str(int(v)) if float(v).is_integer() else f"{v:.1f}"


def to_png(chart: dict, *, width: int = 1400) -> bytes:
    """Horizontal grouped bar chart: categories down the side, one bar per series, value at the end of each bar."""
    cats, series = chart["categories"], chart["series"]
    title_f, label_f, small_f = _font(30), _font(22), _font(18)
    probe = ImageDraw.Draw(Image.new("RGB", (1, 1)))
    label_w = min(520, max(int(probe.textlength(c, font=label_f)) for c in cats) + 30)
    bar_h, gap = 30, 22
    group_h = bar_h * len(series)
    legend_h = 44 if len(series) > 1 else 0
    top = 80 + legend_h
    height = top + len(cats) * (group_h + gap) + 30
    img = Image.new("RGB", (width, height), "white")
    d = ImageDraw.Draw(img)
    d.text((30, 22), chart["title"], fill=(0x1F, 0x29, 0x37), font=title_f)
    if legend_h:
        x = 30
        for i, s in enumerate(series):
            d.rectangle((x, 76, x + 22, 98), fill=PALETTE[i % len(PALETTE)])
            d.text((x + 30, 74), s["name"], fill=(0x37, 0x41, 0x51), font=small_f)
            x += 60 + int(probe.textlength(s["name"], font=small_f))
    peak = max(max(s["values"]) for s in series) or 1.0
    plot_x0, plot_x1 = label_w + 40, width - 110
    y = top
    for ci, cat in enumerate(cats):
        text = cat if probe.textlength(cat, font=label_f) <= label_w else cat[: max(4, int(len(cat) * label_w / probe.textlength(cat, font=label_f)) - 1)] + "…"
        d.text((30, y + group_h / 2 - 13), text, fill=(0x37, 0x41, 0x51), font=label_f)
        for si, s in enumerate(series):
            v = s["values"][ci]
            x1 = plot_x0 + (plot_x1 - plot_x0) * (v / peak)
            by = y + si * bar_h
            d.rectangle((plot_x0, by + 3, max(plot_x0 + 2, x1), by + bar_h - 3), fill=PALETTE[si % len(PALETTE)])
            d.text((max(plot_x0 + 2, x1) + 8, by + 4), _fmt(v), fill=(0x37, 0x41, 0x51), font=small_f)
        y += group_h + gap
    d.line((plot_x0, top - 8, plot_x0, y - gap + 6), fill=(0xC8, 0xCD, 0xD3), width=2)
    buf = io.BytesIO()
    img.save(buf, format="PNG", optimize=True)
    return buf.getvalue()


def add_pptx_chart(slide: Any, chart: dict, x: Any, y: Any, w: Any, h: Any) -> Any:
    """A native PowerPoint bar chart (editable in PowerPoint, data in the embedded sheet)."""
    from pptx.chart.data import CategoryChartData
    from pptx.enum.chart import XL_CHART_TYPE, XL_LEGEND_POSITION
    from pptx.util import Pt

    data = CategoryChartData()
    data.categories = chart["categories"]
    for s in chart["series"]:
        data.add_series(s["name"], s["values"])
    gf = slide.shapes.add_chart(XL_CHART_TYPE.BAR_CLUSTERED, x, y, w, h, data)
    ch = gf.chart
    ch.has_title = True
    ch.chart_title.text_frame.text = chart["title"]
    ch.has_legend = len(chart["series"]) > 1
    if ch.has_legend:
        ch.legend.position = XL_LEGEND_POSITION.BOTTOM
        ch.legend.include_in_layout = False
    plot = ch.plots[0]
    plot.has_data_labels = True
    plot.data_labels.font.size = Pt(11)
    ch.category_axis.reverse_order = True               # first category at the top, as in the table
    ch.category_axis.tick_labels.font.size = Pt(11)
    for i, s in enumerate(plot.series):
        s.format.fill.solid()
        r, g, b = PALETTE[i % len(PALETTE)]
        from pptx.dml.color import RGBColor

        s.format.fill.fore_color.rgb = RGBColor(r, g, b)
    return gf
