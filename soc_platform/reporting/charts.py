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
PALETTE = ((0x25, 0x63, 0xEB), (0xE0, 0x8A, 0x1E), (0x3A, 0x9E, 0x6E), (0xB8, 0x4A, 0x62), (0x6B, 0x5B, 0xA8))
# meaning-bearing colours, shared with the Word / PowerPoint house style (reporting/design.py)
STATUS = {"critical": (0xB9, 0x1C, 0x1C), "high": (0xEA, 0x58, 0x0C), "medium": (0xCA, 0x8A, 0x04),
          "low": (0x25, 0x63, 0xEB), "informational": (0x9C, 0xA3, 0xAF),
          "P1": (0xB9, 0x1C, 0x1C), "P2": (0xEA, 0x58, 0x0C), "P3": (0xCA, 0x8A, 0x04), "P4": (0x9C, 0xA3, 0xAF),
          "malicious": (0xB9, 0x1C, 0x1C), "suspicious": (0xEA, 0x58, 0x0C), "spam": (0xCA, 0x8A, 0x04),
          "safe": (0x15, 0x80, 0x3D), "pending": (0x9C, 0xA3, 0xAF),
          "past SLA": (0xB9, 0x1C, 0x1C), "within SLA": (0x25, 0x63, 0xEB)}
INK, SOFT, GRID = (0x1F, 0x29, 0x37), (0x6B, 0x72, 0x80), (0xE5, 0xE7, 0xEB)


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
            colour = STATUS.get(cat, PALETTE[si % len(PALETTE)]) if len(series) == 1 else PALETTE[si % len(PALETTE)]
            d.rectangle((plot_x0, by + 3, max(plot_x0 + 2, x1), by + bar_h - 3), fill=colour)
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


# ---------------------------------------------------------------------------------------------------- house charts


def nice_step(peak: float, ticks: int = 5) -> int:
    """A whole-number axis step a reader expects (1, 2, 5, 10, 20, 25, 50, ...), about ``ticks`` steps to the peak."""
    raw = max(1.0, float(peak) / ticks)
    magnitude = 10 ** int(len(str(int(raw))) - 1)
    for m in (1, 2, 2.5, 5, 10):
        step = m * magnitude
        if step >= raw and float(step).is_integer():
            return int(step)
    return int(10 * magnitude)


def color_for(label: str, i: int) -> tuple[int, int, int]:
    return STATUS.get(label, PALETTE[i % len(PALETTE)])


def _png(img: Image.Image) -> bytes:
    buf = io.BytesIO()
    img.save(buf, format="PNG", optimize=True)
    return buf.getvalue()


def donut_png(title: str, counts: dict[str, Any], *, order: tuple[str, ...] = (), size: int = 900,
              centre_label: str = "total") -> bytes | None:
    """A donut with the total in the middle and a legend with each share. None when there is nothing to draw."""
    keys = [k for k in order if counts.get(k)] + sorted(k for k in counts if k not in order and counts.get(k))
    values = [_num(counts[k]) for k in keys]
    total = sum(values)
    if not total:
        return None
    w, h = size, int(size * 0.62)
    img = Image.new("RGB", (w, h), "white")
    d = ImageDraw.Draw(img)
    d.text((24, 16), title, fill=INK, font=_font(36))
    box = (40, 86, 40 + h - 116, h - 30)
    start = -90.0
    for i, (k, v) in enumerate(zip(keys, values, strict=True)):
        sweep = 360.0 * v / total
        d.pieslice(box, start, start + sweep, fill=color_for(k, i))
        start += sweep
    inset = (box[2] - box[0]) * 0.27
    d.ellipse((box[0] + inset, box[1] + inset, box[2] - inset, box[3] - inset), fill="white")
    cx, cy = (box[0] + box[2]) / 2, (box[1] + box[3]) / 2
    big, small = _font(54), _font(20)
    tw = d.textlength(_fmt(total), font=big)
    d.text((cx - tw / 2, cy - 42), _fmt(total), fill=INK, font=big)
    lw = d.textlength(centre_label, font=small)
    d.text((cx - lw / 2, cy + 18), centre_label, fill=SOFT, font=small)
    lx, ly = box[2] + 50, 110
    lf = _font(32)
    for i, (k, v) in enumerate(zip(keys, values, strict=True)):
        d.rounded_rectangle((lx, ly + 6, lx + 28, ly + 34), 5, fill=color_for(k, i))
        d.text((lx + 42, ly), f"{k}", fill=INK, font=lf)
        d.text((lx + 42 + d.textlength(str(k), font=lf) + 14, ly), f"{_fmt(v)}  ({100 * v / total:.0f}%)", fill=SOFT, font=lf)
        ly += 54
    return _png(img)


def stacked_png(title: str, categories: list[str], series: list[tuple[str, list[float]]], *, width: int = 900) -> bytes | None:
    """Horizontal stacked bars, one per category (for example a team: within SLA / past SLA), totals at the end."""
    if not categories or not any(v for _, vals in series for v in vals):
        return None
    lab_f, small_f = _font(30), _font(27)
    probe = ImageDraw.Draw(Image.new("RGB", (1, 1)))
    label_w = min(380, max(int(probe.textlength(c, font=lab_f)) for c in categories) + 24)
    bar_h, gap, top = 52, 22, 140
    height = top + len(categories) * (bar_h + gap) + 20
    img = Image.new("RGB", (width, height), "white")
    d = ImageDraw.Draw(img)
    d.text((24, 16), title, fill=INK, font=_font(36))
    x = 24
    for i, (name, _) in enumerate(series):
        d.rounded_rectangle((x, 80, x + 26, 106), 5, fill=color_for(name, i))
        d.text((x + 36, 77), name, fill=SOFT, font=small_f)
        x += 70 + int(probe.textlength(name, font=small_f))
    totals = [sum(vals[i] for _, vals in series) for i in range(len(categories))]
    peak = max(totals) or 1
    x0, x1 = label_w + 36, width - 70
    y = top
    for ci, cat in enumerate(categories):
        d.text((24, y + 9), cat[:40], fill=INK, font=lab_f)
        cx = x0
        for si, (name, vals) in enumerate(series):
            seg = (x1 - x0) * vals[ci] / peak
            if seg > 0:
                d.rectangle((cx, y, cx + seg, y + bar_h), fill=color_for(name, si))
                if seg > 30:
                    tw = d.textlength(_fmt(vals[ci]), font=small_f)
                    d.text((cx + seg / 2 - tw / 2, y + 11), _fmt(vals[ci]), fill="white", font=small_f)
            cx += seg
        d.text((cx + 10, y + 11), _fmt(totals[ci]), fill=INK, font=small_f)
        y += bar_h + gap
    return _png(img)


def columns_png(title: str, categories: list[str], series: list[tuple[str, list[float]]], *, width: int = 1100,
                height: int = 560) -> bytes | None:
    """Vertical stacked columns (for example findings by age bucket, stacked by priority), whole-number grid."""
    if not categories or not any(v for _, vals in series for v in vals):
        return None
    img = Image.new("RGB", (width, height), "white")
    d = ImageDraw.Draw(img)
    small_f, lab_f = _font(19), _font(21)
    d.text((24, 16), title, fill=INK, font=_font(30))
    x = 24
    probe = d
    for i, (name, _) in enumerate(series):
        d.rounded_rectangle((x, 70, x + 20, 90), 4, fill=color_for(name, i))
        d.text((x + 28, 68), name, fill=SOFT, font=small_f)
        x += 60 + int(probe.textlength(name, font=small_f))
    totals = [sum(vals[i] for _, vals in series) for i in range(len(categories))]
    peak = max(totals) or 1
    step = nice_step(peak)
    top, bottom, left, right = 120, height - 60, 70, width - 30
    ticks = list(range(0, int(peak) + step + 1, step))
    scale = (bottom - top) / ticks[-1]
    for tv in ticks:
        ty = bottom - tv * scale
        d.line((left, ty, right, ty), fill=GRID, width=2)
        d.text((left - 12 - d.textlength(str(tv), font=small_f), ty - 11), str(tv), fill=SOFT, font=small_f)
    slot = (right - left) / len(categories)
    cw = slot * 0.55
    for ci, cat in enumerate(categories):
        cx = left + slot * ci + (slot - cw) / 2
        y = bottom
        for si, (name, vals) in enumerate(series):
            hgt = vals[ci] * scale
            if hgt > 0:
                d.rectangle((cx, y - hgt, cx + cw, y), fill=color_for(name, si))
            y -= hgt
        if totals[ci]:
            tw = d.textlength(_fmt(totals[ci]), font=small_f)
            d.text((cx + cw / 2 - tw / 2, y - 26), _fmt(totals[ci]), fill=INK, font=small_f)
        lw = d.textlength(cat, font=lab_f)
        d.text((cx + cw / 2 - lw / 2, bottom + 12), cat, fill=INK, font=lab_f)
    return _png(img)
