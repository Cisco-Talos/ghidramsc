# SPDX-License-Identifier: Apache-2.0
#
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Build the standalone GhidraMSC user manual PDF from its Markdown source.

This intentionally supports the small Markdown vocabulary used by USER_MANUAL.md:
headings, paragraphs, numbered/bulleted steps, fenced code, local screenshots,
and inline code and links. It never fetches network resources.
"""

from __future__ import annotations

import argparse
import html
import re
from pathlib import Path

import reportlab
from PIL import Image as PILImage
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    BaseDocTemplate, Flowable, Frame, Image, KeepTogether, PageBreak,
    PageTemplate, Paragraph, Preformatted, Spacer,
)
from reportlab.platypus.tableofcontents import TableOfContents


HERE = Path(__file__).resolve().parent
BLUE = colors.HexColor("#15466E")
INK = colors.HexColor("#203047")
MUTED = colors.HexColor("#526478")
PAGE_W, PAGE_H = letter
CONTENT_W = PAGE_W - 116


def register_fonts() -> None:
    font_dir = Path(reportlab.__file__).resolve().parent / "fonts"
    for name, file in (
        ("Vera", "Vera.ttf"),
        ("Vera-Bold", "VeraBd.ttf"),
        ("Vera-Italic", "VeraIt.ttf"),
    ):
        pdfmetrics.registerFont(TTFont(name, str(font_dir / file)))
    pdfmetrics.registerFontFamily(
        "Vera", normal="Vera", bold="Vera-Bold", italic="Vera-Italic"
    )


def slug(title: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-")


def inline(text: str) -> str:
    chunks = re.split(r"(`[^`]+`|\[[^]]+\]\([^)]+\))", text)
    result: list[str] = []
    for chunk in chunks:
        if chunk.startswith("`") and chunk.endswith("`"):
            result.append(f'<font name="Courier" color="#15466E">{html.escape(chunk[1:-1])}</font>')
        elif chunk.startswith("[") and "](" in chunk:
            match = re.fullmatch(r"\[([^]]+)\]\(([^)]+)\)", chunk)
            assert match is not None
            label, target = match.groups()
            if target.startswith("#") or target.startswith("https://"):
                result.append(f'<link href="{html.escape(target)}" color="#0B5E90"><u>{html.escape(label)}</u></link>')
            else:
                result.append(html.escape(label))
        else:
            result.append(html.escape(chunk))
    return "".join(result)


class ManualDoc(BaseDocTemplate):
    def __init__(self, filename: str):
        super().__init__(
            filename,
            pagesize=letter,
            leftMargin=58,
            rightMargin=58,
            topMargin=66,
            bottomMargin=58,
            title="GhidraMSC User Manual",
            author="GhidraMSC project",
            subject="Installation and task-oriented use of GhidraMSC",
        )
        frame = Frame(58, 58, CONTENT_W, PAGE_H - 124, leftPadding=0,
                      rightPadding=0, topPadding=0, bottomPadding=0)
        self.addPageTemplates(PageTemplate(id="main", frames=frame, onPage=self._page))

    def _page(self, canvas, doc) -> None:
        canvas.saveState()
        canvas.setStrokeColor(colors.HexColor("#D2DCE5"))
        canvas.line(58, PAGE_H - 48, PAGE_W - 58, PAGE_H - 48)
        canvas.setFont("Vera", 8)
        canvas.setFillColor(MUTED)
        canvas.drawString(58, PAGE_H - 38, "GHIDRAMSC  |  USER MANUAL")
        canvas.line(58, 46, PAGE_W - 58, 46)
        canvas.drawString(58, 31, "Ghidra 12.1.4  |  October 2026")
        canvas.drawRightString(PAGE_W - 58, 31, str(doc.page))
        canvas.restoreState()

    def afterFlowable(self, flowable: Flowable) -> None:
        key = getattr(flowable, "_bookmark", None)
        if key:
            level = getattr(flowable, "_level", 0)
            title = getattr(flowable, "_title", "")
            self.canv.bookmarkPage(key)
            self.canv.addOutlineEntry(title, key, level=level, closed=False)
            self.notify("TOCEntry", (level, title, self.page, key))


def styles() -> dict[str, ParagraphStyle]:
    return {
        "title": ParagraphStyle("title", fontName="Vera-Bold", fontSize=27,
                                leading=34, textColor=BLUE, spaceAfter=18),
        "subtitle": ParagraphStyle("subtitle", fontName="Vera", fontSize=12,
                                   leading=18, textColor=MUTED, spaceAfter=16),
        "h2": ParagraphStyle("h2", fontName="Vera-Bold", fontSize=17,
                             leading=23, textColor=BLUE, spaceBefore=15,
                             spaceAfter=10, keepWithNext=True),
        "h3": ParagraphStyle("h3", fontName="Vera-Bold", fontSize=11.5,
                             leading=17, textColor=BLUE, spaceBefore=11,
                             spaceAfter=6, keepWithNext=True),
        "body": ParagraphStyle("body", fontName="Vera", fontSize=9.1,
                               leading=14.3, textColor=INK, spaceAfter=7),
        "step": ParagraphStyle("step", fontName="Vera", fontSize=9.1,
                               leading=14.3, textColor=INK, leftIndent=20,
                               firstLineIndent=-18, spaceAfter=6),
        "caption": ParagraphStyle("caption", fontName="Vera-Italic", fontSize=8.2,
                                  leading=11.5, textColor=MUTED, alignment=TA_CENTER,
                                  spaceBefore=5, spaceAfter=12),
        "code": ParagraphStyle("code", fontName="Courier", fontSize=8,
                               leading=11.5, textColor=INK, leftIndent=9,
                               rightIndent=9, spaceBefore=5, spaceAfter=9),
        "toc": ParagraphStyle("toc", fontName="Vera", fontSize=9.5,
                              leading=16, textColor=INK, leftIndent=15,
                              firstLineIndent=-15),
    }


def parse(source: Path) -> list[Flowable]:
    st = styles()
    lines = source.read_text(encoding="utf-8").splitlines()
    story: list[Flowable] = []
    paragraph: list[str] = []
    code: list[str] | None = None
    title_seen = False
    heading_keys: set[str] = set()

    def flush() -> None:
        if paragraph:
            story.append(Paragraph(inline(" ".join(paragraph)), st["body"]))
            paragraph.clear()

    for line in lines + [""]:
        if code is not None:
            if line.startswith("```"):
                if any(len(original) > 77 for original in code):
                    raise ValueError("code line exceeds 77 characters; split it in the source")
                story.append(Preformatted("\n".join(code), st["code"], maxLineLength=77))
                code = None
            else:
                code.append(line)
            continue
        if line.startswith("```"):
            flush()
            code = []
            continue
        if not line.strip():
            flush()
            continue
        if line == "[[TOC]]":
            flush()
            story.append(PageBreak())
            story.append(Paragraph("Contents", st["h2"]))
            toc = TableOfContents()
            toc.levelStyles = [st["toc"], st["toc"]]
            story.append(toc)
            story.append(PageBreak())
            continue
        if line.startswith("# ") and not title_seen:
            flush()
            story.append(Spacer(1, 110))
            story.append(Paragraph(inline(line[2:]), st["title"]))
            title_seen = True
            continue
        match = re.match(r"^(##|###) (.+)$", line)
        if match:
            flush()
            level = 0 if match.group(1) == "##" else 1
            title = match.group(2)
            key = slug(title)
            if key in heading_keys:
                raise ValueError(f"duplicate heading anchor: {key}")
            heading_keys.add(key)
            heading = Paragraph(inline(title), st["h2" if level == 0 else "h3"])
            heading._bookmark = key
            heading._level = level
            heading._title = title
            story.append(heading)
            continue
        image_match = re.fullmatch(r"!\[([^]]+)\]\(([^)]+)\)", line)
        if image_match:
            flush()
            caption, relative = image_match.groups()
            image_path = (source.parent / relative).resolve()
            if source.parent.resolve() not in image_path.parents or not image_path.is_file():
                raise FileNotFoundError(f"missing local screenshot: {relative}")
            with PILImage.open(image_path) as bitmap:
                width, height = bitmap.size
            scale = min(CONTENT_W / width, 315 / height, 1)
            figure = Image(str(image_path), width=width * scale, height=height * scale)
            figure.hAlign = "CENTER"
            story.append(KeepTogether([figure, Paragraph(inline(caption), st["caption"])]))
            continue
        step_match = re.match(r"^(\d+\.|-) (.+)$", line)
        if step_match:
            flush()
            marker, body = step_match.groups()
            label = "•" if marker == "-" else marker
            story.append(Paragraph(f"<b>{label}</b> {inline(body)}", st["step"]))
            continue
        paragraph.append(line.strip())
    if code is not None:
        raise ValueError("unclosed code fence")
    return story


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=HERE / "USER_MANUAL.md")
    parser.add_argument("--output", type=Path, default=HERE / "GhidraMSC_User_Manual.pdf")
    args = parser.parse_args()
    register_fonts()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    doc = ManualDoc(str(args.output))
    doc.multiBuild(parse(args.source))
    print(f"Built {args.output} ({args.output.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
