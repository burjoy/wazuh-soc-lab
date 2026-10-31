#!/usr/bin/env python3
"""Render a Markdown document to PDF with a cover page and table of contents.

Uses Python-Markdown for conversion and headless Chrome for printing. No LaTeX,
pandoc, or system packages required beyond Chrome.

Usage:
    python3 tools/md2pdf.py writeups/INC-001/01-findings-report.md

A document can declare a cover subtitle with an HTML comment after its H1:

    # Title
    <!-- subtitle: A short line for the cover -->

Requires:
    pip install markdown pygments
"""

from __future__ import annotations

import argparse
import datetime
import pathlib
import re
import subprocess
import sys
import tempfile

import markdown

CHROME = "/opt/google/chrome/chrome"

CSS = """
@page {
  size: A4;
  margin: 17mm 15mm 17mm 15mm;
}

* { box-sizing: border-box; -webkit-print-color-adjust: exact; print-color-adjust: exact; }

body {
  font-family: -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
  font-size: 10.2pt;
  line-height: 1.55;
  color: #1f2328;
  margin: 0;
}

article { max-width: 100%; }

h1 {
  font-size: 21pt;
  line-height: 1.2;
  margin: 0 0 6pt 0;
  padding-bottom: 8pt;
  border-bottom: 2px solid #1f2328;
}

h1 + h3, h1 + p { color: #57606a; }

h2 {
  font-size: 14.5pt;
  margin: 20pt 0 7pt 0;
  padding-bottom: 3pt;
  border-bottom: 1px solid #d0d7de;
  page-break-after: avoid;
}

h3 {
  font-size: 11.8pt;
  margin: 14pt 0 5pt 0;
  page-break-after: avoid;
}

p, li { orphans: 2; widows: 2; }

ul, ol { margin: 4pt 0 8pt 0; padding-left: 18pt; }
li { margin: 2pt 0; }

a { color: #0969da; text-decoration: none; }

code {
  font-family: "JetBrains Mono", "SFMono-Regular", Consolas, "Liberation Mono", monospace;
  font-size: 8.4pt;
  background: #f6f8fa;
  padding: 1pt 3pt;
  border-radius: 3pt;
}

pre {
  background: #f6f8fa;
  border: 1px solid #d8dee4;
  border-radius: 5pt;
  padding: 8pt 10pt;
  margin: 7pt 0 10pt 0;
  overflow-wrap: anywhere;
  page-break-inside: auto;
}

pre code {
  background: none;
  padding: 0;
  font-size: 8.1pt;
  line-height: 1.42;
  white-space: pre-wrap;
  word-break: break-word;
}

table {
  width: 100%;
  border-collapse: collapse;
  margin: 8pt 0 12pt 0;
  font-size: 8.9pt;
  page-break-inside: avoid;
}

th, td {
  border: 1px solid #d0d7de;
  padding: 4pt 6pt;
  text-align: left;
  vertical-align: top;
}

th { background: #f6f8fa; font-weight: 600; }
tr:nth-child(even) td { background: #fbfcfd; }

blockquote {
  margin: 8pt 0;
  padding: 6pt 10pt;
  border-left: 3px solid #d0d7de;
  color: #57606a;
  background: #fafbfc;
}

blockquote p { margin: 2pt 0; }

hr {
  border: none;
  border-top: 1px solid #d8dee4;
  margin: 14pt 0;
}

img { max-width: 100%; }

/* ---------- Cover ---------- */

.cover {
  min-height: 245mm;
  display: flex;
  flex-direction: column;
  page-break-after: always;
}

.cover-band {
  height: 7mm;
  background: #0b1f33;
  margin-bottom: 20mm;
}

.cover-eyebrow {
  font-size: 8.5pt;
  letter-spacing: 2.2pt;
  text-transform: uppercase;
  color: #57606a;
  font-weight: 600;
}

.cover-title {
  font-size: 29pt;
  line-height: 1.14;
  border: none;
  padding: 0;
  margin: 5mm 0 4mm 0;
  color: #0b1f33;
}

.cover-subtitle {
  font-size: 13pt;
  line-height: 1.4;
  color: #57606a;
  margin: 0;
  max-width: 150mm;
}

.cover-meta {
  margin-top: 22mm;
  border-top: 1px solid #d0d7de;
  padding-top: 6mm;
}

.cover-meta dl {
  display: grid;
  grid-template-columns: 38mm 1fr;
  row-gap: 3mm;
  margin: 0;
  font-size: 9.5pt;
}

.cover-meta dt {
  color: #57606a;
  text-transform: uppercase;
  letter-spacing: 0.6pt;
  font-size: 8pt;
  padding-top: 1pt;
}

.cover-meta dd { margin: 0; color: #1f2328; }

.cover-footer {
  margin-top: auto;
  padding-top: 8mm;
  border-top: 1px solid #d0d7de;
  font-size: 8pt;
  color: #8c959f;
}

/* ---------- Table of contents ---------- */

.toc-page { page-break-after: always; }

.toc-heading {
  font-size: 19pt;
  border: none;
  padding: 0;
  margin: 0 0 8mm 0;
  color: #0b1f33;
}

.toc { font-size: 10pt; }
.toc > ul { padding-left: 0; }
.toc ul { list-style: none; margin: 0; padding-left: 0; }
.toc ul ul { padding-left: 7mm; }
.toc li { margin: 2.1mm 0; line-height: 1.3; }
.toc a { color: #1f2328; }
.toc ul ul a { color: #57606a; font-size: 9.2pt; }

/* Keep a section heading with its first block */
h2 + table, h3 + table { page-break-before: avoid; }
"""

TEMPLATE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{title}</title>
<style>{css}</style>
</head>
<body>
{cover}
{toc_page}
<article class="markdown-body">
{body}
</article>
</body>
</html>
"""

COVER = """
<section class="cover">
  <div class="cover-band"></div>
  <div class="cover-eyebrow">SOC L1 Lab &middot; {id}</div>
  <h1 class="cover-title">{title}</h1>
  <p class="cover-subtitle">{subtitle}</p>
  <div class="cover-meta">
    <dl>
      <dt>Incident</dt><dd>{incident}</dd>
      <dt>Report date</dt><dd>{date}</dd>
      <dt>Classification</dt><dd>{classification}</dd>
      <dt>Environment</dt><dd>{environment}</dd>
      <dt>Severity</dt><dd>{severity}</dd>
    </dl>
  </div>
  <div class="cover-footer">
    Independent portfolio lab. No production systems, client data, or real credentials.
  </div>
</section>
"""

TOC_PAGE = """
<section class="toc-page">
  <h1 class="toc-heading">Contents</h1>
  {toc}
</section>
"""

SUBTITLE_RE = re.compile(r"<!--\s*subtitle:\s*(.*?)\s*-->", re.S | re.I)
META_RE = re.compile(r"<!--\s*meta\s*(.*?)\s*-->", re.S | re.I)


def split_title(text: str) -> tuple[str, str]:
    """Return (title, body) with the first H1 removed from the body."""
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if line.startswith("# "):
            title = line[2:].strip()
            body = "\n".join(lines[:index] + lines[index + 1 :])
            return title, body
    raise SystemExit("document has no H1 title")


def convert(md_path: pathlib.Path, pdf_path: pathlib.Path) -> None:
    text = md_path.read_text(encoding="utf-8")

    meta = {
        "id": "INC-001",
        "incident": "INC-001 &mdash; SSH brute force to persistence",
        "severity": "High",
        "classification": "Lab exercise &mdash; sanitized for publication",
        "environment": "Wazuh 4.14.7 &middot; Debian 12 &middot; QEMU/KVM",
    }
    meta_match = META_RE.search(text)
    if meta_match:
        for raw_line in meta_match.group(1).splitlines():
            if ":" in raw_line:
                key, value = raw_line.split(":", 1)
                meta[key.strip().lower()] = value.strip()
        text = META_RE.sub("", text)

    match = SUBTITLE_RE.search(text)
    subtitle = match.group(1).strip() if match else ""
    text = SUBTITLE_RE.sub("", text)

    title, body_md = split_title(text)

    md = markdown.Markdown(
        extensions=[
            "tables",
            "fenced_code",
            "codehilite",
            "toc",
            "sane_lists",
            "attr_list",
        ],
        extension_configs={
            "codehilite": {"guess_lang": False, "noclasses": True},
            "toc": {"permalink": False, "toc_depth": "2-2"},
        },
    )
    body = md.convert(body_md)
    toc = md.toc.strip()

    cover = COVER.format(
        title=title,
        subtitle=subtitle,
        date=datetime.date.today().isoformat(),
        **meta,
    )
    toc_page = TOC_PAGE.format(toc=toc) if toc else ""

    html_doc = TEMPLATE.format(
        title=title,
        css=CSS,
        cover=cover,
        toc_page=toc_page,
        body=body,
    )

    with tempfile.NamedTemporaryFile(
        "w", suffix=".html", dir=pdf_path.parent, delete=False, encoding="utf-8"
    ) as fh:
        fh.write(html_doc)
        html_path = pathlib.Path(fh.name)

    profile = tempfile.mkdtemp(prefix="chrome-pdf-")
    cmd = [
        CHROME,
        "--headless=new",
        "--disable-gpu",
        "--no-sandbox",
        "--no-pdf-header-footer",
        f"--user-data-dir={profile}",
        "--virtual-time-budget=4000",
        f"--print-to-pdf={pdf_path}",
        html_path.as_uri(),
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    html_path.unlink(missing_ok=True)

    if result.returncode != 0 or not pdf_path.exists():
        sys.stderr.write(result.stdout)
        sys.stderr.write(result.stderr)
        raise SystemExit(f"PDF generation failed for {md_path}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Markdown to PDF via headless Chrome")
    parser.add_argument("paths", nargs="+", help="Markdown files")
    parser.add_argument(
        "--out-dir",
        default=None,
        help="Output directory (default: alongside each Markdown file)",
    )
    args = parser.parse_args()

    for raw in args.paths:
        md_path = pathlib.Path(raw).resolve()
        if not md_path.exists():
            raise SystemExit(f"missing: {md_path}")
        out_dir = pathlib.Path(args.out_dir).resolve() if args.out_dir else md_path.parent
        out_dir.mkdir(parents=True, exist_ok=True)
        pdf_path = out_dir / (md_path.stem + ".pdf")
        convert(md_path, pdf_path)
        print(f"{md_path.name} -> {pdf_path}")


if __name__ == "__main__":
    main()
