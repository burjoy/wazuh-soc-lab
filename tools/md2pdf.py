#!/usr/bin/env python3
"""Render a Markdown document to PDF.

Uses Python-Markdown for conversion and headless Chrome for printing. No LaTeX,
pandoc, or system packages required beyond Chrome.

Usage:
    python3 tools/md2pdf.py writeups/INC-001/01-findings-report.md

Requires:
    pip install markdown pygments
"""

from __future__ import annotations

import argparse
import pathlib
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

* { box-sizing: border-box; }

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

/* Keep section leads with their content */
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
<article class="markdown-body">
{body}
</article>
</body>
</html>
"""


def convert(md_path: pathlib.Path, pdf_path: pathlib.Path) -> None:
    text = md_path.read_text(encoding="utf-8")
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
            "toc": {"permalink": False},
        },
    )
    body = md.convert(text)
    title = next(
        (line[2:].strip() for line in text.splitlines() if line.startswith("# ")),
        md_path.stem.replace("-", " ").title(),
    )
    html_doc = TEMPLATE.format(title=title, css=CSS, body=body)

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
