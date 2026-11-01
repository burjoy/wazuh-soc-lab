#!/usr/bin/env python3
"""Normalise prose style across the lab reports.

Rules applied outside fenced code blocks and inline code:
  - em dash becomes a comma, or a colon in headings
  - semicolon becomes a full stop with a capitalised next word
  - arrows become the word "to"
  - bold survives only as a short line label or subheading, never as inline emphasis
  - table cells carry no bold
  - a bold bullet label gets its description on the next, indented line
"""

import re
import sys
from pathlib import Path

FENCE = re.compile(r"^\s*(```|~~~)")
LIST = re.compile(r"^(\s*)([-*+]|\d+\.)\s+(.*)$")
LABEL = re.compile(
    r"^\*\*(.+?)\*\*\s*([:.]|\u2014|\u2013|-)?\s*(.*)$"
)
SENT_OPEN, SENT_CLOSE = "\x01", "\x02"
INLINE_CODE = re.compile(r"`[^`\n]+`")


def split_code(line):
    spans = []

    def repl(m):
        spans.append(m.group(0))
        return f"\x00{len(spans) - 1}\x00"

    return INLINE_CODE.sub(repl, line), spans


def restore_code(line, spans):
    for i, s in enumerate(spans):
        line = line.replace(f"\x00{i}\x00", s)
    return line


def fix_punctuation(line):
    if re.match(r"^#{1,6}\s", line):
        line = line.replace(" \u2014 ", ": ").replace("\u2014", ":")
    else:
        line = line.replace(" \u2014 ", ", ").replace("\u2014", ", ")
        line = line.replace(" ,", ",")

    line = re.sub(r";\s+(\S)", lambda m: ". " + m.group(1).upper(), line)
    line = re.sub(r";\s*$", ".", line)

    line = line.replace(" \u2192 ", " to ").replace("\u2192", " to ")
    line = line.replace(" \u2190 ", " from ").replace("\u2190", " from ")
    line = re.sub(r"(?<!-)->(?!>)", " to ", line)
    line = line.replace("=>", " to ")
    line = re.sub(r"[ \t]+([,.:])", r"\1", line)
    return line


def capitalise(text):
    if not text:
        return text
    ch = text[0]
    if ch.islower():
        return ch.upper() + text[1:]
    return text


def label_from_bold(match):
    """Return (label, rest) when the bold text is a real label, else None."""
    raw = match.group(1).strip()
    sep = match.group(2) or ""
    rest = match.group(3).strip()
    if not raw or not (raw[0].isupper() or raw[0].isdigit()):
        return None
    ends_with_sep = raw.endswith((".", ":", "\u2014", "\u2013"))
    if sep not in (":", ".", "\u2014", "\u2013") and not ends_with_sep:
        return None
    label = raw.rstrip(".:\u2014\u2013 ")
    if len(label) > 70 or not label:
        return None
    return label, rest


def process_line(line):
    line, spans = split_code(line)
    stripped = line.lstrip()

    if stripped.startswith("#") or stripped.startswith("|"):
        line = line.replace("**", "")
        return restore_code(fix_punctuation(line), spans)

    m = LIST.match(line)
    if m:
        indent, marker, body = m.group(1), m.group(2), m.group(3)
        body = fix_punctuation(body)
        lm = LABEL.match(body)
        if lm:
            got = label_from_bold(lm)
            if got:
                label, rest = got
                head = f"{indent}{marker} {SENT_OPEN}{label}{SENT_CLOSE}"
                return restore_code(
                    head + ("\n" + indent + "  " + capitalise(rest) if rest else ""),
                    spans,
                )
        line = f"{indent}{marker} {body}"
    else:
        pm = LABEL.match(line.strip())
        if pm and stripped == line:
            got = label_from_bold(pm)
            if got:
                label, rest = got
                line = (
                    SENT_OPEN
                    + label
                    + SENT_CLOSE
                    + ("\n\n" + capitalise(rest) if rest else "")
                )
                return restore_code(fix_punctuation(line), spans)

    line = line.replace("**", "")
    line = fix_punctuation(line)
    return restore_code(line, spans)


def process_file(path):
    text = Path(path).read_text(encoding="utf-8")
    out, in_fence, fence_marker = [], False, None
    for line in text.splitlines():
        m = FENCE.match(line)
        if m:
            marker = m.group(1)
            if not in_fence:
                in_fence, fence_marker = True, marker
            elif marker == fence_marker:
                in_fence = False
            out.append(line)
            continue
        out.append(line if in_fence else process_line(line))

    new = "\n".join(out)
    new = new.replace(SENT_OPEN, "**").replace(SENT_CLOSE, "**")
    if text.endswith("\n"):
        new += "\n"
    if new != text:
        Path(path).write_text(new, encoding="utf-8")
        return True
    return False


if __name__ == "__main__":
    changed = [p for p in sys.argv[1:] if process_file(p)]
    print(f"changed {len(changed)} files")
    for p in changed:
        print(" ", p)
