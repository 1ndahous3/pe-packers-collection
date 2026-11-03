#!/usr/bin/env python3
"""Check local Markdown links and heading anchors with Python 3.8+.

Usage:
    python tools/check_links.py
    python tools/check_links.py PATH_TO_COLLECTION

The default root is this script's parent collection, regardless of the working
directory. Checks simple inline links/images and headings starting with #.
External URLs, code blocks, inline code, and generated/cache directories are
skipped. Reference-style links and raw HTML anchors are not parsed.

Exit codes: 0 = valid links, 1 = broken links or unreadable files, 2 = bad arguments.
"""
import argparse
import re
from functools import lru_cache
from pathlib import Path
from urllib.parse import unquote

SKIP = {".git", ".venv", "__pycache__", "build", "cache"}
LINK = re.compile(r"""\[[^\]\n]*\]\((?:<([^>\n]+)>|([^\s)]+))(?:\s+["'][^"']*["'])?\)""")
SCHEME = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*:")


def prose_lines(text):
    """Keep line numbers while ignoring fenced and indented code blocks."""
    fence = None
    for number, line in enumerate(text.splitlines(), 1):
        marker = re.match(r"^ {0,3}(\x60{3,}|~{3,})", line)
        if marker:
            run = marker.group(1)
            if fence is None:
                fence = (run[0], len(run))
            elif run[0] == fence[0] and len(run) >= fence[1]:
                fence = None
            continue
        if fence is None and not line.startswith(("    ", "\t")):
            yield number, line


@lru_cache(maxsize=None)
def heading_anchors(path):
    anchors = set()
    for _, line in prose_lines(path.read_text(encoding="utf-8-sig")):
        match = re.match(r"^ {0,3}#{1,6}\s+(.+?)\s*#*\s*$", line)
        if not match:
            continue
        title = re.sub(r"\[([^]]+)\]\([^)]+\)", r"\1", match.group(1))
        title = re.sub(r"\\(.)", r"\1", title)
        slug = re.sub(r"[^\w -]", "", title.lower()).replace(" ", "-")
        candidate, suffix = slug, 0
        while candidate in anchors:
            suffix += 1
            candidate = slug + "-" + str(suffix)
        anchors.add(candidate)
    return anchors


def check(root):
    documents = sorted(
        p for p in root.rglob("*.md")
        if not SKIP.intersection(p.relative_to(root).parts)
    )
    errors, links = [], 0
    for path in documents:
        try:
            text = path.read_text(encoding="utf-8-sig")
        except (OSError, UnicodeError) as exc:
            errors.append("{}: {}".format(path.relative_to(root), exc))
            continue
        for number, line in prose_lines(text):
            line = re.sub(r"(\x60+).*?\1", "", line)
            for match in LINK.finditer(line):
                link = match.group(1) or match.group(2)
                if SCHEME.match(link) or link.startswith("//"):
                    continue
                links += 1
                filename, _, fragment = link.partition("#")
                target = (path.parent / unquote(filename)).resolve() if filename else path
                problem = None
                if not target.exists():
                    problem = "missing path"
                elif fragment and target.is_file() and target.suffix.lower() == ".md":
                    try:
                        if unquote(fragment) not in heading_anchors(target):
                            problem = "missing heading"
                    except (OSError, UnicodeError) as exc:
                        problem = str(exc)
                if problem:
                    errors.append("{}:{}: {}: {}".format(
                        path.relative_to(root), number, problem, link))
    for error in errors:
        print(error)
    print("Checked {} local links in {} Markdown files; {} errors.".format(
        links, len(documents), len(errors)))
    return 1 if errors else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("root", nargs="?", type=Path,
                        default=Path(__file__).resolve().parents[1],
                        help="Collection root (default: this script's parent collection)")
    args = parser.parse_args()
    root = args.root.resolve()
    if not root.is_dir():
        parser.error("Root is not a directory: {}".format(root))
    return check(root)


if __name__ == "__main__":
    raise SystemExit(main())
