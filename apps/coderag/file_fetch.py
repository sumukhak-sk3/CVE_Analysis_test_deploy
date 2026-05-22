"""File-fetch fallback: read exact files and slice symbol/keyword windows.

Used when the indexed retriever returns weak hits or no hits at all.
"""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Iterable

from ..common.logging_utils import get_logger

logger = get_logger(__name__)


def _safe_path(repo_root: Path, candidate: str) -> Path | None:
    """Resolve `candidate` against `repo_root` and ensure it stays inside it."""
    try:
        target = (repo_root / candidate).resolve()
    except (OSError, RuntimeError):
        return None
    try:
        target.relative_to(repo_root.resolve())
    except ValueError:
        return None
    if not target.is_file():
        return None
    return target


def grep_keyword_windows(
    repo_root: str | os.PathLike[str],
    keywords: Iterable[str],
    window_lines: int = 40,
    max_files: int = 8,
    max_per_file: int = 3,
) -> list[dict]:
    """Search the repo for any of `keywords` and return surrounding code windows.

    Returns a list of {path, start_line, end_line, snippet, matched_keyword}.
    """
    root = Path(repo_root).resolve()
    if not root.exists():
        return []
    keywords = [k for k in keywords if k]
    if not keywords:
        return []
    pattern = re.compile(
        "|".join(re.escape(k) for k in keywords), re.IGNORECASE
    )

    SKIP_DIRS = {
        ".git", ".hg", ".svn", "node_modules", ".venv", "venv", "__pycache__",
        "dist", "build", "target", ".next", ".cache", ".tox",
    }
    SKIP_EXT = {".png", ".jpg", ".jpeg", ".gif", ".pdf", ".zip", ".gz", ".tar", ".so", ".dll", ".exe"}

    out: list[dict] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".")]
        for name in filenames:
            if Path(name).suffix.lower() in SKIP_EXT:
                continue
            if len(out) >= max_files * max_per_file:
                return out
            fp = Path(dirpath) / name
            try:
                if fp.stat().st_size > 1_000_000:
                    continue
                lines = fp.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                continue
            file_hits = 0
            for i, line in enumerate(lines):
                m = pattern.search(line)
                if not m:
                    continue
                start = max(0, i - window_lines // 2)
                end = min(len(lines), i + window_lines // 2)
                snippet = "\n".join(lines[start:end])
                out.append({
                    "path": str(fp.relative_to(root)),
                    "start_line": start + 1,
                    "end_line": end,
                    "snippet": snippet,
                    "matched_keyword": m.group(0),
                })
                file_hits += 1
                if file_hits >= max_per_file:
                    break
    return out


def fetch_exact_window(
    repo_root: str | os.PathLike[str],
    relative_path: str,
    start_line: int,
    end_line: int,
) -> dict | None:
    """Return an exact line window from `relative_path` inside `repo_root`."""
    root = Path(repo_root).resolve()
    target = _safe_path(root, relative_path)
    if not target:
        return None
    try:
        lines = target.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None
    start = max(0, start_line - 1)
    end = min(len(lines), end_line)
    return {
        "path": relative_path,
        "start_line": start + 1,
        "end_line": end,
        "snippet": "\n".join(lines[start:end]),
    }
