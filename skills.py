"""Skill data loading and fuzzy search."""

import json
import os
import sys
from dataclasses import dataclass, field
from difflib import SequenceMatcher


@dataclass
class SkillData:
    """Precomputed skill lookup tables."""
    skills: dict = field(default_factory=dict)        # name -> [ids]
    id_to_name: dict = field(default_factory=dict)    # id -> name
    all_ids: set = field(default_factory=set)          # all known skill IDs
    first_bytes: set = field(default_factory=set)      # first byte of each ID


def get_resource_path(filename: str) -> str:
    """Get path to resource, works for dev, PyInstaller, and Nuitka.

    Checks next to __file__ first (works for source and Nuitka bundled data),
    then next to the original exe (for external files like templates/).
    """
    file_dir = os.path.dirname(os.path.abspath(__file__))
    candidate = os.path.join(file_dir, filename)
    if os.path.exists(candidate):
        return candidate
    argv0 = sys.argv[0]
    if os.path.isabs(argv0):
        exe_dir = os.path.dirname(argv0)
    else:
        exe_dir = file_dir
    return os.path.join(exe_dir, filename)


def load_skills(path: str = None) -> SkillData:
    """Load skills.json and build lookup tables."""
    if path is None:
        path = get_resource_path("skills.json")
    data = SkillData()
    if not os.path.exists(path):
        return data
    with open(path, 'r', encoding='utf-8') as f:
        data.skills = json.load(f)
    for name, ids in data.skills.items():
        for sid in ids:
            data.id_to_name[sid] = name
            data.all_ids.add(sid)
            data.first_bytes.add(sid & 0xFF)
    return data


def fuzzy_search(query: str, skills: dict, limit: int = 10) -> list[str]:
    """Fuzzy search skill names. Returns up to `limit` best matches."""
    if not query or len(query) < 2:
        return []
    q = query.lower()
    results = []
    for name in skills:
        nl = name.lower()
        if q in nl:
            if nl.startswith(q):
                score = 1.0
            elif f" {q}" in f" {nl}":
                score = 0.95
            else:
                score = 0.9
            results.append((name, score))
        else:
            ratio = SequenceMatcher(None, q, nl).ratio()
            if ratio > 0.5:
                results.append((name, ratio * 0.8))
    results.sort(key=lambda x: -x[1])
    return [name for name, _ in results[:limit]]
