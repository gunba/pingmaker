"""
Generate skills.json from parsed game data.

Reads parsed/Skill.json and L10NString_en-US.json to produce a clean
skill-name → [IDs] mapping filtered to PC-only skills
(SkillString_Key contains 'STR_SKILL_PC').

Usage:
    python generate_skills.py
    python generate_skills.py --class TEMPLAR
    python generate_skills.py --dry-run
"""

import json
import argparse
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).parent


def load_l10n_strings(path: Path) -> dict:
    """Load L10N string table and return the flat key→value dict."""
    with open(path, encoding='utf-8') as f:
        data = json.load(f)
    # Format: {"version": N, "count": N, "strings": {...}}
    return data.get('strings', data)


def generate(class_filter: str | None = None) -> dict:
    """Return {skill_name: [sorted IDs]} from game dump, PC skills only."""
    skill_path = ROOT / 'parsed' / 'Skill.json'
    l10n_path = ROOT / 'L10NString_en-US.json'

    if not skill_path.exists():
        # Try parsed/ subfolder for L10N too
        alt = ROOT / 'parsed' / 'L10NString_en-US.json'
        if alt.exists():
            l10n_path = alt

    with open(skill_path, encoding='utf-8') as f:
        skill_data = json.load(f)

    strings = load_l10n_strings(l10n_path)

    skills = defaultdict(list)
    unresolved = 0

    for row in skill_data['rows']:
        key = row.get('SkillString_Key', '')
        if 'STR_SKILL_PC' not in key:
            continue

        # Optional class filter (e.g., "TEMPLAR")
        if class_filter and class_filter.upper() not in key:
            continue

        skill_id = row['ID']
        name_key = f'SkillString_{key}_skill_name'
        name = strings.get(name_key)
        if name:
            skills[name].append(skill_id)
        else:
            unresolved += 1

    # Sort IDs within each name, and sort output by name
    result = {}
    for name in sorted(skills.keys()):
        result[name] = sorted(skills[name])

    return result, unresolved


def main():
    parser = argparse.ArgumentParser(description='Generate skills.json from game data')
    parser.add_argument('--class', dest='class_filter', default=None,
                        help='Filter to a specific class (e.g., TEMPLAR)')
    parser.add_argument('--dry-run', action='store_true',
                        help='Print stats without writing')
    parser.add_argument('-o', '--output', default='skills.json',
                        help='Output file (default: skills.json)')
    args = parser.parse_args()

    skills, unresolved = generate(args.class_filter)
    total_ids = sum(len(v) for v in skills.values())

    print(f"Generated: {len(skills)} skill names, {total_ids} IDs")
    if unresolved:
        print(f"  ({unresolved} skills had no L10N name)")
    if args.class_filter:
        print(f"  Filtered to class: {args.class_filter.upper()}")

    if args.dry_run:
        # Show a summary of what would change
        out_path = ROOT / args.output
        if out_path.exists():
            with open(out_path, encoding='utf-8') as f:
                current = json.load(f)
            cur_ids = sum(len(v) for v in current.values())
            new_names = set(skills.keys()) - set(current.keys())
            removed_names = set(current.keys()) - set(skills.keys())
            added_ids = 0
            removed_ids = 0
            for name in set(skills.keys()) & set(current.keys()):
                added_ids += len(set(skills[name]) - set(current[name]))
                removed_ids += len(set(current[name]) - set(skills[name]))
            print(f"\nCurrent: {len(current)} names, {cur_ids} IDs")
            print(f"Changes: +{len(new_names)} names, -{len(removed_names)} names, "
                  f"+{added_ids} IDs, -{removed_ids} IDs")
        return

    out_path = ROOT / args.output
    with open(out_path, 'w', encoding='utf-8') as f:
        json.dump(skills, f, indent=2, ensure_ascii=False)
    print(f"Written to {out_path}")


if __name__ == '__main__':
    main()
