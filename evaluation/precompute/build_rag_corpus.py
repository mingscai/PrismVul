#!/usr/bin/env python3
from __future__ import annotations
import argparse
import json
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from utils.dataset import load_records, load_split_ids, filter_by_ids, get_input_text
GT_CLASSES = {'root_cause_vulnerable', 'supporting_fix'}

def _module_prefix(file_path: str, depth: int=2) -> str | None:
    if not file_path:
        return None
    parts = [p for p in file_path.split('/') if p]
    if not parts:
        return None
    return '/'.join(parts[:depth])

def _gt_funcs_from_record(record: dict) -> list[dict]:
    out: list[dict] = []
    for chain in record.get('src_commits_chained') or []:
        chain_id = chain.get('chain_id')
        chain_len = chain.get('len') or len(chain.get('commit_ids') or [])
        root_par = (chain.get('root_parent_id') or '').strip()
        cids = chain.get('commit_ids') or []
        leaf = cids[-1] if cids else ''
        for d in chain.get('diffs') or []:
            fname = d.get('filename') or ''
            dfs = d.get('diff_funcs') or {}
            for cat in ('modified', 'removed'):
                for fn in dfs.get(cat) or []:
                    cls = fn.get('classification') or ''
                    if cls not in GT_CLASSES:
                        continue
                    sig = fn.get('sig') or fn.get('name') or ''
                    if not sig:
                        continue
                    out.append({'file': fname, 'sig': sig, 'classification': cls, 'category': cat, 'chain_id': chain_id, 'chain_len': chain_len, 'root_parent_id': root_par, 'leaf_id': leaf, 'body_pre_fix': fn.get('code') or '', 'body_post_fix': fn.get('code_after') if cat == 'modified' else None})
    return out
CONTENT_CHOICES = ('both', 'cve', 'restated', 'issue')

def _build_cve_entry(record: dict, split: str, content: str) -> dict:
    entry = {'cve_id': record.get('cve_id'), 'split': split, 'content_variant': content, 'cwe_id': record.get('cwe_id'), 'cwe_name': record.get('cwe_name')}
    if content == 'both' or content == 'cve':
        entry['cve_desc'] = record.get('cve_desc')
        entry['cve_desc_restated'] = record.get('cve_desc_restated')
    elif content == 'restated':
        entry['cve_desc_restated'] = record.get('cve_desc_restated')
    if content in ('both', 'issue'):
        entry['issue_summary'] = get_input_text(record, 'issue_summary')
    entry['vulnerable_functions'] = _gt_funcs_from_record(record)
    return entry

def _summary_for_index(entry: dict, content: str) -> str:
    if content == 'issue':
        txt = entry.get('issue_summary') or ''
    elif content == 'restated':
        txt = entry.get('cve_desc_restated') or ''
    elif content == 'cve':
        txt = entry.get('cve_desc_restated') or entry.get('cve_desc') or ''
    else:
        txt = entry.get('cve_desc_restated') or entry.get('cve_desc') or entry.get('issue_summary') or ''
    return ' '.join(txt.split())[:120]

def _one_liner(entry: dict, content: str) -> str:
    funcs = entry.get('vulnerable_functions') or []
    modules: list[str] = []
    seen: set[str] = set()
    for f in funcs:
        m = _module_prefix(f.get('file') or '')
        if m and m not in seen:
            seen.add(m)
            modules.append(m)
    summary = _summary_for_index(entry, content)
    cwe = entry.get('cwe_id') or '?'
    cve_id = entry.get('cve_id') or '?'
    split = entry.get('split') or '?'
    mods_str = ','.join(modules[:3]) or '(no-GT)'
    return f'{cve_id:<18}  {split:<5}  {cwe:<10}  {mods_str:<40}  {summary}'

def _make_symlink(link_path: Path, target_abs: Path) -> None:
    if link_path.is_symlink() or link_path.exists():
        link_path.unlink()
    rel = Path('..') / '..' / target_abs.relative_to(target_abs.parents[1])
    link_path.symlink_to(rel)

def _rmtree(p: Path) -> None:
    if not p.exists() and (not p.is_symlink()):
        return
    if p.is_symlink() or p.is_file():
        p.unlink()
        return
    for c in p.iterdir():
        _rmtree(c)
    p.rmdir()
_CONTENT_DESCRIPTIONS = {'both': 'cve_desc + cve_desc_restated + issue_summary', 'cve': 'cve_desc + cve_desc_restated   (issue text stripped — RAG-on-cve variant)', 'restated': 'cve_desc_restated only         (raw cve_desc AND issue text stripped — strict RAG-on-restated variant)', 'issue': 'issue_summary                  (cve text stripped — RAG-on-issue variant)'}
_CONTENT_JSON_TEMPLATES = {'both': '    "cve_desc":           "(public NVD entry)",\n    "cve_desc_restated":  "(scrubbed, no answer anchors)",\n    "issue_summary":      "(pre-fix bug report from chromium issue tracker)",', 'cve': '    "cve_desc":           "(public NVD entry)",\n    "cve_desc_restated":  "(scrubbed, no answer anchors)",\n    # NOTE: issue_summary is intentionally absent in this variant.', 'restated': '    "cve_desc_restated":  "(scrubbed, no answer anchors)",\n    # NOTE: raw cve_desc AND issue_summary are intentionally absent in this variant.', 'issue': '    "issue_summary":      "(pre-fix bug report from chromium issue tracker)",\n    # NOTE: cve_desc / cve_desc_restated are intentionally absent in this variant.'}

def _render_readme(content: str) -> str:
    return f'''HISTORICAL CVE corpus (zero-shot RAG for iv_b_agent_icl). TRAIN + VAL splits of the\nChromium CVE dataset (TEST split is excluded). All entries are real,\nGT-annotated CVEs from past chromium history.\n\nCONTENT VARIANT: {content}\n  → text fields kept: {_CONTENT_DESCRIPTIONS[content]}\n  → vulnerable_functions (with body_pre_fix / body_post_fix) is kept in every variant.\n\nDO NOT TRUST BLINDLY — these are HINTS from a different point in chromium\nhistory. Past CVEs in the same module / CWE class can suggest *what to look\nfor*, but the function names + file paths are usually different. Always\nverify candidates in the current worktree before submitting.\n\nLAYOUT\n------\n  README.txt           — this file\n  INDEX.txt            — one line per CVE: cve_id | split | cwe | top-module | summary\n                         (sorted by cve_id; ideal first-pass grep target)\n  full/                — canonical CVE records (one JSON per CVE)\n  by_cwe/<CWE-XXX>/    — symlinks grouped by CWE id (UAF=CWE-416, OOB-read=CWE-125 etc.)\n  by_module/<prefix>/  — symlinks grouped by top-2 path segments of GT files;\n                         a CVE with GT in multiple modules appears under multiple prefixes\n\nEACH per-CVE JSON\n-----------------\n  {{\n    "cve_id": "CVE-2023-XXXX",\n    "split":  "train",   # or "val"\n    "content_variant": "{content}",\n    "cwe_id": "CWE-416", "cwe_name": "Use After Free",\n{_CONTENT_JSON_TEMPLATES[content]}\n    "vulnerable_functions": [\n      {{\n        "file":            "components/exo/extended_drag_source.cc",\n        "sig":             "exo.ExtendedDragSource.OnToplevelWindowDragStarted:void()",\n        "classification":  "root_cause_vulnerable",   # or supporting_fix\n        "category":        "modified",                # or removed\n        "chain_id":        "...", "chain_len": N,\n        "root_parent_id":  "<pre-fix commit>",\n        "leaf_id":         "<post-fix commit>",\n        "body_pre_fix":    "(C++ source as of the pre-fix state)",\n        "body_post_fix":   "(post-fix; null if function was removed)"\n      }},\n      ...\n    ]\n  }}\n\nUSEFUL COMMANDS (run with absolute paths from this dir)\n-------------------------------------------------------\n  # narrow by keyword(s) in the one-liner:\n  grep -i "use after free" INDEX.txt | head\n  grep -i "race" INDEX.txt | grep -i "blink" | head\n\n  # all UAFs:\n  ls by_cwe/CWE-416/ | head\n\n  # everything that touched the blink renderer:\n  ls by_module/third_party/blink/ 2>/dev/null | head\n\n  # full details of a specific CVE:\n  cat full/CVE-2022-3196.json | jq .vulnerable_functions\n\n  # extract pre-fix bodies of vulnerable functions across all UAFs (for pattern study):\n  for f in by_cwe/CWE-416/*.json; do\n      jq -r '.vulnerable_functions[] | select(.classification=="root_cause_vulnerable") | .body_pre_fix' "$f"\n  done | head -200\n'''

def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--input', default='data/chromium_cve_data.jsonl')
    ap.add_argument('--split-dir', default='data/splits')
    ap.add_argument('--out', default='data/train_cves')
    ap.add_argument('--include-val', action=argparse.BooleanOptionalAction, default=True, help='Also include val-split CVEs (safe for iv_b_agent_icl zero-shot: val is never used as a scoring target and val ∩ test = ∅). Use --no-include-val to revert to train-only.')
    ap.add_argument('--content', choices=CONTENT_CHOICES, default='both', help='Which text fields to ship per CVE:\n  both  → cve_desc + cve_desc_restated + issue_summary (default)\n  cve   → cve text only, issue stripped (RAG-on-cve ablation)\n  issue → issue text only, cve stripped (RAG-on-issue ablation)\nvulnerable_functions (with bodies) is always kept.')
    args = ap.parse_args()
    records = load_records(args.input)
    train_ids, val_ids, test_ids = load_split_ids(args.split_dir)
    split_of: dict[str, str] = {cid: 'train' for cid in train_ids}
    if args.include_val:
        for cid in val_ids:
            split_of[cid] = 'val'
    keep_ids = set(split_of)
    keep_records = filter_by_ids(records, keep_ids)
    n_train = sum((1 for r in keep_records if split_of.get(r.get('cve_id', '')) == 'train'))
    n_val = sum((1 for r in keep_records if split_of.get(r.get('cve_id', '')) == 'val'))
    leakage = sum((1 for r in keep_records if r.get('cve_id', '') in test_ids))
    print(f'[export] kept {len(keep_records)} records (train={n_train}, val={n_val}; test leakage check={leakage})  of {len(records)} total')
    if leakage:
        raise SystemExit(f'[export] FATAL: {leakage} test-split CVEs slipped into corpus')
    out = Path(args.out).resolve()
    print(f'[export] clearing {out}')
    _rmtree(out)
    (out / 'full').mkdir(parents=True)
    (out / 'by_cwe').mkdir(parents=True)
    (out / 'by_module').mkdir(parents=True)
    one_liners: list[str] = []
    n_no_gt = 0
    n_cwe_groups: dict[str, int] = {}
    n_mod_groups: dict[str, int] = {}
    for r in keep_records:
        cve_id = r.get('cve_id') or ''
        if not cve_id:
            continue
        split = split_of.get(cve_id, '?')
        entry = _build_cve_entry(r, split, args.content)
        if not entry['vulnerable_functions']:
            n_no_gt += 1
        full_path = out / 'full' / f'{cve_id}.json'
        full_path.write_text(json.dumps(entry, indent=2, ensure_ascii=False))
        cwe = entry.get('cwe_id') or 'UNK-CWE'
        cwe_dir = out / 'by_cwe' / cwe
        cwe_dir.mkdir(parents=True, exist_ok=True)
        _make_symlink(cwe_dir / f'{cve_id}.json', full_path)
        n_cwe_groups[cwe] = n_cwe_groups.get(cwe, 0) + 1
        modules_seen: set[str] = set()
        for f in entry['vulnerable_functions']:
            m = _module_prefix(f.get('file') or '')
            if not m or m in modules_seen:
                continue
            modules_seen.add(m)
            mod_dir = out / 'by_module' / m
            mod_dir.mkdir(parents=True, exist_ok=True)
            _make_symlink(mod_dir / f'{cve_id}.json', full_path)
            n_mod_groups[m] = n_mod_groups.get(m, 0) + 1
        one_liners.append(_one_liner(entry, args.content))
    one_liners.sort()
    summary_src = {'both': 'cve_desc_restated', 'cve': 'cve_desc_restated', 'restated': 'cve_desc_restated', 'issue': 'issue_summary'}[args.content]
    (out / 'INDEX.txt').write_text(f'# cve_id | split | cwe | top-module(s) | summary ({summary_src})\n' + '\n'.join(one_liners) + '\n')
    (out / 'README.txt').write_text(_render_readme(args.content))
    print(f'[export] content variant: {args.content} ({_CONTENT_DESCRIPTIONS[args.content]})')
    print(f'[export] wrote {len(one_liners)} CVEs (no-GT: {n_no_gt}) → {out}')
    print(f'[export]   by_cwe groups : {len(n_cwe_groups)}  (top 3: {sorted(n_cwe_groups.items(), key=lambda x: -x[1])[:3]})')
    print(f'[export]   by_module groups: {len(n_mod_groups)}  (top 3: {sorted(n_mod_groups.items(), key=lambda x: -x[1])[:3]})')
if __name__ == '__main__':
    main()
