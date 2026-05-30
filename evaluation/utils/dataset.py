import json
import os
import random
import re
from collections import defaultdict
from pathlib import Path
from typing import Literal
_IMPL_EXTS = {'.cc', '.cpp', '.cxx', '.cu', '.c', '.m', '.mm'}
_HDR_EXTS = {'.h', '.hpp', '.hxx', '.cuh', '.inc'}

def _qualified_name(sig: str) -> str:
    s = sig
    i = 0
    while i < len(s):
        if s[i] == ':':
            prev = i > 0 and s[i - 1] == ':'
            nxt = i + 1 < len(s) and s[i + 1] == ':'
            if not prev and (not nxt):
                return s[:i].strip()
        i += 1
    return s.split('(')[0].strip()

def _collapse_header_impl_pairs(funcs: list[dict]) -> list[dict]:
    groups: dict[tuple, list[dict]] = {}
    order: list[tuple] = []
    for vf in funcs:
        d = os.path.dirname(vf.get('file', ''))
        qn = _qualified_name(vf.get('sig', ''))
        key = (d, qn)
        if key not in groups:
            order.append(key)
        groups.setdefault(key, []).append(vf)
    result = []
    for key in order:
        members = groups[key]
        impls = [m for m in members if os.path.splitext(m.get('file', ''))[1].lower() in _IMPL_EXTS]
        result.append(impls[0] if impls else members[0])
    return result

def load_records(path: str | Path) -> list[dict]:
    records = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records
TargetClassification = Literal['root_cause_vulnerable', 'related', 'all']

def extract_instances(record: dict, target: TargetClassification='root_cause_vulnerable', collapse_header_impl: bool=True, use_chained: bool=False) -> list[dict]:
    if use_chained:
        return _extract_instances_chained(record, target, collapse_header_impl)
    instances = []
    for commit in record.get('src_commits', []):
        vuln_funcs = []
        seen: set[tuple] = set()
        for diff in commit.get('diffs', []):
            file_path = diff['filename']
            for func in diff.get('diff_funcs', {}).get('modified', []):
                cls = func.get('classification')
                include = _should_include(cls, target)
                if include:
                    key = (file_path, func['sig'])
                    if key not in seen:
                        seen.add(key)
                        vuln_funcs.append({'file': file_path, 'sig': func['sig']})
            for func in diff.get('diff_funcs', {}).get('removed', []):
                cls = func.get('classification')
                include = _should_include(cls, target)
                if include:
                    key = (file_path, func['sig'])
                    if key not in seen:
                        seen.add(key)
                        vuln_funcs.append({'file': file_path, 'sig': func['sig']})
        if collapse_header_impl:
            vuln_funcs = _collapse_header_impl_pairs(vuln_funcs)
        if vuln_funcs:
            instances.append({'cve_id': record['cve_id'], 'commit_id': commit['id'], 'commit_date': commit.get('commit_date', ''), 'parent_id': commit['parent_id'], 'vuln_funcs': vuln_funcs})
    return instances

def _extract_instances_chained(record: dict, target: TargetClassification, collapse_header_impl: bool) -> list[dict]:
    chains = record.get('src_commits_chained') or []
    if not chains:
        return []
    by_id = {c['id']: c for c in record.get('src_commits') or [] if c.get('id')}
    instances = []
    for ch in chains:
        vuln_funcs = []
        seen: set[tuple] = set()
        for d in ch.get('diffs') or []:
            fname = d.get('filename') or ''
            df = d.get('diff_funcs') or {}
            for cat in ('modified', 'removed'):
                for fn in df.get(cat) or []:
                    if not _should_include(fn.get('classification'), target):
                        continue
                    sig = fn.get('sig') or ''
                    key = (fname, sig)
                    if not sig or key in seen:
                        continue
                    seen.add(key)
                    vuln_funcs.append({'file': fname, 'sig': sig})
        if collapse_header_impl:
            vuln_funcs = _collapse_header_impl_pairs(vuln_funcs)
        if not vuln_funcs:
            continue
        commit_ids = ch.get('commit_ids') or []
        leaf_id = commit_ids[-1] if commit_ids else ''
        leaf = by_id.get(leaf_id, {})
        instances.append({'cve_id': record['cve_id'], 'commit_id': leaf_id, 'commit_date': leaf.get('commit_date', ''), 'parent_id': ch.get('root_parent_id') or '', 'vuln_funcs': vuln_funcs})
    return instances

def _should_include(cls: str | None, target: TargetClassification) -> bool:
    if target == 'all':
        return cls is not None
    if target == 'related':
        return cls in ('root_cause_vulnerable', 'supporting_fix')
    return cls == 'root_cause_vulnerable'

def build_all_instances(records: list[dict], target: TargetClassification='root_cause_vulnerable', use_chained: bool=False) -> list[dict]:
    all_instances = []
    for record in records:
        all_instances.extend(extract_instances(record, target, use_chained=use_chained))
    return all_instances
_CWE_RE = re.compile('^CWE-\\d+$')

def filter_records(records: list[dict], verbose: bool=True, use_chained: bool=False) -> tuple[list[dict], dict]:
    kept, dropped = ([], [])
    reasons: dict[str, int] = {'no_valid_cwe': 0, 'no_issue_summary': 0, 'no_src_commits': 0, 'no_mod_rem_funcs': 0, 'no_annotated_func': 0}
    for r in records:
        cwe_ok = any((_CWE_RE.match(rep.get('id', '')) for rep in r.get('cwe_reps', [])))
        if not cwe_ok:
            reasons['no_valid_cwe'] += 1
            dropped.append(r)
            continue
        issue_ok = any((i.get('summary') for i in r.get('issues') or []))
        if not issue_ok:
            reasons['no_issue_summary'] += 1
            dropped.append(r)
            continue
        commits = r.get('src_commits') or []
        if not commits:
            reasons['no_src_commits'] += 1
            dropped.append(r)
            continue
        _RELATED = {'root_cause_vulnerable', 'supporting_fix'}
        if use_chained:
            chains = r.get('src_commits_chained') or []
            has_mod_rem = False
            has_annotated = False
            for ch in chains:
                for d in ch.get('diffs') or []:
                    df = d.get('diff_funcs') or {}
                    for cat in ('modified', 'removed'):
                        funcs = df.get(cat) or []
                        if funcs:
                            has_mod_rem = True
                        for fn in funcs:
                            if fn.get('classification') in _RELATED:
                                has_annotated = True
                                break
                        if has_annotated:
                            break
                    if has_annotated:
                        break
                if has_annotated:
                    break
            if not has_mod_rem:
                reasons['no_mod_rem_funcs'] += 1
                dropped.append(r)
                continue
            if not has_annotated:
                reasons['no_annotated_func'] += 1
                dropped.append(r)
                continue
        else:
            has_mod_rem = False
            for commit in commits:
                for diff in commit.get('diffs', []):
                    df = diff.get('diff_funcs', {})
                    if df.get('modified') or df.get('removed'):
                        has_mod_rem = True
                        break
                if has_mod_rem:
                    break
            if not has_mod_rem:
                reasons['no_mod_rem_funcs'] += 1
                dropped.append(r)
                continue
            has_annotated = False
            for commit in commits:
                for diff in commit.get('diffs', []):
                    df = diff.get('diff_funcs', {})
                    for func in df.get('modified', []) + df.get('removed', []):
                        if func.get('classification') in _RELATED:
                            has_annotated = True
                            break
                    if has_annotated:
                        break
                if has_annotated:
                    break
            if not has_annotated:
                reasons['no_annotated_func'] += 1
                dropped.append(r)
                continue
        kept.append(r)
    stats = {'total': len(records), 'kept': len(kept), 'dropped': len(dropped), 'reasons': reasons}
    if verbose:
        print(f'Filter: {len(kept)}/{len(records)} kept  ({len(dropped)} dropped)')
        for k, v in reasons.items():
            if v:
                print(f'  {k}: {v}')
    return (kept, stats)

def get_input_text(record: dict, input_field: str) -> str:
    if input_field == 'issue_summary':
        issues = record.get('issues') or []
        for issue in issues:
            summary = issue.get('summary')
            if summary:
                return summary
        return ''
    if input_field == 'issue_description':
        issues = record.get('issues') or []
        for issue in issues:
            d = ((issue.get('content') or {}).get('description') or {}).get('content')
            if d and d.strip():
                return d
        for issue in issues:
            s = issue.get('summary')
            if s:
                return s
        return ''
    if input_field == 'cve_desc_structured':
        structured = record.get('cve_desc_structured') or {}
        return json.dumps(structured, indent=2, ensure_ascii=False)
    return record.get(input_field, '') or ''

def split_records(records: list[dict], train_ratio: float=0.7, val_ratio: float=0.1, test_ratio: float=0.2, random_state: int=42, sort_by_date: bool=True) -> tuple[list[dict], list[dict], list[dict]]:
    assert abs(train_ratio + val_ratio + test_ratio - 1.0) < 1e-06
    if sort_by_date:

        def _date_key(r):
            dates = [c.get('commit_date', '') for c in r.get('src_commits', []) if c.get('commit_date')]
            return max(dates) if dates else ''
        records = sorted(records, key=_date_key)
    else:
        rng = random.Random(random_state)
        records = list(records)
        rng.shuffle(records)
    n = len(records)
    n_train = int(n * train_ratio)
    n_val = int(n * val_ratio)
    train = records[:n_train]
    val = records[n_train:n_train + n_val]
    test = records[n_train + n_val:]
    return (train, val, test)

def save_split_ids(train, val, test, out_dir: str | Path, prefix: str='chromium'):
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    for split_name, split_records in [('train', train), ('val', val), ('test', test)]:
        ids = [r['cve_id'] for r in split_records]
        (out_dir / f'{prefix}_{split_name}_ids.txt').write_text('\n'.join(ids) + '\n')
    print(f'Saved split IDs → {out_dir}  (train={len(train)}, val={len(val)}, test={len(test)})')

def load_split_ids(out_dir: str | Path, prefix: str='chromium') -> tuple[set, set, set]:
    out_dir = Path(out_dir)

    def _read(name):
        p = out_dir / f'{prefix}_{name}_ids.txt'
        return set(p.read_text().split()) if p.exists() else set()
    return (_read('train'), _read('val'), _read('test'))

def filter_by_ids(records: list[dict], ids: set[str]) -> list[dict]:
    return [r for r in records if r['cve_id'] in ids]
_TARGET_TO_CLASSES = {'root_cause_vulnerable': {'root_cause_vulnerable'}, 'related': {'root_cause_vulnerable', 'supporting_fix'}, 'all': {'root_cause_vulnerable', 'supporting_fix', 'incidental_or_unrelated'}}

def remove_singletons(records: list[dict], target: TargetClassification='root_cause_vulnerable') -> tuple[list[dict], set[tuple]]:
    func_counter: dict[tuple, int] = defaultdict(int)
    for r in records:
        cve_funcs: set[tuple] = set()
        for inst in extract_instances(r, target):
            for vf in inst['vuln_funcs']:
                cve_funcs.add((vf['file'], vf['sig']))
        for fk in cve_funcs:
            func_counter[fk] += 1
    singleton_keys = {fk for fk, cnt in func_counter.items() if cnt == 1}
    filtered = []
    for r in records:
        cve_funcs: set[tuple] = set()
        for inst in extract_instances(r, target):
            for vf in inst['vuln_funcs']:
                cve_funcs.add((vf['file'], vf['sig']))
        if cve_funcs - singleton_keys:
            filtered.append(r)
    print(f'Singleton filter: {len(singleton_keys)}/{len(func_counter)} funcs are singletons; {len(records) - len(filtered)} CVEs dropped; {len(filtered)} remain')
    return (filtered, singleton_keys)

def remove_singleton_funcs_global(records: list[dict], target: TargetClassification='root_cause_vulnerable', verbose: bool=True) -> tuple[list[dict], set[tuple]]:
    import copy
    target_classes = _TARGET_TO_CLASSES.get(target, {'root_cause_vulnerable'})
    func_counter: dict[tuple, int] = defaultdict(int)
    for r in records:
        cve_funcs: set[tuple] = set()
        for inst in extract_instances(r, target):
            for vf in inst['vuln_funcs']:
                cve_funcs.add((vf['file'], vf['sig']))
        for fk in cve_funcs:
            func_counter[fk] += 1
    singleton_keys = {fk for fk, cnt in func_counter.items() if cnt == 1}
    new_records = []
    for r in records:
        new_r = copy.deepcopy(r)
        for commit in new_r.get('src_commits', []):
            for diff in commit.get('diffs', []):
                fname = diff.get('filename', '')
                for cat in ('modified', 'removed'):
                    for func in diff.get('diff_funcs', {}).get(cat, []):
                        if func.get('classification') in target_classes:
                            if (fname, func['sig']) in singleton_keys:
                                func['classification'] = 'incidental_or_unrelated'
        kept_any = any((func.get('classification') in target_classes for commit in new_r.get('src_commits', []) for diff in commit.get('diffs', []) for cat in ('modified', 'removed') for func in diff.get('diff_funcs', {}).get(cat, [])))
        if kept_any:
            new_records.append(new_r)
    if verbose:
        print(f'Per-func singleton filter (target={target}): {len(singleton_keys)}/{len(func_counter)} funcs are singletons; {len(records) - len(new_records)} CVEs dropped; {len(new_records)} remain')
    return (new_records, singleton_keys)

def expand_by_cwe_node(records: list[dict]) -> list[dict]:
    expanded = []
    for r in records:
        for cwe_rep in r.get('cwe_reps', []):
            expanded.append({'cve_id': r['cve_id'], 'cwe_node_id': cwe_rep['id'], 'cwe_node_name': cwe_rep['name'], 'cwe_node_desc': cwe_rep.get('desc', ''), 'record': r})
    return expanded
