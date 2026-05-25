#!/usr/bin/env python3
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
from typing import Any

def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--input-jsonl', type=Path, default=Path('data/chromium_cve_data.commit_chained.jsonl'), help='Input dataset JSONL (must already have src_commits_chained)')
    ap.add_argument('--diff-root', type=Path, default=Path('cache/diff_files/chromium_c_cpp_no_comments_chain'), help='Root containing <leaf_id>/<file>.<sidecar-suffix>')
    ap.add_argument('--output-jsonl', type=Path, default=Path('data/chromium_cve_data.commit_chained.jsonl'), help='Output dataset JSONL (defaults to in-place update)')
    ap.add_argument('--sidecar-suffix', type=str, default='.diff_w_code_after.json', help='Sidecar filename suffix')
    ap.add_argument('--field-name', type=str, default='diffs', help='Name of the new field on each chain (mirrors per-commit `diffs`)')
    ap.add_argument('--missing-out', type=Path, default=Path('data/processing/6_6b_missing_chain_sidecars.jsonl'), help='JSONL listing chains with missing/parse-error sidecars')
    ap.add_argument('--overwrite', action='store_true', help='Allow overwriting output JSONL when it already exists and equals input.')
    return ap.parse_args()

def empty_diff_funcs() -> dict[str, list[Any]]:
    return {'added': [], 'removed': [], 'modified': []}

def normalize_func_list(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    out: list[dict[str, Any]] = []
    for item in value:
        if isinstance(item, dict):
            sig = item.get('sig')
            if not isinstance(sig, str) or not sig:
                continue
            entry: dict[str, Any] = {'sig': sig, 'code': item.get('code')}
            if 'code_after' in item:
                entry['code_after'] = item.get('code_after')
            out.append(entry)
            continue
        if isinstance(item, str):
            out.append({'sig': item, 'code': None})
    return out

def extract_diff_funcs(sidecar_obj: Any) -> dict[str, list[dict[str, Any]]]:
    if not isinstance(sidecar_obj, dict):
        return empty_diff_funcs()
    return {'added': normalize_func_list(sidecar_obj.get('added', [])), 'removed': normalize_func_list(sidecar_obj.get('removed', [])), 'modified': normalize_func_list(sidecar_obj.get('modified', []))}

def is_parent_file(name: str) -> bool:
    stem, ext = os.path.splitext(name)
    if ext:
        return stem.endswith('_parent')
    return name.endswith('_parent')

def list_leaf_files(leaf_dir: Path) -> list[str]:
    if not leaf_dir.is_dir():
        return []
    files = []
    for p in leaf_dir.rglob('*'):
        if not p.is_file():
            continue
        if p.suffix == '.json' and '.diff_w_code' in p.name:
            continue
        if is_parent_file(p.name):
            continue
        files.append(str(p.relative_to(leaf_dir)))
    return files

def main() -> None:
    args = parse_args()
    if not args.input_jsonl.is_file():
        raise SystemExit(f'Input JSONL not found: {args.input_jsonl}')
    if not args.diff_root.is_dir():
        raise SystemExit(f'Diff root not found: {args.diff_root}')
    same_path = args.input_jsonl.resolve() == args.output_jsonl.resolve()
    if same_path and (not args.overwrite):
        raise SystemExit(f'Output equals input ({args.output_jsonl}); pass --overwrite to update in place')
    args.output_jsonl.parent.mkdir(parents=True, exist_ok=True)
    output_tmp = args.output_jsonl.with_suffix(args.output_jsonl.suffix + '.tmp')
    args.missing_out.parent.mkdir(parents=True, exist_ok=True)
    missing_tmp = args.missing_out.with_suffix(args.missing_out.suffix + '.tmp')
    stats = {'records': 0, 'chains': 0, 'chains_no_leaf': 0, 'chains_no_files': 0, 'files_total': 0, 'sidecar_found': 0, 'sidecar_missing': 0, 'sidecar_parse_error': 0, 'files_with_funcs': 0, 'modified_funcs': 0, 'added_funcs': 0, 'removed_funcs': 0}
    try:
        with args.input_jsonl.open('r', encoding='utf-8') as fin, output_tmp.open('w', encoding='utf-8') as fout, missing_tmp.open('w', encoding='utf-8') as fmiss:
            for line_num, raw in enumerate(fin, start=1):
                stripped = raw.strip()
                if not stripped:
                    continue
                rec = json.loads(stripped)
                stats['records'] += 1
                cve = rec.get('cve_id') or rec.get('id') or ''
                chains = rec.get('src_commits_chained') or []
                for ch in chains:
                    stats['chains'] += 1
                    commit_ids = ch.get('commit_ids') or []
                    leaf = commit_ids[-1] if commit_ids else ''
                    if not leaf:
                        stats['chains_no_leaf'] += 1
                        ch[args.field_name] = []
                        continue
                    leaf_dir = args.diff_root / leaf
                    files = list_leaf_files(leaf_dir)
                    if not files:
                        stats['chains_no_files'] += 1
                        ch[args.field_name] = []
                        continue
                    real_diffs: list[dict[str, Any]] = []
                    for fname in files:
                        stats['files_total'] += 1
                        sidecar = leaf_dir / f'{fname}{args.sidecar_suffix}'
                        funcs = empty_diff_funcs()
                        reason = None
                        if sidecar.is_file():
                            try:
                                obj = json.loads(sidecar.read_text(encoding='utf-8'))
                                funcs = extract_diff_funcs(obj)
                                stats['sidecar_found'] += 1
                            except Exception as e:
                                stats['sidecar_parse_error'] += 1
                                reason = f'parse_error:{e}'
                        else:
                            stats['sidecar_missing'] += 1
                            reason = 'missing'
                        n_mod = len(funcs['modified'])
                        n_add = len(funcs['added'])
                        n_rem = len(funcs['removed'])
                        if n_mod or n_add or n_rem:
                            stats['files_with_funcs'] += 1
                        stats['modified_funcs'] += n_mod
                        stats['added_funcs'] += n_add
                        stats['removed_funcs'] += n_rem
                        real_diffs.append({'filename': fname, 'diff_funcs': funcs})
                        if reason is not None:
                            fmiss.write(json.dumps({'line': line_num, 'cve_id': cve, 'chain_id': ch.get('chain_id'), 'root_parent_id': ch.get('root_parent_id'), 'leaf_id': leaf, 'filename': fname, 'expected_sidecar': str(sidecar), 'reason': reason}, ensure_ascii=False) + '\n')
                    ch[args.field_name] = real_diffs
                fout.write(json.dumps(rec, ensure_ascii=False) + '\n')
        output_tmp.replace(args.output_jsonl)
        missing_tmp.replace(args.missing_out)
    finally:
        if output_tmp.exists():
            output_tmp.unlink(missing_ok=True)
        if missing_tmp.exists():
            missing_tmp.unlink(missing_ok=True)
    print('=== 6_6b merge complete ===')
    print(f'Input  JSONL: {args.input_jsonl}')
    print(f'Output JSONL: {args.output_jsonl}')
    print(f'Diff root:    {args.diff_root}')
    print(f'Missing report: {args.missing_out}')
    print()
    print(f"Records:                  {stats['records']:,}")
    print(f"Chains:                   {stats['chains']:,}")
    print(f"  no leaf id:             {stats['chains_no_leaf']:,}")
    print(f"  no files (empty diff):  {stats['chains_no_files']:,}")
    print(f"Files seen:               {stats['files_total']:,}")
    print(f"  sidecar found:          {stats['sidecar_found']:,}")
    print(f"  sidecar missing:        {stats['sidecar_missing']:,}")
    print(f"  sidecar parse error:    {stats['sidecar_parse_error']:,}")
    print(f"  with non-empty funcs:   {stats['files_with_funcs']:,}")
    print()
    print(f"Total modified funcs: {stats['modified_funcs']:,}")
    print(f"Total added funcs:    {stats['added_funcs']:,}")
    print(f"Total removed funcs:  {stats['removed_funcs']:,}")
if __name__ == '__main__':
    main()
