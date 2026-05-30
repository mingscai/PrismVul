import argparse
import json
import os
import sys
from collections import Counter, defaultdict
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parents[1]))
from utils.dataset import load_records, load_split_ids, filter_by_ids
from utils.metrics import save_metrics, eval_loose_dual_instance
TOP_K = 10

def extract_function_names(sigs: list[str]) -> set[str]:
    names = set()
    for sig in sigs:
        s = sig
        i = 0
        while i < len(s):
            if s[i] == ':':
                prev_colon = i > 0 and s[i - 1] == ':'
                next_colon = i + 1 < len(s) and s[i + 1] == ':'
                if not prev_colon and (not next_colon):
                    s = s[:i]
                    break
            i += 1
        s = s.split('(')[0].strip()
        s = s.replace('::', '.').rsplit('.', 1)[-1].strip()
        if s:
            names.add(s)
    return names
_TARGET_CLASSES = {'root_cause_vulnerable': {'root_cause_vulnerable'}, 'related': {'root_cause_vulnerable', 'supporting_fix'}}
_TARGET_SHORT = {'root_cause_vulnerable': 'root_cause', 'related': 'related'}

def _file_key(path: str | None) -> str | None:
    if not path:
        return None
    return os.path.splitext(path)[0]

def get_legacy_pairs(record: dict, target_classes: set[str], use_chained: bool=True) -> list[tuple[str, str]]:
    pairs: set[tuple[str, str]] = set()
    if use_chained:
        for ch in record.get('src_commits_chained') or []:
            for diff in ch.get('diffs') or []:
                fname = diff.get('filename', '')
                if 'test' in fname.lower():
                    continue
                fk = _file_key(fname)
                if not fk:
                    continue
                df = diff.get('diff_funcs') or {}
                for cat in ('modified', 'removed'):
                    sigs = [f['sig'] for f in df.get(cat) or [] if f.get('classification') in target_classes]
                    for bn in extract_function_names(sigs):
                        pairs.add((fk, bn))
    else:
        for commit in record.get('src_commits', []):
            for diff in commit.get('diffs', []):
                fname = diff.get('filename', '')
                if 'test' in fname.lower():
                    continue
                fk = _file_key(fname)
                if not fk:
                    continue
                df = diff.get('diff_funcs', {})
                for cat in ('modified', 'removed'):
                    sigs = [f['sig'] for f in df.get(cat, []) if f.get('classification') in target_classes]
                    for bn in extract_function_names(sigs):
                        pairs.add((fk, bn))
    return list(pairs)

def build_legacy_row(r: dict, target_classes: set[str], use_chained: bool=True) -> dict | None:
    if not r.get('cwe_id'):
        return None
    pairs = get_legacy_pairs(r, target_classes, use_chained=use_chained)
    if not pairs:
        return None
    return {'cve_id': r['cve_id'], 'cwe_reps': [rep['id'] for rep in r.get('cwe_reps', [])] or ['unknown'], 'vuln_pairs': pairs}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--input', required=True, help='CVE dataset JSONL')
    ap.add_argument('--split-dir', required=True, help='Dir with train/val/test id files')
    ap.add_argument('--target', required=True, choices=['root_cause_vulnerable', 'related'], help='GT class to score against')
    ap.add_argument('--pred-dir', help='Output dir for predictions')
    ap.add_argument('--metrics-dir', help='Output dir for metrics')
    ap.add_argument('--top-k', type=int, default=TOP_K)
    ap.add_argument('--per-commit', action='store_true', help='Use per-commit instances instead of chain-level')
    args = ap.parse_args()
    use_chained = not args.per_commit
    target_short = _TARGET_SHORT[args.target]
    target_classes = _TARGET_CLASSES[args.target]
    pred_dir = Path(args.pred_dir or f'results/predictions/i_cwe_freq/{target_short}')
    metrics_dir = Path(args.metrics_dir or f'results/metrics/i_cwe_freq/{target_short}')
    pred_dir.mkdir(parents=True, exist_ok=True)
    metrics_dir.mkdir(parents=True, exist_ok=True)
    print(f'i_cwe_freq  target={args.target}  split={args.split_dir}')
    records = load_records(args.input)
    train_ids, val_ids, test_ids = load_split_ids(args.split_dir)
    train_records = filter_by_ids(records, train_ids | val_ids)
    test_records = filter_by_ids(records, test_ids)
    train_rows = [r for r in (build_legacy_row(x, target_classes, use_chained=use_chained) for x in train_records) if r]
    test_rows = [r for r in (build_legacy_row(x, target_classes, use_chained=use_chained) for x in test_records) if r]
    print(f'After row construction — train+val: {len(train_rows)}  test: {len(test_rows)}')
    pair_counter: Counter = Counter()
    for row in train_rows + test_rows:
        pair_counter.update(set(row['vuln_pairs']))
    n_singleton = sum((1 for c in pair_counter.values() if c == 1))
    print(f'  unique pairs: {len(pair_counter)}; singletons: {n_singleton}')
    for row in train_rows + test_rows:
        row['vuln_pairs'] = [p for p in row['vuln_pairs'] if pair_counter[p] > 1]
    train_rows = [r for r in train_rows if r['vuln_pairs']]
    test_rows = [r for r in test_rows if r['vuln_pairs']]
    print(f'  after singleton removal — train+val: {len(train_rows)}  test: {len(test_rows)}')
    cwe_pair_counter: dict[str, Counter] = defaultdict(Counter)
    for row in train_rows:
        seen = set(row['vuln_pairs'])
        for node in row['cwe_reps']:
            for p in seen:
                cwe_pair_counter[node][p] += 1
    pred_path = pred_dir / 'predictions.jsonl'
    k_vals = [1, 3, 5, 10]
    instance_metrics: list[dict] = []
    with open(pred_path, 'w') as f_out:
        for row in test_rows:
            combined: Counter = Counter()
            for node in row['cwe_reps']:
                combined.update(cwe_pair_counter.get(node, Counter()))
            predicted_pairs = [p for p, _ in combined.most_common(args.top_k)]
            gt_pairs = list(set(row['vuln_pairs']))
            metrics = eval_loose_dual_instance(predicted_pairs, gt_pairs, k_vals)
            instance_metrics.append(metrics)
            f_out.write(json.dumps({'cve_id': row['cve_id'], 'method': 'cwe_frequency', 'predicted_pairs': [list(p) for p in predicted_pairs], 'gt_pairs': [list(p) for p in sorted(gt_pairs)]}, ensure_ascii=False) + '\n')
    import numpy as np
    if not instance_metrics:
        print('No test instances evaluated.')
        return
    keys = list(instance_metrics[0].keys())
    overall = {k: float(np.mean([m[k] for m in instance_metrics])) for k in keys}
    save_metrics(overall, metrics_dir / 'overall.json')
    print(f'\ni_cwe_freq results ({len(instance_metrics)} test instances):')
    for k in sorted(overall):
        print(f'  {k:<22} {overall[k]:.4f}')
if __name__ == '__main__':
    main()
