import argparse
import json
import os
import sys
from collections import Counter, defaultdict
from pathlib import Path
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
sys.path.insert(0, str(Path(__file__).parents[1]))
from utils.dataset import load_records, load_split_ids, filter_by_ids, get_input_text
from utils.metrics import save_metrics, eval_loose_dual_instance
_TARGET_CLASSES = {'root_cause_vulnerable': {'root_cause_vulnerable'}, 'related': {'root_cause_vulnerable', 'supporting_fix'}}
_TARGET_SHORT = {'root_cause_vulnerable': 'root_cause', 'related': 'related'}
VARIANT_MAP = {('cve_desc_restated', 'cve_desc_restated'): 'post2post', ('cve_desc', 'cve_desc_restated'): 'raw2post', ('cve_desc', 'issue_summary'): 'raw2pre', ('cve_desc_restated', 'issue_summary'): 'post2pre', ('issue_summary', 'issue_summary'): 'pre2pre'}

def detect_variant(train_field, test_field):
    return VARIANT_MAP.get((train_field, test_field), 'custom')

def extract_bare_name(sig: str) -> str | None:
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
    return s or None

def _file_key(path):
    if not path:
        return None
    return os.path.splitext(path)[0]

def collect_pairs(record, target_classes, use_chained=True):
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
                    for func in df.get(cat) or []:
                        if func.get('classification') in target_classes:
                            bn = extract_bare_name(func['sig'])
                            if bn:
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
                    for func in df.get(cat, []):
                        if func.get('classification') in target_classes:
                            bn = extract_bare_name(func['sig'])
                            if bn:
                                pairs.add((fk, bn))
    return pairs

def build_row(r, target_classes, use_chained=True):
    if not r.get('cwe_id'):
        return None
    pairs = collect_pairs(r, target_classes, use_chained=use_chained)
    if not pairs:
        return None
    return {'cve_id': r['cve_id'], 'cwe_reps': [rep['id'] for rep in r.get('cwe_reps', [])] or ['unknown'], 'pairs': pairs, 'train_text': None, 'test_text': None}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--input', required=True, help='CVE dataset JSONL')
    ap.add_argument('--split-dir', required=True, help='Dir with train/val/test id files')
    ap.add_argument('--train-field', required=True, choices=['cve_desc_restated', 'cve_desc', 'issue_summary'], help='Text field used to fit the model')
    ap.add_argument('--test-field', required=True, choices=['cve_desc_restated', 'cve_desc', 'issue_summary'], help='Text field used at inference')
    ap.add_argument('--target', required=True, choices=['root_cause_vulnerable', 'related'], help='GT class to score against')
    ap.add_argument('--pred-dir', help='Output dir for predictions')
    ap.add_argument('--metrics-dir', help='Output dir for metrics')
    ap.add_argument('--k-neighbors', type=int, default=5, help='kNN neighbours')
    ap.add_argument('--top-k', type=int, default=10, help='Predictions kept per instance')
    ap.add_argument('--per-commit', action='store_true', help='Use per-commit instances instead of chain-level')
    args = ap.parse_args()
    use_chained = not args.per_commit
    variant = detect_variant(args.train_field, args.test_field)
    target_short = _TARGET_SHORT[args.target]
    target_classes = _TARGET_CLASSES[args.target]
    pred_dir = Path(args.pred_dir or f'results/predictions/ii_a_tfidf_knn-{variant}/{target_short}')
    metrics_dir = Path(args.metrics_dir or f'results/metrics/ii_a_tfidf_knn-{variant}/{target_short}')
    pred_dir.mkdir(parents=True, exist_ok=True)
    metrics_dir.mkdir(parents=True, exist_ok=True)
    print(f'ii_a_tfidf_knn-{variant}/{target_short}  (train={args.train_field}, test={args.test_field})')
    records = load_records(args.input)
    train_ids, val_ids, test_ids = load_split_ids(args.split_dir)
    train_records = filter_by_ids(records, train_ids | val_ids)
    test_records = filter_by_ids(records, test_ids)
    train_rows = [r for r in (build_row(x, target_classes, use_chained=use_chained) for x in train_records) if r]
    test_rows = [r for r in (build_row(x, target_classes, use_chained=use_chained) for x in test_records) if r]
    print(f'After row construction — train+val: {len(train_rows)}  test: {len(test_rows)}')
    cve_to_record = {r['cve_id']: r for r in train_records + test_records}
    for row in train_rows + test_rows:
        orig = cve_to_record[row['cve_id']]
        row['train_text'] = get_input_text(orig, args.train_field)
        row['test_text'] = get_input_text(orig, args.test_field)
    pair_counter: Counter = Counter()
    for row in train_rows + test_rows:
        pair_counter.update(row['pairs'])
    n_singleton = sum((1 for c in pair_counter.values() if c == 1))
    print(f'  unique pairs: {len(pair_counter)}; singletons: {n_singleton}')
    for row in train_rows + test_rows:
        row['pairs'] = {p for p in row['pairs'] if pair_counter[p] > 1}
    train_rows = [r for r in train_rows if r['pairs'] and r['train_text']]
    test_rows = [r for r in test_rows if r['pairs'] and r['test_text']]
    print(f'  after singleton removal — train+val: {len(train_rows)}  test: {len(test_rows)}')
    cwe_groups: dict[str, list[dict]] = defaultdict(list)
    for row in train_rows:
        for node in row['cwe_reps']:
            cwe_groups[node].append(row)
    index = {}
    for node, rows in cwe_groups.items():
        vocab_texts, train_texts, pairs_list = ([], [], [])
        for row in rows:
            train_texts.append(row['train_text'])
            pairs_list.append(list(row['pairs']))
            vocab_texts.append(row['train_text'])
            if args.train_field != args.test_field and row.get('test_text'):
                vocab_texts.append(row['test_text'])
        if len(train_texts) < 2:
            continue
        vec = TfidfVectorizer(stop_words='english', max_features=5000, sublinear_tf=True)
        vec.fit(vocab_texts)
        X = vec.transform(train_texts)
        index[node] = {'vectorizer': vec, 'matrix': X, 'pairs': pairs_list}
    print(f'Index built for {len(index)} CWE nodes')
    pred_path = pred_dir / 'predictions.jsonl'
    k_vals = [1, 3, 5, 10]
    instance_metrics: list[dict] = []
    with open(pred_path, 'w') as f_out:
        for row in test_rows:
            candidate_score: dict[tuple, float] = defaultdict(float)
            for node in row['cwe_reps']:
                if node not in index:
                    continue
                vec = index[node]['vectorizer']
                X = index[node]['matrix']
                plist = index[node]['pairs']
                try:
                    q_vec = vec.transform([row['test_text']])
                except Exception:
                    continue
                sims = cosine_similarity(q_vec, X)[0]
                top_idx = sims.argsort()[-args.k_neighbors:][::-1]
                for rank, idx in enumerate(top_idx):
                    sim = float(sims[idx])
                    for pr in plist[idx]:
                        candidate_score[pr] += sim / (rank + 1)
            predicted_pairs = [pr for pr, _ in sorted(candidate_score.items(), key=lambda x: -x[1])[:args.top_k]]
            gt_pairs = list(row['pairs'])
            m = eval_loose_dual_instance(predicted_pairs, gt_pairs, k_vals)
            instance_metrics.append(m)
            f_out.write(json.dumps({'cve_id': row['cve_id'], 'method': 'tfidf_knn', 'variant': f'ii_a_tfidf_knn-{variant}', 'train_field': args.train_field, 'test_field': args.test_field, 'predicted_pairs': [list(p) for p in predicted_pairs], 'gt_pairs': [list(p) for p in sorted(gt_pairs)]}, ensure_ascii=False) + '\n')
    if not instance_metrics:
        print('No test instances evaluated.')
        return
    keys = list(instance_metrics[0].keys())
    overall = {k: float(np.mean([m[k] for m in instance_metrics])) for k in keys}
    save_metrics(overall, metrics_dir / 'overall.json')
    print(f'\nii_a_tfidf_knn-{variant} ({args.target}, {len(instance_metrics)} instances):')
    for k in sorted(overall):
        print(f'  {k:<22} {overall[k]:.4f}')
if __name__ == '__main__':
    main()
