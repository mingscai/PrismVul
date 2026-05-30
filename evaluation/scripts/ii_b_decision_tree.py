import argparse
import json
import os
import sys
from collections import Counter
from pathlib import Path
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.multiclass import OneVsRestClassifier
from sklearn.preprocessing import MultiLabelBinarizer
from sklearn.tree import DecisionTreeClassifier
sys.path.insert(0, str(Path(__file__).parents[1]))
from utils.dataset import load_records, load_split_ids, filter_by_ids, get_input_text
from utils.metrics import save_metrics, eval_loose_dual_instance
_TARGET_CLASSES = {'root_cause_vulnerable': {'root_cause_vulnerable'}, 'related': {'root_cause_vulnerable', 'supporting_fix'}}
_TARGET_SHORT = {'root_cause_vulnerable': 'root_cause', 'related': 'related'}
VARIANT_MAP = {('cve_desc_restated', 'cve_desc_restated'): 'post2post', ('cve_desc', 'cve_desc_restated'): 'raw2post', ('cve_desc', 'issue_summary'): 'raw2pre', ('cve_desc_restated', 'issue_summary'): 'post2pre', ('issue_summary', 'issue_summary'): 'pre2pre'}

def detect_variant(train_field, test_field):
    return VARIANT_MAP.get((train_field, test_field), 'custom')

def _file_key(path):
    if not path:
        return None
    return os.path.splitext(path)[0]

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

def build_feature_text(record, input_field):
    parts = [get_input_text(record, input_field), record.get('cwe_name', ''), record.get('cwe_desc', '')]
    return ' '.join((p for p in parts if p))

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
    return {'cve_id': r['cve_id'], 'cwe_reps': [rep['id'] for rep in r.get('cwe_reps', [])] or ['unknown'], 'pairs': pairs}

def eval_classifier_pairs(y_pred_pairs, gt_pairs):
    pred_set = set(y_pred_pairs)
    gt_set = set(gt_pairs)

    def _set_metrics(p, g, suffix):
        n_p, n_g = (len(p), len(g))
        if n_p == 0:
            return {f'n_pred{suffix}': 0, f'precision{suffix}': 0.0, f'recall{suffix}': 0.0, f'f1{suffix}': 0.0, f'iou{suffix}': 0.0, f'subset_acc{suffix}': 0.0}
        n_match = len(p & g)
        prec = n_match / n_p
        rec = n_match / n_g if n_g > 0 else 0.0
        f1 = 2 * prec * rec / (prec + rec) if prec + rec > 0 else 0.0
        union = n_p + n_g - n_match
        iou = n_match / union if union > 0 else 0.0
        sub = 1.0 if n_match == n_g and n_p == n_match else 0.0
        return {f'n_pred{suffix}': float(n_p), f'precision{suffix}': prec, f'recall{suffix}': rec, f'f1{suffix}': f1, f'iou{suffix}': iou, f'subset_acc{suffix}': sub}
    out = {}
    out.update(_set_metrics({bn for _, bn in pred_set}, {bn for _, bn in gt_set}, ''))
    out.update(_set_metrics({fk for fk, _ in pred_set}, {fk for fk, _ in gt_set}, '_file'))
    out.update(_set_metrics(pred_set, gt_set, '_tuple'))
    out['empty_pred'] = 1.0 if not pred_set else 0.0
    return out

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--input', required=True, help='CVE dataset JSONL')
    ap.add_argument('--split-dir', required=True, help='Dir with train/val/test id files')
    ap.add_argument('--train-field', required=True, choices=['cve_desc_restated', 'cve_desc', 'issue_summary'], help='Text field used to fit the model')
    ap.add_argument('--test-field', required=True, choices=['cve_desc_restated', 'cve_desc', 'issue_summary'], help='Text field used at inference')
    ap.add_argument('--target', required=True, choices=['root_cause_vulnerable', 'related'], help='GT class to score against')
    ap.add_argument('--pred-dir', help='Output dir for predictions')
    ap.add_argument('--metrics-dir', help='Output dir for metrics')
    ap.add_argument('--max-features', type=int, default=2000, help='TF-IDF vocabulary cap')
    ap.add_argument('--top-k', type=int, default=10, help='Predictions kept per instance')
    ap.add_argument('--per-commit', action='store_true', help='Use per-commit instances instead of chain-level')
    args = ap.parse_args()
    use_chained = not args.per_commit
    variant = detect_variant(args.train_field, args.test_field)
    target_short = _TARGET_SHORT[args.target]
    target_classes = _TARGET_CLASSES[args.target]
    pred_dir = Path(args.pred_dir or f'results/predictions/ii_b_decision_tree-{variant}/{target_short}')
    metrics_dir = Path(args.metrics_dir or f'results/metrics/ii_b_decision_tree-{variant}/{target_short}')
    pred_dir.mkdir(parents=True, exist_ok=True)
    metrics_dir.mkdir(parents=True, exist_ok=True)
    print(f'ii_b_decision_tree-{variant}/{target_short}  (train={args.train_field}, test={args.test_field})')
    records = load_records(args.input)
    train_ids, val_ids, test_ids = load_split_ids(args.split_dir)
    train_records = filter_by_ids(records, train_ids | val_ids)
    test_records = filter_by_ids(records, test_ids)
    train_rows = [r for r in (build_row(x, target_classes, use_chained=use_chained) for x in train_records) if r]
    test_rows = [r for r in (build_row(x, target_classes, use_chained=use_chained) for x in test_records) if r]
    print(f'After row construction — train+val: {len(train_rows)}  test: {len(test_rows)}')
    pair_counter: Counter = Counter()
    for row in train_rows + test_rows:
        pair_counter.update(row['pairs'])
    n_singleton = sum((1 for c in pair_counter.values() if c == 1))
    print(f'  unique pairs: {len(pair_counter)}; singletons: {n_singleton}')
    for row in train_rows + test_rows:
        row['pairs'] = {p for p in row['pairs'] if pair_counter[p] > 1}
    train_rows = [r for r in train_rows if r['pairs']]
    test_rows = [r for r in test_rows if r['pairs']]
    print(f'  after singleton removal — train+val: {len(train_rows)}  test: {len(test_rows)}')
    cve_to_rec = {r['cve_id']: r for r in train_records + test_records}
    train_texts, train_labels, vocab_texts = ([], [], [])
    for row in train_rows:
        orig = cve_to_rec[row['cve_id']]
        t = build_feature_text(orig, args.train_field)
        if not t:
            continue
        train_texts.append(t)
        train_labels.append(list(row['pairs']))
        vocab_texts.append(t)
        if args.train_field != args.test_field:
            tv = build_feature_text(orig, args.test_field)
            if tv:
                vocab_texts.append(tv)
    print(f'Training samples: {len(train_texts)}')
    if not train_texts:
        print('No training data — abort.')
        return
    vec = TfidfVectorizer(stop_words='english', max_features=args.max_features, sublinear_tf=True)
    vec.fit(vocab_texts)
    X_train = vec.transform(train_texts)
    mlb = MultiLabelBinarizer()
    Y_train = mlb.fit_transform(train_labels)
    print(f'Label space: {len(mlb.classes_)} (file, name) pairs')
    clf = OneVsRestClassifier(DecisionTreeClassifier(random_state=42))
    clf.fit(X_train, Y_train)
    pred_path = pred_dir / 'predictions.jsonl'
    clf_pred_path = pred_dir / 'predictions_classifier.jsonl'
    k_vals = [1, 3, 5, 10]
    retrieval_instance: list[dict] = []
    clf_instance: list[dict] = []
    with open(pred_path, 'w') as f_rank, open(clf_pred_path, 'w') as f_clf:
        for row in test_rows:
            orig = cve_to_rec[row['cve_id']]
            text = build_feature_text(orig, args.test_field)
            if not text:
                continue
            X_test = vec.transform([text])
            try:
                proba = clf.predict_proba(X_test)
                if isinstance(proba, list):
                    proba_scores = np.array([p[0, 1] if p.shape[1] == 2 else p[0, 0] for p in proba])
                else:
                    proba_scores = proba[0]
            except Exception:
                proba_scores = clf.decision_function(X_test)[0]
            ranked_idx = np.argsort(proba_scores)[::-1]
            ranked_pairs = [tuple(mlb.classes_[i]) for i in ranked_idx[:args.top_k]]
            y_pred = clf.predict(X_test)[0]
            clf_pred_pairs = [tuple(mlb.classes_[i]) for i in np.where(y_pred > 0)[0]]
            gt_pairs = list(row['pairs'])
            retrieval_instance.append(eval_loose_dual_instance(ranked_pairs, gt_pairs, k_vals))
            clf_instance.append(eval_classifier_pairs(clf_pred_pairs, gt_pairs))
            f_rank.write(json.dumps({'cve_id': row['cve_id'], 'method': 'decision_tree', 'variant': f'ii_b_decision_tree-{variant}', 'train_field': args.train_field, 'test_field': args.test_field, 'predicted_pairs': [list(p) for p in ranked_pairs], 'gt_pairs': [list(p) for p in sorted(gt_pairs)]}, ensure_ascii=False) + '\n')
            f_clf.write(json.dumps({'cve_id': row['cve_id'], 'predicted_pairs': [list(p) for p in clf_pred_pairs], 'gt_pairs': [list(p) for p in sorted(gt_pairs)]}, ensure_ascii=False) + '\n')
    if not retrieval_instance:
        print('No test instances evaluated.')
        return
    keys = list(retrieval_instance[0].keys())
    overall = {k: float(np.mean([m[k] for m in retrieval_instance])) for k in keys}
    save_metrics(overall, metrics_dir / 'overall.json')
    clf_keys = list(clf_instance[0].keys())
    clf_overall = {k: float(np.mean([m[k] for m in clf_instance])) for k in clf_keys}
    save_metrics(clf_overall, metrics_dir / 'overall_classifier.json')
    print(f'\nii_b_decision_tree-{variant} ({args.target}, {len(retrieval_instance)} instances):')
if __name__ == '__main__':
    main()
