#!/usr/bin/env python3
from __future__ import annotations
import argparse
import json
import multiprocessing as mp
import re
import sqlite3
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path
import numpy as np
from scipy.sparse import csr_matrix
sys.path.insert(0, str(Path(__file__).parents[1]))
from utils.dataset import load_records, load_split_ids, filter_by_ids, get_input_text
from utils.metrics import build_gt_index, full_evaluation_pipeline, save_metrics, print_overall
_WORD_RE = re.compile('[A-Za-z][A-Za-z0-9]*')
_CAMEL_SPLIT_RE = re.compile('(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])')

def tokenize(text: str) -> list[str]:
    if not text:
        return []
    out: list[str] = []
    for w in _WORD_RE.findall(text):
        if len(w) < 2:
            continue
        if w.isupper() or w.islower():
            for s in w.split('_'):
                s = s.lower()
                if len(s) >= 2:
                    out.append(s)
            continue
        for sub in _CAMEL_SPLIT_RE.split(w):
            for s in sub.split('_'):
                s = s.lower()
                if len(s) >= 2:
                    out.append(s)
    return out

class BM25Sparse:

    def __init__(self, corpus_tokens: list[list[str]]):
        self.N = len(corpus_tokens)
        if self.N == 0:
            self.vocab = {}
            self.tf_matrix = csr_matrix((0, 0), dtype=np.float32)
            self.doc_len = np.zeros(0, dtype=np.float32)
            self.avgdl = 0.0
            self.idf = np.zeros(0, dtype=np.float32)
            return
        vocab: dict[str, int] = {}
        for toks in corpus_tokens:
            for t in toks:
                if t not in vocab:
                    vocab[t] = len(vocab)
        self.vocab = vocab
        V = len(vocab)
        indptr = [0]
        indices: list[int] = []
        data: list[int] = []
        doc_len: list[int] = []
        for toks in corpus_tokens:
            counts = Counter(toks)
            for term, c in counts.items():
                indices.append(vocab[term])
                data.append(c)
            indptr.append(len(indices))
            doc_len.append(len(toks))
        self.tf_matrix = csr_matrix((np.asarray(data, dtype=np.float32), np.asarray(indices, dtype=np.int32), np.asarray(indptr, dtype=np.int32)), shape=(self.N, V))
        self.doc_len = np.asarray(doc_len, dtype=np.float32)
        self.avgdl = float(self.doc_len.mean()) if self.N > 0 else 0.0
        df = np.asarray((self.tf_matrix > 0).sum(axis=0)).ravel().astype(np.float32)
        self.idf = np.log((self.N - df + 0.5) / (df + 0.5) + 1.0).astype(np.float32)

    def get_scores(self, query_tokens: list[str], k1: float, b: float) -> np.ndarray:
        if self.N == 0 or not query_tokens:
            return np.zeros(self.N, dtype=np.float32)
        q_idx = [self.vocab[t] for t in query_tokens if t in self.vocab]
        if not q_idx:
            return np.zeros(self.N, dtype=np.float32)
        q_idx = np.asarray(q_idx, dtype=np.int32)
        sub = self.tf_matrix[:, q_idx].toarray()
        norm = 1.0 - b + b * (self.doc_len / max(self.avgdl, 1e-06))
        denom = sub + (k1 * norm)[:, None]
        num = sub * (k1 + 1.0)
        per_q = np.zeros_like(sub)
        np.divide(num, denom, out=per_q, where=sub > 0)
        return per_q @ self.idf[q_idx]
_W_DB = None
_W_MAX_BODY = 50000
_W_USE_BODY = True

def _worker_init(db_path: str, max_body: int, use_body: bool):
    global _W_DB, _W_MAX_BODY, _W_USE_BODY
    _W_DB = sqlite3.connect(db_path, timeout=60.0)
    _W_DB.execute('PRAGMA query_only=ON')
    _W_DB.execute('PRAGMA cache_size=-262144')
    _W_MAX_BODY = max_body
    _W_USE_BODY = use_body

def _process_commit(task):
    rp, queries_per_field, grid_pairs, top_k = task
    if _W_USE_BODY:
        cur = _W_DB.execute('SELECT cf.file, f.sig, f.body FROM commit_files cf JOIN funcs f USING (blob_oid) WHERE cf.commit_id = ?', (rp,))
    else:
        cur = ((fp, sig, None) for fp, sig in _W_DB.execute('SELECT cf.file, f.sig FROM commit_files cf JOIN funcs f USING (blob_oid) WHERE cf.commit_id = ?', (rp,)))
    funcs: list[dict] = []
    vocab: dict[str, int] = {}
    indptr: list[int] = [0]
    indices: list[int] = []
    data: list[int] = []
    doc_len: list[int] = []
    for fp, sig, body in cur:
        if _W_USE_BODY:
            body = body or ''
            if len(body) > _W_MAX_BODY:
                body = body[:_W_MAX_BODY]
            text = (fp or '') + ' ' + body if body else (fp or '') + ' ' + (sig or '')
        else:
            text = (fp or '') + ' ' + (sig or '')
        toks = tokenize(text)
        counts = Counter(toks)
        for term, c in counts.items():
            tid = vocab.get(term)
            if tid is None:
                tid = len(vocab)
                vocab[term] = tid
            indices.append(tid)
            data.append(c)
        indptr.append(len(indices))
        doc_len.append(len(toks))
        funcs.append({'file': fp, 'sig': sig or ''})
    N = len(funcs)
    if N == 0:
        out = {}
        for field, queries in queries_per_field.items():
            for k1, b in grid_pairs:
                out.setdefault((field, k1, b), [])
                for cve, commit, _ in queries:
                    out[field, k1, b].append({'cve_id': cve, 'commit_id': commit, 'root_parent_id': rp, 'predicted_functions': []})
        return (rp, out)
    bm25 = BM25Sparse.__new__(BM25Sparse)
    bm25.N = N
    bm25.vocab = vocab
    V = len(vocab)
    bm25.tf_matrix = csr_matrix((np.asarray(data, dtype=np.float32), np.asarray(indices, dtype=np.int32), np.asarray(indptr, dtype=np.int32)), shape=(N, V))
    bm25.doc_len = np.asarray(doc_len, dtype=np.float32)
    bm25.avgdl = float(bm25.doc_len.mean()) if N > 0 else 0.0
    df = np.asarray((bm25.tf_matrix > 0).sum(axis=0)).ravel().astype(np.float32)
    bm25.idf = np.log((N - df + 0.5) / (df + 0.5) + 1.0).astype(np.float32)
    del data, indices, indptr, doc_len, df
    out: dict = {}
    for field, queries in queries_per_field.items():
        for k1, b in grid_pairs:
            out.setdefault((field, k1, b), [])
        for cve, commit, q_tokens in queries:
            for k1, b in grid_pairs:
                if not q_tokens or bm25.N == 0:
                    pred = []
                else:
                    scores = bm25.get_scores(q_tokens, k1, b)
                    if scores.size == 0:
                        pred = []
                    else:
                        kk = min(top_k, scores.size)
                        top_idx = np.argpartition(scores, -kk)[-kk:]
                        top_idx = top_idx[np.argsort(scores[top_idx])[::-1]]
                        pred = [{'file': funcs[i]['file'], 'sig': funcs[i]['sig']} for i in top_idx if scores[i] > 0]
                out[field, k1, b].append({'cve_id': cve, 'commit_id': commit, 'root_parent_id': rp, 'predicted_functions': pred})
    return (rp, out)

def root_parent_for_instance(records_by_cve: dict, cve_id: str, commit_id: str):
    rec = records_by_cve.get(cve_id)
    if not rec:
        return None
    chains = rec.get('src_commits_chained') or []
    for ch in chains:
        commit_ids = ch.get('commit_ids') or []
        if commit_ids and commit_ids[-1] == commit_id:
            return ch.get('root_parent_id')
    if len(chains) == 1:
        return chains[0].get('root_parent_id')
    return None

def build_tasks(records: list[dict], target: str, fields: list[str], grid_pairs: list[tuple], top_k: int):
    gt_index = build_gt_index(records, target, use_chained=True)
    records_by_cve = {r['cve_id']: r for r in records}
    by_rp: dict[str, dict[str, list]] = defaultdict(lambda: defaultdict(list))
    skipped = 0
    for (cve_id, commit_id), gt in gt_index.items():
        rp = root_parent_for_instance(records_by_cve, cve_id, commit_id)
        if not rp:
            skipped += 1
            continue
        rec = records_by_cve.get(cve_id)
        for field in fields:
            q = tokenize(get_input_text(rec, field) or '' if rec else '')
            by_rp[rp][field].append((cve_id, commit_id, q))
    tasks = [(rp, dict(qpf), grid_pairs, top_k) for rp, qpf in by_rp.items()]
    return (gt_index, tasks, skipped)

def run_pool(tasks, db_path: str, max_body: int, workers: int, log_prefix: str, use_body: bool=True, progress_every: int=20):
    preds: dict = defaultdict(list)
    n_total = len(tasks)
    t0 = time.time()
    with mp.Pool(workers, initializer=_worker_init, initargs=(db_path, max_body, use_body)) as pool:
        n_done = 0
        for rp, out in pool.imap_unordered(_process_commit, tasks, chunksize=2):
            for key, plist in out.items():
                preds[key].extend(plist)
            n_done += 1
            if n_done % progress_every == 0 or n_done == n_total:
                el = time.time() - t0
                eta = (n_total - n_done) / max(1e-06, n_done / el) / 60
                print(f'  {log_prefix}[{n_done:4d}/{n_total}] elapsed {el:5.0f}s  eta {eta:4.1f}min', flush=True)
    return preds
FIELD_ALIAS = {'pre': 'issue_summary', 'post': 'cve_desc_restated', 'raw': 'cve_desc'}

def parse_combos(spec: str) -> list[tuple[str, str, str]]:
    out = []
    for tok in spec.split(','):
        tok = tok.strip()
        if not tok:
            continue
        if '2' not in tok:
            sys.exit(f"bad combo '{tok}': expected '<train>2<test>'")
        ta, tb = tok.split('2', 1)
        if ta not in FIELD_ALIAS or tb not in FIELD_ALIAS:
            sys.exit(f"bad combo '{tok}': aliases must be pre/post/raw")
        out.append((tok, FIELD_ALIAS[ta], FIELD_ALIAS[tb]))
    return out

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--input', required=True, help='CVE dataset JSONL')
    ap.add_argument('--split-dir', required=True, help='Dir with train/val/test id files')
    ap.add_argument('--db', required=True, help='Function-corpus SQLite db')
    ap.add_argument('--combos', default=None, help="Comma list of '<trainAlias>2<testAlias>' combos (aliases pre/post/raw); overrides --test-fields")
    ap.add_argument('--test-fields', default='cve_desc_restated,issue_summary', help='Matched train==test fields list')
    ap.add_argument('--top-k', type=int, default=10, help='Predictions kept per instance')
    ap.add_argument('--max-body-chars', type=int, default=50000, help='Char cap on function body')
    ap.add_argument('--workers', type=int, default=16, help='Parallel workers')
    ap.add_argument('--tune-on', choices=['none', 'val', 'trainval'], default='none', help='Split for k1/b grid search')
    ap.add_argument('--k1', type=float, default=1.5, help='BM25 k1')
    ap.add_argument('--b', type=float, default=0.75, help='BM25 b')
    ap.add_argument('--k1-grid', default='1.0,1.5,2.0', help='k1 grid for tuning')
    ap.add_argument('--b-grid', default='0.25,0.5,0.75', help='b grid for tuning')
    ap.add_argument('--tune-metric', default='f1@10', help='Metric optimised during tuning')
    ap.add_argument('--predict-split', default='test', choices=['test', 'train', 'val', 'trainval'], help='Split to run predictions on')
    ap.add_argument('--output-suffix', default=None, help='Suffix appended to combo name in output dirs')
    args = ap.parse_args()
    if args.combos:
        combos = parse_combos(args.combos)
    else:
        combos = [(f'{f}2{f}', f, f) for f in (s.strip() for s in args.test_fields.split(',')) if f]
    train_fields = sorted({tr for _, tr, _ in combos})
    test_fields = sorted({te for _, _, te in combos})
    all_fields = sorted(set(train_fields) | set(test_fields))
    db_path = Path(args.db)
    if not db_path.exists():
        sys.exit(f'corpus DB not found: {db_path}')
    print(f'iii_a_bm25  combos={[c[0] for c in combos]}  train_fields={train_fields}  test_fields={test_fields}', flush=True)
    print(f'  workers={args.workers}  max_body={args.max_body_chars}  tune={args.tune_on}', flush=True)
    records = load_records(args.input)
    train_ids, val_ids, test_ids = load_split_ids(args.split_dir)
    TARGET_FOR_RETRIEVAL = 'related'
    TARGET_NAMES = {'related': 'related', 'root_cause_vulnerable': 'root_cause'}
    EVAL_TARGETS = ['related', 'root_cause_vulnerable']
    chosen_per_train_field: dict[str, tuple[float, float]] = {}
    tune_log_per_ft: dict = {}
    if args.tune_on != 'none':
        tune_records = filter_by_ids(records, train_ids | val_ids if args.tune_on == 'trainval' else val_ids)
        k1_grid = [float(x) for x in args.k1_grid.split(',')]
        b_grid = [float(x) for x in args.b_grid.split(',')]
        grid = [(k1, b) for k1 in k1_grid for b in b_grid]
        print(f"Tuning on '{args.tune_on}' ({len(tune_records)} CVEs, {len(grid)} grid pts × {len(train_fields)} train_fields)...", flush=True)
        gt_tune, tasks_tune, skipped = build_tasks(tune_records, TARGET_FOR_RETRIEVAL, train_fields, grid, args.top_k)
        print(f'  {len(tasks_tune)} unique commits  ({skipped} skipped)', flush=True)
        t0 = time.time()
        preds_tune = run_pool(tasks_tune, str(db_path), args.max_body_chars, args.workers, '[tune] ')
        print(f'  tune scan {time.time() - t0:.0f}s', flush=True)
        for tf in train_fields:
            for tgt in EVAL_TARGETS:
                gt_for_tgt = build_gt_index(tune_records, tgt, use_chained=True)
                best = (-1.0, None)
                log = []
                for k1, b in grid:
                    plist = preds_tune.get((tf, k1, b), [])
                    res = full_evaluation_pipeline(plist, gt_for_tgt, tune_records)
                    v = float(res['overall'].get(args.tune_metric, 0.0))
                    log.append({'k1': k1, 'b': b, args.tune_metric: v})
                    if v > best[0]:
                        best = (v, (k1, b))
                tune_log_per_ft[tf, tgt] = (best, log)
                print(f'  ★ train_field={tf} target={TARGET_NAMES[tgt]}  best {args.tune_metric}={best[0]:.4f} @ k1={best[1][0]} b={best[1][1]}', flush=True)
            chosen_per_train_field[tf] = tune_log_per_ft[tf, 'related'][0][1] or (args.k1, args.b)
    else:
        for tf in train_fields:
            chosen_per_train_field[tf] = (args.k1, args.b)
    SPLIT_IDS = {'test': test_ids, 'train': train_ids, 'val': val_ids, 'trainval': train_ids | val_ids}
    test_records = filter_by_ids(records, SPLIT_IDS[args.predict_split])
    suffix = args.output_suffix if args.output_suffix is not None else '' if args.predict_split == 'test' else f'_{args.predict_split}'
    print(f"\nEvaluating on '{args.predict_split}' split ({len(test_records)} CVEs; suffix={suffix!r})...", flush=True)
    grid_per_test_field: dict[str, set] = defaultdict(set)
    for combo_name, tr, te in combos:
        grid_per_test_field[te].add(chosen_per_train_field[tr])
    union_grid = sorted({pair for s in grid_per_test_field.values() for pair in s})
    gt_test, tasks_test, skipped = build_tasks(test_records, TARGET_FOR_RETRIEVAL, test_fields, union_grid, args.top_k)
    print(f'  {len(tasks_test)} unique commits ({skipped} skipped); scoring {len(union_grid)} (k1,b) × {len(test_fields)} test_fields', flush=True)
    t0 = time.time()
    preds_test = run_pool(tasks_test, str(db_path), args.max_body_chars, args.workers, '[test] ')
    print(f'  test scan {time.time() - t0:.0f}s', flush=True)
    for combo_name, tr, te in combos:
        k1, b = chosen_per_train_field[tr]
        plist = preds_test.get((te, k1, b), [])
        for tgt in EVAL_TARGETS:
            tgt_short = TARGET_NAMES[tgt]
            pred_dir = Path(f'results/predictions/iii_a_bm25/{tgt_short}/{combo_name}{suffix}')
            metrics_dir = Path(f'results/metrics/iii_a_bm25/{tgt_short}/{combo_name}{suffix}')
            pred_dir.mkdir(parents=True, exist_ok=True)
            metrics_dir.mkdir(parents=True, exist_ok=True)
            with (pred_dir / 'predictions.jsonl').open('w') as f:
                for p in plist:
                    obj = {**p, 'method': 'bm25', 'combo': combo_name, 'train_field': tr, 'test_field': te, 'k1': k1, 'b': b}
                    f.write(json.dumps(obj, ensure_ascii=False) + '\n')
            gt_idx = build_gt_index(test_records, tgt, use_chained=True)
            res = full_evaluation_pipeline(plist, gt_idx, test_records)
            save_metrics(res['overall'], metrics_dir / 'overall.json')
            save_metrics(res.get('by_cwe', {}), metrics_dir / 'by_cwe.json')
            if tune_log_per_ft:
                best, log = tune_log_per_ft.get((tr, tgt), ((0, None), []))
                save_metrics({'tune_on': args.tune_on, 'tune_metric': args.tune_metric, 'train_field': tr, 'test_field': te, 'best_k1': (best[1] or (0, 0))[0], 'best_b': (best[1] or (0, 0))[1], 'best_metric_on_tune': best[0], 'grid': log}, metrics_dir / 'tuning.json')
            print_overall(res['overall'], f'iii_a_bm25/{tgt_short}/{combo_name} (k1={k1}, b={b})')
if __name__ == '__main__':
    main()
