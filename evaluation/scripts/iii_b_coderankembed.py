#!/usr/bin/env python3
from __future__ import annotations
import argparse
import json
import os
import sqlite3
import sys
import time
from collections import defaultdict
from pathlib import Path
from typing import Iterable
import numpy as np
sys.path.insert(0, str(Path(__file__).parents[1]))
DEFAULT_MODEL = 'nomic-ai/CodeRankEmbed'
DEFAULT_DIM = 768
MODEL_DEFAULTS = {'nomic-ai/CodeRankEmbed': {'pooling': 'cls', 'query_prefix': 'Represent this query for searching relevant code: ', 'doc_prefix': ''}, 'BAAI/bge-code-v1': {'pooling': 'last_token', 'query_prefix': '<|im_start|>user\nQuery: {q}<|im_end|>\n<|im_start|>assistant\n', 'doc_prefix': ''}}
FIELD_ALIAS = {'pre': 'issue_summary', 'post': 'cve_desc_restated', 'raw': 'cve_desc'}

def model_defaults(model_name: str) -> dict:
    if model_name in MODEL_DEFAULTS:
        return MODEL_DEFAULTS[model_name]
    base = os.path.basename(os.path.normpath(model_name))
    for hf_id, defaults in MODEL_DEFAULTS.items():
        if hf_id.rsplit('/', 1)[-1] == base:
            return defaults
    return {'pooling': 'cls', 'query_prefix': '', 'doc_prefix': ''}

def resolve_model_path(model_name: str) -> str:
    if not model_name:
        return model_name
    if model_name.startswith(('/', '~')):
        if Path(os.path.expanduser(model_name)).exists():
            return model_name
        base = os.path.basename(os.path.normpath(model_name))
        for hf_id in MODEL_DEFAULTS:
            if hf_id.rsplit('/', 1)[-1] == base:
                return hf_id
        return DEFAULT_MODEL
    return model_name

def apply_gpu_memory_cap(fraction):
    if not fraction or fraction >= 1.0:
        return
    import torch
    if not torch.cuda.is_available():
        return
    for i in range(torch.cuda.device_count()):
        try:
            torch.cuda.set_per_process_memory_fraction(float(fraction), device=i)
        except Exception as e:
            print(f'[warn] set_per_process_memory_fraction failed on cuda:{i}: {e}', flush=True)

def pool_embeddings(hidden: 'torch.Tensor', attention_mask: 'torch.Tensor', strategy: str) -> 'torch.Tensor':
    import torch
    if strategy == 'cls':
        return hidden[:, 0]
    if strategy == 'mean':
        mask = attention_mask.unsqueeze(-1).float()
        return (hidden * mask).sum(1) / mask.sum(1).clamp(min=1e-09)
    if strategy == 'last_token':
        seq_len = attention_mask.sum(dim=1) - 1
        return hidden[torch.arange(hidden.size(0)), seq_len]
    raise ValueError(f'unknown pooling strategy: {strategy}')

def alias_to_field(alias: str) -> str:
    if alias not in FIELD_ALIAS:
        sys.exit(f'unknown field alias: {alias}')
    return FIELD_ALIAS[alias]

def open_corpus_db(db_path: str) -> sqlite3.Connection:
    if not Path(db_path).exists():
        sys.exit(f'corpus DB not found: {db_path}')
    con = sqlite3.connect(db_path, timeout=60.0)
    con.execute('PRAGMA query_only=ON')
    con.execute('PRAGMA cache_size=-1048576')
    return con

def load_split_ids(split_dir: str) -> tuple[set, set, set]:

    def rd(name):
        return {l.strip() for l in open(f'{split_dir}/chromium_{name}_ids.txt') if l.strip()}
    return (rd('train'), rd('val'), rd('test'))

def collect_test_commits(input_jsonl: str, test_ids: set[str]) -> set[str]:
    rps = set()
    with open(input_jsonl) as f:
        for line in f:
            r = json.loads(line)
            if r.get('cve_id') not in test_ids:
                continue
            for ch in r.get('src_commits_chained') or []:
                rp = (ch.get('root_parent_id') or '').strip()
                if rp:
                    rps.add(rp)
    return rps

def root_parent_for_instance(records_by_cve, cve_id: str, commit_id: str):
    rec = records_by_cve.get(cve_id)
    if not rec:
        return None
    chains = rec.get('src_commits_chained') or []
    for ch in chains:
        cids = ch.get('commit_ids') or []
        if cids and cids[-1] == commit_id:
            return ch.get('root_parent_id')
    if len(chains) == 1:
        return chains[0].get('root_parent_id')
    return None

def fetch_funcs_for_commits(con: sqlite3.Connection, commit_ids: Iterable[str], max_body: int) -> Iterable[dict]:
    cmts = list(commit_ids)
    blob_file: dict[str, str] = {}
    for i in range(0, len(cmts), 100):
        chunk = cmts[i:i + 100]
        cur = con.execute(f"SELECT blob_oid, file FROM commit_files WHERE commit_id IN ({','.join('?' * len(chunk))})", chunk)
        for blob_oid, fp in cur:
            if blob_oid not in blob_file:
                blob_file[blob_oid] = fp or ''
    blobs = list(blob_file)
    BLOB_BATCH = 5000
    for i in range(0, len(blobs), BLOB_BATCH):
        bchunk = blobs[i:i + BLOB_BATCH]
        cur = con.execute(f"SELECT blob_oid, idx, sig, body FROM funcs WHERE blob_oid IN ({','.join('?' * len(bchunk))})", bchunk)
        for blob_oid, idx, sig, body in cur:
            body = (body or '')[:max_body]
            yield {'blob_oid': blob_oid, 'idx': idx, 'file': blob_file[blob_oid], 'sig': sig or '', 'body': body}

def func_text(rec: dict) -> str:
    body = rec['body'] or rec['sig']
    return (rec['file'] + ' ' + body).strip()

def cmd_encode(args):
    from accelerate import Accelerator
    from accelerate.utils import InitProcessGroupKwargs
    from datetime import timedelta
    import torch
    from transformers import AutoModel, AutoTokenizer
    pg_kwargs = InitProcessGroupKwargs(timeout=timedelta(hours=2))
    accelerator = Accelerator(kwargs_handlers=[pg_kwargs])
    rank = accelerator.process_index
    world = accelerator.num_processes
    is_main = accelerator.is_main_process
    apply_gpu_memory_cap(getattr(args, 'gpu_memory_fraction', None))
    out_dir = Path(args.cache_dir) / args.run_name
    out_dir.mkdir(parents=True, exist_ok=True)
    if is_main:
        print(f'[encode] run={args.run_name} model={args.model}', flush=True)
        print(f'[encode] world={world} rank={rank}', flush=True)
    model_path = args.checkpoint or args.model
    defaults = model_defaults(args.model)
    pooling = args.pooling or defaults['pooling']
    doc_prefix = args.doc_prefix if args.doc_prefix is not None else defaults['doc_prefix']
    if is_main:
        print(f'[encode] pooling={pooling}  doc_prefix={doc_prefix!r}', flush=True)
    tok = AutoTokenizer.from_pretrained(model_path, trust_remote_code=True)
    model = AutoModel.from_pretrained(model_path, trust_remote_code=True, torch_dtype=torch.float16, safe_serialization=True).to(accelerator.device).eval()
    dim = getattr(model.config, 'hidden_size', getattr(model.config, 'd_model', DEFAULT_DIM))
    train_ids, val_ids, test_ids = load_split_ids(args.split_dir)
    test_rps = collect_test_commits(args.input, test_ids)
    if is_main:
        print(f'[encode] {len(test_rps)} unique test commits', flush=True)
    funcs_cache = Path(args.cache_dir) / f'funcs_max{args.max_body}.pkl'
    import pickle
    if is_main:
        if funcs_cache.exists() and (not args.rebuild):
            print(f'[encode] reusing funcs cache → {funcs_cache}', flush=True)
            with funcs_cache.open('rb') as f:
                all_funcs = pickle.load(f)
            print(f'[encode] {len(all_funcs):,} unique funcs loaded from cache', flush=True)
        else:
            con = open_corpus_db(args.db)
            print(f'[encode] enumerating funcs on rank0 (this may take a few min)...', flush=True)
            all_funcs = list(fetch_funcs_for_commits(con, test_rps, args.max_body))
            print(f'[encode] {len(all_funcs):,} unique funcs to encode, dumping cache...', flush=True)
            funcs_cache.parent.mkdir(parents=True, exist_ok=True)
            tmp = funcs_cache.with_suffix('.pkl.tmp')
            with tmp.open('wb') as f:
                pickle.dump(all_funcs, f, protocol=4)
            tmp.replace(funcs_cache)
            print(f'[encode] funcs cached → {funcs_cache} ({funcs_cache.stat().st_size / 1000000000.0:.2f} GB)', flush=True)
    accelerator.wait_for_everyone()
    if not is_main:
        with funcs_cache.open('rb') as f:
            all_funcs = pickle.load(f)
    my_slice = all_funcs[rank::world]
    if is_main:
        print(f'[encode] rank0 slice = {len(my_slice):,} funcs (≈{len(my_slice) * world / 1000000.0:.1f}M total)', flush=True)
    shard_emb_path = out_dir / f'shard_{rank:03d}.npy'
    shard_idx_path = out_dir / f'shard_{rank:03d}.index.jsonl'
    if shard_emb_path.exists() and shard_idx_path.exists() and (not args.rebuild):
        if is_main:
            print(f'[encode] shard {rank} exists, skipping (use --rebuild to redo)', flush=True)
    else:
        slice_texts = [doc_prefix + func_text(r) for r in my_slice]
        order = sorted(range(len(my_slice)), key=lambda i: len(slice_texts[i]))
        inv_order = [0] * len(order)
        for new_pos, orig in enumerate(order):
            inv_order[orig] = new_pos
        embs = np.zeros((len(my_slice), dim), dtype=np.float16)
        bs = args.batch_size
        t0 = time.time()
        n_seen = 0
        with torch.no_grad():
            for i in range(0, len(order), bs):
                idx_batch = order[i:i + bs]
                texts = [slice_texts[j] for j in idx_batch]
                enc = tok(texts, padding=True, truncation=True, max_length=args.max_tokens, return_tensors='pt').to(accelerator.device)
                out = model(**enc)
                v = pool_embeddings(out.last_hidden_state, enc['attention_mask'], pooling)
                v = torch.nn.functional.normalize(v, dim=-1)
                v_np = v.cpu().numpy().astype(np.float16)
                for k, orig_pos in enumerate(idx_batch):
                    embs[orig_pos] = v_np[k]
                n_seen += len(idx_batch)
                if is_main and i // bs % 20 == 0:
                    el = time.time() - t0
                    rate = n_seen / max(1e-06, el)
                    eta = (len(order) - n_seen) / max(1e-06, rate) / 60
                    seq_len = enc['input_ids'].shape[1]
                    print(f'  [rank{rank}] {n_seen:>9,}/{len(my_slice):,} bs={len(idx_batch)} seq={seq_len}  rate {rate:.0f}/s eta {eta:.1f}min', flush=True)
        np.save(shard_emb_path, embs)
        with shard_idx_path.open('w') as f:
            for r in my_slice:
                f.write(json.dumps({'blob_oid': r['blob_oid'], 'idx': r['idx'], 'file': r['file'], 'sig': r['sig']}) + '\n')
        if is_main:
            print(f'[rank{rank}] shard saved ({time.time() - t0:.0f}s)', flush=True)
    accelerator.wait_for_everyone()
    if is_main:
        print(f'[encode] merging shards...', flush=True)
        all_embs = []
        all_idx = []
        for r in range(world):
            ep = out_dir / f'shard_{r:03d}.npy'
            ip = out_dir / f'shard_{r:03d}.index.jsonl'
            all_embs.append(np.load(ep, mmap_mode='r'))
            with ip.open() as f:
                for line in f:
                    all_idx.append(json.loads(line))
        merged = np.concatenate(all_embs, axis=0)
        emb_out = out_dir / 'embeddings.npy'
        idx_out = out_dir / 'embeddings.index.jsonl'
        np.save(emb_out, merged)
        with idx_out.open('w') as f:
            for r in all_idx:
                f.write(json.dumps(r) + '\n')
        manifest = {'model': args.model, 'checkpoint': args.checkpoint, 'pooling': pooling, 'query_prefix': defaults['query_prefix'], 'doc_prefix': doc_prefix, 'n_funcs': int(merged.shape[0]), 'dim': int(merged.shape[1]), 'max_tokens': args.max_tokens, 'max_body': args.max_body, 'test_commits': len(test_rps), 'world_size': world, 'created_at': int(time.time())}
        (out_dir / 'manifest.json').write_text(json.dumps(manifest, indent=2))
        print(f'[encode] DONE merged → {emb_out}  ({merged.shape})', flush=True)

def cmd_retrieve(args):
    from utils.dataset import load_records, filter_by_ids, get_input_text
    from utils.metrics import build_gt_index, full_evaluation_pipeline, save_metrics, print_overall
    apply_gpu_memory_cap(getattr(args, 'gpu_memory_fraction', None))
    out_dir = Path(args.cache_dir) / args.run_name
    if not (out_dir / 'embeddings.npy').exists():
        sys.exit(f"embeddings not found in {out_dir}, run 'encode' first")
    print(f"[retrieve] loading embeddings ({('mmap' if args.mmap else 'full RAM')})...", flush=True)
    t0 = time.time()
    embeddings = np.load(out_dir / 'embeddings.npy', mmap_mode='r' if args.mmap else None)
    print(f'[retrieve] {embeddings.shape} loaded ({embeddings.nbytes / 1000000000.0:.1f} GB) in {time.time() - t0:.0f}s', flush=True)
    blob_to_row: dict[tuple, int] = {}
    with (out_dir / 'embeddings.index.jsonl').open() as f:
        for row, line in enumerate(f):
            r = json.loads(line)
            blob_to_row[r['blob_oid'], r['idx']] = row
    print(f'[retrieve] index built: {len(blob_to_row):,} funcs', flush=True)
    import torch
    from transformers import AutoModel, AutoTokenizer
    manifest = json.loads((out_dir / 'manifest.json').read_text())
    if args.model:
        model_path = args.model
    elif manifest.get('checkpoint'):
        model_path = manifest['checkpoint']
    else:
        model_path = resolve_model_path(manifest['model'])
        if model_path != manifest['model']:
            print(f"[retrieve] manifest model '{manifest['model']}' not found locally — using '{model_path}' instead", flush=True)
    pooling = manifest.get('pooling') or model_defaults(manifest['model'])['pooling']
    query_prefix = args.query_prefix if args.query_prefix is not None else manifest.get('query_prefix') or model_defaults(manifest['model'])['query_prefix']
    print(f'[retrieve] model={model_path}  pooling={pooling}  query_prefix={query_prefix!r}', flush=True)
    tok = AutoTokenizer.from_pretrained(model_path, trust_remote_code=True)
    device = 'cuda' if torch.cuda.is_available() else 'cpu'
    model = AutoModel.from_pretrained(model_path, trust_remote_code=True, torch_dtype=torch.float16, safe_serialization=True).to(device).eval()
    print(f'[retrieve] query encoder ready on {device}', flush=True)

    @torch.no_grad()
    def encode_query(text: str) -> 'torch.Tensor':
        if '{q}' in query_prefix:
            full = query_prefix.format(q=text)
        else:
            full = query_prefix + text
        enc = tok([full], padding=True, truncation=True, max_length=args.max_tokens, return_tensors='pt').to(device)
        out = model(**enc)
        v = pool_embeddings(out.last_hidden_state, enc['attention_mask'], pooling)
        v = torch.nn.functional.normalize(v, dim=-1)
        return v[0]
    records = load_records(args.input)
    train_ids, val_ids, test_ids = load_split_ids(args.split_dir)
    test_records = filter_by_ids(records, test_ids)
    records_by_cve = {r['cve_id']: r for r in test_records}
    fields = [alias_to_field(a.strip()) for a in args.combos.split(',') if a.strip()]
    print(f'[retrieve] fields: {fields}', flush=True)
    con = open_corpus_db(args.db)
    EVAL_TARGETS = ['related', 'root_cause_vulnerable']
    TARGET_NAMES = {'related': 'related', 'root_cause_vulnerable': 'root_cause'}
    gt_index_related = build_gt_index(test_records, 'related', use_chained=True)
    from collections import defaultdict as _dd
    by_rp: dict[str, list[tuple]] = _dd(list)
    skipped = 0
    for (cve, commit), _ in gt_index_related.items():
        rp = root_parent_for_instance(records_by_cve, cve, commit)
        if not rp:
            skipped += 1
            continue
        by_rp[rp].append((cve, commit))
    print(f'[retrieve] {len(by_rp)} unique commits ({skipped} skipped)', flush=True)
    preds_per_field: dict[str, list] = {f: [] for f in fields}
    t0 = time.time()
    use_gpu_score = device == 'cuda'
    for n_done, (rp, instances) in enumerate(by_rp.items(), start=1):
        rows = list(con.execute('SELECT cf.blob_oid, f.idx, cf.file, f.sig FROM commit_files cf JOIN funcs f USING (blob_oid) WHERE cf.commit_id = ?', (rp,)))
        emb_rows = []
        meta = []
        for blob_oid, idx, fp, sig in rows:
            r = blob_to_row.get((blob_oid, idx))
            if r is not None:
                emb_rows.append(r)
                meta.append({'file': fp or '', 'sig': sig or ''})
        if not emb_rows:
            continue
        sorted_perm = sorted(range(len(emb_rows)), key=lambda i: emb_rows[i])
        emb_rows_sorted = [emb_rows[i] for i in sorted_perm]
        emb_subset_np = embeddings[emb_rows_sorted]
        if use_gpu_score:
            emb_subset = torch.from_numpy(emb_subset_np).to(device)
        for cve, commit in instances:
            rec = records_by_cve.get(cve)
            for field in fields:
                qtext = get_input_text(rec, field) or '' if rec else ''
                if not qtext.strip():
                    preds_per_field[field].append({'cve_id': cve, 'commit_id': commit, 'root_parent_id': rp, 'predicted_functions': []})
                    continue
                q = encode_query(qtext)
                if use_gpu_score:
                    q_t = q.to(emb_subset.dtype)
                    scores_t = emb_subset @ q_t
                    kk = min(args.top_k, scores_t.numel())
                    topk = torch.topk(scores_t, kk)
                    top_scores = topk.values.float().cpu().numpy()
                    top_idx_sorted = topk.indices.cpu().numpy()
                else:
                    q_np = q.float().cpu().numpy()
                    scores = emb_subset_np @ q_np
                    kk = min(args.top_k, scores.size)
                    top_idx_sorted = np.argpartition(scores, -kk)[-kk:]
                    top_idx_sorted = top_idx_sorted[np.argsort(scores[top_idx_sorted])[::-1]]
                    top_scores = scores[top_idx_sorted]
                top_idx = [sorted_perm[i] for i in top_idx_sorted]
                pred = [meta[i] for i, s in zip(top_idx, top_scores) if s > 0]
                preds_per_field[field].append({'cve_id': cve, 'commit_id': commit, 'root_parent_id': rp, 'method': 'coderankembed', 'test_field': field, 'predicted_functions': pred})
        if use_gpu_score:
            del emb_subset
        if n_done % 20 == 0 or n_done == len(by_rp):
            el = time.time() - t0
            rate = n_done / max(1e-06, el)
            eta = (len(by_rp) - n_done) / max(1e-06, rate) / 60
            print(f'  [retrieve] {n_done}/{len(by_rp)}  elapsed {el:.0f}s eta {eta:.1f}min', flush=True)
    for field in fields:
        plist = preds_per_field[field]
        alias = next((a for a, f in FIELD_ALIAS.items() if f == field), field)
        combo = f'{alias}2{alias}'
        for tgt in EVAL_TARGETS:
            tgt_short = TARGET_NAMES[tgt]
            pred_dir = Path(f'results/predictions/iii_b_coderankembed/{tgt_short}/{args.run_name}/{combo}')
            metrics_dir = Path(f'results/metrics/iii_b_coderankembed/{tgt_short}/{args.run_name}/{combo}')
            pred_dir.mkdir(parents=True, exist_ok=True)
            metrics_dir.mkdir(parents=True, exist_ok=True)
            with (pred_dir / 'predictions.jsonl').open('w') as f:
                for p in plist:
                    f.write(json.dumps(p, ensure_ascii=False) + '\n')
            gt_idx = build_gt_index(test_records, tgt, use_chained=True)
            res = full_evaluation_pipeline(plist, gt_idx, test_records)
            save_metrics(res['overall'], metrics_dir / 'overall.json')
            save_metrics(res.get('by_cwe', {}), metrics_dir / 'by_cwe.json')
            print_overall(res['overall'], f'iii_b_coderankembed/{tgt_short}/{args.run_name}/{combo}')

def cmd_train(args):
    import torch
    from accelerate import Accelerator
    from accelerate.utils import InitProcessGroupKwargs
    from datetime import timedelta
    from transformers import AutoModel, AutoTokenizer
    from torch.utils.data import Dataset, DataLoader
    pg_kwargs = InitProcessGroupKwargs(timeout=timedelta(hours=2))
    accelerator = Accelerator(kwargs_handlers=[pg_kwargs])
    is_main = accelerator.is_main_process
    apply_gpu_memory_cap(getattr(args, 'gpu_memory_fraction', None))
    from utils.dataset import load_records, filter_by_ids, get_input_text
    records = load_records(args.input)
    train_ids, val_ids, test_ids = load_split_ids(args.split_dir)
    train_recs = filter_by_ids(records, train_ids)
    val_recs = filter_by_ids(records, val_ids)
    if args.train_split == 'trainval':
        if is_main:
            print(f'[train] training on TRAIN+VAL combined ({len(train_ids)}+{len(val_ids)} CVEs); val_recs becomes empty → no val monitor', flush=True)
        train_recs = filter_by_ids(records, train_ids | val_ids)
        val_recs = []
    bm25_neg_pool: dict[tuple, list] = {}
    if args.bm25_pred_dir:
        bm25_path = Path(args.bm25_pred_dir) / 'predictions.jsonl'
        if bm25_path.exists():
            with bm25_path.open() as f:
                for line in f:
                    p = json.loads(line)
                    bm25_neg_pool[p['cve_id'], p['commit_id']] = p.get('predicted_functions', [])
            if is_main:
                print(f'[train] loaded BM25 hard-neg pool: {len(bm25_neg_pool)} instances', flush=True)
    con = open_corpus_db(args.db)
    import random as _random
    _rng = _random.Random(0)

    def collect_positives(recs):
        out = defaultdict(list)
        misses = 0
        for r in recs:
            cve = r['cve_id']
            for ch in r.get('src_commits_chained') or []:
                rp = (ch.get('root_parent_id') or '').strip()
                if not rp:
                    continue
                commit_leaf = (ch.get('commit_ids') or [None])[-1]
                for d in ch.get('diffs') or []:
                    fname = d.get('filename')
                    df = d.get('diff_funcs') or {}
                    for cat in ('modified', 'removed'):
                        for fn in df.get(cat) or []:
                            if fn.get('classification') not in ('root_cause_vulnerable', 'supporting_fix'):
                                continue
                            sig = fn.get('sig')
                            if not sig or not fname:
                                continue
                            row = con.execute('SELECT f.body FROM commit_files cf JOIN funcs f USING (blob_oid) WHERE cf.commit_id=? AND cf.file=? AND f.sig=? LIMIT 1', (rp, fname, sig)).fetchone()
                            if row is None:
                                misses += 1
                                continue
                            body = (row[0] or sig)[:args.max_body]
                            text = (fname + ' ' + body).strip()
                            out[cve].append((commit_leaf, rp, fname, sig, text))
        return (out, misses)
    train_positives, train_miss = collect_positives(train_recs)
    val_positives, val_miss = collect_positives(val_recs) if val_recs else ({}, 0)
    if is_main:
        print(f'[train] positives: train {sum((len(v) for v in train_positives.values())):,} ({train_miss} GT not in DB)  val {sum((len(v) for v in val_positives.values())):,}', flush=True)
    cve_neighbors: dict[str, list[tuple[str, float]]] = {}
    if args.cross_cve_negs > 0:
        if is_main:
            print(f'[train] computing cross-CVE neighbor index (zero-shot encoder over {len(train_positives)} train queries)...', flush=True)
        from transformers import AutoModel, AutoTokenizer
        zs_tok = AutoTokenizer.from_pretrained(args.base_model, trust_remote_code=True)
        zs_model = AutoModel.from_pretrained(args.base_model, trust_remote_code=True, torch_dtype=torch.float16, safe_serialization=True).to(accelerator.device).eval()
        zs_defaults = model_defaults(args.base_model)
        zs_pooling, zs_qprefix = (zs_defaults['pooling'], zs_defaults['query_prefix'])
        cves_list = sorted(train_positives.keys())
        cve_to_query: dict[str, str] = {}
        for r in train_recs:
            if r['cve_id'] in train_positives:
                qt = get_input_text(r, args.train_field) or ''
                if qt.strip():
                    cve_to_query[r['cve_id']] = qt
        cves_with_q = [c for c in cves_list if c in cve_to_query]
        embs = []
        bs = 16
        with torch.no_grad():
            for i in range(0, len(cves_with_q), bs):
                batch = cves_with_q[i:i + bs]
                texts = [zs_qprefix.format(q=cve_to_query[c]) if '{q}' in zs_qprefix else zs_qprefix + cve_to_query[c] for c in batch]
                enc = zs_tok(texts, padding=True, truncation=True, max_length=args.max_tokens, return_tensors='pt').to(accelerator.device)
                out = zs_model(**enc)
                v = pool_embeddings(out.last_hidden_state, enc['attention_mask'], zs_pooling)
                v = torch.nn.functional.normalize(v, dim=-1)
                embs.append(v.cpu().float().numpy())
        embs = np.concatenate(embs, axis=0)
        sim = embs @ embs.T
        np.fill_diagonal(sim, -1.0)
        for i, cve in enumerate(cves_with_q):
            top_idx = np.argsort(-sim[i])[:args.cross_cve_pool_size]
            cve_neighbors[cve] = [(cves_with_q[j], float(sim[i][j])) for j in top_idx]
        del zs_model, zs_tok
        torch.cuda.empty_cache()
        if is_main:
            print(f'[train] cve_neighbors built: {len(cve_neighbors)} entries; avg-top-1 sim = {np.mean([cve_neighbors[c][0][1] for c in cve_neighbors]):.3f}', flush=True)

    def build_pairs(recs: list[dict], positives_map: dict, label: str) -> list[tuple]:
        K_total = args.hard_negs_per_pos
        K_sf = min(args.same_file_negs, K_total)
        K_cc = min(args.cross_cve_negs, K_total - K_sf)
        K_bm25 = max(0, K_total - K_sf - K_cc)
        if is_main:
            print(f'[train] {label} neg mix: same_file={K_sf}  cross_cve={K_cc}  bm25={K_bm25}', flush=True)
        out, missed_pos = ([], 0)
        n_sf_actual = n_cc_actual = n_bm25_actual = 0
        for r in recs:
            cve = r['cve_id']
            q_text = get_input_text(r, args.train_field) or ''
            if not q_text.strip():
                continue
            record_gt = {(fname, sig) for _, _, fname, sig, _ in positives_map.get(cve, [])}
            for commit_leaf, rp, fname, sig, pos_text in positives_map.get(cve, []):
                negs: list[str] = []
                if K_sf > 0:
                    sf_rows = con.execute('SELECT f.sig, f.body FROM commit_files cf JOIN funcs f USING (blob_oid) WHERE cf.commit_id=? AND cf.file=?', (rp, fname)).fetchall()
                    sf_pool = [(s, b) for s, b in sf_rows if s and (fname, s) not in record_gt]
                    _rng.shuffle(sf_pool)
                    for s, b in sf_pool[:K_sf]:
                        body = (b or s)[:args.max_body]
                        negs.append((fname + ' ' + body).strip())
                    n_sf_actual += min(len(sf_pool), K_sf)
                if K_cc > 0 and cve in cve_neighbors:
                    cc_added = 0
                    for nb_cve, score in cve_neighbors[cve]:
                        if score < args.cross_cve_min_sim:
                            break
                        for _, _, nb_file, nb_sig, nb_text in train_positives.get(nb_cve, []):
                            if (nb_file, nb_sig) in record_gt:
                                continue
                            negs.append(nb_text)
                            cc_added += 1
                            if cc_added >= K_cc:
                                break
                        if cc_added >= K_cc:
                            break
                    n_cc_actual += cc_added
                if K_bm25 > 0:
                    pool = bm25_neg_pool.get((cve, commit_leaf), [])
                    bm25_added = 0
                    for nf in pool:
                        nf_file, nf_sig = (nf.get('file') or '', nf.get('sig') or '')
                        if (nf_file, nf_sig) in record_gt:
                            continue
                        nrow = con.execute('SELECT f.body FROM commit_files cf JOIN funcs f USING (blob_oid) WHERE cf.commit_id=? AND cf.file=? AND f.sig=? LIMIT 1', (rp, nf_file, nf_sig)).fetchone()
                        if nrow is None:
                            continue
                        nbody = (nrow[0] or nf_sig)[:args.max_body]
                        negs.append((nf_file + ' ' + nbody).strip())
                        bm25_added += 1
                        if bm25_added >= K_bm25:
                            break
                    n_bm25_actual += bm25_added
                out.append((q_text, pos_text, negs))
        if is_main:
            n = max(1, len(out))
            print(f'[train] {label}: {len(out):,} pairs  avg negs/pos: same_file={n_sf_actual / n:.1f}  cross_cve={n_cc_actual / n:.1f}  bm25={n_bm25_actual / n:.1f}', flush=True)
        return out
    pairs = build_pairs(train_recs, train_positives, 'train')
    val_pairs = build_pairs(val_recs, val_positives, 'val') if val_recs else []
    cap_neg = args.hard_negs_per_pos
    defaults = model_defaults(args.base_model)
    pooling = defaults['pooling']
    query_prefix = defaults['query_prefix']
    doc_prefix = defaults['doc_prefix']
    if is_main:
        print(f'[train] pooling={pooling}  query_prefix={query_prefix!r}  doc_prefix={doc_prefix!r}', flush=True)
    tok = AutoTokenizer.from_pretrained(args.base_model, trust_remote_code=True)
    model = AutoModel.from_pretrained(args.base_model, trust_remote_code=True, torch_dtype=torch.float32, safe_serialization=True).to(accelerator.device)
    model.train()

    class TripletDataset(Dataset):

        def __init__(self, pairs):
            self.pairs = pairs

        def __len__(self):
            return len(self.pairs)

        def __getitem__(self, i):
            return self.pairs[i]

    def collate(batch):
        qs, ps, neg_lists = zip(*batch)
        K = cap_neg
        all_negs = []
        for negs in neg_lists:
            negs = list(negs[:K])
            while len(negs) < K:
                negs.append('')
            all_negs.extend(negs)
        return (list(qs), list(ps), all_negs)
    dl = DataLoader(TripletDataset(pairs), batch_size=args.batch_size, shuffle=True, collate_fn=collate, drop_last=True)
    val_dl = DataLoader(TripletDataset(val_pairs), batch_size=args.batch_size, shuffle=False, collate_fn=collate, drop_last=False) if val_pairs else None
    opt = torch.optim.AdamW(model.parameters(), lr=args.lr)
    if val_dl is not None:
        model, opt, dl, val_dl = accelerator.prepare(model, opt, dl, val_dl)
    else:
        model, opt, dl = accelerator.prepare(model, opt, dl)

    def encode(texts):
        enc = tok(texts, padding=True, truncation=True, max_length=args.max_tokens, return_tensors='pt').to(accelerator.device)
        out = model(**enc)
        v = pool_embeddings(out.last_hidden_state, enc['attention_mask'], pooling)
        return torch.nn.functional.normalize(v, dim=-1)

    def encode_q(qs):
        if '{q}' in query_prefix:
            return encode([query_prefix.format(q=q) for q in qs])
        return encode([query_prefix + q for q in qs])

    def encode_d(ds):
        return encode([doc_prefix + d for d in ds])

    def contrastive_loss(qs, ps, negs):
        B = len(qs)
        q_emb = encode_q(list(qs))
        pos_emb = encode_d(list(ps))
        neg_emb = encode_d(list(negs))
        neg_emb = neg_emb.view(B, cap_neg, -1)
        pos_scores = (q_emb * pos_emb).sum(-1, keepdim=True)
        hard_scores = (q_emb.unsqueeze(1) * neg_emb).sum(-1)
        inbatch = q_emb @ pos_emb.t()
        inbatch.fill_diagonal_(-1000000000.0)
        logits = torch.cat([pos_scores, hard_scores, inbatch], dim=1) / args.temperature
        labels = torch.zeros(B, dtype=torch.long, device=logits.device)
        return torch.nn.functional.cross_entropy(logits, labels)

    @torch.no_grad()
    def eval_val_loss() -> float:
        if val_dl is None:
            return float('nan')
        model.eval()
        total, n_batches = (0.0, 0)
        for qs, ps, negs in val_dl:
            loss = contrastive_loss(qs, ps, negs)
            total += loss.item()
            n_batches += 1
        model.train()
        return total / max(1, n_batches)
    ckpt_root = Path(args.cache_dir) / args.run_name
    best_val_loss = float('inf')
    best_epoch = -1
    history = []
    for epoch in range(args.epochs):
        t0 = time.time()
        for step, (qs, ps, negs) in enumerate(dl):
            loss = contrastive_loss(qs, ps, negs)
            accelerator.backward(loss)
            opt.step()
            opt.zero_grad()
            if is_main and step % 20 == 0:
                el = time.time() - t0
                print(f'  [epoch {epoch} step {step}/{len(dl)}] loss={loss.item():.4f}  elapsed {el:.0f}s', flush=True)
        train_secs = time.time() - t0
        val_loss = eval_val_loss()
        if is_main:
            print(f'[epoch {epoch}] done in {train_secs:.0f}s  val_loss={val_loss:.4f}', flush=True)
            history.append({'epoch': epoch, 'train_secs': round(train_secs, 1), 'val_loss': None if val_loss != val_loss else val_loss})
            epoch_dir = ckpt_root / f'checkpoint_epoch{epoch}'
            epoch_dir.mkdir(parents=True, exist_ok=True)
            accelerator.unwrap_model(model).save_pretrained(epoch_dir)
            tok.save_pretrained(epoch_dir)
            if val_dl is not None and val_loss < best_val_loss:
                best_val_loss = val_loss
                best_epoch = epoch
                best_dir = ckpt_root / 'checkpoint_best'
                best_dir.mkdir(parents=True, exist_ok=True)
                accelerator.unwrap_model(model).save_pretrained(best_dir)
                tok.save_pretrained(best_dir)
                print(f'[epoch {epoch}] ★ new best val_loss={val_loss:.4f}, saved → {best_dir}', flush=True)
    if is_main:
        final_dir = ckpt_root / 'checkpoint_final'
        final_dir.mkdir(parents=True, exist_ok=True)
        accelerator.unwrap_model(model).save_pretrained(final_dir)
        tok.save_pretrained(final_dir)
        canonical = ckpt_root / 'checkpoint'
        if canonical.exists() or canonical.is_symlink():
            canonical.unlink()
        target = 'checkpoint_best' if val_dl is not None and best_epoch >= 0 else 'checkpoint_final'
        canonical.symlink_to(target)
        history_path = ckpt_root / 'train_history.json'
        history_path.write_text(json.dumps({'history': history, 'best_epoch': best_epoch, 'best_val_loss': None if best_val_loss == float('inf') else best_val_loss, 'canonical_ckpt': str(canonical), 'points_to': target}, indent=2))
        print(f'[train] final → {final_dir}', flush=True)
        if val_dl is not None and best_epoch >= 0:
            print(f'[train] BEST = epoch {best_epoch} (val_loss={best_val_loss:.4f}) → {ckpt_root}/checkpoint_best', flush=True)
        print(f'[train] canonical ckpt symlink: {canonical} → {target}', flush=True)

def parse_args():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest='cmd', required=True)

    def common(p):
        p.add_argument('--input', required=True, help='CVE dataset JSONL')
        p.add_argument('--db', required=True, help='Function-corpus SQLite db')
        p.add_argument('--split-dir', required=True, help='Dir with train/val/test id files')
        p.add_argument('--cache-dir', required=True, help='Dir for embeddings/manifests')
        p.add_argument('--run-name', required=True, help='Run identifier')
        p.add_argument('--max-tokens', type=int, default=256, help='Encoder token cap')
        p.add_argument('--max-body', type=int, default=2000, help='Char cap on body before tokenization')
        p.add_argument('--gpu-memory-fraction', type=float, default=None, help='Cap per-process GPU memory fraction (0..1)')
    pe = sub.add_parser('encode', help='Phase A/D: encode test corpus')
    common(pe)
    pe.add_argument('--model', default=DEFAULT_MODEL, help='Encoder model id')
    pe.add_argument('--checkpoint', default=None, help='Local trained checkpoint dir (overrides --model)')
    pe.add_argument('--batch-size', type=int, default=512, help='Encoder batch size')
    pe.add_argument('--rebuild', action='store_true')
    pe.add_argument('--pooling', default=None, choices=[None, 'cls', 'mean', 'last_token'], help='Override per-model pooling')
    pe.add_argument('--doc-prefix', default=None, help='Override per-model doc-side prefix')
    pe.set_defaults(func=cmd_encode)
    pr = sub.add_parser('retrieve', help='Phase B/E: retrieve & metrics')
    common(pr)
    pr.add_argument('--combos', default='pre,post', help='Comma-list of test-field aliases (pre/post/raw)')
    pr.add_argument('--top-k', type=int, default=10, help='Predictions kept per instance')
    pr.add_argument('--query-prefix', default=None, help="Override the manifest's query-side prefix")
    pr.add_argument('--model', default=None, help='Override the model path/id from manifest')
    pr.add_argument('--mmap', action='store_true', help='Memory-map the embedding matrix instead of loading into RAM')
    pr.set_defaults(func=cmd_retrieve)
    pt = sub.add_parser('train', help='Phase C: contrastive fine-tune')
    common(pt)
    pt.add_argument('--base-model', default=DEFAULT_MODEL, help='Base encoder to fine-tune')
    pt.add_argument('--bm25-pred-dir', default=None, help='Source for BM25 hard negatives')
    pt.add_argument('--train-field', default='issue_summary', help='CVE text field used as the query during train')
    pt.add_argument('--train-split', default='train', choices=['train', 'trainval'], help='train = train+val-monitor; trainval = combine both')
    pt.add_argument('--hard-negs-per-pos', type=int, default=10, help='Total hard-negs per positive')
    pt.add_argument('--same-file-negs', type=int, default=0, help='Hard-negs sampled from same-file funcs')
    pt.add_argument('--cross-cve-negs', type=int, default=0, help='Hard-negs sampled from similar CVEs')
    pt.add_argument('--cross-cve-pool-size', type=int, default=20, help='Top-K similar CVEs as cross-CVE neg sources')
    pt.add_argument('--cross-cve-min-sim', type=float, default=0.3, help='Cosine threshold for cross-CVE negs')
    pt.add_argument('--epochs', type=int, default=3, help='Training epochs')
    pt.add_argument('--batch-size', type=int, default=32, help='Training batch size')
    pt.add_argument('--lr', type=float, default=2e-05, help='Learning rate')
    pt.add_argument('--temperature', type=float, default=0.05, help='Contrastive temperature')
    pt.set_defaults(func=cmd_train)
    return ap.parse_args()
if __name__ == '__main__':
    args = parse_args()
    args.func(args)
