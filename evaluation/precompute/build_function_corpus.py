#!/usr/bin/env python3
from __future__ import annotations
import argparse
import json
import multiprocessing as mp
import os
import sqlite3
import subprocess
import sys
import threading
import time
from pathlib import Path
from queue import Queue, Empty
from typing import Any
CPP_EXTS = {'.cc', '.cpp', '.cxx', '.cu', '.c', '.m', '.mm'}
HDR_EXTS = {'.h', '.hpp', '.hxx', '.cuh', '.inc'}
ALL_EXTS = CPP_EXTS | HDR_EXTS
_W_CPP = None
_W_GIT_PROC = None
_W_REPO = None
_S2_REPO = None
_S2_SKIP_PREFIXES: tuple[str, ...] = ()

def _worker_init(repo_path: str) -> None:
    global _W_REPO
    _W_REPO = repo_path

def _ls_tree_for_commit(repo: str, commit: str, skip_prefixes: tuple[str, ...]):
    try:
        out = subprocess.run(['git', 'ls-tree', '-r', commit], cwd=repo, capture_output=True, text=True, check=True, timeout=120).stdout
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return None
    rows = []
    for ln in out.splitlines():
        parts = ln.split('\t', 1)
        if len(parts) != 2:
            continue
        meta, path = parts
        mode_type_oid = meta.split()
        if len(mode_type_oid) != 3:
            continue
        _mode, _type, oid = mode_type_oid
        ext = os.path.splitext(path)[1].lower()
        if ext not in ALL_EXTS:
            continue
        if any((path.startswith(p) for p in skip_prefixes)):
            continue
        rows.append((commit, path, oid, lang_for_path(path)))
    return rows

def _s2_worker_init(repo_path: str, skip_prefixes: tuple[str, ...]) -> None:
    global _S2_REPO, _S2_SKIP_PREFIXES
    _S2_REPO = repo_path
    _S2_SKIP_PREFIXES = tuple(skip_prefixes)

def _s2_worker_call(commit: str):
    rows = _ls_tree_for_commit(_S2_REPO, commit, _S2_SKIP_PREFIXES)
    return (commit, rows)

def _worker_cpp_parser():
    global _W_CPP
    if _W_CPP is None:
        proj_root = str(Path(__file__).resolve().parents[1])
        if proj_root not in sys.path:
            sys.path.insert(0, proj_root)
        from utils import cpp_parser
        _W_CPP = cpp_parser
    return _W_CPP

def _worker_git_proc():
    global _W_GIT_PROC
    if _W_GIT_PROC is None or _W_GIT_PROC.poll() is not None:
        _W_GIT_PROC = subprocess.Popen(['git', 'cat-file', '--batch'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, cwd=_W_REPO, bufsize=0)
    return _W_GIT_PROC

def _read_blob(oid: str) -> bytes | None:
    proc = _worker_git_proc()
    proc.stdin.write((oid + '\n').encode())
    proc.stdin.flush()
    header = proc.stdout.readline()
    if not header:
        return None
    h = header.decode('ascii', errors='replace').strip()
    if 'missing' in h:
        return None
    parts = h.split()
    if len(parts) != 3:
        return None
    _h_oid, _h_type, h_size = parts
    n = int(h_size)
    blob = b''
    while len(blob) < n:
        chunk = proc.stdout.read(n - len(blob))
        if not chunk:
            break
        blob += chunk
    proc.stdout.read(1)
    return blob

def _extract_funcs_from_blob(blob: bytes) -> list[dict[str, Any]]:
    cpp = _worker_cpp_parser()
    try:
        code_str = blob.decode('utf-8', errors='ignore')
        clean_str = cpp.preprocess_preproc_conditionals(cpp.preprocess_code(code_str))
        clean_bytes = clean_str.encode('utf-8')
        nodes = cpp.extract_functions_from_code(clean_bytes)
    except Exception:
        return []
    out: list[dict[str, Any]] = []
    for node in nodes:
        try:
            sig = cpp.get_function_signature(node, clean_bytes)
        except Exception:
            sig = None
        if not sig:
            continue
        sig = sig.replace('::', '.')
        try:
            if node.type == 'function_definition':
                body_node = node.child_by_field_name('body')
                end = body_node.end_byte if body_node else node.end_byte
                body_bytes = clean_bytes[node.start_byte:end]
            elif node.type == 'ERROR':
                body_node = cpp.find_first_compound_statement(node, skip_nested_function_defs=True)
                if body_node:
                    body_bytes = clean_bytes[node.start_byte:body_node.end_byte]
                else:
                    body_bytes = clean_bytes[node.start_byte:node.end_byte]
            else:
                body_bytes = clean_bytes[node.start_byte:node.end_byte]
            body = body_bytes.decode('utf-8', errors='replace')
        except Exception:
            body = ''
        line_start = clean_bytes.count(b'\n', 0, node.start_byte) + 1
        line_end = clean_bytes.count(b'\n', 0, node.end_byte) + 1
        out.append({'sig': sig, 'body': body, 'line_start': line_start, 'line_end': line_end})
    return out

def worker_process_oids(oids: list[str]) -> list[tuple[str, list[dict[str, Any]]]]:
    results = []
    for oid in oids:
        blob = _read_blob(oid)
        if blob is None:
            results.append((oid, []))
            continue
        funcs = _extract_funcs_from_blob(blob)
        results.append((oid, funcs))
    return results

def open_db(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path), timeout=60.0)
    conn.execute('PRAGMA journal_mode=WAL')
    conn.execute('PRAGMA synchronous=NORMAL')
    conn.executescript('\n        CREATE TABLE IF NOT EXISTS blobs (\n            blob_oid TEXT PRIMARY KEY,\n            n_funcs  INTEGER NOT NULL\n        );\n        CREATE TABLE IF NOT EXISTS funcs (\n            blob_oid   TEXT    NOT NULL,\n            idx        INTEGER NOT NULL,\n            sig        TEXT,\n            body       TEXT,\n            line_start INTEGER,\n            line_end   INTEGER,\n            PRIMARY KEY (blob_oid, idx)\n        );\n        CREATE INDEX IF NOT EXISTS idx_funcs_blob ON funcs(blob_oid);\n        CREATE TABLE IF NOT EXISTS commit_files (\n            commit_id TEXT NOT NULL,\n            file      TEXT NOT NULL,\n            blob_oid  TEXT NOT NULL,\n            lang      TEXT,\n            PRIMARY KEY (commit_id, file)\n        );\n        CREATE INDEX IF NOT EXISTS idx_cf_commit ON commit_files(commit_id);\n        CREATE INDEX IF NOT EXISTS idx_cf_blob   ON commit_files(blob_oid);\n        CREATE TABLE IF NOT EXISTS manifest (\n            commit_id    TEXT PRIMARY KEY,\n            n_files      INTEGER,\n            n_funcs      INTEGER,\n            generated_at INTEGER\n        );\n    ')
    conn.commit()
    return conn

def collect_target_commits(input_jsonl: Path, split_dir: Path, split: str) -> list[str]:
    selected_cves: set[str] | None = None
    if split != 'all':
        sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
        from utils.dataset import load_split_ids
        train_ids, val_ids, test_ids = load_split_ids(str(split_dir))
        if split == 'train':
            selected_cves = train_ids
        elif split == 'val':
            selected_cves = val_ids
        elif split == 'test':
            selected_cves = test_ids
        elif split == 'trainval':
            selected_cves = train_ids | val_ids
        else:
            sys.exit(f'unknown --split: {split}')
    commits: set[str] = set()
    with input_jsonl.open() as f:
        for line in f:
            r = json.loads(line)
            cve = r.get('cve_id') or r.get('id') or ''
            if selected_cves is not None and cve not in selected_cves:
                continue
            for ch in r.get('src_commits_chained') or []:
                rp = (ch.get('root_parent_id') or '').strip()
                if rp:
                    commits.add(rp)
    return sorted(commits)

def lang_for_path(path: str) -> str:
    ext = os.path.splitext(path)[1].lower()
    if ext in HDR_EXTS:
        return 'cpp_hdr'
    if ext == '.c':
        return 'c'
    return 'cpp'

def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--input', default='data/chromium_cve_data.jsonl')
    ap.add_argument('--split-dir', default='data/splits')
    ap.add_argument('--split', default='all', choices=['all', 'train', 'val', 'test', 'trainval'])
    ap.add_argument('--repo', default='chromium')
    ap.add_argument('--db', default='cache/function_corpus.db')
    ap.add_argument('--workers', type=int, default=16)
    ap.add_argument('--skip-paths', type=str, default='third_party/llvm-build,third_party/rust,third_party/boringssl,third_party/catapult,third_party/depot_tools,third_party/devtools-frontend,third_party/sqlite,third_party/test_fonts,third_party/icu,third_party/abseil-cpp', help="Comma-separated path prefixes to skip (third_party trees we don't care about)")
    ap.add_argument('--max-commits', type=int, default=0, help='Cap commits processed (0 = no cap; for smoke tests)')
    ap.add_argument('--blob-batch-size', type=int, default=64, help='OIDs per worker task')
    ap.add_argument('--s2-flush-every', type=int, default=50, help='Stage 2: flush commit_files rows to DB every N commits (keeps RAM bounded; default 50)')
    ap.add_argument('--s2-workers', type=int, default=1, help='Stage 2: parallelize git ls-tree across N processes (default 1 = sequential; ~150 MB RAM per worker)')
    ap.add_argument('--stage3-chunk-size', type=int, default=100000, help='Stage 3/4: stream pending OIDs in chunks of this size (keeps RAM bounded; default 100k → ~10 MB per chunk)')
    return ap.parse_args()

def main() -> None:
    args = parse_args()
    if not Path(args.repo).is_dir():
        sys.exit(f'repo not found: {args.repo}')
    skip_prefixes = tuple((p.strip() for p in args.skip_paths.split(',') if p.strip()))
    print(f'[init] repo={args.repo}')
    print(f'[init] db={args.db}')
    print(f'[init] split={args.split}  workers={args.workers}')
    print(f'[init] skipping {len(skip_prefixes)} third_party prefixes')
    db = open_db(Path(args.db))
    t0 = time.time()
    commits = collect_target_commits(Path(args.input), Path(args.split_dir), args.split)
    print(f'[stage1] {len(commits):,} unique chain.root_parent commits ({time.time() - t0:.1f}s)')
    done = {row[0] for row in db.execute('SELECT commit_id FROM manifest').fetchall()}
    pending_commits = [c for c in commits if c not in done]
    print(f'[stage1] {len(done):,} already done in DB; {len(pending_commits):,} pending')
    if args.max_commits > 0:
        pending_commits = pending_commits[:args.max_commits]
        print(f'[stage1] capped to --max-commits {args.max_commits}')
    if not pending_commits:
        print('[done] nothing to process')
        return
    s2_flush_every = max(1, args.s2_flush_every)
    s2_workers = max(1, args.s2_workers)
    print(f'[stage2] running git ls-tree on {len(pending_commits):,} commits ({s2_workers} workers, flush every {s2_flush_every} commits)...')
    t0 = time.time()
    n_rows_total = 0

    def _flush_commit_files(buf):
        nonlocal n_rows_total
        if not buf:
            return
        db.executemany('INSERT OR REPLACE INTO commit_files (commit_id, file, blob_oid, lang) VALUES (?, ?, ?, ?)', buf)
        db.commit()
        n_rows_total += len(buf)
        buf.clear()
    chunk_buf: list[tuple[str, str, str, str]] = []
    if s2_workers == 1:
        for i, commit in enumerate(pending_commits, start=1):
            rows = _ls_tree_for_commit(args.repo, commit, skip_prefixes)
            if rows is None:
                print(f'  WARN: ls-tree failed for {commit[:10]}, skipping')
                continue
            chunk_buf.extend(rows)
            if i % s2_flush_every == 0:
                _flush_commit_files(chunk_buf)
                print(f'  ls-tree {i}/{len(pending_commits)}  rows={n_rows_total:,}  ({time.time() - t0:.1f}s)', flush=True)
    else:
        i = 0
        with mp.Pool(s2_workers, initializer=_s2_worker_init, initargs=(args.repo, skip_prefixes)) as pool:
            for commit, rows in pool.imap_unordered(_s2_worker_call, pending_commits, chunksize=4):
                i += 1
                if rows is None:
                    print(f'  WARN: ls-tree failed for {commit[:10]}, skipping')
                else:
                    chunk_buf.extend(rows)
                if i % s2_flush_every == 0:
                    _flush_commit_files(chunk_buf)
                    print(f'  ls-tree {i}/{len(pending_commits)}  rows={n_rows_total:,}  ({time.time() - t0:.1f}s)', flush=True)
    _flush_commit_files(chunk_buf)
    print(f'[stage2] done — {n_rows_total:,} (commit, file) rows  ({time.time() - t0:.1f}s)')
    t0 = time.time()
    print(f'[stage3] counting pending blob OIDs...')
    n_pending = db.execute('\n        SELECT COUNT(*) FROM (\n            SELECT DISTINCT cf.blob_oid\n            FROM commit_files cf\n            LEFT JOIN blobs b ON b.blob_oid = cf.blob_oid\n            WHERE b.blob_oid IS NULL\n        )\n    ').fetchone()[0]
    print(f'[stage3] {n_pending:,} blob OIDs need parsing  ({time.time() - t0:.1f}s)')
    if n_pending:
        n_workers = max(1, args.workers)
        bs = args.blob_batch_size
        chunk_size = max(bs, args.stage3_chunk_size)
        FLUSH_EVERY = 50
        print(f'[stage4] parsing in {n_workers} workers, {n_pending:,} OIDs, streaming in chunks of {chunk_size:,}, worker-batch={bs}, flush every {FLUSH_EVERY} batches')
        n_blobs_done = 0
        n_funcs_total = 0
        t0_s4 = time.time()
        batch_funcs: list[tuple] = []
        batch_blobs: list[tuple] = []

        def flush():
            if not batch_blobs:
                return
            db.executemany('INSERT OR REPLACE INTO blobs (blob_oid, n_funcs) VALUES (?, ?)', batch_blobs)
            db.executemany('INSERT OR REPLACE INTO funcs (blob_oid, idx, sig, body, line_start, line_end) VALUES (?, ?, ?, ?, ?, ?)', batch_funcs)
            db.commit()
            batch_blobs.clear()
            batch_funcs.clear()
        read_conn = sqlite3.connect(str(Path(args.db)), timeout=60.0, uri=False, check_same_thread=False)
        read_conn.execute('PRAGMA journal_mode=WAL')
        read_conn.execute('PRAGMA query_only=ON')
        oid_cursor = read_conn.execute('\n            SELECT DISTINCT cf.blob_oid\n            FROM commit_files cf\n            LEFT JOIN blobs b ON b.blob_oid = cf.blob_oid\n            WHERE b.blob_oid IS NULL\n        ')

        def next_chunk():
            out = []
            for _ in range(chunk_size):
                row = oid_cursor.fetchone()
                if row is None:
                    break
                out.append(row[0])
            return out
        with mp.Pool(n_workers, initializer=_worker_init, initargs=(args.repo,)) as pool:
            done_batches = 0
            while True:
                chunk = next_chunk()
                if not chunk:
                    break
                batches = [chunk[i:i + bs] for i in range(0, len(chunk), bs)]
                for batch_results in pool.imap_unordered(worker_process_oids, batches):
                    for oid, funcs in batch_results:
                        batch_blobs.append((oid, len(funcs)))
                        for idx, fn in enumerate(funcs):
                            batch_funcs.append((oid, idx, fn['sig'], fn['body'], fn['line_start'], fn['line_end']))
                        n_blobs_done += 1
                        n_funcs_total += len(funcs)
                    done_batches += 1
                    if done_batches % FLUSH_EVERY == 0:
                        flush()
                        elapsed = time.time() - t0_s4
                        rate = n_blobs_done / max(1e-06, elapsed)
                        eta = (n_pending - n_blobs_done) / max(1e-06, rate) / 60
                        print(f'  [stage4] {n_blobs_done:,}/{n_pending:,} blobs, {n_funcs_total:,} funcs  rate={rate:.1f}/s  eta={eta:.1f}min', flush=True)
                flush()
            flush()
        read_conn.close()
        print(f'[stage4] done: {n_blobs_done:,} blobs, {n_funcs_total:,} funcs in {time.time() - t0_s4:.1f}s')
    t0 = time.time()
    print(f'[stage5] writing manifest for {len(pending_commits):,} commits...')
    now = int(time.time())
    rows = []
    for commit in pending_commits:
        n_files = db.execute('SELECT COUNT(*) FROM commit_files WHERE commit_id=?', (commit,)).fetchone()[0]
        n_funcs = db.execute('SELECT COALESCE(SUM(b.n_funcs), 0) FROM (SELECT DISTINCT blob_oid FROM commit_files WHERE commit_id=?) cf JOIN blobs b USING (blob_oid)', (commit,)).fetchone()[0]
        rows.append((commit, n_files, n_funcs, now))
    db.executemany('INSERT OR REPLACE INTO manifest (commit_id, n_files, n_funcs, generated_at) VALUES (?, ?, ?, ?)', rows)
    db.commit()
    print(f'[stage5] done ({time.time() - t0:.1f}s)')
    cur = db.execute('SELECT COUNT(*), SUM(n_files), SUM(n_funcs) FROM manifest')
    n_commits, total_files, total_funcs = cur.fetchone()
    cur = db.execute('SELECT COUNT(*), SUM(n_funcs) FROM blobs')
    n_blobs, dedup_funcs = cur.fetchone()
    print()
    print('=== overall corpus ===')
    print(f'  commits in manifest:       {n_commits:,}')
    print(f'  total (commit, file) rows: {total_files:,}')
    print(f'  total funcs (per-commit):  {total_funcs:,}')
    print(f'  unique blobs:              {n_blobs:,}')
    print(f'  unique funcs (post-dedup): {dedup_funcs:,}')
    print(f'  dedup ratio:               {total_funcs / max(1, dedup_funcs):.1f}x')
    print(f'  db size: {Path(args.db).stat().st_size / 1000000000.0:.2f} GB')
if __name__ == '__main__':
    main()
