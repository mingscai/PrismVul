#!/usr/bin/env python3
import argparse
import json
import os
import posixpath
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any
from tqdm import tqdm
ALLOWED_EXTENSIONS = {'.c', '.cc', '.cpp', '.h'}
SUCCESS_STATUSES = {'downloaded', 'exists', 'empty_placeholder'}
RETRY_STATUSES = {'failed', 'not_found', None}

def normalize_rel_path(file_path: str) -> str:
    path = (file_path or '').replace('\\', '/').strip()
    if not path:
        raise ValueError('empty file path')
    norm = posixpath.normpath(path)
    if norm.startswith('/'):
        raise ValueError(f'absolute path not allowed: {file_path}')
    if norm == '..' or norm.startswith('../'):
        raise ValueError(f'path traversal not allowed: {file_path}')
    if norm in ('.', ''):
        raise ValueError(f'invalid normalized path: {file_path}')
    return norm

def add_parent_suffix_before_extension(rel_path: str) -> str:
    p = PurePosixPath(rel_path)
    name = p.name
    stem, ext = os.path.splitext(name)
    if ext:
        parent_name = f'{stem}_parent{ext}'
    else:
        parent_name = f'{name}_parent'
    return str(p.with_name(parent_name))

def is_present_file(path: Path) -> bool:
    return path.exists() and path.is_file()

def git_diff_name_only(repo: Path, a: str, b: str) -> tuple[list[str], str | None]:
    try:
        proc = subprocess.run(['git', 'diff', '--name-only', f'{a}..{b}'], cwd=repo, capture_output=True, text=True, timeout=60, check=False)
    except subprocess.TimeoutExpired:
        return ([], 'git_diff_timeout')
    except Exception as e:
        return ([], f'git_diff_exec_error:{e}')
    if proc.returncode != 0:
        err = (proc.stderr or '').strip()[:400]
        return ([], f'git_diff_exit_{proc.returncode}:{err}')
    files = [ln for ln in proc.stdout.splitlines() if ln.strip()]
    return (files, None)

def git_show(repo: Path, sha: str, rel_path: str, timeout_sec: int) -> tuple[bytes | None, str | None]:
    try:
        proc = subprocess.run(['git', 'show', f'{sha}:{rel_path}'], cwd=repo, capture_output=True, timeout=timeout_sec, check=False)
    except subprocess.TimeoutExpired:
        return (None, f'git_show_timeout_after_{timeout_sec}s')
    except Exception as e:
        return (None, f'git_show_exec_error:{e}')
    if proc.returncode != 0:
        err = (proc.stderr or b'').decode('utf-8', errors='replace').strip()[:200]
        return (None, err or f'git_show_exit_{proc.returncode}')
    return (proc.stdout, None)

@dataclass(frozen=True)
class PairTask:
    leaf_id: str
    root_parent_id: str
    file_path: str

@dataclass(frozen=True)
class FileJob:
    pair_key: tuple[str, str, str]
    role: str
    src_sha: str
    rel_path: str
    output_path: Path

def collect_tasks(records: list[dict[str, Any]], repo: Path) -> tuple[dict[tuple[str, str, str], PairTask], dict[str, int], list[dict[str, Any]]]:
    pairs: dict[tuple[str, str, str], PairTask] = {}
    chain_index: list[dict[str, Any]] = []
    stats = {'records_total': len(records), 'chains_total': 0, 'chains_with_files': 0, 'chains_skipped_empty': 0, 'chains_skipped_missing_bounds': 0, 'git_diff_failures': 0, 'files_total': 0, 'files_non_cpp': 0, 'invalid_paths_skipped': 0, 'unique_pairs': 0}
    for rec in records:
        cve = rec.get('cve_id') or rec.get('id') or ''
        chains = rec.get('src_commits_chained') or []
        for ch in chains:
            stats['chains_total'] += 1
            root_parent = (ch.get('root_parent_id') or '').strip()
            commit_ids = ch.get('commit_ids') or []
            leaf = (commit_ids[-1] if commit_ids else '').strip()
            if not root_parent or not leaf:
                stats['chains_skipped_missing_bounds'] += 1
                continue
            files, err = git_diff_name_only(repo, root_parent, leaf)
            if err is not None:
                stats['git_diff_failures'] += 1
                continue
            cpp_files = []
            for f in files:
                stats['files_total'] += 1
                ext = os.path.splitext(f)[1].lower()
                if ext not in ALLOWED_EXTENSIONS:
                    stats['files_non_cpp'] += 1
                    continue
                try:
                    rel = normalize_rel_path(f)
                except ValueError:
                    stats['invalid_paths_skipped'] += 1
                    continue
                cpp_files.append(rel)
            chain_index.append({'cve_id': cve, 'chain_id': ch.get('chain_id'), 'root_parent_id': root_parent, 'leaf_id': leaf, 'files_total': len(files), 'files_cpp': len(cpp_files)})
            if cpp_files:
                stats['chains_with_files'] += 1
            else:
                stats['chains_skipped_empty'] += 1
            for rel in cpp_files:
                key = (root_parent, leaf, rel)
                if key not in pairs:
                    pairs[key] = PairTask(leaf_id=leaf, root_parent_id=root_parent, file_path=rel)
    stats['unique_pairs'] = len(pairs)
    return (pairs, stats, chain_index)

def write_meta_jsonl(meta_path: Path, rows: list[dict[str, Any]]) -> None:
    meta_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = meta_path.with_suffix(meta_path.suffix + '.tmp')
    with open(tmp, 'w', encoding='utf-8') as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + '\n')
    tmp.replace(meta_path)

def load_meta_jsonl(meta_path: Path) -> dict[tuple[str, str, str], dict[str, Any]]:
    rows_map: dict[tuple[str, str, str], dict[str, Any]] = {}
    if not meta_path.exists():
        return rows_map
    with open(meta_path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except Exception:
                continue
            rp = (row.get('root_parent_id') or '').strip()
            lf = (row.get('leaf_id') or '').strip()
            fp = (row.get('file_path') or '').strip()
            if not (rp and lf and fp):
                continue
            rows_map[rp, lf, fp] = row
    return rows_map

def merge_previous_role(current_role: dict[str, Any], previous_role: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(previous_role, dict):
        return current_role
    merged = dict(current_role)
    for k in ('status', 'bytes', 'error'):
        if k in previous_role:
            merged[k] = previous_role.get(k)
    return merged

def should_retry_role(previous_status: str | None, output_path: Path, overwrite: bool) -> bool:
    if overwrite:
        return True
    if previous_status in SUCCESS_STATUSES:
        return not is_present_file(output_path)
    return previous_status in RETRY_STATUSES or previous_status not in SUCCESS_STATUSES

def fetch_one_file(job: FileJob, repo: Path, timeout_sec: int, overwrite: bool) -> dict[str, Any]:
    if not overwrite and is_present_file(job.output_path):
        return {'pair_key': job.pair_key, 'role': job.role, 'status': 'exists', 'bytes': job.output_path.stat().st_size, 'path': str(job.output_path), 'error': None}
    job.output_path.parent.mkdir(parents=True, exist_ok=True)
    content, err = git_show(repo, job.src_sha, job.rel_path, timeout_sec)
    if content is None:
        try:
            with open(job.output_path, 'wb') as f:
                f.write(b'')
            return {'pair_key': job.pair_key, 'role': job.role, 'status': 'empty_placeholder', 'bytes': 0, 'path': str(job.output_path), 'error': err}
        except Exception as e:
            return {'pair_key': job.pair_key, 'role': job.role, 'status': 'failed', 'bytes': 0, 'path': str(job.output_path), 'error': f'placeholder_write_error:{e}'}
    try:
        with open(job.output_path, 'wb') as f:
            f.write(content)
        return {'pair_key': job.pair_key, 'role': job.role, 'status': 'downloaded', 'bytes': len(content), 'path': str(job.output_path), 'error': None}
    except Exception as e:
        return {'pair_key': job.pair_key, 'role': job.role, 'status': 'failed', 'bytes': 0, 'path': str(job.output_path), 'error': f'write_error:{e}'}

def main() -> None:
    parser = argparse.ArgumentParser(description='Download chain-level diff file pairs (root_parent vs leaf) from local git.')
    parser.add_argument('--input', type=Path, default=Path('data/chromium_cve_data.commit_chained.jsonl'), help='Input JSONL containing src_commits_chained')
    parser.add_argument('--output-dir', type=Path, default=Path('cache/diff_files/chromium_chain'), help='Output root dir; files saved under output-dir/<leaf>/...')
    parser.add_argument('--meta-out', type=Path, default=Path('data/processing/6_2b_get_chain_diff_files.meta.jsonl'), help='Output metadata JSONL path')
    parser.add_argument('--chain-index-out', type=Path, default=Path('data/processing/6_2b_get_chain_diff_files.chain_index.jsonl'), help='Output JSONL with one row per chain (cve_id, chain_id, root_parent, leaf, file counts)')
    parser.add_argument('--src-repo', type=Path, default=Path('chromium'), help='Local chromium git clone for git show / git diff')
    parser.add_argument('--workers', type=int, default=min(16, (os.cpu_count() or 8) * 2), help='Concurrent git-show workers')
    parser.add_argument('--timeout-sec', type=int, default=30, help='Per git-show timeout seconds')
    parser.add_argument('--overwrite', action='store_true', help='Overwrite existing files')
    parser.add_argument('--meta-flush-every', type=int, default=500, help='Flush metadata JSONL every N completed jobs (0 disables)')
    parser.add_argument('--max-pairs', type=int, default=0, help='Cap unique (root_parent, leaf, file) pairs (0 = no cap, for smoke tests)')
    args = parser.parse_args()
    if not args.src_repo.is_dir():
        raise SystemExit(f'src-repo not found: {args.src_repo}')
    records = []
    with open(args.input, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    print(f'Loaded records: {len(records):,}')
    pair_map, collect_stats, chain_index = collect_tasks(records, args.src_repo)
    previous_meta = load_meta_jsonl(args.meta_out)
    print(f"Chains total: {collect_stats['chains_total']:,}")
    print(f"  with C/C++ files: {collect_stats['chains_with_files']:,}")
    print(f"  empty (no C/C++ diff): {collect_stats['chains_skipped_empty']:,}")
    print(f"  missing root_parent or leaf: {collect_stats['chains_skipped_missing_bounds']:,}")
    print(f"  git diff failures: {collect_stats['git_diff_failures']:,}")
    print(f"Files total in diffs: {collect_stats['files_total']:,}")
    print(f"  non C/C++ skipped: {collect_stats['files_non_cpp']:,}")
    print(f"  invalid paths skipped: {collect_stats['invalid_paths_skipped']:,}")
    print(f"Unique (root_parent, leaf, file) pairs: {collect_stats['unique_pairs']:,}")
    if previous_meta:
        print(f'Loaded previous meta rows: {len(previous_meta):,}')
    args.chain_index_out.parent.mkdir(parents=True, exist_ok=True)
    tmp = args.chain_index_out.with_suffix(args.chain_index_out.suffix + '.tmp')
    with open(tmp, 'w', encoding='utf-8') as f:
        for row in chain_index:
            f.write(json.dumps(row, ensure_ascii=False) + '\n')
    tmp.replace(args.chain_index_out)
    print(f'Chain index written: {args.chain_index_out}')
    args.output_dir.mkdir(parents=True, exist_ok=True)
    pair_results: dict[tuple[str, str, str], dict[str, Any]] = {}
    jobs: list[FileJob] = []
    queued_leaf = 0
    queued_root = 0
    skipped_from_meta = 0
    items = list(pair_map.items())
    if args.max_pairs > 0:
        items = items[:args.max_pairs]
    for key, task in items:
        rel_parent = add_parent_suffix_before_extension(task.file_path)
        leaf_out = args.output_dir / task.leaf_id / task.file_path
        root_out = args.output_dir / task.leaf_id / rel_parent
        pair_results[key] = {'root_parent_id': task.root_parent_id, 'leaf_id': task.leaf_id, 'file_path': task.file_path, 'leaf': {'status': None, 'path': str(leaf_out), 'bytes': 0, 'error': None}, 'root_parent': {'status': None, 'path': str(root_out), 'bytes': 0, 'error': None}}
        prev = previous_meta.get(key)
        if isinstance(prev, dict):
            pair_results[key]['leaf'] = merge_previous_role(pair_results[key]['leaf'], prev.get('leaf'))
            pair_results[key]['root_parent'] = merge_previous_role(pair_results[key]['root_parent'], prev.get('root_parent'))
        if should_retry_role(pair_results[key]['leaf'].get('status'), leaf_out, args.overwrite):
            jobs.append(FileJob(pair_key=key, role='leaf', src_sha=task.leaf_id, rel_path=task.file_path, output_path=leaf_out))
            queued_leaf += 1
        else:
            skipped_from_meta += 1
        if should_retry_role(pair_results[key]['root_parent'].get('status'), root_out, args.overwrite):
            jobs.append(FileJob(pair_key=key, role='root_parent', src_sha=task.root_parent_id, rel_path=task.file_path, output_path=root_out))
            queued_root += 1
        else:
            skipped_from_meta += 1
    print(f'File jobs queued: {len(jobs):,}  (leaf={queued_leaf:,} parent={queued_root:,})')
    print(f'Skipped by previous meta: {skipped_from_meta:,}')
    completed = 0
    failed = 0
    placeholders = 0
    periodic_flushes = 0
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = [pool.submit(fetch_one_file, job, args.src_repo, args.timeout_sec, args.overwrite) for job in jobs]
        for fut in tqdm(as_completed(futures), total=len(futures), desc='git show'):
            res = fut.result()
            key = res['pair_key']
            role = res['role']
            pair_results[key][role] = {'status': res['status'], 'path': res['path'], 'bytes': res['bytes'], 'error': res['error']}
            completed += 1
            if res['status'] == 'failed':
                failed += 1
                print(f"[FAIL] root_parent={pair_results[key]['root_parent_id'][:10]} leaf={pair_results[key]['leaf_id'][:10]} file={pair_results[key]['file_path']} role={role} err={res['error']}")
            elif res['status'] == 'empty_placeholder':
                placeholders += 1
            if args.meta_flush_every > 0 and completed % args.meta_flush_every == 0:
                write_meta_jsonl(args.meta_out, list(pair_results.values()))
                periodic_flushes += 1
    rows = list(pair_results.values())
    write_meta_jsonl(args.meta_out, rows)
    leaf_ok = sum((1 for r in rows if r['leaf']['status'] in {'downloaded', 'exists'}))
    root_ok = sum((1 for r in rows if r['root_parent']['status'] in {'downloaded', 'exists'}))
    both_ok = sum((1 for r in rows if r['leaf']['status'] in {'downloaded', 'exists'} and r['root_parent']['status'] in {'downloaded', 'exists'}))
    leaf_ph = sum((1 for r in rows if r['leaf']['status'] == 'empty_placeholder'))
    root_ph = sum((1 for r in rows if r['root_parent']['status'] == 'empty_placeholder'))
    print('\nDone.')
    print(f'Pairs processed: {len(rows):,}')
    print(f'Leaf side OK (downloaded/existing): {leaf_ok:,}')
    print(f'Root_parent side OK (downloaded/existing): {root_ok:,}')
    print(f'Both sides OK: {both_ok:,}')
    print(f'Empty placeholders: leaf={leaf_ph:,} root_parent={root_ph:,}')
    print(f'Failed jobs: {failed:,}')
    print(f'Periodic flushes: {periodic_flushes:,}')
    print(f'Metadata: {args.meta_out}')
    print(f'Files written under: {args.output_dir}')
if __name__ == '__main__':
    main()
