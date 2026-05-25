#!/usr/bin/env python3
import argparse
import json
import os
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from tqdm import tqdm
ALLOWED_EXTENSIONS = {'.c', '.cc', '.cpp', '.h'}
SUCCESS_STATUSES = {'processed', 'exists', 'dry_run'}

@dataclass(frozen=True)
class PairJob:
    commit_sha: str
    src_path: Path
    dst_path: Path
    out_path: Path
    rel_dst_path: str
    raw_src_path: Path | None
    raw_dst_path: Path | None

def write_meta_jsonl(meta_path: Path, rows: list[dict[str, Any]]) -> None:
    meta_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = meta_path.with_suffix(meta_path.suffix + '.tmp')
    with open(tmp, 'w', encoding='utf-8') as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + '\n')
    tmp.replace(meta_path)

def load_meta_jsonl(meta_path: Path) -> dict[tuple[str, str], dict[str, Any]]:
    rows: dict[tuple[str, str], dict[str, Any]] = {}
    if not meta_path.exists() or not meta_path.is_file():
        return rows
    with open(meta_path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except Exception:
                continue
            sha = (row.get('sha') or '').strip()
            rel_dst_path = (row.get('rel_dst_path') or '').strip()
            if not sha or not rel_dst_path:
                continue
            rows[sha, rel_dst_path] = row
    return rows

def parent_to_base_name(name: str) -> str | None:
    stem, ext = os.path.splitext(name)
    if ext:
        if not stem.endswith('_parent'):
            return None
        return f'{stem[:-7]}{ext}'
    if not name.endswith('_parent'):
        return None
    return name[:-7]

def is_allowed_source_file(path: Path) -> bool:
    return path.suffix.lower() in ALLOWED_EXTENSIONS

def build_jobs(input_dir: Path, raw_input_dir: Path | None, out_suffix: str, max_jobs: int | None) -> tuple[list[PairJob], dict[str, int]]:
    stats = {'commit_dirs': 0, 'files_scanned': 0, 'parent_candidates': 0, 'non_cpp_skipped': 0, 'missing_counterpart': 0, 'raw_pairs_ready': 0, 'raw_pairs_missing': 0}
    jobs: list[PairJob] = []
    for commit_dir in sorted((p for p in input_dir.iterdir() if p.is_dir())):
        stats['commit_dirs'] += 1
        commit_sha = commit_dir.name
        for p in commit_dir.rglob('*'):
            if not p.is_file():
                continue
            stats['files_scanned'] += 1
            if not is_allowed_source_file(p):
                stats['non_cpp_skipped'] += 1
                continue
            base_name = parent_to_base_name(p.name)
            if base_name is None:
                continue
            stats['parent_candidates'] += 1
            dst = p.with_name(base_name)
            if not dst.exists() or not dst.is_file():
                stats['missing_counterpart'] += 1
                continue
            rel_dst = str(dst.relative_to(commit_dir))
            out_path = Path(str(dst) + out_suffix)
            raw_src_path: Path | None = None
            raw_dst_path: Path | None = None
            if raw_input_dir is not None:
                candidate_raw_src = raw_input_dir / commit_sha / p.relative_to(commit_dir)
                candidate_raw_dst = raw_input_dir / commit_sha / dst.relative_to(commit_dir)
                if candidate_raw_src.exists() and candidate_raw_dst.exists():
                    raw_src_path = candidate_raw_src
                    raw_dst_path = candidate_raw_dst
                    stats['raw_pairs_ready'] += 1
                else:
                    stats['raw_pairs_missing'] += 1
            jobs.append(PairJob(commit_sha=commit_sha, src_path=p, dst_path=dst, out_path=out_path, rel_dst_path=rel_dst, raw_src_path=raw_src_path, raw_dst_path=raw_dst_path))
            if max_jobs is not None and len(jobs) >= max_jobs:
                return (jobs, stats)
    return (jobs, stats)

def should_skip_existing(out_path: Path, overwrite: bool) -> bool:
    if overwrite:
        return False
    return out_path.exists() and out_path.is_file() and (out_path.stat().st_size > 0)

def should_retry_from_meta(previous_status: str | None, out_path: Path, overwrite: bool) -> bool:
    if overwrite:
        return True
    if previous_status in SUCCESS_STATUSES:
        return not (out_path.exists() and out_path.is_file() and (out_path.stat().st_size > 0))
    return True

def run_one_job(job: PairJob, jar_path: Path, timeout_sec: int, preprocess: bool, strict_mapping: bool, overwrite: bool, dry_run: bool) -> dict[str, Any]:
    if should_skip_existing(job.out_path, overwrite):
        return {'sha': job.commit_sha, 'rel_dst_path': job.rel_dst_path, 'src_path': str(job.src_path), 'dst_path': str(job.dst_path), 'out_path': str(job.out_path), 'status': 'exists', 'exit_code': 0, 'duration_ms': 0, 'error': None}
    if dry_run:
        return {'sha': job.commit_sha, 'rel_dst_path': job.rel_dst_path, 'src_path': str(job.src_path), 'dst_path': str(job.dst_path), 'out_path': str(job.out_path), 'status': 'dry_run', 'exit_code': None, 'duration_ms': 0, 'error': None}
    job.out_path.parent.mkdir(parents=True, exist_ok=True)
    cmd = ['java', '-jar', str(jar_path), '--srcPath', str(job.src_path), '--dstPath', str(job.dst_path), '--outPath', str(job.out_path)]
    if job.raw_src_path is not None and job.raw_dst_path is not None:
        cmd.extend(['--rawSrcPath', str(job.raw_src_path)])
        cmd.extend(['--rawDstPath', str(job.raw_dst_path)])
    if preprocess:
        cmd.append('--preprocess')
    if strict_mapping:
        cmd.append('--strictMapping')
    t0 = time.time()
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_sec, check=False)
    except subprocess.TimeoutExpired:
        return {'sha': job.commit_sha, 'rel_dst_path': job.rel_dst_path, 'src_path': str(job.src_path), 'dst_path': str(job.dst_path), 'out_path': str(job.out_path), 'status': 'failed', 'exit_code': None, 'duration_ms': int((time.time() - t0) * 1000), 'error': f'timeout_after_{timeout_sec}s'}
    except Exception as e:
        return {'sha': job.commit_sha, 'rel_dst_path': job.rel_dst_path, 'src_path': str(job.src_path), 'dst_path': str(job.dst_path), 'out_path': str(job.out_path), 'status': 'failed', 'exit_code': None, 'duration_ms': int((time.time() - t0) * 1000), 'error': str(e)}
    elapsed_ms = int((time.time() - t0) * 1000)
    if proc.returncode == 0 and job.out_path.exists() and (job.out_path.stat().st_size > 0):
        return {'sha': job.commit_sha, 'rel_dst_path': job.rel_dst_path, 'src_path': str(job.src_path), 'dst_path': str(job.dst_path), 'out_path': str(job.out_path), 'status': 'processed', 'exit_code': 0, 'duration_ms': elapsed_ms, 'error': None}
    stderr = (proc.stderr or '').strip()
    stdout = (proc.stdout or '').strip()
    msg = stderr if stderr else stdout
    if len(msg) > 800:
        msg = msg[-800:]
    if not msg and proc.returncode == 0:
        msg = 'jar_returned_0_but_output_missing_or_empty'
    elif not msg:
        msg = f'jar_exit_{proc.returncode}'
    return {'sha': job.commit_sha, 'rel_dst_path': job.rel_dst_path, 'src_path': str(job.src_path), 'dst_path': str(job.dst_path), 'out_path': str(job.out_path), 'status': 'failed', 'exit_code': proc.returncode, 'duration_ms': elapsed_ms, 'error': msg}

def main() -> None:
    parser = argparse.ArgumentParser(description='Run gumtree jar on every _parent/base file pair')
    parser.add_argument('--input-dir', type=Path, default=Path('cache/diff_files/chromium_c_cpp_no_comments_chain'), help='Root directory containing chain-level C/C++ pairs')
    parser.add_argument('--jar-path', type=Path, default=Path('data/processing/gumtree_differ/app/build/libs/app.jar'), help='Path to gumtree_differ jar')
    parser.add_argument('--raw-input-dir', type=Path, default=Path('cache/diff_files/chromium_c_cpp_chain'), help='Optional raw-source root used to pass --rawSrcPath/--rawDstPath to jar. Set to empty path or non-existing path to disable.')
    parser.add_argument('--meta-out', type=Path, default=Path('cache/diff_files/chromium_c_cpp_no_comments_chain.gumtree.meta.jsonl'), help='Metadata JSONL path')
    parser.add_argument('--out-suffix', type=str, default='.diff.json', help='Output sidecar suffix appended to dst file path')
    parser.add_argument('--workers', type=int, default=min(8, os.cpu_count() or 8), help='Concurrent jar workers')
    parser.add_argument('--timeout-sec', type=int, default=120, help='Timeout seconds per pair')
    parser.add_argument('--meta-flush-every', type=int, default=200, help='Flush metadata every N completed jobs (0 disables periodic flush)')
    parser.add_argument('--overwrite', action='store_true', help='Re-run even if .diff.json already exists')
    parser.add_argument('--strict-mapping', action='store_true', help='Pass --strictMapping to jar')
    parser.add_argument('--no-preprocess', action='store_true', help='Do not pass --preprocess to jar')
    parser.add_argument('--max-jobs', type=int, default=None, help='Process at most N pairs (for smoke tests)')
    parser.add_argument('--dry-run', action='store_true', help='Build job list and metadata without running jar')
    args = parser.parse_args()
    if not args.input_dir.exists() or not args.input_dir.is_dir():
        raise SystemExit(f'Input directory not found: {args.input_dir}')
    if not args.jar_path.exists() or not args.jar_path.is_file():
        raise SystemExit(f'Jar not found: {args.jar_path}')
    if not args.out_suffix:
        raise SystemExit('--out-suffix must be non-empty')
    raw_input_dir: Path | None = None
    if args.raw_input_dir and args.raw_input_dir.exists() and args.raw_input_dir.is_dir():
        raw_input_dir = args.raw_input_dir
    jobs, scan_stats = build_jobs(args.input_dir, raw_input_dir, args.out_suffix, args.max_jobs)
    previous_meta = load_meta_jsonl(args.meta_out)
    print(f"Commit directories scanned: {scan_stats['commit_dirs']:,}")
    print(f"Files scanned: {scan_stats['files_scanned']:,}")
    print(f"Parent candidates: {scan_stats['parent_candidates']:,}")
    print(f"Missing counterpart files: {scan_stats['missing_counterpart']:,}")
    print(f"Non C/C++ skipped: {scan_stats['non_cpp_skipped']:,}")
    if raw_input_dir is not None:
        print(f"Raw pair paths ready: {scan_stats['raw_pairs_ready']:,}")
        print(f"Raw pair paths missing: {scan_stats['raw_pairs_missing']:,}")
    else:
        print('Raw pair paths disabled: raw-input-dir missing')
    print(f'Pair jobs discovered: {len(jobs):,}')
    if args.max_jobs is not None:
        print(f'Max jobs cap: {args.max_jobs:,}')
    if previous_meta:
        print(f'Loaded previous meta rows: {len(previous_meta):,}')
    filtered_jobs: list[PairJob] = []
    pair_rows: dict[tuple[str, str], dict[str, Any]] = {}
    skipped_by_meta = 0
    for job in jobs:
        key = (job.commit_sha, job.rel_dst_path)
        row = {'sha': job.commit_sha, 'rel_dst_path': job.rel_dst_path, 'src_path': str(job.src_path), 'dst_path': str(job.dst_path), 'out_path': str(job.out_path), 'status': None, 'exit_code': None, 'duration_ms': 0, 'error': None}
        prev = previous_meta.get(key)
        if isinstance(prev, dict):
            for field in ('status', 'exit_code', 'duration_ms', 'error'):
                if field in prev:
                    row[field] = prev.get(field)
        pair_rows[key] = row
        if should_retry_from_meta(row.get('status'), job.out_path, args.overwrite):
            filtered_jobs.append(job)
        else:
            skipped_by_meta += 1
    print(f'Jobs queued: {len(filtered_jobs):,}')
    print(f'Jobs skipped by previous meta success: {skipped_by_meta:,}')
    completed = 0
    periodic_flushes = 0
    with ThreadPoolExecutor(max_workers=max(1, args.workers)) as pool:
        futures = [pool.submit(run_one_job, job, args.jar_path, args.timeout_sec, not args.no_preprocess, args.strict_mapping, args.overwrite, args.dry_run) for job in filtered_jobs]
        for fut in tqdm(as_completed(futures), total=len(futures), desc='Running gumtree'):
            r = fut.result()
            key = (r['sha'], r['rel_dst_path'])
            pair_rows[key] = r
            completed += 1
            if r['status'] == 'failed':
                print(f"[FAIL] sha={r['sha']} file={r['rel_dst_path']} exit={r['exit_code']} err={r['error']}")
            if args.meta_flush_every > 0 and completed % args.meta_flush_every == 0:
                write_meta_jsonl(args.meta_out, list(pair_rows.values()))
                periodic_flushes += 1
                print(f'[META] Flushed at completed jobs: {completed:,} (flush #{periodic_flushes})')
    rows = list(pair_rows.values())
    write_meta_jsonl(args.meta_out, rows)
    processed = sum((1 for r in rows if r['status'] == 'processed'))
    exists = sum((1 for r in rows if r['status'] == 'exists'))
    dry_run = sum((1 for r in rows if r['status'] == 'dry_run'))
    failed = sum((1 for r in rows if r['status'] == 'failed'))
    print('\nDone.')
    print(f'Rows: {len(rows):,}')
    print(f'  - processed: {processed:,}')
    print(f'  - exists: {exists:,}')
    print(f'  - dry_run: {dry_run:,}')
    print(f'  - failed: {failed:,}')
    if periodic_flushes:
        print(f'Periodic meta flush count: {periodic_flushes:,}')
    print(f'Metadata written to: {args.meta_out}')
if __name__ == '__main__':
    main()
