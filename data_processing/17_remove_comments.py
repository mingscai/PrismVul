#!/usr/bin/env python3
import argparse
import json
import os
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from tqdm import tqdm
ALLOWED_EXTENSIONS = {'.c', '.cc', '.cpp', '.h'}

@dataclass(frozen=True)
class ProcessJob:
    src_path: Path
    dst_path: Path
    rel_path: str
    ext: str
    sha: str | None
    is_parent: bool

def iter_files(root: Path) -> list[Path]:
    return [p for p in root.rglob('*') if p.is_file()]

def rel_sha(rel_path: Path) -> str | None:
    parts = rel_path.parts
    if not parts:
        return None
    return parts[0]

def write_meta_jsonl(meta_path: Path, rows: list[dict[str, Any]]) -> None:
    meta_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = meta_path.with_suffix(meta_path.suffix + '.tmp')
    with open(tmp, 'w', encoding='utf-8') as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + '\n')
    tmp.replace(meta_path)

def language_for_ext(ext: str) -> str:
    if ext == '.c':
        return 'c'
    return 'c++'

def run_gcc_strip_comments(src_path: Path, gcc_bin: str, keep_linemarkers: bool, timeout_sec: int) -> tuple[bytes | None, str | None]:
    cmd = [gcc_bin, '-fpreprocessed', '-dD', '-E', '-x', language_for_ext(src_path.suffix.lower())]
    if not keep_linemarkers:
        cmd.append('-P')
    cmd.append(str(src_path))
    try:
        proc = subprocess.run(cmd, check=False, capture_output=True, timeout=timeout_sec)
    except subprocess.TimeoutExpired:
        return (None, f'timeout_after_{timeout_sec}s')
    except FileNotFoundError:
        return (None, f'compiler_not_found:{gcc_bin}')
    except Exception as e:
        return (None, f'gcc_exec_error:{e}')
    if proc.returncode != 0:
        stderr = proc.stderr.decode('utf-8', errors='replace').strip()
        return (None, stderr or f'gcc_exit_{proc.returncode}')
    return (proc.stdout, None)

def process_one(job: ProcessJob, overwrite: bool, gcc_bin: str, keep_linemarkers: bool, timeout_sec: int, fallback_copy_on_fail: bool) -> dict[str, Any]:
    src_bytes = job.src_path.read_bytes()
    src_size = len(src_bytes)
    if not overwrite and job.dst_path.exists() and job.dst_path.is_file():
        return {'sha': job.sha, 'rel_path': job.rel_path, 'src_path': str(job.src_path), 'dst_path': str(job.dst_path), 'ext': job.ext, 'is_parent': job.is_parent, 'status': 'exists', 'bytes_in': src_size, 'bytes_out': job.dst_path.stat().st_size, 'changed': None, 'error': None}
    out_bytes, err = run_gcc_strip_comments(job.src_path, gcc_bin, keep_linemarkers, timeout_sec)
    job.dst_path.parent.mkdir(parents=True, exist_ok=True)
    if out_bytes is None:
        if fallback_copy_on_fail:
            job.dst_path.write_bytes(src_bytes)
            return {'sha': job.sha, 'rel_path': job.rel_path, 'src_path': str(job.src_path), 'dst_path': str(job.dst_path), 'ext': job.ext, 'is_parent': job.is_parent, 'status': 'fallback_copied', 'bytes_in': src_size, 'bytes_out': src_size, 'changed': False, 'error': err}
        return {'sha': job.sha, 'rel_path': job.rel_path, 'src_path': str(job.src_path), 'dst_path': str(job.dst_path), 'ext': job.ext, 'is_parent': job.is_parent, 'status': 'failed', 'bytes_in': src_size, 'bytes_out': 0, 'changed': None, 'error': err}
    job.dst_path.write_bytes(out_bytes)
    return {'sha': job.sha, 'rel_path': job.rel_path, 'src_path': str(job.src_path), 'dst_path': str(job.dst_path), 'ext': job.ext, 'is_parent': job.is_parent, 'status': 'processed', 'bytes_in': src_size, 'bytes_out': len(out_bytes), 'changed': src_bytes != out_bytes, 'error': None}

def main() -> None:
    parser = argparse.ArgumentParser(description='Strip comments from chain C/C++ files via GCC preprocessor')
    parser.add_argument('--input-dir', type=Path, default=Path('cache/diff_files/chromium_c_cpp_chain'))
    parser.add_argument('--output-dir', type=Path, default=Path('cache/diff_files/chromium_c_cpp_no_comments_chain'))
    parser.add_argument('--meta-out', type=Path, default=Path('cache/diff_files/chromium_c_cpp_no_comments_chain.meta.jsonl'))
    parser.add_argument('--gcc-bin', type=str, default='gcc')
    parser.add_argument('--workers', type=int, default=min(8, os.cpu_count() or 8))
    parser.add_argument('--timeout-sec', type=int, default=30)
    parser.add_argument('--keep-linemarkers', action='store_true')
    parser.add_argument('--fallback-copy-on-fail', action='store_true')
    parser.add_argument('--overwrite', action='store_true')
    parser.add_argument('--dry-run', action='store_true')
    args = parser.parse_args()
    if not args.input_dir.exists() or not args.input_dir.is_dir():
        raise SystemExit(f'Input directory not found: {args.input_dir}')
    files = iter_files(args.input_dir)
    print(f'Input files scanned: {len(files):,}')
    jobs: list[ProcessJob] = []
    skipped = 0
    parents = 0
    for src in files:
        rel = src.relative_to(args.input_dir)
        ext = src.suffix.lower()
        if ext not in ALLOWED_EXTENSIONS:
            skipped += 1
            continue
        is_parent = src.stem.endswith('_parent')
        if is_parent:
            parents += 1
        jobs.append(ProcessJob(src_path=src, dst_path=args.output_dir / rel, rel_path=str(rel), ext=ext, sha=rel_sha(rel), is_parent=is_parent))
    print(f'Matched C/C++: {len(jobs):,}  (parents={parents:,}, skipped={skipped:,})')
    rows: list[dict[str, Any]] = []
    if args.dry_run:
        for j in jobs:
            rows.append({'sha': j.sha, 'rel_path': j.rel_path, 'src_path': str(j.src_path), 'dst_path': str(j.dst_path), 'ext': j.ext, 'is_parent': j.is_parent, 'status': 'dry_run', 'bytes_in': j.src_path.stat().st_size, 'bytes_out': None, 'changed': None, 'error': None})
    else:
        args.output_dir.mkdir(parents=True, exist_ok=True)
        with ThreadPoolExecutor(max_workers=max(1, args.workers)) as pool:
            futs = [pool.submit(process_one, j, args.overwrite, args.gcc_bin, args.keep_linemarkers, args.timeout_sec, args.fallback_copy_on_fail) for j in jobs]
            for f in tqdm(as_completed(futs), total=len(futs), desc='Stripping'):
                rows.append(f.result())
    write_meta_jsonl(args.meta_out, rows)
    proc_n = sum((1 for r in rows if r['status'] == 'processed'))
    ex_n = sum((1 for r in rows if r['status'] == 'exists'))
    fb_n = sum((1 for r in rows if r['status'] == 'fallback_copied'))
    fail_n = sum((1 for r in rows if r['status'] == 'failed'))
    print('\nDone.')
    print(f'Rows: {len(rows):,}  processed={proc_n:,} exists={ex_n:,} fallback={fb_n:,} failed={fail_n:,}')
    print(f'Metadata: {args.meta_out}')
    if not args.dry_run:
        print(f'Files written under: {args.output_dir}')
if __name__ == '__main__':
    main()
