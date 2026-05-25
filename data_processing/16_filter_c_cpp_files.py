#!/usr/bin/env python3
import argparse
import json
import shutil
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from tqdm import tqdm
ALLOWED_EXTENSIONS = {'.c', '.cc', '.cpp', '.h'}

@dataclass(frozen=True)
class CopyJob:
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

def copy_one(job: CopyJob, overwrite: bool) -> dict[str, Any]:
    if not overwrite and job.dst_path.exists() and job.dst_path.is_file():
        return {'sha': job.sha, 'rel_path': job.rel_path, 'dst_path': str(job.dst_path), 'ext': job.ext, 'is_parent': job.is_parent, 'bytes': job.dst_path.stat().st_size, 'status': 'exists', 'copied': False}
    job.dst_path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(job.src_path, job.dst_path)
    return {'sha': job.sha, 'rel_path': job.rel_path, 'dst_path': str(job.dst_path), 'ext': job.ext, 'is_parent': job.is_parent, 'bytes': job.dst_path.stat().st_size, 'status': 'copied', 'copied': True}

def main() -> None:
    parser = argparse.ArgumentParser(description='Filter chain diff files to strict C/C++')
    parser.add_argument('--input-dir', type=Path, default=Path('cache/diff_files/chromium_chain'))
    parser.add_argument('--output-dir', type=Path, default=Path('cache/diff_files/chromium_c_cpp_chain'))
    parser.add_argument('--meta-out', type=Path, default=Path('cache/diff_files/chromium_c_cpp_chain_diff_files.meta.jsonl'))
    parser.add_argument('--workers', type=int, default=8)
    parser.add_argument('--overwrite', action='store_true')
    parser.add_argument('--dry-run', action='store_true')
    args = parser.parse_args()
    if not args.input_dir.exists() or not args.input_dir.is_dir():
        raise SystemExit(f'Input directory not found: {args.input_dir}')
    files = iter_files(args.input_dir)
    print(f'Input files scanned: {len(files):,}')
    jobs: list[CopyJob] = []
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
        jobs.append(CopyJob(src_path=src, dst_path=args.output_dir / rel, rel_path=str(rel), ext=ext, sha=rel_sha(rel), is_parent=is_parent))
    print(f'Matched C/C++ files: {len(jobs):,}')
    print(f'Skipped non C/C++: {skipped:,}')
    print(f'Parent-side files: {parents:,}')
    rows: list[dict[str, Any]] = []
    if args.dry_run:
        for job in jobs:
            rows.append({'sha': job.sha, 'rel_path': job.rel_path, 'dst_path': str(job.dst_path), 'ext': job.ext, 'is_parent': job.is_parent, 'bytes': job.src_path.stat().st_size, 'status': 'dry_run', 'copied': False})
    else:
        args.output_dir.mkdir(parents=True, exist_ok=True)
        with ThreadPoolExecutor(max_workers=max(1, args.workers)) as pool:
            futs = [pool.submit(copy_one, j, args.overwrite) for j in jobs]
            for f in tqdm(as_completed(futs), total=len(futs), desc='Copying'):
                rows.append(f.result())
    write_meta_jsonl(args.meta_out, rows)
    copied = sum((1 for r in rows if r['status'] == 'copied'))
    exists = sum((1 for r in rows if r['status'] == 'exists'))
    print('\nDone.')
    print(f'Retained: {len(rows):,}  (copied={copied:,} exists={exists:,})')
    print(f'Metadata: {args.meta_out}')
    if not args.dry_run:
        print(f'Files written under: {args.output_dir}')
if __name__ == '__main__':
    main()
