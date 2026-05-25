#!/usr/bin/env python3
import argparse
import json
import os
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any
from tqdm import tqdm
_GITHUB_TOKEN = os.environ.get('GITHUB_TOKEN')
_VALIDATION_CACHE: dict[str, bool] = {}
_VALIDATION_CACHE_FILE: Path | None = None

def load_validation_cache(cache_file: Path) -> dict[str, bool]:
    if cache_file.exists():
        try:
            with open(cache_file, 'r') as f:
                return json.load(f)
        except Exception:
            pass
    return {}

def save_validation_cache(cache_file: Path, cache: dict[str, bool]):
    cache_file.parent.mkdir(parents=True, exist_ok=True)
    try:
        with open(cache_file, 'w') as f:
            json.dump(cache, f, ensure_ascii=False, indent=2)
    except Exception as e:
        print(f'警告：无法保存验证缓存文件: {e}')

def validate_commit_exists(commit_hash: str) -> bool:
    if commit_hash in _VALIDATION_CACHE:
        return _VALIDATION_CACHE[commit_hash]
    api_url = f'https://api.github.com/repos/chromium/chromium/commits/{commit_hash}'
    try:
        req = urllib.request.Request(api_url)
        req.add_header('User-Agent', 'Mozilla/5.0')
        if _GITHUB_TOKEN:
            req.add_header('Authorization', f'token {_GITHUB_TOKEN}')
        with urllib.request.urlopen(req, timeout=30) as response:
            if response.status == 200:
                _VALIDATION_CACHE[commit_hash] = True
                return True
    except urllib.error.HTTPError as e:
        if e.code == 404:
            _VALIDATION_CACHE[commit_hash] = False
            return False
        elif e.code == 403:
            print(f'\n警告：GitHub API rate limit 超限，请稍后重试或设置 GITHUB_TOKEN')
            return False
        else:
            print(f'\n警告：验证 {commit_hash} 时出错: HTTP {e.code}')
            return False
    except Exception as e:
        print(f'\n警告：验证 {commit_hash} 时出错: {e}')
        return False
    _VALIDATION_CACHE[commit_hash] = False
    return False

def validate_commits_batch(commit_hashes: list[str], batch_size: int=100, delay: float=1.0) -> dict[str, bool]:
    results = {}
    to_validate = [h for h in commit_hashes if h not in _VALIDATION_CACHE]
    if not to_validate:
        print('所有 commit 都已在缓存中')
        return {h: _VALIDATION_CACHE[h] for h in commit_hashes}
    print(f'\n开始验证 {len(to_validate):,} 个 commit hashes...')
    total_batches = (len(to_validate) + batch_size - 1) // batch_size
    for i in range(0, len(to_validate), batch_size):
        batch = to_validate[i:i + batch_size]
        batch_num = i // batch_size + 1
        print(f'[Batch {batch_num}/{total_batches}] 验证 {len(batch)} 个 commits...')
        for commit_hash in tqdm(batch, desc=f'Batch {batch_num}'):
            exists = validate_commit_exists(commit_hash)
            results[commit_hash] = exists
            time.sleep(0.1)
        if _VALIDATION_CACHE_FILE:
            save_validation_cache(_VALIDATION_CACHE_FILE, _VALIDATION_CACHE)
        if i + batch_size < len(to_validate):
            print(f'  等待 {delay:.1f}s...')
            time.sleep(delay)
    for commit_hash in commit_hashes:
        if commit_hash in _VALIDATION_CACHE:
            results[commit_hash] = _VALIDATION_CACHE[commit_hash]
    return results

def process_records(records: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    all_hashes = set()
    for record in records:
        for commit in record.get('src_commit_links', []):
            commit_hash = commit.get('hash')
            if commit_hash:
                all_hashes.add(commit_hash)
    all_hashes = sorted(all_hashes)
    print(f'收集到 {len(all_hashes):,} 个唯一的 commit hashes')
    validation_results = validate_commits_batch(all_hashes, batch_size=100, delay=1.0)
    valid_count = sum((1 for exists in validation_results.values() if exists))
    invalid_count = len(validation_results) - valid_count
    print(f'\n验证结果：')
    print(f'  - 有效 commits: {valid_count:,} ({valid_count / len(validation_results) * 100:.1f}%)')
    print(f'  - 无效 commits: {invalid_count:,} ({invalid_count / len(validation_results) * 100:.1f}%)')
    filtered_records = []
    total_commits_before = 0
    total_commits_after = 0
    cves_affected = 0
    for record in records:
        original_links = record.get('src_commit_links', [])
        total_commits_before += len(original_links)
        filtered_links = [commit for commit in original_links if commit.get('hash') and validation_results.get(commit['hash'], False)]
        total_commits_after += len(filtered_links)
        if len(filtered_links) != len(original_links):
            cves_affected += 1
        record['src_commit_links'] = filtered_links
        filtered_records.append(record)
    stats = {'total_unique_hashes': len(all_hashes), 'valid_hashes': valid_count, 'invalid_hashes': invalid_count, 'total_commits_before': total_commits_before, 'total_commits_after': total_commits_after, 'commits_removed': total_commits_before - total_commits_after, 'cves_affected': cves_affected}
    return (filtered_records, stats)

def main():
    global _VALIDATION_CACHE, _VALIDATION_CACHE_FILE
    parser = argparse.ArgumentParser(description='验证 Chromium commit hashes 是否在仓库中存在')
    parser.add_argument('--input', type=Path, default=Path('data/processing/chromium_cve_data.jsonl'), help='输入 JSONL 文件')
    parser.add_argument('--output', type=Path, default=Path('data/processing/chromium_cve_data.jsonl'), help='输出 JSONL 文件')
    parser.add_argument('--cache', type=Path, default=Path('cache/commit_validation.json'), help='验证结果缓存文件')
    args = parser.parse_args()
    if not _GITHUB_TOKEN:
        print('警告：未设置 GITHUB_TOKEN 环境变量')
        print('GitHub API rate limit 为 60 requests/hour（未认证）')
        print('建议设置 GITHUB_TOKEN 以提高到 5000 requests/hour')
        print()
    _VALIDATION_CACHE_FILE = args.cache
    _VALIDATION_CACHE = load_validation_cache(_VALIDATION_CACHE_FILE)
    print(f'从缓存加载了 {len(_VALIDATION_CACHE)} 条验证记录')
    records = []
    with open(args.input, 'r', encoding='utf-8') as f:
        for line in f:
            records.append(json.loads(line))
    print(f'读取了 {len(records)} 条 CVE 记录')
    filtered_records, stats = process_records(records)
    print(f'\n处理完成：')
    print(f"  - 总唯一 hashes: {stats['total_unique_hashes']:,}")
    print(f"  - 有效 hashes: {stats['valid_hashes']:,}")
    print(f"  - 无效 hashes: {stats['invalid_hashes']:,}")
    print(f"  - 处理前总 commits: {stats['total_commits_before']:,}")
    print(f"  - 处理后总 commits: {stats['total_commits_after']:,}")
    print(f"  - 移除的 commits: {stats['commits_removed']:,}")
    print(f"  - 受影响的 CVEs: {stats['cves_affected']:,}")
    with open(args.output, 'w', encoding='utf-8') as f:
        for record in filtered_records:
            f.write(json.dumps(record, ensure_ascii=False) + '\n')
    if _VALIDATION_CACHE_FILE:
        save_validation_cache(_VALIDATION_CACHE_FILE, _VALIDATION_CACHE)
    print(f'\n输出已保存到: {args.output}')
    print(f'验证缓存已保存到: {_VALIDATION_CACHE_FILE}')
if __name__ == '__main__':
    main()
