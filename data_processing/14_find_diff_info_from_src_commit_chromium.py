#!/usr/bin/env python3
import os
import json
import argparse
import asyncio
import aiohttp
from pathlib import Path
from tqdm.asyncio import tqdm_asyncio
GITHUB_API_BASE = 'https://api.github.com'
GITHUB_REPO = 'chromium/chromium'
_RATE_LIMITED = '__RATE_LIMITED__'

async def fetch_commit_details(session: aiohttp.ClientSession, commit_hash: str, token: str, sem: asyncio.Semaphore) -> dict | str | None:
    url = f'{GITHUB_API_BASE}/repos/{GITHUB_REPO}/commits/{commit_hash}'
    headers = {'Authorization': f'token {token}', 'Accept': 'application/vnd.github.v3+json'}
    async with sem:
        try:
            async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                if resp.status == 403:
                    return _RATE_LIMITED
                if resp.status == 404:
                    print(f'  [!] Commit not found: {commit_hash}')
                    return None
                if resp.status != 200:
                    print(f'  [!] GitHub API error {resp.status} for {commit_hash}')
                    return _RATE_LIMITED
                data = await resp.json()
                parents = data.get('parents', [])
                parent_id = parents[0]['sha'] if parents else None
                diffs = []
                for file_data in data.get('files', []):
                    diffs.append({'filename': file_data['filename'], 'previous_filename': file_data.get('previous_filename', ''), 'status': file_data['status'], 'additions': file_data['additions'], 'deletions': file_data['deletions'], 'changes': file_data['changes'], 'raw_url': file_data.get('raw_url', ''), 'patch': file_data.get('patch', '')})
                return {'id': data['sha'], 'commit_date': data['commit']['committer']['date'], 'message': data['commit']['message'], 'parent_id': parent_id, 'diffs': diffs}
        except asyncio.TimeoutError:
            print(f'  [!] Timeout fetching {commit_hash}')
            return _RATE_LIMITED
        except Exception as e:
            print(f'  [!] Error fetching {commit_hash}: {e}')
            return _RATE_LIMITED

async def process_record(record: dict, session: aiohttp.ClientSession, token: str, sem: asyncio.Semaphore, cache: dict, rate_limited_hashes: set) -> dict:
    src_links = record.get('src_commit_links', [])
    src_hashes = [link['hash'] for link in src_links if link.get('hash')]
    if not src_hashes:
        record['src_commits'] = []
        return record
    src_hashes = list(dict.fromkeys(src_hashes))
    commits = []
    for h in src_hashes:
        if h in cache:
            if cache[h] is not None:
                commits.append(cache[h])
            continue
        commit_data = await fetch_commit_details(session, h, token, sem)
        if commit_data is _RATE_LIMITED:
            rate_limited_hashes.add(h)
        elif commit_data is None:
            cache[h] = None
        else:
            cache[h] = commit_data
            commits.append(commit_data)
    record['src_commits'] = commits
    return record

async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--input', default='data/processing/chromium_cve_data.jsonl')
    parser.add_argument('--output', default='data/processing/chromium_cve_data.jsonl')
    parser.add_argument('--cache', default='cache/github_commits.json')
    parser.add_argument('--workers', type=int, default=10)
    parser.add_argument('--github-token', default=None, help='GitHub token (defaults to env GITHUB_TOKEN if omitted)')
    args = parser.parse_args()
    token = args.github_token or os.getenv('GITHUB_TOKEN')
    if not token:
        print('Error: missing GitHub token. Use --github-token or set GITHUB_TOKEN')
        return
    input_path = Path(args.input)
    output_path = Path(args.output)
    cache_path = Path(args.cache)
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    cache: dict = {}
    if cache_path.exists():
        with open(cache_path) as f:
            cache = json.load(f)
    print(f'Cache loaded: {len(cache):,} entries')
    records = []
    with open(input_path) as f:
        for line in f:
            records.append(json.loads(line))
    print(f'Loaded {len(records):,} records')
    sem = asyncio.Semaphore(args.workers)
    rate_limited_hashes: set = set()
    async with aiohttp.ClientSession() as session:
        tasks = [process_record(r, session, token, sem, cache, rate_limited_hashes) for r in records]
        await tqdm_asyncio.gather(*tasks, desc='Fetching commits')
    with open(cache_path, 'w') as f:
        json.dump(cache, f, ensure_ascii=False, indent=2)
    print(f'Cache saved: {len(cache):,} entries')
    with_commits = sum((1 for r in records if r.get('src_commits')))
    total_commits = sum((len(r.get('src_commits', [])) for r in records))
    total_links = sum((len(r.get('src_commit_links', [])) for r in records))
    all_hashes = set()
    for r in records:
        for link in r.get('src_commit_links', []):
            if link.get('hash'):
                all_hashes.add(link['hash'])
    cached_success = sum((1 for h in all_hashes if h in cache and cache[h] is not None))
    cached_none = sum((1 for h in all_hashes if h in cache and cache[h] is None))
    print(f"\n{'=' * 60}")
    print(f'统计结果:')
    print(f'  - Records with src_commits: {with_commits:,} / {len(records):,}')
    print(f'  - Total src_commits fetched: {total_commits:,} / {total_links:,} links')
    print(f'  - Unique hashes: {len(all_hashes):,}')
    print(f'    - Fetched successfully: {cached_success:,}')
    print(f'    - Not found (404): {cached_none:,}')
    print(f'    - Rate limited (403, not cached): {len(rate_limited_hashes):,}')
    if rate_limited_hashes:
        print(f"\n{'=' * 60}")
        print(f'⚠ 警告: {len(rate_limited_hashes):,} 个 commit 因 GitHub API rate limit (403) 获取失败')
        print(f'  这些结果未被缓存，重新运行脚本即可重试')
        print(f'  请等待 rate limit 恢复后再次执行')
        print(f"{'=' * 60}")
    with_commits = sum((1 for r in records if r.get('src_commits')))
    print(f'Records with src_commits: {with_commits:,} / {len(records):,}')
    tmp_path = output_path.with_suffix('.tmp')
    with open(tmp_path, 'w') as f:
        for record in records:
            f.write(json.dumps(record, ensure_ascii=False) + '\n')
    tmp_path.replace(output_path)
    print('Done.')
if __name__ == '__main__':
    asyncio.run(main())
