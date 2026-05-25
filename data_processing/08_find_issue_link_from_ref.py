#!/usr/bin/env python3
import json
import re
from pathlib import Path
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
from tqdm import tqdm
HEADERS = {'User-Agent': 'Mozilla/5.0 (compatible; CVE-research-bot/1.0)'}
ISSUE_TAGS = {'Issue Tracking', 'issue-tracking'}
ISSUE_URL_PATTERNS = re.compile('(bugs\\.chromium\\.org/p/[^/]+/issues/|crbug\\.com/|bugzilla\\.[^/]+/|bugs\\.webkit\\.org/|github\\.com/[^/]+/[^/]+/issues/|gitlab\\.[^/]+/[^/]+/[^/]+/-/issues/|bugs\\.launchpad\\.net/|bugzilla\\.mozilla\\.org/|bugzilla\\.redhat\\.com/|bugzilla\\.kernel\\.org/|bugs\\.debian\\.org/|sourceforge\\.net/tracker/|jira\\.[^/]+/|issues\\.apache\\.org/)', re.IGNORECASE)
_JS_REDIRECT_RE = re.compile('const\\s+url\\s*=\\s*"(https?://[^"]+)"')
_DEAD = '__DEAD__'

def resolve_url(url: str, timeout: int) -> str:
    try:
        r = requests.head(url, allow_redirects=True, timeout=timeout, headers=HEADERS)
        current = r.url
        if r.status_code >= 400:
            r = requests.get(url, allow_redirects=True, timeout=timeout, headers=HEADERS, stream=True)
            r.close()
            if r.status_code >= 400:
                return _DEAD
            current = r.url
        r2 = requests.get(current, allow_redirects=True, timeout=timeout, headers=HEADERS)
        if r2.status_code >= 400:
            return _DEAD
        m = _JS_REDIRECT_RE.search(r2.text)
        if m:
            return m.group(1)
        return r2.url
    except Exception:
        return _DEAD

def is_issue_ref(ref: dict) -> bool:
    tags = set(ref.get('tags') or [])
    if tags & ISSUE_TAGS:
        return True
    url = ref.get('url', '')
    return bool(ISSUE_URL_PATTERNS.search(url))

def main():
    parser = argparse.ArgumentParser(description='Extract and verify issue links from CVE references')
    parser.add_argument('--input', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--cache', default='cache/issue_link_redirects.json')
    parser.add_argument('--workers', type=int, default=20)
    parser.add_argument('--timeout', type=int, default=10)
    args = parser.parse_args()
    input_path = Path(args.input)
    output_path = Path(args.output)
    cache_path = Path(args.cache)
    tmp_path = output_path.with_suffix('.tmp')
    output_path.parent.mkdir(parents=True, exist_ok=True)
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    cache: dict[str, str] = {}
    if cache_path.exists():
        with open(cache_path) as f:
            cache = json.load(f)
    print(f'Cache loaded: {len(cache):,} entries')
    all_urls: set[str] = set()
    with open(input_path) as f:
        for line in f:
            d = json.loads(line)
            for ref in d.get('references', []):
                url = ref.get('url', '')
                if url and is_issue_ref(ref) and (url not in cache):
                    all_urls.add(url)
    print(f'URLs to check: {len(all_urls):,}')
    if all_urls:
        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            futures = {pool.submit(resolve_url, url, args.timeout): url for url in all_urls}
            for fut in tqdm(as_completed(futures), total=len(futures), desc='Checking'):
                orig = futures[fut]
                cache[orig] = fut.result()
        with open(cache_path, 'w') as f:
            json.dump(cache, f, ensure_ascii=False, indent=2)
        print(f'Cache saved: {len(cache):,} entries')
    dead = sum((1 for v in cache.values() if v == _DEAD))
    print(f'Dead URLs in cache: {dead:,}')
    total = with_issues = dropped_total = 0
    with open(input_path) as fin, open(tmp_path, 'w') as fout:
        for line in fin:
            total += 1
            d = json.loads(line)
            raw_links = list(dict.fromkeys((ref['url'] for ref in d.get('references', []) if ref.get('url') and is_issue_ref(ref))))
            issue_links = []
            for url in raw_links:
                resolved = cache.get(url, url)
                if resolved != _DEAD:
                    issue_links.append(resolved)
                else:
                    dropped_total += 1
            issue_links = list(dict.fromkeys(issue_links))
            if issue_links:
                with_issues += 1
            ordered = {}
            inserted = False
            for k, v in d.items():
                ordered[k] = v
                if k == 'references' and (not inserted):
                    ordered['issue_links'] = issue_links
                    inserted = True
            if not inserted:
                ordered['issue_links'] = issue_links
            fout.write(json.dumps(ordered, ensure_ascii=False) + '\n')
    tmp_path.replace(output_path)
    print(f'\nDone. Total: {total:,} | With issue links: {with_issues:,} | Dropped dead URLs: {dropped_total:,}')
if __name__ == '__main__':
    main()
