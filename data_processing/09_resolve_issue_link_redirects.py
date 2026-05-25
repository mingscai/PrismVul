#!/usr/bin/env python3
import json
import re
import argparse
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
from tqdm import tqdm
HEADERS = {'User-Agent': 'Mozilla/5.0 (compatible; CVE-research-bot/1.0)'}
_JS_REDIRECT_RE = re.compile('const\\s+url\\s*=\\s*"(https?://[^"]+)"')

def resolve_url(url: str, timeout: int) -> str:
    try:
        r = requests.head(url, allow_redirects=True, timeout=timeout, headers=HEADERS)
        current = r.url
        if r.status_code >= 400:
            r = requests.get(url, allow_redirects=True, timeout=timeout, headers=HEADERS, stream=True)
            r.close()
            current = r.url
        r2 = requests.get(current, allow_redirects=True, timeout=timeout, headers=HEADERS)
        m = _JS_REDIRECT_RE.search(r2.text)
        if m:
            return m.group(1)
        return r2.url
    except Exception:
        return url

def main():
    parser = argparse.ArgumentParser(description='Resolve redirects in issue_links')
    parser.add_argument('--input', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--cache', default='cache/issue_link_redirects.json')
    parser.add_argument('--workers', type=int, default=20)
    parser.add_argument('--timeout', type=int, default=10)
    args = parser.parse_args()
    input_path = Path(args.input)
    output_path = Path(args.output)
    cache_path = Path(args.cache)
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
            for url in d.get('issue_links', []):
                if url and url not in cache:
                    all_urls.add(url)
    print(f'URLs to resolve: {len(all_urls):,}')
    if all_urls:
        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            futures = {pool.submit(resolve_url, url, args.timeout): url for url in all_urls}
            for fut in tqdm(as_completed(futures), total=len(futures), desc='Resolving'):
                orig = futures[fut]
                cache[orig] = fut.result()
        with open(cache_path, 'w') as f:
            json.dump(cache, f, ensure_ascii=False, indent=2)
        print(f'Cache saved: {len(cache):,} entries')
    tmp_path = output_path.with_suffix('.tmp')
    changed = 0
    with open(input_path) as fin, open(tmp_path, 'w') as fout:
        for line in fin:
            d = json.loads(line)
            if d.get('issue_links'):
                resolved = [cache.get(u, u) for u in d['issue_links']]
                resolved = list(dict.fromkeys(resolved))
                if resolved != d['issue_links']:
                    changed += 1
                d['issue_links'] = resolved
            fout.write(json.dumps(d, ensure_ascii=False) + '\n')
    tmp_path.replace(output_path)
    print(f'Done. CVEs with updated issue_links: {changed:,}')
if __name__ == '__main__':
    main()
