#!/usr/bin/env python3
import asyncio
import json
import gc
import random
import argparse
from pathlib import Path
from playwright.async_api import async_playwright, TimeoutError as PlaywrightTimeoutError
from tqdm import tqdm
CONCURRENT_LIMIT = 5
BATCH_SIZE = 30
SEARCH_BASE = 'https://issues.chromium.org/issues?q='

async def query_issue_links(page, cve_suffix: str) -> list[str]:
    try:
        await page.goto(f'{SEARCH_BASE}{cve_suffix}', timeout=15000)
        try:
            await page.wait_for_selector('a.row-issue-title', timeout=10000)
        except PlaywrightTimeoutError:
            return []
        rows = await page.query_selector_all('tr[data-row-id]')
        links = []
        for row in rows:
            title_el = await row.query_selector('a.row-issue-title')
            if not title_el:
                continue
            href = await title_el.get_attribute('href')
            if href and href.startswith('issues/'):
                links.append(f'https://issues.chromium.org/{href}')
        return links
    except Exception:
        return []

async def scrape_metadata(page, url: str) -> dict:
    try:
        await page.goto(url, timeout=15000)
        await page.wait_for_load_state('networkidle', timeout=15000)
        try:
            btn = page.locator("button[id='b-collapsible-panel-header-2']")
            if await btn.count() > 0:
                await btn.first.click()
        except Exception:
            pass
        for _ in range(10):
            try:
                show_all = page.locator("span.bv2-metadata-link:has-text('(show all)')")
                if await show_all.count() == 0:
                    break
                await show_all.first.click()
                await page.wait_for_timeout(300)
            except Exception:
                break
        metadata = {}
        fields = await page.locator('div.bv2-issue-metadata-field').all()
        for field in fields:
            try:
                children = field.locator(':scope > *')
                text_node = children.nth(0)
                text_str = (await text_node.inner_text()).strip().rstrip(':')
                parts = text_str.split('\n', 1)
                label = parts[0].strip()
                value = parts[1].strip() if len(parts) > 1 else ''
                for suffix in ('\nCC me', '\nAdd me', '\nAdd', '\nEdit', '\nView', 'Add', 'Add me', '\n(show fewer)'):
                    value = value.removesuffix(suffix)
                if value == '--':
                    value = ''
                metadata[label] = value
            except Exception:
                continue
        return metadata
    except Exception:
        return {}

def cve_matches(metadata: dict, cve_id: str) -> bool:
    cve_val = (metadata.get('CVE') or '').strip()
    if not cve_val:
        return False
    expected_suffix = cve_id[4:] if cve_id.startswith('CVE-') else cve_id
    return cve_val == expected_suffix

async def process_cve(cve_id: str, browser, sem: asyncio.Semaphore, cache: dict, timeout: int) -> list[str]:
    if cve_id in cache:
        return cache[cve_id]
    cve_suffix = cve_id[4:] if cve_id.startswith('CVE-') else cve_id
    validated = []
    async with sem:
        await asyncio.sleep(random.uniform(1, 2))
        page = await browser.new_page()
        try:
            candidate_links = await query_issue_links(page, cve_suffix)
            for link in candidate_links:
                await asyncio.sleep(random.uniform(0.5, 1.5))
                metadata = await scrape_metadata(page, link)
                if cve_matches(metadata, cve_id):
                    validated.append(link)
        except Exception as e:
            print(f'  [!] Error processing {cve_id}: {e}')
        finally:
            try:
                await page.close()
            except Exception:
                pass
    cache[cve_id] = validated
    return validated

async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--input', default='data/processing/chromium_cve_data.jsonl')
    parser.add_argument('--output', default='data/processing/chromium_cve_data.jsonl')
    parser.add_argument('--cache', default='cache/tracker_issue_links.json')
    parser.add_argument('--workers', type=int, default=CONCURRENT_LIMIT)
    parser.add_argument('--batch', type=int, default=BATCH_SIZE)
    args = parser.parse_args()
    input_path = Path(args.input)
    output_path = Path(args.output)
    cache_path = Path(args.cache)
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    cache: dict[str, list[str]] = {}
    if cache_path.exists():
        with open(cache_path) as f:
            cache = json.load(f)
    print(f'Cache loaded: {len(cache):,} entries')
    records = []
    with open(input_path) as f:
        for line in f:
            records.append(json.loads(line))

    def needs_query(d: dict) -> bool:
        links = d.get('issue_links') or []
        if not links:
            return True
        return not any(('issues.chromium.org' in u for u in links))
    targets = [d['cve_id'] for d in records if needs_query(d)]
    to_query = [cid for cid in targets if cid not in cache]
    empty_count = sum((1 for d in records if not d.get('issue_links')))
    no_chromium_count = sum((1 for d in records if d.get('issue_links') and (not any(('issues.chromium.org' in u for u in d['issue_links'])))))
    print(f'CVEs with empty issue_links: {empty_count:,} | No chromium tracker link: {no_chromium_count:,} | To query: {len(to_query):,}')
    sem = asyncio.Semaphore(args.workers)
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        for i in range(0, len(to_query), args.batch):
            batch = to_query[i:i + args.batch]
            batch_num = i // args.batch + 1
            total_batches = (len(to_query) + args.batch - 1) // args.batch
            print(f'\n[Batch {batch_num}/{total_batches}] {len(batch)} CVEs')
            tasks = [asyncio.create_task(process_cve(cid, browser, sem, cache, 15)) for cid in batch]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            found = sum((1 for r in results if isinstance(r, list) and r))
            print(f'  Found links for {found}/{len(batch)} CVEs')
            with open(cache_path, 'w') as f:
                json.dump(cache, f, ensure_ascii=False, indent=2)
            gc.collect()
            if i + args.batch < len(to_query):
                delay = random.uniform(3, 6)
                print(f'  Waiting {delay:.1f}s...')
                await asyncio.sleep(delay)
        await browser.close()
    print(f'\nCache saved: {len(cache):,} entries')
    updated = 0
    tmp_path = output_path.with_suffix('.tmp')
    with open(input_path) as fin, open(tmp_path, 'w') as fout:
        for d in records:
            new_links = cache.get(d['cve_id'], [])
            if new_links:
                existing = d.get('issue_links') or []
                merged = list(dict.fromkeys(existing + new_links))
                if merged != existing:
                    d['issue_links'] = merged
                    updated += 1
            fout.write(json.dumps(d, ensure_ascii=False) + '\n')
    tmp_path.replace(output_path)
    print(f'Done. Updated {updated:,} CVEs with new issue links.')
if __name__ == '__main__':
    asyncio.run(main())
