#!/usr/bin/env python3
import asyncio
import json
import gc
import re
import random
import argparse
from pathlib import Path
from urllib.parse import urlparse
from playwright.async_api import async_playwright, TimeoutError as PlaywrightTimeoutError
from tqdm import tqdm
CONCURRENT_LIMIT = 5
BATCH_SIZE = 100

def issue_id_from_url(url: str) -> str:
    m = re.search('/issues/(\\d+)', url)
    return m.group(1) if m else ''

async def scrape_issue(page, url: str) -> dict:
    await page.goto(url, timeout=20000)
    await page.wait_for_load_state('networkidle', timeout=20000)
    title = await page.title()
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
            text_node = field.locator(':scope > *').nth(0)
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
    try:
        effort = page.locator('b-estimated-effort-row')
        if await effort.count() > 0:
            lbl = await effort.locator('onedev-field-label').inner_text()
            val = await effort.locator('onedev-field-value').inner_text()
            metadata[lbl.strip()] = val.strip() if val.strip() != '--' else ''
    except Exception:
        pass
    description = {}
    try:
        desc = page.locator('b-issue-description')
        await desc.wait_for(timeout=5000)
        creator = ''
        ud = desc.locator('b-user-display-name')
        if await ud.count() > 0:
            ct = await ud.first.inner_text()
            creator = '' if 'Deleted User' in ct else ct.strip()
        time_str = ''
        if await desc.locator('time').count() > 0:
            time_str = await desc.locator('time').first.inner_text()
        content = ''
        if await desc.locator('b-markdown-format-presenter').count() > 0:
            content = await desc.locator('b-markdown-format-presenter').inner_text()
        elif await desc.locator('b-plain-format-presenter').count() > 0:
            content = await desc.locator('b-plain-format-presenter').inner_text()
        attachments = []
        anchors = desc.locator("a[href*='download=true']")
        for i in range(await anchors.count()):
            href = await anchors.nth(i).get_attribute('href')
            if href:
                attachments.append(href)
        description = {'creator': creator, 'time': time_str.strip(), 'content': content.strip(), 'attachments': attachments}
    except Exception:
        pass
    comments = []
    for node in await page.locator('b-history-event').all():
        try:
            try:
                expand_selectors = ["a:has-text('Expand for full commit details')", "button:has-text('Expand for full commit details')", "span:has-text('Expand for full commit details')", "[role='button']:has-text('Expand for full commit details')"]
                for selector in expand_selectors:
                    expand_elem = node.locator(selector)
                    if await expand_elem.count() > 0:
                        await expand_elem.first.click()
                        await page.wait_for_timeout(800)
                        break
            except Exception as e:
                pass
            creator = ''
            ud = node.locator('b-user-display-name')
            if await ud.count() > 0:
                ct = await ud.inner_text()
                creator = '' if 'Deleted User' in ct else ct.strip()
            time_str = await node.locator('time').first.inner_text()
            cn = node.locator('b-formatted-comment-presenter')
            body = ''
            if await cn.locator('b-markdown-format-presenter').count() > 0:
                body = await cn.locator('b-markdown-format-presenter').inner_text()
            elif await cn.locator('b-plain-format-presenter').count() > 0:
                body = await cn.locator('b-plain-format-presenter').inner_text()
            elif await cn.count() > 0:
                body = await cn.inner_text()
            attachments = []
            for i in range(await node.locator("a[href*='download=true']").count()):
                href = await node.locator("a[href*='download=true']").nth(i).get_attribute('href')
                if href:
                    attachments.append(href)
            comments.append({'creator': creator, 'time': time_str.strip(), 'content': body.strip(), 'attachments': attachments})
        except Exception:
            continue
    modified_time = ''
    try:
        mt = await page.locator('meta[itemprop="dateModified"]').get_attribute('content')
        if mt:
            modified_time = mt
    except Exception:
        pass
    return {'title': title, 'metadata': metadata, 'description': description, 'comments': comments, 'modified_time': modified_time}

async def scrape_url(url: str, browser, sem: asyncio.Semaphore, cache: dict, pbar) -> None:
    async with sem:
        if url in cache:
            pbar.update(1)
            return
        await asyncio.sleep(random.uniform(1, 2))
        page = await browser.new_page()
        try:
            scraped = await scrape_issue(page, url)
            issue_id = issue_id_from_url(url)
            cache[url] = {'issue_id': issue_id, 'link': url, 'title': scraped['title'], 'priority': scraped['metadata'].get('Priority', ''), 'type': scraped['metadata'].get('Type', ''), 'status': scraped['metadata'].get('Status', ''), 'modified_time': scraped['modified_time'], 'content': {'title': scraped['title'], 'metadata': scraped['metadata'], 'description': scraped['description'], 'comments': scraped['comments']}}
        except Exception as e:
            print(f'  [!] Failed {url}: {e}')
            cache[url] = None
        finally:
            try:
                await page.close()
            except Exception:
                pass
            pbar.update(1)

async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--input', default='data/processing/chromium_cve_data.jsonl')
    parser.add_argument('--output', default='data/processing/chromium_cve_data.jsonl')
    parser.add_argument('--cache', default='cache/issue_content_chromium.json')
    parser.add_argument('--workers', type=int, default=CONCURRENT_LIMIT)
    parser.add_argument('--batch', type=int, default=BATCH_SIZE)
    args = parser.parse_args()
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

    def chromium_links(d: dict) -> list[str]:
        return [u for u in d.get('issue_links') or [] if 'issues.chromium.org' in u]
    all_urls = list(dict.fromkeys((u for d in records for u in chromium_links(d) if u not in cache)))
    print(f'URLs to scrape: {len(all_urls):,}')
    sem = asyncio.Semaphore(args.workers)
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        for i in range(0, len(all_urls), args.batch):
            batch = all_urls[i:i + args.batch]
            batch_num = i // args.batch + 1
            total_batches = (len(all_urls) + args.batch - 1) // args.batch
            print(f'\n[Batch {batch_num}/{total_batches}] {len(batch)} URLs')
            with tqdm(total=len(batch), desc=f'Batch {batch_num}') as pbar:
                tasks = [asyncio.create_task(scrape_url(url, browser, sem, cache, pbar)) for url in batch]
                await asyncio.gather(*tasks, return_exceptions=True)
            with open(cache_path, 'w') as f:
                json.dump(cache, f, ensure_ascii=False, indent=2)
            print(f'  Cache saved: {len(cache):,} entries')
            gc.collect()
            if i + args.batch < len(all_urls):
                delay = random.uniform(3, 6)
                print(f'  Waiting {delay:.1f}s...')
                await asyncio.sleep(delay)
        await browser.close()
    tmp_path = output_path.with_suffix('.tmp')
    with open(input_path) as fin, open(tmp_path, 'w') as fout:
        for d in records:
            links = chromium_links(d)
            if links:
                issues = [cache[u] for u in links if cache.get(u) is not None]
            else:
                issues = []
            d['issues'] = issues
            fout.write(json.dumps(d, ensure_ascii=False) + '\n')
    tmp_path.replace(output_path)
    print('\nDone.')
if __name__ == '__main__':
    asyncio.run(main())
