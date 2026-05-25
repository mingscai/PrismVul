from playwright.sync_api import sync_playwright
from bs4 import BeautifulSoup
import json
import time
import os
import argparse
import random
from datetime import datetime
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path

def parse_cve_details(html, include_raw_html=False):
    soup = BeautifulSoup(html, 'html.parser')
    parsed = {}
    title_div = soup.find('div', id='cvedetails-title-div')
    parsed['cve_id'] = title_div.find('a', href=True).text.strip() if title_div else None
    title_h5 = soup.find('div', class_='h5 text-dark mb-2 fw-bold')
    parsed['title'] = title_h5.text.strip() if title_h5 else None
    summary_div = soup.find('div', id='cvedetailssummary')
    parsed['summary'] = summary_div.text.strip() if summary_div else None
    parsed['published'] = parsed['updated'] = parsed['source'] = None
    for block in soup.select('div.d-inline-block'):
        label_span = block.find('span', class_='ssc-text-secondary')
        if not label_span:
            continue
        label = label_span.text.strip().lower()
        value = block.get_text(strip=True).replace(label_span.text.strip(), '').strip()
        if 'published' in label:
            parsed['published'] = value
        elif 'updated' in label:
            parsed['updated'] = value
        elif 'source' in label:
            source_tag = block.find('a')
            parsed['source'] = source_tag.text.strip() if source_tag else value
    vuln_cat_div = soup.find('div', id='cve_catslabelsnotes_div')
    if vuln_cat_div:
        category_span = vuln_cat_div.find('span', class_='ssc-vuln-cat')
        parsed['category'] = category_span.text.strip() if category_span else None
    epss_div = soup.find('h2', id='cvedH2EPSSScore')
    epss_score = epss_percentile = None
    if epss_div:
        container = epss_div.find_next('div', class_='bg-white border-top py-2 px-3')
        if container:
            epss_score_span = container.find('span', class_=lambda c: c and 'epssbox' in c and ('score_' in c))
            epss_percentile_span = container.find('span', class_=lambda c: c and 'epssbox' in c and ('text-bg' in c))
            epss_score = epss_score_span.text.strip() if epss_score_span else None
            epss_percentile = epss_percentile_span.text.strip() if epss_percentile_span else None
    parsed['epss'] = {'score': epss_score, 'percentile': epss_percentile}
    cvss_table = soup.find('h2', id='cvedH2CVSSScores')
    parsed['cvss'] = {}
    if cvss_table:
        try:
            row = cvss_table.find_next('table').find('tbody').find('tr')
            if row:
                cols = row.find_all('td')
                if len(cols) >= 7:
                    parsed['cvss'] = {'base_score': cols[0].text.strip(), 'severity': cols[1].text.strip(), 'vector': cols[2].text.strip(), 'exploitability_score': cols[3].text.strip(), 'impact_score': cols[4].text.strip(), 'source': cols[5].text.strip(), 'first_seen': cols[6].text.strip()}
        except Exception:
            pass
    parsed['cwes'] = []
    cwe_section = soup.find('h2', id='cvedH2CWEs')
    if cwe_section:
        ul = cwe_section.find_next('ul')
        if ul:
            for li in ul.find_all('li'):
                cwe_entry = {}
                link = li.find('a', href=True)
                if link:
                    cwe_entry['id'] = link.text.split()[0]
                    cwe_entry['name'] = ' '.join(link.text.split()[1:])
                    cwe_entry['url'] = f"https://www.cvedetails.com{link['href']}"
                desc_div = li.find('div', class_='ms-1')
                if desc_div:
                    cwe_entry['description'] = desc_div.text.strip()
                parsed['cwes'].append(cwe_entry)
    refs = []
    ref_section = soup.find('h2', id='cvedH2References')
    if ref_section:
        ref_list = ref_section.find_next('ul')
        if ref_list:
            for li in ref_list.find_all('li'):
                link = li.find('a', href=True)
                if link:
                    refs.append(link['href'])
    parsed['references'] = refs
    if include_raw_html:
        parsed['raw_cvedetails_content'] = html
    return parsed

def is_valid_cve_details(parsed, expected_cve_id=None):
    if not isinstance(parsed, dict):
        return False
    cve_id = parsed.get('cve_id')
    if not cve_id:
        return False
    if expected_cve_id and cve_id.strip().upper() != expected_cve_id.strip().upper():
        return False
    return True

def fetch_single_cve(task):
    url, max_retries, delay, include_raw_html = task
    from playwright.sync_api import sync_playwright
    import time, random
    cve_id = url.strip().split('/')[-2]
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True, args=['--disable-blink-features=AutomationControlled', '--no-sandbox'])
        context = browser.new_context(user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36', locale='en-GB', timezone_id='Europe/London', viewport={'width': 1280, 'height': 800})
        page = context.new_page()
        retry_count = 0
        while retry_count <= max_retries:
            try:
                page.goto(url, timeout=60000, wait_until='domcontentloaded')
                page.wait_for_selector('body', timeout=10000)
                html = page.content()
                parsed = parse_cve_details(html, include_raw_html)
                parsed['url'] = url
                if not is_valid_cve_details(parsed, expected_cve_id=cve_id):
                    raise ValueError('Parsed page missing CVE details (possible rate limit/block)')
                browser.close()
                time.sleep(random.uniform(delay * 0.5, delay * 1.5))
                return (cve_id, parsed, None)
            except Exception as e:
                retry_count += 1
                if retry_count > max_retries:
                    browser.close()
                    return (cve_id, None, str(e))
                wait_time = 2 ** retry_count + random.uniform(0, 2)
                time.sleep(wait_time)
        browser.close()
        return (cve_id, None, 'Max retries exceeded')

def process_month_file_parallel(input_path, output_path, max_retries, delay, workers, include_raw_html, resume):
    print(f'[*] Processing: {input_path}')
    with open(input_path, 'r') as f:
        month_data = json.load(f)
    existing_cves = {}
    if resume and os.path.exists(output_path):
        try:
            with open(output_path, 'r') as f:
                existing_output = json.load(f)
                raw_existing = existing_output.get('cves', {})
            invalid_cves = []
            for cid, parsed in raw_existing.items():
                if is_valid_cve_details(parsed, expected_cve_id=cid):
                    existing_cves[cid] = parsed
                else:
                    invalid_cves.append(cid)
            print(f'    → Resuming: Found {len(existing_cves)} valid CVEs')
            if invalid_cves:
                print(f'    → Found {len(invalid_cves)} invalid CVEs; will re-fetch')
        except Exception:
            pass
    output = {'metadata': month_data.get('metadata', {}), 'year': month_data.get('year'), 'month': month_data.get('month'), 'month_name': month_data.get('month_name'), 'is_complete': month_data.get('is_complete'), 'cves': existing_cves.copy()}
    urls = month_data.get('cve_links', [])
    if resume:
        urls_to_process = []
        for url in urls:
            cve_id = url.strip().split('/')[-2]
            if cve_id not in existing_cves:
                urls_to_process.append(url)
        print(f'    → Need to process: {len(urls_to_process)}/{len(urls)} CVEs')
    else:
        urls_to_process = urls
    if not urls_to_process:
        print(f'    → All CVEs already processed, skipping')
        return
    total_links = len(urls_to_process)
    tasks = [(url, max_retries, delay, include_raw_html) for url in urls_to_process]
    with ProcessPoolExecutor(max_workers=workers) as executor:
        futures = [executor.submit(fetch_single_cve, task) for task in tasks]
        completed = 0
        success = 0
        failed = 0
        for future in as_completed(futures):
            cve_id, parsed, error = future.result()
            completed += 1
            if parsed:
                output['cves'][cve_id] = parsed
                success += 1
                severity = parsed.get('cvss', {}).get('severity', 'N/A')
                print(f'    [{completed}/{total_links}] ✓ {cve_id} (Severity: {severity})')
            else:
                failed += 1
                print(f'    [{completed}/{total_links}] ✗ {cve_id} - Error: {error}')
            if completed % 10 == 0:
                with open(output_path, 'w', encoding='utf-8') as f:
                    json.dump(output, f, indent=2, ensure_ascii=False)
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    print(f'[+] Saved to {output_path}')
    print(f"    → Success: {success}, Failed: {failed}, Total: {len(output['cves'])} CVEs")

def process_month_file_sequential(input_path, output_path, max_retries, delay, include_raw_html, resume):
    print(f'[*] Processing: {input_path}')
    with open(input_path, 'r') as f:
        month_data = json.load(f)
    existing_cves = {}
    if resume and os.path.exists(output_path):
        try:
            with open(output_path, 'r') as f:
                existing_output = json.load(f)
                raw_existing = existing_output.get('cves', {})
            invalid_cves = []
            for cid, parsed in raw_existing.items():
                if is_valid_cve_details(parsed, expected_cve_id=cid):
                    existing_cves[cid] = parsed
                else:
                    invalid_cves.append(cid)
            print(f'    → Resuming: Found {len(existing_cves)} valid CVEs')
            if invalid_cves:
                print(f'    → Found {len(invalid_cves)} invalid CVEs; will re-fetch')
        except Exception:
            pass
    output = {'metadata': month_data.get('metadata', {}), 'year': month_data.get('year'), 'month': month_data.get('month'), 'month_name': month_data.get('month_name'), 'is_complete': month_data.get('is_complete'), 'cves': existing_cves.copy()}
    urls = month_data.get('cve_links', [])
    if resume:
        urls_to_process = []
        for url in urls:
            cve_id = url.strip().split('/')[-2]
            if cve_id not in existing_cves:
                urls_to_process.append(url)
        print(f'    → Need to process: {len(urls_to_process)}/{len(urls)} CVEs')
    else:
        urls_to_process = urls
    if not urls_to_process:
        print(f'    → All CVEs already processed, skipping')
        return
    total_links = len(urls_to_process)
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True, args=['--disable-blink-features=AutomationControlled', '--no-sandbox'])
        context = browser.new_context(user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36', locale='en-GB', timezone_id='Europe/London', viewport={'width': 1280, 'height': 800})
        page = context.new_page()
        success = 0
        failed = 0
        for idx, url in enumerate(urls_to_process, 1):
            cve_id = url.strip().split('/')[-2]
            retry_count = 0
            while retry_count <= max_retries:
                try:
                    page.goto(url, timeout=60000, wait_until='domcontentloaded')
                    page.wait_for_selector('body', timeout=10000)
                    html = page.content()
                    parsed = parse_cve_details(html, include_raw_html)
                    parsed['url'] = url
                    if not is_valid_cve_details(parsed, expected_cve_id=cve_id):
                        raise ValueError('Parsed page missing CVE details (possible rate limit/block)')
                    output['cves'][cve_id] = parsed
                    success += 1
                    severity = parsed.get('cvss', {}).get('severity', 'N/A')
                    print(f'    [{idx}/{total_links}] ✓ {cve_id} (Severity: {severity})')
                    break
                except Exception as e:
                    retry_count += 1
                    if retry_count > max_retries:
                        failed += 1
                        print(f'    [{idx}/{total_links}] ✗ {cve_id} - Error: {e}')
                        break
                    wait_time = 2 ** retry_count + random.uniform(0, 2)
                    time.sleep(wait_time)
            time.sleep(random.uniform(delay * 0.5, delay * 1.5))
            if idx % 10 == 0:
                with open(output_path, 'w', encoding='utf-8') as f:
                    json.dump(output, f, indent=2, ensure_ascii=False)
        browser.close()
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    print(f'[+] Saved to {output_path}')
    print(f"    → Success: {success}, Failed: {failed}, Total: {len(output['cves'])} CVEs")

def parse_args():
    parser = argparse.ArgumentParser(description='Parse CVE details from CVEdetails.com pages', formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('--input-dir', type=str, required=True, help='Input directory containing month JSON files with CVE links')
    parser.add_argument('--max-retries', type=int, default=5, help='Maximum number of retries for failed requests')
    parser.add_argument('--delay', type=float, default=1.0, help='Delay between requests in seconds')
    parser.add_argument('--parallel', action='store_true', help='Enable parallel processing (multi-process for CVEs within each month)')
    parser.add_argument('--workers', type=int, default=4, help='Number of parallel workers per month file (only with --parallel)')
    parser.add_argument('--include-raw-html', action='store_true', help='Include raw HTML content in output (warning: large file sizes)')
    parser.add_argument('--resume', action='store_true', help='Resume from existing output files (skip already processed CVEs)')
    parser.add_argument('--file-pattern', type=str, default='*.json', help="File pattern to match (e.g., '2024/*.json' for specific year)")
    return parser.parse_args()

def main():
    args = parse_args()
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    print(f'[{timestamp}] [+] Starting CVE details parsing...')
    print(f'[{timestamp}] [+] Input directory: {args.input_dir}')
    print(f"[{timestamp}] [+] Mode: {('Parallel' if args.parallel else 'Sequential')}")
    if args.parallel:
        print(f'[{timestamp}] [+] Workers per month: {args.workers}')
    print(f"[{timestamp}] [+] Resume mode: {('Enabled' if args.resume else 'Disabled')}")
    print(f"[{timestamp}] [+] Include raw HTML: {('Yes' if args.include_raw_html else 'No')}")
    input_path = Path(args.input_dir)
    if not input_path.exists():
        print(f'[{timestamp}] [✗] Error: Input directory does not exist: {args.input_dir}')
        return
    json_files = []
    for root, dirs, files in os.walk(args.input_dir):
        for file in files:
            if file.endswith('.json') and (not file.endswith('_details.json')):
                json_files.append(os.path.join(root, file))
    if not json_files:
        print(f'[{timestamp}] [✗] No JSON files found in {args.input_dir}')
        return
    print(f'[{timestamp}] [+] Found {len(json_files)} month files to process')
    for idx, input_file in enumerate(json_files, 1):
        output_file = input_file.replace('.json', '_details.json')
        print(f'\n[{timestamp}] [{idx}/{len(json_files)}] Processing month file: {input_file}')
        try:
            if args.parallel:
                process_month_file_parallel(input_file, output_file, args.max_retries, args.delay, args.workers, args.include_raw_html, args.resume)
            else:
                process_month_file_sequential(input_file, output_file, args.max_retries, args.delay, args.include_raw_html, args.resume)
        except Exception as e:
            print(f'[{timestamp}] [✗] Error processing {input_file}: {e}')
            continue
    print(f'\n[{timestamp}] [+] All done!')
if __name__ == '__main__':
    main()
