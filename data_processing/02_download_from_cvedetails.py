from playwright.sync_api import sync_playwright
import time
import random
import json
from datetime import datetime
import os
import argparse
from concurrent.futures import ProcessPoolExecutor, as_completed
months = ['January', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October', 'November', 'December']

def scrape_one_month(task):
    year, month_num, args_dict = task
    from playwright.sync_api import sync_playwright
    import os, json, time, random
    months = args_dict['months']
    month_name = months[month_num - 1]
    output_dir = args_dict['output_dir']
    max_retries = args_dict['max_retries']
    timestamp = args_dict['timestamp']
    year_dir = os.path.join(output_dir, str(year))
    os.makedirs(year_dir, exist_ok=True)
    month_output_path = os.path.join(year_dir, f'{month_num:02d}.json')
    print(f'[{timestamp}] [*] Processing {month_name} {year}...')
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True, args=['--disable-blink-features=AutomationControlled', '--no-sandbox'])
        context = browser.new_context(user_agent=args_dict['user_agent'], locale='en-GB', timezone_id='Europe/London', viewport={'width': 1280, 'height': 800})
        page = context.new_page()
        page_number = 1
        first_page_html = None
        cve_links = []
        is_complete = 1
        while True:
            url = f'https://www.cvedetails.com/vulnerability-list/year-{year}/month-{month_num}/{month_name}.html?page={page_number}&order=1'
            retry_count = 0
            while retry_count <= max_retries:
                try:
                    page.goto(url, timeout=60000, wait_until='domcontentloaded')
                    page.wait_for_selector('body', timeout=10000)
                    break
                except:
                    retry_count += 1
                    if retry_count > max_retries:
                        print(f'[{timestamp}]     ✗ Gave up after {max_retries} retries for {url}')
                        is_complete = 0
                        break
                    wait_time = 2 ** retry_count + random.uniform(0, 2)
                    print(f'[{timestamp}]     → Retry {retry_count}/{max_retries} after {wait_time:.1f}s...')
                    time.sleep(wait_time)
            if retry_count > max_retries:
                break
            current_html = page.content()
            if page_number == 1:
                first_page_html = current_html
            elif current_html == first_page_html:
                print(f'[{timestamp}]     → Page {page_number} is same as page 1. Stop.')
                break
            links = page.query_selector_all('div.border-top.py-3.px-2.hover-bg-light h3.col-md-4.text-nowrap a')
            if not links:
                print(f'[{timestamp}]     → No CVEs found. Ending {month_name} {year}.')
                break
            for link in links:
                href = link.get_attribute('href')
                if href and '/cve/' in href:
                    full_url = f'https://www.cvedetails.com{href}'
                    cve_links.append(full_url)
            page_number += 1
            time.sleep(random.uniform(0.1, 0.3))
        cve_links = sorted(set(cve_links))
        month_data = {'metadata': args_dict['metadata'], 'year': year, 'month': month_num, 'month_name': month_name, 'is_complete': 1 if is_complete else 0, 'cve_links': cve_links}
        with open(month_output_path, 'w', encoding='utf-8') as f:
            json.dump(month_data, f, indent=2, ensure_ascii=False)
        browser.close()
    print(f'[{timestamp}] [+] Saved {len(cve_links)} CVEs to {month_output_path}')
    return (year, month_num, len(cve_links), is_complete)

def run_parallel(start_year, end_year, start_month, end_month, max_retries, output_dir, workers, timestamp):
    tasks = []
    for year in range(start_year, end_year + 1):
        m_start = start_month if year == start_year else 1
        m_end = end_month if year == end_year else 12
        for month in range(m_start, m_end + 1):
            tasks.append((year, month))
    args_dict = {'months': months, 'output_dir': output_dir, 'max_retries': max_retries, 'timestamp': timestamp, 'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36', 'metadata': {'timestamp': timestamp, 'start_year': start_year, 'end_year': end_year, 'start_month': start_month, 'end_month': end_month}}
    print(f'[{timestamp}] [+] Starting parallel CVE scraping with {workers} workers')
    print(f'[{timestamp}] [+] Processing {len(tasks)} months from {start_year}-{start_month} to {end_year}-{end_month}')
    print(f'[{timestamp}] [+] Results will be saved in: {output_dir}/YEAR/MONTH.json')
    with ProcessPoolExecutor(max_workers=workers) as executor:
        futures = [executor.submit(scrape_one_month, (y, m, args_dict)) for y, m in tasks]
        completed = 0
        total_cves = 0
        for future in as_completed(futures):
            y, m, n, ok = future.result()
            completed += 1
            total_cves += n
            status = '✓' if ok else '✗'
            print(f'[{timestamp}] [{status}] Completed {y}-{m:02d}: {n} CVEs ({completed}/{len(tasks)} months done)')
    print(f'[{timestamp}] [+] All done! Total: {total_cves} CVEs across {len(tasks)} months')

def scrape_cve_links(start_year, end_year, start_month, end_month, max_retries, output_dir, headless, timestamp):
    metadata = {'timestamp': timestamp, 'start_year': start_year, 'end_year': end_year, 'start_month': start_month, 'end_month': end_month}
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True, args=['--disable-blink-features=AutomationControlled', '--no-sandbox'])
        context = browser.new_context(user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36', locale='en-GB', timezone_id='Europe/London', viewport={'width': 1280, 'height': 800})
        page = context.new_page()
        print(f'[{timestamp}] [+] Starting CVE scraping for {start_year}-{start_month} to {end_year}-{end_month}')
        print(f'[{timestamp}] [+] Monthly results will be saved in folder: {output_dir}/YEAR/MONTH.json')
        for year in range(start_year, end_year + 1):
            year_dir = os.path.join(output_dir, str(year))
            os.makedirs(year_dir, exist_ok=True)
            month_start = start_month if year == start_year else 1
            month_end = end_month if year == end_year else 12
            for month_num in range(month_start, month_end + 1):
                month_name = months[month_num - 1]
                print(f'[{timestamp}] [*] Processing {month_name} {year}...')
                page_number = 1
                first_page_html = None
                cve_links = []
                is_complete = 1
                while True:
                    url = f'https://www.cvedetails.com/vulnerability-list/year-{year}/month-{month_num}/{month_name}.html?page={page_number}&order=1'
                    retry_count = 0
                    while retry_count <= max_retries:
                        try:
                            page.goto(url, timeout=60000)
                            page.wait_for_selector('#searchresults', timeout=10000)
                            break
                        except:
                            retry_count += 1
                            if retry_count > max_retries:
                                print(f'[{timestamp}]     ✗ Gave up after {max_retries} retries for {url}')
                                is_complete = 0
                                break
                            wait_time = 2 ** retry_count + random.uniform(0, 2)
                            print(f'[{timestamp}]     → Retry {retry_count}/{max_retries} after {wait_time:.1f}s...')
                            time.sleep(wait_time)
                    if retry_count > max_retries:
                        break
                    current_html = page.content()
                    if page_number == 1:
                        first_page_html = current_html
                    elif current_html == first_page_html:
                        print(f'[{timestamp}]     → Page {page_number} is same as page 1. Stop.')
                        break
                    links = page.query_selector_all('div.border-top.py-3.px-2.hover-bg-light h3.col-md-4.text-nowrap a')
                    if not links:
                        print(f'[{timestamp}]     → No CVEs found. Ending {month_name} {year}.')
                        break
                    for link in links:
                        href = link.get_attribute('href')
                        if href and '/cve/' in href:
                            full_url = f'https://www.cvedetails.com{href}'
                            if full_url not in cve_links:
                                cve_links.append(full_url)
                                print(f'[{timestamp}]         ✓ Found CVE: {full_url}')
                    page_number += 1
                    time.sleep(random.uniform(0.5, 1.0))
                month_data = {'metadata': metadata, 'year': year, 'month': month_num, 'month_name': month_name, 'is_complete': 1 if is_complete else 0, 'cve_links': cve_links}
                month_output_path = os.path.join(year_dir, f'{month_num:02d}.json')
                with open(month_output_path, 'w', encoding='utf-8') as f:
                    json.dump(month_data, f, indent=2, ensure_ascii=False)
                print(f'[{timestamp}] [+] Saved {len(cve_links)} CVEs to {month_output_path}')
        browser.close()

def parse_args():
    parser = argparse.ArgumentParser(description='Scrape CVE links from CVEdetails.com using Playwright', formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('--start-year', type=int, default=2015, help='Starting year for CVE scraping')
    parser.add_argument('--end-year', type=int, default=2025, help='Ending year for CVE scraping')
    parser.add_argument('--start-month', type=int, default=1, choices=range(1, 13), metavar='[1-12]', help='Starting month (1-12)')
    parser.add_argument('--end-month', type=int, default=12, choices=range(1, 13), metavar='[1-12]', help='Ending month (1-12)')
    parser.add_argument('--max-retries', type=int, default=5, help='Maximum number of retries for failed requests')
    parser.add_argument('--output-dir', type=str, default=None, help='Output directory for scraped data (default: ../CVEdetails_scrape_result_playwright_TIMESTAMP)')
    parser.add_argument('--headless', action='store_true', help='Run browser in headless mode')
    parser.add_argument('--parallel', action='store_true', help='Enable parallel processing (multi-process, recommended for large date ranges)')
    parser.add_argument('--workers', type=int, default=6, help='Number of parallel workers (only used with --parallel)')
    return parser.parse_args()
if __name__ == '__main__':
    args = parse_args()
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    output_dir = args.output_dir if args.output_dir else f'../CVEdetails_scrape_result_playwright_{timestamp}'
    os.makedirs(output_dir, exist_ok=True)
    if args.parallel:
        run_parallel(start_year=args.start_year, end_year=args.end_year, start_month=args.start_month, end_month=args.end_month, max_retries=args.max_retries, output_dir=output_dir, workers=args.workers, timestamp=timestamp)
    else:
        scrape_cve_links(start_year=args.start_year, end_year=args.end_year, start_month=args.start_month, end_month=args.end_month, max_retries=args.max_retries, output_dir=output_dir, headless=args.headless, timestamp=timestamp)
