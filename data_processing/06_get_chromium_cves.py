#!/usr/bin/env python3
import json
from pathlib import Path
import argparse
from tqdm import tqdm

def is_chrome_cna(cna: list) -> bool:
    for item in cna:
        vendor = item.get('vendor', '').lower()
        product = item.get('product', '').lower()
        if 'google' in vendor and 'chrome' in product:
            return True
    return False

def is_chrome_cpe(cpe: list) -> bool:
    for node in cpe:
        for n in node.get('nodes', []):
            for match in n.get('cpeMatch', []):
                if 'google:chrome' in match.get('criteria', '').lower():
                    return True
    return False

def main():
    parser = argparse.ArgumentParser(description='Filter Chromium CVEs')
    parser.add_argument('--input', default='data/processing/all_cve_data.jsonl')
    parser.add_argument('--output', default='data/processing/chromium_cve_data.jsonl')
    args = parser.parse_args()
    input_path = Path(args.input)
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    total = matched = 0
    match_cna = match_cpe = match_both = 0
    with open(input_path) as fin, open(output_path, 'w') as fout:
        for line in tqdm(fin, desc='Filtering'):
            total += 1
            d = json.loads(line)
            hit_cna = is_chrome_cna(d.get('cna', []))
            hit_cpe = is_chrome_cpe(d.get('cpe', []))
            if hit_cna or hit_cpe:
                matched += 1
                if hit_cna:
                    match_cna += 1
                if hit_cpe:
                    match_cpe += 1
                if hit_cna and hit_cpe:
                    match_both += 1
                fout.write(json.dumps(d, ensure_ascii=False) + '\n')
    print(f'\nTotal CVEs scanned: {total:,}')
    print(f'Chromium CVEs found: {matched:,}')
    print(f'  Matched via CNA:  {match_cna:,}')
    print(f'  Matched via CPE:  {match_cpe:,}')
    print(f'  Matched via both: {match_both:,}')
    print(f'\nOutput: {output_path}')
if __name__ == '__main__':
    main()
