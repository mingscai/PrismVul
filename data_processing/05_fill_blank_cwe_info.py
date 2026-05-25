#!/usr/bin/env python3
import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path
import argparse
from tqdm import tqdm
NS = 'http://cwe.mitre.org/cwe-7'

def load_cwe_catalog(xml_path: Path) -> dict:
    print(f'Parsing CWE catalog: {xml_path.name} ...')
    tree = ET.parse(xml_path)
    root = tree.getroot()
    catalog = {}
    for weakness in root.iter(f'{{{NS}}}Weakness'):
        cwe_num = weakness.get('ID', '')
        cwe_name = weakness.get('Name', '')
        desc_el = weakness.find(f'{{{NS}}}Description')
        cwe_desc = desc_el.text.strip() if desc_el is not None and desc_el.text else ''
        cwe_desc = re.sub('\\s+', ' ', cwe_desc)
        ext_el = weakness.find(f'{{{NS}}}Extended_Description')
        cwe_desc_ext = ext_el.text.strip() if ext_el is not None and ext_el.text else ''
        cwe_desc_ext = re.sub('\\s+', ' ', cwe_desc_ext)
        catalog[f'CWE-{cwe_num}'] = {'name': cwe_name, 'desc': cwe_desc, 'desc_ext': cwe_desc_ext}
    print(f'  Loaded {len(catalog):,} CWE entries')
    return catalog

def main():
    parser = argparse.ArgumentParser(description='Fill missing CWE name/desc from official XML catalog')
    parser.add_argument('--input', default='data/processing/all_cve_data.jsonl')
    parser.add_argument('--output', default='data/processing/all_cve_data.jsonl')
    parser.add_argument('--cwe-xml', default='data/raw_cwes/cwec_v4.19.1.xml')
    args = parser.parse_args()
    catalog = load_cwe_catalog(Path(args.cwe_xml))
    input_path = Path(args.input)
    output_path = Path(args.output)
    tmp_path = output_path.with_suffix('.tmp')
    filled_name = filled_desc = skipped = total = 0
    print(f'Processing {input_path} ...')
    with open(input_path) as fin, open(tmp_path, 'w') as fout:
        for line in tqdm(fin):
            total += 1
            d = json.loads(line)
            cwe_id = d.get('cwe_id', '')
            if cwe_id and cwe_id in catalog:
                entry = catalog[cwe_id]
                if not d.get('cwe_name') and entry['name']:
                    d['cwe_name'] = entry['name']
                    filled_name += 1
                if not d.get('cwe_desc') and entry['desc']:
                    d['cwe_desc'] = entry['desc']
                    filled_desc += 1
                if entry['desc_ext']:
                    ordered = {}
                    for k, v in d.items():
                        ordered[k] = v
                        if k == 'cwe_desc':
                            ordered['cwe_desc_ext'] = d.get('cwe_desc_ext') or entry['desc_ext']
                    d = ordered
                elif 'cwe_desc_ext' not in d:
                    ordered = {}
                    for k, v in d.items():
                        ordered[k] = v
                        if k == 'cwe_desc':
                            ordered['cwe_desc_ext'] = ''
                    d = ordered
            elif cwe_id:
                skipped += 1
                if 'cwe_desc_ext' not in d:
                    ordered = {}
                    for k, v in d.items():
                        ordered[k] = v
                        if k == 'cwe_desc':
                            ordered['cwe_desc_ext'] = ''
                    d = ordered
            fout.write(json.dumps(d, ensure_ascii=False) + '\n')
    tmp_path.replace(output_path)
    print(f'\nDone! Processed {total:,} CVEs')
    print(f'  Filled cwe_name: {filled_name:,}')
    print(f'  Filled cwe_desc: {filled_desc:,}')
    print(f'  CWE ID not in catalog: {skipped:,}')
if __name__ == '__main__':
    main()
