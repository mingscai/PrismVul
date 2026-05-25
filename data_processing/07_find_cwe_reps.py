#!/usr/bin/env python3
import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from collections import defaultdict
import argparse
from tqdm import tqdm
NS = 'http://cwe.mitre.org/cwe-7'

def load_cwe_catalog(xml_path: Path):
    tree = ET.parse(xml_path)
    root = tree.getroot()
    catalog = {}
    parents_1000 = defaultdict(list)
    for w in root.iter(f'{{{NS}}}Weakness'):
        cid = w.get('ID')
        name = w.get('Name', '')
        desc_el = w.find(f'{{{NS}}}Description')
        desc = re.sub('\\s+', ' ', desc_el.text.strip()) if desc_el is not None and desc_el.text else ''
        ext_el = w.find(f'{{{NS}}}Extended_Description')
        desc_ext = re.sub('\\s+', ' ', ext_el.text.strip()) if ext_el is not None and ext_el.text else ''
        catalog[cid] = {'name': name, 'desc': desc, 'desc_ext': desc_ext}
        rw = w.find(f'{{{NS}}}Related_Weaknesses')
        if rw is not None:
            for r in rw.findall(f'{{{NS}}}Related_Weakness'):
                if r.get('Nature') == 'ChildOf' and r.get('View_ID') == '1000':
                    parents_1000[cid].append(r.get('CWE_ID'))
    cat_catalog = {}
    member_of_699 = defaultdict(list)
    for c in root.iter(f'{{{NS}}}Category'):
        cat_id = c.get('ID')
        cat_name = c.get('Name', '')
        summary_el = c.find(f'{{{NS}}}Summary')
        cat_desc = re.sub('\\s+', ' ', summary_el.text.strip()) if summary_el is not None and summary_el.text else ''
        cat_catalog[cat_id] = {'name': cat_name, 'desc': cat_desc, 'desc_ext': ''}
        rels = c.find(f'{{{NS}}}Relationships')
        if rels is not None:
            for m in rels.findall(f'{{{NS}}}Has_Member'):
                if m.get('View_ID') == '699':
                    member_of_699[m.get('CWE_ID')].append(cat_id)
    all_1000 = set(parents_1000.keys()) | {p for plist in parents_1000.values() for p in plist}
    roots_1000 = all_1000 - set(parents_1000.keys())
    return (catalog, cat_catalog, dict(parents_1000), roots_1000, dict(member_of_699))

def get_all_paths(cid: str, parents_map: dict, visited: frozenset=frozenset()) -> list:
    if cid in visited:
        return []
    visited = visited | {cid}
    if cid not in parents_map or not parents_map[cid]:
        return [[cid]]
    paths = []
    for pid in parents_map[cid]:
        for path in get_all_paths(pid, parents_map, visited):
            paths.append([cid] + path)
    return paths if paths else [[cid]]

def find_cwe_reps(cwe_num: str, parents_1000: dict, roots_1000: set, member_of_699: dict, catalog: dict, cat_catalog: dict) -> list:
    all_kept_paths = []
    paths = get_all_paths(cwe_num, parents_1000)
    if not paths:
        paths = [[cwe_num]]
    for path in paths:
        top = path[-1]
        if top in roots_1000 or len(path) == 1:
            full_path = path + ['1000']
            rep = full_path[-2] if len(full_path) > 2 else cwe_num
            prefixed = [f'CWE-{x}' for x in full_path]
            all_kept_paths.append((rep, prefixed, False))
    seen_699 = set()
    for path in paths:
        for i, node in enumerate(path):
            for cat_id in member_of_699.get(node, []):
                key = (node, cat_id)
                if key in seen_699:
                    continue
                seen_699.add(key)
                sub_path = [f'CWE-{x}' for x in path[:i + 1]] + [f'CWE-{cat_id}', 'CWE-699']
                all_kept_paths.append((cat_id, sub_path, True))
    if not all_kept_paths:
        all_kept_paths.append((cwe_num, [f'CWE-{cwe_num}'], False))
    rep_map = defaultdict(list)
    rep_is_cat = {}
    for rep_id, path, is_cat in all_kept_paths:
        rep_map[rep_id].append(path)
        rep_is_cat[rep_id] = is_cat
    result = []
    seen_reps = set()
    for rep_id, paths in rep_map.items():
        if rep_id in seen_reps:
            continue
        seen_reps.add(rep_id)
        unique_paths = list({tuple(p): p for p in paths}.values())
        info = cat_catalog.get(rep_id, {}) if rep_is_cat.get(rep_id) else catalog.get(rep_id, {})
        result.append({'id': f'CWE-{rep_id}', 'name': info.get('name', ''), 'desc': info.get('desc', ''), 'desc_ext': info.get('desc_ext', ''), 'hierarchies': unique_paths})
    return result

def main():
    parser = argparse.ArgumentParser(description='Find CWE representative nodes for each CVE')
    parser.add_argument('--input', default='data/processing/chromium_cve_data.jsonl')
    parser.add_argument('--output', default='data/processing/chromium_cve_data.jsonl')
    parser.add_argument('--cwe-xml', default='data/raw_cwes/cwec_v4.19.1.xml')
    args = parser.parse_args()
    print(f'Loading CWE catalog from {args.cwe_xml} ...')
    catalog, cat_catalog, parents_1000, roots_1000, member_of_699 = load_cwe_catalog(Path(args.cwe_xml))
    print(f'  Loaded {len(catalog):,} weakness entries, {len(cat_catalog):,} view-699 categories')
    print(f'  View 1000 roots: {sorted(roots_1000, key=int)}')
    input_path = Path(args.input)
    output_path = Path(args.output)
    tmp_path = output_path.with_suffix('.tmp')
    total = processed = skipped = 0
    print(f'Processing {input_path} ...')
    with open(input_path) as fin, open(tmp_path, 'w') as fout:
        for line in tqdm(fin):
            total += 1
            d = json.loads(line)
            cwe_id = d.get('cwe_id', '')
            cwe_num = cwe_id.replace('CWE-', '').strip() if cwe_id.startswith('CWE-') else ''
            if cwe_num and cwe_num in catalog:
                cwe_reps = find_cwe_reps(cwe_num, parents_1000, roots_1000, member_of_699, catalog, cat_catalog)
                processed += 1
            else:
                cwe_reps = []
                if cwe_id:
                    skipped += 1
            ordered = {}
            inserted = False
            for k, v in d.items():
                if k == 'cwe_reps':
                    continue
                ordered[k] = v
                if k == 'cwe_desc_ext' and (not inserted):
                    ordered['cwe_reps'] = cwe_reps
                    inserted = True
            if not inserted:
                ordered2 = {}
                for k, v in ordered.items():
                    ordered2[k] = v
                    if k == 'cwe_desc' and (not inserted):
                        ordered2['cwe_reps'] = cwe_reps
                        inserted = True
                ordered = ordered2
            if not inserted:
                ordered['cwe_reps'] = cwe_reps
            fout.write(json.dumps(ordered, ensure_ascii=False) + '\n')
    tmp_path.replace(output_path)
    print(f'\nDone! Processed {total:,} CVEs')
    print(f'  CWE reps found:        {processed:,}')
    print(f'  CWE ID not in catalog: {skipped:,}')
if __name__ == '__main__':
    main()
