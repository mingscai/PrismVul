#!/usr/bin/env python3
import json
import re
from pathlib import Path
from typing import Dict, Any, Optional
import argparse
from tqdm import tqdm

def _first_en(descriptions: list) -> str:
    for d in descriptions:
        if d.get('lang') == 'en':
            return d.get('value', '')
    return descriptions[0].get('value', '') if descriptions else ''

def _pick_cvss(entries: list) -> Optional[Dict]:
    if not entries:
        return None
    for e in entries:
        if e.get('type') == 'Primary':
            return e
    return entries[0]

def _parse_epss_score(raw: str) -> Optional[float]:
    if not raw:
        return None
    try:
        return round(float(raw.strip().rstrip('%')) / 100, 6)
    except ValueError:
        return None

def _parse_epss_percentile(raw: str) -> Optional[float]:
    if not raw:
        return None
    m = re.search('[\\d.]+', raw)
    if not m:
        return None
    try:
        return round(float(m.group()) / 100, 6)
    except ValueError:
        return None

def _mitre_state_to_status(state: str) -> str:
    return {'PUBLISHED': 'Published', 'REJECTED': 'Rejected'}.get(state.upper(), state.title())

def extract_mitre(raw: Dict) -> Dict:
    meta = raw.get('cveMetadata', {})
    cna = raw.get('containers', {}).get('cna', {})
    cwe_id = cwe_name = ''
    for pt in cna.get('problemTypes', []):
        for d in pt.get('descriptions', []):
            if d.get('type') == 'CWE' and d.get('cweId'):
                cwe_id = d['cweId']
                desc_text = d.get('description', '')
                cwe_name = desc_text.split(' ', 1)[1] if ' ' in desc_text else desc_text
                break
        if cwe_id:
            break
    refs = []
    for r in cna.get('references', []):
        entry = {'url': r.get('url', ''), 'source': 'MITRE'}
        if r.get('tags'):
            entry['tags'] = r['tags']
        refs.append(entry)
    return {'cve_id': meta.get('cveId', ''), 'cve_desc': _first_en(cna.get('descriptions', [])), 'vuln_status': _mitre_state_to_status(meta.get('state', '')), 'published_at': meta.get('datePublished', ''), 'last_modified_at': meta.get('dateUpdated', '') or meta.get('dateModified', ''), 'cwe_id': cwe_id, 'cwe_name': cwe_name, 'cna': cna.get('affected', []), 'references': refs}

def extract_nvd(raw: Dict) -> Dict:
    cve = raw.get('cve', {})
    metrics = cve.get('metrics', {})
    cwe_id = ''
    for w in cve.get('weaknesses', []):
        if w.get('type') == 'Primary':
            descs = w.get('description', [])
            if descs:
                cwe_id = descs[0].get('value', '')
            break
    if not cwe_id:
        for w in cve.get('weaknesses', []):
            descs = w.get('description', [])
            if descs:
                cwe_id = descs[0].get('value', '')
                break
    refs = []
    for r in cve.get('references', []):
        entry = {'url': r.get('url', ''), 'source': 'NVD'}
        if r.get('tags'):
            entry['tags'] = r['tags']
        refs.append(entry)
    return {'cve_id': cve.get('id', ''), 'cve_desc': _first_en(cve.get('descriptions', [])), 'vuln_status': cve.get('vulnStatus', ''), 'published_at': cve.get('published', ''), 'last_modified_at': cve.get('lastModified', ''), 'cwe_id': cwe_id, 'cvss_v31': _pick_cvss(metrics.get('cvssMetricV31', [])), 'cvss_v30': _pick_cvss(metrics.get('cvssMetricV30', [])), 'cvss_v2': _pick_cvss(metrics.get('cvssMetricV2', [])), 'cpe': cve.get('configurations', []), 'references': refs}

def extract_cvedetails(raw: Dict) -> Dict:
    cwes = raw.get('cwes', [])
    cwe_id = cwe_name = cwe_desc = ''
    if cwes:
        cwe_id = cwes[0].get('id', '')
        cwe_name = cwes[0].get('name', '')
        cwe_desc = cwes[0].get('description', '')
    epss = raw.get('epss', {})
    epss_score = _parse_epss_score(epss.get('score', ''))
    epss_percentile = _parse_epss_percentile(epss.get('percentile', ''))
    refs = [{'url': u, 'source': 'CVEDetails'} for u in raw.get('references', []) if u]
    return {'cve_id': raw.get('cve_id', ''), 'cve_title': raw.get('title', ''), 'cve_desc': raw.get('summary', ''), 'vuln_category': raw.get('category') or None, 'published_at': raw.get('published', ''), 'last_modified_at': raw.get('updated', ''), 'cwe_id': cwe_id, 'cwe_name': cwe_name, 'cwe_desc': cwe_desc, 'epss_score': epss_score, 'epss_percentile': epss_percentile, 'references': refs}

def merge_references(mitre_refs, nvd_refs, cvedetails_refs) -> list:
    seen: Dict[str, Dict] = {}
    for ref in (mitre_refs or []) + (nvd_refs or []) + (cvedetails_refs or []):
        url = ref.get('url', '')
        if not url:
            continue
        if url not in seen:
            seen[url] = {'url': url, 'tags': set(), 'sources': set()}
        seen[url]['tags'].update(ref.get('tags', []))
        if ref.get('source'):
            seen[url]['sources'].add(ref['source'])
    result = []
    for entry in seen.values():
        rec = {'url': entry['url'], 'sources': sorted(entry['sources'])}
        if entry['tags']:
            rec['tags'] = sorted(entry['tags'])
        result.append(rec)
    return result

def merge_cve(mitre: Optional[Dict], nvd: Optional[Dict], cvedetails: Optional[Dict]) -> Dict:
    m = mitre or {}
    n = nvd or {}
    c = cvedetails or {}

    def first(*vals):
        for v in vals:
            if v:
                return v
        return None
    return {'cve_id': first(n.get('cve_id'), m.get('cve_id'), c.get('cve_id')) or '', 'cve_title': c.get('cve_title') or '', 'cve_desc': first(n.get('cve_desc'), m.get('cve_desc'), c.get('cve_desc')) or '', 'vuln_status': first(n.get('vuln_status'), m.get('vuln_status')) or '', 'vuln_category': c.get('vuln_category'), 'published_at': first(n.get('published_at'), m.get('published_at'), c.get('published_at')) or '', 'last_modified_at': first(n.get('last_modified_at'), m.get('last_modified_at'), c.get('last_modified_at')) or '', 'cwe_id': first(m.get('cwe_id'), n.get('cwe_id'), c.get('cwe_id')) or '', 'cwe_name': first(c.get('cwe_name'), m.get('cwe_name')) or '', 'cwe_desc': c.get('cwe_desc') or '', 'cvss_v31': n.get('cvss_v31'), 'cvss_v30': n.get('cvss_v30'), 'cvss_v2': n.get('cvss_v2'), 'epss': {'score': c.get('epss_score'), 'percentile': c.get('epss_percentile')} if cvedetails else None, 'cna': m.get('cna') or [], 'cpe': n.get('cpe') or [], 'references': merge_references(m.get('references', []), n.get('references', []), c.get('references', []))}

def load_mitre(base_path: Path) -> Dict[str, Dict]:
    print('Loading MITRE data...')
    data = {}
    for year_dir in sorted(base_path.glob('*')):
        if not year_dir.is_dir():
            continue
        for f in year_dir.rglob('*.json'):
            try:
                raw = json.loads(f.read_text())
                rec = extract_mitre(raw)
                if rec['cve_id']:
                    data[rec['cve_id']] = rec
            except Exception as e:
                print(f'  [MITRE] Error {f}: {e}')
    print(f'  Loaded {len(data):,} CVEs')
    return data

def load_nvd(base_path: Path) -> Dict[str, Dict]:
    print('Loading NVD data...')
    data = {}
    for nvd_file in sorted(base_path.glob('nvdcve-2.0-*.json')):
        try:
            raw = json.loads(nvd_file.read_text())
            for vuln in tqdm(raw.get('vulnerabilities', []), desc=f'  {nvd_file.name}', leave=False):
                rec = extract_nvd(vuln)
                if rec['cve_id']:
                    data[rec['cve_id']] = rec
        except Exception as e:
            print(f'  [NVD] Error {nvd_file}: {e}')
    print(f'  Loaded {len(data):,} CVEs')
    return data

def load_cvedetails(base_path: Path) -> Dict[str, Dict]:
    print('Loading CVEDetails data...')
    data = {}
    for year_dir in sorted(base_path.glob('*')):
        if not year_dir.is_dir():
            continue
        for details_file in year_dir.glob('*_details.json'):
            try:
                raw = json.loads(details_file.read_text())
                for cve_data in raw.get('cves', {}).values():
                    rec = extract_cvedetails(cve_data)
                    if rec['cve_id']:
                        data[rec['cve_id']] = rec
            except Exception as e:
                print(f'  [CVEDetails] Error {details_file}: {e}')
    print(f'  Loaded {len(data):,} CVEs')
    return data

def main():
    parser = argparse.ArgumentParser(description='Merge CVE data from MITRE, NVD, and CVEDetails')
    parser.add_argument('--raw-dir', default='data/raw_cves')
    parser.add_argument('--output', default='data/processing/merged_cve_data.jsonl')
    parser.add_argument('--year-start', type=int)
    parser.add_argument('--year-end', type=int)
    args = parser.parse_args()
    raw_dir = Path(args.raw_dir)
    mitre_data = load_mitre(raw_dir / 'mitre')
    nvd_data = load_nvd(raw_dir / 'nvd')
    cvedetails_data = load_cvedetails(raw_dir / 'cvedetails')
    all_ids = set(mitre_data) | set(nvd_data) | set(cvedetails_data)
    print(f'\nTotal unique CVEs: {len(all_ids):,}')
    if args.year_start or args.year_end:

        def in_range(cid):
            try:
                y = int(cid.split('-')[1])
                if args.year_start and y < args.year_start:
                    return False
                if args.year_end and y > args.year_end:
                    return False
                return True
            except Exception:
                return False
        all_ids = {cid for cid in all_ids if in_range(cid)}
        print(f'Filtered to {len(all_ids):,} CVEs ({args.year_start}-{args.year_end})')
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    print(f'\nMerging → {output_path}')
    with open(output_path, 'w') as f:
        for cve_id in tqdm(sorted(all_ids)):
            merged = merge_cve(mitre_data.get(cve_id), nvd_data.get(cve_id), cvedetails_data.get(cve_id))
            f.write(json.dumps(merged, ensure_ascii=False) + '\n')
    print(f'\nDone! Wrote {len(all_ids):,} CVEs')
    in_m = set(mitre_data) & all_ids
    in_n = set(nvd_data) & all_ids
    in_c = set(cvedetails_data) & all_ids
    print(f'  MITRE only:       {len(in_m - in_n - in_c):,}')
    print(f'  NVD only:         {len(in_n - in_m - in_c):,}')
    print(f'  CVEDetails only:  {len(in_c - in_m - in_n):,}')
    print(f'  All three:        {len(in_m & in_n & in_c):,}')
if __name__ == '__main__':
    main()
