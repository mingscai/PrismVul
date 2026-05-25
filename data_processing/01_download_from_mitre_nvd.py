#!/usr/bin/env python3
import argparse
import shutil
import sys
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Dict
import requests
from tqdm import tqdm

def download_file(url: str, dest_path: Path, desc: str=None) -> bool:
    try:
        response = requests.get(url, stream=True, timeout=30)
        response.raise_for_status()
        total_size = int(response.headers.get('content-length', 0))
        with open(dest_path, 'wb') as f, tqdm(desc=desc or f'Downloading {dest_path.name}', total=total_size, unit='B', unit_scale=True, unit_divisor=1024) as pbar:
            for chunk in response.iter_content(chunk_size=8192):
                if chunk:
                    f.write(chunk)
                    pbar.update(len(chunk))
        return True
    except requests.exceptions.RequestException as e:
        print(f'Error downloading {url}: {e}', file=sys.stderr)
        return False

def extract_zip(zip_path: Path, extract_to: Path) -> Dict[str, int]:
    stats = {'files': 0, 'dirs': 0, 'total_size': 0}
    try:
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            members = zip_ref.namelist()
            with tqdm(total=len(members), desc=f'Extracting {zip_path.name}') as pbar:
                for member in members:
                    zip_ref.extract(member, extract_to)
                    pbar.update(1)
                    extracted_path = extract_to / member
                    if extracted_path.is_file():
                        stats['files'] += 1
                        stats['total_size'] += extracted_path.stat().st_size
                    elif extracted_path.is_dir():
                        stats['dirs'] += 1
        return stats
    except zipfile.BadZipFile as e:
        print(f'Error extracting {zip_path}: {e}', file=sys.stderr)
        return stats

def download_mitre(base_path: Path) -> Dict:
    print('\n=== Downloading MITRE CVE Data ===')
    mitre_url = 'https://github.com/CVEProject/cvelistV5/archive/refs/heads/main.zip'
    mitre_dir = base_path / 'mitre'
    mitre_dir.mkdir(parents=True, exist_ok=True)
    zip_path = mitre_dir / 'cvelistV5-main.zip'
    temp_extract_dir = mitre_dir / 'temp_extract'
    print(f'Downloading from: {mitre_url}')
    if not download_file(mitre_url, zip_path, 'Downloading MITRE CVE data'):
        return {'success': False, 'error': 'Download failed'}
    print(f'Extracting to temporary directory...')
    temp_extract_dir.mkdir(exist_ok=True)
    extract_stats = extract_zip(zip_path, temp_extract_dir)
    zip_path.unlink()
    cves_dir = temp_extract_dir / 'cvelistV5-main' / 'cves'
    if not cves_dir.exists():
        shutil.rmtree(temp_extract_dir)
        return {'success': False, 'error': 'CVEs directory not found in extracted archive'}
    print(f'Moving year folders to {mitre_dir}...')
    year_folders = [d for d in cves_dir.iterdir() if d.is_dir() and d.name.isdigit()]
    for year_folder in tqdm(year_folders, desc='Moving year folders'):
        dest = mitre_dir / year_folder.name
        if dest.exists():
            shutil.rmtree(dest)
        shutil.move(str(year_folder), str(dest))
    shutil.rmtree(temp_extract_dir)
    cve_files = list(mitre_dir.rglob('CVE-*.json'))
    year_dirs = [d for d in mitre_dir.iterdir() if d.is_dir() and d.name.isdigit()]
    total_size = sum((f.stat().st_size for f in cve_files))
    stats = {'success': True, 'download_url': mitre_url, 'destination': str(mitre_dir), 'year_folders': len(year_dirs), 'years_range': f'{min((d.name for d in year_dirs))}-{max((d.name for d in year_dirs))}' if year_dirs else 'N/A', 'cve_files': len(cve_files), 'total_size_mb': total_size / (1024 * 1024)}
    return stats

def download_nvd(base_path: Path, start_year: int=2002) -> Dict:
    print('\n=== Downloading NVD CVE Data ===')
    current_year = datetime.now().year
    nvd_dir = base_path / 'nvd'
    nvd_dir.mkdir(parents=True, exist_ok=True)
    stats = {'success': True, 'years': [], 'failed_years': [], 'total_files': 0, 'total_size_mb': 0, 'destination': str(nvd_dir)}
    for year in range(start_year, current_year + 1):
        url = f'https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{year}.json.zip'
        zip_path = nvd_dir / f'nvdcve-2.0-{year}.json.zip'
        print(f'\nProcessing year {year}...')
        print(f'URL: {url}')
        if not download_file(url, zip_path, f'Downloading NVD {year}'):
            print(f'Warning: Failed to download data for year {year}')
            stats['failed_years'].append(year)
            continue
        extract_stats = extract_zip(zip_path, nvd_dir)
        if extract_stats['files'] > 0:
            stats['years'].append(year)
            stats['total_files'] += extract_stats['files']
            stats['total_size_mb'] += extract_stats['total_size'] / (1024 * 1024)
        else:
            stats['failed_years'].append(year)
        zip_path.unlink()
    if not stats['years']:
        stats['success'] = False
        stats['error'] = 'No data downloaded successfully'
    return stats

def print_summary(mitre_stats: Dict=None, nvd_stats: Dict=None):
    print('\n' + '=' * 60)
    print('DOWNLOAD SUMMARY')
    print('=' * 60)
    if mitre_stats:
        print('\n--- MITRE CVE Data ---')
        if mitre_stats.get('success'):
            print(f'✓ Successfully downloaded and extracted')
            print(f"  Destination: {mitre_stats['destination']}")
            print(f"  Year folders: {mitre_stats['year_folders']} ({mitre_stats['years_range']})")
            print(f"  CVE files: {mitre_stats['cve_files']:,}")
            print(f"  Total size: {mitre_stats['total_size_mb']:.2f} MB")
        else:
            print(f"✗ Failed: {mitre_stats.get('error', 'Unknown error')}")
    if nvd_stats:
        print('\n--- NVD CVE Data ---')
        if nvd_stats.get('success'):
            print(f'✓ Successfully downloaded and extracted')
            print(f"  Destination: {nvd_stats['destination']}")
            print(f"  Years covered: {len(nvd_stats['years'])} ({min(nvd_stats['years'])}-{max(nvd_stats['years'])})")
            print(f"  Total files: {nvd_stats['total_files']:,}")
            print(f"  Total size: {nvd_stats['total_size_mb']:.2f} MB")
            if nvd_stats['failed_years']:
                print(f"  ⚠ Failed years: {', '.join(map(str, nvd_stats['failed_years']))}")
        else:
            print(f"✗ Failed: {nvd_stats.get('error', 'Unknown error')}")
    print('\n' + '=' * 60)

def main():
    parser = argparse.ArgumentParser(description='Download CVE data from MITRE and/or NVD', formatter_class=argparse.RawDescriptionHelpFormatter, epilog='\nExamples:\n  %(prog)s --path ./data                              # Download both MITRE and NVD\n  %(prog)s --source mitre --path ./data               # Download only MITRE\n  %(prog)s --source nvd --path ./data                 # Download only NVD\n  %(prog)s --source nvd --path ./data --start-year 2020  # NVD from 2020 onwards\n        ')
    parser.add_argument('--source', choices=['mitre', 'nvd', 'both'], default='both', help='Data source to download from (default: both)')
    parser.add_argument('--path', type=str, required=True, help='Base directory to save downloaded data')
    parser.add_argument('--start-year', type=int, default=2002, help='Starting year for NVD data (default: 2002)')
    args = parser.parse_args()
    base_path = Path(args.path).resolve()
    base_path.mkdir(parents=True, exist_ok=True)
    print(f'Base directory: {base_path}')
    print(f'Source: {args.source}')
    mitre_stats = None
    nvd_stats = None
    if args.source in ['mitre', 'both']:
        mitre_stats = download_mitre(base_path)
    if args.source in ['nvd', 'both']:
        nvd_stats = download_nvd(base_path, args.start_year)
    print_summary(mitre_stats, nvd_stats)
    success = True
    if mitre_stats and (not mitre_stats.get('success')):
        success = False
    if nvd_stats and (not nvd_stats.get('success')):
        success = False
    sys.exit(0 if success else 1)
if __name__ == '__main__':
    main()
