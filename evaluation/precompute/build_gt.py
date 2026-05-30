import argparse
import json
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parents[1]))
from utils.dataset import load_records, load_split_ids, filter_by_ids, build_all_instances, filter_records

def write_gt(instances: list[dict], out_path: Path, label: str):
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, 'w') as f:
        for inst in instances:
            f.write(json.dumps(inst, ensure_ascii=False) + '\n')
    print(f'  [{label}] {len(instances)} instances → {out_path}')

def prepare_records(input_path: str, no_filter: bool, use_chained: bool):
    records = load_records(input_path)
    if not no_filter:
        records, _ = filter_records(records, verbose=False, use_chained=use_chained)
    return records

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--input', default='data/chromium_cve_data.jsonl')
    ap.add_argument('--split-dir', default='data/splits', help='Directory with train_ids.txt / val_ids.txt / test_ids.txt')
    ap.add_argument('--split', default='test', choices=['train', 'val', 'test', 'all'])
    ap.add_argument('--target', default='root_cause_vulnerable', choices=['root_cause_vulnerable', 'related', 'all'])
    ap.add_argument('--output', default='data/ground_truth/chromium_root_cause.jsonl')
    ap.add_argument('--all-targets', action='store_true', help='Generate both root_cause and related GT files (ignores --target and --output)')
    ap.add_argument('--no-filter', action='store_true', help='Skip data quality filtering (must match build_splits.py)')
    ap.add_argument('--per-commit', action='store_true', help='Use legacy per-commit instances (src_commits) instead of chain-level (src_commits_chained).')
    args = ap.parse_args()
    use_chained = not args.per_commit
    print(f"Mode: {('chain-level' if use_chained else 'per-commit (legacy)')}")
    train_ids, val_ids, test_ids = (set(), set(), set())
    if args.split != 'all':
        train_ids, val_ids, test_ids = load_split_ids(args.split_dir)
    split_map = {'train': train_ids, 'val': val_ids, 'test': test_ids}
    base_records = prepare_records(args.input, args.no_filter, use_chained)

    def _build_for_target(target: str, out_path: Path, label: str):
        records = base_records
        if args.split != 'all':
            records = filter_by_ids(records, split_map[args.split])
        instances = build_all_instances(records, target=target, use_chained=use_chained)
        write_gt(instances, out_path, label)
    if args.all_targets:
        out_dir = Path(args.output).parent
        print(f'Generating ground truth for both targets ({args.split} split):')
        _build_for_target('root_cause_vulnerable', out_dir / 'chromium_root_cause.jsonl', 'root_cause_vulnerable')
        _build_for_target('related', out_dir / 'chromium_related.jsonl', 'related')
    else:
        _build_for_target(args.target, Path(args.output), args.target)
if __name__ == '__main__':
    main()
