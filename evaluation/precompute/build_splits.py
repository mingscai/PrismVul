import argparse
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parents[1]))
from utils.dataset import load_records, filter_records, split_records, save_split_ids

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--input', default='data/chromium_cve_data.jsonl')
    ap.add_argument('--out-dir', default='data/splits')
    ap.add_argument('--train', type=float, default=0.7)
    ap.add_argument('--val', type=float, default=0.1)
    ap.add_argument('--test', type=float, default=0.2)
    ap.add_argument('--seed', type=int, default=42)
    ap.add_argument('--no-sort-date', action='store_true')
    ap.add_argument('--no-filter', action='store_true', help='Skip data quality filtering (use full dataset)')
    ap.add_argument('--per-commit', action='store_true', help='Use legacy per-commit (src_commits) filter instead of chain-level (src_commits_chained).')
    args = ap.parse_args()
    use_chained = not args.per_commit
    records = load_records(args.input)
    print(f'Loaded {len(records)} records from {args.input}')
    print(f"Filter mode: {('chain-level' if use_chained else 'per-commit (legacy)')}")
    if not args.no_filter:
        records, _ = filter_records(records, use_chained=use_chained)
    train, val, test = split_records(records, train_ratio=args.train, val_ratio=args.val, test_ratio=args.test, random_state=args.seed, sort_by_date=not args.no_sort_date)
    save_split_ids(train, val, test, args.out_dir)
    print(f'Train: {len(train)}  Val: {len(val)}  Test: {len(test)}')
if __name__ == '__main__':
    main()
