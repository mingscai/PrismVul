import argparse
import hashlib
import json
import multiprocessing as mp
import sys
import time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parents[1]))
from utils.dataset import load_records, load_split_ids, filter_by_ids
from utils.metrics import build_gt_index, full_evaluation_pipeline, print_overall, save_metrics
from utils.agent_runner import WorktreeManager, load_system_prompt, load_task_template, render_task_prompt, run_agent_on_instance
VARIANT_MAP = {'cve_desc_restated': 'post', 'cve_desc': 'raw', 'issue_summary': 'pre', 'issue_description': 'pre_desc'}

def _parse_args():
    ap = argparse.ArgumentParser()
    ap.add_argument('--input', required=True, help='CVE dataset JSONL')
    ap.add_argument('--split-dir', required=True, help='Dir with train/val/test id files')
    ap.add_argument('--test-field', required=True, choices=['cve_desc_restated', 'cve_desc', 'issue_summary', 'issue_description'], help='Text field fed to the agent')
    ap.add_argument('--target', required=True, choices=['root_cause_vulnerable', 'related'], help='GT class to score against')
    ap.add_argument('--pred-dir', help='Output dir for predictions')
    ap.add_argument('--metrics-dir', help='Output dir for metrics')
    ap.add_argument('--repo-path', required=True, help='Path to the target git repo')
    ap.add_argument('--model', default='openai/gpt-5-mini', help='Agent model id')
    ap.add_argument('--step-limit', type=int, default=30, help='Max agent steps per instance')
    ap.add_argument('--cost-limit', type=float, default=3.0, help='Max USD cost per instance')
    ap.add_argument('--cmd-timeout', type=int, default=30, help='Per-command timeout (s)')
    ap.add_argument('--max-instances', type=int, default=0, help='0 = all; cap for smoke tests')
    ap.add_argument('--instance-ids', nargs='*', help='Run only these CVE IDs')
    ap.add_argument('--no-resume', action='store_true', help="Don't skip instances with existing trajectories")
    ap.add_argument('--metrics-every', type=int, default=10, help='Print running metrics every N instances (0=off)')
    ap.add_argument('--num-workers', type=int, default=1, help='>1: spawn N shard-parallel workers')
    ap.add_argument('--system-prompt', default=None, help='Explicit system prompt path (default: auto by model)')
    ap.add_argument('--worktree-dir', default='./worktrees', help='Parent dir for git worktrees')
    ap.add_argument('--circuit-breaker-limit', type=int, default=3, help='Abort shard after N consecutive server errors (0=off)')
    ap.add_argument('--use-chained', action='store_true', help='Iterate chain-level GT instead of per-commit')
    ap.add_argument('--metrics-only', action='store_true', help='Skip the agent loop; re-score existing predictions')
    return ap.parse_args()

def _resolve_paths(args):
    variant = VARIANT_MAP[args.test_field]
    target_short = 'root_cause' if args.target == 'root_cause_vulnerable' else 'related'
    pred_dir = Path(args.pred_dir or f'results/predictions/iv_a_agent-{variant}/{target_short}')
    metrics_dir = Path(args.metrics_dir or f'results/metrics/iv_a_agent-{variant}/{target_short}')
    pred_dir.mkdir(parents=True, exist_ok=True)
    metrics_dir.mkdir(parents=True, exist_ok=True)
    traj_dir = pred_dir / 'trajectories'
    traj_dir.mkdir(parents=True, exist_ok=True)
    model_tag = args.model.replace('/', '_')
    return (variant, target_short, pred_dir, metrics_dir, traj_dir, model_tag)

def _sibling_glob(model_tag: str) -> str:
    return f'predictions.{model_tag}*.jsonl'

def _load_done_keys(pred_dir: Path, model_tag: str) -> set[tuple]:
    done: set[tuple] = set()
    for sib in sorted(pred_dir.glob(_sibling_glob(model_tag))):
        for line in sib.open():
            try:
                r = json.loads(line)
                done.add((r['cve_id'], r['commit_id']))
            except Exception:
                continue
    return done

def _read_all_predictions(pred_dir: Path, model_tag: str) -> list[dict]:
    out = []
    for sib in sorted(pred_dir.glob(_sibling_glob(model_tag))):
        for line in sib.open():
            try:
                out.append(json.loads(line))
            except Exception:
                continue
    return out

def run_shard(args, shard_id: int, num_shards: int):
    variant, target_short, pred_dir, metrics_dir, traj_dir, model_tag = _resolve_paths(args)
    sharded = num_shards > 1
    shard_tag = f'.shard{shard_id}of{num_shards}' if sharded else ''
    pred_path = pred_dir / f'predictions.{model_tag}{shard_tag}.jsonl'
    tag = f'[shard {shard_id}/{num_shards}] ' if sharded else ''
    print(f'{tag}iv_a_agent-{variant}/{target_short}  model={args.model}  test_field={args.test_field}')
    print(f'{tag}  Repo: {args.repo_path}')
    print(f'{tag}  Step limit={args.step_limit}, cost limit=${args.cost_limit}, timeout={args.cmd_timeout}s')
    if sharded:
        print(f'{tag}  Writing to {pred_path.name}')
    records = load_records(args.input)
    _, _, test_ids = load_split_ids(args.split_dir)
    test_records = filter_by_ids(records, test_ids)
    if args.instance_ids:
        test_records = [r for r in test_records if r['cve_id'] in args.instance_ids]
    print(f'{tag}Test records: {len(test_records)}')
    gt_index = build_gt_index(test_records, args.target, use_chained=args.use_chained)
    done_keys: set[tuple] = set() if args.no_resume else _load_done_keys(pred_dir, model_tag)
    if not args.no_resume:
        n_sibs = len(list(pred_dir.glob(_sibling_glob(model_tag))))
        print(f'{tag}Resume: {len(done_keys)} already done' + (f'  (from {n_sibs} sibling file(s))' if sharded else ''))
    all_instances = []
    for record in test_records:
        if args.use_chained:
            for ch in record.get('src_commits_chained') or []:
                cids = ch.get('commit_ids') or []
                if not cids:
                    continue
                cid = cids[-1]
                pid = ch.get('root_parent_id') or ''
                if not cid or not pid:
                    continue
                if (record['cve_id'], cid) not in gt_index:
                    continue
                all_instances.append((record, cid, pid))
        else:
            for commit in record.get('src_commits', []):
                cid = commit.get('id', '')
                pid = commit.get('parent_id', '')
                if not cid or not pid:
                    continue
                if (record['cve_id'], cid) not in gt_index:
                    continue
                all_instances.append((record, cid, pid))

    def _in_shard(cve_id: str) -> bool:
        if not sharded:
            return True
        h = int(hashlib.md5(cve_id.encode()).hexdigest(), 16)
        return h % num_shards == shard_id
    in_shard_list = [(r, c, p) for r, c, p in all_instances if _in_shard(r['cve_id'])]
    instances = [(r, c, p) for r, c, p in in_shard_list if (r['cve_id'], c) not in done_keys]
    if args.max_instances > 0:
        instances = instances[:args.max_instances]
    print(f'{tag}Instances total (eligible for this target): {len(all_instances)}')
    if sharded:
        print(f"{tag}  this shard's slice:               {len(in_shard_list)}")
    print(f'{tag}  already done (all shards, resume): {len(done_keys)}')
    print(f'{tag}  to run this session:               {len(instances)}' + (f'  (capped by --max-instances {args.max_instances})' if args.max_instances > 0 else ''))
    system_prompt = load_system_prompt(explicit_file=args.system_prompt)
    task_template = load_task_template(args.test_field)
    wt = WorktreeManager(Path(args.repo_path), worktree_dir=Path(args.worktree_dir))
    consec_server_err = 0
    CIRCUIT_BREAKER_LIMIT = args.circuit_breaker_limit
    try:
        with open(pred_path, 'a') as f:
            for i, (record, commit_id, parent_id) in enumerate(instances, 1):
                iid = f"{record['cve_id']}::{commit_id[:12]}"
                print(f'\n{tag}[{i}/{len(instances)}] {iid}  parent={parent_id[:12]}')
                try:
                    task_prompt = render_task_prompt(task_template, record, args.test_field)
                except Exception as e:
                    print(f'{tag}  SKIP: prompt render failed: {e}')
                    continue
                traj_path = traj_dir / f"{iid.replace('::', '__')}.{model_tag}.json"
                try:
                    result = run_agent_on_instance(record, commit_id, parent_id, wt, model_name=args.model, system_prompt=system_prompt, task_prompt=task_prompt, step_limit=args.step_limit, cost_limit=args.cost_limit, cmd_timeout=args.cmd_timeout, traj_path=traj_path)
                except Exception as e:
                    print(f'{tag}  FAIL: {type(e).__name__}: {e}')
                    continue
                err_str = result.get('error') or ''
                if 'InternalServerError' in err_str or 'APIConnectionError' in err_str or 'Connection error' in err_str:
                    consec_server_err += 1
                    if CIRCUIT_BREAKER_LIMIT > 0 and consec_server_err >= CIRCUIT_BREAKER_LIMIT:
                        print(f'{tag}  ABORT: {consec_server_err} consecutive server errors — backend appears down. Check vLLM and restart this shard to resume.')
                        break
                else:
                    consec_server_err = 0
                entry = {'cve_id': record['cve_id'], 'commit_id': commit_id, 'parent_id': parent_id, 'method': 'agent_zero_shot', 'variant': f'iv_a_agent-{variant}', 'test_field': args.test_field, 'model': args.model, 'predicted_functions': result['predictions'], 'raw_predictions': result['raw_predictions'], 'agent_steps': result['agent_steps'], 'agent_cost': result['agent_cost'], 'elapsed_s': result['elapsed_s'], 'error': result['error']}
                f.write(json.dumps(entry, ensure_ascii=False) + '\n')
                f.flush()
                print(f"{tag}  {iid}  {result['agent_steps']} steps  ${result['agent_cost']:.3f}  {result['elapsed_s']}s  → {len(result['predictions'])} preds")
                if not sharded and args.metrics_every > 0:
                    total_done = len(done_keys) + i
                    if total_done % args.metrics_every == 0:
                        _print_running_metrics(pred_dir, model_tag, gt_index, test_records, metrics_dir)
    finally:
        wt.cleanup()

def _print_running_metrics(pred_dir, model_tag, gt_index, test_records, metrics_dir):
    all_so_far = _read_all_predictions(pred_dir, model_tag)
    if not all_so_far:
        return
    try:
        snap = full_evaluation_pipeline(all_so_far, gt_index, test_records)
        ov = snap['overall']
        print(f"  [running metrics @ {len(all_so_far)} instances] hit@1={ov.get('hit@1', 0):.3f}  hit@10={ov.get('hit@10', 0):.3f}  mrr={ov.get('mrr', 0):.3f}  map={ov.get('map', 0):.3f}  recall@10={ov.get('recall@10', 0):.3f}")
        save_metrics(ov, metrics_dir / f'overall.{model_tag}.running.json')
    except Exception as e:
        print(f'  [running metrics] failed: {e}')

def aggregate_and_save(args):
    variant, target_short, pred_dir, metrics_dir, _, model_tag = _resolve_paths(args)
    records = load_records(args.input)
    _, _, test_ids = load_split_ids(args.split_dir)
    test_records = filter_by_ids(records, test_ids)
    if args.instance_ids:
        test_records = [r for r in test_records if r['cve_id'] in args.instance_ids]
    gt_index = build_gt_index(test_records, args.target, use_chained=args.use_chained)
    all_preds = _read_all_predictions(pred_dir, model_tag)
    print(f'\nTotal predictions (all shards): {len(all_preds)}')
    if not all_preds:
        return
    result = full_evaluation_pipeline(all_preds, gt_index, test_records)
    print_overall(result['overall'], f'iv_a_agent-{variant} ({args.test_field}, {args.model})')
    save_metrics(result['overall'], metrics_dir / f'overall.{model_tag}.json')
    save_metrics(result.get('by_cwe', {}), metrics_dir / f'by_cwe.{model_tag}.json')
    running_path = metrics_dir / f'overall.{model_tag}.running.json'
    if running_path.exists():
        running_path.unlink()

def _worker_entry(args_dict, shard_id, num_shards):
    args = argparse.Namespace(**args_dict)
    run_shard(args, shard_id, num_shards)

def main():
    args = _parse_args()
    if getattr(args, 'metrics_only', False):
        variant, target_short, pred_dir, metrics_dir, _, model_tag = _resolve_paths(args)
        print(f'[metrics-only] iv_a_agent-{variant}/{target_short}  target={args.target}  pred_dir={pred_dir}')
        aggregate_and_save(args)
        return
    if args.num_workers <= 1:
        run_shard(args, shard_id=0, num_shards=1)
    else:
        ctx = mp.get_context('spawn')
        procs = []
        for i in range(args.num_workers):
            p = ctx.Process(target=_worker_entry, args=(vars(args), i, args.num_workers))
            p.start()
            procs.append(p)
        try:
            for p in procs:
                p.join()
        except KeyboardInterrupt:
            print('\n[main] KeyboardInterrupt — terminating workers')
            for p in procs:
                if p.is_alive():
                    p.terminate()
            for p in procs:
                p.join()
            raise
    aggregate_and_save(args)
if __name__ == '__main__':
    main()
