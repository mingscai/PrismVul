import json
import os
from collections import defaultdict
from pathlib import Path
from typing import Sequence
import numpy as np
from utils.matching import match_predictions
DEFAULT_K = [1, 3, 5, 10]

def _file_key(item) -> str | None:
    if not isinstance(item, dict):
        return None
    path = item.get('file')
    if not path:
        return None
    return os.path.splitext(path)[0]

def _topk_unique_files(predicted_functions, k):
    out, seen = ([], set())
    for f in predicted_functions:
        key = _file_key(f)
        if key is None or key in seen:
            continue
        seen.add(key)
        out.append(key)
        if len(out) >= k:
            break
    return out

def eval_loose_dual_instance(predicted_pairs: list[tuple[str, str]], gt_pairs: list[tuple[str, str]], k_values: list[int]=DEFAULT_K) -> dict:
    metrics: dict[str, float] = {}
    pred_funcs = [bn for _, bn in predicted_pairs]
    pred_files_ranked = []
    seen_f = set()
    for fk, _ in predicted_pairs:
        if fk and fk not in seen_f:
            seen_f.add(fk)
            pred_files_ranked.append(fk)
    pred_tuples = [(fk, bn) for fk, bn in predicted_pairs if fk]
    gt_funcs_set = {bn for _, bn in gt_pairs if bn}
    gt_files_set = {fk for fk, _ in gt_pairs if fk}
    gt_tuples_set = {(fk, bn) for fk, bn in gt_pairs if fk and bn}

    def _topk_set_metrics(predicted_seq, gt_set, k_values, suffix):
        n_gt = len(gt_set)
        for k in k_values:
            topk = predicted_seq[:k]
            n_pred = len(topk)
            topk_set = set(topk)
            n_match = len(topk_set & gt_set)
            prec = n_match / k if k > 0 else 0.0
            rec = n_match / n_gt if n_gt > 0 else 0.0
            f1 = 2 * prec * rec / (prec + rec) if prec + rec > 0 else 0.0
            union = n_pred + n_gt - n_match
            iou = n_match / union if union > 0 else 0.0
            sub = 1.0 if n_gt > 0 and n_match == n_gt else 0.0
            metrics[f'hit{suffix}@{k}'] = 1.0 if n_match > 0 else 0.0
            metrics[f'precision{suffix}@{k}'] = prec
            metrics[f'recall{suffix}@{k}'] = rec
            metrics[f'f1{suffix}@{k}'] = f1
            metrics[f'iou{suffix}@{k}'] = iou
            metrics[f'subset_acc{suffix}@{k}'] = sub
        rr = 0.0
        for rank, x in enumerate(predicted_seq, 1):
            if x in gt_set:
                rr = 1.0 / rank
                break
        metrics[f'mrr{suffix}'] = rr
        hits, sum_p, matched = (0, 0.0, set())
        for rank, x in enumerate(predicted_seq, 1):
            if x in gt_set and x not in matched:
                hits += 1
                sum_p += hits / rank
                matched.add(x)
        metrics[f'map{suffix}'] = sum_p / n_gt if n_gt > 0 else 0.0
    _topk_set_metrics(pred_funcs, gt_funcs_set, k_values, '')
    _topk_set_metrics(pred_files_ranked, gt_files_set, k_values, '_file')
    _topk_set_metrics(pred_tuples, gt_tuples_set, k_values, '_tuple')
    return metrics

def eval_instance(predicted_functions: list[dict | str], ground_truth_funcs: list[dict], k_values: list[int]=DEFAULT_K) -> dict:
    metrics: dict[str, float] = {}
    n_gt = len(ground_truth_funcs)
    gt_file_keys = {_file_key(g) for g in ground_truth_funcs} - {None}
    n_gt_files = len(gt_file_keys)
    if n_gt == 0:
        for k in k_values:
            metrics[f'hit@{k}'] = 0.0
            metrics[f'precision@{k}'] = 0.0
            metrics[f'recall@{k}'] = 0.0
            metrics[f'f1@{k}'] = 0.0
            metrics[f'iou@{k}'] = 0.0
            metrics[f'subset_acc@{k}'] = 0.0
            metrics[f'hit_file@{k}'] = 0.0
            metrics[f'precision_file@{k}'] = 0.0
            metrics[f'recall_file@{k}'] = 0.0
            metrics[f'f1_file@{k}'] = 0.0
            metrics[f'iou_file@{k}'] = 0.0
            metrics[f'subset_acc_file@{k}'] = 0.0
        metrics['mrr'] = 0.0
        metrics['map'] = 0.0
        metrics['mrr_file'] = 0.0
        metrics['map_file'] = 0.0
        return metrics
    for k in k_values:
        topk = predicted_functions[:k]
        n_pred = len(topk)
        matched = match_predictions(topk, ground_truth_funcs)
        n_match = len(matched)
        prec = n_match / k if k > 0 else 0.0
        rec = n_match / n_gt
        f1 = 2 * prec * rec / (prec + rec) if prec + rec > 0 else 0.0
        union = n_pred + n_gt - n_match
        iou = n_match / union if union > 0 else 0.0
        sub_acc = 1.0 if n_match == n_gt else 0.0
        metrics[f'hit@{k}'] = 1.0 if n_match > 0 else 0.0
        metrics[f'precision@{k}'] = prec
        metrics[f'recall@{k}'] = rec
        metrics[f'f1@{k}'] = f1
        metrics[f'iou@{k}'] = iou
        metrics[f'subset_acc@{k}'] = sub_acc
    for k in k_values:
        topk_files = _topk_unique_files(predicted_functions, k)
        n_pred_f = len(topk_files)
        match_f = set(topk_files) & gt_file_keys
        n_match_f = len(match_f)
        prec_f = n_match_f / k if k > 0 else 0.0
        rec_f = n_match_f / n_gt_files if n_gt_files > 0 else 0.0
        f1_f = 2 * prec_f * rec_f / (prec_f + rec_f) if prec_f + rec_f > 0 else 0.0
        union_f = n_pred_f + n_gt_files - n_match_f
        iou_f = n_match_f / union_f if union_f > 0 else 0.0
        sub_f = 1.0 if n_match_f == n_gt_files else 0.0
        metrics[f'hit_file@{k}'] = 1.0 if n_match_f > 0 else 0.0
        metrics[f'precision_file@{k}'] = prec_f
        metrics[f'recall_file@{k}'] = rec_f
        metrics[f'f1_file@{k}'] = f1_f
        metrics[f'iou_file@{k}'] = iou_f
        metrics[f'subset_acc_file@{k}'] = sub_f
    mrr = 0.0
    for rank, func in enumerate(predicted_functions, start=1):
        if match_predictions([func], ground_truth_funcs):
            mrr = 1.0 / rank
            break
    metrics['mrr'] = mrr
    hits_so_far = 0
    sum_prec = 0.0
    matched_gt_so_far: set[int] = set()
    for rank, func in enumerate(predicted_functions, start=1):
        newly_matched = match_predictions([func], ground_truth_funcs) - matched_gt_so_far
        if newly_matched:
            hits_so_far += 1
            sum_prec += hits_so_far / rank
            matched_gt_so_far |= newly_matched
    metrics['map'] = sum_prec / n_gt
    mrr_f = 0.0
    seen_keys: set[str] = set()
    file_rank = 0
    for func in predicted_functions:
        key = _file_key(func)
        if key is None or key in seen_keys:
            continue
        seen_keys.add(key)
        file_rank += 1
        if key in gt_file_keys:
            mrr_f = 1.0 / file_rank
            break
    metrics['mrr_file'] = mrr_f
    seen_keys = set()
    file_rank = 0
    hits_so_far = 0
    sum_prec_f = 0.0
    matched_gt_files: set[str] = set()
    for func in predicted_functions:
        key = _file_key(func)
        if key is None or key in seen_keys:
            continue
        seen_keys.add(key)
        file_rank += 1
        if key in gt_file_keys and key not in matched_gt_files:
            hits_so_far += 1
            sum_prec_f += hits_so_far / file_rank
            matched_gt_files.add(key)
    metrics['map_file'] = sum_prec_f / n_gt_files if n_gt_files > 0 else 0.0
    return metrics

def eval_classifier_instance(predicted_functions: list[dict], ground_truth_funcs: list[dict]) -> dict:
    n_gt = len(ground_truth_funcs)
    n_pred = len(predicted_functions)
    pred_file_keys = {_file_key(p) for p in predicted_functions} - {None}
    gt_file_keys = {_file_key(g) for g in ground_truth_funcs} - {None}
    n_pred_f = len(pred_file_keys)
    n_gt_f = len(gt_file_keys)
    if n_pred == 0:
        return {'n_pred': 0, 'precision': 0.0, 'recall': 0.0, 'f1': 0.0, 'iou': 0.0, 'subset_acc': 0.0, 'n_pred_file': 0, 'precision_file': 0.0, 'recall_file': 0.0, 'f1_file': 0.0, 'iou_file': 0.0, 'subset_acc_file': 0.0, 'empty_pred': 1.0}
    matched = match_predictions(predicted_functions, ground_truth_funcs)
    n_match = len(matched)
    prec = n_match / n_pred
    rec = n_match / n_gt if n_gt > 0 else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec > 0 else 0.0
    union = n_pred + n_gt - n_match
    iou = n_match / union if union > 0 else 0.0
    sub_acc = 1.0 if n_match == n_gt and n_pred == n_match else 0.0
    match_f = pred_file_keys & gt_file_keys
    n_match_f = len(match_f)
    prec_f = n_match_f / n_pred_f if n_pred_f > 0 else 0.0
    rec_f = n_match_f / n_gt_f if n_gt_f > 0 else 0.0
    f1_f = 2 * prec_f * rec_f / (prec_f + rec_f) if prec_f + rec_f > 0 else 0.0
    union_f = n_pred_f + n_gt_f - n_match_f
    iou_f = n_match_f / union_f if union_f > 0 else 0.0
    sub_acc_f = 1.0 if n_match_f == n_gt_f and n_pred_f == n_match_f else 0.0
    return {'n_pred': float(n_pred), 'precision': prec, 'recall': rec, 'f1': f1, 'iou': iou, 'subset_acc': sub_acc, 'n_pred_file': float(n_pred_f), 'precision_file': prec_f, 'recall_file': rec_f, 'f1_file': f1_f, 'iou_file': iou_f, 'subset_acc_file': sub_acc_f, 'empty_pred': 0.0}

def aggregate_classifier_overall(instance_metrics: list[dict]) -> dict:
    if not instance_metrics:
        return {}
    keys = list(instance_metrics[0].keys())
    return {k: float(np.mean([m[k] for m in instance_metrics])) for k in keys}

def aggregate_to_cve(instance_results: list[dict]) -> list[dict]:
    by_cve: dict[str, list[dict]] = defaultdict(list)
    for inst in instance_results:
        by_cve[inst['cve_id']].append(inst['metrics'])
    cve_results = []
    for cve_id, metrics_list in by_cve.items():
        keys = list(metrics_list[0].keys())
        avg = {k: float(np.mean([m[k] for m in metrics_list])) for k in keys}
        cve_results.append({'cve_id': cve_id, 'metrics': avg, 'n_commits': len(metrics_list)})
    return cve_results

def aggregate_overall(cve_results: list[dict]) -> dict:
    if not cve_results:
        return {}
    keys = list(cve_results[0]['metrics'].keys())
    return {k: float(np.mean([r['metrics'][k] for r in cve_results])) for k in keys}

def aggregate_by_cwe(cve_results: list[dict], records: list[dict]) -> dict:
    cve_to_cwe: dict[str, list[str]] = {}
    for r in records:
        cve_to_cwe[r['cve_id']] = [rep['id'] for rep in r.get('cwe_reps', [])] or ['unknown']
    groups: dict[str, list[dict]] = defaultdict(list)
    for r in cve_results:
        for cwe_node in cve_to_cwe.get(r['cve_id'], ['unknown']):
            groups[cwe_node].append(r['metrics'])
    keys = list(list(cve_results[0]['metrics'].keys()))
    per_group = {}
    for group, mlist in groups.items():
        per_group[group] = {k: float(np.mean([m[k] for m in mlist])) for k in keys}
    macro_avg = {k: float(np.mean([g[k] for g in per_group.values()])) for k in keys}
    return {'per_group': per_group, 'macro_average': macro_avg}

def full_evaluation_pipeline(predictions: list[dict], ground_truth_index: dict[tuple, list[dict]], records: list[dict] | None=None, k_values: list[int]=DEFAULT_K) -> dict:
    instance_results = []
    for pred in predictions:
        key = (pred['cve_id'], pred['commit_id'])
        gt_funcs = ground_truth_index.get(key, [])
        m = eval_instance(pred.get('predicted_functions', []), gt_funcs, k_values)
        instance_results.append({'cve_id': pred['cve_id'], 'commit_id': pred['commit_id'], 'metrics': m})
    cve_results = aggregate_to_cve(instance_results)
    overall = aggregate_overall(cve_results)
    result = {'instance_results': instance_results, 'cve_results': cve_results, 'overall': overall, 'n_instances': len(instance_results), 'n_cves': len(cve_results)}
    if records:
        result['by_cwe'] = aggregate_by_cwe(cve_results, records)
    return result

def build_gt_index(records: list[dict], target: str='root_cause_vulnerable', use_chained: bool=False) -> dict[tuple, list[dict]]:
    from utils.dataset import extract_instances
    index: dict[tuple, list[dict]] = {}
    for r in records:
        for inst in extract_instances(r, target, use_chained=use_chained):
            key = (inst['cve_id'], inst['commit_id'])
            index[key] = inst['vuln_funcs']
    return index

def substitutability_analysis(post_cve_results: list[dict], pre_cve_results: list[dict], metric_key: str='mrr') -> dict:
    from scipy.stats import spearmanr
    post_dict = {r['cve_id']: r['metrics'][metric_key] for r in post_cve_results}
    pre_dict = {r['cve_id']: r['metrics'][metric_key] for r in pre_cve_results}
    common = sorted(set(post_dict) & set(pre_dict))
    post_scores = [post_dict[c] for c in common]
    pre_scores = [pre_dict[c] for c in common]
    rho, p_value = spearmanr(post_scores, pre_scores)
    return {'metric': metric_key, 'n_cves': len(common), 'spearman_rho': float(rho), 'spearman_p': float(p_value), 'mean_post': float(np.mean(post_scores)), 'mean_pre': float(np.mean(pre_scores)), 'mean_gap_post_minus_pre': float(np.mean(np.array(post_scores) - np.array(pre_scores)))}

def save_metrics(result: dict, out_path: str | Path):
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, 'w') as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
    print(f'Metrics saved → {out_path}')

def print_overall(overall: dict, title: str='Overall'):
    print(f"\n{'─' * 50}")
    print(f'  {title}')
    print(f"{'─' * 50}")
    for k, v in sorted(overall.items()):
        print(f'  {k:<20s} {v:.4f}')
