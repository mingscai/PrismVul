#!/usr/bin/env python3
from __future__ import annotations
import argparse
import hashlib
import json
import re
import time
from collections import Counter, defaultdict
from pathlib import Path
RE_CHERRY = re.compile('\\(cherry picked from commit ([0-9a-f]{7,40})\\)', re.IGNORECASE)
_TRAILER_RE = re.compile('^(?:Change-Id|Reviewed-on|Reviewed-by|Commit-Queue|Auto-Submit|Cr-Commit-Position|Cr-Original-Commit-Position|Cr-Branched-From|Bug|BUG|Test|TEST|Tested-by|Signed-off-by|Fixed|NOPRESUBMIT):.*$', re.MULTILINE)
CLASSIFICATION_PRIORITY = {'root_cause_vulnerable': 3, 'supporting_fix': 2, 'incidental_or_unrelated': 1, None: 0}

def _match_source_in_set(src_hash: str, by_id: dict[str, dict]) -> str | None:
    s = src_hash.lower()
    if s in by_id:
        return s
    for cid in by_id:
        cidl = cid.lower()
        if cidl.startswith(s) or s.startswith(cidl[:max(7, len(s))]):
            return cid
    return None

def normalize_cherries(commits: list[dict]) -> tuple[list[dict], dict[str, list[str]]]:
    by_id: dict[str, dict] = {c['id']: c for c in commits if c.get('id')}
    cherry_src: dict[str, str] = {}
    for cid, c in by_id.items():
        msg = c.get('message') or ''
        m = RE_CHERRY.search(msg)
        if not m:
            continue
        src_full = _match_source_in_set(m.group(1), by_id)
        if src_full and src_full != cid:
            cherry_src[cid] = src_full

    def root_of(cid: str) -> str:
        seen = {cid}
        while cid in cherry_src:
            nxt = cherry_src[cid]
            if nxt in seen:
                return cid
            seen.add(nxt)
            cid = nxt
        return cid
    absorbed_map: dict[str, list[str]] = defaultdict(list)
    for cid in by_id:
        root = root_of(cid)
        if root != cid:
            absorbed_map[root].append(cid)
    kept_ids = set(by_id) - {cid for lst in absorbed_map.values() for cid in lst}
    kept_commits = [by_id[c] for c in by_id if c in kept_ids]
    return (kept_commits, dict(absorbed_map))

def _canonicalize_message(msg: str) -> str:
    msg = RE_CHERRY.sub('', msg or '')
    msg = _TRAILER_RE.sub('', msg)
    msg = re.sub('\\s+', ' ', msg)
    return msg.strip()

def dedup_parallel_duplicates(commits: list[dict]) -> tuple[list[dict], dict[str, list[str]]]:
    groups: dict[str, list[dict]] = defaultdict(list)
    for c in commits:
        key = hashlib.sha1(_canonicalize_message(c.get('message') or '').encode('utf-8')).hexdigest()
        groups[key].append(c)
    kept: list[dict] = []
    dedup_map: dict[str, list[str]] = {}
    for members in groups.values():
        if len(members) == 1:
            kept.append(members[0])
            continue
        members_sorted = sorted(members, key=lambda c: c.get('commit_date') or '\uffff')
        keeper = members_sorted[0]
        kept.append(keeper)
        dedup_map[keeper['id']] = [c['id'] for c in members_sorted[1:]]
    return (kept, dedup_map)

def build_chains(commits: list[dict]) -> list[list[dict]]:
    ids_in_set: dict[str, dict] = {c['id']: c for c in commits if c.get('id')}
    children_of: dict[str, list[str]] = defaultdict(list)
    for c in commits:
        p = c.get('parent_id')
        if p and p in ids_in_set:
            children_of[p].append(c['id'])
    roots = [c for c in commits if c.get('parent_id') not in ids_in_set or not c.get('parent_id')]
    chains: list[list[dict]] = []
    for root in roots:
        chain = [root]
        cur = root['id']
        while children_of.get(cur):
            nxt_id = children_of[cur][0]
            chain.append(ids_in_set[nxt_id])
            cur = nxt_id
        chains.append(chain)
    return chains

def chain_net_diff_funcs(chain: list[dict]) -> list[dict]:
    state: dict[tuple[str, str], dict] = {}
    for commit in chain:
        for diff in commit.get('diffs') or []:
            filename = diff.get('filename') or ''
            df = diff.get('diff_funcs') or {}
            mod_rem_sigs = {fn.get('sig') for cat2 in ('modified', 'removed') for fn in df.get(cat2) or [] if fn.get('sig')}
            for cat in ('added', 'modified', 'removed'):
                for fn in df.get(cat) or []:
                    sig = fn.get('sig') or ''
                    if not sig:
                        continue
                    if cat == 'added' and sig in mod_rem_sigs:
                        continue
                    key = (filename, sig)
                    code = fn.get('code')
                    code_after = fn.get('code_after')
                    if cat == 'added':
                        pre_body, post_body = (None, code)
                    elif cat == 'modified':
                        pre_body, post_body = (code, code_after)
                    else:
                        pre_body, post_body = (code, None)
                    if key not in state:
                        state[key] = {'first_action': cat, 'initial_body': pre_body, 'first_callgraph': fn.get('callgraph'), 'last_action': cat, 'final_body': post_body, 'classifications': {}}
                    else:
                        state[key]['last_action'] = cat
                        state[key]['final_body'] = post_body
                    cls = fn.get('classification')
                    if cls:
                        state[key]['classifications'][cls] = fn.get('vuln_reasoning') or ''
    out = []
    for (file, sig), ent in state.items():
        initial_existed = ent['first_action'] in ('modified', 'removed')
        if not initial_existed:
            continue
        final_existed = ent['last_action'] != 'removed'
        if final_existed:
            ib, fb = (ent['initial_body'], ent['final_body'])
            if ib is not None and fb is not None and (ib == fb):
                continue
        best_cls = None
        best_reasoning = ''
        best_prio = 0
        for cls, reason in ent['classifications'].items():
            prio = CLASSIFICATION_PRIORITY.get(cls, 0)
            if prio > best_prio:
                best_prio = prio
                best_cls = cls
                best_reasoning = reason
        last_action = 'removed' if not final_existed else 'modified'
        out.append({'file': file, 'sig': sig, 'classification': best_cls, 'vuln_reasoning': best_reasoning, 'last_action': last_action, 'code': ent['initial_body'], 'code_after': ent['final_body'], 'callgraph': ent['first_callgraph']})
    return out

def process_record(record: dict) -> list[dict]:
    commits = record.get('src_commits') or []
    if not commits:
        return []
    by_id = {c['id']: c for c in commits if c.get('id')}
    after_cherry, absorbed_cherry_map = normalize_cherries(commits)
    after_dedup, dedup_map = dedup_parallel_duplicates(after_cherry)
    chains = build_chains(after_dedup)
    result = []
    for i, chain in enumerate(chains):
        root = chain[0]
        ch_commit_ids = [c['id'] for c in chain]
        absorbed_cherries = []
        absorbed_duplicates = []
        for cid in ch_commit_ids:
            absorbed_cherries.extend(absorbed_cherry_map.get(cid, []))
            absorbed_duplicates.extend(dedup_map.get(cid, []))
        gt_funcs = chain_net_diff_funcs(chain)
        if absorbed_cherries and gt_funcs:
            cherry_cls: dict[tuple, dict[str, str]] = {}
            for cherry_id in absorbed_cherries:
                cherry = by_id.get(cherry_id)
                if not cherry:
                    continue
                for diff in cherry.get('diffs') or []:
                    fname = diff.get('filename') or ''
                    df = diff.get('diff_funcs') or {}
                    for cat in ('modified', 'removed'):
                        for fn in df.get(cat) or []:
                            sig = fn.get('sig') or ''
                            if not sig:
                                continue
                            cls = fn.get('classification')
                            if not cls:
                                continue
                            key = (fname, sig)
                            cherry_cls.setdefault(key, {})[cls] = fn.get('vuln_reasoning') or ''
            for gt in gt_funcs:
                key = (gt['file'], gt['sig'])
                cands = cherry_cls.get(key)
                if not cands:
                    continue
                cur_prio = CLASSIFICATION_PRIORITY.get(gt['classification'], 0)
                for cls, reason in cands.items():
                    p = CLASSIFICATION_PRIORITY.get(cls, 0)
                    if p > cur_prio:
                        gt['classification'] = cls
                        gt['vuln_reasoning'] = reason
                        cur_prio = p
        result.append({'chain_id': i, 'root_parent_id': root.get('parent_id'), 'commit_ids': ch_commit_ids, 'len': len(chain), 'gt_funcs': gt_funcs, 'absorbed_cherries': absorbed_cherries, 'absorbed_duplicates': absorbed_duplicates})
    return result

def classify_topology(chains: list[dict]) -> str:
    if not chains:
        return 'empty'
    n = len(chains)
    max_len = max((c['len'] for c in chains))
    any_absorbed = any((c['absorbed_cherries'] for c in chains))
    if n == 1:
        if max_len == 1:
            return 'pure_cherry' if any_absorbed else 'singleton'
        else:
            return 'mixed' if any_absorbed else 'pure_chain'
    if max_len == 1 and (not any_absorbed):
        return 'parallel_only'
    return 'multi_independent'

def parse_args():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--input-jsonl', type=Path, required=True)
    ap.add_argument('--output-jsonl', type=Path, required=True)
    ap.add_argument('--field-name', default='src_commits_chained', help='Name of the new top-level field to add (default: %(default)s)')
    return ap.parse_args()

def main():
    args = parse_args()
    records = []
    with args.input_jsonl.open() as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    print(f'[input] {len(records)} CVE records')
    t0 = time.time()
    topo_count = Counter()
    n_chains_total = 0
    n_gt_total = 0
    for r in records:
        chains = process_record(r)
        r[args.field_name] = chains
        topo_count[classify_topology(chains)] += 1
        n_chains_total += len(chains)
        for ch in chains:
            n_gt_total += len(ch['gt_funcs'])
    elapsed = time.time() - t0
    print(f'[process] {elapsed:.1f}s')
    tmp = args.output_jsonl.with_suffix(args.output_jsonl.suffix + '.tmp')
    with tmp.open('w') as f:
        for r in records:
            f.write(json.dumps(r, ensure_ascii=False) + '\n')
    tmp.replace(args.output_jsonl)
    print(f'[output] {args.output_jsonl}')
    print('\n=== Materialization summary ===')
    print(f'  Total records:     {len(records)}')
    print(f'  Total chains:      {n_chains_total}')
    print(f'  Total GT entries:  {n_gt_total}')
    print('\n  Topology distribution:')
    for cls, n in topo_count.most_common():
        print(f'    {cls:<22} {n:>5}  ({100 * n / len(records):5.1f}%)')
if __name__ == '__main__':
    main()
